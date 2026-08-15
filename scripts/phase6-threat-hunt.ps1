param(
    [string[]]$Targets = @('windows-endpoint'),
    [string]$EndpointMapPath = '.\shuffle\investigation-agent-endpoint-map.json',
    [string]$OutputDir = '.\phase6-evidence',
    [string]$WazuhConfigDir = '.\configs\wazuh-manager',
    [int]$TimeoutSeconds = 120,
    [switch]$CreateTheHiveCase,
    [string]$SshPassword = ''
)

$ErrorActionPreference = 'Stop'

function Read-DotEnv {
    param([string]$Path)
    $values = @{}
    if (!(Test-Path -LiteralPath $Path)) { return $values }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (!$trimmed -or $trimmed.StartsWith('#') -or !$trimmed.Contains('=')) { continue }
        $name, $value = $trimmed.Split('=', 2)
        $values[$name.Trim()] = $value.Trim()
    }
    return $values
}

function Invoke-ProxmoxCommand {
    param(
        [string]$Command,
        [hashtable]$Env
    )
    $plink = 'C:\Program Files\PuTTY\plink.exe'
    if (!(Test-Path -LiteralPath $plink)) { throw "PuTTY plink not found at $plink" }
    $password = $SshPassword
    if (!$password) { $password = $Env['PROXMOX_SSH_PASS'] }
    if (!$password) { $password = $Env['PFSENSE_WEB_PASS'] }
    if (!$password) { throw 'No SSH password found. Pass -SshPassword or set PROXMOX_SSH_PASS/PFSENSE_WEB_PASS in .env.' }
    $hostName = if ($Env['PROXMOX_HOST']) { $Env['PROXMOX_HOST'] } else { '192.168.2.200' }
    $hostKey = 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg'
    & $plink -ssh -P 22 -noagent -batch -pw $password -hostkey $hostKey "root@$hostName" $Command
    if ($LASTEXITCODE -ne 0) { throw "Remote command failed with exit code $LASTEXITCODE" }
}

function Invoke-VelociraptorCollection {
    param(
        [string]$ClientId,
        [string[]]$Artifacts,
        [int]$Timeout,
        [hashtable]$Env
    )

    $artifactArgs = ($Artifacts | ForEach-Object { "'$_'" }) -join ' '
    $remoteScript = @"
#!/bin/sh
set -eu
/velociraptor/velociraptor --api_config /tmp/shuffle-investigation-admin-api.yaml artifacts collect --client_id '$ClientId' --timeout $Timeout --format json $artifactArgs
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remoteScript))
    $remote = "pct exec 200 -- docker exec velociraptor sh -c 'echo $encoded | base64 -d > /tmp/phase6-hunt-run.sh && chmod +x /tmp/phase6-hunt-run.sh && /tmp/phase6-hunt-run.sh'"
    Invoke-ProxmoxCommand -Command $remote -Env $Env
}

function Read-IocValues {
    param([string]$Directory)
    $values = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('misp_ip_iocs', 'misp_domain_iocs', 'misp_hash_iocs')) {
        $path = Join-Path $Directory $name
        if (!(Test-Path -LiteralPath $path)) { continue }
        foreach ($line in Get-Content -LiteralPath $path) {
            $trimmed = $line.Trim()
            if (!$trimmed -or $trimmed.StartsWith('#')) { continue }
            $values.Add(($trimmed.Split(':', 2)[0]).ToLowerInvariant())
        }
    }
    return @($values | Sort-Object -Unique)
}

function Test-PrivateIp {
    param([string]$Ip)
    if (!$Ip) { return $true }
    return ($Ip -match '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|::1$|fe80:)')
}

function Find-HuntHits {
    param(
        [object[]]$Events,
        [string[]]$Iocs
    )

    $hits = New-Object System.Collections.Generic.List[object]
    $suspiciousProcessNames = @('mimikatz', 'psexec', 'procdump', 'rubeus', 'bloodhound', 'sharp', 'cobalt', 'beacon', 'nc.exe', 'netcat', 'powershell.exe', 'pwsh.exe')
    foreach ($event in $Events) {
        $source = [string]$event._Source
        $json = ($event | ConvertTo-Json -Depth 20 -Compress).ToLowerInvariant()

        foreach ($ioc in $Iocs) {
            if ($ioc -and $json.Contains($ioc)) {
                $hits.Add([ordered]@{ hypothesis = 'misp_ioc_seen_in_endpoint_data'; severity = 'high'; source = $source; value = $ioc; detail = 'Endpoint collection output contains a current MISP IOC.' })
            }
        }

        foreach ($name in $suspiciousProcessNames) {
            if ($json.Contains($name)) {
                $level = if ($name -in @('powershell.exe', 'pwsh.exe')) { 'low' } else { 'medium' }
                $hits.Add([ordered]@{ hypothesis = 'suspicious_process_name'; severity = $level; source = $source; value = $name; detail = 'Process or command-line data contains a watched process string.' })
            }
        }

        if ($source -eq 'Windows.Network.Netstat') {
            $remoteIp = if ($event.Raddr) { [string]$event.Raddr } elseif ($event.RemoteAddr) { [string]$event.RemoteAddr } elseif ($event.RemoteAddress) { [string]$event.RemoteAddress } else { '' }
            if ($remoteIp -and !(Test-PrivateIp -Ip $remoteIp)) {
                $hits.Add([ordered]@{ hypothesis = 'public_network_connection'; severity = 'info'; source = $source; value = $remoteIp; detail = 'Netstat contains a public remote endpoint. Review process context before escalating.' })
            }
        }
    }

    $seen = @{}
    $uniqueHits = New-Object System.Collections.Generic.List[object]
    foreach ($hit in $hits) {
        $key = "$($hit.hypothesis)|$($hit.severity)|$($hit.source)|$($hit.value)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $uniqueHits.Add($hit)
    }
    return $uniqueHits.ToArray()
}

function New-TheHiveCase {
    param(
        [hashtable]$Env,
        [object]$Summary
    )
    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = $Env['THEHIVE_PUBLIC_URL']
    if (!$baseUrl) { $baseUrl = $Env['THEHIVE_URL'] }
    if (!$baseUrl) { $baseUrl = 'https://thehive' }
    if (!$apiKey) { throw 'THEHIVE_API_KEY is missing from .env.' }

    $payload = [ordered]@{
        title = "[Phase 6] Threat Hunting Agent run $($Summary.timestamp)"
        description = @"
## Phase 6 Threat Hunting Agent Evidence

**Targets:** $($Summary.targets -join ', ')
**Total events:** $($Summary.total_events)
**Total hits:** $($Summary.total_hits)
**Summary file:** $($Summary.summary_path)

This case was created by `scripts/phase6-threat-hunt.ps1`. Velociraptor actions were read-only. Hits are hunt leads, not confirmed incidents.
"@
        severity = if ($Summary.high_hits -gt 0) { 3 } elseif ($Summary.medium_hits -gt 0) { 2 } else { 1 }
        tlp = 2
        pap = 2
        tags = @('phase6', 'threat-hunting-agent', 'velociraptor', 'read-only')
    }
    $tempPayload = Join-Path $env:TEMP "phase6-thehive-case-$([guid]::NewGuid()).json"
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/case" -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -InFile $tempPayload
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')
if (!(Test-Path -LiteralPath $EndpointMapPath)) { throw "Endpoint map not found: $EndpointMapPath" }
if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$endpointMap = Get-Content -LiteralPath $EndpointMapPath -Raw | ConvertFrom-Json
$iocValues = Read-IocValues -Directory $WazuhConfigDir
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$allTargetSummaries = New-Object System.Collections.Generic.List[object]
$allHits = New-Object System.Collections.Generic.List[object]
$totalEvents = 0

foreach ($target in $Targets) {
    $entry = $endpointMap.$target
    if (!$entry) { throw "Target '$target' was not found in $EndpointMapPath" }
    $clientId = [string]$entry.velociraptor_client_id
    $artifacts = @($entry.default_artifacts)
    if ($artifacts.Count -eq 0) { $artifacts = @('Generic.Client.Info') }
    $safeTarget = $target.Replace('\', '-').Replace('/', '-')
    $evidencePath = Join-Path $OutputDir "$timestamp-$safeTarget-$clientId.jsonl"

    $rawOutput = Invoke-VelociraptorCollection -ClientId $clientId -Artifacts $artifacts -Timeout $TimeoutSeconds -Env $envValues
    $rawOutput | Set-Content -LiteralPath $evidencePath -Encoding UTF8

    $events = @()
    foreach ($line in $rawOutput) {
        if (!$line.Trim().StartsWith('{')) { continue }
        try { $events += ($line | ConvertFrom-Json) } catch { }
    }
    $hits = Find-HuntHits -Events $events -Iocs $iocValues
    foreach ($hit in $hits) { $allHits.Add([ordered]@{ target = $target; hostname = $entry.hostname; client_id = $clientId; hit = $hit }) }
    $totalEvents += $events.Count

    $allTargetSummaries.Add([ordered]@{
        target = $target
        hostname = $entry.hostname
        client_id = $clientId
        artifacts = $artifacts
        evidence_path = (Resolve-Path -LiteralPath $evidencePath).Path
        event_count = $events.Count
        hit_count = @($hits).Count
    })
}

$highHits = @($allHits | Where-Object { $_.hit.severity -eq 'high' }).Count
$mediumHits = @($allHits | Where-Object { $_.hit.severity -eq 'medium' }).Count
$summaryPath = Join-Path $OutputDir "$timestamp-threat-hunt-summary.json"
$summary = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    targets = $Targets
    ioc_count = $iocValues.Count
    total_events = $totalEvents
    total_hits = $allHits.Count
    high_hits = $highHits
    medium_hits = $mediumHits
    target_summaries = $allTargetSummaries.ToArray()
    hits = $allHits.ToArray()
    summary_path = (Join-Path (Resolve-Path -LiteralPath $OutputDir).Path (Split-Path -Leaf $summaryPath))
}

$case = $null
if ($CreateTheHiveCase) {
    $case = New-TheHiveCase -Env $envValues -Summary ([pscustomobject]$summary)
    $summary['thehive_case_id'] = $case.id
    $summary['thehive_case_number'] = $case.caseId
}

$summary | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

[pscustomobject]@{
    Targets = ($Targets -join ',')
    IocCount = $iocValues.Count
    TotalEvents = $totalEvents
    TotalHits = $allHits.Count
    HighHits = $highHits
    MediumHits = $mediumHits
    SummaryPath = (Resolve-Path -LiteralPath $summaryPath).Path
    TheHiveCaseId = if ($case) { $case.id } else { $null }
    TheHiveCaseNumber = if ($case) { $case.caseId } else { $null }
}
