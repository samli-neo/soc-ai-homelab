param(
    [ValidateSet('windows', 'proxmox')]
    [string]$Target = 'windows',

    [string]$ClientId = '',
    [string]$CaseTitle = '',
    [switch]$CreateTheHiveCase,
    [string]$EvidenceDir = '.\phase2-evidence',
    [string[]]$Artifacts = @(),
    [int]$TimeoutSeconds = 120,
    [string]$SshPassword = ''
)

$ErrorActionPreference = 'Stop'

function Read-DotEnv {
    param([string]$Path)
    $values = @{}
    if (!(Test-Path -LiteralPath $Path)) {
        return $values
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (!$trimmed -or $trimmed.StartsWith('#') -or !$trimmed.Contains('=')) {
            continue
        }
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
    if (!(Test-Path -LiteralPath $plink)) {
        throw "PuTTY plink not found at $plink"
    }
    $password = $SshPassword
    if (!$password) {
        $password = $Env['PROXMOX_SSH_PASS']
    }
    if (!$password) {
        $password = $Env['PFSENSE_WEB_PASS']
    }
    if (!$password) {
        throw 'No SSH password found. Pass -SshPassword or set PROXMOX_SSH_PASS/PFSENSE_WEB_PASS in .env.'
    }
    $hostName = if ($Env['PROXMOX_HOST']) { $Env['PROXMOX_HOST'] } else { '192.168.2.200' }
    $hostKey = 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg'
    & $plink -ssh -P 22 -noagent -batch -pw $password -hostkey $hostKey "root@$hostName" $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Remote command failed with exit code $LASTEXITCODE"
    }
}

function Invoke-VelociraptorCollection {
    param(
        [string]$ResolvedClientId,
        [string[]]$ResolvedArtifacts,
        [int]$Timeout,
        [hashtable]$Env
    )

    $artifactArgs = ($ResolvedArtifacts | ForEach-Object { "'$_'" }) -join ' '
    $remoteScript = @"
#!/bin/sh
set -eu
/velociraptor/velociraptor --api_config /tmp/shuffle-investigation-admin-api.yaml artifacts collect --client_id '$ResolvedClientId' --timeout $Timeout --format json $artifactArgs
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remoteScript))
    $remote = "pct exec 200 -- docker exec velociraptor sh -c 'echo $encoded | base64 -d > /tmp/phase2-investigate-run.sh && chmod +x /tmp/phase2-investigate-run.sh && /tmp/phase2-investigate-run.sh'"
    Invoke-ProxmoxCommand -Command $remote -Env $Env
}

function New-TheHiveCase {
    param(
        [hashtable]$Env,
        [string]$Title,
        [string]$Description,
        [string]$EvidencePath,
        [string]$ResolvedClientId
    )
    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = $Env['THEHIVE_PUBLIC_URL']
    if (!$baseUrl) { $baseUrl = $Env['THEHIVE_URL'] }
    if (!$baseUrl) { $baseUrl = 'https://thehive' }
    if (!$apiKey) { throw 'THEHIVE_API_KEY is missing from .env.' }

    $payload = [ordered]@{
        title = $Title
        description = $Description
        severity = 2
        tlp = 2
        pap = 2
        tags = @('phase2', 'investigation-agent', 'velociraptor', "client:$ResolvedClientId")
    }
    $tempPayload = Join-Path $env:TEMP "phase2-thehive-case-$([guid]::NewGuid()).json"
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
    try {
        $response = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/case" -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -InFile $tempPayload
        return $response
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')

if (!$ClientId) {
    $ClientId = if ($Target -eq 'windows') { $envValues['VELO_CLIENT_WINDOWS_ID'] } else { $envValues['VELO_CLIENT_PROXMOX_ID'] }
}
if (!$ClientId) {
    throw "No Velociraptor client ID found for target '$Target'."
}

if ($Artifacts.Count -eq 0) {
    if ($Target -eq 'windows') {
        $Artifacts = @('Generic.Client.Info', 'Windows.System.Pslist', 'Windows.Network.Netstat')
    }
    else {
        $Artifacts = @('Generic.Client.Info')
    }
}

if (!(Test-Path -LiteralPath $EvidenceDir)) {
    New-Item -ItemType Directory -Path $EvidenceDir | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeTarget = $Target.Replace('\', '-').Replace('/', '-')
$evidencePath = Join-Path $EvidenceDir "$timestamp-$safeTarget-$ClientId.jsonl"
$summaryPath = Join-Path $EvidenceDir "$timestamp-$safeTarget-$ClientId-summary.json"

$rawOutput = Invoke-VelociraptorCollection -ResolvedClientId $ClientId -ResolvedArtifacts $Artifacts -Timeout $TimeoutSeconds -Env $envValues
$rawOutput | Set-Content -LiteralPath $evidencePath -Encoding UTF8

$events = @()
foreach ($line in $rawOutput) {
    if (!$line.Trim().StartsWith('{')) { continue }
    try { $events += ($line | ConvertFrom-Json) } catch { }
}

$bySource = @{}
foreach ($event in $events) {
    $source = if ($event._Source) { [string]$event._Source } else { 'unknown' }
    if (!$bySource.ContainsKey($source)) { $bySource[$source] = 0 }
    $bySource[$source]++
}

$basic = $events | Where-Object { $_._Source -eq 'Generic.Client.Info/BasicInformation' } | Select-Object -First 1
$hostName = if ($basic.Hostname) { $basic.Hostname } elseif ($Target -eq 'windows') { $envValues['VELO_CLIENT_WINDOWS_HOST'] } else { $envValues['VELO_CLIENT_PROXMOX_HOST'] }
$platform = if ($basic.Platform) { $basic.Platform } elseif ($basic.OS) { $basic.OS } else { $Target }

$summary = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    target = $Target
    client_id = $ClientId
    hostname = $hostName
    platform = $platform
    artifacts = $Artifacts
    total_events = $events.Count
    events_by_source = $bySource
    evidence_path = (Resolve-Path -LiteralPath $evidencePath).Path
}

$case = $null
if ($CreateTheHiveCase) {
    if (!$CaseTitle) { $CaseTitle = "[Phase 2] Investigation Agent evidence for $hostName" }
    $description = @"
## Phase 2 Investigation Agent Evidence

**Target:** $Target
**Host:** $hostName
**Velociraptor client:** $ClientId
**Artifacts:** $($Artifacts -join ', ')
**Evidence file:** $((Resolve-Path -LiteralPath $evidencePath).Path)
**Event count:** $($events.Count)

This case was created by `scripts/phase2-investigation.ps1`. Velociraptor actions were read-only.
"@
    $case = New-TheHiveCase -Env $envValues -Title $CaseTitle -Description $description -EvidencePath $evidencePath -ResolvedClientId $ClientId
    $summary['thehive_case_id'] = $case.id
    $summary['thehive_case_number'] = $case.caseId
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

[pscustomobject]@{
    Target = $Target
    ClientId = $ClientId
    Hostname = $hostName
    Platform = $platform
    EventCount = $events.Count
    EvidencePath = (Resolve-Path -LiteralPath $evidencePath).Path
    SummaryPath = (Resolve-Path -LiteralPath $summaryPath).Path
    TheHiveCaseId = if ($case) { $case.id } else { $null }
    TheHiveCaseNumber = if ($case) { $case.caseId } else { $null }
}
