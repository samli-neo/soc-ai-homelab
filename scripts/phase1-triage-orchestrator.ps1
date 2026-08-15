param(
    [string]$AlertPath = '.\samples\phase1-wazuh-alert-misp-hash.json',
    [string]$OutputDir = '.\phase1-evidence',
    [switch]$CreateTheHiveCase,
    [switch]$UseOpenRouter,
    [string]$MispUrl = '',
    [string]$MispApiKey = ''
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

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )
    if (!$Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if (!$property) { return $Default }
    if ($null -eq $property.Value) { return $Default }
    return $property.Value
}

function Get-MispType {
    param([string]$Kind, [string]$Value)
    if ($Kind -eq 'ip') { return 'ip-src' }
    if ($Kind -eq 'domain') { return 'domain' }
    if ($Kind -eq 'hash') {
        if ($Value.Length -eq 32) { return 'md5' }
        if ($Value.Length -eq 40) { return 'sha1' }
        return 'sha256'
    }
    return $Kind
}

function Add-Observable {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Kind,
        [string]$Value
    )
    if (!$Value -or $Value -in @('null', 'None')) { return }
    $clean = $Value.Trim()
    if (!$clean) { return }
    $mispType = Get-MispType -Kind $Kind -Value $clean
    $key = "$Kind|$clean"
    foreach ($item in $List) {
        if ($item.key -eq $key) { return }
    }
    $List.Add([ordered]@{ key = $key; type = $Kind; misp_type = $mispType; value = $clean })
}

function ConvertTo-NormalizedAlert {
    param([object]$Alert)
    $rule = Get-PropertyValue -Object $Alert -Name 'rule' -Default ([pscustomobject]@{})
    $agent = Get-PropertyValue -Object $Alert -Name 'agent' -Default ([pscustomobject]@{})
    $data = Get-PropertyValue -Object $Alert -Name 'data' -Default ([pscustomobject]@{})
    $level = [int](Get-PropertyValue -Object $rule -Name 'level' -Default 0)
    $observables = New-Object System.Collections.Generic.List[object]

    Add-Observable -List $observables -Kind 'ip' -Value ([string](Get-PropertyValue -Object $data -Name 'srcip' -Default (Get-PropertyValue -Object $data -Name 'src_ip' -Default '')))
    Add-Observable -List $observables -Kind 'ip' -Value ([string](Get-PropertyValue -Object $data -Name 'dstip' -Default (Get-PropertyValue -Object $data -Name 'dst_ip' -Default '')))
    Add-Observable -List $observables -Kind 'domain' -Value ([string](Get-PropertyValue -Object $data -Name 'domain' -Default ''))
    Add-Observable -List $observables -Kind 'domain' -Value ([string](Get-PropertyValue -Object $data -Name 'url' -Default ''))
    Add-Observable -List $observables -Kind 'hash' -Value ([string](Get-PropertyValue -Object $data -Name 'md5' -Default ''))
    Add-Observable -List $observables -Kind 'hash' -Value ([string](Get-PropertyValue -Object $data -Name 'sha1' -Default ''))
    Add-Observable -List $observables -Kind 'hash' -Value ([string](Get-PropertyValue -Object $data -Name 'sha256' -Default ''))

    [ordered]@{
        alert_id = Get-PropertyValue -Object $Alert -Name 'id' -Default ''
        timestamp = Get-PropertyValue -Object $Alert -Name 'timestamp' -Default (Get-Date).ToString('o')
        rule_id = Get-PropertyValue -Object $rule -Name 'id' -Default ''
        rule_level = $level
        rule_description = Get-PropertyValue -Object $rule -Name 'description' -Default 'Wazuh alert'
        severity = if ($level -ge 13) { 'critical' } elseif ($level -ge 10) { 'high' } elseif ($level -ge 7) { 'medium' } else { 'low' }
        thehive_severity = if ($level -ge 10) { 3 } elseif ($level -ge 7) { 2 } else { 1 }
        agent_id = Get-PropertyValue -Object $agent -Name 'id' -Default ''
        agent_name = Get-PropertyValue -Object $agent -Name 'name' -Default ''
        agent_ip = Get-PropertyValue -Object $agent -Name 'ip' -Default ''
        location = Get-PropertyValue -Object $Alert -Name 'location' -Default ''
        full_log = Get-PropertyValue -Object $Alert -Name 'full_log' -Default ''
        observables = $observables.ToArray()
        primary_observable = if ($observables.Count -gt 0) { $observables[0] } else { $null }
    }
}

function Invoke-MispSearch {
    param(
        [string]$BaseUrl,
        [string]$ApiKey,
        [object[]]$Observables
    )
    $results = New-Object System.Collections.Generic.List[object]
    if (!$ApiKey) { return $results.ToArray() }
    foreach ($observable in $Observables) {
        $payload = [ordered]@{ returnFormat = 'json'; value = $observable.value; type = $observable.misp_type; limit = 10 }
        $tempPayload = Join-Path $env:TEMP "phase1-misp-$([guid]::NewGuid()).json"
        $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
        try {
            $response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/attributes/restSearch" -Headers @{ Authorization = $ApiKey; Accept = 'application/json' } -ContentType 'application/json' -InFile $tempPayload
            $attributes = @()
            if ($response.response.Attribute) {
                $attributes = @($response.response.Attribute)
            }
            elseif ($response.Attribute) {
                $attributes = @($response.Attribute)
            }
            elseif ($response.response) {
                foreach ($item in @($response.response)) {
                    if ($item.Attribute) { $attributes += @($item.Attribute) }
                    elseif ($item.id -and $item.value) { $attributes += $item }
                }
            }
            $attributes = @($attributes | Where-Object { $_ -and $_.id -and $_.value })
            $results.Add([ordered]@{ observable = $observable; matched = ($attributes.Count -gt 0); match_count = $attributes.Count; attributes = $attributes })
        }
        catch {
            $results.Add([ordered]@{ observable = $observable; matched = $false; match_count = 0; error = $_.Exception.Message })
        }
        finally {
            Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
        }
    }
    return $results.ToArray()
}

function Get-DeterministicTriage {
    param([object]$Alert, [object[]]$MispResults)
    $mispMatches = @($MispResults | Where-Object { $_.matched })
    $level = [int]$Alert.rule_level
    $verdict = 'monitor'
    $severity = $Alert.severity
    $confidence = 0.72
    $caseRequired = $false
    $humanRequired = $false
    $actions = New-Object System.Collections.Generic.List[string]
    $reason = "Rule level $level alert reviewed with $($MispResults.Count) observable enrichment checks."

    if ($mispMatches.Count -gt 0 -and $level -ge 10) {
        $verdict = 'critical'
        $severity = 'critical'
        $confidence = 0.92
        $caseRequired = $true
        $humanRequired = $true
        $reason = "High-severity Wazuh alert includes observable(s) matching MISP intelligence."
        $actions.Add('Create TheHive case')
        $actions.Add('Start Investigation Agent')
        $actions.Add('Pre-stage Incident Response approval; do not auto-contain')
    }
    elseif ($mispMatches.Count -gt 0 -or $level -ge 10) {
        $verdict = 'investigate'
        $severity = if ($level -ge 10) { 'high' } else { 'medium' }
        $confidence = 0.85
        $caseRequired = $true
        $humanRequired = $false
        $reason = "Alert has either high Wazuh severity or MISP enrichment context."
        $actions.Add('Create TheHive case')
        $actions.Add('Start Investigation Agent')
    }
    elseif ($level -ge 7) {
        $verdict = 'investigate'
        $severity = 'medium'
        $confidence = 0.76
        $caseRequired = $true
        $reason = "Medium severity Wazuh alert should be investigated because enrichment is limited."
        $actions.Add('Create TheHive case')
    }
    else {
        $verdict = 'monitor'
        $severity = 'low'
        $confidence = 0.74
        $caseRequired = $false
        $reason = "Low severity alert with no MISP match; monitor rather than close as false positive."
        $actions.Add('Record metric only')
    }

    [ordered]@{
        verdict = $verdict
        confidence = $confidence
        severity = $severity
        reasoning = $reason
        recommended_actions = $actions.ToArray()
        case_required = $caseRequired
        human_required = $humanRequired
        source = 'deterministic'
        misp_match_count = $mispMatches.Count
    }
}

function Invoke-OpenRouterTriage {
    param([hashtable]$Env, [object]$Alert, [object[]]$MispResults, [object]$Fallback)
    if (!$Env['OPENROUTER_API_KEY']) { return $Fallback }
    $body = [ordered]@{
        model = if ($Env['OPENROUTER_MODEL']) { $Env['OPENROUTER_MODEL'] } else { 'qwen/qwen3-next-80b-a3b-instruct:free' }
        response_format = [ordered]@{ type = 'json_object' }
        temperature = 0.1
        max_tokens = 700
        messages = @(
            [ordered]@{ role = 'system'; content = 'You are a Tier 1 SOC analyst. Use only the provided Wazuh alert and MISP enrichment. Return strict JSON with verdict, confidence, severity, reasoning, recommended_actions, case_required, human_required. If enrichment is missing or failed, never return false_positive.' },
            [ordered]@{ role = 'user'; content = (@{ alert = $Alert; misp = $MispResults } | ConvertTo-Json -Depth 12 -Compress) }
        )
    }
    $tempPayload = Join-Path $env:TEMP "phase1-openrouter-$([guid]::NewGuid()).json"
    $body | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tempPayload -Encoding UTF8
    try {
        $response = Invoke-RestMethod -Method Post -Uri "$($Env['OPENROUTER_BASE_URL'])/chat/completions" -Headers @{ Authorization = "Bearer $($Env['OPENROUTER_API_KEY'])"; 'Content-Type' = 'application/json'; 'HTTP-Referer' = 'https://shuffle'; 'X-Title' = 'SOC Homelab Triage Agent' } -ContentType 'application/json' -InFile $tempPayload
        $content = [string]$response.choices[0].message.content
        $json = $content | ConvertFrom-Json
        return [ordered]@{
            verdict = [string]$json.verdict
            confidence = [double]$json.confidence
            severity = [string]$json.severity
            reasoning = [string]$json.reasoning
            recommended_actions = @($json.recommended_actions)
            case_required = [bool]$json.case_required
            human_required = [bool]$json.human_required
            source = 'openrouter'
            fallback = $Fallback
        }
    }
    catch {
        $Fallback['llm_error'] = $_.Exception.Message
        return $Fallback
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

function New-TheHiveCase {
    param([hashtable]$Env, [object]$Alert, [object]$Triage, [string]$SummaryPath)
    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = if ($Env['THEHIVE_PUBLIC_URL']) { $Env['THEHIVE_PUBLIC_URL'] } elseif ($Env['THEHIVE_URL']) { $Env['THEHIVE_URL'] } else { 'https://thehive' }
    if (!$apiKey) { throw 'THEHIVE_API_KEY is missing from .env.' }
    $payload = [ordered]@{
        title = "[Phase 1] $($Triage.verdict): $($Alert.rule_description)"
        description = @"
## Phase 1 Orchestrator/Triage Agent

**Verdict:** $($Triage.verdict)
**Confidence:** $($Triage.confidence)
**Severity:** $($Triage.severity)
**Reasoning:** $($Triage.reasoning)
**Wazuh rule:** $($Alert.rule_id) / level $($Alert.rule_level)
**Agent:** $($Alert.agent_name) ($($Alert.agent_id), $($Alert.agent_ip))
**Summary:** $SummaryPath

No containment action was executed. Use Phase 2 for investigation and Phase 5 for approval-gated response.
"@
        severity = if ($Triage.severity -eq 'critical') { 4 } elseif ($Triage.severity -eq 'high') { 3 } elseif ($Triage.severity -eq 'medium') { 2 } else { 1 }
        tlp = 2
        pap = 2
        tags = @('phase1', 'triage-agent', 'orchestrator', "verdict:$($Triage.verdict)", "source:$($Triage.source)")
    }
    $tempPayload = Join-Path $env:TEMP "phase1-thehive-case-$([guid]::NewGuid()).json"
    $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/case" -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -InFile $tempPayload
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')
if (!$MispUrl) { $MispUrl = if ($envValues['MISP_URL']) { $envValues['MISP_URL'] } else { 'https://misp' } }
if (!$MispApiKey) { $MispApiKey = $envValues['MISP_API_KEY'] }
$MispUrl = $MispUrl.TrimEnd('/').Replace('https://misp:443', 'https://misp')
if (!(Test-Path -LiteralPath $AlertPath)) { throw "Alert file not found: $AlertPath" }
if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$alert = Get-Content -LiteralPath $AlertPath -Raw | ConvertFrom-Json
$normalized = ConvertTo-NormalizedAlert -Alert $alert
$mispResults = Invoke-MispSearch -BaseUrl $MispUrl -ApiKey $MispApiKey -Observables $normalized.observables
$deterministic = Get-DeterministicTriage -Alert ([pscustomobject]$normalized) -MispResults $mispResults
$triage = if ($UseOpenRouter) { Invoke-OpenRouterTriage -Env $envValues -Alert ([pscustomobject]$normalized) -MispResults $mispResults -Fallback $deterministic } else { $deterministic }
if ([double]$triage.confidence -lt 0.70) { $triage.human_required = $true; $triage.case_required = $true }

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$summaryPath = Join-Path $OutputDir "$timestamp-triage-summary.json"
$case = $null
$summary = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    alert_path = (Resolve-Path -LiteralPath $AlertPath).Path
    normalized_alert = $normalized
    misp = [ordered]@{ url = $MispUrl; checks = $mispResults; matched_observables = @($mispResults | Where-Object { $_.matched }).Count }
    triage = $triage
    routing = [ordered]@{
        create_thehive_case = [bool]$triage.case_required
        start_investigation_agent = $triage.verdict -in @('investigate', 'critical')
        prestage_incident_response = $triage.verdict -eq 'critical'
        notify_ciso = $triage.verdict -eq 'critical'
    }
}

if ($CreateTheHiveCase -and $triage.case_required) {
    $case = New-TheHiveCase -Env $envValues -Alert ([pscustomobject]$normalized) -Triage ([pscustomobject]$triage) -SummaryPath (Join-Path (Resolve-Path -LiteralPath $OutputDir).Path (Split-Path -Leaf $summaryPath))
    $summary['thehive_case_id'] = $case.id
    $summary['thehive_case_number'] = $case.caseId
}

$summary | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

[pscustomobject]@{
    AlertId = $normalized.alert_id
    Verdict = $triage.verdict
    Confidence = $triage.confidence
    Severity = $triage.severity
    MispMatches = $summary.misp.matched_observables
    CaseRequired = $triage.case_required
    HumanRequired = $triage.human_required
    SummaryPath = (Resolve-Path -LiteralPath $summaryPath).Path
    TheHiveCaseId = if ($case) { $case.id } else { $null }
    TheHiveCaseNumber = if ($case) { $case.caseId } else { $null }
}
