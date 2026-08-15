param(
    [string]$CaseId = '',
    [string]$CaseNumber = '',
    [ValidateSet('low', 'medium', 'high', 'critical')]
    [string]$Severity = 'high',
    [ValidateSet('malware', 'credential_compromise', 'ioc_match', 'host_compromise', 'manual')]
    [string]$IncidentType = 'manual',
    [string]$HostName = '',
    [string]$VelociraptorClientId = '',
    [string[]]$Iocs = @(),
    [string]$Reason = '',
    [string]$OutputDir = '.\phase5-evidence',
    [switch]$CreateTheHiveApprovalCase,
    [switch]$Execute,
    [string]$ApprovalToken = ''
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

function New-TheHiveCase {
    param(
        [hashtable]$Env,
        [object]$Plan,
        [string]$PlanPath
    )

    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = $Env['THEHIVE_PUBLIC_URL']
    if (!$baseUrl) { $baseUrl = $Env['THEHIVE_URL'] }
    if (!$baseUrl) { $baseUrl = 'https://thehive' }
    if (!$apiKey) { throw 'THEHIVE_API_KEY is missing from .env.' }

    $titleCase = if ($Plan.case_number) { "case $($Plan.case_number)" } elseif ($Plan.case_id) { "case $($Plan.case_id)" } else { 'manual incident' }
    $payload = [ordered]@{
        title = "[Phase 5] Incident Response approval for $titleCase"
        description = @"
## Phase 5 Incident Response Approval

**Source case ID:** $($Plan.case_id)
**Source case number:** $($Plan.case_number)
**Severity:** $($Plan.severity)
**Incident type:** $($Plan.incident_type)
**Host:** $($Plan.host.hostname)
**Velociraptor client:** $($Plan.host.velociraptor_client_id)
**Plan file:** $PlanPath

### Recommended Actions

$($Plan.recommended_actions | ForEach-Object { "- [$($_.risk)] $($_.action): $($_.description)" } | Out-String)

### Approval Requirement

No containment action was executed. To request execution from the local runner after human approval, rerun `scripts/phase5-incident-response.ps1` with `-Execute -ApprovalToken $($Plan.guardrails.required_approval_token)`. Execution adapters are not enabled yet, so the current runner will still refuse live containment and preserve the request as evidence.
"@
        severity = if ($Plan.severity -eq 'critical') { 4 } elseif ($Plan.severity -eq 'high') { 3 } elseif ($Plan.severity -eq 'medium') { 2 } else { 1 }
        tlp = 2
        pap = 2
        tags = @('phase5', 'incident-response-agent', 'approval-required', "severity:$($Plan.severity)", "incident:$($Plan.incident_type)")
    }

    $tempPayload = Join-Path $env:TEMP "phase5-thehive-approval-$([guid]::NewGuid()).json"
    $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/case" -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -InFile $tempPayload
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

function New-RecommendedActions {
    param(
        [string]$ResolvedSeverity,
        [string]$ResolvedIncidentType,
        [string]$ResolvedHostName,
        [string]$ResolvedClientId,
        [string[]]$ResolvedIocs
    )

    $actions = New-Object System.Collections.Generic.List[object]
    $actions.Add([ordered]@{
        id = 'preserve-evidence'
        action = 'Preserve endpoint evidence'
        tool = 'Velociraptor'
        risk = 'low'
        requires_approval = $false
        description = 'Run read-only triage collection before containment changes alter host state.'
        command_hint = if ($ResolvedClientId) { "scripts/phase2-investigation.ps1 -ClientId $ResolvedClientId" } else { 'Map host to Velociraptor client, then run Phase 2 collection.' }
    })

    if ($ResolvedIocs.Count -gt 0) {
        $actions.Add([ordered]@{
            id = 'block-iocs'
            action = 'Block or monitor confirmed IOCs'
            tool = 'Wazuh / firewall'
            risk = 'medium'
            requires_approval = $true
            description = 'Apply blocking or heightened monitoring for confirmed indicators after analyst approval.'
            indicators = $ResolvedIocs
        })
    }

    if ($ResolvedHostName -or $ResolvedClientId) {
        $actions.Add([ordered]@{
            id = 'isolate-host'
            action = 'Isolate affected host'
            tool = 'Velociraptor / Wazuh active response'
            risk = 'high'
            requires_approval = $true
            description = 'Disconnect the endpoint from the network if compromise is confirmed and business impact is accepted.'
            target = [ordered]@{ hostname = $ResolvedHostName; velociraptor_client_id = $ResolvedClientId }
        })
    }

    if ($ResolvedIncidentType -eq 'credential_compromise') {
        $actions.Add([ordered]@{
            id = 'disable-account'
            action = 'Disable or reset affected account'
            tool = 'Identity provider / directory service'
            risk = 'high'
            requires_approval = $true
            description = 'Disable account or force password reset after confirming the affected identity.'
        })
    }

    if ($ResolvedSeverity -in @('high', 'critical')) {
        $actions.Add([ordered]@{
            id = 'notify-stakeholders'
            action = 'Notify stakeholders'
            tool = 'TheHive / email'
            risk = 'low'
            requires_approval = $false
            description = 'Send a concise status update to the SOC owner/CISO with case link, current containment status, and next decision required.'
        })
    }

    return $actions.ToArray()
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')
if (!$HostName -and $envValues['VELO_CLIENT_WINDOWS_HOST']) { $HostName = $envValues['VELO_CLIENT_WINDOWS_HOST'] }
if (!$VelociraptorClientId -and $envValues['VELO_CLIENT_WINDOWS_ID']) { $VelociraptorClientId = $envValues['VELO_CLIENT_WINDOWS_ID'] }
if (!$Reason) { $Reason = 'Manual Phase 5 incident response plan generation.' }

if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$planPath = Join-Path $OutputDir "$timestamp-incident-response-plan.json"
$requiredApprovalToken = "PHASE5-APPROVE-$timestamp"
$recommendedActions = New-RecommendedActions -ResolvedSeverity $Severity -ResolvedIncidentType $IncidentType -ResolvedHostName $HostName -ResolvedClientId $VelociraptorClientId -ResolvedIocs $Iocs

$plan = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    mode = if ($Execute) { 'execute-requested' } else { 'proposal-only' }
    case_id = $CaseId
    case_number = $CaseNumber
    severity = $Severity
    incident_type = $IncidentType
    reason = $Reason
    host = [ordered]@{
        hostname = $HostName
        velociraptor_client_id = $VelociraptorClientId
    }
    indicators = $Iocs
    recommended_actions = $recommendedActions
    guardrails = [ordered]@{
        default_mode = 'proposal-only'
        execution_requires_human_approval = $true
        high_impact_actions = @('isolate-host', 'disable-account')
        required_approval_token = $requiredApprovalToken
    }
    executed_actions = @()
}

if ($Execute) {
    if (!$ApprovalToken) {
        $plan['execution_blocked'] = $true
        $plan['execution_block_reason'] = 'Approval token missing. No containment action was executed.'
        $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $planPath -Encoding UTF8
        throw "Execution blocked. Review $planPath and rerun with -ApprovalToken $requiredApprovalToken after human approval."
    }

    $plan['execution_blocked'] = $true
    $plan['execution_block_reason'] = 'Execution adapters are intentionally not enabled yet. This runner currently supports proposal and approval documentation only.'
}

$approvalCase = $null
if ($CreateTheHiveApprovalCase) {
    $approvalCase = New-TheHiveCase -Env $envValues -Plan ([pscustomobject]$plan) -PlanPath (Join-Path (Resolve-Path -LiteralPath $OutputDir).Path (Split-Path -Leaf $planPath))
    $plan['thehive_approval_case_id'] = $approvalCase.id
    $plan['thehive_approval_case_number'] = $approvalCase.caseId
}

$plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $planPath -Encoding UTF8

[pscustomobject]@{
    Mode = $plan.mode
    Severity = $Severity
    IncidentType = $IncidentType
    HostName = $HostName
    VelociraptorClientId = $VelociraptorClientId
    RecommendedActions = @($recommendedActions).Count
    PlanPath = (Resolve-Path -LiteralPath $planPath).Path
    ApprovalToken = $requiredApprovalToken
    TheHiveApprovalCaseId = if ($approvalCase) { $approvalCase.id } else { $null }
    TheHiveApprovalCaseNumber = if ($approvalCase) { $approvalCase.caseId } else { $null }
}
