param(
    [string]$EvidenceRoot = '.',
    [string]$OutputDir = '.\phase7-evidence',
    [string]$CisoEmail = '',
    [switch]$SendEmail,
    [switch]$CreateTheHiveCase
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

function Read-JsonFile {
    param([string]$Path)
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
    catch { return $null }
}

function Get-LatestFile {
    param([string]$Pattern)
    $files = @(Get-ChildItem -Path $EvidenceRoot -Filter $Pattern -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($files.Count -eq 0) { return $null }
    return $files[0].FullName
}

function Get-LatestJsonFileWithProperty {
    param(
        [string]$Pattern,
        [string]$PropertyName
    )
    $files = @(Get-ChildItem -Path $EvidenceRoot -Filter $Pattern -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    foreach ($file in $files) {
        $json = Read-JsonFile -Path $file.FullName
        if ($json -and $json.PSObject.Properties[$PropertyName] -and $json.PSObject.Properties[$PropertyName].Value) {
            return $file.FullName
        }
    }
    if ($files.Count -eq 0) { return $null }
    return $files[0].FullName
}

function Get-JsonValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )
    if (!$Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if (!$property) { return $Default }
    return $property.Value
}

function New-TheHiveCase {
    param(
        [hashtable]$Env,
        [object]$Report,
        [string]$MarkdownPath
    )

    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = $Env['THEHIVE_PUBLIC_URL']
    if (!$baseUrl) { $baseUrl = $Env['THEHIVE_URL'] }
    if (!$baseUrl) { $baseUrl = 'https://thehive' }
    if (!$apiKey) { throw 'THEHIVE_API_KEY is missing from .env.' }

    $payload = [ordered]@{
        title = "[Phase 7] Reporting/QA Agent digest $($Report.report_date)"
        description = @"
## Phase 7 Reporting/QA Digest

**Report file:** $MarkdownPath
**Cases referenced:** $($Report.metrics.thehive_cases_referenced)
**Automation phases summarized:** $($Report.metrics.completed_or_started_phases)
**Open follow-ups:** $($Report.follow_ups.Count)
**Email mode:** $($Report.email.mode)

$($Report.executive_summary)

Generated email draft: $($Report.email.draft_path)
"@
        severity = if ($Report.metrics.high_or_critical_items -gt 0) { 2 } else { 1 }
        tlp = 2
        pap = 2
        tags = @('phase7', 'reporting-qa-agent', 'digest', 'email-draft-only')
    }

    $tempPayload = Join-Path $env:TEMP "phase7-thehive-case-$([guid]::NewGuid()).json"
    $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/case" -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -InFile $tempPayload
    }
    finally {
        Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
    }
}

function Send-SmtpDigest {
    param(
        [hashtable]$Env,
        [string]$To,
        [string]$Subject,
        [string]$Body
    )
    foreach ($name in @('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM')) {
        if (!$Env[$name]) { throw "$name is required for -SendEmail." }
    }
    $securePassword = ConvertTo-SecureString $Env['SMTP_PASS'] -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($Env['SMTP_USER'], $securePassword)
    Send-MailMessage -SmtpServer $Env['SMTP_HOST'] -Port ([int]$Env['SMTP_PORT']) -UseSsl -Credential $credential -From $Env['SMTP_FROM'] -To $To -Subject $Subject -Body $Body
}

function Get-TheHiveCase {
    param(
        [hashtable]$Env,
        [string]$CaseId
    )
    if (!$CaseId) { return $null }
    $apiKey = $Env['THEHIVE_API_KEY']
    $baseUrl = $Env['THEHIVE_PUBLIC_URL']
    if (!$baseUrl) { $baseUrl = $Env['THEHIVE_URL'] }
    if (!$baseUrl) { $baseUrl = 'https://thehive' }
    if (!$apiKey) { return $null }
    try {
        return Invoke-RestMethod -Method Get -Uri "$baseUrl/api/case/$CaseId" -Headers @{ Authorization = "Bearer $apiKey" }
    }
    catch { return $null }
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')
if (!$CisoEmail) { $CisoEmail = $envValues['CISO_EMAIL'] }
if (!$CisoEmail) { $CisoEmail = 'salim.hadda@outlook.com' }
if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$phase2Path = Get-LatestJsonFileWithProperty -Pattern '*-windows-*-summary.json' -PropertyName 'thehive_case_id'
$phase3Path = Get-LatestJsonFileWithProperty -Pattern '*cape-task-12-summary.json' -PropertyName 'thehive_case_id'
$phase4Path = Get-LatestFile -Pattern '*threat-intel-summary.json'
$phase5Path = Get-LatestFile -Pattern '*incident-response-plan.json'
$phase6Path = Get-LatestFile -Pattern '*threat-hunt-summary.json'

$phase2 = Read-JsonFile -Path $phase2Path
$phase3 = Read-JsonFile -Path $phase3Path
$phase4 = Read-JsonFile -Path $phase4Path
$phase5 = Read-JsonFile -Path $phase5Path
$phase6 = Read-JsonFile -Path $phase6Path

$caseRefs = New-Object System.Collections.Generic.List[object]
foreach ($item in @(
    @{ phase = 'phase2'; id = Get-JsonValue -Object $phase2 -Name 'thehive_case_id'; number = Get-JsonValue -Object $phase2 -Name 'thehive_case_number' },
    @{ phase = 'phase3'; id = Get-JsonValue -Object $phase3 -Name 'thehive_case_id'; number = Get-JsonValue -Object $phase3 -Name 'thehive_case_number' },
    @{ phase = 'phase5'; id = Get-JsonValue -Object $phase5 -Name 'thehive_approval_case_id'; number = Get-JsonValue -Object $phase5 -Name 'thehive_approval_case_number' },
    @{ phase = 'phase6'; id = Get-JsonValue -Object $phase6 -Name 'thehive_case_id'; number = Get-JsonValue -Object $phase6 -Name 'thehive_case_number' }
)) {
    if ($item.id -or $item.number) { $caseRefs.Add([ordered]@{ phase = $item.phase; id = $item.id; number = $item.number }) }
}

$theHiveReadbacks = New-Object System.Collections.Generic.List[object]
foreach ($caseRef in $caseRefs) {
    $case = Get-TheHiveCase -Env $envValues -CaseId $caseRef.id
    if ($case) {
        $theHiveReadbacks.Add([ordered]@{
            phase = $caseRef.phase
            id = $case._id
            case_number = $case.caseId
            title = $case.title
            severity = $case.severity
            tags = $case.tags
        })
    }
}

$followUps = New-Object System.Collections.Generic.List[string]
if ((Get-JsonValue -Object $phase5 -Name 'executed_actions' -Default @()).Count -eq 0) { $followUps.Add('Phase 5 containment adapters remain disabled; choose and test Velociraptor isolation or Wazuh active response before enabling execution.') }
if ((Get-JsonValue -Object $phase4 -Name 'hash_indicators' -Default 0) -gt 0 -and (Get-JsonValue -Object $phase6 -Name 'high_hits' -Default 0) -eq 0) { $followUps.Add('Current MISP hash IOC is deployed and did not appear in the latest read-only hunt output.') }
if ($envValues['CISO_EMAIL'] -and !$envValues['SMTP_HOST']) { $followUps.Add('CISO email recipient is configured, but SMTP/Shuffle Email sending is not verified; keep Phase 7 in draft-only mode.') }
if (!$phase3 -or (Get-JsonValue -Object $phase3 -Name 'verdict') -eq 'pending') { $followUps.Add('Some CAPEv2 submissions may remain pending; use reported CAPEv2 tasks for final incident reports.') }

$completedOrStarted = @('Phase 2', 'Phase 3', 'Phase 4', 'Phase 5', 'Phase 6')
$highOrCriticalItems = 0
if ((Get-JsonValue -Object $phase5 -Name 'severity') -in @('high', 'critical')) { $highOrCriticalItems++ }
if ((Get-JsonValue -Object $phase6 -Name 'high_hits' -Default 0) -gt 0) { $highOrCriticalItems++ }

$reportDate = Get-Date -Format 'yyyy-MM-dd'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $OutputDir "$timestamp-reporting-qa-summary.json"
$mdPath = Join-Path $OutputDir "$timestamp-reporting-qa-digest.md"
$emailPath = Join-Path $OutputDir "$timestamp-ciso-email-draft.txt"

$emailStatusSentence = if ($SendEmail) {
    'This digest was sent through the configured Gmail SMTP path.'
}
elseif ($envValues['SMTP_HOST']) {
    'SMTP is configured; run with -SendEmail to deliver this digest.'
}
else {
    'Email delivery remains draft-only until SMTP/Shuffle Email is verified.'
}
$executiveSummary = "SOC automation now has verified runners for investigation, malware analysis, threat intelligence deployment, approval-gated incident response planning, and read-only threat hunting. Latest hunt found no high or medium severity leads; one low-severity PowerShell lead was retained for context. $emailStatusSentence"

$report = [ordered]@{
    report_date = $reportDate
    generated_at = (Get-Date).ToString('o')
    ciso_email = $CisoEmail
    executive_summary = $executiveSummary
    evidence_sources = [ordered]@{
        phase2 = $phase2Path
        phase3 = $phase3Path
        phase4 = $phase4Path
        phase5 = $phase5Path
        phase6 = $phase6Path
    }
    metrics = [ordered]@{
        completed_or_started_phases = $completedOrStarted.Count
        thehive_cases_referenced = $caseRefs.Count
        thehive_cases_read_back = $theHiveReadbacks.Count
        phase2_events = Get-JsonValue -Object $phase2 -Name 'total_events' -Default 0
        phase3_verdict = Get-JsonValue -Object $phase3 -Name 'verdict' -Default 'unknown'
        phase3_malscore = Get-JsonValue -Object $phase3 -Name 'malscore' -Default $null
        phase4_indicators = Get-JsonValue -Object $phase4 -Name 'indicators_total' -Default 0
        phase6_events = Get-JsonValue -Object $phase6 -Name 'total_events' -Default 0
        phase6_hits = Get-JsonValue -Object $phase6 -Name 'total_hits' -Default 0
        phase6_high_hits = Get-JsonValue -Object $phase6 -Name 'high_hits' -Default 0
        phase6_medium_hits = Get-JsonValue -Object $phase6 -Name 'medium_hits' -Default 0
        high_or_critical_items = $highOrCriticalItems
    }
    thehive_cases = $caseRefs.ToArray()
    thehive_readbacks = $theHiveReadbacks.ToArray()
    follow_ups = $followUps.ToArray()
    email = [ordered]@{
        mode = if ($SendEmail) { 'send-requested' } else { 'draft-only' }
        to = $CisoEmail
        subject = "[SOC] Automation digest $reportDate - no high/medium hunt hits"
        draft_path = (Join-Path (Resolve-Path -LiteralPath $OutputDir).Path (Split-Path -Leaf $emailPath))
    }
}

$caseLines = @($theHiveReadbacks | ForEach-Object { "- $($_.phase): case #$($_.case_number), id $($_.id), severity $($_.severity), $($_.title)" })
if ($caseLines.Count -eq 0) { $caseLines = @('- No TheHive cases were read back.') }
$followUpLines = @($followUps | ForEach-Object { "- $_" })
if ($followUpLines.Count -eq 0) { $followUpLines = @('- No follow-ups identified.') }

$markdownLines = New-Object System.Collections.Generic.List[string]
@(
    "# SOC Reporting/QA Digest - $reportDate",
    '',
    '## Executive Summary',
    '',
    $executiveSummary,
    '',
    '## Metrics',
    '',
    "- Automation phases summarized: $($report.metrics.completed_or_started_phases)",
    "- TheHive cases referenced: $($report.metrics.thehive_cases_referenced)",
    "- TheHive cases read back: $($report.metrics.thehive_cases_read_back)",
    "- Phase 2 endpoint events: $($report.metrics.phase2_events)",
    "- Phase 3 malware verdict: $($report.metrics.phase3_verdict), malscore $($report.metrics.phase3_malscore)",
    "- Phase 4 indicators deployed: $($report.metrics.phase4_indicators)",
    "- Phase 6 hunt events: $($report.metrics.phase6_events)",
    "- Phase 6 hits: $($report.metrics.phase6_hits), high $($report.metrics.phase6_high_hits), medium $($report.metrics.phase6_medium_hits)",
    '',
    '## TheHive Cases',
    ''
) | ForEach-Object { $markdownLines.Add($_) }
$caseLines | ForEach-Object { $markdownLines.Add($_) }
@('', '## Follow-Ups', '') | ForEach-Object { $markdownLines.Add($_) }
$followUpLines | ForEach-Object { $markdownLines.Add($_) }
@('', '## Email Status', '', "Mode: $($report.email.mode). Draft path: $emailPath") | ForEach-Object { $markdownLines.Add($_) }
$markdown = $markdownLines.ToArray() -join [Environment]::NewLine

$emailDraft = @(
    "To: $CisoEmail",
    "Subject: [SOC] Automation digest $reportDate - no high/medium hunt hits",
    '',
    $executiveSummary,
    '',
    'Key metrics:',
    "- TheHive cases referenced: $($report.metrics.thehive_cases_referenced)",
    "- Phase 6 hunt events: $($report.metrics.phase6_events)",
    "- Phase 6 high/medium hits: $($report.metrics.phase6_high_hits)/$($report.metrics.phase6_medium_hits)",
    "- Current follow-ups: $($followUps.Count)",
    '',
    "Full local report: $mdPath",
    '',
    "Phase 7 email mode: $(if ($SendEmail) { 'SMTP send requested' } else { $report.email.mode })."
) -join [Environment]::NewLine

if ($SendEmail) {
    Send-SmtpDigest -Env $envValues -To $CisoEmail -Subject $report.email.subject -Body $emailDraft
    $report.email.mode = 'sent'
    $report.email.sent_at = (Get-Date).ToString('o')
    $report.email.smtp_host = $envValues['SMTP_HOST']
}

$case = $null
if ($CreateTheHiveCase) {
    $case = New-TheHiveCase -Env $envValues -Report ([pscustomobject]$report) -MarkdownPath (Join-Path (Resolve-Path -LiteralPath $OutputDir).Path (Split-Path -Leaf $mdPath))
    $report['thehive_reporting_case_id'] = $case.id
    $report['thehive_reporting_case_number'] = $case.caseId
}

$report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$markdown | Set-Content -LiteralPath $mdPath -Encoding UTF8
$emailDraft | Set-Content -LiteralPath $emailPath -Encoding UTF8

[pscustomobject]@{
    ReportDate = $reportDate
    JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    MarkdownPath = (Resolve-Path -LiteralPath $mdPath).Path
    EmailDraftPath = (Resolve-Path -LiteralPath $emailPath).Path
    TheHiveCasesReferenced = $report.metrics.thehive_cases_referenced
    TheHiveCasesReadBack = $report.metrics.thehive_cases_read_back
    FollowUps = $followUps.Count
    EmailMode = $report.email.mode
    TheHiveReportingCaseId = if ($case) { $case.id } else { $null }
    TheHiveReportingCaseNumber = if ($case) { $case.caseId } else { $null }
}
