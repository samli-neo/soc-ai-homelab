param(
    [string]$OutputDir = '.\phase8-evidence',
    [string]$Root = '.'
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

function Test-PathItem {
    param([string]$Path)
    [ordered]@{ path = $Path; exists = (Test-Path -LiteralPath (Join-Path $Root $Path)) }
}

function Get-LatestPath {
    param([string]$Pattern)
    $fullPattern = Join-Path $Root $Pattern
    $files = @(Get-ChildItem -Path $fullPattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($files.Count -eq 0) { return $null }
    return $files[0].FullName
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Recommendation
    )
    $List.Add([ordered]@{
        severity = $Severity
        title = $Title
        detail = $Detail
        recommendation = $Recommendation
    })
}

if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$envPath = Join-Path $Root '.env'
$envValues = Read-DotEnv -Path $envPath
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $OutputDir "$timestamp-hardening-audit.json"
$mdPath = Join-Path $OutputDir "$timestamp-hardening-audit.md"

$requiredScripts = @(
    'scripts\phase1-triage-orchestrator.ps1',
    'scripts\phase2-investigation.ps1',
    'scripts\phase3-malware-analysis.ps1',
    'scripts\phase4-threat-intel.ps1',
    'scripts\phase5-incident-response.ps1',
    'scripts\phase6-threat-hunt.ps1',
    'scripts\phase7-reporting-qa.ps1'
)
$requiredRunbooks = @(
    'shuffle\triage-agent-openrouter.md',
    'shuffle\investigation-agent-velociraptor.md',
    'shuffle\malware-analysis-agent-capev2.md',
    'shuffle\threat-intel-agent-misp-wazuh.md',
    'shuffle\incident-response-agent-approval.md',
    'shuffle\threat-hunting-agent-velociraptor.md',
    'shuffle\reporting-qa-agent-ciso.md'
)
$requiredEvidencePatterns = @(
    'phase1-evidence\*-triage-summary.json',
    'phase2-evidence\*-summary.json',
    'phase3-evidence\*-summary.json',
    'phase4-evidence\*-threat-intel-summary.json',
    'phase5-evidence\*-incident-response-plan.json',
    'phase6-evidence\*-threat-hunt-summary.json',
    'phase7-evidence\*-reporting-qa-summary.json'
)

$findings = New-Object System.Collections.Generic.List[object]
$scriptChecks = @($requiredScripts | ForEach-Object { Test-PathItem -Path $_ })
$runbookChecks = @($requiredRunbooks | ForEach-Object { Test-PathItem -Path $_ })
$evidenceChecks = @($requiredEvidencePatterns | ForEach-Object {
    $latest = Get-LatestPath -Pattern $_
    [ordered]@{ pattern = $_; latest = $latest; exists = [bool]$latest }
})

foreach ($check in @($scriptChecks + $runbookChecks)) {
    if (!$check.exists) {
        Add-Finding -List $findings -Severity 'high' -Title 'Missing automation artifact' -Detail $check.path -Recommendation 'Restore or recreate the missing script/runbook before relying on the automation chain.'
    }
}
foreach ($check in $evidenceChecks) {
    if (!$check.exists) {
        Add-Finding -List $findings -Severity 'medium' -Title 'Missing verification evidence' -Detail $check.pattern -Recommendation 'Run the corresponding phase verification to regenerate evidence.'
    }
}

$smtpKeys = @('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM', 'SMTP_ENABLE_SSL')
$smtpPresent = @{}
foreach ($key in $smtpKeys) { $smtpPresent[$key] = [bool]$envValues[$key] }
if ($smtpPresent.Values -contains $false) {
    Add-Finding -List $findings -Severity 'medium' -Title 'SMTP configuration incomplete' -Detail 'One or more SMTP_* keys are missing from .env.' -Recommendation 'Complete Gmail SMTP configuration before scheduled Phase 7 email sends.'
}

if (Test-Path -LiteralPath $envPath) {
    Add-Finding -List $findings -Severity 'high' -Title '.env contains live secrets' -Detail '.env stores SOC credentials and Gmail SMTP app password.' -Recommendation 'Keep .env untracked, restrict filesystem access, and rotate credentials if this repo is ever shared.'
}

$gitignorePath = Join-Path $Root '.gitignore'
$gitignoreHasEnv = $false
if (Test-Path -LiteralPath $gitignorePath) {
    $gitignoreHasEnv = [bool](@(Get-Content -LiteralPath $gitignorePath | Where-Object { $_.Trim() -in @('.env', '*.env') }).Count)
}
if (!$gitignoreHasEnv) {
    Add-Finding -List $findings -Severity 'high' -Title '.env is not explicitly ignored' -Detail '.gitignore does not contain .env or *.env.' -Recommendation 'Add .env to .gitignore before any commit operation.'
}

$dirtySecretCandidates = @(Get-ChildItem -Path $Root -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\.git\\' -and
        $_.FullName -notmatch '\\.venv\\' -and
        $_.Length -lt 5MB -and
        $_.Name -match '(\.env$|credential|secret|password|token|key|login)'
    } |
    Select-Object -First 50 -ExpandProperty FullName)
if ($dirtySecretCandidates.Count -gt 0) {
    Add-Finding -List $findings -Severity 'medium' -Title 'Secret-like files present' -Detail ($dirtySecretCandidates -join '; ') -Recommendation 'Review secret-like files before commits or backups. Do not print or share their contents.'
}

$phaseStatus = [ordered]@{
    phase1 = 'complete'
    phase2 = 'complete'
    phase3 = 'complete'
    phase4 = 'complete'
    phase5 = 'started_proposal_only'
    phase6 = 'complete_read_only'
    phase7 = 'complete_smtp_verified'
    phase8 = 'audit_generated'
}

$highCount = @($findings | Where-Object { $_.severity -eq 'high' }).Count
$mediumCount = @($findings | Where-Object { $_.severity -eq 'medium' }).Count
$lowCount = @($findings | Where-Object { $_.severity -eq 'low' }).Count

$audit = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    root = (Resolve-Path -LiteralPath $Root).Path
    phase_status = $phaseStatus
    scripts = $scriptChecks
    runbooks = $runbookChecks
    evidence = $evidenceChecks
    smtp_configured = -not ($smtpPresent.Values -contains $false)
    smtp_keys_present = $smtpPresent
    findings = $findings.ToArray()
    finding_counts = [ordered]@{ high = $highCount; medium = $mediumCount; low = $lowCount; total = $findings.Count }
    residual_risks = @(
        'Phase 5 live containment adapters remain disabled until safe isolation/rollback tests are complete.',
        'Cortex analyzers are not configured yet.',
        'Secrets are stored locally in .env and must not be committed or shared.'
    )
}

$findingLines = @($findings | ForEach-Object { "- [$($_.severity)] $($_.title): $($_.detail) Recommendation: $($_.recommendation)" })
if ($findingLines.Count -eq 0) { $findingLines = @('- No findings.') }
$evidenceLines = @($evidenceChecks | ForEach-Object { "- $($_.pattern): $(if ($_.exists) { $_.latest } else { 'missing' })" })
$markdownLines = New-Object System.Collections.Generic.List[string]
@(
    "# Phase 8 Hardening Audit - $timestamp",
    '',
    '## Summary',
    '',
    "- High findings: $highCount",
    "- Medium findings: $mediumCount",
    "- Low findings: $lowCount",
    "- SMTP configured: $($audit.smtp_configured)",
    '',
    '## Phase Status',
    ''
) | ForEach-Object { $markdownLines.Add($_) }
$phaseStatus.GetEnumerator() | ForEach-Object { $markdownLines.Add("- $($_.Key): $($_.Value)") }
@('', '## Latest Evidence', '') | ForEach-Object { $markdownLines.Add($_) }
$evidenceLines | ForEach-Object { $markdownLines.Add($_) }
@('', '## Findings', '') | ForEach-Object { $markdownLines.Add($_) }
$findingLines | ForEach-Object { $markdownLines.Add($_) }
@('', '## Residual Risks', '') | ForEach-Object { $markdownLines.Add($_) }
$audit.residual_risks | ForEach-Object { $markdownLines.Add("- $_") }
$markdown = $markdownLines.ToArray() -join [Environment]::NewLine

$audit | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$markdown | Set-Content -LiteralPath $mdPath -Encoding UTF8

[pscustomobject]@{
    JsonPath = (Resolve-Path -LiteralPath $jsonPath).Path
    MarkdownPath = (Resolve-Path -LiteralPath $mdPath).Path
    HighFindings = $highCount
    MediumFindings = $mediumCount
    LowFindings = $lowCount
    SmtpConfigured = $audit.smtp_configured
}
