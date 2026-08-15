param(
    [string]$Root = '.',
    [string]$ProxmoxHost = '',
    [switch]$SkipWazuhRegression
)

$ErrorActionPreference = 'Stop'

function Read-DotEnv {
    param([string]$Path)
    $values = @{}
    if (!(Test-Path -LiteralPath $Path)) { return $values }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if (!$trimmed -or $trimmed.StartsWith('#') -or !$trimmed.Contains('=')) { continue }
        $name, $value = $trimmed.Split('=', 2)
        $values[$name.Trim()] = $value.Trim()
    }
    return $values
}

function ConvertTo-Base64Utf8 {
    param([string]$Text)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
}

function Invoke-ProxmoxScript {
    param(
        [string]$HostName,
        [string]$Password,
        [string]$Script
    )

    $plink = 'C:\Program Files\PuTTY\plink.exe'
    if (!(Test-Path -LiteralPath $plink)) { throw "plink not found at $plink" }

    $encoded = ConvertTo-Base64Utf8 -Text $Script
    $remote = "echo '$encoded' | base64 -d > /tmp/soc-health-check.sh && sh /tmp/soc-health-check.sh"
    & $plink -ssh -P 22 -noagent -batch -pw $Password -hostkey 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg' "root@$HostName" $remote
    if ($LASTEXITCODE -ne 0) { throw "SOC health check failed with exit code $LASTEXITCODE" }
}

$rootPath = Resolve-Path -LiteralPath $Root
$envValues = Read-DotEnv -Path (Join-Path $rootPath '.env')
if (!$ProxmoxHost) { $ProxmoxHost = if ($envValues['PROXMOX_HOST']) { $envValues['PROXMOX_HOST'] } else { '192.168.2.200' } }
$proxmoxPassword = if ($envValues['PROXMOX_SSH_PASS']) { $envValues['PROXMOX_SSH_PASS'] } else { $envValues['PFSENSE_WEB_PASS'] }
if (!$proxmoxPassword) { throw 'Missing PROXMOX_SSH_PASS or PFSENSE_WEB_PASS in .env' }

$remoteScript = @'
set -eu

run_in_lxc() {
  if command -v docker >/dev/null 2>&1; then
    sh -c "$1"
  else
    pct exec 200 -- sh -lc "$1"
  fi
}

run_in_lxc '
set -eu

failures=0

pass() { printf "PASS %s\n" "$1"; }
fail() { printf "FAIL %s\n" "$1"; failures=$((failures + 1)); }

check_container() {
  name="$1"
  status=$(docker inspect -f "{{.State.Running}}" "$name" 2>/dev/null || true)
  if [ "$status" = "true" ]; then pass "container $name running"; else fail "container $name running"; fi
}

check_http() {
  label="$1"
  url="$2"
  code=$(docker run --rm --network root_soc-net curlimages/curl:8.10.1 -k -s -o /dev/null -w "%{http_code}" --max-time 8 "$url" 2>/dev/null || true)
  case "$code" in
    2*|3*|401|403) pass "$label reachable ($code)" ;;
    *) fail "$label reachable ($code)" ;;
  esac
}

for name in wazuh-manager wazuh-indexer wazuh-dashboard shuffle-backend soc-intake-router soc-report-mailer soc-ir-ai-advisor soc-approval-gateway soc-action-executor soc-ops-dashboard soc-thehive-deduper soc-workflow-watchdog soc-cortex-runner soc-misp-runner soc-capev2-runner soc-velociraptor-runner soc-ghidra-runner soc-malware-pipeline-runner; do
  check_container "$name"
done

check_http "intake router" "http://soc-intake-router:8080/health"
check_http "intake router metrics" "http://soc-intake-router:8080/metrics"
check_http "report mailer" "http://soc-report-mailer:8080/health"
check_http "IR advisor" "http://soc-ir-ai-advisor:8080/health"
check_http "approval gateway" "http://soc-approval-gateway:8080/health"
check_http "action executor" "http://soc-action-executor:8080/health"
check_http "SOC ops dashboard" "http://soc-ops-dashboard:8080/health"
check_http "TheHive deduper" "http://soc-thehive-deduper:8080/health"
check_http "workflow watchdog" "http://soc-workflow-watchdog:8080/health"
check_http "Cortex runner" "http://soc-cortex-runner:8080/health"
check_http "MISP runner" "http://soc-misp-runner:8080/health"
check_http "CAPEv2 runner" "http://soc-capev2-runner:8080/health"
check_http "Velociraptor runner" "http://soc-velociraptor-runner:8080/health"
check_http "Ghidra runner" "http://soc-ghidra-runner:8080/health"
check_http "malware pipeline runner" "http://soc-malware-pipeline-runner:8080/health"
check_http "Shuffle backend" "http://shuffle-backend:5001/api/v1/getinfo"

if docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t >/tmp/soc-analysisd-test.out 2>&1; then
  if grep -qi "warning" /tmp/soc-analysisd-test.out; then
    fail "wazuh-analysisd config test without warnings"
    grep -i "warning" /tmp/soc-analysisd-test.out
  else
    pass "wazuh-analysisd config test without warnings"
  fi
else
  fail "wazuh-analysisd config test"
  tail -80 /tmp/soc-analysisd-test.out || true
fi

if docker exec wazuh-manager /var/ossec/bin/agent_control -i 001 2>/dev/null | grep -Eq "Status:[[:space:]]+Active"; then
  pass "pfSense Wazuh agent 001 active"
else
  fail "pfSense Wazuh agent 001 active"
fi

if [ "$failures" -gt 0 ]; then
  printf "SOC health checks failed: %s\n" "$failures"
  exit 1
fi

printf "SOC health checks passed\n"
'
'@

Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script $remoteScript

if (!$SkipWazuhRegression) {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $rootPath 'scripts\test-wazuh-pfsense-snort.ps1') -Root $rootPath
    if ($LASTEXITCODE -ne 0) { throw "Wazuh pfSense/Snort regression failed with exit code $LASTEXITCODE" }
}

Write-Host 'SOC test suite passed.'
