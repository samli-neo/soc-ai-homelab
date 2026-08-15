param(
    [string]$Root = '.',
    [string]$ProxmoxHost = '',
    [string]$OutputDir = '.\wazuh-test-evidence'
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
    $remote = "echo '$encoded' | base64 -d > /tmp/wazuh-regression-tests.sh && sh /tmp/wazuh-regression-tests.sh"
    & $plink -ssh -P 22 -noagent -batch -pw $Password -hostkey 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg' "root@$HostName" $remote
    if ($LASTEXITCODE -ne 0) { throw "Remote Wazuh regression tests failed with exit code $LASTEXITCODE" }
}

$envPath = Join-Path $Root '.env'
$envValues = Read-DotEnv -Path $envPath
if (!$ProxmoxHost) { $ProxmoxHost = if ($envValues['PROXMOX_HOST']) { $envValues['PROXMOX_HOST'] } else { '192.168.2.200' } }
$proxmoxPassword = if ($envValues['PROXMOX_SSH_PASS']) { $envValues['PROXMOX_SSH_PASS'] } else { $envValues['PFSENSE_WEB_PASS'] }
if (!$proxmoxPassword) { throw 'Missing PROXMOX_SSH_PASS or PFSENSE_WEB_PASS in .env' }

if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcriptPath = Join-Path $OutputDir "$timestamp-wazuh-pfsense-snort-tests.txt"

$remoteScript = @'
set -eu

if ! command -v docker >/dev/null 2>&1; then
  pct push 200 /tmp/wazuh-regression-tests.sh /tmp/wazuh-regression-tests.sh >/dev/null
  pct exec 200 -- sh /tmp/wazuh-regression-tests.sh
  exit $?
fi

WORKDIR=/tmp/wazuh-regression-tests
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
OUT="$WORKDIR/results.txt"
: > "$OUT"

run_logtest() {
  name="$1"
  input_file="$2"
  output_file="$WORKDIR/$name.out"
  docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < "$input_file" > "$output_file" 2>&1
  cat "$output_file" >> "$OUT"
  printf '\n--- END %s ---\n' "$name" >> "$OUT"
}

assert_contains() {
  file="$1"
  needle="$2"
  label="$3"
  if grep -Fq "$needle" "$file"; then
    echo "PASS $label"
  else
    echo "FAIL $label"
    echo "Missing: $needle"
    echo "Output:"
    tail -120 "$file"
    exit 1
  fi
}

assert_not_contains() {
  file="$1"
  needle="$2"
  label="$3"
  if grep -Fq "$needle" "$file"; then
    echo "FAIL $label"
    echo "Unexpected: $needle"
    echo "Output:"
    tail -160 "$file"
    exit 1
  else
    echo "PASS $label"
  fi
}

cat > "$WORKDIR/snort-priority-1.log" <<'EOF'
08/04/26-04:10:00.000000 ,999,910001,1,"SOC-REGRESSION-SNORT-P1",TCP,192.0.2.101,44401,198.51.100.101,22,910001,Attempted Administrator Privilege Gain,1,alert,Allow
EOF

cat > "$WORKDIR/snort-priority-2.log" <<'EOF'
08/04/26-04:10:01.000000 ,999,910002,1,"SOC-REGRESSION-SNORT-P2",TCP,192.0.2.102,44402,198.51.100.102,443,910002,Attempted Information Leak,2,alert,Allow
EOF

cat > "$WORKDIR/snort-priority-3-repeated.log" <<'EOF'
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
08/04/26-04:10:02.000000 ,999,910003,1,"SOC-REGRESSION-SNORT-P3",TCP,192.0.2.103,44403,198.51.100.103,80,910003,Not Suspicious Traffic,3,alert,Allow
EOF

cat > "$WORKDIR/pfsense-block-repeated.log" <<'EOF'
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
filterlog[12345]: 1,,,910004,vtnet0,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,203.0.113.104,10.10.50.10,55001,22
EOF

run_logtest snort-priority-1 "$WORKDIR/snort-priority-1.log"
assert_contains "$WORKDIR/snort-priority-1.out" "name: 'soc-pfsense-snort-csv'" "Snort priority 1 decoder"
assert_contains "$WORKDIR/snort-priority-1.out" "id: '100121'" "Snort priority 1 rule id"
assert_contains "$WORKDIR/snort-priority-1.out" "level: '10'" "Snort priority 1 level"

run_logtest snort-priority-2 "$WORKDIR/snort-priority-2.log"
assert_contains "$WORKDIR/snort-priority-2.out" "id: '100122'" "Snort priority 2 rule id"
assert_contains "$WORKDIR/snort-priority-2.out" "level: '7'" "Snort priority 2 level"

run_logtest snort-priority-3-repeated "$WORKDIR/snort-priority-3-repeated.log"
assert_contains "$WORKDIR/snort-priority-3-repeated.out" "id: '100120'" "Snort priority 3 base rule"
assert_not_contains "$WORKDIR/snort-priority-3-repeated.out" "id: '100123'" "Snort priority 3 does not escalate"

run_logtest pfsense-block-repeated "$WORKDIR/pfsense-block-repeated.log"
assert_contains "$WORKDIR/pfsense-block-repeated.out" "name: 'soc-pfsense-filterlog'" "pfSense filterlog decoder"
assert_contains "$WORKDIR/pfsense-block-repeated.out" "srcip: '203.0.113.104'" "pfSense filterlog srcip parsed"
assert_contains "$WORKDIR/pfsense-block-repeated.out" "id: '100112'" "pfSense repeated block rule id"
assert_contains "$WORKDIR/pfsense-block-repeated.out" "level: '10'" "pfSense repeated block level"

echo "ALL TESTS PASSED"
cat "$OUT"
'@

Start-Transcript -LiteralPath $transcriptPath | Out-Null
try {
    Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script $remoteScript
    Write-Host "Wazuh pfSense/Snort regression tests passed. Evidence: $transcriptPath"
} finally {
    Stop-Transcript | Out-Null
}
