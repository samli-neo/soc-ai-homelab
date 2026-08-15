param(
    [string]$Root = '.',
    [string]$ProxmoxHost = '',
    [int]$LxcId = 200,
    [switch]$Restart,
    [switch]$RunRegression
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

function Invoke-Plink {
    param(
        [string]$HostName,
        [string]$Password,
        [string]$Command
    )

    $plink = 'C:\Program Files\PuTTY\plink.exe'
    if (!(Test-Path -LiteralPath $plink)) { throw "plink not found at $plink" }
    & $plink -ssh -P 22 -noagent -batch -pw $Password -hostkey 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg' "root@$HostName" $Command
    if ($LASTEXITCODE -ne 0) { throw "Remote command failed with exit code $LASTEXITCODE" }
}

function Invoke-ProxmoxScript {
    param(
        [string]$HostName,
        [string]$Password,
        [string]$Script
    )

    $encoded = ConvertTo-Base64Utf8 -Text $Script
    Invoke-Plink -HostName $HostName -Password $Password -Command "echo '$encoded' | base64 -d > /tmp/deploy-wazuh-config.sh && sh /tmp/deploy-wazuh-config.sh"
}

$rootPath = Resolve-Path -LiteralPath $Root
$configDir = Join-Path $rootPath 'configs\wazuh-manager'
$files = @(
    @{ Name = 'ossec.conf'; Source = Join-Path $configDir 'ossec.conf' },
    @{ Name = 'agent.conf'; Source = Join-Path $configDir 'agent.conf' },
    @{ Name = 'local_rules.xml'; Source = Join-Path $configDir 'local_rules.xml' },
    @{ Name = 'misp_ioc_rules.xml'; Source = Join-Path $configDir 'misp_ioc_rules.xml' },
    @{ Name = 'soc_decoders.xml'; Source = Join-Path $configDir 'soc_decoders.xml' },
    @{ Name = 'custom-shuffle.py'; Source = Join-Path $configDir 'custom-shuffle.py' }
)

foreach ($file in $files) {
    if (!(Test-Path -LiteralPath $file.Source)) { throw "Missing required config file: $($file.Source)" }
}

$envValues = Read-DotEnv -Path (Join-Path $rootPath '.env')
if (!$ProxmoxHost) { $ProxmoxHost = if ($envValues['PROXMOX_HOST']) { $envValues['PROXMOX_HOST'] } else { '192.168.2.200' } }
$proxmoxPassword = if ($envValues['PROXMOX_SSH_PASS']) { $envValues['PROXMOX_SSH_PASS'] } else { $envValues['PFSENSE_WEB_PASS'] }
if (!$proxmoxPassword) { throw 'Missing PROXMOX_SSH_PASS or PFSENSE_WEB_PASS in .env' }

$deployId = Get-Date -Format 'yyyyMMdd-HHmmss'
$remoteDir = "/tmp/soc-wazuh-deploy-$deployId"
Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script "set -eu`nrm -rf '$remoteDir'`nmkdir -p '$remoteDir'"

foreach ($file in $files) {
    $bytes = [IO.File]::ReadAllBytes($file.Source)
    $encoded = [Convert]::ToBase64String($bytes)
    $remotePath = "$remoteDir/$($file.Name).b64"
    $uploadScript = "set -eu`ncat > '$remotePath' <<'EOF'`n$encoded`nEOF`nbase64 -d '$remotePath' > '$remoteDir/$($file.Name)'`nrm -f '$remotePath'"
    Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script $uploadScript
}

$restartValue = if ($Restart) { '1' } else { '0' }
$remoteScript = @"
set -eu

DEPLOY_DIR='$remoteDir'
LXC_ID='$LxcId'
RESTART='$restartValue'
TS='$deployId'

pct exec "`$LXC_ID" -- mkdir -p "/tmp/soc-wazuh-deploy-`$TS"

for name in ossec.conf agent.conf local_rules.xml misp_ioc_rules.xml soc_decoders.xml custom-shuffle.py; do
  pct push "`$LXC_ID" "`$DEPLOY_DIR/`$name" "/tmp/soc-wazuh-deploy-`$TS/`$name" >/dev/null
done

pct exec "`$LXC_ID" -- sh -lc '
set -eu
TS="$deployId"
DEPLOY_DIR="/tmp/soc-wazuh-deploy-$deployId"
BACKUP_DIR="/var/ossec/etc/soc-deploy-backups/$deployId"
HOST_CONFIG_DIR="/root/soc-configs/wazuh-manager"

mkdir -p "`$HOST_CONFIG_DIR"
cp "`$DEPLOY_DIR/ossec.conf" "`$HOST_CONFIG_DIR/ossec.conf"
cp "`$DEPLOY_DIR/agent.conf" "`$HOST_CONFIG_DIR/agent.conf"
cp "`$DEPLOY_DIR/local_rules.xml" "`$HOST_CONFIG_DIR/local_rules.xml"
cp "`$DEPLOY_DIR/misp_ioc_rules.xml" "`$HOST_CONFIG_DIR/misp_ioc_rules.xml"
cp "`$DEPLOY_DIR/soc_decoders.xml" "`$HOST_CONFIG_DIR/soc_decoders.xml"
cp "`$DEPLOY_DIR/custom-shuffle.py" "`$HOST_CONFIG_DIR/custom-shuffle.py"
chmod 750 "`$HOST_CONFIG_DIR/custom-shuffle.py"

docker exec wazuh-manager sh -lc "set -eu
mkdir -p \"`$BACKUP_DIR\"
cp /var/ossec/etc/ossec.conf \"`$BACKUP_DIR/ossec.conf\"
cp /var/ossec/etc/shared/default/agent.conf \"`$BACKUP_DIR/agent.conf\" 2>/dev/null || true
cp /var/ossec/etc/rules/local_rules.xml \"`$BACKUP_DIR/local_rules.xml\" 2>/dev/null || true
cp /var/ossec/etc/rules/misp_ioc_rules.xml \"`$BACKUP_DIR/misp_ioc_rules.xml\" 2>/dev/null || true
cp /var/ossec/etc/decoders/soc_decoders.xml \"`$BACKUP_DIR/soc_decoders.xml\" 2>/dev/null || true
cp /var/ossec/integrations/custom-shuffle.py \"`$BACKUP_DIR/custom-shuffle.py\" 2>/dev/null || true
"

docker exec wazuh-manager mkdir -p "/tmp/soc-wazuh-deploy-`$TS" /var/ossec/etc/shared/default /var/ossec/etc/rules /var/ossec/etc/decoders
for name in ossec.conf agent.conf local_rules.xml misp_ioc_rules.xml soc_decoders.xml; do
  docker cp "`$DEPLOY_DIR/`$name" "wazuh-manager:/tmp/soc-wazuh-deploy-`$TS/`$name"
done

docker exec wazuh-manager sh -lc "set -eu
cat /tmp/soc-wazuh-deploy-`$TS/ossec.conf > /var/ossec/etc/ossec.conf
cat /tmp/soc-wazuh-deploy-`$TS/agent.conf > /var/ossec/etc/shared/default/agent.conf
cat /tmp/soc-wazuh-deploy-`$TS/local_rules.xml > /var/ossec/etc/rules/local_rules.xml
cat /tmp/soc-wazuh-deploy-`$TS/misp_ioc_rules.xml > /var/ossec/etc/rules/misp_ioc_rules.xml
cat /tmp/soc-wazuh-deploy-`$TS/soc_decoders.xml > /var/ossec/etc/decoders/soc_decoders.xml
chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/shared/default/agent.conf /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/misp_ioc_rules.xml /var/ossec/etc/decoders/soc_decoders.xml
chmod 640 /var/ossec/etc/ossec.conf /var/ossec/etc/shared/default/agent.conf /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/misp_ioc_rules.xml /var/ossec/etc/decoders/soc_decoders.xml
"

if docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t >/tmp/wazuh-analysisd-deploy-test.out 2>&1; then
  if grep -qi warning /tmp/wazuh-analysisd-deploy-test.out; then
    echo "Validation produced warnings; restoring backup."
    cat /tmp/wazuh-analysisd-deploy-test.out
    docker exec wazuh-manager sh -lc "cp \"`$BACKUP_DIR/ossec.conf\" /var/ossec/etc/ossec.conf; cp \"`$BACKUP_DIR/agent.conf\" /var/ossec/etc/shared/default/agent.conf 2>/dev/null || true; cp \"`$BACKUP_DIR/local_rules.xml\" /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true; cp \"`$BACKUP_DIR/misp_ioc_rules.xml\" /var/ossec/etc/rules/misp_ioc_rules.xml 2>/dev/null || true; cp \"`$BACKUP_DIR/soc_decoders.xml\" /var/ossec/etc/decoders/soc_decoders.xml 2>/dev/null || true"
    exit 1
  fi
  echo "Wazuh analysisd validation passed without warnings. Backup: `$BACKUP_DIR"
else
  echo "Validation failed; restoring backup."
  cat /tmp/wazuh-analysisd-deploy-test.out || true
  docker exec wazuh-manager sh -lc "cp \"`$BACKUP_DIR/ossec.conf\" /var/ossec/etc/ossec.conf; cp \"`$BACKUP_DIR/agent.conf\" /var/ossec/etc/shared/default/agent.conf 2>/dev/null || true; cp \"`$BACKUP_DIR/local_rules.xml\" /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true; cp \"`$BACKUP_DIR/misp_ioc_rules.xml\" /var/ossec/etc/rules/misp_ioc_rules.xml 2>/dev/null || true; cp \"`$BACKUP_DIR/soc_decoders.xml\" /var/ossec/etc/decoders/soc_decoders.xml 2>/dev/null || true"
  exit 1
fi

if [ "$restartValue" = "1" ]; then
  docker restart wazuh-manager >/dev/null
  echo "wazuh-manager restarted."
fi
'
"@

Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script $remoteScript

if ($RunRegression) {
    if ($Restart) { Start-Sleep -Seconds 20 }
    & powershell -ExecutionPolicy Bypass -File (Join-Path $rootPath 'scripts\test-wazuh-pfsense-snort.ps1') -Root $rootPath
    if ($LASTEXITCODE -ne 0) { throw "Wazuh pfSense/Snort regression failed with exit code $LASTEXITCODE" }
}

Write-Host "Wazuh config deployment completed. Deploy ID: $deployId"
