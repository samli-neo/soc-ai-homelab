param(
    [string]$MispUrl = '',
    [string]$MispApiKey = '',
    [string]$OutputDir = '.\phase4-evidence',
    [string]$WazuhConfigDir = '.\configs\wazuh-manager',
    [int]$Limit = 500,
    [switch]$DeployWazuh,
    [switch]$RestartWazuh,
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

function Get-WorkflowVariable {
    param([string]$Name)
    $paths = @(
        (Join-Path (Get-Location) 'shuffle\workflow_updated_payload.json'),
        (Join-Path (Get-Location) 'shuffle\workflow_payload.json'),
        (Join-Path (Get-Location) 'shuffle\workflow_as_created.json')
    )
    foreach ($path in $paths) {
        if (!(Test-Path -LiteralPath $path)) { continue }
        try {
            $workflow = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $variable = @($workflow.workflow_variables | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
            if ($variable.Count -gt 0 -and $variable[0].value) { return [string]$variable[0].value }
        }
        catch { }
    }
    return ''
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

function Copy-ToProxmox {
    param(
        [string]$LocalPath,
        [string]$RemotePath,
        [hashtable]$Env
    )
    $pscp = 'C:\Program Files\PuTTY\pscp.exe'
    if (!(Test-Path -LiteralPath $pscp)) { throw "PuTTY pscp not found at $pscp" }
    $password = $SshPassword
    if (!$password) { $password = $Env['PROXMOX_SSH_PASS'] }
    if (!$password) { $password = $Env['PFSENSE_WEB_PASS'] }
    if (!$password) { throw 'No SSH password found. Pass -SshPassword or set PROXMOX_SSH_PASS/PFSENSE_WEB_PASS in .env.' }
    $hostName = if ($Env['PROXMOX_HOST']) { $Env['PROXMOX_HOST'] } else { '192.168.2.200' }
    $hostKey = 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg'
    & $pscp -scp -P 22 -batch -pw $password -hostkey $hostKey $LocalPath "root@${hostName}:$RemotePath"
    if ($LASTEXITCODE -ne 0) { throw "Remote copy failed with exit code $LASTEXITCODE" }
}

function Normalize-Attribute {
    param([object]$Attribute)
    $type = [string]$Attribute.type
    $value = ([string]$Attribute.value).Trim()
    if (!$value) { return $null }
    if ($type -in @('ip-src', 'ip-dst')) { return [pscustomobject]@{ kind = 'ip'; type = $type; value = $value; event_id = $Attribute.event_id; uuid = $Attribute.uuid } }
    if ($type -in @('domain', 'hostname')) { return [pscustomobject]@{ kind = 'domain'; type = $type; value = $value.ToLowerInvariant(); event_id = $Attribute.event_id; uuid = $Attribute.uuid } }
    if ($type -eq 'url') { return [pscustomobject]@{ kind = 'domain'; type = $type; value = $value.ToLowerInvariant(); event_id = $Attribute.event_id; uuid = $Attribute.uuid } }
    if ($type -in @('md5', 'sha1', 'sha256')) { return [pscustomobject]@{ kind = 'hash'; type = $type; value = $value.ToLowerInvariant(); event_id = $Attribute.event_id; uuid = $Attribute.uuid } }
    return $null
}

function Write-WazuhList {
    param(
        [string]$Path,
        [object[]]$Indicators
    )
    $lines = @($Indicators | Sort-Object value -Unique | ForEach-Object { "$($_.value):misp_event_$($_.event_id)_$($_.type)" })
    if ($lines.Count -eq 0) { $lines = @('# empty') }
    $lines | Set-Content -LiteralPath $Path -Encoding ASCII
}

$envValues = Read-DotEnv -Path (Join-Path (Get-Location) '.env')
if (!$MispUrl) { $MispUrl = $envValues['MISP_URL'] }
if (!$MispUrl) { $MispUrl = Get-WorkflowVariable -Name 'MISP_URL' }
if (!$MispUrl) { $MispUrl = 'https://misp' }
$MispUrl = $MispUrl.TrimEnd('/').Replace('https://misp:443', 'https://misp')

if (!$MispApiKey) { $MispApiKey = $envValues['MISP_API_KEY'] }
if (!$MispApiKey) { $MispApiKey = Get-WorkflowVariable -Name 'MISP_API_KEY' }
if (!$MispApiKey) { throw 'MISP API key not found in .env or Shuffle workflow payloads.' }

if (!(Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
if (!(Test-Path -LiteralPath $WazuhConfigDir)) { New-Item -ItemType Directory -Path $WazuhConfigDir | Out-Null }

$searchPayload = [ordered]@{
    returnFormat = 'json'
    limit = $Limit
    type = @('ip-src', 'ip-dst', 'domain', 'hostname', 'url', 'md5', 'sha1', 'sha256')
}
$tempPayload = Join-Path $env:TEMP "phase4-misp-search-$([guid]::NewGuid()).json"
$searchPayload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempPayload -Encoding ASCII
try {
    $misp = Invoke-RestMethod -Method Post -Uri "$MispUrl/attributes/restSearch" -Headers @{ Authorization = $MispApiKey; Accept = 'application/json' } -ContentType 'application/json' -InFile $tempPayload
}
finally {
    Remove-Item -LiteralPath $tempPayload -ErrorAction SilentlyContinue
}

$rawAttributes = @()
if ($misp.response.Attribute) { $rawAttributes = @($misp.response.Attribute) }
elseif ($misp.Attribute) { $rawAttributes = @($misp.Attribute) }
elseif ($misp.response) { $rawAttributes = @($misp.response) }

$indicators = @($rawAttributes | ForEach-Object { Normalize-Attribute -Attribute $_ } | Where-Object { $_ })
$ips = @($indicators | Where-Object { $_.kind -eq 'ip' })
$domains = @($indicators | Where-Object { $_.kind -eq 'domain' })
$hashes = @($indicators | Where-Object { $_.kind -eq 'hash' })

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$attributesPath = Join-Path $OutputDir "$timestamp-misp-attributes.json"
$summaryPath = Join-Path $OutputDir "$timestamp-threat-intel-summary.json"
$misp | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $attributesPath -Encoding UTF8

$ipListPath = Join-Path $WazuhConfigDir 'misp_ip_iocs'
$domainListPath = Join-Path $WazuhConfigDir 'misp_domain_iocs'
$hashListPath = Join-Path $WazuhConfigDir 'misp_hash_iocs'
$rulesPath = Join-Path $WazuhConfigDir 'misp_ioc_rules.xml'
$ossecConfPath = Join-Path $WazuhConfigDir 'ossec.conf'
$localRulesPath = Join-Path $WazuhConfigDir 'local_rules.xml'
$localDecodersPlaceholderPath = Join-Path $WazuhConfigDir 'local_decoders.xml'
$socDecodersPath = Join-Path $WazuhConfigDir 'soc_decoders.xml'
Write-WazuhList -Path $ipListPath -Indicators $ips
Write-WazuhList -Path $domainListPath -Indicators $domains
Write-WazuhList -Path $hashListPath -Indicators $hashes

$rules = @'
<group name="soc-threat-intel,misp,">
  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <match>phase4_misp</match>
    <description>SOC CTI: JSON event eligible for MISP IOC checks</description>
  </rule>

  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/misp_ip_iocs</list>
    <description>SOC CTI: Source IP matched MISP indicator</description>
    <group>threat_intel,misp,ip,</group>
  </rule>

  <rule id="100202" level="12">
    <if_sid>100200</if_sid>
    <list field="dstip" lookup="address_match_key">etc/lists/misp_ip_iocs</list>
    <description>SOC CTI: Destination IP matched MISP indicator</description>
    <group>threat_intel,misp,ip,</group>
  </rule>

  <rule id="100203" level="10">
    <if_sid>100200</if_sid>
    <list field="url" lookup="match_key">etc/lists/misp_domain_iocs</list>
    <description>SOC CTI: URL/domain matched MISP indicator</description>
    <group>threat_intel,misp,domain,</group>
  </rule>

  <rule id="100204" level="12">
    <if_sid>100200</if_sid>
    <list field="sha256" lookup="match_key">etc/lists/misp_hash_iocs</list>
    <description>SOC CTI: File hash matched MISP indicator</description>
    <group>threat_intel,misp,hash,malware,</group>
  </rule>
__DIRECT_IOC_RULES__
</group>
'@
$directRules = New-Object System.Collections.Generic.List[string]
$ruleId = 100300
foreach ($indicator in @($indicators | Sort-Object kind, value -Unique | Select-Object -First 200)) {
    $fieldNames = @()
    if ($indicator.kind -eq 'hash') { $fieldNames = @($indicator.type) }
    elseif ($indicator.kind -eq 'ip') { $fieldNames = @('srcip', 'dstip') }
    elseif ($indicator.kind -eq 'domain') { $fieldNames = @('url', 'domain') }

    foreach ($fieldName in $fieldNames) {
        $escapedValue = [System.Security.SecurityElement]::Escape([regex]::Escape($indicator.value))
        $escapedDescription = [System.Security.SecurityElement]::Escape("SOC CTI: $fieldName matched MISP $($indicator.type) indicator $($indicator.value)")
        $directRules.Add(@"
  <rule id="$ruleId" level="12">
    <if_sid>100200</if_sid>
    <field name="$fieldName">^$escapedValue$</field>
    <description>$escapedDescription</description>
    <group>threat_intel,misp,direct_ioc,</group>
  </rule>

"@)
        $ruleId++
    }
}
$rules = $rules.Replace('__DIRECT_IOC_RULES__', ($directRules -join ''))
$rules | Set-Content -LiteralPath $rulesPath -Encoding ASCII

[xml](Get-Content -LiteralPath $rulesPath -Raw) | Out-Null

$summary = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    misp_url = $MispUrl
    raw_attributes = @($rawAttributes).Count
    indicators_total = @($indicators).Count
    ip_indicators = @($ips | Sort-Object value -Unique).Count
    domain_indicators = @($domains | Sort-Object value -Unique).Count
    hash_indicators = @($hashes | Sort-Object value -Unique).Count
    attributes_path = (Resolve-Path -LiteralPath $attributesPath).Path
    wazuh_lists = [ordered]@{
        ip = (Resolve-Path -LiteralPath $ipListPath).Path
        domain = (Resolve-Path -LiteralPath $domainListPath).Path
        hash = (Resolve-Path -LiteralPath $hashListPath).Path
    }
    wazuh_rules = (Resolve-Path -LiteralPath $rulesPath).Path
    deployed = $false
}

if ($DeployWazuh) {
    $remoteDir = '/root/phase4-threat-intel'
    Invoke-ProxmoxCommand -Command "mkdir -p $remoteDir" -Env $envValues
    Copy-ToProxmox -LocalPath $ipListPath -RemotePath "$remoteDir/misp_ip_iocs" -Env $envValues
    Copy-ToProxmox -LocalPath $domainListPath -RemotePath "$remoteDir/misp_domain_iocs" -Env $envValues
    Copy-ToProxmox -LocalPath $hashListPath -RemotePath "$remoteDir/misp_hash_iocs" -Env $envValues
    Copy-ToProxmox -LocalPath $rulesPath -RemotePath "$remoteDir/misp_ioc_rules.xml" -Env $envValues
    if (Test-Path -LiteralPath $ossecConfPath) { Copy-ToProxmox -LocalPath $ossecConfPath -RemotePath "$remoteDir/ossec.conf" -Env $envValues }
    if (Test-Path -LiteralPath $localRulesPath) { Copy-ToProxmox -LocalPath $localRulesPath -RemotePath "$remoteDir/local_rules.xml" -Env $envValues }
    if (Test-Path -LiteralPath $localDecodersPlaceholderPath) { Copy-ToProxmox -LocalPath $localDecodersPlaceholderPath -RemotePath "$remoteDir/local_decoders.xml" -Env $envValues }
    if (Test-Path -LiteralPath $socDecodersPath) { Copy-ToProxmox -LocalPath $socDecodersPath -RemotePath "$remoteDir/soc_decoders.xml" -Env $envValues }
    $install = "pct push 200 $remoteDir/misp_ip_iocs /tmp/misp_ip_iocs && pct push 200 $remoteDir/misp_domain_iocs /tmp/misp_domain_iocs && pct push 200 $remoteDir/misp_hash_iocs /tmp/misp_hash_iocs && pct push 200 $remoteDir/misp_ioc_rules.xml /tmp/misp_ioc_rules.xml && pct push 200 $remoteDir/ossec.conf /tmp/ossec.conf && pct push 200 $remoteDir/local_rules.xml /tmp/local_rules.xml && pct push 200 $remoteDir/local_decoders.xml /tmp/local_decoders.xml && pct push 200 $remoteDir/soc_decoders.xml /tmp/soc_decoders.xml && pct exec 200 -- docker cp /tmp/misp_ip_iocs wazuh-manager:/tmp/misp_ip_iocs && pct exec 200 -- docker cp /tmp/misp_domain_iocs wazuh-manager:/tmp/misp_domain_iocs && pct exec 200 -- docker cp /tmp/misp_hash_iocs wazuh-manager:/tmp/misp_hash_iocs && pct exec 200 -- docker cp /tmp/misp_ioc_rules.xml wazuh-manager:/tmp/misp_ioc_rules.xml && pct exec 200 -- docker cp /tmp/ossec.conf wazuh-manager:/tmp/ossec.conf && pct exec 200 -- docker cp /tmp/local_rules.xml wazuh-manager:/tmp/local_rules.xml && pct exec 200 -- docker cp /tmp/local_decoders.xml wazuh-manager:/tmp/local_decoders.xml && pct exec 200 -- docker cp /tmp/soc_decoders.xml wazuh-manager:/tmp/soc_decoders.xml && pct exec 200 -- docker exec wazuh-manager sh -c 'cat /tmp/misp_ip_iocs > /var/ossec/etc/lists/misp_ip_iocs && cat /tmp/misp_domain_iocs > /var/ossec/etc/lists/misp_domain_iocs && cat /tmp/misp_hash_iocs > /var/ossec/etc/lists/misp_hash_iocs && cat /tmp/misp_ioc_rules.xml > /var/ossec/etc/rules/misp_ioc_rules.xml && cat /tmp/ossec.conf > /var/ossec/etc/ossec.conf && cat /tmp/local_rules.xml > /var/ossec/etc/rules/local_rules.xml && cat /tmp/local_decoders.xml > /var/ossec/etc/rules/local_decoders.xml && cat /tmp/soc_decoders.xml > /var/ossec/etc/decoders/soc_decoders.xml' && pct exec 200 -- docker exec wazuh-manager chown root:wazuh /var/ossec/etc/lists/misp_ip_iocs /var/ossec/etc/lists/misp_domain_iocs /var/ossec/etc/lists/misp_hash_iocs /var/ossec/etc/rules/misp_ioc_rules.xml /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_decoders.xml /var/ossec/etc/decoders/soc_decoders.xml /var/ossec/etc/ossec.conf && pct exec 200 -- docker exec wazuh-manager chmod 660 /var/ossec/etc/lists/misp_ip_iocs /var/ossec/etc/lists/misp_domain_iocs /var/ossec/etc/lists/misp_hash_iocs /var/ossec/etc/rules/misp_ioc_rules.xml /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_decoders.xml /var/ossec/etc/decoders/soc_decoders.xml /var/ossec/etc/ossec.conf && pct exec 200 -- docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t"
    Invoke-ProxmoxCommand -Command $install -Env $envValues
    $summary['deployed'] = $true
    if ($RestartWazuh) {
        Invoke-ProxmoxCommand -Command 'pct exec 200 -- docker restart wazuh-manager' -Env $envValues
        $summary['wazuh_restarted'] = $true
    }
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

[pscustomobject]@{
    MispUrl = $MispUrl
    RawAttributes = $summary.raw_attributes
    Indicators = $summary.indicators_total
    IpIndicators = $summary.ip_indicators
    DomainIndicators = $summary.domain_indicators
    HashIndicators = $summary.hash_indicators
    RulesPath = $summary.wazuh_rules
    SummaryPath = (Resolve-Path -LiteralPath $summaryPath).Path
    Deployed = $summary.deployed
}
