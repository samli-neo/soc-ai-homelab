param(
    [string]$Root = '.',
    [string]$ProxmoxHost = '',
    [int]$TimeoutSeconds = 360
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
    $remote = "echo '$encoded' | base64 -d > /tmp/soc-shuffle-e2e.sh && sh /tmp/soc-shuffle-e2e.sh"
    & $plink -ssh -P 22 -noagent -batch -pw $Password -hostkey 'SHA256:iNQgGxjHemb/sk6KJTGFpa003qzFOUhYDEvqIty1gPg' "root@$HostName" $remote
    if ($LASTEXITCODE -ne 0) { throw "Shuffle workflow E2E failed with exit code $LASTEXITCODE" }
}

$rootPath = Resolve-Path -LiteralPath $Root
$envValues = Read-DotEnv -Path (Join-Path $rootPath '.env')
if (!$ProxmoxHost) { $ProxmoxHost = if ($envValues['PROXMOX_HOST']) { $envValues['PROXMOX_HOST'] } else { '192.168.2.200' } }
$proxmoxPassword = if ($envValues['PROXMOX_SSH_PASS']) { $envValues['PROXMOX_SSH_PASS'] } else { $envValues['PFSENSE_WEB_PASS'] }
if (!$proxmoxPassword) { throw 'Missing PROXMOX_SSH_PASS or PFSENSE_WEB_PASS in .env' }

$remoteScript = @"
set -eu
cat > /tmp/soc-shuffle-e2e.py <<'PY'
import json
import time
import urllib.request
from pathlib import Path

timeout_seconds = $TimeoutSeconds
expected_nodes = {
    'soc-orchestrator-0001',
    'soc-triage-misp-0002',
    'soc-cortex-agent-0003',
    'soc-thehive-case-0004',
    'soc-velociraptor-0005',
    'soc-capev2-agent-0006',
    'soc-threatintel-0007',
    'soc-pfsense-agent-0008',
    'soc-ir-approval-0009',
    'soc-reporting-0010',
}

def load_env(path):
    values = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
    return values

def post_json(url, payload, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={'Content-Type':'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode() or '{}')

def get_json(url, api_key, timeout=30):
    req = urllib.request.Request(url, headers={'Authorization':'Bearer ' + api_key, 'Accept':'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode() or '[]')

def parse_node_message(result):
    value = result.get('result') or result.get('output') or result.get('data')
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except Exception:
            return {'raw': value[:1000]}
    if isinstance(value, dict) and isinstance(value.get('message'), str):
        try:
            value['message'] = json.loads(value['message'])
        except Exception:
            pass
    if isinstance(value, dict) and isinstance(value.get('message'), dict):
        return value['message']
    return value if isinstance(value, dict) else {}

def semantic_failure(action_id, message):
    status = str(message.get('status') or '').lower()
    if message.get('success') is False:
        return 'inner_success_false'
    if message.get('error'):
        return 'inner_error: ' + str(message.get('error'))[:500]
    if status in {'agent_contract_unavailable', 'shuffle_python_node_error'}:
        return 'bad_inner_status: ' + status
    if 'error' in status or 'unavailable' in status:
        return 'bad_inner_status: ' + status
    return None

env = load_env('/host/soc-intake-router/env')
shuffle_base = env.get('SHUFFLE_BASE_URL', 'http://shuffle-backend:5001').rstrip('/')
workflow_id = env.get('SHUFFLE_WORKFLOW_ID', '043882e1-8ea3-4f88-898c-b12957ff2785')
api_key = env['SHUFFLE_API_KEY']
marker = f'soc-workflow-e2e-{int(time.time())}'
alert = {
    'timestamp': '2026-08-13T23:00:00.000+0000',
    'id': marker,
    'rule': {'id': '100778', 'level': 10, 'description': f'SOC workflow E2E validation {marker}', 'groups': ['soc_e2e', 'validation']},
    'agent': {'id': '001', 'name': 'pfsense', 'ip': '192.168.2.1'},
    'location': 'soc-workflow-e2e',
    'data': {'srcip': '203.0.113.77', 'dstip': '10.10.50.10', 'domain': 'example.net', 'url': 'https://example.net/soc-e2e', 'test_type': 'soc_workflow_e2e'},
}
_, intake = post_json('http://soc-intake-router:8080/intake', alert)
execution_id = ((intake.get('shuffle_response') or {}).get('execution_id') or '')
if not execution_id:
    raise SystemExit('missing execution_id from intake response: ' + json.dumps(intake))

deadline = time.time() + timeout_seconds
last = None
while time.time() < deadline:
    _, executions = get_json(f'{shuffle_base}/api/v1/workflows/{workflow_id}/executions?limit=100', api_key)
    last = next((item for item in executions if item.get('execution_id') == execution_id or item.get('id') == execution_id), None)
    if last and str(last.get('status') or '').upper() == 'FINISHED':
        break
    time.sleep(5)
if not last:
    raise SystemExit(f'execution {execution_id} not found')
if str(last.get('status') or '').upper() != 'FINISHED':
    raise SystemExit(f'execution {execution_id} did not finish: {last.get("status")}')
seen = set()
failed = []
semantic_failed = []
semantic_warnings = []
for result in last.get('results') or []:
    action = result.get('action')
    action_id = action.get('id') if isinstance(action, dict) else result.get('action_id') or result.get('id')
    if action_id:
        seen.add(action_id)
    if str(result.get('status') or '').upper() != 'SUCCESS':
        failed.append({'action_id': action_id, 'status': result.get('status')})
    message = parse_node_message(result)
    reason = semantic_failure(action_id, message)
    if reason:
        semantic_failed.append({'action_id': action_id, 'reason': reason, 'status': message.get('status')})
    verdict = message.get('verdict') if isinstance(message.get('verdict'), dict) else {}
    verdict_reasons = verdict.get('reasons') if isinstance(verdict, dict) else []
    if isinstance(verdict_reasons, list) and verdict_reasons:
        semantic_warnings.append({'action_id': action_id, 'verdict_reasons': verdict_reasons[:5]})
missing = sorted(expected_nodes - seen)
if failed or missing or semantic_failed:
    raise SystemExit(json.dumps({'execution_id': execution_id, 'failed': failed, 'semantic_failed': semantic_failed, 'semantic_warnings': semantic_warnings, 'missing': missing, 'seen': sorted(seen)}))
print(json.dumps({'success': True, 'execution_id': execution_id, 'marker': marker, 'result_count': len(last.get('results') or []), 'nodes': sorted(seen), 'semantic_warnings': semantic_warnings}))
PY
if command -v docker >/dev/null 2>&1; then
  docker run --rm --network root_soc-net -v /root:/host -v /tmp:/tmp python:3.13-alpine python /tmp/soc-shuffle-e2e.py
else
  pct push 200 /tmp/soc-shuffle-e2e.py /tmp/soc-shuffle-e2e.py >/dev/null
  pct exec 200 -- docker run --rm --network root_soc-net -v /root:/host -v /tmp:/tmp python:3.13-alpine python /tmp/soc-shuffle-e2e.py
fi
"@

Invoke-ProxmoxScript -HostName $ProxmoxHost -Password $proxmoxPassword -Script $remoteScript
