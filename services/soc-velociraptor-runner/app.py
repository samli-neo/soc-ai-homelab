import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


DEFAULT_AGENT_ID = os.environ.get("SOC_VELO_AGENT_ID", "l3_dfir")
API_CONFIG = os.environ.get("VELO_API_CONFIG", "/root/soc-agent-credentials/velociraptor/ai-dfir-agent.config.yaml")
VELO_CONTAINER = os.environ.get("VELO_CONTAINER", "velociraptor")
DEFAULT_CLIENT_ID = os.environ.get("VELO_DEFAULT_CLIENT_ID", "")
WINDOWS_CLIENT_ID = os.environ.get("VELO_CLIENT_WINDOWS_ID", "")
PROXMOX_CLIENT_ID = os.environ.get("VELO_CLIENT_PROXMOX_ID", "")
SANDBOX_CLIENT_ID = os.environ.get("VELO_CLIENT_SANDBOX_ID", "")
TIMEOUT_SECONDS = int(os.environ.get("VELO_COLLECTION_TIMEOUT_SECONDS", "90"))
MAX_OUTPUT_BYTES = int(os.environ.get("VELO_MAX_OUTPUT_BYTES", "200000"))
DEFAULT_ARTIFACTS = [item.strip() for item in os.environ.get("VELO_SAFE_ARTIFACTS", "Generic.Client.Info").split(",") if item.strip()]
WINDOWS_ARTIFACTS = [item.strip() for item in os.environ.get("VELO_WINDOWS_SAFE_ARTIFACTS", "Generic.Client.Info,Windows.System.Pslist,Windows.Network.Netstat").split(",") if item.strip()]
ALLOWED_ARTIFACTS = {
    item.strip()
    for item in os.environ.get(
        "VELO_ALLOWED_ARTIFACTS",
        "Generic.Client.Info,Windows.System.Pslist,Windows.Network.Netstat,Windows.EventLogs.EvtxHunter",
    ).split(",")
    if item.strip()
}


def parse_alert(payload):
    value = payload.get("execution_argument") or payload.get("alert") or payload
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return json.loads(parsed) if isinstance(parsed, str) else parsed
        except Exception:
            return {"raw": value[:2000]}
    return {}


def alert_value(alert, *keys):
    current = alert
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return str(current or "").strip()


def choose_client(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    explicit = str(data.get("velociraptor_client_id") or data.get("velo_client_id") or "").strip()
    if explicit:
        return explicit, "alert_explicit"
    agent_name = alert_value(alert, "agent", "name").lower()
    agent_id = alert_value(alert, "agent", "id")
    if any(value in agent_name for value in ("win11pro", "win11", "sandbox")) and SANDBOX_CLIENT_ID:
        return SANDBOX_CLIENT_ID, "sandbox_agent_name"
    if "windows" in agent_name and WINDOWS_CLIENT_ID:
        return WINDOWS_CLIENT_ID, "windows_agent_name"
    if agent_id == "004" and WINDOWS_CLIENT_ID:
        return WINDOWS_CLIENT_ID, "windows_agent_id"
    if ("homelab" in agent_name or "proxmox" in agent_name) and PROXMOX_CLIENT_ID:
        return PROXMOX_CLIENT_ID, "proxmox_agent_name"
    if DEFAULT_CLIENT_ID:
        return DEFAULT_CLIENT_ID, "default"
    return "", "unmapped"


def choose_artifacts(alert):
    agent_name = alert_value(alert, "agent", "name").lower()
    agent_id = alert_value(alert, "agent", "id")
    requested = []
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    raw = data.get("velociraptor_artifacts") or data.get("velo_artifacts")
    if isinstance(raw, list):
        requested = [str(item).strip() for item in raw]
    elif isinstance(raw, str) and raw.strip():
        requested = [item.strip() for item in raw.split(",")]
    selected = requested or (WINDOWS_ARTIFACTS if "windows" in agent_name or agent_id == "004" else DEFAULT_ARTIFACTS)
    return [item for item in selected if item in ALLOWED_ARTIFACTS]


def run_velociraptor(client_id, artifacts):
    cmd = [
        "docker",
        "exec",
        VELO_CONTAINER,
        "/velociraptor/velociraptor",
        "--api_config",
        API_CONFIG,
        "artifacts",
        "collect",
        "--client_id",
        client_id,
        "--timeout",
        str(TIMEOUT_SECONDS),
        "--format",
        "json",
        *artifacts,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=TIMEOUT_SECONDS + 30)
    stdout = proc.stdout[:MAX_OUTPUT_BYTES]
    stderr = proc.stderr[:5000]
    events = []
    by_source = {}
    flow_id = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        events.append(event)
        source = str(event.get("_Source") or "unknown")
        by_source[source] = by_source.get(source, 0) + 1
        flow_id = flow_id or str(event.get("FlowId") or event.get("flow_id") or "")
    return {
        "returncode": proc.returncode,
        "success": proc.returncode == 0,
        "flow_id": flow_id,
        "event_count": len(events),
        "events_by_source": by_source,
        "sample_events": events[:5],
        "stderr_preview": stderr,
    }


def collect(payload):
    alert = parse_alert(payload)
    client_id, client_reason = choose_client(alert)
    artifacts = choose_artifacts(alert)
    if not client_id:
        return {
            "success": True,
            "soc_stage": "velociraptor_read_only_collection",
            "status": "no_velociraptor_client_mapped",
            "execution_audit": {"agent_id": DEFAULT_AGENT_ID, "credential_env": "VELO_API_CONFIG", "credential_scope": "agent_dedicated"},
            "approval_required": False,
            "executed_actions": [],
            "client_mapping_reason": client_reason,
            "artifacts": artifacts,
        }
    if not artifacts:
        return {
            "success": True,
            "soc_stage": "velociraptor_read_only_collection",
            "status": "no_allowed_artifacts_selected",
            "execution_audit": {"agent_id": DEFAULT_AGENT_ID, "credential_env": "VELO_API_CONFIG", "credential_scope": "agent_dedicated"},
            "approval_required": False,
            "executed_actions": [],
            "client_id": client_id,
            "client_mapping_reason": client_reason,
        }
    result = run_velociraptor(client_id, artifacts)
    return {
        "success": True,
        "soc_stage": "velociraptor_read_only_collection",
        "status": "velociraptor_collection_completed" if result["success"] else "velociraptor_collection_failed",
        "execution_audit": {"agent_id": DEFAULT_AGENT_ID, "credential_env": "VELO_API_CONFIG", "credential_scope": "agent_dedicated"},
        "approval_required": False,
        "executed_actions": ["velociraptor_collect_read_only"],
        "destructive_actions_executed": [],
        "client_id": client_id,
        "client_mapping_reason": client_reason,
        "artifacts": artifacts,
        "collection": result,
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path != "/collect":
            self.send_response(404)
            self.end_headers()
            return
        start = time.time()
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = collect(payload)
            result["duration_ms"] = int((time.time() - start) * 1000)
            self._json(result)
        except Exception as exc:
            self._json({"success": False, "error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _json(self, response, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
