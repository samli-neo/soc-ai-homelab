import html
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


STARTED_AT = time.time()
CHECKS = {
    "intake": "http://soc-intake-router:8080/metrics",
    "workflow_watchdog": "http://soc-workflow-watchdog:8080/metrics",
    "approval_gateway": "http://soc-approval-gateway:8080/health",
    "action_executor": "http://soc-action-executor:8080/metrics",
    "thehive_deduper": "http://soc-thehive-deduper:8080/health",
    "misp_runner": "http://soc-misp-runner:8080/health",
    "cortex_runner": "http://soc-cortex-runner:8080/health",
    "malware_pipeline": "http://soc-malware-pipeline-runner:8080/health",
    "velociraptor_runner": "http://soc-velociraptor-runner:8080/health",
}


def get_json(name, url):
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            body = response.read().decode("utf-8")
            try:
                data = json.loads(body or "{}")
            except Exception:
                data = {"status": "ok" if 200 <= response.status < 400 else "error", "raw": body[:200]}
            return {"ok": 200 <= response.status < 400, "http_status": response.status, "data": data}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "data": {}}


def collect_metrics():
    checks = {name: get_json(name, url) for name, url in CHECKS.items()}
    degraded = [name for name, result in checks.items() if not result.get("ok")]
    watchdog = checks.get("workflow_watchdog", {}).get("data") or {}
    if watchdog.get("status") not in (None, "ok"):
        degraded.append("workflow_watchdog")
    return {
        "success": True,
        "status": "ok" if not degraded else "degraded",
        "service": "soc-ops-dashboard",
        "degraded_components": sorted(set(degraded)),
        "started_at": int(STARTED_AT),
        "uptime_seconds": int(time.time() - STARTED_AT),
        "checks": checks,
    }


def render_html(metrics):
    intake = ((metrics.get("checks") or {}).get("intake") or {}).get("data") or {}
    watchdog = ((metrics.get("checks") or {}).get("workflow_watchdog") or {}).get("data") or {}
    executor = ((metrics.get("checks") or {}).get("action_executor") or {}).get("data") or {}
    rows = []
    for name, result in (metrics.get("checks") or {}).items():
        data = result.get("data") or {}
        status = data.get("status") or ("ok" if result.get("ok") else "error")
        rows.append(f"<tr><td>{html.escape(name)}</td><td>{html.escape(str(status))}</td><td>{html.escape(str(result.get('http_status') or result.get('error') or ''))}</td></tr>")
    body = f"""
<!doctype html>
<html><head><title>SOC Operations</title><style>
body{{font-family:Arial,sans-serif;margin:32px;background:#101418;color:#f2f5f7}} .card{{background:#182028;padding:18px;margin:14px 0;border-radius:10px}} table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border-bottom:1px solid #2b3640;text-align:left}} .ok{{color:#62d26f}} .degraded{{color:#ffbf47}}
</style></head><body>
<h1>SOC Operations</h1>
<div class="card"><h2 class="{html.escape(metrics.get('status',''))}">Status: {html.escape(metrics.get('status','unknown'))}</h2><p>Degraded: {html.escape(', '.join(metrics.get('degraded_components') or []) or 'none')}</p></div>
<div class="card"><h2>Intake</h2><p>Total: {intake.get('total_intakes',0)} | Full workflow: {intake.get('full_workflow',0)} | Digest: {intake.get('digest_only',0)} | Errors: {intake.get('errors',0)}</p><p>Last route: {html.escape(json.dumps(intake.get('last_route') or {}, sort_keys=True))}</p></div>
<div class="card"><h2>Workflow</h2><p>Recent finished: {watchdog.get('recent_finished_count',0)} | Semantic failures: {watchdog.get('semantic_failed_count',0)} | Warnings: {watchdog.get('semantic_warning_count',0)} | Stuck: {watchdog.get('stuck_count',0)}</p></div>
<div class="card"><h2>Actions</h2><p>Executor mode: {html.escape(str(executor.get('execution_mode','unknown')))} | Recent attempts: {executor.get('recent_attempt_count',0)}</p></div>
<div class="card"><h2>Components</h2><table><tr><th>Component</th><th>Status</th><th>HTTP/Error</th></tr>{''.join(rows)}</table></div>
</body></html>
"""
    return body.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        metrics = collect_metrics()
        if path == "/health":
            self._json({"status": metrics["status"], "service": "soc-ops-dashboard", "degraded_components": metrics["degraded_components"]})
            return
        if path == "/metrics":
            self._json(metrics)
            return
        if path in {"/", "/dashboard"}:
            body = render_html(metrics)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({"error": "not_found"}, status=404)

    def _json(self, response, status=200):
        body = json.dumps(response).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
