import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


SHUFFLE_BASE = os.environ.get("SHUFFLE_BASE_URL", "http://shuffle-backend:5001").rstrip("/")
SHUFFLE_WORKFLOW_ID = os.environ.get("SHUFFLE_WORKFLOW_ID", "043882e1-8ea3-4f88-898c-b12957ff2785")
SHUFFLE_API_KEY = os.environ.get("SHUFFLE_API_KEY", "")
EXECUTION_LIMIT = int(os.environ.get("WATCHDOG_EXECUTION_LIMIT", "100"))
STUCK_AFTER_SECONDS = int(os.environ.get("WATCHDOG_STUCK_AFTER_SECONDS", "900"))
EXPECTED_ACTION_COUNT = int(os.environ.get("WATCHDOG_EXPECTED_ACTION_COUNT", "10"))
STARTED_AT = time.time()


def shuffle_get(path):
    req = urllib.request.Request(
        f"{SHUFFLE_BASE}{path}",
        headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        text = response.read().decode("utf-8")
        return response.status, json.loads(text) if text else {}


def execution_started_at(execution):
    for key in ("started_at", "start", "execution_start"):
        value = execution.get(key)
        if isinstance(value, (int, float)):
            return int(value / 1000) if value > 10_000_000_000 else int(value)
    return 0


def execution_id(execution):
    return execution.get("execution_id") or execution.get("id") or execution.get("authorization") or ""


def parse_node_message(result):
    value = result.get("result") or result.get("output") or result.get("data")
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except Exception:
            return {"raw": value[:1000]}
    if isinstance(value, dict) and isinstance(value.get("message"), str):
        try:
            value["message"] = json.loads(value["message"])
        except Exception:
            pass
    if isinstance(value, dict) and isinstance(value.get("message"), dict):
        return value["message"]
    return value if isinstance(value, dict) else {}


def result_action_id(result):
    action = result.get("action")
    return action.get("id") if isinstance(action, dict) else result.get("action_id") or result.get("id") or ""


def semantic_failure(message):
    status = str(message.get("status") or "").lower()
    if message.get("success") is False:
        return "inner_success_false"
    if message.get("error"):
        return "inner_error: " + str(message.get("error"))[:500]
    if status in {"agent_contract_unavailable", "shuffle_python_node_error"}:
        return "bad_inner_status: " + status
    if "error" in status or "unavailable" in status:
        return "bad_inner_status: " + status
    return None


def inspect_semantic_results(execution):
    failures = []
    warnings = []
    for result in execution.get("results") or []:
        action_id = result_action_id(result)
        message = parse_node_message(result)
        reason = semantic_failure(message)
        if reason:
            failures.append({"action_id": action_id, "reason": reason, "status": message.get("status")})
        verdict = message.get("verdict") if isinstance(message.get("verdict"), dict) else {}
        verdict_reasons = verdict.get("reasons") if isinstance(verdict, dict) else []
        if isinstance(verdict_reasons, list) and verdict_reasons:
            warnings.append({"action_id": action_id, "verdict_reasons": verdict_reasons[:5]})
    return failures, warnings


def inspect_workflow():
    if not SHUFFLE_API_KEY:
        return {"success": False, "status": "missing_shuffle_api_key", "error": "SHUFFLE_API_KEY is not configured"}
    workflow_status, workflow = shuffle_get(f"/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}")
    executions_status, executions = shuffle_get(f"/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/executions?limit={EXECUTION_LIMIT}")
    if not isinstance(executions, list):
        executions = []
    now = int(time.time())
    stuck = []
    failed = []
    incomplete_finished = []
    semantic_failed = []
    semantic_warnings = []
    recent_finished = 0
    for item in executions:
        status = str(item.get("status") or "").upper()
        started = execution_started_at(item)
        age = now - started if started else None
        result_count = len(item.get("results") or [])
        summary = {
            "execution_id": execution_id(item),
            "status": status,
            "age_seconds": age,
            "result_count": result_count,
            "last_node": item.get("last_node") or "",
        }
        if status == "EXECUTING" and age is not None and age >= STUCK_AFTER_SECONDS:
            stuck.append(summary)
        if status in {"FAILURE", "FAILED", "ABORTED", "TIMEOUT"}:
            failed.append(summary)
        if status == "FINISHED":
            recent_finished += 1
            if result_count and result_count < EXPECTED_ACTION_COUNT:
                incomplete_finished.append(summary)
            node_failures, node_warnings = inspect_semantic_results(item)
            if node_failures:
                semantic_failed.append({**summary, "node_failures": node_failures[:10]})
            if node_warnings:
                semantic_warnings.append({**summary, "node_warnings": node_warnings[:10]})
    health_status = "ok" if not stuck and not failed and not incomplete_finished and not semantic_failed else "degraded"
    return {
        "success": True,
        "status": health_status,
        "service": "soc-workflow-watchdog",
        "workflow_id": SHUFFLE_WORKFLOW_ID,
        "workflow_name": workflow.get("name") if isinstance(workflow, dict) else None,
        "workflow_status": workflow.get("status") if isinstance(workflow, dict) else None,
        "workflow_http_status": workflow_status,
        "executions_http_status": executions_status,
        "execution_limit": EXECUTION_LIMIT,
        "stuck_after_seconds": STUCK_AFTER_SECONDS,
        "expected_action_count": EXPECTED_ACTION_COUNT,
        "execution_count": len(executions),
        "recent_finished_count": recent_finished,
        "stuck_count": len(stuck),
        "failed_count": len(failed),
        "incomplete_finished_count": len(incomplete_finished),
        "semantic_failed_count": len(semantic_failed),
        "semantic_warning_count": len(semantic_warnings),
        "stuck_executions": stuck[:10],
        "failed_executions": failed[:10],
        "incomplete_finished_executions": incomplete_finished[:10],
        "semantic_failed_executions": semantic_failed[:10],
        "semantic_warning_executions": semantic_warnings[:10],
        "started_at": int(STARTED_AT),
        "uptime_seconds": int(time.time() - STARTED_AT),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            try:
                result = inspect_workflow()
                self._json(result)
            except urllib.error.HTTPError as exc:
                self._json({"success": False, "status": "shuffle_http_error", "error": f"HTTP {exc.code}"}, status=200)
            except Exception as exc:
                self._json({"success": False, "status": "watchdog_error", "error": f"{type(exc).__name__}: {exc}"}, status=200)
            return
        if path == "/metrics":
            try:
                self._json(inspect_workflow())
            except Exception as exc:
                self._json({"success": False, "status": "watchdog_error", "error": f"{type(exc).__name__}: {exc}"}, status=500)
            return
        self.send_response(404)
        self.end_headers()

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
