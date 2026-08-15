import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


DATA_DIR = Path(os.environ.get("ACTION_EXECUTOR_DATA_DIR", "/data")).resolve()
DB_PATH = DATA_DIR / "actions.sqlite3"
EXECUTION_MODE = os.environ.get("ACTION_EXECUTOR_MODE", "audit_only").strip().lower()
ALLOWED_ACTIONS = {
    item.strip()
    for item in os.environ.get(
        "ACTION_EXECUTOR_ALLOWED_ACTIONS",
        "pfsense_block,snort_rule_change,velociraptor_isolate,wazuh_active_response,account_disable,sample_detonation",
    ).split(",")
    if item.strip()
}
STARTED_AT = time.time()


def connect_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS action_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            execution_mode TEXT NOT NULL,
            target_json TEXT NOT NULL,
            approval_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def row_to_dict(row):
    result = dict(row)
    for key in ("target_json", "approval_json"):
        try:
            result[key.replace("_json", "")] = json.loads(result.get(key) or "{}")
        except Exception:
            result[key.replace("_json", "")] = result.get(key)
        result.pop(key, None)
    return result


def recent_attempts(limit=20):
    with connect_db() as conn:
        rows = conn.execute("SELECT * FROM action_attempts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_dict(row) for row in rows]


def record_attempt(action, approval, status):
    target = approval.get("target") if isinstance(approval.get("target"), dict) else {}
    request_id = str(approval.get("request_id") or "")
    with connect_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO action_attempts
            (request_id, action, status, execution_mode, target_json, approval_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                action,
                status,
                EXECUTION_MODE,
                json.dumps(target, sort_keys=True),
                json.dumps(approval, sort_keys=True),
                int(time.time()),
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM action_attempts WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return row_to_dict(row)


def execute_action(action, payload):
    if action not in ALLOWED_ACTIONS:
        return {"success": False, "status": "action_not_allowed", "action": action}, 400
    approval = payload.get("approval") if isinstance(payload.get("approval"), dict) else payload
    if approval.get("status") != "approved":
        attempt = record_attempt(action, approval, "approval_not_approved")
        return {"success": False, "status": "approval_not_approved", "attempt": attempt}, 409
    if EXECUTION_MODE != "execute":
        attempt = record_attempt(action, approval, "audit_only_recorded")
        return {
            "success": True,
            "executed": False,
            "status": "audit_only_recorded",
            "execution_mode": EXECUTION_MODE,
            "action": action,
            "attempt": attempt,
        }, 200
    attempt = record_attempt(action, approval, "execute_mode_not_implemented")
    return {
        "success": False,
        "executed": False,
        "status": "execute_mode_not_implemented",
        "reason": "Real containment adapters must be implemented per action before ACTION_EXECUTOR_MODE=execute is enabled.",
        "attempt": attempt,
    }, 501


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._json({"status": "ok", "service": "soc-action-executor", "execution_mode": EXECUTION_MODE, "allowed_actions": sorted(ALLOWED_ACTIONS)})
            return
        if path == "/metrics":
            attempts = recent_attempts(20)
            self._json({"success": True, "service": "soc-action-executor", "execution_mode": EXECUTION_MODE, "recent_attempt_count": len(attempts), "recent_attempts": attempts, "started_at": int(STARTED_AT), "uptime_seconds": int(time.time() - STARTED_AT)})
            return
        self._json({"error": "not_found"}, status=404)

    def do_POST(self):
        action = urlparse(self.path).path.strip("/")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            body, status = execute_action(action, payload)
            self._json(body, status=status)
        except Exception as exc:
            self._json({"success": False, "status": "executor_error", "error": f"{type(exc).__name__}: {exc}"}, status=500)

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
