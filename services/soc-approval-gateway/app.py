import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


DATA_DIR = Path(os.environ.get("APPROVAL_DATA_DIR", "/data")).resolve()
DB_PATH = DATA_DIR / "approvals.sqlite3"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
APPROVAL_SIGNING_SECRET = os.environ.get("APPROVAL_SIGNING_SECRET", "").strip() or secrets.token_hex(32)
ACTION_EXECUTOR_URL = os.environ.get("ACTION_EXECUTOR_URL", "").rstrip("/")
EXECUTION_MODE = os.environ.get("APPROVAL_EXECUTION_MODE", "audit_only").strip().lower()
TELEGRAM_POLLING_ENABLED = os.environ.get("TELEGRAM_POLLING_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
DEFAULT_TTL_SECONDS = int(os.environ.get("APPROVAL_DEFAULT_TTL_SECONDS", "1800"))
MAX_TTL_SECONDS = int(os.environ.get("APPROVAL_MAX_TTL_SECONDS", "3600"))
ALLOWED_CHAT_IDS = {item.strip() for item in os.environ.get("TELEGRAM_ALLOWED_CHAT_IDS", TELEGRAM_CHAT_ID).split(",") if item.strip()}
ALLOWED_USER_IDS = {item.strip() for item in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if item.strip()}
HIGH_RISK_ACTIONS = {"pfsense_block", "snort_rule_change", "velociraptor_isolate", "wazuh_active_response", "account_disable", "sample_detonation"}


def json_response(handler, body, status=200):
    data = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def now_ts():
    return int(time.time())


def connect_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            request_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            action TEXT NOT NULL,
            target_json TEXT NOT NULL,
            request_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            decided_at INTEGER,
            decided_by TEXT,
            decision_reason TEXT,
            telegram_message_id TEXT,
            execution_json TEXT
        )
        """
    )
    conn.commit()
    return conn


def row_to_dict(row):
    if not row:
        return None
    result = dict(row)
    for key in ("target_json", "request_json", "execution_json"):
        value = result.get(key)
        if value:
            try:
                result[key.replace("_json", "")] = json.loads(value)
            except Exception:
                result[key.replace("_json", "")] = value
        result.pop(key, None)
    return result


def read_request(request_id):
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE request_id = ?", (request_id,)).fetchone()
    return row_to_dict(row)


def sign_callback(request_id, decision):
    msg = f"{request_id}:{decision}".encode("utf-8")
    return hmac.new(APPROVAL_SIGNING_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:16]


def callback_data(request_id, decision):
    return f"soc:{decision}:{request_id}:{sign_callback(request_id, decision)}"


def verify_callback(data):
    parts = str(data or "").split(":")
    if len(parts) != 4 or parts[0] != "soc":
        return None, None, False
    _, decision, request_id, sig = parts
    if decision not in {"approve", "deny", "info"}:
        return request_id, decision, False
    return request_id, decision, hmac.compare_digest(sig, sign_callback(request_id, decision))


def telegram_api(method, payload):
    if not TELEGRAM_BOT_TOKEN:
        return {"sent": False, "status": "telegram_disabled", "reason": "TELEGRAM_BOT_TOKEN not configured"}
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = json.loads(response.read().decode("utf-8") or "{}")
            return {"sent": bool(body.get("ok")), "http_status": response.status, "response": body}
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")[:1000]
        return {"sent": False, "http_status": exc.code, "error": text}
    except Exception as exc:
        return {"sent": False, "error": f"{type(exc).__name__}: {exc}"}


def telegram_poll_updates():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_POLLING_ENABLED:
        return
    offset = None
    while True:
        payload = {"timeout": 25, "allowed_updates": ["callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        result = telegram_api("getUpdates", payload)
        response = result.get("response") if isinstance(result.get("response"), dict) else {}
        updates = response.get("result") if response.get("ok") else []
        if isinstance(updates, list):
            for update in updates:
                update_id = update.get("update_id")
                if isinstance(update_id, int):
                    offset = max(offset or 0, update_id + 1)
                handle_telegram_update(update, {"X-Telegram-Bot-Api-Secret-Token": TELEGRAM_WEBHOOK_SECRET})
        time.sleep(1 if result.get("sent") else 10)


def approval_message(request_id, request):
    target = request.get("target") if isinstance(request.get("target"), dict) else {}
    evidence = request.get("evidence") if isinstance(request.get("evidence"), dict) else {}
    action = str(request.get("action") or "unknown")
    severity = str(request.get("severity") or "unknown").upper()
    case_id = str(request.get("case_id") or "unknown")
    reason = str(request.get("reason") or "")[:900]
    risk = str(request.get("risk") or "High-risk SOC action requires confirmation.")[:700]
    target_text = json.dumps(target, sort_keys=True)[:700] if target else "{}"
    evidence_text = json.dumps(evidence, sort_keys=True)[:900] if evidence else "{}"
    lines = [
        "SOC Human Approval Required",
        "",
        f"Severity: {severity}",
        f"Action: {action}",
        f"Case: {case_id}",
        f"Request: {request_id}",
        "",
        f"Target: {target_text}",
        "",
        f"Why: {reason}",
        "",
        f"Risk if approved: {risk}",
        "",
        "Current mode: audit_only (records decision; does not execute containment).",
        "",
        "Use Approve only when target, evidence, and blast radius are acceptable.",
    ]
    if evidence:
        lines.extend(["", f"Evidence: {evidence_text}"])
    return "\n".join(lines)[:3500]


def send_telegram_approval(request_id, request):
    if not TELEGRAM_CHAT_ID:
        return {"sent": False, "status": "telegram_disabled", "reason": "TELEGRAM_CHAT_ID not configured"}
    keyboard = {
        "inline_keyboard": [
            [
                {"text": "Approve", "callback_data": callback_data(request_id, "approve")},
                {"text": "Deny", "callback_data": callback_data(request_id, "deny")},
            ],
            [{"text": "Need More Info", "callback_data": callback_data(request_id, "info")}],
        ]
    }
    return telegram_api("sendMessage", {"chat_id": TELEGRAM_CHAT_ID, "text": approval_message(request_id, request), "reply_markup": keyboard})


def create_approval(payload):
    action = str(payload.get("action") or "").strip()
    if not action:
        return {"success": False, "error": "action is required"}, 400
    if action not in HIGH_RISK_ACTIONS:
        return {"success": False, "error": "action is not configured as high-risk"}, 400
    request_id = str(payload.get("request_id") or f"apr-{int(time.time())}-{secrets.token_hex(4)}")
    ttl = min(max(int(payload.get("ttl_seconds") or DEFAULT_TTL_SECONDS), 60), MAX_TTL_SECONDS)
    created = now_ts()
    expires = created + ttl
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    with connect_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO approvals
            (request_id, status, action, target_json, request_json, created_at, expires_at)
            VALUES (?, 'pending', ?, ?, ?, ?, ?)
            """,
            (request_id, action, json.dumps(target, sort_keys=True), json.dumps(payload, sort_keys=True), created, expires),
        )
        conn.commit()
    telegram = send_telegram_approval(request_id, payload)
    message_id = (((telegram.get("response") or {}).get("result") or {}).get("message_id")) if telegram.get("sent") else None
    if message_id:
        with connect_db() as conn:
            conn.execute("UPDATE approvals SET telegram_message_id = ? WHERE request_id = ?", (str(message_id), request_id))
            conn.commit()
    result = read_request(request_id)
    result["success"] = True
    result["telegram"] = {key: value for key, value in telegram.items() if key != "response"}
    result["execution_mode"] = EXECUTION_MODE
    result["approval_required"] = True
    return result, 200


def execute_approved_action(record):
    if EXECUTION_MODE != "execute" or not ACTION_EXECUTOR_URL:
        return {"executed": False, "status": "audit_only", "reason": "APPROVAL_EXECUTION_MODE is not execute or ACTION_EXECUTOR_URL is unset"}
    payload = {"approval": record, "approval_token": sign_callback(record["request_id"], "approve")}
    data = json.dumps(payload).encode("utf-8")
    url = f"{ACTION_EXECUTOR_URL}/{record['action']}"
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return {"executed": True, "http_status": response.status, "response": json.loads(response.read().decode("utf-8") or "{}")}
    except Exception as exc:
        return {"executed": False, "status": "executor_error", "error": f"{type(exc).__name__}: {exc}"}


def decide(request_id, decision, user_id, reason=""):
    record = read_request(request_id)
    if not record:
        return {"success": False, "error": "approval_not_found"}, 404
    if record["status"] != "pending":
        return {"success": False, "error": "approval_already_decided", "approval": record}, 409
    if int(record["expires_at"]) < now_ts():
        with connect_db() as conn:
            conn.execute("UPDATE approvals SET status = 'expired', decided_at = ?, decided_by = ?, decision_reason = ? WHERE request_id = ?", (now_ts(), user_id, "expired", request_id))
            conn.commit()
        return {"success": False, "error": "approval_expired", "approval": read_request(request_id)}, 409
    status = "approved" if decision == "approve" else "denied" if decision == "deny" else "info_requested"
    execution = {}
    with connect_db() as conn:
        conn.execute("UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ? WHERE request_id = ?", (status, now_ts(), user_id, reason, request_id))
        conn.commit()
    updated = read_request(request_id)
    if status == "approved":
        execution = execute_approved_action(updated)
        with connect_db() as conn:
            conn.execute("UPDATE approvals SET execution_json = ? WHERE request_id = ?", (json.dumps(execution, sort_keys=True), request_id))
            conn.commit()
        updated = read_request(request_id)
    return {"success": True, "approval": updated, "execution": execution}, 200


def handle_telegram_update(update, headers):
    if TELEGRAM_WEBHOOK_SECRET and headers.get("X-Telegram-Bot-Api-Secret-Token") != TELEGRAM_WEBHOOK_SECRET:
        return {"success": False, "error": "invalid_telegram_secret"}, 403
    callback = update.get("callback_query") if isinstance(update.get("callback_query"), dict) else None
    if not callback:
        return {"success": True, "status": "ignored_non_callback"}, 200
    message = callback.get("message") if isinstance(callback.get("message"), dict) else {}
    chat_id = str((message.get("chat") or {}).get("id") or "")
    user_id = str((callback.get("from") or {}).get("id") or "")
    if ALLOWED_CHAT_IDS and chat_id not in ALLOWED_CHAT_IDS:
        return {"success": False, "error": "chat_not_allowed"}, 403
    if ALLOWED_USER_IDS and user_id not in ALLOWED_USER_IDS:
        return {"success": False, "error": "user_not_allowed"}, 403
    request_id, decision, valid = verify_callback(callback.get("data"))
    if not valid:
        return {"success": False, "error": "invalid_callback_signature"}, 403
    result, status = decide(request_id, decision, user_id, reason=f"telegram_callback:{callback.get('id', '')}")
    telegram_api("answerCallbackQuery", {"callback_query_id": callback.get("id"), "text": result.get("error") or result.get("approval", {}).get("status") or "recorded", "show_alert": False})
    return result, status


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            json_response(self, {"status": "ok", "service": "soc-approval-gateway", "execution_mode": EXECUTION_MODE, "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)})
            return
        if path.startswith("/approval/"):
            record = read_request(path.rsplit("/", 1)[-1])
            if not record:
                json_response(self, {"success": False, "error": "approval_not_found"}, status=404)
                return
            json_response(self, {"success": True, "approval": record})
            return
        json_response(self, {"error": "not_found"}, status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            if path == "/approval/request":
                body, status = create_approval(payload)
                json_response(self, body, status=status)
                return
            if path == "/telegram/webhook":
                body, status = handle_telegram_update(payload, self.headers)
                json_response(self, body, status=status)
                return
            json_response(self, {"error": "not_found"}, status=404)
        except Exception as exc:
            json_response(self, {"success": False, "error": f"{type(exc).__name__}: {exc}"}, status=500)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    connect_db().close()
    threading.Thread(target=telegram_poll_updates, daemon=True).start()
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
