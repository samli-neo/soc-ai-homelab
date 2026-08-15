import json
import os
import ssl
import time
import zipfile
from io import BytesIO
import urllib.error
import urllib.parse
import urllib.request
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


CAPE_BASE_URL = os.environ.get("CAPE_BASE_URL", "https://10.10.50.102").rstrip("/")
CAPE_API_KEY = os.environ.get("CAPEV2_API_KEY_MALWARE_ANALYST") or os.environ.get("CAPE_API_KEY") or os.environ.get("CAPEV2_API_KEY") or ""
DEFAULT_AGENT_ID = os.environ.get("SOC_CAPE_AGENT_ID", "malware_analyst")
VERIFY_TLS = os.environ.get("CAPE_VERIFY_TLS", "false").lower() == "true"
MAX_REPORT_SIGNATURES = int(os.environ.get("CAPE_MAX_REPORT_SIGNATURES", "10"))
SANDBOX_LABEL = os.environ.get("CAPE_SANDBOX_LABEL", "win11")
SANDBOX_IP = os.environ.get("CAPE_SANDBOX_IP", "10.10.50.103")
SANDBOX_AGENT_PORT = int(os.environ.get("CAPE_SANDBOX_AGENT_PORT", "8000"))
ALLOW_DETONATION = os.environ.get("CAPE_ALLOW_SAMPLE_DETONATION", "false").lower() == "true"
CAPE_POLL_INTERVAL_SECONDS = int(os.environ.get("CAPE_POLL_INTERVAL_SECONDS", "10"))
CAPE_ANALYSIS_TIMEOUT_SECONDS = int(os.environ.get("CAPE_ANALYSIS_TIMEOUT_SECONDS", "300"))
CAPE_POLL_TIMEOUT_SECONDS = int(os.environ.get("CAPE_POLL_TIMEOUT_SECONDS", str(CAPE_ANALYSIS_TIMEOUT_SECONDS + 180)))
CAPE_ANALYSIS_PACKAGE = os.environ.get("CAPE_ANALYSIS_PACKAGE", "exe")
CAPE_ANALYSIS_ROUTE = os.environ.get("CAPE_ANALYSIS_ROUTE", "none")
CAPE_ANALYSIS_OPTIONS = os.environ.get("CAPE_ANALYSIS_OPTIONS", "procmemdump=yes,import_reconstruction=yes,strings=yes")
CAPE_ENFORCE_TIMEOUT = os.environ.get("CAPE_ENFORCE_TIMEOUT", "true").lower() in {"1", "true", "yes", "on"}


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


def extract_hashes(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    hashes = []
    seen = set()
    for field in ("sha256", "sha1", "md5"):
        value = str(data.get(field) or "").strip()
        if not value or value in {"-", "null", "None"} or value in seen:
            continue
        seen.add(value)
        hashes.append({"type": field, "value": value})
    return hashes


def cape_headers():
    headers = {"Accept": "application/json"}
    if CAPE_API_KEY:
        headers["Authorization"] = f"Token {CAPE_API_KEY}"
    return headers


def request_json(path, timeout=20, method="GET", payload=None, content_type="application/json"):
    context = None if VERIFY_TLS else ssl._create_unverified_context()
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = cape_headers()
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(f"{CAPE_BASE_URL}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        text = response.read().decode("utf-8")
        return response.status, json.loads(text) if text else {}


def request_bytes(path, timeout=60):
    context = None if VERIFY_TLS else ssl._create_unverified_context()
    req = urllib.request.Request(f"{CAPE_BASE_URL}{path}", headers=cape_headers(), method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        return response.status, response.read()


def cape_api_status():
    try:
        status, response = request_json("/apiv2/tasks/list/?limit=1&offset=0", timeout=10)
        return {"reachable": True, "status": status, "error": False, "task_count": len(response.get("data") or []) if isinstance(response, dict) else None}
    except urllib.error.HTTPError as exc:
        return {"reachable": False, "status": exc.code, "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"reachable": False, "status": None, "error": f"{type(exc).__name__}: {exc}"}


def sandbox_ready():
    checks = []
    for port in (SANDBOX_AGENT_PORT, 3389):
        sock = socket.socket()
        sock.settimeout(2)
        try:
            sock.connect((SANDBOX_IP, port))
            open_port = True
            error = ""
        except Exception as exc:
            open_port = False
            error = f"{type(exc).__name__}: {exc}"
        finally:
            sock.close()
        checks.append({"host": SANDBOX_IP, "port": port, "open": open_port, "error": error})
    agent_open = any(item["port"] == SANDBOX_AGENT_PORT and item["open"] for item in checks)
    return {
        "label": SANDBOX_LABEL,
        "ip": SANDBOX_IP,
        "agent_port": SANDBOX_AGENT_PORT,
        "ready": agent_open,
        "checks": checks,
    }


def extract_sample_request(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    file_path = str(data.get("sample_path") or data.get("cape_sample_path") or "").strip()
    url = str(data.get("sample_url") or data.get("cape_sample_url") or "").strip()
    return {"file_path": file_path, "url": url}


def multipart_body(fields, files=None):
    boundary = "----soc-capev2-runner-%d" % int(time.time() * 1000)
    chunks = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode("utf-8"))
    for field, spec in (files or {}).items():
        filename, content = spec
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode("utf-8"))
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    return boundary, b"".join(chunks)


def post_multipart(path, fields, files=None, timeout=60):
    context = None if VERIFY_TLS else ssl._create_unverified_context()
    boundary, body = multipart_body(fields, files)
    headers = cape_headers()
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    req = urllib.request.Request(f"{CAPE_BASE_URL}{path}", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        text = response.read().decode("utf-8")
        return response.status, json.loads(text) if text else {}


def submit_sample(sample):
    fields = {
        "machine": SANDBOX_LABEL,
        "timeout": str(CAPE_ANALYSIS_TIMEOUT_SECONDS),
        "priority": "2",
        "route": CAPE_ANALYSIS_ROUTE,
        "options": CAPE_ANALYSIS_OPTIONS,
        "enforce_timeout": "1" if CAPE_ENFORCE_TIMEOUT else "0",
    }
    if CAPE_ANALYSIS_PACKAGE:
        fields["package"] = CAPE_ANALYSIS_PACKAGE
    if sample.get("file_path"):
        file_path = sample["file_path"]
        if not os.path.isfile(file_path):
            return {"submitted": False, "error": "sample_file_not_found", "sample_path": file_path}
        with open(file_path, "rb") as handle:
            content = handle.read()
        upload_filename = cape_upload_filename(file_path)
        status, response = post_multipart("/apiv2/tasks/create/file/", fields, {"file": (upload_filename, content)}, timeout=120)
    elif sample.get("url"):
        fields["url"] = sample["url"]
        status, response = post_multipart("/apiv2/tasks/create/url/", fields, timeout=60)
    else:
        return {"submitted": False, "status": "no_sample_requested"}
    task_ids = []
    data = response.get("data") if isinstance(response.get("data"), dict) else {}
    if isinstance(data.get("task_ids"), list):
        task_ids = data["task_ids"]
    elif response.get("task_id"):
        task_ids = [response.get("task_id")]
    response_error = bool(response.get("error"))
    if response_error or not task_ids:
        result = {"submitted": False, "http_status": status, "task_ids": task_ids, "task_reports": [], "submission_fields": safe_submission_fields(fields), "response_error": response_error, "response_error_value": response.get("error_value") or "no_task_ids_returned"}
        if sample.get("file_path"):
            result["upload_filename"] = upload_filename
        return result
    task_reports = [poll_task_report(int(task_id)) for task_id in task_ids if str(task_id).isdigit()]
    result = {"submitted": True, "http_status": status, "task_ids": task_ids, "task_reports": task_reports, "submission_fields": safe_submission_fields(fields), "response_error": False, "response_error_value": response.get("error_value")}
    if sample.get("file_path"):
        result["upload_filename"] = upload_filename
    return result


def cape_upload_filename(file_path):
    filename = os.path.basename(file_path)
    if CAPE_ANALYSIS_PACKAGE.lower() == "exe" and not filename.lower().endswith(".exe"):
        return f"{filename}.exe"
    return filename


def safe_submission_fields(fields):
    return {key: fields.get(key) for key in ("machine", "timeout", "priority", "route", "package", "options", "enforce_timeout") if key in fields}


def task_status(task_id):
    _, task = request_json(f"/apiv2/tasks/view/{task_id}/", timeout=20)
    data = task.get("data") if isinstance(task.get("data"), dict) else task
    return data if isinstance(data, dict) else {}


def poll_task_report(task_id):
    deadline = time.time() + CAPE_POLL_TIMEOUT_SECONDS
    last_task = {}
    while time.time() <= deadline:
        try:
            last_task = task_status(task_id)
        except Exception as exc:
            return {"task_id": task_id, "reported": False, "status": "task_status_error", "error": f"{type(exc).__name__}: {exc}"}
        status = str(last_task.get("status") or "").lower()
        if status == "reported":
            try:
                summary = report_summary(task_id)
                summary["reported"] = True
                summary["task_status"] = status
                return summary
            except Exception as exc:
                return {"task_id": task_id, "reported": True, "status": "report_fetch_error", "error": f"{type(exc).__name__}: {exc}", "task": compact_task(last_task)}
        if status in {"failed_analysis", "failed_processing", "failed_reporting"}:
            return {"task_id": task_id, "reported": False, "task_status": status, "task": compact_task(last_task)}
        time.sleep(CAPE_POLL_INTERVAL_SECONDS)
    return {"task_id": task_id, "reported": False, "task_status": str(last_task.get("status") or "timeout"), "timeout_seconds": CAPE_POLL_TIMEOUT_SECONDS, "task": compact_task(last_task)}


def compact_task(task):
    sample = task.get("sample") if isinstance(task.get("sample"), dict) else {}
    return {
        "id": task.get("id"),
        "status": task.get("status"),
        "machine": task.get("machine"),
        "started_on": task.get("started_on"),
        "completed_on": task.get("completed_on"),
        "sample_sha256": sample.get("sha256"),
        "errors": task.get("errors"),
    }


def search_hash(item):
    quoted = urllib.parse.quote(item["value"], safe="")
    status, response = request_json(f"/apiv2/tasks/search/{item['type']}/{quoted}/", timeout=20)
    tasks = response.get("data") if isinstance(response.get("data"), list) else []
    reported = [task for task in tasks if str(task.get("status") or "").lower() == "reported"]
    selected = sorted(reported or tasks, key=lambda task: int(task.get("id") or 0), reverse=True)[:1]
    result = {
        "success": True,
        "status": status,
        "observable": item,
        "match_count": len(tasks),
        "reported_match_count": len(reported),
        "selected_task_id": selected[0].get("id") if selected else None,
        "selected_task_status": selected[0].get("status") if selected else None,
    }
    if selected and str(selected[0].get("status") or "").lower() == "reported":
        result["report_summary"] = report_summary(int(selected[0]["id"]))
    return result


def report_summary(task_id):
    _, task = request_json(f"/apiv2/tasks/view/{task_id}/", timeout=20)
    _, report = request_json(f"/apiv2/tasks/get/report/{task_id}/json/", timeout=40)
    signatures = report.get("signatures") if isinstance(report.get("signatures"), list) else []
    alert_signatures = [sig for sig in signatures if sig.get("alert")]
    malscore = report.get("malscore") or 0
    try:
        malscore = float(malscore)
    except (TypeError, ValueError):
        malscore = 0.0
    verdict = "malicious" if alert_signatures or malscore >= 6 else "suspicious" if malscore >= 1 else "benign"
    sample = (task.get("data") or {}).get("sample") if isinstance(task.get("data"), dict) else {}
    task_data = task.get("data") if isinstance(task.get("data"), dict) else task if isinstance(task, dict) else {}
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    behavior = report.get("behavior") if isinstance(report.get("behavior"), dict) else {}
    dropped = report.get("dropped") if isinstance(report.get("dropped"), list) else []
    errors = report.get("errors") if isinstance(report.get("errors"), list) else []
    debug = report.get("debug") if isinstance(report.get("debug"), dict) else {}
    analysis_log = analysis_log_summary(task_id)
    return {
        "task_id": task_id,
        "reported": True,
        "task_status": task_data.get("status"),
        "verdict": verdict,
        "malscore": malscore,
        "malstatus": report.get("malstatus"),
        "target": report.get("target"),
        "info": report.get("info"),
        "errors": errors[:10],
        "debug": {key: debug.get(key) for key in sorted(debug.keys())[:10]} if debug else {},
        "sample": {
            "md5": sample.get("md5") if isinstance(sample, dict) else None,
            "sha1": sample.get("sha1") if isinstance(sample, dict) else None,
            "sha256": sample.get("sha256") if isinstance(sample, dict) else None,
            "file_type": sample.get("file_type") if isinstance(sample, dict) else None,
            "file_size": sample.get("file_size") if isinstance(sample, dict) else None,
        },
        "signatures_total": len(signatures),
        "alert_signature_count": len(alert_signatures),
        "signatures": [
            {
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity"),
                "confidence": sig.get("confidence"),
                "alert": sig.get("alert"),
            }
            for sig in signatures[:MAX_REPORT_SIGNATURES]
        ],
        "observables": {
            "domains": [item.get("domain") or item for item in network.get("domains", [])[:20]] if isinstance(network.get("domains"), list) else [],
            "hosts": [item.get("ip") or item for item in network.get("hosts", [])[:20]] if isinstance(network.get("hosts"), list) else [],
            "files_written": [item.get("path") or item.get("name") or item for item in dropped[:20] if isinstance(item, dict)] if dropped else [],
        },
        "behavior_summary": {
            "process_count": len(behavior.get("processes") or []) if isinstance(behavior.get("processes"), list) else 0,
            "generic_count": len(behavior.get("generic") or []) if isinstance(behavior.get("generic"), list) else 0,
        },
        "analysis_log_summary": analysis_log,
    }


def analysis_log_summary(task_id):
    try:
        _, archive = request_bytes(f"/apiv2/tasks/get/report/{task_id}/all/", timeout=90)
        with zipfile.ZipFile(BytesIO(archive)) as zf:
            with zf.open("analysis.log") as handle:
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    executed = [line for line in lines if "Successfully executed process" in line]
    injected = [line for line in lines if "Injected into" in line]
    resumed = [line for line in lines if "Successfully resumed" in line]
    warnings = [line for line in lines if " WARNING: " in line]
    errors = [line for line in lines if " ERROR: " in line or "Traceback" in line or "CuckooError" in line]
    failed_open = [line for line in lines if "failed to open process" in line]
    return {
        "available": True,
        "line_count": len(lines),
        "executed_process_count": len(executed),
        "injected_process_count": len(injected),
        "resumed_process_count": len(resumed),
        "warning_count": len(warnings),
        "error_count": len(errors),
        "failed_open_process_count": len(failed_open),
        "executed_processes": executed[:10],
        "injected_processes": injected[:10],
        "errors": errors[:10],
        "warnings": warnings[:10],
    }


def analyze(payload):
    alert = parse_alert(payload)
    hashes = extract_hashes(alert)
    sample = extract_sample_request(alert)
    api_status = cape_api_status()
    readiness = sandbox_ready()
    results = []
    status = "no_hash_observable"
    if not api_status["reachable"]:
        return {
            "success": True,
            "soc_stage": "capev2_malware_analysis",
            "status": "cape_api_unreachable",
            "execution_audit": {
                "agent_id": DEFAULT_AGENT_ID,
                "credential_env": "CAPEV2_API_KEY_MALWARE_ANALYST" if os.environ.get("CAPEV2_API_KEY_MALWARE_ANALYST") else "CAPE_API_KEY" if os.environ.get("CAPE_API_KEY") else "none",
                "credential_scope": "agent_dedicated" if os.environ.get("CAPEV2_API_KEY_MALWARE_ANALYST") else "fallback_or_anonymous",
            },
            "cape_base_url": CAPE_BASE_URL,
            "cape_api": api_status,
            "sandbox": readiness,
            "hash_count": len(hashes),
            "results": [],
            "sample_request": {"has_file_path": bool(sample.get("file_path")), "has_url": bool(sample.get("url"))},
            "sample_detonation": {"submitted": False, "status": "cape_api_unreachable"},
            "executed_actions": [],
            "approval_required": False,
            "sample_detonation_executed": False,
        }
    for item in hashes:
        try:
            results.append(search_hash(item))
        except urllib.error.HTTPError as exc:
            results.append({"success": False, "observable": item, "error": f"HTTP {exc.code}"})
        except Exception as exc:
            results.append({"success": False, "observable": item, "error": f"{type(exc).__name__}: {exc}"})
    if results:
        status = "cape_hash_reports_checked"
    detonation = {"submitted": False, "status": "not_requested"}
    sample_requested = bool(sample.get("file_path") or sample.get("url"))
    if sample_requested and not ALLOW_DETONATION:
        detonation = {"submitted": False, "status": "detonation_disabled", "reason": "CAPE_ALLOW_SAMPLE_DETONATION is not true"}
    elif sample_requested and not readiness["ready"]:
        detonation = {"submitted": False, "status": "sandbox_not_ready", "sandbox": readiness}
    elif sample_requested:
        detonation = submit_sample(sample)
        status = "cape_sample_submitted" if detonation.get("submitted") else "cape_sample_submission_failed"
    return {
        "success": True,
        "soc_stage": "capev2_malware_analysis",
        "status": status,
        "execution_audit": {
            "agent_id": DEFAULT_AGENT_ID,
            "credential_env": "CAPEV2_API_KEY_MALWARE_ANALYST" if os.environ.get("CAPEV2_API_KEY_MALWARE_ANALYST") else "CAPE_API_KEY" if os.environ.get("CAPE_API_KEY") else "none",
            "credential_scope": "agent_dedicated" if os.environ.get("CAPEV2_API_KEY_MALWARE_ANALYST") else "fallback_or_anonymous",
        },
        "cape_base_url": CAPE_BASE_URL,
        "cape_api": api_status,
        "sandbox": readiness,
        "hash_count": len(hashes),
        "results": results,
        "sample_request": {"has_file_path": bool(sample.get("file_path")), "has_url": bool(sample.get("url"))},
        "sample_detonation": detonation,
        "executed_actions": (["cape_hash_search", "cape_report_lookup"] if hashes else []) + (["cape_sample_submit"] if detonation.get("submitted") else []),
        "approval_required": False,
        "sample_detonation_executed": bool(detonation.get("submitted")),
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
        if urlparse(self.path).path != "/analyze":
            self.send_response(404)
            self.end_headers()
            return
        start = time.time()
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = analyze(payload)
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
