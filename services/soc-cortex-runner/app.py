import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


CORTEX_BASE_URL = os.environ.get("CORTEX_BASE_URL", "http://cortex:9001")
CORTEX_API_KEY = os.environ["CORTEX_API_KEY"]
DEFAULT_AGENT_ID = os.environ.get("SOC_CORTEX_AGENT_ID", "l1_triage")
AGENT_EXECUTION_MODE = os.environ.get("SOC_AGENT_EXECUTION_MODE", "canary").strip().lower()
MAX_JOBS = int(os.environ.get("MAX_CORTEX_JOBS", "16"))
JOB_WAIT_SECONDS = int(os.environ.get("CORTEX_JOB_WAIT_SECONDS", "45"))


def parse_alert(payload):
    value = payload.get("execution_argument") or payload.get("alert") or payload
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except Exception:
            return {"raw": value[:2000]}
    return {}


def observable_type(field, value):
    field = (field or "").lower()
    value = str(value or "").strip()
    if not value:
        return ""
    if field in {"srcip", "dstip"}:
        return "ip"
    if field in {"sha256", "sha1", "md5"}:
        return "hash"
    if field in {"domain", "hostname", "fqdn"}:
        return "domain"
    if field == "url" or value.startswith(("http://", "https://")):
        return "url"
    return field or "unknown"


def extract_observables(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    observables = []
    seen = set()
    for field in ("srcip", "dstip", "domain", "hostname", "url", "sha256", "sha1", "md5"):
        value = str(data.get(field) or "").strip()
        if not value or value in {"-", "null", "None"}:
            continue
        dtype = observable_type(field, value)
        key = (dtype, value)
        if key in seen:
            continue
        seen.add(key)
        observables.append({"field": field, "type": dtype, "value": value})
    return observables


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def rule_level(alert):
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    try:
        return int(rule.get("level") or 0)
    except (TypeError, ValueError):
        return 0


def env_name_for_agent(prefix, agent_id):
    normalized = "".join(char if char.isalnum() else "_" for char in str(agent_id or "").upper()).strip("_")
    return f"{prefix}_{normalized}"


def cortex_api_key(agent_id=DEFAULT_AGENT_ID):
    env_name = env_name_for_agent("CORTEX_API_KEY", agent_id)
    key = os.environ.get(env_name)
    if key:
        return key, {"agent_id": agent_id, "credential_env": env_name, "credential_scope": "agent_dedicated"}
    return CORTEX_API_KEY, {"agent_id": agent_id, "credential_env": "CORTEX_API_KEY", "credential_scope": "fallback_shared"}


def request_json(method, path, payload=None, timeout=30, agent_id=DEFAULT_AGENT_ID):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    key, _ = cortex_api_key(agent_id)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {key}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"{CORTEX_BASE_URL}{path}",
        data=body,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        text = response.read().decode("utf-8")
        return response.status, json.loads(text) if text else {}


def analyzer_map(agent_id=DEFAULT_AGENT_ID):
    status, analyzers = request_json("GET", "/api/analyzer?range=all", timeout=15, agent_id=agent_id)
    if status != 200 or not isinstance(analyzers, list):
        return {}
    return {item.get("name"): item for item in analyzers if item.get("name") and item.get("id")}


def select_jobs(observables, analyzers, alert_level):
    selected = []
    for observable in observables:
        dtype = observable["type"]
        value = observable["value"]
        names = ["ValidateObservable"]
        if dtype == "ip":
            if is_public_ip(value):
                if alert_level >= 12:
                    names.append("AbuseIPDB")
                    names.append("VirusTotal_GetReport")
                names.extend(["DShield_lookup", "TorProject", "IP-API", "Mnemonic_pDNS_Public"])
            names.append("GoogleDNS_resolve")
        elif dtype == "domain":
            if alert_level >= 12:
                names.append("VirusTotal_GetReport")
            names.extend(["SpamhausDBL", "DomainMailSPFDMARC", "GoogleDNS_resolve", "Mnemonic_pDNS_Public", "IP-API"])
        elif dtype == "url":
            if alert_level >= 12:
                names.append("VirusTotal_GetReport")
            names.append("UnshortenLink")
        elif dtype == "hash":
            if alert_level >= 12:
                names.append("VirusTotal_GetReport")
            names.extend(["CIRCLHashlookup", "Hashdd_Status"])
        for name in names:
            analyzer = analyzers.get(name)
            if analyzer:
                selected.append({"observable": observable, "analyzer": analyzer})
            if len(selected) >= MAX_JOBS:
                return selected
    return selected


def run_job(item, agent_id=DEFAULT_AGENT_ID):
    analyzer = item["analyzer"]
    observable = item["observable"]
    payload = {"data": observable["value"], "dataType": observable["type"], "tlp": 2, "pap": 2}
    _, created = request_json("POST", f"/api/analyzer/{analyzer['id']}/run", payload=payload, timeout=20, agent_id=agent_id)
    job_id = created.get("id")
    if not job_id:
        return {"success": False, "analyzer": analyzer.get("name"), "observable": observable, "error": "missing_job_id"}
    _, report = request_json("GET", f"/api/job/{job_id}/waitreport?atMost={JOB_WAIT_SECONDS}seconds", timeout=JOB_WAIT_SECONDS + 10, agent_id=agent_id)
    report_body = report.get("report") if isinstance(report.get("report"), dict) else {}
    summary = report_body.get("summary") if isinstance(report_body.get("summary"), dict) else {}
    return {
        "success": report.get("status") == "Success",
        "job_id": job_id,
        "status": report.get("status"),
        "analyzer": analyzer.get("name"),
        "analyzer_definition_id": analyzer.get("analyzerDefinitionId") or analyzer.get("workerDefinitionId"),
        "observable": observable,
        "error_message": report.get("errorMessage") or report_body.get("errorMessage"),
        "taxonomies": summary.get("taxonomies") or [],
        "summary": summary,
    }


def triage(payload):
    alert = parse_alert(payload)
    agent_id = str(payload.get("agent") or payload.get("agent_id") or DEFAULT_AGENT_ID).strip() or DEFAULT_AGENT_ID
    _, execution_audit = cortex_api_key(agent_id)
    alert_level = rule_level(alert)
    observables = extract_observables(alert)
    status, cortex_status = request_json("GET", "/api/status", timeout=10, agent_id=agent_id)
    analyzers = analyzer_map(agent_id=agent_id)
    selected = select_jobs(observables, analyzers, alert_level)
    results = []
    if AGENT_EXECUTION_MODE == "propose_only":
        return {
            "success": True,
            "soc_stage": "cortex_observable_triage",
            "status": "cortex_jobs_proposed_only",
            "execution_mode": AGENT_EXECUTION_MODE,
            "execution_audit": execution_audit,
            "cortex_available": status == 200,
            "cortex_status_code": status,
            "cortex_version": ((cortex_status.get("versions") or {}).get("Cortex") if isinstance(cortex_status, dict) else None),
            "enabled_analyzer_count": len(analyzers),
            "observable_count": len(observables),
            "rule_level": alert_level,
            "observables": observables,
            "selected_job_count": len(selected),
            "proposed_jobs": [{"observable": item["observable"], "analyzer": item["analyzer"].get("name")} for item in selected],
            "job_results": [],
            "successful_job_count": 0,
            "failed_job_count": 0,
            "duration_ms": None,
        }
    for item in selected:
        try:
            results.append(run_job(item, agent_id=agent_id))
        except urllib.error.HTTPError as exc:
            results.append({"success": False, "analyzer": item["analyzer"].get("name"), "observable": item["observable"], "error": f"HTTP {exc.code}"})
        except Exception as exc:
            results.append({"success": False, "analyzer": item["analyzer"].get("name"), "observable": item["observable"], "error": f"{type(exc).__name__}: {exc}"})
    return {
        "success": True,
        "soc_stage": "cortex_observable_triage",
        "status": "cortex_jobs_completed" if results else "no_cortex_jobs_selected",
        "execution_mode": AGENT_EXECUTION_MODE,
        "execution_audit": execution_audit,
        "cortex_available": status == 200,
        "cortex_status_code": status,
        "cortex_version": ((cortex_status.get("versions") or {}).get("Cortex") if isinstance(cortex_status, dict) else None),
        "enabled_analyzer_count": len(analyzers),
        "observable_count": len(observables),
        "rule_level": alert_level,
        "observables": observables,
        "selected_job_count": len(selected),
        "job_results": results,
        "successful_job_count": sum(1 for result in results if result.get("success")),
        "failed_job_count": sum(1 for result in results if result.get("success") is False),
        "duration_ms": None,
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
        if urlparse(self.path).path != "/triage":
            self.send_response(404)
            self.end_headers()
            return
        start = time.time()
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = triage(payload)
            result["duration_ms"] = int((time.time() - start) * 1000)
            self._json(result)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:2000]
            self._json({"success": False, "error": f"HTTP {exc.code}", "body": body}, status=502)
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
