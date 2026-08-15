import hashlib
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote, urlparse

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive-api-compat")
THEHIVE_API_KEY = os.environ["THEHIVE_API_KEY"]
DEFAULT_AGENT_ID = os.environ.get("SOC_THEHIVE_AGENT_ID", "l2_case_manager")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
WINDOW_SECONDS = int(os.environ.get("DEDUP_WINDOW_SECONDS", "900"))
STATE_PATH = DATA_DIR / "dedup-state.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

TASK_OWNERS = {
    "l1_triage": "ai-l1-triage@lab.local",
    "l2_case_manager": "ai-l2-case-manager@lab.local",
    "l3_dfir": "ai-l3-dfir@lab.local",
    "threat_intel": "ai-threat-intel@lab.local",
    "malware_analyst": "ai-malware-analyst@lab.local",
    "detection_engineer": "ai-detection-engineer@lab.local",
    "ir_responder": "ai-ir-responder@lab.local",
    "ciso_reporting": "ai-ciso-reporting@lab.local",
}


def owned_task(owner_key, title, description, group="default"):
    return {
        "title": title,
        "description": description,
        "owner": TASK_OWNERS[owner_key],
        "owner_agent": owner_key,
        "group": group,
    }


def utc_now():
    return datetime.now(timezone.utc)


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


def load_state():
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state):
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    tmp.replace(STATE_PATH)


def clean_state(state, now):
    return {key: value for key, value in state.items() if float(value.get("expires_at", 0)) > now}


def alert_value(alert, *path, default=""):
    current = alert
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current not in (None, "") else default


def is_snort_alert(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    groups = alert_value(alert, "rule", "groups", default=[])
    if isinstance(groups, str):
        groups = [groups]
    return bool(data.get("snort_sid") or data.get("snort_priority") or "snort" in {str(group).lower() for group in groups})


def is_public_ip(value):
    try:
        return ipaddress.ip_address(str(value or "")).is_global
    except ValueError:
        return False


def alert_groups(alert):
    groups = alert_value(alert, "rule", "groups", default=[])
    if isinstance(groups, str):
        groups = [groups]
    return {str(group).lower() for group in groups}


def case_template(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    groups = alert_groups(alert)
    rule_id = str(alert_value(alert, "rule", "id", default=""))
    desc = str(alert_value(alert, "rule", "description", default="")).lower()
    if is_snort_alert(alert):
        return "snort_ids"
    if "firewall" in groups or "pfsense_block" in groups or rule_id in {"100112"}:
        return "pfsense_firewall"
    if any(data.get(field) for field in ("sha256", "sha1", "md5")):
        return "malware_hash"
    if "windows" in groups or "logon" in desc or "login" in desc or "authentication" in groups:
        return "authentication"
    return "generic_wazuh"


def sla_for_level(level):
    try:
        value = int(level)
    except Exception:
        value = 0
    if value >= 12:
        return {"tier": "critical", "ack_minutes": 15, "containment_decision_minutes": 30, "update_minutes": 60}
    if value >= 10:
        return {"tier": "high", "ack_minutes": 60, "containment_decision_minutes": 120, "update_minutes": 240}
    if value >= 7:
        return {"tier": "medium", "ack_minutes": 240, "containment_decision_minutes": 1440, "update_minutes": 1440}
    return {"tier": "low", "ack_minutes": 1440, "containment_decision_minutes": 2880, "update_minutes": 2880}


def professional_tasks(alert, template, sla):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    srcip = str(data.get("srcip") or "")
    tasks = [
        owned_task("l2_case_manager", f"SLA: acknowledge within {sla['ack_minutes']} minutes", "Confirm analyst ownership, severity, affected asset, and whether this is a true positive or expected activity."),
        owned_task("l1_triage", "Triage evidence and timeline", "Review Wazuh alert JSON, source/destination, user/host context, related alerts, and previous duplicates in this case."),
        owned_task("threat_intel", "Review MISP and Cortex enrichment", "Check IOC reputation, Cortex taxonomies, MISP matches, false-positive indicators, and confidence before escalation."),
    ]
    if template == "snort_ids":
        tasks.extend([
            owned_task("detection_engineer", "Validate Snort IDS signature and priority", "Review Snort SID, priority, classification, packet direction, destination service, and whether the alert maps to exploitable exposure."),
            owned_task("l2_case_manager", "Scope IDS source and target", "Check whether source is public/internal, whether destination is a protected SOC service, and whether similar Snort alerts exist from the same source."),
        ])
    elif template == "pfsense_firewall":
        tasks.append(owned_task("ir_responder", "Validate firewall block pattern", "Review repeated block frequency, source reputation, targeted ports, and whether the source is internal/reserved before containment."))
    elif template == "malware_hash":
        tasks.append(owned_task("malware_analyst", "Malware/hash analysis decision", "Review hash reputation and decide whether CAPEv2 detonation or sample handling is needed. Do not detonate without approval."))
    elif template == "authentication":
        tasks.append(owned_task("l2_case_manager", "Authentication review", "Validate user, source IP, time window, MFA/VPN context, and whether activity is expected business behavior."))

    tasks.extend([
        owned_task("l3_dfir", "Approval required: Velociraptor read-only collection", "Approve scope before any endpoint collection. Host isolation, destructive collection, or large acquisition remains prohibited without separate approval."),
        owned_task("ir_responder", "Approval required: containment decision", "Review pfSense/Wazuh/EDR containment proposal, business impact, rollback plan, and owner approval before execution."),
        owned_task("l2_case_manager", "Quality gate: verify evidence before closure", "Before closing, confirm Wazuh source alert, asset context, MISP/Cortex enrichment, DFIR or malware-analysis decision when relevant, IR recommendation, approval status, and final disposition are recorded."),
        owned_task("l2_case_manager", "Closure criteria and lessons learned", "Document disposition, false-positive reason or confirmed impact, evidence reviewed, containment outcome, and detection tuning follow-up."),
    ])
    if srcip and is_public_ip(srcip):
        tasks.append(owned_task("ir_responder", f"Approval candidate: review source block {srcip}", "Only approve if IOC is confirmed malicious, source is not business-critical, and rollback owner is identified."))
    return tasks


def quality_gates(alert, template):
    gates = [
        {"name": "wazuh_source_alert", "required": True, "status": "present" if alert else "missing"},
        {"name": "asset_context", "required": True, "status": "present" if alert.get("soc_asset_context") else "pending"},
        {"name": "triage_score", "required": True, "status": "present" if alert.get("soc_triage") else "pending"},
        {"name": "misp_enrichment", "required": True, "status": "pending"},
        {"name": "cortex_enrichment", "required": True, "status": "pending"},
        {"name": "ir_recommendation", "required": True, "status": "pending"},
        {"name": "human_approval_status", "required": True, "status": "pending"},
        {"name": "final_disposition", "required": True, "status": "pending"},
    ]
    if template in {"malware_hash", "generic_wazuh"}:
        gates.append({"name": "malware_analysis_decision", "required": template == "malware_hash", "status": "pending"})
    if template in {"snort_ids", "pfsense_firewall"}:
        gates.append({"name": "network_containment_decision", "required": True, "status": "pending"})
    return gates


def dedup_key(alert):
    parts = [
        str(alert_value(alert, "rule", "id", default="unknown")),
        str(alert_value(alert, "agent", "name", default="unknown")),
        str(alert_value(alert, "data", "srcip", default="")),
        str(alert_value(alert, "location", default="")),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24], raw


def severity_from_level(level):
    try:
        value = int(level)
    except Exception:
        value = 2
    if value >= 12:
        return 4
    if value >= 9:
        return 3
    if value >= 6:
        return 2
    return 1


def env_name_for_agent(prefix, agent_id):
    normalized = "".join(char if char.isalnum() else "_" for char in str(agent_id or "").upper()).strip("_")
    return f"{prefix}_{normalized}"


def thehive_api_key(agent_id=DEFAULT_AGENT_ID):
    env_name = env_name_for_agent("THEHIVE_API_KEY", agent_id)
    key = os.environ.get(env_name)
    if key:
        return key, {"agent_id": agent_id, "credential_env": env_name, "credential_scope": "agent_dedicated"}
    return THEHIVE_API_KEY, {"agent_id": agent_id, "credential_env": "THEHIVE_API_KEY", "credential_scope": "fallback_shared"}


def thehive_headers(agent_id=DEFAULT_AGENT_ID, content_type=False):
    key, audit = thehive_api_key(agent_id)
    headers = {"Authorization": f"Bearer {key}"}
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers, audit


def thehive_request(path, body, agent_id=DEFAULT_AGENT_ID):
    headers, audit = thehive_headers(agent_id, content_type=True)
    req = urllib.request.Request(
        f"{THEHIVE_URL}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        response_body = response.read().decode("utf-8")
        try:
            parsed = json.loads(response_body) if response_body else {}
        except Exception:
            parsed = {"raw": response_body[:2000]}
        if isinstance(parsed, dict):
            parsed.setdefault("soc_execution_audit", audit)
        return response.status, parsed


def create_task(case_raw_id, task):
    body = {
        "title": task["title"],
        "description": task.get("description", ""),
        "status": "Waiting",
        "group": task.get("group", "default"),
    }
    if task.get("owner"):
        body["owner"] = task["owner"]
    return thehive_request(f"/api/v1/case/{quote(str(case_raw_id), safe='')}/task", body)


def alert_artifacts(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    artifacts = []
    mapping = {
        "srcip": ("ip", "source ip"),
        "dstip": ("ip", "destination ip"),
        "domain": ("domain", "domain"),
        "url": ("url", "url"),
        "sha256": ("hash", "sha256"),
        "sha1": ("hash", "sha1"),
        "md5": ("hash", "md5"),
    }
    seen = set()
    for field, (data_type, message) in mapping.items():
        value = str(data.get(field) or "").strip()
        if not value or value in {"-", "null", "None"}:
            continue
        key = (data_type, value)
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({"dataType": data_type, "data": value, "message": message})
    for field in ("snort_sid", "snort_priority", "snort_msg", "snort_classification"):
        value = str(data.get(field) or "").strip()
        if value:
            artifacts.append({"dataType": "other", "data": f"{field}:{value}", "message": field})
    return artifacts


def create_alert(alert, key, template, sla, tags):
    rule_id = str(alert_value(alert, "rule", "id", default="unknown"))
    level = alert_value(alert, "rule", "level", default=0)
    desc = str(alert_value(alert, "rule", "description", default="Wazuh alert"))
    agent = str(alert_value(alert, "agent", "name", default="unknown"))
    srcip = str(alert_value(alert, "data", "srcip", default=""))
    source_ref_raw = "|".join([rule_id, agent, srcip, str(alert_value(alert, "location", default="")), key])
    source_ref = hashlib.sha256(source_ref_raw.encode("utf-8")).hexdigest()[:32]
    body = {
        "type": f"soc-{template}",
        "source": "SOC Shuffle",
        "sourceRef": source_ref,
        "title": f"[SOC Alert][{template}] L{level} rule {rule_id} on {agent}",
        "description": "\n".join([
            "SOC automation received this signal and opened/updated the corresponding investigation workflow.",
            f"Rule: {rule_id} L{level} - {desc}",
            f"Agent: {agent}",
            f"Template: {template}",
            f"SLA: {sla['tier']} / ack {sla['ack_minutes']}m / containment {sla['containment_decision_minutes']}m",
            f"Dedup key: {key}",
        ]),
        "severity": severity_from_level(level),
        "tlp": 1,
        "tags": list(dict.fromkeys(tags + ["thehive-alert", f"sourceRef:{source_ref}"])),
        "artifacts": alert_artifacts(alert),
    }
    return thehive_request("/api/v1/alert", body)


def create_alert_nonfatal(alert, key, template, sla, tags):
    try:
        return create_alert(alert, key, template, sla, tags)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        if exc.code == 400 and "version conflict" in body.lower():
            return 409, {"success": True, "duplicate": True, "status": "thehive_alert_already_exists", "body": body}
        raise


def create_case_tasks(case_raw_id, alert, template, sla):
    results = []
    if not case_raw_id:
        return [{"success": False, "error": "missing_case_raw_id"}]
    for task in professional_tasks(alert, template, sla):
        try:
            status, response = create_task(case_raw_id, task)
            results.append({"success": status in (200, 201), "status": status, "title": task["title"], "owner": task.get("owner"), "owner_agent": task.get("owner_agent"), "task_owner": response.get("owner"), "task_id": response.get("id") or response.get("_id")})
        except Exception as exc:
            results.append({"success": False, "title": task.get("title"), "error": f"{type(exc).__name__}: {exc}"})
    return results


def thehive_get(path, agent_id=DEFAULT_AGENT_ID):
    headers, audit = thehive_headers(agent_id)
    req = urllib.request.Request(
        f"{THEHIVE_URL}{path}",
        headers=headers,
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        response_body = response.read().decode("utf-8")
        try:
            parsed = json.loads(response_body) if response_body else {}
        except Exception:
            parsed = {"raw": response_body[:2000]}
        if isinstance(parsed, dict):
            parsed.setdefault("soc_execution_audit", audit)
        return response.status, parsed


def thehive_patch(path, body, agent_id=DEFAULT_AGENT_ID):
    headers, audit = thehive_headers(agent_id, content_type=True)
    req = urllib.request.Request(
        f"{THEHIVE_URL}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="PATCH",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        response_body = response.read().decode("utf-8")
        try:
            parsed = json.loads(response_body) if response_body else {}
        except Exception:
            parsed = {"raw": response_body[:2000]}
        if isinstance(parsed, dict):
            parsed.setdefault("soc_execution_audit", audit)
        return response.status, parsed


def create_case(alert, key, raw_key):
    rule_id = str(alert_value(alert, "rule", "id", default="unknown"))
    level = alert_value(alert, "rule", "level", default=0)
    desc = str(alert_value(alert, "rule", "description", default="Wazuh alert"))
    agent = str(alert_value(alert, "agent", "name", default="unknown"))
    srcip = str(alert_value(alert, "data", "srcip", default=""))
    dstip = str(alert_value(alert, "data", "dstip", default=""))
    snort_sid = str(alert_value(alert, "data", "snort_sid", default=""))
    snort_priority = str(alert_value(alert, "data", "snort_priority", default=""))
    snort_msg = str(alert_value(alert, "data", "snort_msg", default=""))
    detection_source = "Snort IDS" if is_snort_alert(alert) else "Wazuh"
    template = case_template(alert)
    sla = sla_for_level(level)
    gates = quality_gates(alert, template)
    location = str(alert_value(alert, "location", default=""))
    title = f"[SOC][{detection_source}] L{level} rule {rule_id} on {agent}"
    description_lines = [
        f"Hybrid SOC workflow received a {detection_source} alert via Wazuh.",
        f"AI agent: {DEFAULT_AGENT_ID}",
        f"Rule: {rule_id} L{level} - {desc}",
        f"Agent: {agent}",
        f"Source IP: {srcip or 'n/a'}",
        f"Destination IP: {dstip or 'n/a'}",
        f"Location: {location or 'n/a'}",
    ]
    if is_snort_alert(alert):
        description_lines.extend([
            f"Snort SID: {snort_sid or 'n/a'}",
            f"Snort priority: {snort_priority or 'n/a'}",
            f"Snort message: {snort_msg or 'n/a'}",
        ])
    description_lines.extend([
        f"Dedup key: {key}",
        "Quality gates: Wazuh source alert, asset context, triage score, MISP/Cortex enrichment, IR recommendation, approval status, and final disposition must be reviewed before closure.",
        "Containment: approval required; no automatic pfSense or Velociraptor action executed.",
    ])
    tags = [
        "soc",
        "wazuh",
        "shuffle-hybrid",
        f"rule:{rule_id}",
        f"agent:{agent}",
        f"dedup:{key}",
        f"ai_agent:{DEFAULT_AGENT_ID}",
        f"case_template:{template}",
        f"sla:{sla['tier']}",
        f"sla_ack:{sla['ack_minutes']}m",
        f"sla_containment:{sla['containment_decision_minutes']}m",
        "approval-gated",
        "quality-gated",
    ]
    if is_snort_alert(alert):
        tags.extend(["snort", "ids", "pfsense-snort"])
        if snort_sid:
            tags.append(f"snort_sid:{snort_sid}")
        if snort_priority:
            tags.append(f"snort_priority:{snort_priority}")
    alert_status, alert_response = create_alert_nonfatal(alert, key, template, sla, tags)
    body = {
        "title": title,
        "description": "\n".join(description_lines),
        "summary": desc,
        "severity": severity_from_level(level),
        "tlp": 1,
        "pap": 2,
        "tags": tags,
    }
    if srcip:
        body["tags"].append(f"srcip:{srcip}")
    status, case = thehive_request("/api/v1/case", body)
    task_results = create_case_tasks(case.get("_id") or case.get("id"), alert, template, sla) if status in (200, 201) else []
    case["soc_case_template"] = template
    case["soc_sla"] = sla
    case["soc_quality_gates"] = gates
    case["soc_task_results"] = task_results
    case["soc_alert_status"] = alert_status
    case["soc_alert_response"] = alert_response
    case["soc_execution_audit"] = thehive_api_key(DEFAULT_AGENT_ID)[1]
    return status, case


def should_comment_duplicate(count):
    return count in (2, 5, 10, 20) or (count > 20 and count % 25 == 0)


def update_duplicate_case_tags(existing):
    case_raw_id = existing.get("case_raw_id")
    if not case_raw_id:
        return {"attempted": False, "reason": "missing_case_raw_id"}
    count = int(existing.get("count", 1))
    if not should_comment_duplicate(count):
        return {"attempted": False, "reason": "rate_limited"}

    try:
        path = f"/api/v1/case/{quote(str(case_raw_id), safe='')}"
        _, case = thehive_get(path)
        current_tags = case.get("tags") if isinstance(case, dict) else []
        if not isinstance(current_tags, list):
            current_tags = []
        duplicate_tags = [
            "dedup:duplicate-observed",
            f"dedup-count:{count}",
            f"dedup-last-seen:{utc_now().date().isoformat()}",
        ]
        new_tags = list(dict.fromkeys([str(tag) for tag in current_tags + duplicate_tags if tag]))
        status, response = thehive_patch(path, {"tags": new_tags})
        return {"attempted": True, "success": True, "status": status, "response": response}
    except Exception as exc:
        return {"attempted": True, "success": False, "error": f"{type(exc).__name__}: {exc}"}


def handle_case(payload):
    alert = parse_alert(payload)
    key, raw_key = dedup_key(alert)
    now = time.time()
    state = clean_state(load_state(), now)
    existing = state.get(key)
    if existing:
        existing["count"] = int(existing.get("count", 1)) + 1
        existing["last_seen"] = utc_now().isoformat()
        existing["expires_at"] = now + WINDOW_SECONDS
        duplicate_case_update = update_duplicate_case_tags(existing)
        state[key] = existing
        save_state(state)
        return {
            "success": True,
            "duplicate": True,
            "dedup_key": key,
            "raw_key": raw_key,
            "case": existing,
            "created": False,
            "duplicate_case_update": duplicate_case_update,
        }
    status, case = create_case(alert, key, raw_key)
    entry = {
        "case_id": case.get("caseId") or case.get("number") or case.get("id") or case.get("_id"),
        "case_raw_id": case.get("_id") or case.get("id"),
        "title": case.get("title"),
        "template": case.get("soc_case_template"),
        "sla": case.get("soc_sla"),
        "quality_gates": case.get("soc_quality_gates"),
        "task_count": len(case.get("soc_task_results") or []),
        "alert_id": (case.get("soc_alert_response") or {}).get("id") or (case.get("soc_alert_response") or {}).get("_id"),
        "alert_source_ref": (case.get("soc_alert_response") or {}).get("sourceRef"),
        "execution_audit": case.get("soc_execution_audit"),
        "count": 1,
        "first_seen": utc_now().isoformat(),
        "last_seen": utc_now().isoformat(),
        "expires_at": now + WINDOW_SECONDS,
    }
    state[key] = entry
    save_state(state)
    return {"success": True, "duplicate": False, "dedup_key": key, "raw_key": raw_key, "created": True, "thehive_status": status, "thehive_alert_status": case.get("soc_alert_status"), "case": entry, "quality_gates": case.get("soc_quality_gates") or [], "task_results": case.get("soc_task_results") or [], "thehive_alert_response": case.get("soc_alert_response"), "thehive_response": case}


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
        if urlparse(self.path).path != "/case":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            self._json(handle_case(payload))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:2000]
            self._json({"success": False, "error": f"TheHive HTTP {exc.code}", "body": body}, status=502)
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
