import json
import os
import ssl
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


MISP_BASE_URL = os.environ.get("MISP_BASE_URL", "https://misp").rstrip("/")
MISP_API_KEY = os.environ["MISP_API_KEY"]
DEFAULT_AGENT_ID = os.environ.get("SOC_MISP_AGENT_ID", "l1_triage")
VERIFY_TLS = os.environ.get("MISP_VERIFY_TLS", "false").lower() == "true"
EVENT_WRITES_ENABLED = os.environ.get("MISP_EVENT_WRITES_ENABLED", "true").lower() == "true"
EVENT_WRITE_MIN_LEVEL = int(os.environ.get("MISP_EVENT_WRITE_MIN_LEVEL", "10"))
EVENT_WRITE_AGENT_ID = os.environ.get("MISP_EVENT_WRITE_AGENT_ID", "threat_intel")


TYPE_BY_FIELD = {
    "srcip": ("Network activity", "ip-src"),
    "dstip": ("Network activity", "ip-dst"),
    "domain": ("Network activity", "domain"),
    "hostname": ("Network activity", "hostname"),
    "url": ("Network activity", "url"),
    "sha256": ("Payload delivery", "sha256"),
    "sha1": ("Payload delivery", "sha1"),
    "md5": ("Payload delivery", "md5"),
}


def env_name_for_agent(prefix, agent_id):
    normalized = "".join(char if char.isalnum() else "_" for char in str(agent_id or "").upper()).strip("_")
    return f"{prefix}_{normalized}"


def misp_api_key(agent_id=DEFAULT_AGENT_ID):
    env_name = env_name_for_agent("MISP_API_KEY", agent_id)
    key = os.environ.get(env_name)
    if key:
        return key, {"agent_id": agent_id, "credential_env": env_name, "credential_scope": "agent_dedicated"}
    return MISP_API_KEY, {"agent_id": agent_id, "credential_env": "MISP_API_KEY", "credential_scope": "fallback_shared"}


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


def extract_values(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    values = []
    seen = set()
    for field in ("srcip", "dstip", "domain", "hostname", "url", "sha256", "sha1", "md5"):
        value = str(data.get(field) or "").strip()
        if not value or value in {"-", "null", "None"} or value in seen:
            continue
        seen.add(value)
        values.append({"field": field, "value": value})
    return values


def alert_level(alert):
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    for value in (rule.get("level"), alert.get("level")):
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def alert_rule_id(alert):
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    value = rule.get("id") or alert.get("rule_id") or "unknown"
    return str(value).strip() or "unknown"


def alert_title(alert):
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    description = str(rule.get("description") or alert.get("description") or "SOC alert").strip()
    return description[:180] or "SOC alert"


def first_value(values):
    return values[0]["value"] if values else "no-observable"


def build_event(alert, values):
    level = alert_level(alert)
    rule_id = alert_rule_id(alert)
    event_info = f"SOC alert L{level} rule {rule_id}: {alert_title(alert)} ({first_value(values)})"
    attributes = []
    for item in values:
        category, misp_type = TYPE_BY_FIELD[item["field"]]
        attributes.append({
            "category": category,
            "type": misp_type,
            "value": item["value"],
            "to_ids": True,
            "comment": f"Created by SOC automation from rule {rule_id}",
            "distribution": "0",
        })
    return {
        "Event": {
            "info": event_info,
            "distribution": "0",
            "threat_level_id": "2" if level >= 12 else "3",
            "analysis": "0",
            "published": False,
            "Attribute": attributes,
            "Tag": [
                {"name": "soc-generated"},
                {"name": "source:wazuh"},
                {"name": f"wazuh:rule-id={rule_id}"},
            ],
        }
    }


def existing_match_count(results):
    return sum(result.get("match_count", 0) for result in results)


def request_json(method, path, payload=None, agent_id=DEFAULT_AGENT_ID, timeout=30):
    key, audit = misp_api_key(agent_id)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": key, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    context = None if VERIFY_TLS else ssl._create_unverified_context()
    req = urllib.request.Request(f"{MISP_BASE_URL}{path}", data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        text = response.read().decode("utf-8")
        return response.status, json.loads(text) if text else {}, audit


def triage(payload):
    agent_id = str(payload.get("agent") or payload.get("agent_id") or DEFAULT_AGENT_ID).strip() or DEFAULT_AGENT_ID
    alert = parse_alert(payload)
    values = extract_values(alert)
    _, _, audit = request_json("GET", "/users/view/me", agent_id=agent_id, timeout=15)
    results = []
    for item in values:
        body = {
            "value": item["value"],
            "includeContext": True,
            "includeEventTags": True,
            "includeWarninglistHits": True,
        }
        try:
            status, response, _ = request_json("POST", "/attributes/restSearch", body, agent_id=agent_id, timeout=30)
            attrs = response.get("response", {}).get("Attribute") if isinstance(response.get("response"), dict) else response.get("Attribute")
            if attrs is None and isinstance(response.get("response"), list):
                attrs = response.get("response")
            attrs = attrs if isinstance(attrs, list) else []
            results.append({"success": True, "status": status, "observable": item, "match_count": len(attrs), "matches": attrs[:5]})
        except urllib.error.HTTPError as exc:
            results.append({"success": False, "observable": item, "error": f"HTTP {exc.code}"})
        except Exception as exc:
            results.append({"success": False, "observable": item, "error": f"{type(exc).__name__}: {exc}"})
    event_creation = maybe_create_event(alert, values, results, payload)
    return {
        "success": True,
        "soc_stage": "misp_l1_ioc_enrichment",
        "status": "misp_lookup_completed" if values else "no_misp_observables",
        "execution_audit": audit,
        "observable_count": len(values),
        "match_count": existing_match_count(results),
        "event_creation": event_creation,
        "results": results,
    }


def maybe_create_event(alert, values, results, payload):
    if not EVENT_WRITES_ENABLED:
        return {"attempted": False, "reason": "event_writes_disabled"}
    if not values:
        return {"attempted": False, "reason": "no_observables"}
    if payload.get("create_event") is False:
        return {"attempted": False, "reason": "payload_disabled"}
    level = alert_level(alert)
    if level < EVENT_WRITE_MIN_LEVEL and not payload.get("create_event"):
        return {"attempted": False, "reason": "below_min_level", "level": level, "min_level": EVENT_WRITE_MIN_LEVEL}
    if existing_match_count(results) > 0 and not payload.get("force_create_event"):
        return {"attempted": False, "reason": "observable_already_in_misp", "match_count": existing_match_count(results)}
    try:
        status, response, audit = request_json("POST", "/events/add", build_event(alert, values), agent_id=EVENT_WRITE_AGENT_ID, timeout=30)
        event = response.get("Event") if isinstance(response, dict) else None
        return {
            "attempted": True,
            "created": 200 <= status < 300,
            "status": status,
            "event_id": event.get("id") if isinstance(event, dict) else None,
            "event_uuid": event.get("uuid") if isinstance(event, dict) else None,
            "attribute_count": len(values),
            "published": False,
            "execution_audit": audit,
        }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        return {"attempted": True, "created": False, "error": f"HTTP {exc.code}", "body": body}
    except Exception as exc:
        return {"attempted": True, "created": False, "error": f"{type(exc).__name__}: {exc}"}


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
            self._json({"success": False, "error": f"MISP HTTP {exc.code}", "body": body}, status=502)
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
