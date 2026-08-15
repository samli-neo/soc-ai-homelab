import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

SHUFFLE_BASE = os.environ.get("SHUFFLE_BASE_URL", "http://shuffle-backend:5001")
SHUFFLE_WORKFLOW_ID = os.environ.get("SHUFFLE_WORKFLOW_ID", "043882e1-8ea3-4f88-898c-b12957ff2785")
SHUFFLE_API_KEY = os.environ["SHUFFLE_API_KEY"]
MAILER_RECORD_URL = os.environ.get("MAILER_RECORD_URL", "http://soc-report-mailer:8080/record")
FULL_WORKFLOW_MIN_LEVEL = int(os.environ.get("FULL_WORKFLOW_MIN_LEVEL", "9"))
WORKFLOW_NAME = os.environ.get("WORKFLOW_NAME", "SOC Security Operations - Wazuh Triage and Response v1")
ASSET_INVENTORY_PATH = os.environ.get("SOC_ASSET_INVENTORY_PATH", "")
DEFAULT_ASSET_INVENTORY = [
    {"name": "pfSense", "ips": ["192.168.2.1"], "agent_names": ["pfsense"], "role": "firewall", "criticality": "critical", "owner": "network"},
    {"name": "Wazuh Manager", "ips": ["10.10.50.40"], "agent_names": ["wazuh-manager"], "role": "siem", "criticality": "critical", "owner": "soc"},
    {"name": "Shuffle", "ips": ["10.10.50.10", "10.10.50.11"], "agent_names": ["shuffle", "shuffle-backend"], "role": "soar", "criticality": "high", "owner": "soc"},
    {"name": "TheHive", "ips": ["10.10.50.50"], "agent_names": ["thehive"], "role": "case_management", "criticality": "high", "owner": "soc"},
    {"name": "CAPE", "ips": ["10.10.50.102"], "agent_names": ["cape"], "role": "malware_sandbox_controller", "criticality": "high", "owner": "malware"},
    {"name": "sandbox-WIN11", "ips": ["10.10.50.103"], "agent_names": ["sandbox-win11", "win11", "win11pro"], "role": "malware_sandbox", "criticality": "medium", "owner": "malware"},
]
DIGEST_ONLY_RULE_IDS = {
    item.strip()
    for item in os.environ.get("DIGEST_ONLY_RULE_IDS", "17101,17102,60602").split(",")
    if item.strip()
}
NOISY_INTERNAL_RULE_IDS = {
    item.strip()
    for item in os.environ.get("NOISY_INTERNAL_RULE_IDS", "100401").split(",")
    if item.strip()
}
STARTED_AT = time.time()
METRICS = {
    "total_intakes": 0,
    "digest_only": 0,
    "full_workflow": 0,
    "errors": 0,
    "by_reason": {},
    "by_rule_id": {},
    "by_triage_tier": {},
    "last_route": {},
}


def bump(mapping, key):
    key = str(key or "unknown")
    mapping[key] = mapping.get(key, 0) + 1


def record_route(result):
    METRICS["total_intakes"] += 1
    mode = result.get("mode") or "unknown"
    if mode in {"digest_only", "full_workflow"}:
        METRICS[mode] += 1
    bump(METRICS["by_rule_id"], result.get("rule_id"))
    if result.get("reason"):
        bump(METRICS["by_reason"], result.get("reason"))
    triage = result.get("triage") if isinstance(result.get("triage"), dict) else {}
    if triage.get("tier"):
        bump(METRICS["by_triage_tier"], triage.get("tier"))
    METRICS["last_route"] = {
        "mode": mode,
        "reason": result.get("reason") or "",
        "rule_id": result.get("rule_id") or "",
        "level": result.get("level"),
        "triage_score": triage.get("score"),
        "triage_tier": triage.get("tier") or "",
        "shuffle_forwarded": bool(result.get("shuffle_forwarded")),
        "recorded_at": int(time.time()),
    }


def record_error(error):
    METRICS["errors"] += 1
    METRICS["last_error"] = {
        "error": str(error)[:300],
        "recorded_at": int(time.time()),
    }


def metrics_snapshot():
    return {
        "success": True,
        "service": "soc-intake-router",
        "started_at": int(STARTED_AT),
        "uptime_seconds": int(time.time() - STARTED_AT),
        "workflow_id": SHUFFLE_WORKFLOW_ID,
        "full_workflow_min_level": FULL_WORKFLOW_MIN_LEVEL,
        "asset_inventory_count": len(asset_inventory()),
        **METRICS,
    }


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


def alert_level(alert):
    try:
        return int((alert.get("rule") or {}).get("level") or 0)
    except Exception:
        return 0


def rule_id(alert):
    return str((alert.get("rule") or {}).get("id") or "")


def data_value(alert, key):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    return str(data.get(key) or alert.get(key) or "").strip()


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def asset_inventory():
    raw = os.environ.get("SOC_ASSET_INVENTORY_JSON", "").strip()
    if raw:
        try:
            assets = json.loads(raw)
            return assets if isinstance(assets, list) else DEFAULT_ASSET_INVENTORY
        except Exception:
            return DEFAULT_ASSET_INVENTORY
    if ASSET_INVENTORY_PATH:
        try:
            with open(ASSET_INVENTORY_PATH, "r", encoding="utf-8") as handle:
                assets = json.load(handle)
            return assets if isinstance(assets, list) else DEFAULT_ASSET_INVENTORY
        except Exception:
            return DEFAULT_ASSET_INVENTORY
    return DEFAULT_ASSET_INVENTORY


def compact_asset(asset, match_type, match_value):
    if not asset:
        return None
    return {
        "name": asset.get("name"),
        "role": asset.get("role"),
        "criticality": asset.get("criticality", "unknown"),
        "owner": asset.get("owner", "unknown"),
        "match_type": match_type,
        "match_value": match_value,
    }


def find_asset_by_ip(ip_value):
    if not ip_value:
        return None
    for asset in asset_inventory():
        if ip_value in [str(item) for item in asset.get("ips", [])]:
            return compact_asset(asset, "ip", ip_value)
    return None


def find_asset_by_agent(agent_name):
    value = str(agent_name or "").lower().strip()
    if not value:
        return None
    for asset in asset_inventory():
        names = [str(item).lower().strip() for item in asset.get("agent_names", [])]
        if value in names:
            return compact_asset(asset, "agent_name", agent_name)
    return None


def asset_context(alert):
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    context = {
        "agent_asset": find_asset_by_agent(agent.get("name")) or find_asset_by_ip(str(agent.get("ip") or "")),
        "source_asset": find_asset_by_ip(data_value(alert, "srcip")),
        "destination_asset": find_asset_by_ip(data_value(alert, "dstip")),
    }
    criticalities = [item.get("criticality") for item in context.values() if isinstance(item, dict)]
    rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    context["max_criticality"] = max(criticalities, key=lambda item: rank.get(item, 0)) if criticalities else "unknown"
    return context


def noisy_internal_only(alert, rid):
    if rid not in NOISY_INTERNAL_RULE_IDS:
        return False
    srcip = data_value(alert, "srcip")
    return not is_public_ip(srcip)


def alert_groups(alert):
    groups = (alert.get("rule") or {}).get("groups") or []
    return [str(item).lower() for item in groups if str(item).strip()]


def triage_tier(score):
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def triage_score(alert, assets=None):
    level = alert_level(alert)
    groups = alert_groups(alert)
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    factors = []
    score = min(level * 5, 60)
    factors.append({"name": "wazuh_level", "value": level, "points": score})
    srcip = data_value(alert, "srcip")
    if srcip and is_public_ip(srcip):
        score += 10
        factors.append({"name": "public_source_ip", "value": srcip, "points": 10})
    if any(data_value(alert, key) for key in ("sha256", "sha1", "md5")):
        score += 10
        factors.append({"name": "file_hash_present", "points": 10})
    if any(group.startswith("mitre") or group.startswith("attack") for group in groups):
        score += 10
        factors.append({"name": "mitre_context", "points": 10})
    if any(group in {"ids", "snort", "pfsense-snort"} for group in groups) or data.get("snort_sid"):
        score += 5
        factors.append({"name": "network_ids_signal", "points": 5})
    if data_value(alert, "url") or data_value(alert, "domain"):
        score += 5
        factors.append({"name": "network_observable_present", "points": 5})
    assets = assets if isinstance(assets, dict) else asset_context(alert)
    max_criticality = assets.get("max_criticality")
    if max_criticality == "critical":
        score += 15
        factors.append({"name": "critical_asset_involved", "points": 15})
    elif max_criticality == "high":
        score += 10
        factors.append({"name": "high_value_asset_involved", "points": 10})
    score = max(0, min(score, 100))
    return {"score": score, "tier": triage_tier(score), "factors": factors}


def post_json(url, payload, headers=None, timeout=30):
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        response_body = response.read().decode("utf-8")
        try:
            parsed = json.loads(response_body) if response_body else {}
        except Exception:
            parsed = {"raw": response_body[:2000]}
        return response.status, parsed


def route(payload):
    alert = parse_alert(payload)
    level = alert_level(alert)
    rid = rule_id(alert)
    assets = asset_context(alert)
    triage = triage_score(alert, assets)
    alert = dict(alert)
    alert["soc_triage"] = triage
    alert["soc_asset_context"] = assets
    force_digest_only = rid in DIGEST_ONLY_RULE_IDS
    force_noisy_internal_digest = noisy_internal_only(alert, rid)
    normalized_payload = {
        "workflow_name": WORKFLOW_NAME,
        "execution_argument": json.dumps(alert),
    }
    if force_digest_only or force_noisy_internal_digest or level < FULL_WORKFLOW_MIN_LEVEL:
        status, result = post_json(MAILER_RECORD_URL, normalized_payload, timeout=20)
        return {
            "success": True,
            "mode": "digest_only",
            "reason": "rule_suppressed" if force_digest_only else "noisy_internal_rule" if force_noisy_internal_digest else "below_threshold",
            "rule_id": rid,
            "level": level,
            "threshold": FULL_WORKFLOW_MIN_LEVEL,
            "srcip": data_value(alert, "srcip"),
            "triage": triage,
            "asset_context": assets,
            "shuffle_forwarded": False,
            "mailer_status": status,
            "mailer_response": result,
        }
    shuffle_url = f"{SHUFFLE_BASE}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/execute"
    status, result = post_json(
        shuffle_url,
        {"execution_argument": json.dumps(alert)},
        headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}"},
        timeout=30,
    )
    return {
        "success": True,
        "mode": "full_workflow",
        "rule_id": rid,
        "level": level,
        "threshold": FULL_WORKFLOW_MIN_LEVEL,
        "triage": triage,
        "asset_context": assets,
        "shuffle_forwarded": True,
        "shuffle_status": status,
        "shuffle_response": result,
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if path == "/metrics":
            self._json(metrics_snapshot())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path != "/intake":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = route(payload)
            record_route(result)
            self._json(result)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:2000]
            record_error(f"HTTP {exc.code}")
            self._json({"success": False, "error": f"HTTP {exc.code}", "body": body}, status=502)
        except Exception as exc:
            record_error(f"{type(exc).__name__}: {exc}")
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
