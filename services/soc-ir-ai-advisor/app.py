import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "qwen/qwen3-next-80b-a3b-instruct:free")
OPENROUTER_FALLBACK_MODELS = os.environ.get("OPENROUTER_FALLBACK_MODELS", "")
OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
AGENT_EXECUTION_MODE = os.environ.get("SOC_AGENT_EXECUTION_MODE", "canary").strip().lower()
AUTO_EXECUTE_AGENT_ALLOWLIST = {
    item.strip() for item in os.environ.get("SOC_AUTO_EXECUTE_AGENTS", "l1_triage,l2_case_manager,threat_intel,ciso_reporting").split(",") if item.strip()
}


def openrouter_models():
    models = []
    for value in [OPENROUTER_MODEL, OPENROUTER_FALLBACK_MODELS]:
        for model in value.split(","):
            model = model.strip()
            if model and model not in models:
                models.append(model)
    return models


LOW_RISK_ACTIONS = {
    "lookup_ioc",
    "run_cortex_analyzer",
    "create_thehive_alert",
    "create_thehive_case",
    "create_thehive_task",
    "add_thehive_tag",
    "record_digest",
}
HIGH_RISK_ACTIONS = {
    "pfsense_block",
    "snort_rule_change",
    "velociraptor_collect",
    "velociraptor_isolate",
    "wazuh_active_response",
    "account_disable",
    "sample_detonation",
}


AGENT_PROFILES = {
    "soc_manager": {
        "display_name": "AI SOC Manager",
        "mission": "Coordinate the SOC pipeline, assign severity, decide which specialists should contribute, and keep all actions approval-gated.",
        "allowed_tools": ["Wazuh alert context", "MISP summary", "Cortex summary", "TheHive case summary", "CAPE health", "Velociraptor advisor", "pfSense advisor"],
        "authorization_level": "recommend_only",
        "system_prompt": "You are the AI SOC Manager. Triage the alert, coordinate L1/L2/L3 and specialist agents, and return compact JSON. Never claim execution. Containment requires human approval.",
    },
    "l1_triage": {
        "display_name": "AI L1 Triage Analyst",
        "mission": "Normalize alert evidence, identify observable quality, suppress obvious noise, and escalate meaningful alerts.",
        "allowed_tools": ["Wazuh alert context", "MISP lookup", "Cortex analyzer summaries"],
        "authorization_level": "read_only",
        "system_prompt": "You are an AI L1 SOC analyst. Focus on alert validation, observable extraction, false-positive indicators, and escalation recommendation. Return JSON only.",
    },
    "l2_case_manager": {
        "display_name": "AI L2 Case Manager",
        "mission": "Structure TheHive case context, deduplicate related alerts, and define analyst tasks.",
        "allowed_tools": ["TheHive case metadata", "Wazuh alert context", "MISP/Cortex summaries"],
        "authorization_level": "case_write_proposal",
        "system_prompt": "You are an AI L2 case manager. Create concise case rationale, dedup logic, required tasks, and evidence gaps. Return JSON only.",
    },
    "l3_dfir": {
        "display_name": "AI L3 DFIR Analyst",
        "mission": "Recommend safe read-only DFIR collections and endpoint investigation steps.",
        "allowed_tools": ["Velociraptor read-only artifacts", "Wazuh agent metadata", "TheHive case context"],
        "authorization_level": "read_only_recommendation",
        "system_prompt": "You are an AI L3 DFIR analyst. Recommend read-only Velociraptor collections and investigation hypotheses. Do not execute isolation or collection. Return JSON only.",
    },
    "threat_intel": {
        "display_name": "AI Threat Intel Analyst",
        "mission": "Interpret MISP/Cortex reputation results, identify likely campaign context, and rank IOCs.",
        "allowed_tools": ["MISP attributes", "Cortex taxonomies", "AbuseIPDB", "VirusTotal", "DNS/reputation analyzers"],
        "authorization_level": "read_only",
        "system_prompt": "You are an AI threat intelligence analyst. Explain IOC confidence, likely benign/malicious context, and what should be shared or watched. Return JSON only.",
    },
    "malware_analyst": {
        "display_name": "AI Malware Analyst",
        "mission": "Use CAPEv2 status and malware/hash indicators to recommend sandbox or malware-analysis next steps.",
        "allowed_tools": ["CAPEv2 task list", "hash observables", "Cortex hash analyzers", "MISP malware tags"],
        "authorization_level": "sandbox_submission_requires_approval",
        "system_prompt": "You are an AI malware analyst. Recommend malware-analysis tasks and sandbox needs. Do not upload samples or detonate without approval. Return JSON only.",
    },
    "dfir_agent": {
        "display_name": "AI DFIR Agent",
        "mission": "Prepare endpoint investigation steps and preserve evidence without destructive actions.",
        "allowed_tools": ["Velociraptor read-only artifacts", "Wazuh logs", "case timeline"],
        "authorization_level": "read_only_recommendation",
        "system_prompt": "You are an AI DFIR agent. Build a read-only evidence collection plan with scope, artifacts, and expected findings. Return JSON only.",
    },
    "detection_engineer": {
        "display_name": "AI Detection Engineer",
        "mission": "Recommend Wazuh/Snort/MISP detection tuning and suppression rules with rollback guidance.",
        "allowed_tools": ["Wazuh rule metadata", "Snort SID/priority", "MISP IOC context", "historical alert frequency"],
        "authorization_level": "rule_change_requires_approval",
        "system_prompt": "You are an AI detection engineer. Recommend detection tuning, rule changes, and tests. Do not deploy rules. Return JSON only.",
    },
    "ir_responder": {
        "display_name": "AI IR Responder",
        "mission": "Convert evidence into containment proposals for pfSense, Wazuh active response, EDR, or Velociraptor.",
        "allowed_tools": ["pfSense proposals", "Wazuh active response proposal", "Velociraptor isolation proposal", "TheHive approval context"],
        "authorization_level": "human_approval_required_for_execution",
        "system_prompt": "You are an AI incident responder. Produce containment options and approval checklist. Never execute or claim execution. Return JSON only.",
    },
    "ciso_reporting": {
        "display_name": "AI CISO Reporting",
        "mission": "Summarize business risk, impact, actions requiring approval, and executive-readable next steps.",
        "allowed_tools": ["TheHive case summary", "workflow stage outputs", "digest recorder", "alert statistics"],
        "authorization_level": "report_only",
        "system_prompt": "You are AI CISO reporting. Produce concise executive JSON: business impact, risk, current status, pending approvals, and next update. Return JSON only.",
    },
}

STAGE_AGENT_MAP = {
    "manager": "soc_manager",
    "orchestrator": "soc_manager",
    "l1": "l1_triage",
    "triage": "l1_triage",
    "l2": "l2_case_manager",
    "case": "l2_case_manager",
    "l3": "l3_dfir",
    "velociraptor": "l3_dfir",
    "threatintel": "threat_intel",
    "threat_intel": "threat_intel",
    "malware": "malware_analyst",
    "capev2": "malware_analyst",
    "dfir": "dfir_agent",
    "detection": "detection_engineer",
    "pfsense": "ir_responder",
    "ir": "ir_responder",
    "ir_responder": "ir_responder",
    "reporting": "ciso_reporting",
    "ciso": "ciso_reporting",
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


def alert_level(alert):
    try:
        return int((alert.get("rule") or {}).get("level") or 0)
    except Exception:
        return 0


def alert_observables(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    observables = []
    for field in ("srcip", "dstip", "sha256", "sha1", "md5", "domain", "url"):
        value = str(data.get(field) or "").strip()
        if value and value not in {"-", "null", "None"}:
            observables.append({"field": field, "value": value})
    return observables


def is_snort(alert):
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    groups = (alert.get("rule") or {}).get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    return bool(data.get("snort_sid") or data.get("snort_priority") or "snort" in {str(group).lower() for group in groups})


def action_recommendations(agent_key, alert):
    actions = []
    if agent_key == "l1_triage":
        actions.append({"tool": "misp", "action": "lookup_ioc", "risk_tier": "low", "confidence": "medium"})
        actions.append({"tool": "cortex", "action": "run_cortex_analyzer", "risk_tier": "low", "confidence": "medium"})
    elif agent_key == "l2_case_manager":
        actions.extend([
            {"tool": "thehive", "action": "create_thehive_alert", "risk_tier": "low", "confidence": "high"},
            {"tool": "thehive", "action": "create_thehive_case", "risk_tier": "low", "confidence": "high"},
            {"tool": "thehive", "action": "create_thehive_task", "risk_tier": "low", "confidence": "high"},
        ])
    elif agent_key == "threat_intel":
        actions.append({"tool": "thehive", "action": "add_thehive_tag", "risk_tier": "low", "confidence": "medium"})
    elif agent_key == "ciso_reporting":
        actions.append({"tool": "digest", "action": "record_digest", "risk_tier": "low", "confidence": "high"})
    elif agent_key in {"l3_dfir", "dfir_agent"}:
        actions.append({"tool": "velociraptor", "action": "velociraptor_collect", "risk_tier": "high", "confidence": "medium"})
    elif agent_key == "ir_responder":
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        actions.append({"tool": "pfsense", "action": "pfsense_block", "params": {"srcip": data.get("srcip") or ""}, "risk_tier": "high", "confidence": "medium"})
    elif agent_key == "malware_analyst":
        actions.append({"tool": "capev2", "action": "sample_detonation", "risk_tier": "high", "confidence": "low"})
    elif agent_key == "detection_engineer":
        actions.append({"tool": "snort", "action": "snort_rule_change", "risk_tier": "high", "confidence": "medium"})
    return actions


def apply_execution_policy(agent_key, recommendations):
    evaluated = []
    any_blocked = False
    for item in recommendations:
        action = str(item.get("action") or "")
        risk_tier = str(item.get("risk_tier") or "high").lower()
        low_risk = risk_tier == "low" and action in LOW_RISK_ACTIONS
        high_risk = risk_tier == "high" or action in HIGH_RISK_ACTIONS
        auto_allowed = AGENT_EXECUTION_MODE in {"canary", "auto"} and agent_key in AUTO_EXECUTE_AGENT_ALLOWLIST and low_risk and not high_risk
        evaluated_item = dict(item)
        evaluated_item["auto_execute_allowed"] = auto_allowed
        evaluated_item["approval_required"] = not auto_allowed
        evaluated_item["blocked_reason"] = "" if auto_allowed else ("kill_switch_propose_only" if AGENT_EXECUTION_MODE == "propose_only" else "human_approval_required_or_not_allowlisted")
        if not auto_allowed:
            any_blocked = True
        evaluated.append(evaluated_item)
    return evaluated, any_blocked


def resolve_agent(payload):
    requested = str(payload.get("agent") or payload.get("role") or "").strip().lower()
    stage = str(payload.get("stage") or "general").strip().lower()
    if requested in AGENT_PROFILES:
        return requested
    return STAGE_AGENT_MAP.get(requested) or STAGE_AGENT_MAP.get(stage) or "soc_manager"


def base_agent_response(agent_key, alert, payload):
    profile = AGENT_PROFILES[agent_key]
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    level = alert_level(alert)
    severity = "critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 7 else "low"
    observables = alert_observables(alert)
    srcip = data.get("srcip") or ""
    recommendations, has_blocked_actions = apply_execution_policy(agent_key, action_recommendations(agent_key, alert))
    response = {
        "agent": agent_key,
        "agent_name": profile["display_name"],
        "mission": profile["mission"],
        "authorization_level": profile["authorization_level"],
        "allowed_tools": profile["allowed_tools"],
        "input_contract": {
            "required": ["alert"],
            "optional": ["case_context", "tool_results", "workflow_context"],
        },
        "output_contract": {
            "required": ["severity", "confidence", "summary", "findings", "recommended_next_steps", "approval_required", "executed_actions"],
        },
        "severity": severity,
        "confidence": "medium",
        "summary": f"{profile['display_name']} reviewed Wazuh rule {rule.get('id', 'unknown')} level {level}: {rule.get('description', 'Wazuh alert')}",
        "detection_source": "snort_ids" if is_snort(alert) else "wazuh",
        "observables": observables,
        "findings": [],
        "recommended_next_steps": [],
        "execution_policy": {
            "mode": AGENT_EXECUTION_MODE,
            "auto_execute_agent_allowlist": sorted(AUTO_EXECUTE_AGENT_ALLOWLIST),
            "high_risk_actions_require_human": True,
        },
        "action_recommendations": recommendations,
        "approval_required": has_blocked_actions,
        "executed_actions": [],
        "blocked_actions_without_human": ["pfSense rule changes", "host isolation", "active response", "sample detonation", "detection rule deployment"],
        "case_context_used": bool(payload.get("case_context")),
        "tool_results_used": list((payload.get("tool_results") or {}).keys()) if isinstance(payload.get("tool_results"), dict) else [],
    }
    if agent_key in {"l3_dfir", "dfir_agent"}:
        response["recommended_read_only_collections"] = ["Generic.Client.Info", "Windows.System.Pslist", "Windows.Network.Netstat", "Windows.EventLogs.EvtxHunter"]
        response["recommended_next_steps"] = ["Map Wazuh agent to Velociraptor client", "Collect read-only triage artifacts after analyst approval", "Attach results to TheHive"]
    elif agent_key == "ir_responder":
        proposals = []
        if srcip:
            proposals.append({"type": "review_src_ip_block", "value": srcip, "requires_human_approval": True})
        response["containment_proposals"] = proposals
        response["recommended_next_steps"] = ["Validate IOC is not internal or benign", "Confirm business impact", "Create TheHive approval task before containment"]
    elif agent_key == "threat_intel":
        response["recommended_next_steps"] = ["Review MISP and Cortex taxonomies", "Rank IOCs by confidence", "Promote confirmed IOCs to watchlists only after analyst approval"]
    elif agent_key == "detection_engineer":
        response["recommended_next_steps"] = ["Check false-positive rate", "Draft Wazuh/Snort tuning change", "Run regression before deployment"]
    elif agent_key == "malware_analyst":
        response["recommended_next_steps"] = ["Check hash reputation", "Use CAPEv2 only when sample handling is approved", "Record sandbox decision in TheHive"]
    elif agent_key == "ciso_reporting":
        response["recommended_next_steps"] = ["Summarize current risk", "List pending approvals", "Report whether containment has executed; expected false"]
    else:
        response["recommended_next_steps"] = ["Route alert to L1/L2/L3 as needed", "Preserve approval gate", "Record final status in digest"]
    return response


def call_openrouter(agent_key, alert, payload, fallback):
    if not OPENROUTER_API_KEY:
        fallback["ai_provider"] = "fallback_no_api_key"
        return fallback
    profile = AGENT_PROFILES[agent_key]
    prompt_payload = {
        "agent_profile": {key: profile[key] for key in ("display_name", "mission", "allowed_tools", "authorization_level")},
        "alert": alert,
        "case_context": payload.get("case_context") or {},
        "tool_results": payload.get("tool_results") or {},
        "required_output": fallback["output_contract"],
        "execution_policy": fallback.get("execution_policy"),
        "guardrail": "Never execute containment or claim execution. Low-risk tool actions may be auto-executed by scoped tool services when the execution policy allows it; high-risk actions require human approval.",
    }
    errors = []
    models = openrouter_models()
    for model in models:
        request_payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": profile["system_prompt"] + " Return compact valid JSON. No markdown."},
                {"role": "user", "content": json.dumps(prompt_payload, ensure_ascii=False)[:9000]},
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
        }
        request = urllib.request.Request(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            data=json.dumps(request_payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://shuffle",
                "X-Title": "SOC Homelab Multi-Agent Advisor",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                body = json.loads(response.read().decode("utf-8"))
            content = body.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            try:
                advice = json.loads(content)
            except Exception:
                advice = dict(fallback)
                advice["ai_raw"] = content[:1000]
            merged = dict(fallback)
            merged.update(advice if isinstance(advice, dict) else {})
            merged["agent"] = agent_key
            merged["agent_name"] = profile["display_name"]
            merged["authorization_level"] = profile["authorization_level"]
            merged["allowed_tools"] = profile["allowed_tools"]
            recommendations, has_blocked_actions = apply_execution_policy(agent_key, merged.get("action_recommendations") if isinstance(merged.get("action_recommendations"), list) else action_recommendations(agent_key, alert))
            merged["execution_policy"] = fallback.get("execution_policy")
            merged["action_recommendations"] = recommendations
            merged["approval_required"] = has_blocked_actions
            merged["executed_actions"] = []
            merged["ai_provider"] = "openrouter"
            merged["ai_model"] = model
            merged["ai_model_attempts"] = len(errors) + 1
            if errors:
                merged["ai_fallback_errors"] = errors
            return merged
        except urllib.error.HTTPError as exc:
            errors.append({"model": model, "error": f"HTTPError: HTTP {exc.code}"})
        except Exception as exc:
            errors.append({"model": model, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    fallback["ai_provider"] = "fallback_after_error"
    fallback["ai_model_attempts"] = len(models)
    fallback["ai_fallback_errors"] = errors
    fallback["ai_error"] = errors[-1]["error"] if errors else "no_openrouter_models_configured"
    return fallback


def build_agent_advice(payload):
    alert = parse_alert(payload)
    agent_key = resolve_agent(payload)
    fallback = base_agent_response(agent_key, alert, payload)
    advice = call_openrouter(agent_key, alert, payload, fallback)
    return {"success": True, "agent": agent_key, "profile": AGENT_PROFILES[agent_key], "advice": advice}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/agents":
            self._json({"success": True, "agents": AGENT_PROFILES})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path not in {"/advise", "/agent"}:
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            self._json(build_agent_advice(payload))
        except Exception as exc:
            self._json({"success": False, "error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            print("client disconnected before response completed", flush=True)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
