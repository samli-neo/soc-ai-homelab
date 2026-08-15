import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_AGENT_ID = os.environ.get("SOC_GHIDRA_AGENT_ID", "malware_analyst")
GHIDRA_HEADLESS = os.environ.get("GHIDRA_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
SAMPLES_DIR = Path(os.environ.get("GHIDRA_SAMPLES_DIR", "/samples")).resolve()
WORK_DIR = Path(os.environ.get("GHIDRA_WORK_DIR", "/work")).resolve()
YARA_RULES_DIR = Path(os.environ.get("YARA_RULES_DIR", "/rules")).resolve()
CAPA_RULES_DIR = Path(os.environ.get("CAPA_RULES_DIR", "/opt/capa-rules")).resolve()
TIMEOUT_SECONDS = int(os.environ.get("GHIDRA_TIMEOUT_SECONDS", "300"))
MAX_SAMPLE_BYTES = int(os.environ.get("GHIDRA_MAX_SAMPLE_BYTES", str(100 * 1024 * 1024)))
MAX_OUTPUT_BYTES = int(os.environ.get("GHIDRA_MAX_OUTPUT_BYTES", "50000"))
MAX_CAPA_RULES = int(os.environ.get("CAPA_MAX_RULES", "50"))


def json_response(handler, body, status=200):
    data = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def safe_sample_path(value):
    if not value:
        return None
    path = Path(value).resolve()
    if not str(path).startswith(str(SAMPLES_DIR) + os.sep):
        raise ValueError("sample_path must be under GHIDRA_SAMPLES_DIR")
    if not path.is_file():
        raise FileNotFoundError("sample_path not found")
    if path.stat().st_size > MAX_SAMPLE_BYTES:
        raise ValueError("sample exceeds GHIDRA_MAX_SAMPLE_BYTES")
    return path


def download_sample(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("sample_url must use http or https")
    fd, target = tempfile.mkstemp(prefix="ghidra-url-", dir=SAMPLES_DIR)
    os.close(fd)
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response, open(target, "wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SAMPLE_BYTES:
                raise ValueError("sample_url download exceeds GHIDRA_MAX_SAMPLE_BYTES")
            handle.write(chunk)
    return Path(target)


def file_metadata(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    result = subprocess.run(["file", "-b", str(path)], text=True, capture_output=True, timeout=10)
    return {
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "file_type": result.stdout.strip(),
    }


def run_preview_command(cmd):
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
        return {
            "returncode": result.returncode,
            "stdout_preview": result.stdout[:MAX_OUTPUT_BYTES],
            "stderr_preview": result.stderr[:5000],
        }
    except Exception as exc:
        return {"returncode": -1, "error": f"{type(exc).__name__}: {exc}"}


def run_capa(path):
    try:
        cmd = ["capa", "-j", str(path)]
        if CAPA_RULES_DIR.exists():
            cmd[1:1] = ["-r", str(CAPA_RULES_DIR)]
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=TIMEOUT_SECONDS)
    except Exception as exc:
        return {"returncode": -1, "success": False, "error": f"{type(exc).__name__}: {exc}"}
    result = {
        "returncode": proc.returncode,
        "success": proc.returncode == 0,
        "stderr_preview": proc.stderr[:5000],
        "stdout_preview": proc.stdout[:MAX_OUTPUT_BYTES],
        "capabilities": [],
        "mitre_attack": [],
        "maec": [],
    }
    try:
        parsed = json.loads(proc.stdout or "{}")
    except Exception:
        return result
    rules = parsed.get("rules") if isinstance(parsed.get("rules"), dict) else {}
    mitre = set()
    maec = set()
    for rule_name, rule in list(rules.items())[:MAX_CAPA_RULES]:
        meta = rule.get("meta") if isinstance(rule, dict) else {}
        namespace = str(meta.get("namespace") or "")
        attacks = meta.get("att&ck") or meta.get("attack") or []
        if isinstance(attacks, str):
            attacks = [attacks]
        for item in attacks:
            mitre.add(str(item))
        maec_values = meta.get("maec") or []
        if isinstance(maec_values, str):
            maec_values = [maec_values]
        for item in maec_values:
            maec.add(str(item))
        result["capabilities"].append({
            "name": rule_name,
            "namespace": namespace,
            "scope": meta.get("scope"),
            "attck": attacks,
            "maec": maec_values,
        })
    result["mitre_attack"] = sorted(mitre)
    result["maec"] = sorted(maec)
    return result


def yara_rule_files():
    if not YARA_RULES_DIR.exists():
        return []
    return [path for path in YARA_RULES_DIR.rglob("*.yar") if path.is_file()]


def run_yara(path):
    rules = yara_rule_files()
    if not rules:
        return {"returncode": 0, "success": True, "rule_files": [], "matches": []}
    matches = []
    stderr = []
    returncode = 0
    for rule in rules:
        proc = subprocess.run(["yara", "-m", str(rule), str(path)], text=True, capture_output=True, timeout=60)
        returncode = max(returncode, proc.returncode)
        if proc.stderr:
            stderr.append(proc.stderr[:1000])
        for line in proc.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if not parts:
                continue
            matches.append({"rule": parts[0], "raw": line[:1000], "rule_file": str(rule)})
    return {
        "returncode": returncode,
        "success": returncode in (0, 1),
        "rule_files": [str(item) for item in rules],
        "matches": matches,
        "stderr_preview": "\n".join(stderr)[:5000],
    }


def run_ghidra(path):
    project_root = Path(tempfile.mkdtemp(prefix="ghidra-project-", dir=WORK_DIR))
    project_name = "analysis"
    try:
        cmd = [
            GHIDRA_HEADLESS,
            str(project_root),
            project_name,
            "-import",
            str(path),
            "-deleteProject",
        ]
        started = time.time()
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=TIMEOUT_SECONDS)
        return {
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "duration_ms": int((time.time() - started) * 1000),
            "stdout_preview": proc.stdout[:MAX_OUTPUT_BYTES],
            "stderr_preview": proc.stderr[:MAX_OUTPUT_BYTES],
        }
    finally:
        shutil.rmtree(project_root, ignore_errors=True)


def verdict(metadata, capa, yara):
    score = 0
    reasons = []
    if yara.get("matches"):
        score += 40
        reasons.append("yara_matches")
    if capa.get("mitre_attack"):
        score += 35
        reasons.append("capa_mitre_attack_mapping")
    if len(capa.get("capabilities") or []) >= 10:
        score += 15
        reasons.append("many_capa_capabilities")
    file_type = str(metadata.get("file_type") or "").lower()
    if "executable" in file_type or "pe32" in file_type:
        score += 10
        reasons.append("executable_sample")
    label = "malicious" if score >= 70 else "suspicious" if score >= 35 else "benign_or_unknown"
    return {"label": label, "score": min(score, 100), "reasons": reasons}


def suspicious_functions(capa, objdump):
    names = []
    for capability in capa.get("capabilities") or []:
        name = str(capability.get("name") or "")
        lowered = name.lower()
        if any(word in lowered for word in ("inject", "persist", "credential", "encrypt", "socket", "download", "execute", "process")):
            names.append(name)
    text = objdump.get("stdout_preview") or ""
    for api in ("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "WinExec", "ShellExecute", "MiniDumpWriteDump"):
        if api in text and api not in names:
            names.append(api)
    return names[:25]


def analyze(payload):
    sample = payload.get("sample") if isinstance(payload.get("sample"), dict) else payload
    run_ghidra_requested = payload.get("run_ghidra")
    if run_ghidra_requested is None and isinstance(sample, dict):
        run_ghidra_requested = sample.get("run_ghidra")
    run_ghidra_enabled = str(run_ghidra_requested).lower() in {"1", "true", "yes", "on"}
    sample_path = str(sample.get("sample_path") or sample.get("path") or "").strip()
    sample_url = str(sample.get("sample_url") or sample.get("url") or "").strip()
    if sample_path:
        path = safe_sample_path(sample_path)
        source = "sample_path"
    elif sample_url:
        path = download_sample(sample_url)
        source = "sample_url"
    else:
        return {"success": False, "error": "sample_path or sample_url is required"}

    metadata = file_metadata(path)
    capa = run_capa(path)
    yara = run_yara(path)
    strings = run_preview_command(["strings", "-a", "-n", "6", str(path)])
    objdump = run_preview_command(["objdump", "-x", str(path)])
    ghidra = run_ghidra(path) if run_ghidra_enabled else {"success": None, "skipped": True, "reason": "run_ghidra_not_requested"}
    final_verdict = verdict(metadata, capa, yara)
    executed_actions = ["capa_analyze", "yara_scan"]
    toolchain = ["capa", "yara"]
    if run_ghidra_enabled:
        executed_actions.append("ghidra_static_analyze")
        toolchain.append("ghidra_headless")
    return {
        "success": True,
        "soc_stage": "malware_static_analysis_pipeline",
        "status": "static_analysis_pipeline_completed" if not run_ghidra_enabled or ghidra["success"] else "static_analysis_pipeline_partial",
        "execution_audit": {
            "agent_id": DEFAULT_AGENT_ID,
            "toolchain": toolchain,
            "credential_scope": "no_network_credentials_required",
        },
        "approval_required": False,
        "executed_actions": executed_actions,
        "destructive_actions_executed": [],
        "sample_source": source,
        "sample": metadata,
        "verdict": final_verdict,
        "ioc_candidates": {"sha256": metadata.get("sha256")},
        "ttp_candidates": capa.get("mitre_attack", []),
        "suspicious_functions": suspicious_functions(capa, objdump),
        "capa": capa,
        "yara": yara,
        "strings_preview": strings,
        "objdump_preview": objdump,
        "ghidra": ghidra,
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/health":
            json_response(self, {"status": "ok", "tool": "ghidra", "agent_id": DEFAULT_AGENT_ID})
            return
        json_response(self, {"error": "not_found"}, status=404)

    def do_POST(self):
        if urlparse(self.path).path != "/analyze":
            json_response(self, {"error": "not_found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = analyze(payload)
            json_response(self, result, status=200 if result.get("success") else 400)
        except Exception as exc:
            json_response(self, {"success": False, "error": f"{type(exc).__name__}: {exc}"}, status=500)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
