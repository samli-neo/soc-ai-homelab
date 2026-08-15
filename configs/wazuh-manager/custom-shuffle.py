#!/usr/bin/env python3
import sys
import json
import os
import urllib.request
import urllib.error
import logging

SHUFFLE_BASE = os.environ.get("SHUFFLE_BASE_URL", "http://shuffle-backend:5001")
WORKFLOW_ID = os.environ.get("SHUFFLE_WORKFLOW_ID", "043882e1-8ea3-4f88-898c-b12957ff2785")
SHUFFLE_EXECUTE_URL = os.environ.get(
    "SHUFFLE_EXECUTE_URL",
    f"{SHUFFLE_BASE}/api/v1/workflows/{WORKFLOW_ID}/execute"
)
SHUFFLE_API_KEY = os.environ.get("SHUFFLE_API_KEY", "")
MIN_LEVEL = int(os.environ.get("SHUFFLE_MIN_LEVEL", "7"))
LOG_FILE = "/var/ossec/logs/integration-shuffle.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)


def execute_workflow(alert: dict, execute_url: str, api_key: str) -> bool:
    payload = json.dumps({
        "execution_argument": json.dumps(alert)
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(execute_url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            if resp.status == 200:
                logging.info("Workflow execution triggered: %s", body)
                return True
            logging.error("HTTP %d: %s", resp.status, body)
            return False
    except urllib.error.URLError as e:
        logging.error("Failed to trigger workflow at %s: %s", execute_url, e)
        return False


def normalize_alert(alert: dict) -> dict:
    if not isinstance(alert.get("rule"), dict):
        alert["rule"] = {}
    alert["rule"].setdefault("id", "")
    alert["rule"].setdefault("level", 0)
    alert["rule"].setdefault("description", "")

    if not isinstance(alert.get("agent"), dict):
        alert["agent"] = {}
    alert["agent"].setdefault("id", "")
    alert["agent"].setdefault("name", "")

    if not isinstance(alert.get("manager"), dict):
        alert["manager"] = {}
    alert["manager"].setdefault("name", "")

    if not isinstance(alert.get("data"), dict):
        alert["data"] = {}
    data = alert["data"]
    data.setdefault("srcip", alert.get("srcip", ""))
    data.setdefault("dstip", alert.get("dstip", ""))
    data.setdefault("sha256", alert.get("sha256", ""))
    data.setdefault("test_type", "")

    alert.setdefault("timestamp", "")
    alert.setdefault("id", "")
    alert.setdefault("location", "")
    return alert


def main():
    alert_file = sys.argv[1] if len(sys.argv) > 1 else None
    api_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else SHUFFLE_API_KEY
    execute_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else SHUFFLE_EXECUTE_URL
    if api_key.startswith("SHUFFLE_API_KEY_"):
        api_key = SHUFFLE_API_KEY
    if alert_file:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    else:
        alert = json.loads(sys.stdin.read())

    alert = normalize_alert(alert)

    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_LEVEL:
        logging.debug("Skipped alert level %d (min %d)", level, MIN_LEVEL)
        return

    result = execute_workflow(alert, execute_url, api_key)
    if not result:
        logging.warning("Retrying once for alert %s", alert.get("id"))
        result = execute_workflow(alert, execute_url, api_key)

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
