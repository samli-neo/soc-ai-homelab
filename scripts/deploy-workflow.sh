#!/bin/bash
# ============================================================
# Deploy Wazuh → Shuffle → TheHive + MISP workflow
# Run this on the soc-docker LXC (10.10.50.111)
# ============================================================
set -euo pipefail

SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:3001}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:-}"
SHUFFLE_WORKFLOW_ID="${SHUFFLE_WORKFLOW_ID:-730b80b1-661f-4cfd-8e57-f4746f3181e5}"
SHUFFLE_BACKEND_URL="${SHUFFLE_BACKEND_URL:-http://shuffle-backend:5001}"
SHUFFLE_EXECUTE_URL="${SHUFFLE_BACKEND_URL}/api/v1/workflows/${SHUFFLE_WORKFLOW_ID}/execute"
WAZUH_MANAGER="wazuh-manager"
CONFIG_ROOT="${CONFIG_ROOT:-/root/soc-configs}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

if [ -z "$SHUFFLE_API_KEY" ]; then
    err "SHUFFLE_API_KEY is required"
    echo "Example: SHUFFLE_API_KEY='...' $0"
    exit 1
fi

# --------------------------------------------------
# 1. Copy Wazuh integration files
# --------------------------------------------------
log "Copying integration scripts to Wazuh manager..."
python3 -m py_compile "$CONFIG_ROOT/wazuh-manager/custom-shuffle.py"
docker cp "$CONFIG_ROOT/wazuh-manager/custom-shuffle.py" "$WAZUH_MANAGER":/var/ossec/integrations/custom-shuffle.py
docker exec "$WAZUH_MANAGER" chmod 750 /var/ossec/integrations/custom-shuffle.py
docker exec "$WAZUH_MANAGER" chown root:wazuh /var/ossec/integrations/custom-shuffle.py

log "Copying custom decoders..."
docker cp "$CONFIG_ROOT/wazuh-manager/local_decoders.xml" "$WAZUH_MANAGER":/var/ossec/etc/rules/local_decoders.xml

log "Rendering ossec.conf with Shuffle execute endpoint..."
sed \
  -e "s|SHUFFLE_API_KEY_FROM_ENV_OR_DEPLOY|$SHUFFLE_API_KEY|g" \
  -e "s|http://shuffle-backend:5001/api/v1/workflows/730b80b1-661f-4cfd-8e57-f4746f3181e5/execute|$SHUFFLE_EXECUTE_URL|g" \
  "$CONFIG_ROOT/wazuh-manager/ossec.conf" > /tmp/ossec.conf
docker cp /tmp/ossec.conf "$WAZUH_MANAGER":/wazuh-config-mount/etc/ossec.conf

# --------------------------------------------------
# 2. Restart Wazuh manager
# --------------------------------------------------
log "Restarting Wazuh manager..."
docker exec "$WAZUH_MANAGER" /var/ossec/bin/wazuh-control restart
sleep 5

# --------------------------------------------------
# 3. Get Shuffle webhook URL (create via API)
# --------------------------------------------------
log "Verifying Shuffle workflow execute API..."
# Login to get session token
SHUFFLE_AUTH=$(curl -s -X POST "$SHUFFLE_URL/api/v1/users/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@soc.local", "password": "Admin1234!"}')

SHUFFLE_TOKEN=$(echo "$SHUFFLE_AUTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key', ''))" 2>/dev/null || echo "")

if [ -z "$SHUFFLE_TOKEN" ]; then
    warn "Could not auto-login to Shuffle. Skipping workflow import check."
else
    log "Shuffle token obtained"
    # Import workflow via Shuffle API
    IMPORT_RESP=$(curl -s -X POST "$SHUFFLE_URL/api/v1/workflows/import" \
      -H "Authorization: Bearer $SHUFFLE_TOKEN" \
      -H "Content-Type: application/json" \
      -d @/root/soc/shuffle/wazuh-to-thehive-misp.json 2>/dev/null || echo "failed")

    if echo "$IMPORT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null | grep -q '.'; then
        WF_ID=$(echo "$IMPORT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
        log "Workflow imported: $WF_ID"
    else
        warn "Import failed. Import manually via Shuffle UI (see README)."
    fi
fi

EXEC_RESP=$(curl -s -o /tmp/shuffle-exec-test.json -w "%{http_code}" -X POST "$SHUFFLE_URL/api/v1/workflows/$SHUFFLE_WORKFLOW_ID/execute" \
  -H "Authorization: Bearer $SHUFFLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"execution_argument":"{\"test\":\"deploy-check\"}"}' || true)
if [ "$EXEC_RESP" = "200" ]; then
    log "Shuffle execute API accepted test execution"
else
    warn "Shuffle execute API returned HTTP $EXEC_RESP; see /tmp/shuffle-exec-test.json"
fi

# --------------------------------------------------
# 4. Test the integration
# --------------------------------------------------
log "Testing Wazuh integration..."
docker exec "$WAZUH_MANAGER" /var/ossec/bin/wazuh-control test 2>/dev/null || true

echo ""
log "================================================"
log "Deployment complete!"
log "================================================"
echo ""
echo "Next steps:"
echo "  1. Verify Shuffle workflow at: $SHUFFLE_URL"
echo "  2. Check integration logs:"
echo "     docker exec $WAZUH_MANAGER tail -f /var/ossec/logs/integration-shuffle.log"
echo "  3. Trigger test alert:"
echo "     docker exec $WAZUH_MANAGER /var/ossec/bin/wazuh-control alert-test"
echo ""
