#!/usr/bin/env bash
# broker-entrypoint.sh — runs the broker's two surfaces in one container (local/Mac arm, #98).
#   :8443  model-inference forward proxy (the sa#97-fixed stub)
#   :8080  brokered tool-call API (safe_agents.broker.prototype.broker_server)
# Both bind 0.0.0.0 so the confined agent container can reach them over the private network.
set -uo pipefail

# If backed by DynamoDB LOCAL, create the single table first (idempotent; waits for the DB).
# Only the local arm needs this: AWS_ENDPOINT_URL_DYNAMODB is set ONLY for DynamoDB Local. On AWS
# the grants/counters/intents tables are infra-managed (State stack) and brokerRole cannot create
# tables, so table init is skipped there.
if [ "${BROKER_STORE:-memory}" = "dynamo" ] && [ -n "${AWS_ENDPOINT_URL_DYNAMODB:-}" ]; then
    echo "[broker-box] initializing DynamoDB Local table ..."
    python3 -m safe_agents.broker.prototype.dynamo_init || { echo "[broker-box] dynamo init failed"; exit 1; }
fi

echo "[broker-box] starting model-proxy on :8443 ..."
SA_BROKER_VETH_IP=0.0.0.0 SA_MODEL_PROXY_PORT="${SA_MODEL_PROXY_PORT:-8443}" \
    python3 /app/model-proxy-stub.py &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null' EXIT

echo "[broker-box] starting tool-call API on :8080 ..."
exec env BROKER_HOST=0.0.0.0 BROKER_PORT="${BROKER_PORT:-8080}" \
    python3 -m safe_agents.broker.prototype.broker_server
