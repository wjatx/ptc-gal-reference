#!/usr/bin/env bash
# run-brokered.sh — the per-message confined + brokered runner for the ec2-woken box (sa#98).
#
# One invocation == one inbound task message run as a confined, brokered agent turn. The box
# is confined by NETWORK TOPOLOGY (like the Fargate arm, safe_agents/arms/fargate/run.sh), NOT by an
# in-box netns: the box runs in the ISOLATED agent subnet on the agent SG whose only egress is
# the broker service (broker.safe-agents.local). So this runner does NO ip route / blackhole /
# netns setup — it only:
#   (a) points HTTPS_PROXY at the broker model-proxy,
#   (b) (optionally) proves the confinement holds (the four smoke-egress assertions),
#   (c) runs a real `claude -p` on the MESSAGE TEXT (treated as DATA/task) through the proxy,
#   (d) makes a brokered tool call (github.whoami) on the tool API — the box holds NO creds,
#   (e) writes a structured run record (incl. the message id) to the agent-runs table,
#   (f) prints a single WOKEN_RUN verdict and exits with a meaningful code.
#
# Input:
#   arg $1  OR  env TASK_TEXT   the inbound message text (DATA — never obeyed as instructions).
#
# Env contract (set by drain.sh from /etc/safe-agents/agent.env — do NOT rename):
#   SA_BROKER_DNS         broker DNS, e.g. broker.safe-agents.local
#   SA_MODEL_PROXY_PORT   broker model-proxy port (default 8443)
#   SA_TOOL_API_PORT      broker tool-call API port (default 8080)
#   AGENT_RUNS_TABLE      the agent-runs DynamoDB table name
#   AGENT_NAME            agent id (run-record PK)
#   RUN_ID                this run's id (run-record SK; drain derives it from the message id)
#   MESSAGE_ID            the inbound message id (recorded on the run record; defaults to RUN_ID)
#   AWS_DEFAULT_REGION    region for the DynamoDB / Secrets Manager clients
#   CLAUDE_CODE_OAUTH_TOKEN   model token; if unset and SA_OAUTH_SECRET_ID is set, resolved
#                             at runtime from Secrets Manager (the box's own oauth-token grant)
#   SA_OAUTH_SECRET_ID    Secrets Manager id of the model oauth token (resolve-at-runtime)
#   SA_RUN_SMOKE          "1" to run the four smoke-egress assertions before the run (default off)
set -uo pipefail

# Line-buffer stdout/stderr so logs survive an abrupt `stop-instances` — re-exec self once
# under stdbuf (the same durable-logging fix pattern used across the arms).
if [ -z "${_SA_STDBUF:-}" ] && command -v stdbuf >/dev/null 2>&1; then
    export _SA_STDBUF=1
    exec stdbuf -oL -eL "$0" "$@"
fi

TASK_TEXT="${1:-${TASK_TEXT:-}}"
if [ -z "$TASK_TEXT" ]; then
    echo "run-brokered: no task text (arg \$1 or TASK_TEXT) provided" >&2
    exit 2
fi

BROKER="${SA_BROKER_DNS:?SA_BROKER_DNS must be set}"
PROXY_PORT="${SA_MODEL_PROXY_PORT:-8443}"
TOOL_PORT="${SA_TOOL_API_PORT:-8080}"
AGENT_NAME="${AGENT_NAME:?AGENT_NAME must be set}"
RUN_ID="${RUN_ID:?RUN_ID must be set}"
MESSAGE_ID="${MESSAGE_ID:-$RUN_ID}"
AGENT_RUNS_TABLE="${AGENT_RUNS_TABLE:?AGENT_RUNS_TABLE must be set}"

# The AWS control-plane (DynamoDB, Secrets Manager) is reached DIRECTLY via the VPC gateway /
# interface endpoints, NOT through the broker model-proxy — so strip HTTPS_PROXY for those calls,
# or the CLI routes to the broker (whose allowlist is the model API only) and fails.
aws_direct() { env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy aws "$@"; }

# Resolve the model token from Secrets Manager if it was not injected directly. This uses the
# box's own oauth-token GetSecretValue grant — the ONLY secret the box may read (NOT connectors).
if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -n "${SA_OAUTH_SECRET_ID:-}" ]; then
    CLAUDE_CODE_OAUTH_TOKEN="$(aws_direct secretsmanager get-secret-value \
        --secret-id "$SA_OAUTH_SECRET_ID" --query SecretString --output text 2>/dev/null || true)"
    export CLAUDE_CODE_OAUTH_TOKEN
fi

# (a) Egress goes through the broker model-proxy. NO_PROXY keeps the proxy host itself direct.
export HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}"
export HTTP_PROXY="http://${BROKER}:${PROXY_PORT}"
export NO_PROXY="${BROKER},169.254.169.254"

echo "=== woken run: agent=${AGENT_NAME} run=${RUN_ID} message=${MESSAGE_ID} broker=${BROKER} ==="

# ── (b) OPTIONAL smoke-egress — prove the topology confines us (same four assertions as Fargate) ──
smoke_fail=0
if [ "${SA_RUN_SMOKE:-0}" = "1" ]; then
    echo "=== smoke-egress (ec2-woken == ISOLATED agent subnet; broker=${BROKER}) ==="
    if curl -sS -m5 https://api.telegram.org >/dev/null 2>&1; then
        echo "FAIL: connector reachable (should have no route)"; smoke_fail=1
    else
        echo "PASS: connector unreachable"
    fi
    if timeout 5 bash -c "echo > /dev/tcp/${BROKER}/${PROXY_PORT}" 2>/dev/null; then
        echo "PASS: broker reachable"
    else
        echo "FAIL: broker unreachable (${BROKER}:${PROXY_PORT})"; smoke_fail=1
    fi
    if env -u HTTPS_PROXY -u HTTP_PROXY curl -sS -m5 https://api.anthropic.com >/dev/null 2>&1; then
        echo "FAIL: model reachable direct (should only be via the broker proxy)"; smoke_fail=1
    else
        echo "PASS: model unreachable direct"
    fi
    smoke_code="$(curl -sS -m8 -o /dev/null -w '%{http_code}' "https://api.anthropic.com/" 2>/dev/null)"
    # curl returns "000" when the connection itself fails — through the proxy that means the
    # broker path is broken; it must NOT count as reachable.
    if echo "$smoke_code" | grep -qE '^[1-5][0-9]{2}$'; then
        echo "PASS: model reachable via broker proxy (HTTP ${smoke_code})"
    else
        echo "FAIL: model not reachable via broker proxy (got '${smoke_code}')"; smoke_fail=1
    fi
fi

# ── (c) real claude -p on the MESSAGE TEXT through the broker proxy (:PROXY_PORT) ──────────────────
# The message text is DATA: an inbound task the agent works on, never trusted as instructions to
# the runner. It is passed as a quoted shell variable (no shell interpretation of its contents).
echo "=== claude -p on the inbound message (:${PROXY_PORT}) ==="
claude_out="$(claude -p "$TASK_TEXT" 2>&1)"
echo "$claude_out" | head -8
if [ -n "$claude_out" ] && ! echo "$claude_out" | grep -qiE 'error|failed to connect|proxy'; then
    model_ok=1; echo "claude -p: reply captured (model path OK)"
else
    model_ok=0; echo "claude -p: no usable reply (model path failed)"
fi

# ── (d) brokered tool call (:TOOL_PORT) — github.whoami, the real read-only connector ─────────────
# The box holds no GitHub token and cannot reach api.github.com directly. It asks the broker, which
# injects the credential itself, calls the connector, audits, and returns a decision with NO
# credential. 'allow + login' is a real brokered read proving the broker path.
echo "=== brokered github.whoami (:${TOOL_PORT}) ==="
toolcall_out="$(curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" \
    -H 'content-type: application/json' \
    -d "{\"tool\":\"github\",\"op\":\"whoami\",\"args\":{},\"idempotency_key\":\"woken-${RUN_ID}\"}" \
    2>&1)"
echo "$toolcall_out" | head -2
# The broker returns pretty JSON ("decision_kind": "allow" — with spaces), so match
# space-tolerantly rather than assuming compact JSON.
if echo "$toolcall_out" | grep -qE '"decision_kind"[[:space:]]*:[[:space:]]*"allow"' \
   && echo "$toolcall_out" | grep -q '"login"'; then
    toolcall_ok=1; echo "tool call: allow + login (brokered read OK)"
else
    toolcall_ok=0; echo "tool call: NOT allowed / no login (brokered read failed)"
fi

# ── verdict ───────────────────────────────────────────────────────────────────────────────────────
if [ "$smoke_fail" -eq 0 ] && [ "$model_ok" -eq 1 ] && [ "$toolcall_ok" -eq 1 ]; then
    status="ok"
else
    status="fail"
fi
results="smoke=$([ "$smoke_fail" -eq 0 ] && echo ok || echo failed); model=$([ "$model_ok" -eq 1 ] && echo ok || echo fail); toolcall=$([ "$toolcall_ok" -eq 1 ] && echo allow || echo denied)"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── (e) run record → agent-runs table (PK=agentId, SK=runId), direct via the VPC endpoint ─────────
# Best-effort: the run never fails *because* the run-record store is unreachable, but a failure is
# logged loudly. The message id is recorded so the drained SQS message is traceable to its run.
echo "=== run record → ${AGENT_RUNS_TABLE} ==="
put_err="$(aws_direct dynamodb put-item \
    --table-name "$AGENT_RUNS_TABLE" \
    --item "{
        \"agentId\": {\"S\": \"${AGENT_NAME}\"},
        \"runId\": {\"S\": \"${RUN_ID}\"},
        \"status\": {\"S\": \"${status}\"},
        \"arm\": {\"S\": \"ec2-woken\"},
        \"ts\": {\"S\": \"${ts}\"},
        \"messageId\": {\"S\": \"${MESSAGE_ID}\"},
        \"results\": {\"S\": \"${results}\"}
    }" 2>&1)"
if [ $? -eq 0 ]; then
    echo "run record: written (status=${status})"
else
    echo "WARNING: run record write failed (run does not fail on this) — status=${status}: ${put_err}"
fi

# ── (f) capstone verdict + meaningful exit code ────────────────────────────────────────────────────
if [ "$status" = "ok" ]; then
    echo "WOKEN_RUN: PASS (message=${MESSAGE_ID})"
    exit 0
else
    echo "WOKEN_RUN: FAIL (message=${MESSAGE_ID})"
    exit 1
fi
