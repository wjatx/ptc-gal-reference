#!/usr/bin/env bash
# run-brokered.sh — the confined + brokered turn for the always-on EC2 arm (sa#35, Option A).
#
# Converges the always-on EC2 box onto the TWO-BOX broker model: a real brokered round-trip
# against the broker SERVICE at broker.safe-agents.local — exactly like the proven ec2-woken box
# (safe_agents/arms/ec2_woken/box/run-brokered.sh) — while KEEPING the netns as a defense-in-depth
# process-isolation layer. The netns now FORWARDS to the broker service (agent-netns-setup.sh)
# instead of blackholing to a co-located stub.
#
# HOST vs NETNS split (this is the whole point of the two-phase shape):
#   HOST root netns  — has AWS-endpoint reach: (1) fetch the model oauth token from Secrets Manager
#                      (the box's own oauth grant), (2) write the run record to the agent-runs table.
#                      Neither is reachable from inside the confined netns (the run-record boundary).
#   NETNS agent-ns   — the CONFINED agent turn only: `claude -p` via the broker model proxy and one
#                      brokered `github.whoami` tool call. The box holds NO connector creds; the
#                      broker injects them, audits, and returns a decision with no credential.
#
# The two phases are one script that re-execs itself into the namespace:
#   phase 1 (host)   — default entry: fetch oauth, enter the netns, capture the confined turn's
#                      output + exit code, then write the run record and print the verdict.
#   phase 2 (netns)  — SA_CONFINED_PHASE=1: run ONLY the confined turn and print a TURN_RESULTS line.
#
# Trigger: the systemd agent service ExecStart's this script (timer-driven); it is also directly
# runnable on demand (e.g. over SSM: `SA_RUN_SMOKE=1 /opt/safe-agents/bin/run-brokered.sh "task"`).
#
# Input:
#   arg $1  OR  env TASK_TEXT   the task text (DATA — never obeyed as instructions). Defaults to a
#                               fixed capstone prompt so the timer can fire it with no arguments.
#
# Env contract (from /etc/safe-agents/agent.env, written by user-data — do NOT rename):
#   AGENT_NAME            agent id (run-record PK)
#   SA_BROKER_DNS         broker service DNS (broker.safe-agents.local)
#   SA_MODEL_PROXY_PORT   broker model-proxy port (default 8443)
#   SA_TOOL_API_PORT      broker tool-call API port (default 8080)
#   AGENT_RUNS_TABLE      the agent-runs DynamoDB table name (run records)
#   AWS_DEFAULT_REGION    region for the DynamoDB / Secrets Manager clients
#   SA_OAUTH_SECRET_ID    Secrets Manager id of the model oauth token (resolve-at-runtime)
#   SA_NETNS_NAME         the confined netns name (default agent-ns)
#   AGENT_RUN_USER        unprivileged user the confined turn drops to (default ec2-user)
#   SA_PROFILE            "autonomous" (enter the netns) | anything else (direct host run, break-glass)
#   SA_RUN_SMOKE          "1" to run the four smoke-egress assertions before the turn (default off)
#   CLAUDE_CODE_OAUTH_TOKEN  model token; if unset, resolved at runtime from SA_OAUTH_SECRET_ID
set -uo pipefail

# Load the env contract when present so on-demand (SSM) invocations get the same config the
# systemd service does. Existing environment wins (set -a exports what the file defines).
if [ -f /etc/safe-agents/agent.env ]; then
    set -a
    # shellcheck disable=SC1091
    . /etc/safe-agents/agent.env
    set +a
fi

TASK_TEXT="${1:-${TASK_TEXT:-Reply with a single line confirming you are running.}}"

BROKER="${SA_BROKER_DNS:?SA_BROKER_DNS must be set}"
PROXY_PORT="${SA_MODEL_PROXY_PORT:-8443}"
TOOL_PORT="${SA_TOOL_API_PORT:-8080}"
NS_NAME="${SA_NETNS_NAME:-agent-ns}"
RUN_USER="${AGENT_RUN_USER:-ec2-user}"

# Egress goes through the broker model-proxy; NO_PROXY keeps the broker host itself + IMDS direct
# (the tool-call API is plain HTTP to the broker, and must not be sent through the proxy).
export HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}"
export HTTP_PROXY="http://${BROKER}:${PROXY_PORT}"
export NO_PROXY="${BROKER},169.254.169.254,localhost,127.0.0.1"

# ── phase 2 (netns): the CONFINED turn only ─────────────────────────────────────────────────────
# Runs inside agent-ns (network-namespaced) as the unprivileged user. Prints logs + a single
# machine-parseable TURN_RESULTS line, and encodes pass/fail in the exit code. NO AWS-endpoint
# calls here — Secrets Manager + DynamoDB are unreachable from the confined netns by design.
if [ "${SA_CONFINED_PHASE:-0}" = "1" ]; then
    smoke_fail=0
    if [ "${SA_RUN_SMOKE:-0}" = "1" ]; then
        echo "=== smoke-egress (netns forwards to broker=${BROKER}; connectors + direct model blocked) ==="
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
        if echo "$smoke_code" | grep -qE '^[1-5][0-9]{2}$'; then
            echo "PASS: model reachable via broker proxy (HTTP ${smoke_code})"
        else
            echo "FAIL: model not reachable via broker proxy (got '${smoke_code}')"; smoke_fail=1
        fi
    fi

    echo "=== claude -p on the task (:${PROXY_PORT} via broker) ==="
    claude_out="$(claude -p "$TASK_TEXT" 2>&1)"
    echo "$claude_out" | head -8
    if [ -n "$claude_out" ] && ! echo "$claude_out" | grep -qiE 'error|failed to connect|proxy'; then
        model_ok=1; echo "claude -p: reply captured (model path OK)"
    else
        model_ok=0; echo "claude -p: no usable reply (model path failed)"
    fi

    echo "=== brokered github.whoami (:${TOOL_PORT}) ==="
    toolcall_out="$(curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" \
        -H 'content-type: application/json' \
        -d "{\"tool\":\"github\",\"op\":\"whoami\",\"args\":{},\"idempotency_key\":\"ec2-${RUN_ID:-run}\"}" \
        2>&1)"
    echo "$toolcall_out" | head -2
    if echo "$toolcall_out" | grep -qE '"decision_kind"[[:space:]]*:[[:space:]]*"allow"' \
       && echo "$toolcall_out" | grep -q '"login"'; then
        toolcall_ok=1; echo "tool call: allow + login (brokered read OK)"
    else
        toolcall_ok=0; echo "tool call: NOT allowed / no login (brokered read failed)"
    fi

    echo "TURN_RESULTS smoke=$([ "$smoke_fail" -eq 0 ] && echo ok || echo failed);model=$([ "$model_ok" -eq 1 ] && echo ok || echo fail);toolcall=$([ "$toolcall_ok" -eq 1 ] && echo allow || echo denied)"
    { [ "$smoke_fail" -eq 0 ] && [ "$model_ok" -eq 1 ] && [ "$toolcall_ok" -eq 1 ]; } && exit 0 || exit 1
fi

# ── phase 1 (host): oauth fetch → run the confined turn → run record ────────────────────────────
AGENT_NAME="${AGENT_NAME:?AGENT_NAME must be set}"
AGENT_RUNS_TABLE="${AGENT_RUNS_TABLE:?AGENT_RUNS_TABLE must be set}"
RUN_ID="${RUN_ID:-ec2-$(date -u +%Y%m%dT%H%M%SZ)}"
export RUN_ID

# The AWS control-plane (DynamoDB, Secrets Manager) is reached DIRECTLY via the VPC interface
# endpoints, NOT through the broker model-proxy — strip HTTPS_PROXY for those calls or the CLI
# routes to the broker (whose allowlist is the model API only) and fails.
aws_direct() { env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy aws "$@"; }

# HOST: resolve the model token from Secrets Manager (the box's own oauth grant — the ONLY secret
# the box may read; NOT connectors). Done here because Secrets Manager is unreachable from the netns.
if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -n "${SA_OAUTH_SECRET_ID:-}" ]; then
    CLAUDE_CODE_OAUTH_TOKEN="$(aws_direct secretsmanager get-secret-value \
        --secret-id "$SA_OAUTH_SECRET_ID" --query SecretString --output text 2>/dev/null || true)"
fi
export CLAUDE_CODE_OAUTH_TOKEN="${CLAUDE_CODE_OAUTH_TOKEN:-}"

echo "=== ec2 run: agent=${AGENT_NAME} run=${RUN_ID} broker=${BROKER} profile=${SA_PROFILE:-autonomous} ==="

# Run the confined turn. Autonomous → enter the netns and drop to the unprivileged user; the token
# + proxy env are already in this process (fetched above) and carried across the runuser env reset
# by an explicit whitelist. Break-glass (SA_PROFILE != autonomous) → run the turn directly in the
# host root netns (still SG-confined, but without the netns process-isolation layer).
export SA_CONFINED_PHASE=1
export TASK_TEXT
_WL="CLAUDE_CODE_OAUTH_TOKEN,HTTPS_PROXY,HTTP_PROXY,NO_PROXY,SA_CONFINED_PHASE,TASK_TEXT,RUN_ID"
_WL="${_WL},SA_BROKER_DNS,SA_MODEL_PROXY_PORT,SA_TOOL_API_PORT,SA_RUN_SMOKE,AGENT_NAME"

if [ "${SA_PROFILE:-autonomous}" = "autonomous" ]; then
    confined_out="$(ip netns exec "$NS_NAME" \
        runuser -w "$_WL" -u "$RUN_USER" -- "$0" 2>&1)"; turn_rc=$?
else
    confined_out="$("$0" 2>&1)"; turn_rc=$?
fi
echo "$confined_out"

results="$(printf '%s\n' "$confined_out" | sed -n 's/^TURN_RESULTS //p' | tail -1)"
[ -n "$results" ] || results="smoke=unknown;model=unknown;toolcall=unknown"
status="$([ "$turn_rc" -eq 0 ] && echo ok || echo fail)"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# HOST: run record → agent-runs table (PK=agentId, SK=runId), direct via the VPC endpoint. The
# agent-runs table is CMK-encrypted; the box role carries the tables-CMK grant for this PutItem.
# Best-effort: the run never fails *because* the run-record store is unreachable, but it logs loudly.
echo "=== run record → ${AGENT_RUNS_TABLE} (arm=ec2) ==="
if put_err="$(aws_direct dynamodb put-item \
    --table-name "$AGENT_RUNS_TABLE" \
    --item "{
        \"agentId\": {\"S\": \"${AGENT_NAME}\"},
        \"runId\": {\"S\": \"${RUN_ID}\"},
        \"status\": {\"S\": \"${status}\"},
        \"arm\": {\"S\": \"ec2\"},
        \"ts\": {\"S\": \"${ts}\"},
        \"results\": {\"S\": \"${results}\"}
    }" 2>&1)"; then
    echo "run record: written (status=${status})"
else
    echo "WARNING: run record write failed (run does not fail on this) — status=${status}: ${put_err}"
fi

if [ "$status" = "ok" ]; then
    echo "EC2_RUN: PASS (run=${RUN_ID})"; exit 0
else
    echo "EC2_RUN: FAIL (run=${RUN_ID})"; exit 1
fi
