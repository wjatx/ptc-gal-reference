#!/usr/bin/env bash
# run.sh — the confined agent runner for the AWS Fargate arm (sa#36 C2a).
#
# Executed as the task's entrypoint. On Fargate the agent is confined by NETWORK TOPOLOGY, not by
# in-container netns: the task runs in a PRIVATE_ISOLATED subnet (no NAT, no internet route) with a
# security group whose only egress is the broker. So — unlike safe_agents/arms/local/confine-and-run.sh —
# this runner does NO `ip route`/blackhole/netns setup. It only:
#   (a) points HTTPS_PROXY at the broker model-proxy,
#   (b) proves the confinement holds (the four smoke-egress assertions),
#   (c) runs a real `claude -p` through the broker proxy,
#   (d) makes a brokered tool call (SA_SMOKE_TOOL.SA_SMOKE_OP, default github.whoami) on the tool API,
#   (e) writes a structured run record to the agent-runs table (via the VPC gateway endpoint),
#   (f) prints a single FARGATE_CAPSTONE verdict and exits with a meaningful code.
#
# Env contract (set by the task definition — do NOT rename):
#   SA_BROKER_DNS         broker DNS, e.g. broker.safe-agents.local
#   SA_MODEL_PROXY_PORT   broker model-proxy port, e.g. 8443
#   SA_TOOL_API_PORT      broker tool-call API port, e.g. 8080
#   AGENT_RUNS_TABLE      the agent-runs DynamoDB table name
#   AGENT_NAME            agent id (run-record PK)
#   RUN_ID               this run's id (run-record SK)
#   CLAUDE_CODE_OAUTH_TOKEN   model token, injected from Secrets Manager via the task secrets: block
#   AWS_DEFAULT_REGION    region for the DynamoDB client
#
# OPTIONAL env (NOT set by the task definition; a RunTask containerOverrides may set them to point
# the brokered-call proof at whatever action class the broker really grants this agent):
#   SA_SMOKE_TOOL         tool for the brokered call            (default: github)
#   SA_SMOKE_OP           operation on that tool                (default: whoami)
#   SA_SMOKE_ARGS_JSON    JSON object passed as the call args   (default: {})
#   SA_SMOKE_EXPECT       substring asserted in the result,
#                         alongside "decision_kind": "allow"    (default: login)
set -uo pipefail

BROKER="${SA_BROKER_DNS}"
PROXY_PORT="${SA_MODEL_PROXY_PORT}"
TOOL_PORT="${SA_TOOL_API_PORT}"

# (a) Egress goes through the broker model-proxy. NO_PROXY keeps the proxy host itself direct so the
# TCP reachability probe and the tool-call API are not themselves proxied.
export HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}"
export HTTP_PROXY="http://${BROKER}:${PROXY_PORT}"
export NO_PROXY="${BROKER}"

# ── (b) smoke-egress — prove the topology confines us (same four assertions as the local arm) ──────
echo "=== smoke-egress (Fargate == PRIVATE_ISOLATED subnet; broker=${BROKER}) ==="
smoke_fail=0

# 1. connector unreachable: a direct hit to a connector host must FAIL (no NAT, no internet route).
if curl -sS -m5 https://api.telegram.org >/dev/null 2>&1; then
    echo "FAIL: connector reachable (api.telegram.org should have no route)"; smoke_fail=1
else
    echo "PASS: connector unreachable"
fi

# 2. broker reachable: a TCP open to the broker model-proxy must SUCCEED (the one allowed egress).
if timeout 5 bash -c "echo > /dev/tcp/${BROKER}/${PROXY_PORT}" 2>/dev/null; then
    echo "PASS: broker reachable"
else
    echo "FAIL: broker unreachable (${BROKER}:${PROXY_PORT})"; smoke_fail=1
fi

# 3. model blocked-direct: bypassing the proxy, the model API must be unreachable (no route).
if env -u HTTPS_PROXY -u HTTP_PROXY curl -sS -m5 https://api.anthropic.com >/dev/null 2>&1; then
    echo "FAIL: model reachable direct (should only be reachable via the broker proxy)"; smoke_fail=1
else
    echo "PASS: model unreachable direct"
fi

# 4. model via proxy: through the broker proxy, the model API must answer with an HTTP status code.
model_code="$(curl -sS -m8 -o /dev/null -w '%{http_code}' "https://api.anthropic.com/" 2>/dev/null)"
# A real HTTP status is 1xx-5xx; curl returns "000" when the connection itself fails (which,
# through the proxy, would mean the broker path is broken) — that must NOT count as reachable.
if echo "$model_code" | grep -qE '^[1-5][0-9]{2}$'; then
    echo "PASS: model reachable via broker proxy (HTTP ${model_code})"
else
    echo "FAIL: model not reachable via broker proxy (got '${model_code}')"; smoke_fail=1
fi

if [ "$smoke_fail" -eq 0 ]; then
    echo "smoke-egress: all 4 assertions passed"
else
    echo "smoke-egress: CONFINEMENT/REACHABILITY FAILED"
fi

# ── (c) real claude -p through the broker proxy (:PROXY_PORT) ───────────────────────────────────────
echo "=== claude -p through the broker (:${PROXY_PORT}) ==="
claude_out="$(claude -p "Reply with exactly the token: FARGATE_AGENT_OK and nothing else." 2>&1)"
echo "$claude_out" | head -4
if echo "$claude_out" | grep -q "FARGATE_AGENT_OK"; then
    model_ok=1; echo "claude -p: token present (model path OK)"
else
    model_ok=0; echo "claude -p: token MISSING (model path failed)"
fi

# ── (d) brokered tool call (:TOOL_PORT) — a real read through the broker ───────────────────────────
# The agent holds no connector credential and cannot reach the connector host directly (smoke-egress
# proved it). It asks the broker, which injects the credential itself, calls the connector, audits,
# and returns a decision + result with NO credential. 'allow + expected substring' is the whole
# point: a real brokered read. Which call to make is parameterized so the proof can exercise
# whatever action class the broker really grants this agent (default: github.whoami / "login").
SMOKE_TOOL="${SA_SMOKE_TOOL:-github}"
SMOKE_OP="${SA_SMOKE_OP:-whoami}"
SMOKE_ARGS_JSON="${SA_SMOKE_ARGS_JSON:-"{}"}"
SMOKE_EXPECT="${SA_SMOKE_EXPECT:-login}"
echo "=== brokered ${SMOKE_TOOL}.${SMOKE_OP} (:${TOOL_PORT}) ==="
toolcall_out="$(curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" \
    -H 'content-type: application/json' \
    -d "{\"tool\":\"${SMOKE_TOOL}\",\"op\":\"${SMOKE_OP}\",\"args\":${SMOKE_ARGS_JSON},\"idempotency_key\":\"fargate-${RUN_ID}\"}" \
    2>&1)"
echo "$toolcall_out" | head -2
# The broker returns pretty JSON ("decision_kind": "allow" — with spaces), so match
# space-tolerantly rather than assuming compact JSON.
if echo "$toolcall_out" | grep -qE '"decision_kind"[[:space:]]*:[[:space:]]*"allow"' \
   && echo "$toolcall_out" | grep -qF -- "$SMOKE_EXPECT"; then
    toolcall_ok=1; echo "tool call: allow + '${SMOKE_EXPECT}' (brokered read OK)"
else
    toolcall_ok=0; echo "tool call: NOT allowed / '${SMOKE_EXPECT}' missing (brokered read failed)"
fi

# ── verdict ─────────────────────────────────────────────────────────────────────────────────────
if [ "$smoke_fail" -eq 0 ] && [ "$model_ok" -eq 1 ] && [ "$toolcall_ok" -eq 1 ]; then
    status="ok"
else
    status="fail"
fi
results="smoke=$([ "$smoke_fail" -eq 0 ] && echo 4/4 || echo failed); model=$([ "$model_ok" -eq 1 ] && echo ok || echo fail); toolcall=$([ "$toolcall_ok" -eq 1 ] && echo allow || echo denied)"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── (e) run record → agent-runs table (PK=agentId, SK=runId), via the VPC gateway endpoint ─────────
# A best-effort write: the agent never fails *because* the run-record store is unreachable, but a
# failure is logged loudly so observability/the watcher can see it.
echo "=== run record → ${AGENT_RUNS_TABLE} ==="
# The AWS API (DynamoDB) is reached DIRECTLY via the VPC gateway endpoint, NOT through the broker
# model-proxy — so strip HTTPS_PROXY/HTTP_PROXY for this call, or the CLI routes to the broker
# (whose allowlist is api.anthropic.com only) and fails "Failed to connect to proxy URL".
put_err="$(env -u HTTPS_PROXY -u HTTP_PROXY aws dynamodb put-item \
    --table-name "$AGENT_RUNS_TABLE" \
    --item "{
        \"agentId\": {\"S\": \"${AGENT_NAME}\"},
        \"runId\": {\"S\": \"${RUN_ID}\"},
        \"status\": {\"S\": \"${status}\"},
        \"arm\": {\"S\": \"fargate\"},
        \"ts\": {\"S\": \"${ts}\"},
        \"results\": {\"S\": \"${results}\"}
    }" 2>&1)"
if [ $? -eq 0 ]; then
    echo "run record: written (status=${status})"
else
    echo "WARNING: run record write failed (agent does not fail on this) — status=${status}: ${put_err}"
fi

# ── (f) capstone verdict + meaningful exit code ────────────────────────────────────────────────────
if [ "$status" = "ok" ]; then
    echo "FARGATE_CAPSTONE: PASS"
    exit 0
else
    echo "FARGATE_CAPSTONE: FAIL"
    exit 1
fi
