#!/usr/bin/env bash
# confine-and-run.sh — runs INSIDE the local/Mac agent container (needs --cap-add NET_ADMIN).
#
# A container is a netns, so this is the local equivalent of agent-netns-setup.sh + run-agent.sh:
# blackhole the default route and leave ONLY the broker reachable, then prove the confinement
# (the four smoke-egress assertions), run a real claude -p through the broker model-proxy (:8443),
# and make brokered tool calls (:8080) — exercising BOTH broker surfaces from the confined agent.
# Every step is asserted; the script exits non-zero if ANY assertion fails.
#
# SA_BROKER_HOST: the broker's address. Either another container's IP on a private network
# (two-container topology, #98) or host.containers.internal (broker-as-host-process). Both work:
# this resolves the current path to it before blackholing everything else.
set -uo pipefail

GW="$(ip route | awk '/default/{print $3; exit}')"
BROKER="${SA_BROKER_HOST:-$(getent hosts host.containers.internal | awk '{print $1; exit}')}"
PORT="${SA_MODEL_PROXY_PORT:-8443}"
TOOL_PORT="${SA_TOOL_API_PORT:-8080}"

# --- Confine egress to the broker only (as root) -----------------------------------------------
# Capture how we currently reach the broker BEFORE mutating routes (on-link vs via the gateway).
BROKER_VIA="$(ip route get "$BROKER" 2>/dev/null | grep -oE 'via [0-9.]+' | awk '{print $2}')"
SUBNET="$(ip route | awk '/proto kernel/ && /dev eth0/ {print $1; exit}')"
ip route del default 2>/dev/null || true
[ -n "$SUBNET" ] && ip route del "$SUBNET" dev eth0 2>/dev/null || true   # drop broad subnet reach
if [ -n "$BROKER_VIA" ]; then
    ip route replace "${BROKER}/32" via "$BROKER_VIA" dev eth0
else
    ip route replace "${BROKER}/32" dev eth0
fi
ip route replace blackhole default                                       # everything else: no route

export HTTPS_PROXY="http://${BROKER}:${PORT}" HTTP_PROXY="http://${BROKER}:${PORT}" NO_PROXY="${BROKER}"

echo "=== smoke-egress (container == local netns; broker=${BROKER}) ==="
fail=0
if curl -sS -m5 https://api.telegram.org >/dev/null 2>&1; then echo "FAIL: connector reachable"; fail=1; else echo "PASS: connector unreachable"; fi
if timeout 5 bash -c "echo > /dev/tcp/${BROKER}/${PORT}" 2>/dev/null; then echo "PASS: broker reachable"; else echo "FAIL: broker unreachable"; fail=1; fi
if env -u HTTPS_PROXY -u HTTP_PROXY curl -sS -m5 https://api.anthropic.com >/dev/null 2>&1; then echo "FAIL: model reachable direct"; fail=1; else echo "PASS: model unreachable direct"; fi
if curl -sS -m8 -o /dev/null -w '%{http_code}' "https://api.anthropic.com/" 2>/dev/null | grep -qE '^[0-9]{3}$'; then echo "PASS: model reachable via broker proxy"; else echo "FAIL: model not reachable via proxy"; fail=1; fi
[ "$fail" -eq 0 ] && echo "smoke-egress: all assertions passed" || echo "smoke-egress: CONFINEMENT FAILED"

echo "=== real claude -p through the broker (:${PORT}, as the unprivileged agent) ==="
CLAUDE_OUT="$(runuser -u agent -- env \
  CLAUDE_CODE_OAUTH_TOKEN="${CLAUDE_CODE_OAUTH_TOKEN:-}" \
  HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTP_PROXY" NO_PROXY="$NO_PROXY" PATH="$PATH" \
  claude -p "Reply with exactly the token: LOCAL_MAC_CONFINED_OK and nothing else." 2>&1)"
echo "$CLAUDE_OUT" | head -4
if echo "$CLAUDE_OUT" | grep -q "LOCAL_MAC_CONFINED_OK"; then
  echo "PASS: claude answered through the broker proxy"
else
  echo "FAIL: claude did not answer through the broker proxy"; fail=1
fi

echo "=== brokered github.whoami (:${TOOL_PORT}, the REAL read-only connector) ==="
# The confined agent asks the broker to perform a tool op. The broker decides, injects
# the connector credential itself (the GitHub token from its secrets file), calls
# GET /user, audits — and returns {"login": ...} with NO credential. The agent holds no
# token and never reaches api.github.com directly (smoke-egress proved that). This is
# 'the agent can still only ask.' github.whoami is the class this local run grants
# (BROKER_GRANT_CLASSES, set by run-local.sh) because the harness provisions its
# credential from the macOS Keychain. Called TWICE with the same idempotency_key: the
# second must return idempotent without re-executing — proving the broker's DynamoDB
# conditional-write dedup (when the broker runs BROKER_STORE=dynamo).
_toolcall() {
  runuser -u agent -- curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" \
    -H 'content-type: application/json' -d "$1" 2>&1
}
_expect() {  # _expect <response> <required-substring> <label>
  if echo "$1" | grep -qF -- "$2"; then echo "PASS: $3"; else echo "FAIL: $3"; fail=1; fi
}
WHOAMI='{"tool":"github","op":"whoami","args":{},"idempotency_key":"local-github-whoami-1"}'
echo "--- call 1 (expect allow + login, executed fresh) ---"
R1="$(_toolcall "$WHOAMI")"; echo "$R1" | head -2
_expect "$R1" '"decision_kind": "allow"' "call 1 allowed"
_expect "$R1" '"login"' "call 1 returned the real GitHub login"
_expect "$R1" '"idempotent": false' "call 1 executed fresh (not a replay)"
echo "--- call 2, same idempotency_key (expect idempotent=true, no re-execute) ---"
R2="$(_toolcall "$WHOAMI")"; echo "$R2" | head -2
_expect "$R2" '"idempotent": true' "call 2 replayed idempotently"

echo "=== brokered alpaca.read (:${TOOL_PORT}, an UNGRANTED class — expect deny) ==="
# alpaca.read is in the manifest and its connector is wired, but this local run does
# not grant it (its Alpaca credential is never provisioned here) — the PDP must deny.
# Fail-closed is the other half of the invariant: ungranted means refused, every time.
R3="$(_toolcall '{"tool":"alpaca","op":"read","args":{"kind":"clock"}}')"; echo "$R3" | head -2
_expect "$R3" '"decision_kind": "deny"' "ungranted alpaca.read denied (fail-closed)"

if [ "$fail" -eq 0 ]; then echo "confine-and-run: ALL ASSERTIONS PASSED"
else echo "confine-and-run: FAILED"; fi
exit "$fail"
