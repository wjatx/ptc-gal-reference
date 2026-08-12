#!/usr/bin/env bash
# smoke-egress.sh — prove the netns egress confinement, don't trust it (safe-agents sa#35).
#
# Run on the box (e.g. over SSM). Executes four assertions FROM INSIDE the agent netns,
# converged onto the TWO-BOX broker model (Option A): the netns forwards to the external
# broker SERVICE (broker.safe-agents.local), so the assertions target the broker DNS name
# rather than a co-located veth-IP proxy:
#
#   1. a connector host is UNREACHABLE          (no direct path to connectors)
#   2. the broker SERVICE is REACHABLE          (the one permitted peer, via the agent SG)
#   3. the model endpoint is UNREACHABLE direct (no direct model route)
#   4. the model endpoint IS reachable via the broker proxy (HTTPS_PROXY → broker service)
#
# A confined box passes all four. Any other outcome = confinement has failed and the smoke
# must fail loudly (a connector reachable directly is a SAFETY failure).
#
# Runs as root (needs `ip netns exec`). Network params mirror agent-netns-setup.sh + agent.env.
set -uo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# Load the env contract so SA_BROKER_DNS + ports are available for an on-demand SSM run.
if [ -f /etc/safe-agents/agent.env ]; then
    # shellcheck disable=SC1091
    . /etc/safe-agents/agent.env
fi

NS_NAME="${SA_NETNS_NAME:-agent-ns}"
BROKER="${SA_BROKER_DNS:?SA_BROKER_DNS must be set (broker service DNS)}"
PROXY_PORT="${SA_MODEL_PROXY_PORT:-8443}"
CONNECTOR_HOST="${SA_SMOKE_CONNECTOR_HOST:-api.telegram.org}"  # a known connector; must be blocked
MODEL_HOST="${SA_SMOKE_MODEL_HOST:-api.anthropic.com}"
TIMEOUT=5

in_ns() { ip netns exec "$NS_NAME" "$@"; }
fail=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fail=1; }

# 1. Connector host must be unreachable (network error / non-zero exit).
if in_ns curl -sS -m "$TIMEOUT" "https://${CONNECTOR_HOST}" >/dev/null 2>&1; then
    fail "connector ${CONNECTOR_HOST} is REACHABLE from the agent netns (egress not confined)"
else
    pass "connector ${CONNECTOR_HOST} unreachable from the agent netns"
fi

# 2. The broker SERVICE (its proxy port) must be reachable — the one permitted peer.
if in_ns timeout "$TIMEOUT" bash -c "echo > /dev/tcp/${BROKER}/${PROXY_PORT}" 2>/dev/null; then
    pass "broker service ${BROKER}:${PROXY_PORT} reachable from the agent netns"
else
    fail "broker service ${BROKER}:${PROXY_PORT} UNREACHABLE from the agent netns (broker route broken)"
fi

# 3. The model endpoint must be unreachable WITHOUT the proxy (no direct model route).
if in_ns env -u HTTPS_PROXY -u HTTP_PROXY curl -sS -m "$TIMEOUT" "https://${MODEL_HOST}" >/dev/null 2>&1; then
    fail "model ${MODEL_HOST} is reachable DIRECTLY from the agent netns (should only be via the proxy)"
else
    pass "model ${MODEL_HOST} unreachable directly (no bypass route)"
fi

# 4. The model endpoint must be reachable VIA the broker proxy (the broker service).
if in_ns env HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}" \
        curl -sS -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "https://${MODEL_HOST}/" 2>/dev/null \
        | grep -qE '^[0-9]{3}$'; then
    pass "model ${MODEL_HOST} reachable via the broker proxy"
else
    fail "model ${MODEL_HOST} NOT reachable via the broker proxy (proxy down or allowlist wrong)"
fi

if [ "$fail" -ne 0 ]; then
    echo "smoke-egress: CONFINEMENT FAILED"
    exit 1
fi
echo "smoke-egress: all egress-confinement assertions passed"
