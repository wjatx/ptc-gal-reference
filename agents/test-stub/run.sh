#!/usr/bin/env bash
# Element 1: single headless entrypoint, idempotent per logical date.
#
# Exit-code contract:
#   0               ran (or nothing-to-do — the run record carries the status)
#   non-zero        failed
#
# Convention: this is run.sh on every arm — adapters invoke it; they do not
# replace it. The adapter supplies secrets and co-places the broker; this file
# stays identical across arms.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Element 3: cheap pre-flight gate — decide early whether there is work.
# SA_PREFLIGHT_ONLY=1 causes the agent to check its schedule/queue and exit
# cleanly, writing a nothing-to-do record, without spending the LLM pass.
if [[ "${SA_PREFLIGHT_ONLY:-}" == "1" ]]; then
    python3 "${SCRIPT_DIR}/agent.py" --preflight
    exit $?
fi

# Main execution.
python3 "${SCRIPT_DIR}/agent.py"
agent_exit=$?

# Element 7: liveness push ping — catches total arm death.
# No-op when SA_LIVENESS_URL is unset; never causes the job to report failure.
if [[ -n "${SA_LIVENESS_URL:-}" ]]; then
    curl -sf "${SA_LIVENESS_URL}" > /dev/null 2>&1 \
        || echo "warn: liveness ping to ${SA_LIVENESS_URL} failed (non-fatal)" >&2
fi

exit "${agent_exit}"
