#!/usr/bin/env bash
# Element 6: notification seam.
#
# The agent calls this script and names the action ("notify"); it does not
# name the channel. Swap the channel implementation here — not in the agent.
# Current channels: stdout (for local/test), extensible to Telegram, email, etc.
set -euo pipefail

MESSAGE="${*:-}"

if [[ -z "${SA_NOTIFY_CHANNEL:-}" ]]; then
    echo "notify: SA_NOTIFY_CHANNEL unset — skipping (no-op)" >&2
    exit 0
fi

case "${SA_NOTIFY_CHANNEL}" in
    stdout)
        echo "notify [stdout]: ${MESSAGE}"
        ;;
    *)
        echo "notify: unknown channel '${SA_NOTIFY_CHANNEL}' — skipping" >&2
        ;;
esac

exit 0
