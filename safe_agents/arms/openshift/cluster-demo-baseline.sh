#!/usr/bin/env bash
# cluster-demo-baseline.sh — THE UNBROKERED BASELINE (#154, the concrete half of #304).
#
# Every other leg in this arm shows the platform REFUSING something. None of them
# shows that anything was ever at risk. That gap is what #304 names: "every
# security proof is a drill we designed to pass". A drill in which the harm never
# occurs demonstrates a system saying no; it does not demonstrate that the no
# mattered.
#
# So this leg is the control. The same call, from the same pod, against the same
# server — with the broker simply not in the path.
#
#   Act 1  the agent spawns the ledger server ITSELF and calls `list_entries`.
#          It works. Real entry ids come back.
#   Act 2  the identical call through the broker is REFUSED, while a different
#          call through the broker still executes.
#
# ORDERING IS LOAD-BEARING, and this leg must run BEFORE the drill's step 12.
# Step 12 admits `list_entries` through a second ceremony so demonstration 2 has
# an untrusted read to be tainted by. After that point the broker ALLOWS it and
# Act 2 below would be false. `cluster-arc-run.sh` runs this at 10b, immediately
# after leg five, where it is the control for that leg's refusal.
#
# WHAT THIS LEG IS NOT ALLOWED TO DO, same rule as `cluster-agent.sh`: it must not
# import anything from `safe_agents`. Act 1 uses the third-party `mcp` SDK to speak
# stdio to the example server, which is exactly what an unbrokered agent would do;
# Act 2 is raw HTTP against `/call`. Nothing here reaches through our own code, or
# the control would be a statement about our SDK rather than about the boundary.
set -euo pipefail

BROKER_URL="${AGENT_BROKER_URL:?AGENT_BROKER_URL must be set by the pod spec}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
UNADMITTED="${DRILL_REFUSE_TOOL:-list_entries}"
ADMITTED="${DRILL_ADMIT_TOOL:-get_entry}"

# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

say "0. the same contained pod every other agent leg runs in"
printf '   pod=%s  uid=%s  CapEff=%s\n' \
  "$(hostname | cut -d. -f1)" "$(id -u)" "$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
[ "$(id -u)" != "0" ] || die "running as root — this is not the constrained pod"
for p in /run/connector-secrets /run/issuer-projected /var/lib/broker; do
  [ ! -e "$p" ] || die "$p EXISTS here — this is not the agent's mount topology"
done
ok "non-root, no credential mount — the control runs under the same constraints as the proof"

# ---------------------------------------------------------------------------
say "1. THE HARM — no broker in the path, and the call simply works"
# The agent spawns the ledger server as its own stdio child, the same way the
# broker does (manifest mcp_servers.ledger: python3 -m examples.restricted_mcp_server.server).
# It needs no credential and asks no permission, because there is nothing to ask.
python3 - "$UNADMITTED" <<'PY' || die "the unbrokered call did NOT succeed — the control is broken, and every refusal in this drill is therefore uninterpretable"
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

unadmitted = sys.argv[1]


async def main() -> int:
    params = StdioServerParameters(
        command="python3", args=["-m", "examples.restricted_mcp_server.server"]
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # The positive control for Act 1 itself: the server must really be
            # serving, and must really advertise the tool. Without this, a server
            # that failed to start would produce an exception below and the leg
            # would report "the harm did not occur" — the flattering direction.
            advertised = [t.name for t in (await session.list_tools()).tools]
            print(f"   the server advertises: {advertised}")
            if unadmitted not in advertised:
                print(f"   control FAILED: {unadmitted!r} is not advertised, so calling it "
                      f"proves nothing", file=sys.stderr)
                return 1

            result = await session.call_tool(unadmitted, {"limit": 5})
            if getattr(result, "isError", False):
                print(f"   the unbrokered call ERRORED: {result.content}", file=sys.stderr)
                return 1
            payload = getattr(result, "structuredContent", None) or result.content
            print(f"   CALLED {unadmitted} directly -> {str(payload)[:160]}")
            print("   no credential was needed, no permission was asked, nothing objected.")
    return 0


sys.exit(asyncio.run(main()))
PY
ok "the forbidden call SUCCEEDED with no broker in the path — this is the harm, and it is real"

# ---------------------------------------------------------------------------
say "2. THE SAME CALL, through the broker"
# Two calls, and the second is the positive control. A broker that had crashed
# would "refuse" the first one just as convincingly, which is the failure mode
# #312 exists to stop: a negative proof that cannot name what refused it.
python3 - "$BROKER_URL" "$SERVER_ID" "$UNADMITTED" "$ADMITTED" <<'PY' || die "the brokered half did not behave as the baseline requires"
import json
import sys
import urllib.error
import urllib.request

broker, server_id, unadmitted, admitted = sys.argv[1:5]


def call(op, args, key):
    req = urllib.request.Request(
        f"{broker}/call", method="POST",
        data=json.dumps({"tool": server_id, "op": op, "args": args,
                         "idempotency_key": key}).encode(),
        headers={"content-type": "application/json"})
    # HTTPError before URLError: HTTPError is a SUBCLASS of URLError, and catching
    # the parent first reports "could not reach the broker" for a broker that
    # answered with a 500. That mislabelling already happened once in this arm.
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"   the broker ANSWERED and failed: HTTP {exc.code}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as exc:
        print(f"   could not reach the broker at all: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        sys.exit(1)


failures = []

status, resp = call(unadmitted, {"limit": 5}, "baseline-unadmitted")
print(f"   POST /call {server_id}.{unadmitted} -> HTTP {status}, "
      f"decision={resp.get('decision_kind')}")
if resp.get("result") is not None:
    failures.append(f"{unadmitted} RETURNED A RESULT through the broker — it is admitted "
                    f"at this point in the drill, so this leg is running in the wrong "
                    f"ORDER (it must precede the second-admission ceremony), not failing")

# THE POSITIVE CONTROL. Without it, a dead broker and an enforcing broker are
# indistinguishable, and the refusal above would prove nothing.
status, resp = call(admitted, {"entry_id": "L-001"}, "baseline-admitted")
print(f"   control: POST /call {server_id}.{admitted} -> HTTP {status}, "
      f"decision={resp.get('decision_kind')}")
if resp.get("decision_kind") != "allow" or resp.get("result") is None:
    failures.append(f"the control call {admitted} did not execute "
                    f"({resp.get('decision_kind')}) — the broker is not healthy, so the "
                    f"refusal above is uninterpretable")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "the same op is refused through the broker, while a different op executes — it is ADMISSION that refuses, not a dead broker"

# ---------------------------------------------------------------------------
printf '\n\033[32mUNBROKERED BASELINE: PASS\033[0m — the forbidden call succeeds without the\n'
printf 'broker and is refused through it, from one pod, in one run.\n'
printf '\n\033[1mWhat this does NOT show, stated here rather than left to be found:\033[0m\n'
printf '  * A CREDENTIAL being bypassed. The ledger server needs none, so this leg is\n'
printf '    about the ADMISSION half only. That the agent pod holds no connector secret\n'
printf '    and is refused it by RBAC is leg five, and the two claims compose rather\n'
printf '    than substitute.\n'
printf '  * A COMPROMISED server. `examples/restricted_mcp_server/` is the missileer\n'
printf '    archetype and has no dangerous op at all. `list_entries` is an ordinary,\n'
printf '    legitimate tool — which is the point: what makes it uncallable through the\n'
printf '    broker is that nobody ratified it, not that it is missing.\n'
printf '  * REAL harm. The blast radius is a fictional ledger, deliberately. What is\n'
printf '    real is the mechanism: two-key admission is the only thing standing between\n'
printf '    the agent and a tool the server is genuinely serving.\n'
