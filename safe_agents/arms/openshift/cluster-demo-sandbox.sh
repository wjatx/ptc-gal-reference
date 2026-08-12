#!/usr/bin/env bash
# cluster-demo-sandbox.sh — DEMONSTRATION 1: the sandbox permits, the broker refuses
# (#250 Phase 5).
#
# THE QUESTION THIS ANSWERS is the one the room actually asks: "how is this better than
# just using OpenShell?" The honest answer, and the drill says it on screen, is that it
# is NOT better. It protects a DIFFERENT PARTY, and the two compose:
#
#   the sandbox protects the CLUSTER from the agent — and has no opinion about a ledger
#   the broker  protects the LEDGER from the agent — and has no opinion about /tmp
#
# Neither substitutes for the other, and a room that leaves believing the broker
# replaces a sandbox has been mis-sold.
#
# THE VENUE [ruling: maintainer, 2026-07-28]. The sandbox here is the POD'S OWN
# ISOLATION — SCC and NetworkPolicy — not an OpenShell box. `arms/rhel_openshell/` is the EC2/AMI
# sandbox and wiring it in would put an AWS dependency inside the cluster arm, which
# this epic deliberately does not carry. Say plainly which sandbox is in the picture;
# the claim is about two layers composing, and it does not need the sandbox to be any
# particular product.
#
# THE SHAPE. Act 1 shows the pod's isolation raising NO objection to anything the agent
# is about to do — it writes a program and runs it, and that program makes the calls.
# Act 2 shows the broker refusing them anyway. Nothing in Act 2 breaks a single sandbox
# rule; a sandbox alone would have permitted every one of these calls, because a
# sandbox has no concept of "ledger entry".
set -euo pipefail

BROKER_URL="${AGENT_BROKER_URL:?AGENT_BROKER_URL must be set by the pod spec}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
GRANTED_READ="${DEMO_GRANTED_READ:-get_entry}"
WORKDIR="${DEMO_WORKDIR:-/tmp/agent-scratch}"

# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

say "0. the sandbox is REAL — this is not a pod with nothing switched on"
# Stated first because the whole demonstration is worthless if the sandbox is absent.
# "The sandbox permits" only means something when the sandbox is actually enforcing.
printf '   uid=%s  CapEff=%s\n' "$(id -u)" "$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
[ "$(id -u)" != "0" ] || die "running as root — restricted-v2 is not in force"
[ "$(awk '/^CapEff:/ {print $2}' /proc/self/status)" = "0000000000000000" ] \
  || die "this pod holds capabilities — the sandbox is weaker than claimed"
np_control "an ordinary TCP socket opens" -- \
  python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()'
np_refuse "open a raw ICMP socket" "Operation not permitted" -- \
  python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)'
np_refuse "reach the internet directly" "timed out" -- \
  python3 -c '
import socket, sys
try: socket.create_connection(("1.1.1.1", 443), timeout=8)
except Exception as exc: print("%s: %s" % (type(exc).__name__, exc)); sys.exit(1)
print("CONNECTED"); sys.exit(0)'
np_summary "the SCC drops every capability and the NetworkPolicy drops external egress"

# ---------------------------------------------------------------------------
say "1. and inside that sandbox, the agent is FREE"
# The point of this act: everything below is ordinary, permitted, unremarkable pod
# activity. No SCC violation, no NetworkPolicy violation, nothing for the platform to
# object to. The agent writes a program and runs it — which is exactly what an agent
# does — and that program is what makes the forbidden calls in act 2.
mkdir -p "$WORKDIR"
cat > "$WORKDIR/attempt.py" <<'PROG'
"""Written by the agent, at runtime, inside its own sandbox. Nothing stops this."""
import json
import sys
import urllib.request

broker = sys.argv[1]


def call(tool, op, args, key):
    req = urllib.request.Request(
        f"{broker}/call", method="POST",
        data=json.dumps({"tool": tool, "op": op, "args": args, "idempotency_key": key}).encode(),
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    print(json.dumps(call(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]), sys.argv[5])))
PROG
np_control "write a program into its own filesystem" -- test -s "$WORKDIR/attempt.py"
np_control "execute that program"                   -- python3 "$WORKDIR/attempt.py" \
  "$BROKER_URL" "$SERVER_ID" "$GRANTED_READ" '{"entry_id": "L-001"}' sandbox-selfwritten-read
np_control "spawn a subprocess"                     -- sh -c 'true'
np_summary "the pod permitted the agent to author and run code that calls the broker"

# ---------------------------------------------------------------------------
say "2. THE DEMONSTRATION — the same sandbox permits, and the broker refuses"
python3 - "$BROKER_URL" "$SERVER_ID" "$GRANTED_READ" "$WORKDIR/attempt.py" <<'PY' || die "demonstration 1 did not hold"
import json
import subprocess
import sys

broker, server_id, granted_read, program = sys.argv[1:5]


def via_agents_own_program(tool, op, args, key):
    """Run the forbidden call through the program the AGENT wrote in act 1.

    Deliberately not an inline request: the point is that this code path is the
    agent's own, authored and executed inside a sandbox that never objected once.
    """
    out = subprocess.run(
        [sys.executable, program, broker, tool, op, json.dumps(args), key],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"the agent's own program failed: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout)


failures = []

# THE POSITIVE CONTROL FIRST. Without it the refusals below are indistinguishable from
# a broker that is simply broken, or a program the agent wrote wrong. A granted read
# through the very same path must work.
r = via_agents_own_program(server_id, granted_read, {"entry_id": "L-001"}, "sandbox-control-read")
print(f"   control: {server_id}.{granted_read} through the agent's own program -> {r.get('decision_kind')}")
if r.get("decision_kind") != "allow" or r.get("result") is None:
    print("   control FAILED: the granted read did not execute, so every refusal below "
          "is uninterpretable", file=sys.stderr)
    sys.exit(1)

# The forbidden attempts. Each one is a perfectly ordinary outbound HTTPS-shaped request
# from a pod that is allowed to make it -- the sandbox's answer is "yes, you may make
# this network call". The broker's answer is a different question entirely: "no, you may
# not perform this action."
ATTEMPTS = [
    (server_id, "delete_entry", {"entry_id": "L-001"},
     f"no manifest entry for {server_id}.delete_entry",
     "destroy a ledger record"),
    ("payments", "transfer", {"amount": 100, "to": "attacker"},
     "no manifest entry for payments.transfer",
     "move money through a connector that was never declared"),
]

for tool, op, args, mechanism, english in ATTEMPTS:
    r = via_agents_own_program(tool, op, args, f"sandbox-forbidden-{tool}-{op}")
    kind, reason = r.get("decision_kind"), (r.get("reason") or "")
    print(f"   attempt: {tool}.{op} — {english}")
    print(f"       sandbox: permitted the call (it is an ordinary socket to an allowed peer)")
    print(f"       broker:  {kind} — {reason[:110]}")
    # The MECHANISM, not merely "not allow" (#312). `deny` populates `reason` (unlike
    # require_approval, #316), so demonstration 1 CAN name which control fired -- and a
    # refusal that named a different one must not read as this one.
    if kind == "allow" or r.get("result") is not None:
        failures.append(f"{tool}.{op} WAS ALLOWED — the broker did not refuse it")
    elif kind != "deny":
        failures.append(f"{tool}.{op} -> {kind!r}, expected deny. An escalation is a different "
                        f"control and must not be reported as this one")
    elif mechanism not in reason:
        failures.append(f"{tool}.{op} denied, but not by the expected control. "
                        f"expected: {mechanism!r}  got: {reason!r}")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "every forbidden action was refused by the broker, and by nothing in the sandbox"

# ---------------------------------------------------------------------------
printf '\n\033[32mDEMONSTRATION 1: PASS\033[0m — the sandbox permitted, the broker refused.\n'
printf '\n\033[1mWhat this is NOT, said plainly because it is the trap:\033[0m\n'
printf '  * It is NOT "the broker is better than a sandbox". It is not better. It protects\n'
printf '    a DIFFERENT PARTY. The sandbox kept the agent off the internet and out of the\n'
printf '    kernel — real work, shown in act 0 — and had no opinion whatsoever about the\n'
printf '    ledger. The broker had no opinion about /tmp. Use both.\n'
printf '  * A sandbox alone would have PERMITTED every refused call above. Nothing in an\n'
printf '    SCC or a NetworkPolicy knows what a ledger entry is, so there is no way to\n'
printf '    express "may read entries, may not delete them" at that layer.\n'
printf '  * The sandbox in this drill is the POD (SCC + NetworkPolicy), not an OpenShell\n'
printf '    box. The composition claim does not depend on which sandbox — but the claim\n'
printf '    must name the one actually in the picture, and this one is the platform.\n'
printf '  * The dangerous op is ABSENT from the ledger server, not merely denied — the\n'
printf '    missileer archetype. So the deny above is the SECOND line of defence, and the\n'
printf '    first is that there is no delete tool to call.\n'
