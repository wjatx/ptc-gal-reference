#!/usr/bin/env bash
# cluster-agent.sh — the Phase 4 predicate, attempted from INSIDE the agent pod (#250).
#
# The whole phase is this script's log. Phases 2 and 3 could be argued from a
# manifest if you were willing to take a `readOnly:` field on trust; this one cannot
# be, because its claim is about what a DIFFERENT workload can and cannot do. So
# every denial below is attempted for real, and every attempt names the specific
# mechanism that refused it.
#
# THE PREDICATE, all three or the session is not done:
#   * direct external egress is denied
#   * reading the broker's Secret is denied
#   * a brokered call through the broker still executes
#
# The third is not decoration. A pod that is broken in any unrelated way -- wrong
# image, no network at all, a crashed sidecar -- produces the first two refusals
# perfectly and proves nothing whatsoever. This is the egress twin of #310's write
# canary, and it is the check that is skipped every time it is not written down.
#
# WHAT THIS SCRIPT IS NOT ALLOWED TO DO, and the reason is not stylistic: it must not
# import anything from `safe_agents`. The agent is a synthetic client of the broker's
# HTTP surface, and a proof that reached through the SDK would be proving something
# about our own code rather than about the platform boundary. Everything below is
# stdlib -- urllib, socket, ssl -- against `/call` and against the API server.
#
# (The image DOES contain the SDK, because it is the same image every other leg runs
# and building a second one would be a second build path. That is not a hole and the
# summary says so: the agent holds no credential, no connector secret and no mount.
# Possessing the code buys it nothing, which is the platform's actual thesis --
# a fully compromised agent can still only ask.)
set -euo pipefail

BROKER_URL="${AGENT_BROKER_URL:?AGENT_BROKER_URL must be set by the pod spec}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
ADMIT_TOOL="${DRILL_ADMIT_TOOL:-get_entry}"
REFUSE_TOOL="${DRILL_REFUSE_TOOL:-list_entries}"
NS="${POD_NAMESPACE:-safe-agents}"
SA_TOKEN=/var/run/secrets/kubernetes.io/serviceaccount/token
SA_CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
# The Secret the broker mounts and this pod must not be able to obtain. Both names,
# because the issuer key and the connector credentials are different blast radii and
# a proof about one is not a proof about the other.
TARGET_SECRETS="safe-agents-connector-secrets safe-agents-issuer"

# The shared negative-proof helper (#312). Steps 2-4 below keep their refusals inside
# Python, and that is a deliberate limit rather than an oversight: the egress and RBAC
# checks need to distinguish a timeout from a refusal from a gaierror, and an HTTP 403
# from a 401 from a 404, which is richer than a fixed-string match on an exit code.
# They already assert those mechanisms. This leg is the named driver for the Python
# twin when a Python site is found asserting only "it raised".
# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

say "0. what this pod is"
THIS_POD=$(python3 -c 'import socket; print(socket.gethostname().split(".")[0])')
printf '   pod=%s  uid=%s  broker=%s\n' "$THIS_POD" "$(id -u)" "$BROKER_URL"
[ "$(id -u)" != "0" ] || die "running as root — the SCC did not constrain this pod"

# Asserted from the pod's own filesystem, not from the manifest. A missing mount is
# a real, kernel-level fact here: these paths do not exist because no volume was
# declared, and the pod cannot declare one for itself (step 3 proves that too).
for p in /run/connector-secrets /run/issuer-projected /var/lib/broker /var/lib/broker-grants /var/lib/broker-audit; do
  [ ! -e "$p" ] || die "$p EXISTS in the agent pod — the mount topology is not what Phase 4 claims"
done
ok "no connector secrets, no issuer key, no store, no audit tape in this pod"

# ---------------------------------------------------------------------------
say "1. the SCC constrains what this pod may do at all"
# NET_RAW rather than a low port, deliberately. A bind below 1024 looks like the
# obvious capability test and is not a reliable one: CRI-O can set
# net.ipv4.ip_unprivileged_port_start=0, and where it does the bind SUCCEEDS with the
# capability still dropped -- a green-looking proof of nothing. NET_RAW has no such
# sysctl escape hatch. [verified 2026-07-28 on this cluster: CapEff is all-zero and
# SOCK_RAW is EPERM.]
CAPEFF=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
printf '   CapEff=%s\n' "$CAPEFF"
[ "$CAPEFF" = "0000000000000000" ] || die "this pod holds capabilities ($CAPEFF); restricted-v2 drops ALL"

# "Operation not permitted" is EPERM's strerror — the kernel refusing a syscall for a
# capability the process does not hold. Named rather than left implicit, because a
# pod with no network at all also fails to open a raw socket, and so does a Python
# that cannot import socket. The control is what separates those from this.
np_control "an ordinary TCP socket opens" -- \
  python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()'
np_refuse "open a raw ICMP socket" "Operation not permitted" -- \
  python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)'
np_summary "zero capabilities; a raw socket is refused by the kernel with EPERM, an ordinary one is not"

# ---------------------------------------------------------------------------
say "2. direct external egress is DENIED"
# Two attempts and one control, and the control is what makes the attempts mean
# anything. DNS is deliberately ALLOWED by 60-networkpolicy.yaml so that an external
# name RESOLVES here: without that, a failed connection could be an unresolvable name
# and the drill could not tell the two apart. Resolution succeeding and the
# connection to the resolved address then being dropped is what pins the denial on
# the policy.
python3 - <<'PY' || die "external egress was not denied with the expected mechanism"
import socket
import sys
import time

TIMEOUT = 8


def attempt(label, host, port):
    """Returns (verdict, detail). A DROP shows as a timeout; a REJECT would show as
    ConnectionRefused; a DNS failure as gaierror. Collapsing those into 'it failed'
    is the M7/M8 mislabelling #312 exists to prevent."""
    start = time.time()
    try:
        conn = socket.create_connection((host, port), timeout=TIMEOUT)
        conn.close()
        return "CONNECTED", f"{time.time() - start:.1f}s"
    except TimeoutError as exc:
        return "TIMEOUT", f"{type(exc).__name__}: {exc} after {time.time() - start:.1f}s"
    except OSError as exc:
        return type(exc).__name__.upper(), f"{exc} after {time.time() - start:.1f}s"


failures = []

# The positive control FIRST, so a DNS outage cannot masquerade as a denial below.
try:
    resolved = socket.gethostbyname("api.github.com")
    print(f"   control: api.github.com RESOLVES to {resolved} — DNS is working")
except OSError as exc:
    print(f"   control FAILED: cannot resolve api.github.com ({exc}); a connection "
          f"failure below would be unattributable", file=sys.stderr)
    sys.exit(1)

# (a) the address DNS just handed us. Resolution worked, so a failure here is the
#     network policy and cannot be anything else.
verdict, detail = attempt("resolved", resolved, 443)
print(f"   {resolved}:443 (api.github.com) -> {verdict}  {detail}")
if verdict == "CONNECTED":
    failures.append("EGRESS LEAK: the agent pod reached api.github.com directly")
elif verdict != "TIMEOUT":
    failures.append(f"refused as {verdict}, expected TIMEOUT — OVN DROPS, it does not reject; "
                    f"something other than the NetworkPolicy answered")

# (b) a literal IP, no DNS in the path at all. Belt and braces: it removes even the
#     theoretical possibility that resolution poisoned the result.
verdict, detail = attempt("literal", "1.1.1.1", 443)
print(f"   1.1.1.1:443 (no DNS in the path) -> {verdict}  {detail}")
if verdict == "CONNECTED":
    failures.append("EGRESS LEAK: the agent pod reached 1.1.1.1 directly")
elif verdict != "TIMEOUT":
    failures.append(f"refused as {verdict}, expected TIMEOUT")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "external names resolve, and every connection to them is dropped by the policy"

# ---------------------------------------------------------------------------
say "3. reading the broker's Secret is DENIED"
# The API server is deliberately REACHABLE from this pod (60-networkpolicy.yaml
# explains why at length). The short version: if the firewall dropped it too, the
# refusal below would be a timeout, and a timeout is what a broken mount, a wrong
# namespace and a typo'd hostname all look like. Given MORE reach than production
# would give it, the agent is refused anyway -- by RBAC, with a 403 that names it.
[ -r "$SA_TOKEN" ] || die "no ServiceAccount token projected — cannot even attempt the read"
python3 - "$NS" "$SA_TOKEN" "$SA_CA" $TARGET_SECRETS <<'PY' || die "the Secret read was not refused with the expected mechanism"
import json
import ssl
import sys
import urllib.error
import urllib.request

namespace, token_path, ca_path, *secrets = sys.argv[1:]
token = open(token_path, encoding="utf-8").read().strip()
ctx = ssl.create_default_context(cafile=ca_path)
API = "https://kubernetes.default.svc"


def call(method, path, body=None):
    req = urllib.request.Request(
        f"{API}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {}


failures = []

# THE POSITIVE CONTROL, and it is the one that makes every 403 below mean something.
# SelfSubjectReview is a call any authenticated principal may make. A 201 proves the
# token is valid, the CA is right, and the API server is reachable -- so the refusals
# that follow are AUTHORIZATION and cannot be a broken token (401), an unreachable
# API, or a wrong namespace. Without this, a 403 and a misconfigured client are
# indistinguishable, and only one of them is a control.
status, body = call("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                    {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
whoami = (body.get("status", {}).get("userInfo", {}) or {}).get("username", "<unknown>")
print(f"   control: SelfSubjectReview -> HTTP {status}, the API server says I am {whoami}")
if status not in (200, 201):
    print("   control FAILED: this pod is not authenticating, so a 403 below would "
          "prove nothing about RBAC", file=sys.stderr)
    sys.exit(1)
if "safe-agents-agent" not in whoami:
    failures.append(f"this pod is running as {whoami}, not the agent ServiceAccount")

# (a) ask for the Secret directly.
for name in secrets:
    status, body = call("GET", f"/api/v1/namespaces/{namespace}/secrets/{name}")
    message = body.get("message", "")
    print(f"   GET secret/{name} -> HTTP {status}")
    print(f"       {message[:160]}")
    if status == 200:
        failures.append(f"READ THE SECRET {name} — the agent obtained credential material")
        continue
    # Mechanism, not merely failure. 403 and not 401 (401 would mean the token never
    # arrived, which is a broken client, not a control); and the message must name
    # THIS ServiceAccount, so a 403 aimed at some other principal cannot be cited
    # here. A 404 is not admissible either -- the Secret exists, and "refused"
    # and "absent" are different claims.
    if status != 403:
        failures.append(f"{name}: HTTP {status}, expected 403 (RBAC). 401=token never arrived, "
                        f"404=not the Secret we think we are testing")
    elif "safe-agents-agent" not in message:
        failures.append(f"{name}: 403 whose message does not name the agent SA — "
                        f"cannot attribute the refusal to this principal")

# (b) the other half, and the one that is easy to forget. RBAC governs API access,
#     not kubelet volume mounts: "the agent cannot READ the Secret" would not stop a
#     pod the agent AUTHORED from having it mounted. Both doors, or neither claim.
pod = {"apiVersion": "v1", "kind": "Pod",
       "metadata": {"name": "agent-secret-thief", "namespace": namespace},
       "spec": {"restartPolicy": "Never", "containers": [{
           "name": "thief", "image": "registry.access.redhat.com/ubi9/ubi-minimal",
           "command": ["cat", "/stolen/issuer.pem"],
           "volumeMounts": [{"name": "stolen", "mountPath": "/stolen"}]}],
           "volumes": [{"name": "stolen", "secret": {"secretName": "safe-agents-issuer"}}]}}
status, body = call("POST", f"/api/v1/namespaces/{namespace}/pods", pod)
message = body.get("message", "")
print(f"   POST a pod that MOUNTS secret/safe-agents-issuer -> HTTP {status}")
print(f"       {message[:160]}")
if status in (200, 201):
    failures.append("CREATED a pod that mounts the issuer key — the agent can have "
                    "credential material delivered to a workload it authored")
elif status != 403:
    failures.append(f"pod create: HTTP {status}, expected 403")
elif "safe-agents-agent" not in message:
    failures.append("403 whose message does not name the agent SA")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "the API server answers this pod, and refuses it the Secret AND the pod that would mount it"

# ---------------------------------------------------------------------------
say "4. and a brokered call STILL EXECUTES — the positive control for all of the above"
# Without this the section above is worthless. Two refusals and a dead pod look
# identical, and the failure mode of a Phase 4 that shipped without this check is a
# posture claim resting on a broker that was never running.
#
# Raw HTTP, no SDK: this is what an agent on the other side of the boundary actually
# has. Note what it does NOT send and could not: no credential, no connector handle,
# no turn context. The broker mints the turn itself (sa#136), so the agent cannot
# launder taint by declaring a fresh one.
python3 - "$BROKER_URL" "$SERVER_ID" "$ADMIT_TOOL" "$REFUSE_TOOL" <<'PY' || die "the brokered call did not execute"
import json
import sys
import urllib.error
import urllib.request

broker, server_id, admit_tool, refuse_tool = sys.argv[1:5]


def call(tool, op, args, key):
    req = urllib.request.Request(
        f"{broker}/call", method="POST",
        data=json.dumps({"tool": tool, "op": op, "args": args, "idempotency_key": key}).encode(),
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


failures = []
try:
    status, resp = call(server_id, admit_tool, {"entry_id": "L-001"}, "cluster-agent-admitted")
# HTTPError BEFORE URLError, and the order is the whole point: HTTPError is a
# SUBCLASS of URLError, so catching the parent first reports "could not reach the
# broker" for a broker that answered with a 500. That mislabelling happened here on
# the first run of this leg — a negative proof naming the wrong mechanism, which is
# exactly what #312 exists to stop, arriving in the script written to demonstrate it.
except urllib.error.HTTPError as exc:
    print(f"   the broker ANSWERED and failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
    print("   the network path is fine — this is a broker-side error, not a boundary "
          "problem. Read the broker pod's log, not this policy.", file=sys.stderr)
    sys.exit(1)
except (urllib.error.URLError, OSError) as exc:
    print(f"   the agent pod could not reach the broker at all: {type(exc).__name__}: {exc}",
          file=sys.stderr)
    print("   the two denials above are therefore UNINTERPRETABLE — a pod that cannot "
          "reach anything refuses everything.", file=sys.stderr)
    sys.exit(1)

print(f"   POST /call {server_id}.{admit_tool} -> HTTP {status}, decision={resp.get('decision_kind')}")
if resp.get("decision_kind") != "allow" or resp.get("result") is None:
    failures.append(f"{admit_tool} did not execute: {resp.get('decision_kind')} {resp.get('reason')}")
else:
    print(f"   result: {str(resp['result'])[:120]}")

# The negative twin, over the same wire. Crossing the boundary must not soften the
# broker's own decision: an unadmitted op stays unadmitted whether it is asked for
# in-process or from another pod. This is two-key admission, unchanged by topology.
status, resp = call(server_id, refuse_tool, {"limit": 5}, "cluster-agent-refused")
print(f"   POST /call {server_id}.{refuse_tool} -> HTTP {status}, decision={resp.get('decision_kind')} (never admitted)")
if resp.get("result") is not None:
    failures.append(f"{refuse_tool} RETURNED A RESULT over HTTP — two-key admission is not holding")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "the agent's only reachable endpoint served it, and still refused the unadmitted op"

# ---------------------------------------------------------------------------
printf '\n\033[32mPHASE 4 PREDICATE: PASS\033[0m — from inside this pod: external egress denied,\n'
printf 'the broker Secret denied, and a brokered call executed anyway.\n'
printf '\n\033[1mWhat this does NOT claim, stated here rather than left to be found:\033[0m\n'
printf '  * NetworkPolicy is a platform boundary we ORCHESTRATE, not a sandbox we\n'
printf '    implement. OVN and the kernel enforce it; no safe_agents code is in the path.\n'
printf '    Nothing here constrains what the agent does INSIDE this pod.\n'
printf '  * The API server is deliberately reachable from here, so that the refusal above\n'
printf '    is attributable to RBAC rather than to a dropped packet. A production envelope\n'
printf '    should deny both; this drill trades reach for attributability on purpose.\n'
printf '  * This image contains the safe_agents SDK, because it is the same image every\n'
printf '    other leg runs. That buys the agent nothing — it holds no credential, no\n'
printf '    connector secret and no mount, which is the point: a fully compromised agent\n'
printf '    can still only ask.\n'
