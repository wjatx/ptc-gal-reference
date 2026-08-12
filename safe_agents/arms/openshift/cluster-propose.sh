#!/usr/bin/env bash
# cluster-propose.sh — the MAKER half of the ceremony (#250 Phase 3).
#
# Runs under ServiceAccount `safe-agents-maker`. Its identity is DERIVED by
# round-trip to the API server (SelfSubjectReview), not read off the token it
# holds — and it never touches the issuer signing key, because it has no way to
# obtain one. This script demonstrates that rather than asserting it.
#
# What Phase 2 could not show: there, one pod ran the whole arc under two local
# roles it flipped between, and the record said so (`attestation: solo-local`).
# Here maker and checker are two credentials in two pods, neither mintable by
# the other, and the record carries no solo attestation at all.
set -euo pipefail

STORE_DIR="${STORE_DIR:-/var/lib/broker}"
MANIFEST="${BROKER_MANIFEST:?BROKER_MANIFEST must be set by the pod spec}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
ADMIT_TOOL="${DRILL_ADMIT_TOOL:-get_entry}"
SA_TOKEN=/var/run/secrets/kubernetes.io/serviceaccount/token

# The shared negative-proof helper (#312). This leg's step 4 is the incident that
# motivated it — a refusal grepped for "REFUSED" and labelled M8 as M7.
# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

say "0. identity — derived by asking the authority"
printf '   uid=%s  pod=%s\n' "$(id -u)" "$(python3 -c 'import socket; print(socket.gethostname())')"
WHOAMI=$(python3 -c '
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
') || die "could not derive this pod's ceremony identity"
printf '   SelfSubjectReview says: %s\n' "$WHOAMI"
case "$WHOAMI" in
  system:serviceaccount:*:safe-agents-maker) ;;
  *) die "expected the maker ServiceAccount, got '$WHOAMI'" ;;
esac
ok "identity derived from the cluster, never asserted"

say "0b. NEGATIVE PROOF — the solo arm is refused where a real identity exists"
# The sibling of the dynamo gate. A pod that can prove who it is must not be
# able to fall back to two roles one process flips between, because nothing in
# the resulting record would reveal that the weaker attribution was a CHOICE.
np_refuse "the solo ceremony arm" "projected ServiceAccount token is present" -- \
  env BROKER_LOCAL_IDENTITY=maker BROKER_CEREMONY_IDENTITY= python3 -c '
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
'
# The control for it: the SAME resolution, without the override, must still work.
# Otherwise "the solo arm is refused" would also be satisfied by a pod whose ceremony
# identity is broken outright — which refuses everything and proves nothing.
np_control "the serviceaccount arm still resolves" -- python3 -c '
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
'
np_summary "solo attestation refused where a real identity exists"

say "1. NEGATIVE PROOF — what this credential cannot do"
# Read carefully, because the precise shape matters and the loose version of
# this claim is wrong. RBAC governs API access; it does NOT govern kubelet
# volume mounts, so "the maker SA cannot read the Secret" would NOT by itself
# stop a maker-authored pod from MOUNTING it. The chain that actually holds is
# both halves together: this credential can neither read the key, nor create
# the workload that would have it delivered.
python3 - "$SA_TOKEN" <<'PY' || die "the maker credential is not as powerless as claimed"
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

token = open(sys.argv[1], encoding="utf-8").read().strip()
ns = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", encoding="utf-8").read().strip()
host = os.environ["KUBERNETES_SERVICE_HOST"]
port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
if ":" in host and not host.startswith("["):
    host = f"[{host}]"
base = f"https://{host}:{port}"
ctx = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def attempt(label, path, method="GET", body=None):
    req = urllib.request.Request(
        base + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            print(f"   {label}: HTTP {resp.status} — ALLOWED")
            return resp.status
    except urllib.error.HTTPError as exc:
        print(f"   {label}: HTTP {exc.code} — {'REFUSED by RBAC' if exc.code == 403 else 'refused'}")
        return exc.code


failures = []
code = attempt("read the issuer signing key", f"/api/v1/namespaces/{ns}/secrets/safe-agents-issuer")
if code != 403:
    failures.append(f"the maker could read (or was not cleanly refused) the issuer Secret: {code}")

# The second half, and the one people forget: if this credential could create a
# workload, it could simply mount the Secret into a pod of its own and read it
# there, with RBAC never consulted about the key at all.
code = attempt(
    "create a pod that would mount it", f"/api/v1/namespaces/{ns}/pods", "POST",
    {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "maker-would-mount"},
     "spec": {"containers": [{"name": "c", "image": "busybox",
              "volumeMounts": [{"name": "k", "mountPath": "/k"}]}],
              "volumes": [{"name": "k", "secret": {"secretName": "safe-agents-issuer"}}]}},
)
if code != 403:
    failures.append(f"the maker could create a workload: {code}")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "the maker can neither read the key nor arrange for it to be delivered"

say "1b. and it has no issuer key mounted"
[ ! -e /run/issuer-projected ] || die "the issuer Secret is mounted into the MAKER pod"
[ -z "${ISSUER_SIGNING_KEY_FILE:-}" ] || die "ISSUER_SIGNING_KEY_FILE is set in the maker pod"
ok "no issuer volume, no key path — this pod cannot sign a record"

say "2. snapshot — pre-admission discovery (spawns the MCP stdio child)"
mkdir -p "$STORE_DIR"
python3 -m safe_agents.broker.mcp.commands snapshot \
  --manifest "$MANIFEST" --server-id "$SERVER_ID" --out "$STORE_DIR/snapshot.json" 2>&1 | tail -1
ok "live tool set captured"

say "3. admit-propose, under the maker ServiceAccount"
PROPOSAL_ID=$(python3 -m safe_agents.broker.mcp.commands admit-propose \
  --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" \
  --from-snapshot "$STORE_DIR/snapshot.json" --ttl-hours 1 \
  | tee /dev/stderr | sed -n 's/.*proposal_id=\([0-9a-f-]*\).*/\1/p')
[ -n "$PROPOSAL_ID" ] || die "no proposal id parsed"
printf '%s' "$PROPOSAL_ID" > "$STORE_DIR/proposal_id"
ok "proposal $PROPOSAL_ID"

say "4. NEGATIVE PROOF — the maker's ratify dies at the SIGNING gate"
# Be precise about which control fires, because the first version of this step
# claimed the M7 self-admission refusal and got the M8 signing refusal instead —
# it grepped only for "REFUSED" and passed for the wrong reason. A negative
# proof mislabelled with the wrong mechanism is worse than none: it gets cited
# later as evidence for a control that was never exercised.
#
# What actually happens here, and it is the stronger result: under this topology
# the maker never reaches the identity comparison at all. It cannot sign, so the
# ceremony refuses before it ever asks whether proposer == ratifier. That is the
# mount-topology backstop firing live — the exact cluster analogue of MakerRole
# holding zero */issuer/* permissions on the cloud floor.
#
# M7 itself is exercised where it CAN be reached: in cluster-ratify.sh, by an
# identity that does hold the signing key (so M8 cannot mask it).
# The mechanism string is the SIGNING gate's, not the word "REFUSED" — that is the
# distinction this whole helper exists to keep. Matching "REFUSED" alone is what
# labelled M8 as M7 in the first place.
np_refuse "the maker's own ratify" "issuer signing key not configured" -- \
  python3 -m safe_agents.broker.mcp.commands admit-ratify \
    --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" --proposal-id "$PROPOSAL_ID"
np_summary "refused at M8 before reaching M7: no key, therefore no valid ratification"

say "5. NEGATIVE PROOF — the maker cannot WRITE the grant store (#203)"
# The half Phase 3 was missing. Everything above concerns SIGNING: the maker
# cannot produce a valid ratification. It could still write the row. On a shared
# PVC nothing stopped it, because a filesystem has no per-identity access
# control — which is why this is mount topology rather than a check in our code.
#
# Attempted, not asserted from the manifest. A split that is only declared in
# YAML is indistinguishable from a typo'd variable that silently co-located the
# two key spaces, and the control would vanish while every log still looked
# green. So the leg tries the forbidden write and demands the kernel refuse it.
GRANTS_DB="${BROKER_SQLITE_GRANTS_PATH:?BROKER_SQLITE_GRANTS_PATH must be set}"
[ "$GRANTS_DB" != "${BROKER_SQLITE_PATH:?}" ] \
  || die "the grant store is co-located with the working store — the split is NOT in force"
printf '   work   (expected rw): %s\n' "$BROKER_SQLITE_PATH"
printf '   grants (expected ro): %s\n' "$GRANTS_DB"

# (a) the raw filesystem, so the refusal is visibly the kernel's and not sqlite's.
# EROFS by name: a missing directory, a bad SCC or a full disk all fail `touch` too,
# and only one of them is the control this step claims.
FORGED="$(dirname "$GRANTS_DB")/forged"
np_control "this pod CAN write to the working mount" -- touch "$STORE_DIR/propose-canary"
rm -f "$STORE_DIR/propose-canary"
np_refuse "touch a file in the grant dir" "Read-only file system" -- touch "$FORGED"
np_summary "the grant volume is a read-only mount: refused by the kernel with EROFS"

# (b) the write that actually matters — a forged GRANT# row through sqlite
python3 - "$GRANTS_DB" <<'PY' || die "the maker was able to write a GRANT# row"
import sqlite3, sys
db = sys.argv[1]
try:
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("BEGIN IMMEDIATE")
    c.execute(
        "INSERT INTO items (pk, sk, item) VALUES "
        "('GRANT#forged#by#the#maker', 'CLASS#notify.send', '{}')"
    )
    c.execute("COMMIT")
except sqlite3.OperationalError as exc:
    print(f"   sqlite INSERT of a GRANT# row -> refused: {exc}")
    sys.exit(0)
print("   WROTE A GRANT ROW — the write split is not in force")
sys.exit(1)
PY
ok "a forged GRANT# row is refused by the platform, not by our ConditionExpression"

# (c) and the reads the maker legitimately needs still work. Read-denied is not
# a stricter write-denied: the maker reads grants and counters to assemble a
# proposal, so a mount that broke those would break the ceremony rather than
# harden it.
python3 - "$GRANTS_DB" <<'PY' || die "the maker cannot READ the grant store — the mount is too strict"
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
n = c.execute("SELECT count(*) FROM items WHERE pk LIKE 'GRANT#%'").fetchone()[0]
print(f"   GRANT# rows readable by the maker: {n}")
sys.exit(0 if n > 0 else 1)
PY
ok "evidence reads still succeed — write-denied, not read-denied"

# The breadcrumb the durability leg reads. Under the local arm the pod name was
# embedded in the identity string for free (`user@<pod>#role`); a ServiceAccount
# username carries no pod, so the third leg would have nothing to compare and
# its "a different pod wrote this" claim would quietly become vacuous.
printf 'propose %s %s\n' \
  "$(python3 -c 'import socket; print(socket.gethostname())')" "$WHOAMI" \
  >> "$STORE_DIR/ceremony-pods"

printf '\n\033[32mMAKER LEG: PASS\033[0m — proposed under a derived ServiceAccount identity,\n'
printf 'holding no signing key and unable to obtain one.\n'
