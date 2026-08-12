#!/usr/bin/env bash
# cluster-ratify.sh — the CHECKER half of the ceremony (#250 Phase 3).
#
# Runs under ServiceAccount `safe-agents-checker`, in a different pod from the
# maker, and is the only leg into which the issuer signing Secret is mounted.
# That mount is the maker!=checker backstop: the maker cannot read the key
# (403) and cannot create a workload that would have it delivered (403), so a
# record it forged could not carry a valid signature.
#
# Which is exactly the guarantee the cloud floor has, and no more:
# infra/lib/identity-stack.ts gives MakerRole zero secretsmanager statements
# ("Deliberately NO */issuer/* — the maker cannot sign a record") while its
# UpdateItem "can technically upsert a GRANT# item" (#203, open on both
# substrates). Prevention for signing, detection for writes.
set -euo pipefail

STORE_DIR="${STORE_DIR:-/var/lib/broker}"
PROJECTED_KEY="${PROJECTED_KEY:-/run/issuer-projected/issuer.pem}"
PRIVATE_KEY="${PRIVATE_KEY:-/run/issuer-private/issuer.pem}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
ADMIT_TOOL="${DRILL_ADMIT_TOOL:-get_entry}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die() { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

say "0. identity — a DIFFERENT credential, in a different pod"
printf '   uid=%s  pod=%s\n' "$(id -u)" "$(python3 -c 'import socket; print(socket.gethostname())')"
WHOAMI=$(python3 -c '
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
') || die "could not derive this pod's ceremony identity"
printf '   SelfSubjectReview says: %s\n' "$WHOAMI"
case "$WHOAMI" in
  system:serviceaccount:*:safe-agents-checker) ;;
  *) die "expected the checker ServiceAccount, got '$WHOAMI'" ;;
esac
ok "identity derived from the cluster, never asserted"

say "0b. the #282 shim — a private copy of the projected issuer key"
# A projected Secret under an fsGroup gets 0440 OR-ed into whatever defaultMode
# was requested, unconditionally, so #226's check can never pass on the
# projection itself. A compatibility shim, NOT a control: in a pod the boundary
# protecting this key is the pod, not the file mode.
printf '   projected: %s\n' "$(stat -L -c 'mode=%a owner=%u:%g' "$PROJECTED_KEY")"
install -m 600 "$PROJECTED_KEY" "$PRIVATE_KEY" || die "could not stage the issuer key"
printf '   private:   %s\n' "$(stat -c 'mode=%a owner=%u:%g' "$PRIVATE_KEY")"
export ISSUER_SIGNING_KEY_FILE="$PRIVATE_KEY"
ok "issuer key staged 0600, owned by uid $(id -u)"

say "1. the grant store this leg may write, and the maker could not"
# `seed` moved to leg 0 (cluster-bootstrap.sh) with the #203 write split: the
# maker mounts this file read-only, and a read-only open cannot create it, so
# the store has to exist before the maker's leg runs. The reasoning that put
# seeding under the signing identity is unchanged — it simply argued for a
# bootstrap step of its own all along, since a proposal cannot precede the store
# it proposes against.
GRANTS_DB="${BROKER_SQLITE_GRANTS_PATH:?BROKER_SQLITE_GRANTS_PATH must be set}"
[ "$GRANTS_DB" != "${BROKER_SQLITE_PATH:?}" ] \
  || die "the grant store is co-located with the working store — the split is not in force"
printf '   grants (rw here): %s\n' "$GRANTS_DB"
python3 - "$GRANTS_DB" <<'PY' || die "this leg cannot write the grant store — it must be able to"
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
c.execute("BEGIN IMMEDIATE"); c.execute("ROLLBACK")
n = c.execute("SELECT count(*) FROM items WHERE pk LIKE 'GRANT#%'").fetchone()[0]
print(f"   writer lock acquired; GRANT# rows present: {n}")
sys.exit(0 if n > 0 else 1)
PY
ok "the checker holds the writer lock the maker was refused"

say "2. the maker's proposal, from the shared volume"
PROPOSAL_ID=$(cat "$STORE_DIR/proposal_id") || die "no proposal id on the volume"
[ -n "$PROPOSAL_ID" ] || die "empty proposal id"
printf '   proposal_id=%s\n' "$PROPOSAL_ID"

say "3. admit-ratify — burn the proposal, sign the record, write the row"
python3 -m safe_agents.broker.mcp.commands admit-ratify \
  --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" --proposal-id "$PROPOSAL_ID"
ok "$SERVER_ID/$ADMIT_TOOL ADMITTED"

say "4. what the signed record says about who ran this"
# The GRANT store, not the working store: TOOLREC# is checker-writable key space
# and moved with the #203 split. Reading the old path here would find no rows and
# report a perfectly good ceremony as broken.
python3 - "$GRANTS_DB" <<'PY' || die "the record does not carry two real identities"
import json
import sqlite3
import sys

conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = conn.execute(
    "SELECT pk, sk, item FROM items WHERE pk LIKE 'TOOLREC#%' ORDER BY sk DESC"
).fetchall()
if not rows:
    print("   no admission record found", file=sys.stderr)
    sys.exit(1)

# The stored-bytes basis (#246): the record is a canonical JSON STRING under
# "data", and those exact bytes are what the DSSE signature covers.
attrs = json.loads(rows[0][2])
record = json.loads(attrs["data"])
proposed, ratified = record.get("proposedBy", ""), record.get("ratifiedBy", "")
attestation = record.get("attestation")
signed = "signature" in attrs

print(f"   proposedBy:  {proposed}")
print(f"   ratifiedBy:  {ratified}")
print(f"   attestation: {attestation!r}")
print(f"   signature:   {'present (issuer DSSE)' if signed else 'ABSENT'}")

failures = []
if not proposed.startswith("system:serviceaccount:"):
    failures.append("proposedBy is not a ServiceAccount identity")
if not ratified.startswith("system:serviceaccount:"):
    failures.append("ratifiedBy is not a ServiceAccount identity")
if proposed == ratified:
    failures.append("the same credential proposed and ratified")
if attestation is not None:
    failures.append(f"a solo attestation survived onto a two-credential ceremony: {attestation!r}")
if not signed:
    failures.append("the admission record is unsigned")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "two distinct ServiceAccounts, signed, and NO solo attestation"

say "5. NEGATIVE PROOF — M7, reached this time"
# The maker leg cannot exercise M7: it dies at the signing gate first, which is
# correct but leaves the identity comparison itself unproven under real
# credentials. THIS identity holds the key, so M8 cannot mask the result — if
# the ceremony lets one credential both propose and ratify, it shows up here.
#
# Uses the OTHER tool deliberately. A proposal that is never ratified leaves a
# TOOLPROP row and admits nothing, so `list_entries` stays unadmitted and the
# serve leg's refusal still means what it says.
SELF_PROPOSAL=$(python3 -m safe_agents.broker.mcp.commands admit-propose \
  --server-id "$SERVER_ID" --tool-name "${DRILL_REFUSE_TOOL:-list_entries}" \
  --from-snapshot "$STORE_DIR/snapshot.json" --ttl-hours 1 2>/dev/null \
  | sed -n 's/.*proposal_id=\([0-9a-f-]*\).*/\1/p')
[ -n "$SELF_PROPOSAL" ] || die "could not create the checker's own proposal"
printf '   the checker proposed %s itself: %s\n' "${DRILL_REFUSE_TOOL:-list_entries}" "$SELF_PROPOSAL"
set +e
M7_OUT=$(python3 -m safe_agents.broker.mcp.commands admit-ratify \
  --server-id "$SERVER_ID" --tool-name "${DRILL_REFUSE_TOOL:-list_entries}" \
  --proposal-id "$SELF_PROPOSAL" 2>&1)
M7_RC=$?
set -e
printf '   %s\n' "$(printf '%s' "$M7_OUT" | head -1 | cut -c1-170)"
[ "$M7_RC" -ne 0 ] || die "one ServiceAccount both proposed and ratified — M7 did not hold"
printf '%s' "$M7_OUT" | grep -q "REFUSED" || die "failed, but not with a ceremony refusal"
printf '%s' "$M7_OUT" | grep -qi "same ceremony identity\|two distinct identities\|self-admission" \
  || die "refused, but not with the M7 identity refusal — check which control fired"
ok "one credential cannot be both halves, even holding the signing key (M7)"

printf 'ratify %s %s\n' \
  "$(python3 -c 'import socket; print(socket.gethostname())')" "$WHOAMI" \
  >> "$STORE_DIR/ceremony-pods"

printf '\n\033[32mCHECKER LEG: PASS\033[0m — ratified under a second credential the maker\n'
printf 'could not have obtained, and the record says so without a solo caveat.\n'
