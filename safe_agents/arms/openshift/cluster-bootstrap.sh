#!/usr/bin/env bash
# cluster-bootstrap.sh — leg 0: create the grant store, under the signing identity.
#
# This leg exists because of the #203 write split. Once the checker-writable key
# space (GRANT#/RECORD#/TOOLDEF#/TOOLREC#) lives in its own database file that
# the maker mounts READ-ONLY, something has to create that file before the maker
# opens it — and a read-only open deliberately cannot. The maker's leg would
# otherwise refuse on a fresh volume, which is correct behaviour arriving at the
# wrong moment.
#
# Splitting it out is also the more honest lifecycle, not merely a workaround.
# `seed` MINTS floor grants; it was already deliberately placed in the checker's
# leg rather than the maker's, with the reasoning that "an authority-minting act
# should be attributable to the identity that can sign for it". That reasoning
# always argued for a bootstrap step of its own — a proposal cannot precede the
# store it proposes against. So the arc now reads:
#
#     bootstrap (checker)  seed the grant store, sign the bootstrap records
#     propose   (maker)    read that store, write a proposal — cannot write grants
#     ratify    (checker)  burn the proposal, sign the record, write the row
#     serve     (broker)   read the result, holding neither ceremony credential
#
# Runs under `safe-agents-checker` with the grant volume mounted READ-WRITE. It
# is the only leg besides ratify that mounts the issuer key.
set -euo pipefail

STORE_DIR="${STORE_DIR:-/var/lib/broker}"
PROJECTED_KEY="${PROJECTED_KEY:-/run/issuer-projected/issuer.pem}"
PRIVATE_KEY="${PRIVATE_KEY:-/run/issuer-private/issuer.pem}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die() { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

say "0. identity — the checker credential, before any proposal exists"
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
export ISSUER_SIGNING_KEY_FILE="$PRIVATE_KEY"
ok "issuer key staged 0600, owned by uid $(id -u)"

say "1. the two key spaces are two files, and this leg may write both"
GRANTS_DB="${BROKER_SQLITE_GRANTS_PATH:?BROKER_SQLITE_GRANTS_PATH must be set}"
[ "$GRANTS_DB" != "${BROKER_SQLITE_PATH:?}" ] \
  || die "the grant store is co-located with the working store — the split is not in force"
mkdir -p "$STORE_DIR" "$(dirname "$GRANTS_DB")"
printf '   work   (rw): %s\n' "$BROKER_SQLITE_PATH"
printf '   grants (rw): %s\n' "$GRANTS_DB"
ok "two distinct database paths"

say "2. seed — the bootstrap ceremony, under the signing identity"
# Deliberately not in the maker leg: seeding MINTS floor grants, and an
# authority-minting act should be attributable to the identity that can sign
# for it.
python3 -m safe_agents.broker.grants.commands seed
ok "grants seeded and their bootstrap records signed"

say "3. the grant store exists, with a rollback journal"
# The journal mode is load-bearing rather than incidental: a WAL database cannot
# be opened read-only at all (readers map a -shm sidecar read-write), so the
# maker's leg would fail at OPEN rather than at the write we want to demonstrate.
python3 - "$GRANTS_DB" <<'PY' || die "the grant store is not in a read-only-openable state"
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(db)
mode = c.execute("PRAGMA journal_mode").fetchone()[0]
rows = c.execute("SELECT count(*) FROM items WHERE pk LIKE 'GRANT#%'").fetchone()[0]
print(f"   journal_mode={mode}  GRANT# rows={rows}")
if mode != "delete":
    print(f"   journal_mode is {mode!r}, not 'delete' — a read-only mount could not open it")
    sys.exit(1)
if rows < 1:
    print("   no GRANT# rows were seeded")
    sys.exit(1)
PY
ok "grant store bootstrapped and openable from a read-only mount"

# The breadcrumb the durability leg reads. This leg is a ceremony leg like any
# other — it MINTS the floor grants — so the serve leg's "every ceremony leg ran
# in a pod that is gone" claim has to cover it too, or the strongest-privilege
# leg is the one the durability proof quietly skips.
printf 'bootstrap %s %s\n' \
  "$(python3 -c 'import socket; print(socket.gethostname())')" "$WHOAMI" \
  >> "$STORE_DIR/ceremony-pods"

printf '\n\033[32mBOOTSTRAP COMPLETE\033[0m — the maker may now propose against a store it cannot write.\n'
