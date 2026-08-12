#!/usr/bin/env bash
# cluster-demo-admit.sh — admit a SECOND tool, so demonstration 2 has an untrusted
# read to be tainted by (#250 Phase 5).
#
#   cluster-demo-admit.sh propose    # runs as safe-agents-maker
#   cluster-demo-admit.sh ratify     # runs as safe-agents-checker
#
# WHY A SECOND ADMISSION IS NEEDED AT ALL. Demonstration 2 turns on the difference
# between a TRUSTED read and an UNTRUSTED one. `ledger.get_entry` is named in
# `envelope.trusted_read_sources`, so its response does not taint the turn;
# `ledger.list_entries` is not, so it does. But `list_entries` is deliberately left
# UNADMITTED by the Phase 3 arc — that is the two-key admission proof the serve and
# agent legs both make ("still never admitted"). An unadmitted call never executes,
# and a call that never executes cannot taint anything.
#
# So the tool has to be admitted here, AFTER those legs have made their point. The
# transition is itself worth watching: Phase 4's agent leg saw `list_entries` refused
# over HTTP, and after this ceremony the same call through the same surface executes.
# What changed is a signed admission record written by two credentials, which is
# exactly the claim two-key admission makes.
#
# DELIBERATELY SLIM. It does not re-run the maker's negative proofs, the solo-arm
# refusal, the read-only-mount attempts or the M7 self-ratify — Phase 3's legs own
# those and have already run in this same namespace against these same credentials.
# Re-proving them here would add noise and a second place to keep them correct.
set -euo pipefail

MODE="${1:?usage: cluster-demo-admit.sh propose|ratify}"
STORE_DIR="${STORE_DIR:-/var/lib/broker}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
TOOL="${DEMO_ADMIT_TOOL:-list_entries}"
PROPOSAL_FILE="$STORE_DIR/demo-proposal-id"

# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

WHOAMI=$(python3 -c '
import os
os.environ.setdefault("BROKER_CEREMONY_IDENTITY", "serviceaccount")
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
') || die "could not derive this pod's ceremony identity"

case "$MODE" in
  propose)
    say "P1. propose $SERVER_ID/$TOOL, as the maker"
    printf '   identity: %s\n' "$WHOAMI"
    case "$WHOAMI" in
      system:serviceaccount:*:safe-agents-maker) ;;
      *) die "the propose half must run as the maker, got '$WHOAMI'" ;;
    esac
    # The snapshot the Phase 3 leg captured is on the PVC. Re-using it rather than
    # re-snapshotting is deliberate: admitting a tool against a DIFFERENT discovery
    # than the one the arc reviewed would be a drift the ceremony is supposed to
    # catch, and doing it here by accident would hide that.
    [ -f "$STORE_DIR/snapshot.json" ] || die "no snapshot on the PVC — the Phase 3 propose leg did not run"
    PROPOSAL_ID=$(python3 -m safe_agents.broker.mcp.commands admit-propose \
      --server-id "$SERVER_ID" --tool-name "$TOOL" \
      --from-snapshot "$STORE_DIR/snapshot.json" --ttl-hours 1 \
      | tee /dev/stderr | sed -n 's/.*proposal_id=\([0-9a-f-]*\).*/\1/p')
    [ -n "$PROPOSAL_ID" ] || die "no proposal id parsed"
    printf '%s' "$PROPOSAL_ID" > "$PROPOSAL_FILE"
    ok "proposed $TOOL as $PROPOSAL_ID — unsigned, and uncallable until a second credential ratifies it"
    ;;

  ratify)
    say "P2. ratify $SERVER_ID/$TOOL, as the checker"
    printf '   identity: %s\n' "$WHOAMI"
    case "$WHOAMI" in
      system:serviceaccount:*:safe-agents-checker) ;;
      *) die "the ratify half must run as the checker, got '$WHOAMI'" ;;
    esac
    # The #282 shim, same as cluster-ratify.sh: a projected Secret under an fsGroup
    # gets 0440 OR-ed into whatever defaultMode was requested, so #226's mode check can
    # never pass on the projection itself. A compatibility shim, NOT a control — in a
    # pod the boundary protecting this key is the pod.
    PROJECTED_KEY="${PROJECTED_KEY:-/run/issuer-projected/issuer.pem}"
    PRIVATE_KEY="${PRIVATE_KEY:-/run/issuer-private/issuer.pem}"
    install -m 600 "$PROJECTED_KEY" "$PRIVATE_KEY" || die "could not stage the issuer key"
    export ISSUER_SIGNING_KEY_FILE="$PRIVATE_KEY"
    printf '   issuer key staged %s\n' "$(stat -c 'mode=%a owner=%u:%g' "$PRIVATE_KEY")"

    [ -f "$PROPOSAL_FILE" ] || die "no proposal on the PVC — the propose half did not run"
    PROPOSAL_ID=$(cat "$PROPOSAL_FILE")
    printf '   burning proposal %s\n' "$PROPOSAL_ID"
    python3 -m safe_agents.broker.mcp.commands admit-ratify \
      --server-id "$SERVER_ID" --tool-name "$TOOL" --proposal-id "$PROPOSAL_ID"
    ok "$SERVER_ID/$TOOL ADMITTED by a credential that did not propose it"
    printf '\n   maker≠checker held across BOTH admissions in this namespace: the\n'
    printf '   proposer could not sign, and this pod could not have proposed.\n'
    ;;

  *) die "unknown mode '$MODE' — expected propose or ratify" ;;
esac
