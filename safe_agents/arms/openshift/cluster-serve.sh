#!/usr/bin/env bash
# cluster-serve.sh — the DURABILITY leg: a third pod, the same PVC (#250 Phase 3).
#
# This is the half of the exit predicate a manifest cannot assert. A
# PersistentVolumeClaim in a YAML file is not evidence that anything survived;
# only a later pod reading what the earlier ones wrote is.
#
# What this script deliberately does NOT do: seed, snapshot, admit-propose or
# admit-ratify. It runs no ceremony at all. Everything it serves must already be
# on the PVC, put there by cluster-propose.sh and cluster-ratify.sh in pods that
# no longer exist.
#
# HOW THE "different pod" CLAIM IS MADE, and why it changed. Under Phase 2's
# local arm it was free: the identity string was `<osuser>@<shorthost>#<role>`
# and inside a pod the short hostname IS the pod name, so the record named the
# pod that wrote it. Under the serviceaccount arm the identity names a
# CREDENTIAL and carries no pod at all — and this script went on parsing for an
# '@' that was no longer there, which made the comparison trivially true and the
# whole claim vacuous while still printing PASS. It is now made three ways, none
# of them inferred from the identity string:
#
#   * this pod has no issuer key and no way to obtain one, so it cannot have
#     signed the admission record it is about to serve;
#   * an explicit breadcrumb written by each earlier leg names the pod it ran in;
#   * none of the credentials in the stored attribution is the one this pod holds.
set -euo pipefail

MANIFEST="${BROKER_MANIFEST:?BROKER_MANIFEST must be set by the pod spec}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
ADMIT_TOOL="${DRILL_ADMIT_TOOL:-get_entry}"
REFUSE_TOOL="${DRILL_REFUSE_TOOL:-list_entries}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die() { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

say "0. this is a different pod"
# Via python's socket, not the `hostname` binary: it is the SAME call
# ceremony_identity._derive_operator() makes, so the string compared below is
# derived identically to the one stamped in the record — and `hostname` is not
# guaranteed to be installed in a slim base image.
THIS_HOST=$(python3 -c 'import socket; print(socket.gethostname().split(".")[0])')
printf '   hostname=%s  uid=%s\n' "$THIS_HOST" "$(id -u)"
[ "$(id -u)" != "0" ] || die "running as root"

say "1. this pod could not have produced what it is about to read"
# Under the local arm the identity string carried the pod name for free
# (`user@<pod>#role`), so "a different pod wrote this" was readable straight off
# the record. A ServiceAccount username carries no pod, and the first version of
# this leg went on parsing for an '@' that is no longer there — which made the
# comparison trivially true and the durability claim VACUOUS while still
# printing PASS. Two honest checks replace it.
#
# The strong one first: this pod has no issuer key and no way to get one, so it
# cannot have signed the admission record it is about to serve.
[ ! -e /run/issuer-projected ] || die "the issuer Secret is mounted into the SERVE pod"
[ -z "${ISSUER_SIGNING_KEY_FILE:-}" ] || die "ISSUER_SIGNING_KEY_FILE is set in the serve pod"
SERVE_ID=$(python3 -c '
import os
os.environ["BROKER_CEREMONY_IDENTITY"] = "serviceaccount"
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
' 2>/dev/null || echo "<no ceremony identity>")
printf '   this pod runs as: %s\n' "$SERVE_ID"
printf '   issuer key mounted here: no — it cannot sign anything\n'
ok "whatever signed the record on this volume, it was not this pod"

say "1b. and the ceremony ran in pods that are gone"
if [ -f "${STORE_DIR:-/var/lib/broker}/ceremony-pods" ]; then
  MY_POD=$THIS_HOST
  while read -r leg pod identity; do
    printf '   %-8s ran in pod %s as %s\n' "$leg" "$pod" "$identity"
    [ "$pod" != "$MY_POD" ] || die "the $leg leg ran in THIS pod — that is not durability"
  done < "${STORE_DIR:-/var/lib/broker}/ceremony-pods"
  ok "every ceremony leg ran in a pod that is not this one"
else
  die "no ceremony-pods breadcrumb on the volume — the earlier legs did not run"
fi

say "2. what was already on the PVC before this pod started"
# Read-only, BEFORE the runtime boots, so nothing this pod does can be mistaken
# for what it found. Schema-agnostic on purpose: it scans the item maps for the
# ceremony's own attribution fields rather than hard-coding pk/sk conventions
# that are the store's business and not this drill's.
#
# It has to walk NESTED serialized JSON, not just top-level keys. Under #246 the
# stored-bytes basis means a record item is `{"data": "<canonical record JSON>",
# "signature": ...}` — the attribution is inside that string, because the exact
# bytes are what the signature covers. A flat scan finds nothing and reports a
# perfectly durable store as empty.
# BOTH halves of the #203 split. The attribution the durability claim rests on
# (RECORD#/TOOLREC#) is checker-writable key space and lives in the grant store;
# scanning only the working store would find no attribution at all and report a
# durable, completed ceremony as an empty volume.
python3 - "${BROKER_SQLITE_PATH:?}" "${BROKER_SQLITE_GRANTS_PATH:?}" "$SERVE_ID" <<'PY' || die "the PVC does not carry a completed ceremony"
import json
import sqlite3
import sys

ATTRIBUTION = ("ratifiedBy", "proposedBy", "seededBy")


def walk(node, found):
    """Yield every attribution field, descending into JSON-in-a-string."""
    if isinstance(node, str):
        stripped = node.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                walk(json.loads(node), found)
            except ValueError:
                pass
        return
    if isinstance(node, list):
        for child in node:
            walk(child, found)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ATTRIBUTION and isinstance(value, str) and value:
                found.append((key, value))
            else:
                walk(value, found)


work_path, grants_path, my_identity = sys.argv[1], sys.argv[2], sys.argv[3]

rows = []
for label, db_path in (("work", work_path), ("grants", grants_path)):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    found_rows = conn.execute("SELECT pk, sk, item FROM items ORDER BY pk, sk").fetchall()
    print(f"   {len(found_rows)} rows in the {label} store ({db_path})")
    rows.extend(found_rows)
print(f"   {len(rows)} rows found on the PVC in total")

attributions = []
for pk, sk, raw in rows:
    found = []
    walk(raw, found)
    for field, who in found:
        attributions.append((pk, sk, field, who))
        print(f"     {field}={who}   [{pk} | {sk}]")

if not attributions:
    print("   NO ceremony attribution found on the PVC", file=sys.stderr)
    sys.exit(1)

# Deliberately NOT re-deriving "a different pod" from these strings. A
# ServiceAccount username names a credential, not a pod, and inferring one from
# the other is what made the previous version of this check vacuous. The
# different-pod claim is made in step 1b from an explicit breadcrumb; what THIS
# step adds is that none of the credentials on the volume is the one this pod
# holds — so it could not have written these records even had it tried.
mine = [(pk, sk, f, who) for pk, sk, f, who in attributions if who == my_identity]
if mine:
    for pk, sk, field, who in mine:
        print(f"   {field}={who} names THIS pod's own credential [{pk} | {sk}]",
              file=sys.stderr)
    sys.exit(1)
print(f"   this pod's credential is {my_identity},")
print("   which appears nowhere in the attribution above.")
PY
ok "the PVC carries a ceremony run by credentials this pod does not hold"

say "3. a fresh broker process serves the already-ratified grant"
# No seed. BROKER_GRANT_LOAD=read means boot cannot mint a grant, and #205's F5
# refuses BROKER_GRANT_LOAD=seed on the sqlite arm outright — so "it re-seeded
# quietly" is not an available explanation for what follows.
printf '   BROKER_GRANT_LOAD=%s\n' "${BROKER_GRANT_LOAD:-<unset>}"
python3 - "$MANIFEST" "$SERVER_ID" "$ADMIT_TOOL" "$REFUSE_TOOL" <<'PY'
import logging
import sys

logging.disable(logging.CRITICAL)
from safe_agents.broker.api import AgentRequest, build_runtime, load_agent_manifest

manifest_path, server_id, admit_tool, refuse_tool = sys.argv[1:5]
runtime, _ = build_runtime(load_agent_manifest(manifest_path))
failures = []
try:
    admitted = runtime.handle_request(AgentRequest(
        tool=server_id, op=admit_tool,
        args={"entry_id": "L-001"}, idempotency_key="cluster-serve-admitted"))
    print(f"   {server_id}.{admit_tool} -> {admitted.decision_kind}")
    if admitted.decision_kind != "allow" or admitted.result is None:
        failures.append(f"{admit_tool} did not execute: {admitted.decision_kind} {admitted.reason}")
    else:
        print(f"   result: {str(admitted.result)[:100]}")

    refused = runtime.handle_request(AgentRequest(
        tool=server_id, op=refuse_tool,
        args={"limit": 5}, idempotency_key="cluster-serve-refused"))
    print(f"   {server_id}.{refuse_tool} -> {refused.decision_kind} (still never admitted)")
    if refused.result is not None:
        failures.append(f"{refuse_tool} RETURNED A RESULT — two-key admission is not holding")
finally:
    runtime.close()

if failures:
    for f in failures:
        print(f"   {f}", file=sys.stderr)
    sys.exit(1)
PY
ok "the first pod's ceremony output served by a second pod, no ceremony re-run"

say "4. and those two decisions are on the audit tape, on its own mount (#310)"
# The tape moved out of the mutually-writable working half into `audit/`, which
# only this pod holds read-write. Checked here rather than taken on trust,
# because the failure mode of a mistyped subPath is silent: the broker would
# happily write a tape somewhere nobody looks, and the tamper leg that follows
# would then attempt its writes against a file that was never the real one.
TAPE="${BROKER_AUDIT_PATH:?BROKER_AUDIT_PATH must be set}"
case "$TAPE" in
  "${BROKER_SQLITE_PATH%/*}"/*) die "the tape is inside the working mount — the #310 split is NOT in force" ;;
esac
printf '   tape: %s\n' "$TAPE"
[ -f "$TAPE" ] || die "the broker wrote no audit tape — the writer leg cannot write its own mount"
python3 - "$TAPE" <<'PY' || die "the audit chain does not verify"
import sys

from safe_agents.broker.audit import ChainError, verify_chain
from safe_agents.broker.schemas import AuditRecord

records = [
    AuditRecord.model_validate_json(line)
    for line in open(sys.argv[1], encoding="utf-8")
    if line.strip()
]
for r in records:
    print(f"   seq={r.seq} {r.tool}.{r.op} decision={r.decision} outcome={r.outcome}")
if not records:
    print("   the tape is empty — the two decisions above were not recorded", file=sys.stderr)
    sys.exit(1)
try:
    verify_chain(records)
except ChainError as exc:
    print(f"   chain BROKEN: {exc}", file=sys.stderr)
    sys.exit(1)
print(f"   verify_chain over {len(records)} records: intact")
PY
ok "the writer leg appends to its own mount and the chain verifies"

printf '\n\033[32mPVC DURABILITY: PASS\033[0m — the store outlived the pod that wrote it,\n'
printf 'and the decisions it served are on a tape no ceremony leg can reach.\n'
