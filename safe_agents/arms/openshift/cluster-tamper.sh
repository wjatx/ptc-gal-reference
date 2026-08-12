#!/usr/bin/env bash
# cluster-tamper.sh — the audit-tape tamper attempt (#250 Phase 3, #310).
#
# Runs under ServiceAccount `safe-agents-maker`, in a pod scheduled after the
# broker's has completed, against a tape holding records the broker wrote. It
# attempts every way there is to forge or erase them and demands the kernel
# refuse each one, then verifies the chain is still intact and still what it was
# before the attempts.
#
# WHAT THIS LEG CLAIMS, exactly:
#
#   a ceremony leg cannot forge or erase another leg's records.
#
# and nothing wider. It does NOT claim the tape survives a compromised broker.
# The broker must write the tape, so it can also rewrite it — and the chain is
# unkeyed SHA-256 (`broker/audit/_hash.py`), so a rewrite by anyone holding write
# access re-chains end to end and re-verifies clean. The hash chain detects an
# edit by someone who could not rewrite the REST of the file; read-only mounts
# are what put the other legs in that position. Defending the tape against its
# own writer takes off-device append-only durability (S3 Object Lock on the cloud
# floor), which #310 deliberately did not take here.
#
# Attempted, never asserted. A split declared only in YAML is indistinguishable
# from a typo'd subPath that silently co-located the tape with the working half —
# the control would be gone while every log still printed PASS.
set -euo pipefail

TAPE="${BROKER_AUDIT_PATH:?BROKER_AUDIT_PATH must be set by the pod spec}"
AUDIT_DIR="$(dirname "$TAPE")"
WORK_DIR="${STORE_DIR:-/var/lib/broker}"

# The shared negative-proof helper (#312), extracted from this leg, cluster-propose
# and cluster-agent once all three worked. `say`/`ok`/`die` keep their local names so
# the body below reads unchanged.
# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

say "0. identity — the least-privileged ceremony credential"
printf '   uid=%s  pod=%s\n' "$(id -u)" "$(python3 -c 'import socket; print(socket.gethostname())')"
# The selector is set here rather than in the Job spec: this pod is deliberately
# configured with as little as possible, and the env order matters — the arm is
# resolved from the environment, so it has to be in place before the import.
WHOAMI=$(python3 -c '
import os
os.environ["BROKER_CEREMONY_IDENTITY"] = "serviceaccount"
from safe_agents.broker.ceremony_identity import resolve_ceremony_identity
print(resolve_ceremony_identity())
' 2>/dev/null || echo "<undetermined>")
printf '   SelfSubjectReview says: %s\n' "$WHOAMI"
case "$WHOAMI" in
  system:serviceaccount:*:safe-agents-maker) ;;
  *) die "expected the maker ServiceAccount, got '$WHOAMI'" ;;
esac
ok "running as the maker — the credential #203 already excluded from the grant store"

say "0b. CONTROL — this pod CAN write, so a refusal below means something"
# Without this, every refusal that follows is ambiguous: a read-only root
# filesystem, a bad SCC or a broken volume would produce exactly the same errors
# and the leg would print PASS for the wrong reason.
CANARY="$WORK_DIR/tamper-canary"
np_control "this pod CAN write to the working mount" -- touch "$CANARY"
rm -f "$CANARY"
ok "the working mount is writable by this pod; the audit mount is the variable under test"

say "1. what is on the tape, and who put it there"
# The precondition is part of the proof, not setup. Attempting these four verbs
# against an EMPTY tape would refuse identically while the heading claimed "cannot
# erase another leg's records" — right verb, vacuous target (#310, #312).
np_precondition "the tape exists and is non-empty" -- test -s "$TAPE"
[ -f "$TAPE" ] || die "no audit tape at $TAPE — the broker leg wrote nothing, or the subPath drifted"
BEFORE=$(sha "$TAPE")
printf '   %s\n' "$(ls -l "$TAPE")"
printf '   sha256 before: %s\n' "$BEFORE"
python3 - "$TAPE" "$WHOAMI" <<'PY' || die "the tape does not carry another leg's records"
import json
import sys

from safe_agents.broker.schemas import AuditRecord

tape, me = sys.argv[1], sys.argv[2]
records = [
    AuditRecord.model_validate_json(line)
    for line in open(tape, encoding="utf-8")
    if line.strip()
]
if not records:
    print("   the tape is EMPTY — there is nothing here to fail to erase", file=sys.stderr)
    sys.exit(1)
for r in records:
    print(f"   seq={r.seq} {r.tool}.{r.op} decision={r.decision} outcome={r.outcome} "
          f"principal={r.principal.agentId}")
print(f"   {len(records)} records, written by the broker leg — not by {me}")
PY
ok "a populated tape, written by a credential this pod does not hold"

say "2. NEGATIVE PROOF — every way to erase or forge, attempted"
# Four attempts, because "append-only" is not one control and an attacker does
# not care which verb gets there. Truncation and unlink are the erase paths;
# append and replace are the forge paths.
#
# Each names the mechanism it expects. The local `attempt()` this replaced checked
# rc alone, which is why #310 shipped with the gap #312 then filed: a read-only ROOT
# filesystem, a bad SCC or a mistyped subPath refuse all four exactly as loudly, and
# every one of them would have printed PASS four times over. "Read-only file system"
# is EROFS from the kernel — the claim this leg actually makes — and nothing else
# produces that string.
RO="Read-only file system"
np_refuse "truncate the tape"        "$RO" -- python3 -c 'open(__import__("sys").argv[1], "w").close()' "$TAPE"
np_refuse "append a forged record"   "$RO" -- python3 -c 'open(__import__("sys").argv[1], "a").write("{}\n")' "$TAPE"
np_refuse "unlink the tape"          "$RO" -- rm -f "$TAPE"
np_refuse "write a replacement file" "$RO" -- touch "$AUDIT_DIR/audit.jsonl.new"

np_summary "all four refused by the kernel with EROFS, on a read-only mount — not by a check of ours"

say "3. the tape is byte-identical to what it was before those attempts"
# Deliberately a byte comparison and not just a chain verification. A partial
# tamper that the chain happens to still accept would pass step 4 alone; only the
# bytes answer "did anything change at all".
AFTER=$(sha "$TAPE")
printf '   sha256 after:  %s\n' "$AFTER"
[ "$BEFORE" = "$AFTER" ] || die "the tape CHANGED across the attempts"
ok "not one byte moved"

say "4. the chain verifies, checked by something that is not the sink that wrote it"
# Parsed straight off the file and handed to verify_chain, rather than asking
# FileAuditSink to read its own tape back. "Independently verifiable" means the
# verifier shares no state with the writer — and needs no credential, because the
# chain is unkeyed.
python3 - "$TAPE" <<'PY' || die "the chain does not verify"
import sys

from safe_agents.broker.audit import ChainError, verify_chain
from safe_agents.broker.schemas import AuditRecord

tape = sys.argv[1]
records = [
    AuditRecord.model_validate_json(line)
    for line in open(tape, encoding="utf-8")
    if line.strip()
]
try:
    verify_chain(records)
except ChainError as exc:
    print(f"   chain BROKEN: {exc}", file=sys.stderr)
    sys.exit(1)
print(f"   verify_chain over {len(records)} records: intact "
      f"(seq 0..{records[-1].seq}, unkeyed SHA-256, no credential used)")
PY
ok "an intact chain, verified without the writer and without a key"

printf '\n\033[32mAUDIT SPLIT: PASS\033[0m — a ceremony leg cannot forge or erase another\n'
printf 'leg'"'"'s records. It does NOT follow that the tape survives a compromised broker:\n'
printf 'the writer can still rewrite its own tail and re-chain it, and this leg proves\n'
printf 'nothing about that case (#310).\n'
