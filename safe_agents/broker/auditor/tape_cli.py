"""tape_cli.py — read and verify a local audit tape from a terminal (#300).

The tape is the payoff of the whole architecture: "a fully compromised agent can
still only ask", demonstrated rather than asserted. It was reachable only by
someone who had read the source. Nothing in the product named the file, and the
shipped tape readers were in-memory and S3 — so verifying the one tape the local
floor actually writes meant hand-rolling code around the sink.

A pure reader. It takes a PATH and opens no store, no manifest and no connector:
looking at what was recorded must never be able to change what was recorded, and
a reader that booted a runtime could.

WHAT `--verify` PROVES, AND WHAT IT DOES NOT
--------------------------------------------
The chain is unkeyed SHA-256 over each record plus its predecessor's hash. So an
intact chain establishes SELF-CONSISTENCY — it detects a record edited in place, a
record deleted, or a reordering. It is **not** tamper-evidence: anyone who can
write the file can rewrite every record and recompute every hash, and the result
verifies clean. Real tamper-evidence needs off-device append-only durability (S3
Object Lock — GOVERNANCE mode as deployed, with the limits `_s3_sink.py` states),
which is rung 3.

That distinction is the entire reason this command says "consistent" and never
"untampered". A user who believes they have a boundary stops looking for one
(`docs/posture-ladder.md`), and a verify command that implied more than it checks
would be the most expensive possible place to make that mistake.
"""

from __future__ import annotations

import argparse
import json
import sys

from safe_agents.broker.auditor._chain_verifier import (
    FileTapeReader,
    check_chain_integrity,
)

EXIT_OK = 0
EXIT_BROKEN = 1  # the chain does not verify
EXIT_REFUSED = 2  # the tape could not be read at all

#: Printed with every verify result. The claim and its limit travel together —
#: a caveat in a footnote is a caveat nobody reads.
CHAIN_CAVEAT = (
    "The chain is unkeyed SHA-256, so this proves the tape is SELF-CONSISTENT: no "
    "record was edited, dropped or reordered in place. It is NOT tamper-evidence — "
    "anyone who can write this file can rewrite it whole and recompute every hash. "
    "That needs off-device append-only storage (rung 3, docs/posture-ladder.md)."
)


def render_record(record) -> str:  # noqa: ANN001 — AuditRecord
    """One tape line, human-readably.

    `argsDigest` rather than args, because the broker deliberately hashes args on
    the way in — the audit must not become a PII store — so there is nothing else
    to show and pretending otherwise would misdescribe the record.
    """
    head = (
        f"  [{record.seq:>4}] {record.ts}  {record.tool}.{record.op}  "
        f"{record.decision}/{record.outcome}"
    )
    detail = [f"         args {record.argsDigest}"]
    if record.reason:
        detail.append(f"         why  {record.reason}")
    if record.approvedBy:
        detail.append(f"         approved by {record.approvedBy}")
    if record.intentId:
        detail.append(f"         intent {record.intentId}")
    if record.error:
        detail.append(f"         error {record.error}")
    return "\n".join([head, *detail])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.auditor.tape_cli",
        description="Read a hash-chained audit tape, and optionally verify its chain.",
    )
    parser.add_argument("--path", required=True, help="the audit tape (JSON lines)")
    parser.add_argument(
        "--verify", action="store_true", help="check the hash chain and report"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON on stdout")
    args = parser.parse_args(argv)

    reader = FileTapeReader(args.path)
    try:
        records = reader.read_all()
    except ValueError as exc:
        # Mid-file corruption: a fully-committed line that does not parse. This is
        # NOT a clean "chain broken" answer — the tape cannot even be read — so it
        # is a refusal rather than a verdict.
        print(f"REFUSED: {args.path} is not a readable tape — {exc}", file=sys.stderr)
        return EXIT_REFUSED

    finding = check_chain_integrity(reader) if args.verify else None

    if args.json:
        payload = {
            "path": args.path,
            "records": [r.model_dump(mode="json") for r in records],
            "count": len(records),
        }
        if finding is not None:
            payload["verify"] = {
                "intact": finding.intact,
                "error": finding.error,
                "brokenSeq": finding.broken_seq,
                "proves": CHAIN_CAVEAT,
            }
        print(json.dumps(payload, indent=2))
        return EXIT_OK if finding is None or finding.intact else EXIT_BROKEN

    print(f"audit tape  {args.path}")
    if not records:
        # An absent or empty tape is a legitimate state, not a fault: a project
        # whose agent has made no brokered call yet has nothing recorded.
        print("  (no records yet — nothing has been brokered for this project)")
        return EXIT_OK

    print(f"  {len(records)} record(s)")
    print()
    for record in records:
        print(render_record(record))

    if finding is not None:
        print()
        if finding.intact:
            print(f"CHAIN CONSISTENT — {len(records)} records, seq 0..{records[-1].seq}")
        else:
            print(f"CHAIN BROKEN at seq {finding.broken_seq}: {finding.error}")
        print(f"  {CHAIN_CAVEAT}")

    return EXIT_OK if finding is None or finding.intact else EXIT_BROKEN


if __name__ == "__main__":  # pragma: no cover — process entry point
    sys.exit(main())
