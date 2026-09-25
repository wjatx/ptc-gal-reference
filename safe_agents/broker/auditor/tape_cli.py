"""tape_cli.py — read and verify an audit tape from a terminal (#300, #42).

The tape is the payoff of the whole architecture: "a fully compromised agent can
still only ask", demonstrated rather than asserted. It was reachable only by
someone who had read the source. Nothing in the product named the file, and the
shipped tape readers were in-memory and S3 — so verifying the one tape the local
floor actually writes meant hand-rolling code around the sink.

A pure reader. It takes a PATH (the local floor's JSON-lines tape) or an S3
BUCKET and prefix (the cloud floor's one-object-per-record tape, #42), and opens
no store, no manifest and no connector: looking at what was recorded must never be
able to change what was recorded, and a reader that booted a runtime could. The S3
source needs only s3:ListBucket and s3:GetObject, the read half the auditor
identity holds.

WHAT `--verify` PROVES, AND WHAT IT DOES NOT
--------------------------------------------
The chain is unkeyed SHA-256 over each record plus its predecessor's hash. So an
intact chain establishes SELF-CONSISTENCY — it detects a record edited in place, a
record deleted, or a reordering. It is **not** tamper-evidence: anyone who can
write the file can rewrite every record and recompute every hash, and the result
verifies clean. Real tamper-evidence needs off-device append-only durability (S3
Object Lock — GOVERNANCE mode as deployed, with the limits `_s3_sink.py` states),
which is posture 3.

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
    InMemoryTapeReader,
    S3TapeReader,
    check_chain_integrity,
)

EXIT_OK = 0
EXIT_BROKEN = 1  # the chain does not verify
EXIT_REFUSED = 2  # the tape could not be read at all

#: The key prefix S3ObjectLockSink writes under unless the broker is given
#: BROKER_AUDIT_PREFIX (records land at {prefix}{seq:010d}.json).
DEFAULT_S3_PREFIX = "audit/"

#: Printed with every verify result. The claim and its limit travel together —
#: a caveat in a footnote is a caveat nobody reads.
CHAIN_CAVEAT = (
    "The chain is unkeyed SHA-256, so this proves the tape is SELF-CONSISTENT: no "
    "record was edited, dropped or reordered in place. It is NOT tamper-evidence — "
    "anyone who can write this file can rewrite it whole and recompute every hash. "
    "That needs off-device append-only storage (posture 3, docs/posture-ladder.md)."
)

#: The S3 variant. The chain check is identical, so its limit is too; what differs
#: is that off-device storage is the thing this source IS, and whether it refuses a
#: rewrite depends on the bucket's retention, which this command does not inspect.
#: Say so rather than letting "S3" read as "locked": development sets no default
#: retention at all (infra/lib/state-stack.ts), and GOVERNANCE yields to a
#: principal holding s3:BypassGovernanceRetention (audit/_s3_sink.py).
S3_CHAIN_CAVEAT = (
    "The chain is unkeyed SHA-256, so this proves the tape is SELF-CONSISTENT: no "
    "record was edited, dropped or reordered in place. The check itself is NOT "
    "tamper-evidence — anyone who can write this prefix can rewrite it whole and "
    "recompute every hash. Whether the bucket refuses that rewrite is its Object "
    "Lock retention's job, which this command does not inspect: durable "
    "environments set GOVERNANCE retention, which s3:BypassGovernanceRetention "
    "overrides, and development sets none."
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


class _Unreadable(Exception):
    """The tape could not be read at all: a refusal, never a verdict."""


def _read(args: argparse.Namespace):  # noqa: ANN202
    """(source label, records) from whichever source was named, or raise _Unreadable."""
    if args.path is not None:
        try:
            return args.path, FileTapeReader(args.path).read_all()
        except ValueError as exc:
            # Mid-file corruption: a fully-committed line that does not parse.
            raise _Unreadable(f"{args.path} is not a readable tape — {exc}") from exc

    source = f"s3://{args.s3_bucket}/{args.prefix}"
    try:
        return source, S3TapeReader(args.s3_bucket, key_prefix=args.prefix).read_all()
    except ValueError as exc:
        # An object under the prefix that is not an AuditRecord (pydantic's
        # ValidationError is a ValueError).
        raise _Unreadable(f"{source} holds an object that is not a record — {exc}") from exc
    except ImportError as exc:
        raise _Unreadable(
            f"reading {source} needs boto3, which the `aws` extra installs "
            "(pip install 'safe-agents[aws]')"
        ) from exc
    except Exception as exc:  # noqa: BLE001 — botocore is optional; see below
        # botocore's ClientError / BotoCoreError (no bucket, access denied, no
        # credentials, no region). boto3 is an optional extra, so its exception
        # types are not importable here unconditionally; anything else is a bug
        # and re-raises.
        if type(exc).__module__.startswith("botocore"):
            raise _Unreadable(f"{source} could not be read — {exc}") from exc
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.auditor.tape_cli",
        description="Read a hash-chained audit tape, and optionally verify its chain.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="a local audit tape (JSON lines)")
    source.add_argument(
        "--s3-bucket",
        metavar="BUCKET",
        help="an S3 audit bucket (one object per record, as the broker's S3 sink writes)",
    )
    parser.add_argument(
        "--prefix",
        default=DEFAULT_S3_PREFIX,
        help=f"key prefix within --s3-bucket (default {DEFAULT_S3_PREFIX!r})",
    )
    parser.add_argument(
        "--verify", action="store_true", help="check the hash chain and report"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON on stdout")
    args = parser.parse_args(argv)
    if args.path is not None and args.prefix != DEFAULT_S3_PREFIX:
        parser.error("--prefix applies only to --s3-bucket")

    try:
        label, records = _read(args)
    except _Unreadable as exc:
        # Reporting a verdict over bytes we could not read would be inventing one.
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    # Verify the records just read and rendered, not a second fetch: over S3 a
    # second listing could see a record the first did not, and the verdict would
    # describe a different tape from the one printed above it.
    finding = check_chain_integrity(InMemoryTapeReader(records)) if args.verify else None
    caveat = CHAIN_CAVEAT if args.path is not None else S3_CHAIN_CAVEAT

    if args.json:
        payload = {
            **({"path": args.path} if args.path is not None else {"s3": label}),
            "records": [r.model_dump(mode="json") for r in records],
            "count": len(records),
        }
        if finding is not None:
            payload["verify"] = {
                "intact": finding.intact,
                "error": finding.error,
                "brokenSeq": finding.broken_seq,
                "proves": caveat,
            }
        print(json.dumps(payload, indent=2))
        return EXIT_OK if finding is None or finding.intact else EXIT_BROKEN

    print(f"audit tape  {label}")
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
        print(f"  {caveat}")

    return EXIT_OK if finding is None or finding.intact else EXIT_BROKEN


if __name__ == "__main__":  # pragma: no cover — process entry point
    sys.exit(main())
