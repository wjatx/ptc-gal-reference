"""grants.audit_command — the invocation path for the grant-integrity audit (#252).

## Why this module exists

``grants/audit.py`` has been complete and correct since #62, and until now
**nothing in the repo called it outside a test**. The CI dispatch runs
``pytest safe_agents/broker/tests/test_grants_audit_live.py``; there was no
entry point a person or a program could reach. So the auditor was not missing a
local arm so much as missing a door — and #252 found the local half first only
because the sqlite floor made the absence impossible to ignore.

Two surfaces, deliberately layered:

``run_grants_audit`` — the library entry point. Takes a NAMED target, resolves
the right loader, and returns the ``AuditReport``. Anything in-process (another
base module, a future watcher) calls this.

``main`` — the CLI wrapper, ``python -m safe_agents.broker.grants.audit_command``.
This is what an operator runs, and what ``example-wrapper posture`` shells out to: the
wrapper's import boundary permits ``safe_agents.broker.schemas`` and nothing else,
so a posture command CANNOT import the auditor. It runs
this command and parses ``--json``.

That constraint is worth stating plainly because it inverts the shape #252's
own scoping comment proposed ("a library entry point with a CLI wrapper, rather
than a CLI that shells out"). Both halves exist, but the wrapper consumer is on
the far side of a process boundary either way. What matters is that the thing
it parses is a **contract** — the JSON below — and not prose scraped from a
human-readable report. `cli.py` already scrapes a proposal id out of the
ceremony CLI's stdout and that seam is on the watch-list; this one does not
repeat it.

## Exit codes — the contract a caller keys on

    0   no violations (acknowledged findings are annotations, still 0)
    1   at least one unacknowledged violation
    2   the audit could not be run at all (bad target, unresolvable keys)

2 is distinct from 1 on purpose: "the floor is dirty" and "nobody looked" are
opposite facts, and a caller that conflated them would report an unaudited
store as a clean one.

## What is deliberately NOT here

**No ``--env`` flag.** Resolving an environment name to a deployed table via
CloudFormation exports already has exactly one implementation
(``test_grants_audit_live.resolve_live``, under the standing ``GRANTS_AUDIT_ENV``
ruling). Adding a second one here would be the same second-arm defect #252 is
itself an instance of. Locating a deployment is a different job from auditing
one: this command audits the target it is GIVEN.

**No key material resolution of its own.** ``BROKER_HMAC_KEY`` and
``ISSUER_VERIFY_KEYS_PARAM`` are read through the same seams the live test and
the demotion runner use, so keyed/keyless mode is decided by what the invoking
identity holds — never by a flag, which would let a caller ask for a quieter
audit.

**Known gap, reported rather than papered over:** the issuer VERIFY side has no
local arm. Signing gained one in #226 (``ISSUER_SIGNING_KEY_FILE``); verifying
did not, so ``resolve_issuer_verify_keys`` can only read an SSM parameter. A
local (sqlite) floor therefore ALWAYS lands RECORD_SIGNATURE_VERIFIES in
``skipped_rules``. That is loud by construction — the report says so, and
``example-wrapper posture`` repeats it — but it means a local ledger's signatures are
never checked by this audit today.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.grants.audit import (
    AuditDataset,
    AuditReport,
    load_dataset_sqlite,
    run_audit,
)
from safe_agents.broker.grants.issuer_keys import resolve_issuer_verify_keys

#: The closed backend catalog. A string, resolved in ONE place (``load_target``)
#: — never an import path, and nothing store-loaded can extend it
#: (docs/config-provenance.md).
Backend = Literal["sqlite", "dynamo"]

EXIT_CLEAN = 0
EXIT_VIOLATIONS = 1
EXIT_NOT_RUN = 2


class AuditTargetError(RuntimeError):
    """The named target could not be read — exit 2, never a quiet empty audit."""


@dataclass(frozen=True)
class AuditTarget:
    """What to audit: one backend from the closed catalog, and where.

    ``location`` is a db path on the sqlite arm and a table name on the dynamo
    arm. Always explicit: an audit that defaulted its target could open a fresh
    empty database and report a spotless floor.
    """

    backend: Backend
    location: str


def load_target(target: AuditTarget) -> AuditDataset:
    """Resolve the loader for ``target.backend`` and load the dataset."""
    if target.backend == "sqlite":
        return load_dataset_sqlite(target.location)
    if target.backend == "dynamo":
        try:
            import boto3  # noqa: PLC0415 — lazy: the sqlite arm needs no AWS SDK
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise AuditTargetError(
                "auditing a DynamoDB table needs boto3, which is not installed"
            ) from exc
        from safe_agents.broker.grants.audit import load_dataset  # noqa: PLC0415

        return load_dataset(boto3.resource("dynamodb").Table(target.location))
    raise AuditTargetError(  # pragma: no cover - unreachable via the CLI parser
        f"unknown backend {target.backend!r}; the catalog is sqlite|dynamo"
    )


def run_grants_audit(target: AuditTarget) -> AuditReport:
    """Load ``target`` and run every rule the invoking identity's key material allows.

    Mode is decided by the environment, exactly as the live test and the
    demotion runner decide it: ``BROKER_HMAC_KEY`` present ⇒ keyed, absent ⇒
    keyless with the HMAC rules named in ``skipped_rules``;
    ``ISSUER_VERIFY_KEYS_PARAM`` present ⇒ signature rules run. A
    set-but-unresolvable verify parameter raises rather than skipping a rule
    the operator configured to run.
    """
    hmac_key = os.environ.get("BROKER_HMAC_KEY", "").encode() or None
    return run_audit(
        load_target(target),
        hmac_key=hmac_key,
        record_key_resolver=resolve_issuer_verify_keys(),
    )


def report_to_dict(report: AuditReport, target: AuditTarget) -> dict:
    """The machine-readable contract — what ``example-wrapper posture`` parses.

    ``clean`` is a derived convenience, but the caller is expected to read
    ``skipped_rules`` too: a report with no violations and four skipped rules is
    not the same claim as a report with no violations and none skipped, and
    collapsing the two is the exact overclaim the audit exists to prevent.
    """
    return {
        "backend": target.backend,
        "location": target.location,
        "clean": not report.violations,
        "violations": [
            {"rule": v.rule, "coordinate": v.coordinate, "detail": v.detail}
            for v in report.violations
        ],
        "acknowledged": [
            {
                "rule": entry.violation.rule,
                "coordinate": entry.violation.coordinate,
                "detail": entry.violation.detail,
                "waiver_ref": entry.waiver_ref,
            }
            for entry in report.acknowledged
        ],
        "skipped_rules": sorted(report.skipped_rules),
        "examined": {
            "grants": report.grants_examined,
            "records": report.records_examined,
            "proposals": report.proposals_examined,
            "envelopes": report.envelopes_examined,
        },
    }


def render_text(payload: dict) -> str:
    """The operator rendering. Skipped rules are printed even on a clean run —
    a green audit that ran half its rules must never LOOK like a full one."""
    examined = payload["examined"]
    lines = [
        f"grants audit ({payload['backend']}: {payload['location']})",
        (
            f"  examined: {examined['grants']} grants, {examined['records']} records, "
            f"{examined['proposals']} proposals, {examined['envelopes']} envelopes"
        ),
    ]
    for violation in payload["violations"]:
        lines.append(f"  VIOLATION [{violation['rule']}] {violation['coordinate']}")
        lines.append(f"    {violation['detail']}")
    for entry in payload["acknowledged"]:
        lines.append(
            f"  acknowledged [{entry['rule']}] {entry['coordinate']}: {entry['waiver_ref']}"
        )
    if payload["skipped_rules"]:
        lines.append(f"  SKIPPED (not run, not passed): {', '.join(payload['skipped_rules'])}")
    lines.append(
        f"  {len(payload['violations'])} violations, "
        f"{len(payload['acknowledged'])} acknowledged, "
        f"{len(payload['skipped_rules'])} rules skipped"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.grants.audit_command",
        description="Read-only grant-integrity audit of a named store (#62, #252).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite", metavar="PATH", help="audit a local broker.db")
    source.add_argument("--table", metavar="NAME", help="audit a DynamoDB grants table")
    parser.add_argument(
        "--json", action="store_true", help="emit the machine-readable report"
    )
    args = parser.parse_args(argv)

    target = (
        AuditTarget("sqlite", args.sqlite)
        if args.sqlite
        else AuditTarget("dynamo", args.table)
    )
    try:
        report = run_grants_audit(target)
    except Exception as exc:
        # Exit 2, never 1: failing to RUN the audit is not a clean floor and is
        # not a dirty one either. Callers key on the distinction.
        print(f"audit could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_NOT_RUN

    payload = report_to_dict(report, target)
    print(json.dumps(payload, indent=2) if args.json else render_text(payload))
    return EXIT_VIOLATIONS if report.violations else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
