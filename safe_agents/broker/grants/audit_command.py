"""grants.audit_command — the invocation path for the grant-integrity audit.

## Why this module exists

``grants/audit.py`` has been complete and correct since it landed, and until now
**nothing in the repo called it outside a test**. The CI dispatch runs
``pytest safe_agents/broker/tests/test_grants_audit_live.py``; there was no
entry point a person or a program could reach. So the auditor was not missing a
local arm so much as missing a door — and the sqlite audit work found the local half first only
because the sqlite floor made the absence impossible to ignore.

Two surfaces, deliberately layered:

``run_grants_audit`` — the library entry point. Takes a NAMED target, resolves
the right loader, and returns the ``AuditReport``. Anything in-process (another
base module, a future watcher) calls this. ``run_store_audit`` is the same
entry point for everything the door covers (see "The MCP registry rides the
same door" below), and is what ``main`` runs.

``main`` — the CLI wrapper, ``python -m safe_agents.broker.grants.audit_command``.
This is what an operator runs, and what ``example-wrapper posture`` shells out to: the
wrapper's import boundary permits ``safe_agents.broker.schemas`` and nothing else,
so a posture command CANNOT import the auditor. It runs
this command and parses ``--json``.

That constraint is worth stating plainly because it inverts the shape the sqlite audit work's
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
ruling). Adding a second one here would be the same second-arm defect that work is
itself an instance of. Locating a deployment is a different job from auditing
one: this command audits the target it is GIVEN.

**No key material resolution of its own.** ``BROKER_HMAC_KEY`` and each role's
verify keys (``*_VERIFY_KEYS_PARAM`` or ``*_VERIFY_KEYS_FILE``) are read
through the same seams the live test and the demotion runner use, so
keyed/keyless mode is decided by what the invoking identity holds — never by a
flag, which would let a caller ask for a quieter audit. The one config value
this module does own is ``RECORD_SIGNING_EPOCH``, and it can only ever make
the audit STRICTER (it adds record types to the signing requirement); its
absence is reported as an annotation, so it cannot be used to ask for quiet
either.

**Verify keys on a local floor.** The verify side has a local arm for both
roles (#108): ``ISSUER_VERIFY_KEYS_FILE`` / ``EVALUATOR_VERIFY_KEYS_FILE`` name
a file holding the same ``{key_id: public_key_pem}`` JSON map the SSM parameter
holds. With neither the file nor the parameter set, the signature rules land in
``skipped_rules``, loudly, and the report says no signature was checked.

## The MCP registry rides the same door

``--sqlite PATH`` audits the grants AND the admitted-tool registry
(``mcp/audit.py``) from one read of the file, and reports them together: one
``violations`` list, one ``skipped_rules`` list, one exit code, and a count of
every item kind examined (#143). It is one door on purpose. A local deployment
that only admits MCP tools holds ``TOOLDEF#`` / ``TOOLREC#`` / ``TOOLPROP#``
items and no grants, and this is the command its operator already runs. A
second command for the registry would leave this one reporting zero violations
over zero grants, which is accurate and says nothing about the items that
deployment depends on. The module keeps its name and its place because callers
already key on both.

``--table NAME`` audits the grants table only. The registry is a different
table there and no audit identity can read it (#96), so the report carries
``mcp_*`` counts of ``null`` and an annotation that the registry was NOT
audited. Not audited is never rendered as zero items.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.grants.audit import (
    AuditDataset,
    AuditReport,
    dataset_from_items,
    load_dataset_sqlite,
    read_items_sqlite,
    run_audit,
)
from safe_agents.broker.grants.issuer_keys import resolve_record_key_resolvers
from safe_agents.broker.grants.record_signing import RoleKeyResolvers
from safe_agents.broker.mcp import audit as mcp_audit

#: The ISO-8601 UTC instant from which EVERY ledger record type must carry a
#: verifying signature of its role (GAL-SPEC §6.10). Unset = the pre-epoch
#: scope, reported as a named annotation — never a silent narrowing. Read here
#: rather than in ``audit.py`` so the rules stay pure over their inputs.
RECORD_SIGNING_EPOCH_ENV = "RECORD_SIGNING_EPOCH"

#: The closed backend catalog. A string, resolved in ONE place (``load_target``)
#: — never an import path, and nothing store-loaded can extend it
#: (docs/config-provenance.md).
Backend = Literal["sqlite", "dynamo"]

EXIT_CLEAN = 0
EXIT_VIOLATIONS = 1
EXIT_NOT_RUN = 2

#: Annotation name for a report that did not cover the MCP registry at all.
ANNOTATION_MCP_NOT_AUDITED = "mcp-registry-not-audited"


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


@dataclass(frozen=True)
class StoreAudit:
    """Everything one run of the door covered.

    ``mcp`` is ``None`` when the MCP registry was not audited (the dynamo arm,
    #96). ``None`` and an empty report are different facts and are rendered
    differently.
    """

    grants: AuditReport
    mcp: mcp_audit.McpAuditReport | None = None


@dataclass(frozen=True)
class _KeyMaterial:
    """What the invoking identity holds, resolved once per run."""

    hmac_key: bytes | None
    resolvers: RoleKeyResolvers | None
    signing_epoch: str | None
    now: datetime.datetime


def _resolve_key_material() -> _KeyMaterial:
    """Read the audit's mode from the environment, the one place it is read.

    Mode is decided exactly as the live test and the demotion runner decide it:
    ``BROKER_HMAC_KEY`` present ⇒ keyed, absent ⇒ keyless with the HMAC rules
    named in ``skipped_rules``; a role's verify keys configured
    (``*_VERIFY_KEYS_PARAM`` or ``*_VERIFY_KEYS_FILE``) ⇒ the signature rules
    run for that role's record types. A set-but-unresolvable verify source
    raises rather than skipping a rule the operator configured to run, and so
    does a key_id claimed by both roles.

    This is the ONE wall-clock read on the audit path: the evaluation instant
    the record-signing epoch is judged at is taken here, at the outermost
    caller, and passed down — nothing below derives it from a record's ts.
    """
    return _KeyMaterial(
        hmac_key=os.environ.get("BROKER_HMAC_KEY", "").encode() or None,
        resolvers=resolve_record_key_resolvers(),
        signing_epoch=os.environ.get(RECORD_SIGNING_EPOCH_ENV) or None,
        now=datetime.datetime.now(datetime.UTC),
    )


def _run_grants_rules(dataset: AuditDataset, keys: _KeyMaterial) -> AuditReport:
    return run_audit(
        dataset,
        hmac_key=keys.hmac_key,
        record_key_resolver=keys.resolvers,
        signing_epoch=keys.signing_epoch,
        now=keys.now,
    )


def run_grants_audit(target: AuditTarget) -> AuditReport:
    """Load ``target`` and run every GRANT rule the invoking identity's key
    material allows. The grants half alone; ``run_store_audit`` is what the
    command runs.
    """
    return _run_grants_rules(load_target(target), _resolve_key_material())


def run_store_audit(target: AuditTarget) -> StoreAudit:
    """Audit everything this door covers in ``target``.

    On the sqlite arm that is the grants and the MCP registry, parsed from ONE
    read of the file, so the two reports describe the same snapshot. The
    admission ledger is issuer-signed, so the registry's signature rules take
    the issuer's verify keys and nothing else.

    On the dynamo arm it is the grants alone, and ``mcp`` is ``None``.
    """
    keys = _resolve_key_material()
    if target.backend != "sqlite":
        return StoreAudit(grants=_run_grants_rules(load_target(target), keys))
    items = read_items_sqlite(target.location)
    return StoreAudit(
        grants=_run_grants_rules(dataset_from_items(items), keys),
        mcp=mcp_audit.run_audit(
            mcp_audit.dataset_from_items(items),
            hmac_key=keys.hmac_key,
            key_resolver=keys.resolvers.issuer if keys.resolvers else None,
        ),
    )


def report_to_dict(
    report: AuditReport,
    target: AuditTarget,
    mcp: mcp_audit.McpAuditReport | None = None,
) -> dict:
    """The machine-readable contract — what ``example-wrapper posture`` parses.

    ``clean`` is a derived convenience, but the caller is expected to read
    ``skipped_rules`` too: a report with no violations and four skipped rules is
    not the same claim as a report with no violations and none skipped, and
    collapsing the two is the exact overclaim the audit exists to prevent.

    The MCP registry's findings share the grants' lists rather than sitting
    under a key of their own, so a caller that reads ``clean``, ``violations``
    and ``skipped_rules`` sees a registry finding without learning a new field.
    Every registry rule name starts ``MCP_``. With ``mcp`` absent the three
    ``mcp_*`` counts are ``None``, never zero, and an annotation says the
    registry was not audited.
    """
    violations = list(report.violations) + list(mcp.violations if mcp else ())
    annotations = list(report.annotations) + list(mcp.annotations if mcp else ())
    if mcp is None:
        annotations.append(
            f"{ANNOTATION_MCP_NOT_AUDITED}: the MCP admitted-tool registry was NOT "
            "audited by this run. The registry audit runs on the sqlite arm; no "
            "deployed audit identity can read the DynamoDB registry table (#96)"
        )
    return {
        "backend": target.backend,
        "location": target.location,
        "clean": not violations,
        "violations": [
            {"rule": v.rule, "coordinate": v.coordinate, "detail": v.detail}
            for v in violations
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
        "skipped_rules": sorted(
            set(report.skipped_rules) | set(mcp.skipped_rules if mcp else ())
        ),
        "annotations": annotations,
        "examined": {
            "grants": report.grants_examined,
            "records": report.records_examined,
            "proposals": report.proposals_examined,
            "envelopes": report.envelopes_examined,
            "mcp_rows": mcp.rows_examined if mcp else None,
            "mcp_records": mcp.records_examined if mcp else None,
            "mcp_proposals": mcp.proposals_examined if mcp else None,
        },
    }


def render_text(payload: dict) -> str:
    """The operator rendering. Skipped rules are printed even on a clean run —
    a green audit that ran half its rules must never LOOK like a full one."""
    examined = payload["examined"]
    if examined["mcp_rows"] is None:
        mcp_examined = "NOT AUDITED"
    else:
        mcp_examined = (
            f"{examined['mcp_rows']} rows, {examined['mcp_records']} admission "
            f"records, {examined['mcp_proposals']} proposals"
        )
    lines = [
        f"store audit ({payload['backend']}: {payload['location']})",
        (
            f"  grants examined: {examined['grants']} grants, {examined['records']} "
            f"records, {examined['proposals']} proposals, {examined['envelopes']} envelopes"
        ),
        f"  mcp registry examined: {mcp_examined}",
    ]
    for violation in payload["violations"]:
        lines.append(f"  VIOLATION [{violation['rule']}] {violation['coordinate']}")
        lines.append(f"    {violation['detail']}")
    for entry in payload["acknowledged"]:
        lines.append(
            f"  acknowledged [{entry['rule']}] {entry['coordinate']}: {entry['waiver_ref']}"
        )
    for annotation in payload.get("annotations", ()):
        lines.append(f"  NOTE: {annotation}")
    if payload["skipped_rules"]:
        lines.append(f"  SKIPPED (not run, not passed): {', '.join(payload['skipped_rules'])}")
    lines.append(
        f"  {len(payload['violations'])} violations, "
        f"{len(payload['acknowledged'])} acknowledged, "
        f"{len(payload.get('annotations', ()))} annotations, "
        f"{len(payload['skipped_rules'])} rules skipped"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.grants.audit_command",
        description=(
            "Read-only integrity audit of a named store: the grants, and on the "
            "sqlite arm the MCP admitted-tool registry too."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--sqlite", metavar="PATH", help="audit a local broker.db (grants and MCP registry)"
    )
    source.add_argument(
        "--table", metavar="NAME", help="audit a DynamoDB grants table (grants only)"
    )
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
        audit = run_store_audit(target)
    except Exception as exc:
        # Exit 2, never 1: failing to RUN the audit is not a clean floor and is
        # not a dirty one either. Callers key on the distinction.
        print(f"audit could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_NOT_RUN

    payload = report_to_dict(audit.grants, target, audit.mcp)
    print(json.dumps(payload, indent=2) if args.json else render_text(payload))
    return EXIT_CLEAN if payload["clean"] else EXIT_VIOLATIONS


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
