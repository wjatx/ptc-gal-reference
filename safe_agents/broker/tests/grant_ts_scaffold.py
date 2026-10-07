"""Shared harness for the GRANT_TS_RECORDED suite (#166; GAL §5.2, §6.11, GAL-32, GAL-40).

Every sanctioned write stamps the grant and the record it appends with one
``ts``, so the audit holds each grant's ``ts`` to the ``ts`` of the latest
ledger record at its coordinate. Each clause below is one property of that
rule, and every assertion in the suite names the clause it pins.

| Clause | Guarantee |
|---|---|
| **T1** | The rule: one named finding for every grant whose `ts` is not the `ts` of the latest record at its coordinate, in both directions (later than every record, earlier than the latest). |
| **T2** | A clean ledger passes: after each of seed, promote, demote, lapse, tighten and re-seed, on every store backend through that backend's own loader, there is no such finding. A coordinate whose latest record is a `reattestation` passes too, because this rule does not pass over the type. |
| **T3** | Latest means latest: the maximum instant over every record's parsed `ts`, never string order or list order. |
| **T4** | Waivable, and only by a signed acknowledgment: the rule is in the closed waivable set, and no date, epoch or field on a grant or record takes a grant out of scope. |
| **T5** | The acknowledgment binds the stored bytes: the detail carries the sha256 of the grant's stored bytes, verbatim, and both timestamps, so a grant rewritten after it was acknowledged is a new finding. Where a record's `ts` is not an instant there is no latest `ts` to name, and the detail carries one sha256 over the stored bytes of every record at the coordinate in its place. A finding with no stored bytes to bind is never waived. |
| **T6** | Reported honestly: an acknowledged finding is green with an annotation, in the report and in both renderings. An acknowledgment that does not verify, or that nobody could verify, is not applied. |
| **T7** | No crash, no double blame: a quarantined grant, an unparseable grant, a grant with no record and a ledger with no grant stay with the rules that own them, and a `ts` that is not an instant is a finding and never an exception. A grant whose coordinate holds only records that earn nothing has a latest record, so it is this rule's as well as `LEDGER_COUNTERPART`'s when its `ts` is not that record's. |

T1, T3 and T7 are pinned over hand-built datasets in
test_grants_ts_recorded_rule.py, T2 over the real writers on all three
backends in test_grants_ts_recorded_ceremony.py, and T4 to T6 over the real
acknowledgment ceremony on all three backends in
test_grants_ts_recorded_waiver.py. T4 and T5 over rows no ceremony writes (a
ts from any year, stored bytes that are not canonical, a record ts that is not
an instant) are in test_grants_ts_recorded_binding.py. This module holds what they share: the
per-backend loaders, the writer drivers and the finding helpers. It is not
collected itself.
"""

from __future__ import annotations

import argparse
import datetime

from safe_agents.broker.grants import commands
from safe_agents.broker.grants.acknowledgments import (
    DynamoDBAcknowledgmentStore,
    InMemoryAcknowledgmentStore,
)
from safe_agents.broker.grants.audit import (
    GRANT_TS_RECORDED,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    AuditReport,
    AuditViolation,
    dataset_from_items,
    load_dataset,
    load_dataset_sqlite,
    run_audit,
)
from safe_agents.broker.grants.ceremony import PromotionCeremony
from safe_agents.broker.grants.commands import acknowledge_command
from safe_agents.broker.grants.demotion import DemotionMetrics
from safe_agents.broker.grants.lapse import run_lapse
from safe_agents.broker.grants.record_signing import (
    canonical_record_payload,
    stored_record_digest_hex,
)
from safe_agents.broker.grants.rung import RungStateMachine
from safe_agents.broker.grants.sqlite_ceremony_stores import SqliteAcknowledgmentStore
from safe_agents.broker.grants.store import _principal_key, canonical_grant_payload
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import DemotionTrigger
from safe_agents.broker.tests.reattestation_scaffold import IN
from safe_agents.broker.tests.test_grant_store_differential import (
    ACTION_CLASS,
    HMAC_KEY,
    PRINCIPAL,
    DynamoBackend,
)
from safe_agents.broker.tests.test_grants_rung import proposal_for

COORDINATE = f"{_principal_key(PRINCIPAL)}#{ACTION_CLASS}"
CHECKER = "arn:aws:sts::111111111111:assumed-role/CheckerRole/acknowledger"
# A term far enough out that no run of this suite ratifies it already expired,
# and the instant a lapse of it is evaluated at.
FAR_TERM = "2099-01-01T00:00:00+00:00"
AFTER_FAR_TERM = datetime.datetime(2099, 1, 2, tzinfo=datetime.UTC)
ACKNOWLEDGED_AT = datetime.datetime(2026, 8, 1, tzinfo=datetime.UTC)


# ---------------------------------------------------------------------------
# Hand-built datasets (the rule on its own)
# ---------------------------------------------------------------------------


def dataset(grant: Grant | None, records: list[PromotionRecord]) -> AuditDataset:
    """A grant and its ledger as the loaders would hand them over, stored
    bytes included. ``records`` is taken in the order given: the rule must not
    depend on it."""
    return AuditDataset(
        grants=(AuditedGrant(grant=grant, raw_data=canonical_grant_payload(grant)),)
        if grant is not None
        else (),
        records=tuple(
            AuditedRecord(record=r, raw_data=canonical_record_payload(r)) for r in records
        ),
    )


def ts_findings(report: AuditReport) -> list[AuditViolation]:
    return [v for v in report.violations if v.rule == GRANT_TS_RECORDED]


def stored_digest(raw_data: str) -> str:
    """The form in which a finding names a grant's stored bytes."""
    return f"stored bytes sha256:{stored_record_digest_hex(raw_data)}"


# ---------------------------------------------------------------------------
# One store backend, read through its own loader
# ---------------------------------------------------------------------------


def ack_store(backend):
    """The acknowledgment store beside ``backend``'s grants: the same table,
    the same file, or (in memory) one kept on the harness object."""
    if backend.name == "sqlite":
        return SqliteAcknowledgmentStore(backend.db_path)
    if backend.name == "dynamo":
        return DynamoDBAcknowledgmentStore(DynamoBackend.TABLE)
    if not hasattr(backend, "acks"):
        backend.acks = InMemoryAcknowledgmentStore()
    return backend.acks


def _memory_items(backend) -> list[dict]:
    """The in-memory stores' contents as whole items, keyed as the table is."""
    grants = [
        {"pk": f"GRANT#{principal_key}", "sk": f"CLASS#{action_class}", **item}
        for (principal_key, action_class), item in backend.grants._store.items()
    ]
    records = [
        {"pk": f"RECORD#{pk}", "sk": sk, "data": data, "signature": signature}
        for (pk, sk), (data, signature) in backend.records._records.items()
    ]
    return grants + records + ack_store(backend).items()


def load(backend) -> AuditDataset:
    """Everything in ``backend``, through the loader an operator would use on
    it: a Scan, a read of the local file, or the item parser directly."""
    if backend.name == "sqlite":
        return load_dataset_sqlite(backend.db_path)
    if backend.name == "dynamo":
        return load_dataset(backend._table())
    return dataset_from_items(_memory_items(backend))


def audit(backend, **kwargs) -> AuditReport:
    return run_audit(load(backend), hmac_key=HMAC_KEY, **kwargs)


def stored_grant(backend) -> Grant:
    read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
    assert read.grant is not None and not read.quarantined, read.quarantine_reason
    return read.grant


def ledger(backend) -> list[PromotionRecord]:
    return backend.records.list_records(PRINCIPAL, ACTION_CLASS, None)


# ---------------------------------------------------------------------------
# The sanctioned writers (seed and re-seed are reattestation_scaffold's)
# ---------------------------------------------------------------------------


def _machine(backend) -> RungStateMachine:
    ceremony = PromotionCeremony(
        grant_store=backend.grants, promotion_record_store=backend.records
    )
    return RungStateMachine(
        ceremony=ceremony, grant_store=backend.grants, record_store=backend.records
    )


def promote(backend, level, **proposal) -> None:
    result = _machine(backend).promote(
        proposal_for(
            stored_grant(backend), target_level=level, last_safe_level=IN, **proposal
        ),
        ratifier_id="checker-bot",
    )
    assert result.status == "ratified", result.reason


def demote(backend) -> None:
    _machine(backend).demote(
        stored_grant(backend),
        DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach})),
    )


def tighten(backend) -> None:
    _machine(backend).tighten_to_in_loop(stored_grant(backend), "alice")


def lapse(backend) -> None:
    outcome = run_lapse(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=backend.grants,
        record_store=backend.records,
        now=AFTER_FAR_TERM,
    )
    assert outcome.status == "lapsed", outcome.reason


# ---------------------------------------------------------------------------
# Writes that bypass the ledger, and the ceremony that dispositions them
# ---------------------------------------------------------------------------


def rewrite_grant(backend, **changes) -> Grant:
    """Write the grant with no record beside it, HMAC-clean.

    ``put_grant`` is the stores' blind upsert. It is what `re-seed` did before
    re-attestation appended a record, and what any holder of the write
    credential and the HMAC key can still do.
    """
    rewritten = stored_grant(backend).model_copy(update=changes)
    backend.grants.put_grant(rewritten, None)
    return rewritten


def acknowledge(backend, monkeypatch, finding: AuditViolation, signer) -> int:
    """Run the real `acknowledge` ceremony for ``finding`` as CHECKER."""
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: CHECKER)
    return acknowledge_command(
        argparse.Namespace(
            rule=finding.rule,
            coordinate=finding.coordinate,
            detail=finding.detail,
            rationale="re-attested before re-attestation appended a record",
        ),
        ack_store=ack_store(backend),
        signer=signer,
        now=ACKNOWLEDGED_AT,
    )
