"""Shared harness for the re-attestation suite (#164; GAL §4.3, §5.2, §6.6, §6.8, GAL-15).

`re-seed` used to rewrite a grant's envelopeHash, promotedBy and ts and append
nothing, so the signed ledger could not say who rewrote the grant beside it.
It now writes a `reattestation`-typed record in the same atomic unit. Each
clause below is one property of that write, pinned where it is enforced, on all
three store backends wherever a store is involved (the harness is the grant
store differential suite's).

| Clause | Guarantee |
|---|---|
| **R1** | Atomic: a re-attested grant and exactly one `reattestation` record commit together. A refused record leg leaves the grant's stored bytes unchanged; a conflicting grant leg leaves no record. |
| **R2** | Clock: grant and record carry one `ts`, taken from the ledger clock read for that coordinate, strictly after every record already there, also when the wall clock reads earlier. The clock itself does not pass over the type: the next write is stamped after a `reattestation`. |
| **R3** | Shape: `fromLevel == toLevel`, non-null; no predicate, triggers, demotion reason or term. A record breaking the shape is refused at construction, which is also where every reader parses one. |
| **R4** | Signing role: issuer-signed, verified under the issuer role, refused under the evaluator's; the `re-seed` command resolves the issuer's signer, and with none it refuses up front and writes nothing, with no unsigned override. (The per-type matrix, including the unsigned-with-an-epoch finding, is `test_record_signing_roles.py`.) |
| **R5** | Grant delta: only `envelopeHash`, `promotedBy` and `ts` change. The stores refuse a `reattestation` write that moves anything else, that creates a grant, or whose record does not describe the grant beside it. |
| **R6** | Readers pass over the type: the audit's derived level, earning-record search, term rule and evaluator-continuity walk, the orphan check and the runner's same-day dedupe all read the ledger as it stood immediately before the record. |
| **R7** | Dwell is measured from the ledger and a `reattestation` record does not restart it. |
| **R8** | No other same-level write: the state machine's write surface is a closed list, no store carries a record-less update, and shipped code names a record-less grant write only at two known sites (a create, and the prototype seed mode tracked as #27). |
| **R9** | `re-seed`'s refusals hold and write nothing: a store-layer quarantine, a missing grant, and a grant already under the in-force hash (a skip, with no record). |

The clauses are pinned in five modules, split so a failure is easy to isolate:
R1 to R3 in test_grants_reattestation_write.py, R4 in
test_grants_reattestation_signing.py, R5 in test_grants_reattestation_delta.py,
R6 and R7 in test_grants_reattestation_readers.py, R8 and R9 in
test_grants_reattestation_surface.py. This module holds what they share: the
fixtures, the constants, the re-seed drivers and the record builders. It is not
collected itself.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import sys

from safe_agents.broker.grants import commands
from safe_agents.broker.grants.audit import (
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.commands import (
    build_reattestation,
    reseed_command,
    seed_command,
)
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.store import canonical_grant_payload
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.tests import test_grant_store_differential as differential
from safe_agents.broker.tests.test_grant_store_differential import (
    ACTION_CLASS,
    PRINCIPAL,
    make_grant,
)
from safe_agents.broker.tests.test_record_signing_roles import _keypair
from safe_agents.broker.tests.test_record_signing_roles import roles as _roles_fixture

# The three-backend harness and the two-key fixture, reused as they stand. A
# test module re-binds each by name so pytest resolves it there too.
backend = differential.backend
roles = _roles_fixture

IN, ON, OUT = AutonomyLevel.in_loop, AutonomyLevel.on_loop, AutonomyLevel.out_of_loop
OLD_HASH = "sha256:env-old"
NEW_HASH = "sha256:env-new"
SEEDER = "arn:aws:sts::111111111111:assumed-role/PromotionRole/seeder"
OPERATOR = "arn:aws:sts::111111111111:assumed-role/PromotionRole/reattester"
SEEDED_AT = datetime.datetime(2026, 7, 25, 12, 0, tzinfo=datetime.UTC)
RESEEDED_AT = datetime.datetime(2026, 7, 26, 9, 0, tzinfo=datetime.UTC)
TERM = "2026-12-01T00:00:00+00:00"
OTHER_CLASS = "email.archive"
STAMP = "2031-01-01T00:00:00.000007+00:00"  # nothing a wall clock would give

# re-seed refuses to run without an issuer signer (R4), so a test that is not
# about the signature still hands it a real one. The tests that verify a
# signature pass the `roles` fixture's signer, whose public key they hold.
ISSUER_SIGNER, _ = _keypair("issuer:reattestation-test")


def _writer_pair():
    """build_reattestation over a grant on which every field a re-attestation
    must leave alone holds a value that a wrong write would visibly move."""
    before = make_grant(
        level=ON,
        lastSafeLevel=IN,
        envelopeHash=OLD_HASH,
        promotedBy=SEEDER,
        evidence="evidence-the-level-was-earned-on",
        demotionReason="pending-evidence",
        demotionTriggers=["budget_breach"],
        certifiedUntil=TERM,
    )
    after, record = build_reattestation(
        before, caller=OPERATOR, envelope_hash=NEW_HASH, ts=STAMP
    )
    return before, after, record


def _as(monkeypatch, arn: str) -> None:
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: arn)


def _seed(backend, monkeypatch, **overrides):
    """One HMAC-clean grant under OLD_HASH with its bootstrap record."""
    _as(monkeypatch, SEEDER)
    template = make_grant(**{"envelopeHash": OLD_HASH, **overrides})
    assert seed_command(
        grant_store=backend.grants, record_store=backend.records, grants=[template], now=SEEDED_AT
    ) == 0
    return backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)


def _reseed(
    backend,
    monkeypatch,
    *,
    now=RESEEDED_AT,
    signer=ISSUER_SIGNER,
    envelope_hash=NEW_HASH,
    classes=(ACTION_CLASS,),
) -> tuple[int, str]:
    """Run re-seed as OPERATOR; return (exit code, what it said on stderr).

    stderr is captured so an assertion on the exit code can say WHY re-seed
    refused (the store guard names the field it objected to), then passed on
    so capsys still sees it.
    """
    _as(monkeypatch, OPERATOR)
    said = io.StringIO()
    with contextlib.redirect_stderr(said):
        rc = reseed_command(
            grant_store=backend.grants,
            record_store=backend.records,
            principal=PRINCIPAL,
            granted_classes=list(classes),
            envelope_hash=envelope_hash,
            signer=signer,
            now=now,
        )
    sys.stderr.write(said.getvalue())
    return rc, said.getvalue()


def _reattest(backend, monkeypatch, **kwargs) -> None:
    """A re-seed that must re-attest. If it exits non-zero, the pair it built
    was refused by its own store guard, which is a writer defect."""
    rc, said = _reseed(backend, monkeypatch, **kwargs)
    assert rc == 0, (
        "re-seed refused its own write. The grant and record it builds must be "
        "a re-attestation and nothing more (I2 one ts, I3 the record's shape, "
        f"I5 the three-field grant delta). It said: {said.strip()}"
    )


def _refused(backend, monkeypatch, why: str, **kwargs) -> str:
    """A re-seed that must fail: exit 1, never a success or a skip."""
    rc, said = _reseed(backend, monkeypatch, **kwargs)
    assert rc == 1, f"{why}: re-seed exited {rc}, so the refusal was reported as success or a skip"
    return said


def _ledger(backend) -> list[PromotionRecord]:
    return backend.records.list_records(PRINCIPAL, ACTION_CLASS, None)


def _reattestations(backend) -> list[PromotionRecord]:
    return [r for r in _ledger(backend) if r.recordType == "reattestation"]


def _reattestation(**overrides) -> PromotionRecord:
    defaults = dict(
        recordType="reattestation",
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=ON,
        toLevel=ON,
        evidence="envelope re-attestation",
        predicate=None,
        proposedBy=OPERATOR,
        ratifiedBy=OPERATOR,
        envelopeHash=NEW_HASH,
        ts=RESEEDED_AT.isoformat(),
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


def _record(record_type: str, ts: str, **fields) -> PromotionRecord:
    defaults = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        evidence="evidence-ref",
        proposedBy="operator",
        ratifiedBy="operator",
        envelopeHash=OLD_HASH,
        ts=ts,
    )
    defaults.update(fields)
    return PromotionRecord(**defaults)


def _bootstrap(ts="2026-07-01T00:00:00+00:00", to_level=IN) -> PromotionRecord:
    return _record("bootstrap", ts, fromLevel=None, toLevel=to_level)


def _promotion(ts="2026-07-02T00:00:00+00:00", **fields) -> PromotionRecord:
    return _record(
        "promotion",
        ts,
        **{
            "fromLevel": IN,
            "toLevel": ON,
            "predicate": "passed",
            "ratifiedBy": "checker",
            **fields,
        },
    )


def _demotion(ts, from_level, to_level) -> PromotionRecord:
    return _record(
        "demotion",
        ts,
        fromLevel=from_level,
        toLevel=to_level,
        proposedBy=DEMOTION_RATIFIER,
        ratifiedBy=DEMOTION_RATIFIER,
        triggeredBy=["budget_breach"],
        demotionReason="failing",
    )


def _planted(ts, level) -> PromotionRecord:
    return _record("reattestation", ts, fromLevel=level, toLevel=level, envelopeHash=NEW_HASH)


def _audit(grant, records) -> set[str]:
    dataset = AuditDataset(
        grants=(AuditedGrant(grant=grant, raw_data=canonical_grant_payload(grant)),)
        if grant is not None
        else (),
        records=tuple(
            AuditedRecord(record=r, raw_data=canonical_record_payload(r)) for r in records
        ),
    )
    return {v.rule for v in run_audit(dataset).violations}
