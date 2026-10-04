"""Tests for the owner-verdict audit records: reject_intent (#134) and flag_intent (#34).

An owner's "no" to a held intent and an owner's flag on an executed one each write
exactly one AuditRecord, outcome "rejected" / "flagged", under the STORED call's
coordinates and receipts, with two owner-verdict receipts:

  - actorDigest: a digest of the human who acted, never the identity in clear.
  - evidenceBucket: the counter period bucket the verdict's evidence write landed on.

Every refused path writes nothing. Both new fields follow the receipts discipline:
hash-covered only when present, so a pre-receipts chain still verifies byte-for-byte.

All tests use in-memory fakes; no AWS, no network.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.engine import REJECTED_BY_OWNER_REASON
from safe_agents.broker.audit import (
    ChainError,
    InMemorySink,
    hash_stored_call,
    verify_chain,
)
from safe_agents.broker.audit._chain import _hashable_fields
from safe_agents.broker.audit._hash import hash_record
from safe_agents.broker.auditor.tape_cli import render_record
from safe_agents.broker.enforcement import (
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    InMemoryStore,
    scoped_counter_key,
)
from safe_agents.broker.runtime import StubConnector
from safe_agents.broker.runtime.pep import FLAGGED_BY_OWNER_REASON
from safe_agents.broker.schemas import AuditRecord
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.tests.test_evidence_writers import (
    _EvidenceRaisingStore,
    _put_executed_intent,
)
from safe_agents.broker.tests.test_out_of_band_approval import (
    _materialize_held_intent,
    _put_expired_intent,
    _put_foreign_intent,
)
from safe_agents.broker.tests.test_runtime import (
    _PRINCIPAL,
    ENVELOPE_HASH,
    _make_grant,
    _make_pip,
    _make_runtime,
)

_OWNER = "owner:maintainer@example.com"
_OWNER_DIGEST = "sha256:" + hashlib.sha256(_OWNER.encode("utf-8")).hexdigest()
_HELD_ARGS = {"amount": 500, "to": "acct-xyz"}  # what _materialize_held_intent holds

_GOLDEN = pathlib.Path(__file__).parent / "fixtures" / "golden_prereceipts_chain.json"
# The golden fixture's last record hash, written before any receipt field existed.
_GOLDEN_LAST_HASH = (
    "sha256:dc03460efc1f8c13ad92755ed5882e0fc9d453efdaa4ed3280274a1338232483"
)


class _FlagAuditRaisingSink(InMemorySink):
    """An InMemorySink that refuses the flagged record only (an audit-store fault)."""

    def append(self, record: AuditRecord) -> None:
        if record.outcome == "flagged":
            raise RuntimeError("simulated audit sink fault")
        super().append(record)


def _runtime(store=None, sink=None):
    """A payments.transfer runtime (held by default) with caller-held stores."""
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    intent_store = InMemoryIntentStore()
    runtime, sink, _ = _make_runtime(
        grants,
        connectors={"payments": StubConnector(result={"tx_id": "tx-released"})},
        intent_store=intent_store,
        enforcement_store=store if store is not None else InMemoryStore(),
        audit_sink=sink,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
    )
    return runtime, sink, intent_store


def _by_outcome(sink, outcome: str) -> list[AuditRecord]:
    return [r for r in sink.records() if r.outcome == outcome]


def _assert_verdict_record(record: AuditRecord, *, outcome: str, reason: str, intent_id: str):
    """The fields every owner-verdict record shares, whatever the verdict."""
    assert record.outcome == outcome
    assert record.reason == reason
    assert record.decision == "require_approval"
    assert record.principal == _PRINCIPAL
    assert (record.tool, record.op) == ("payments", "transfer")
    assert record.envelopeHash == ENVELOPE_HASH
    assert record.intentId == intent_id
    assert record.approvedBy is None
    assert record.resultDigest is None
    assert record.actorDigest == _OWNER_DIGEST
    # The clear identity appears nowhere on the record, in any field.
    assert "maintainer@example.com" not in record.model_dump_json()


# ---------------------------------------------------------------------------
# reject_intent (#134)
# ---------------------------------------------------------------------------


def test_reject_cas_win_writes_one_rejected_record():
    store = InMemoryStore()
    runtime, sink, intent_store = _runtime(store)
    intent_id = _materialize_held_intent(runtime, intent_store)
    (hold,) = sink.records()

    result = runtime.reject_intent(intent_id, _OWNER)

    assert result.rejection_reason == REJECTED_BY_OWNER_REASON
    assert len(sink.records()) == 2
    record = sink.records()[-1]
    _assert_verdict_record(
        record, outcome="rejected", reason=REJECTED_BY_OWNER_REASON, intent_id=intent_id
    )
    assert record.error is None
    # Same stored call as the hold: the receipts join the verdict to the frozen bytes.
    assert record.storedCallDigest == hold.storedCallDigest
    assert record.argsDigest == hold.argsDigest
    # The bucket on the record is the one both labels were actually written under.
    assert record.evidenceBucket is not None
    for suffix in (HUMAN_OVERRIDE_SUFFIX, OBSERVATIONS_SUFFIX):
        key = scoped_counter_key(
            _PRINCIPAL, "payments", "transfer", suffix, bucket=record.evidenceBucket
        )
        assert store.read_counter(key) == 1.0, suffix
    verify_chain(sink.records())


def test_reject_labels_and_record_share_one_bucket_across_a_period_rollover(monkeypatch):
    """The labels land on the bucket the record names, even when the period turns over.

    reject_intent reads the period once and keys both label writes and the record on
    that one reading. The clock is pinned here to a period that is long over, so a
    label write that took its own reading of the clock (the default when no bucket
    is passed) would land on today's bucket while the record named the pinned one.
    """
    pinned = "20200101"
    monkeypatch.setattr(
        "safe_agents.broker.runtime.pep.current_period_bucket", lambda period: pinned
    )
    store = InMemoryStore()
    runtime, sink, intent_store = _runtime(store)
    intent_id = _materialize_held_intent(runtime, intent_store)

    runtime.reject_intent(intent_id, _OWNER)

    (record,) = _by_outcome(sink, "rejected")
    assert record.evidenceBucket == pinned
    for suffix in (HUMAN_OVERRIDE_SUFFIX, OBSERVATIONS_SUFFIX):
        on_pinned = scoped_counter_key(
            _PRINCIPAL, "payments", "transfer", suffix, bucket=pinned
        )
        on_today = scoped_counter_key(_PRINCIPAL, "payments", "transfer", suffix)
        assert on_today != on_pinned
        assert store.read_counter(on_pinned) == 1.0, suffix
        assert store.read_counter(on_today) == 0.0, suffix


def _reject_missing(runtime, intent_store):
    return "intent-does-not-exist"


def _reject_foreign(runtime, intent_store):
    _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")
    return "intent-foreign"


def _reject_expired(runtime, intent_store):
    _put_expired_intent(intent_store, "intent-expired")
    return "intent-expired"


def _reject_already_rejected(runtime, intent_store):
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.reject_intent(intent_id, _OWNER)
    return intent_id


def _reject_already_approved(runtime, intent_store):
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by=_OWNER)
    return intent_id


@pytest.mark.parametrize(
    "setup",
    [
        _reject_missing,
        _reject_foreign,
        _reject_expired,
        _reject_already_rejected,
        _reject_already_approved,
    ],
)
def test_reject_non_win_writes_no_record(setup):
    runtime, sink, intent_store = _runtime()
    intent_id = setup(runtime, intent_store)
    before = sink.records()

    result = runtime.reject_intent(intent_id, _OWNER)

    assert result.rejection_reason != REJECTED_BY_OWNER_REASON
    assert sink.records() == before


def test_reject_with_failed_label_write_still_records_without_bucket():
    """The rejection stands and is on the tape, but claims no evidence landing."""
    runtime, sink, intent_store = _runtime(_EvidenceRaisingStore(InMemoryStore()))
    intent_id = _materialize_held_intent(runtime, intent_store)

    result = runtime.reject_intent(intent_id, _OWNER)

    assert result.rejection_reason == REJECTED_BY_OWNER_REASON
    (record,) = _by_outcome(sink, "rejected")
    _assert_verdict_record(
        record, outcome="rejected", reason=REJECTED_BY_OWNER_REASON, intent_id=intent_id
    )
    assert record.evidenceBucket is None
    assert record.error == "evidence label write failed"
    verify_chain(sink.records())


# ---------------------------------------------------------------------------
# flag_intent (#34)
# ---------------------------------------------------------------------------


def test_flag_writes_one_flagged_record_on_the_execution_bucket():
    """A flag arriving long after the op lands, and records, the EXECUTION period's bucket."""
    store = InMemoryStore()
    runtime, sink, intent_store = _runtime(store)
    _put_executed_intent(intent_store, "intent-old", ts="2026-06-01T12:00:00Z")
    stored = intent_store.get_intent("intent-old").materializedRequest

    result = runtime.flag_intent("intent-old", flagged_by=_OWNER)

    assert result.rejection_reason == FLAGGED_BY_OWNER_REASON
    (record,) = sink.records()
    _assert_verdict_record(
        record, outcome="flagged", reason=FLAGGED_BY_OWNER_REASON, intent_id="intent-old"
    )
    assert record.error is None
    assert record.storedCallDigest == hash_stored_call(stored)
    assert record.evidenceBucket == "20260601"
    key = scoped_counter_key(
        _PRINCIPAL, "payments", "transfer", FALSE_ACTION_SUFFIX, bucket="20260601"
    )
    assert store.read_counter(key) == 1.0
    verify_chain(sink.records())


def test_flag_record_joins_the_hold_by_stored_call_digest():
    runtime, sink, intent_store = _runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by=_OWNER)

    runtime.flag_intent(intent_id, flagged_by=_OWNER)

    (hold,) = _by_outcome(sink, "held")
    (flagged,) = _by_outcome(sink, "flagged")
    assert flagged.storedCallDigest == hold.storedCallDigest
    verify_chain(sink.records())


def test_double_flag_writes_one_record():
    runtime, sink, intent_store = _runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by=_OWNER)

    runtime.flag_intent(intent_id, flagged_by=_OWNER)
    second = runtime.flag_intent(intent_id, flagged_by=_OWNER)

    assert second.rejection_reason == "intent already flagged"
    assert len(_by_outcome(sink, "flagged")) == 1


def _flag_not_executed(runtime, intent_store):
    return _materialize_held_intent(runtime, intent_store)


def _flag_unknown(runtime, intent_store):
    return "intent-does-not-exist"


def _flag_foreign(runtime, intent_store):
    _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")
    return "intent-foreign"


@pytest.mark.parametrize("setup", [_flag_not_executed, _flag_unknown, _flag_foreign])
def test_flag_refusal_writes_no_record(setup):
    runtime, sink, intent_store = _runtime()
    intent_id = setup(runtime, intent_store)
    before = sink.records()

    result = runtime.flag_intent(intent_id, flagged_by=_OWNER)

    assert result.rejection_reason != FLAGGED_BY_OWNER_REASON
    assert sink.records() == before


def test_flag_audit_write_failure_is_reported_and_the_count_stands():
    store = InMemoryStore()
    runtime, sink, intent_store = _runtime(store, sink=_FlagAuditRaisingSink())
    _put_executed_intent(intent_store, "intent-old", ts="2026-06-01T12:00:00Z")

    result = runtime.flag_intent("intent-old", flagged_by=_OWNER)

    assert result.executed is False
    assert result.rejection_reason.startswith("flag audit write failed")
    assert _by_outcome(sink, "flagged") == []
    key = scoped_counter_key(
        _PRINCIPAL, "payments", "transfer", FALSE_ACTION_SUFFIX, bucket="20260601"
    )
    assert store.read_counter(key) == 1.0


# ---------------------------------------------------------------------------
# chain: the new receipts are hash-covered only when present
# ---------------------------------------------------------------------------


def _verdict_tape() -> list[AuditRecord]:
    """hold, rejected, hold, executed, flagged: both owner-verdict records on one tape."""
    runtime, sink, intent_store = _runtime()
    rejected_id = _materialize_held_intent(runtime, intent_store)
    runtime.reject_intent(rejected_id, _OWNER)
    runtime.new_turn()
    flagged_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(flagged_id, approved_by=_OWNER)
    runtime.flag_intent(flagged_id, flagged_by=_OWNER)
    records = sink.records()
    assert [r.outcome for r in records] == ["held", "rejected", "held", "executed", "flagged"]
    return records


def test_tape_with_both_verdict_records_verifies():
    verify_chain(_verdict_tape())


@pytest.mark.parametrize("outcome", ["rejected", "flagged"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("actorDigest", None),
        ("evidenceBucket", None),
        ("actorDigest", "sha256:" + "0" * 64),
        ("evidenceBucket", "19700101"),
    ],
)
def test_stripping_or_altering_a_verdict_receipt_breaks_the_chain(outcome, field, value):
    records = _verdict_tape()
    index = next(i for i, r in enumerate(records) if r.outcome == outcome)
    records[index] = records[index].model_copy(update={field: value})
    with pytest.raises(ChainError):
        verify_chain(records)


def test_tape_cli_renders_the_verdict_receipts():
    rendered = {r.outcome: render_record(r) for r in _verdict_tape()}
    for outcome in ("rejected", "flagged"):
        assert f"by   {_OWNER_DIGEST}" in rendered[outcome]
        assert "bucket " in rendered[outcome]
        assert "maintainer@example.com" not in rendered[outcome]
    # A record without the receipts renders no line for them.
    assert "by   " not in rendered["executed"]
    assert "bucket " not in rendered["executed"]


def _golden_records() -> list[AuditRecord]:
    return [
        AuditRecord.model_validate(r)
        for r in json.loads(_GOLDEN.read_text(encoding="utf-8"))
    ]


def test_golden_prereceipts_chain_still_verifies():
    verify_chain(_golden_records())


def test_record_without_the_new_fields_hashes_as_before():
    """A record with no owner-verdict receipt recomputes to its pre-change hash.

    The recomputation goes through the full model dump, so the new keys ARE present
    (as None) and only the receipts filter keeps them out of the hash.
    """
    record = _golden_records()[-1]
    fields = record.model_dump(exclude={"hash"})
    assert fields["actorDigest"] is None and fields["evidenceBucket"] is None
    assert hash_record(_hashable_fields(fields)) == _GOLDEN_LAST_HASH
    assert record.hash == _GOLDEN_LAST_HASH
