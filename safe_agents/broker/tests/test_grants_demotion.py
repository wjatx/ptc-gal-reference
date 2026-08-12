"""Tests for the deterministic demotion evaluator (sa#59).

Coverage:
- evaluate_demotion_triggers: tripped trigger → should_demote=True
- evaluate_demotion_triggers: no breach → should_demote=False
- evaluate_demotion_triggers: only triggers in grant.demotionTriggers count
- evaluate_demotion_triggers: pure — same inputs, same output
- apply_demotion: level is lowered to lastSafeLevel
- apply_demotion: demotion never raises the level
- apply_demotion: already at lastSafeLevel — level stays, event is recorded
- apply_demotion: lastSafeLevel is updated to previous level (re-promotion reference)
- apply_demotion: out-of-loop previous level → lastSafeLevel not overwritten
- apply_demotion: record-only repeat breach (level unchanged) preserves lastSafeLevel
- apply_demotion: concurrent modification → DemotionConflictError
- apply_demotion: grant not in store → GrantNotFoundError (UpdateItem semantics)
- apply_demotion: called with should_demote=False → ValueError
- apply_demotion: session is passed through to store.update_grant and
  record_store.put_record (IAM role assertion)
- Demotion record (demotion-typed PromotionRecord): ratifiedBy is always
  "system:demotion-evaluator"; triggeredBy, fromLevel, toLevel, envelopeHash set
- Demotion record is appended to the ledger AFTER the grant write (safe order);
  appended even when the level was already at/below lastSafeLevel
- Trigger → demotionReason mapping: stale_confidence → pending-evidence; others → failing
- Multi-trigger reason precedence: any "failing" trigger dominates
- All three DemotionTrigger variants trip demotion when listed in grant.demotionTriggers
"""

import pytest
from unittest.mock import MagicMock

from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.grants.demotion import (
    DemotionMetrics,
    DemotionResult,
    DemotionConflictError,
    GrantNotFoundError,
    evaluate_demotion_triggers,
    apply_demotion,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-demo", skill="trade", user="alice", tier="A")
ACTION_CLASS = "payments.transfer"
TEST_HMAC_KEY = b"test-hmac-key-demotion"


def make_grant(**overrides) -> Grant:
    """Build a valid Grant with sensible defaults. put_grant recomputes the hash."""
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.out_of_loop,
        envelopeHash="sha256:env-001",
        promotedBy="alice",
        evidence="evidence-ref-001",
        ts="2026-06-28T00:00:00Z",
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    return Grant(**defaults)


def store_with_grant(grant: Grant) -> InMemoryGrantStore:
    """Return a fresh store containing the given grant (hash recomputed on write)."""
    store = InMemoryGrantStore(hmac_key=TEST_HMAC_KEY)
    store.put_grant(grant, session=None)
    return store


def read_back(store: InMemoryGrantStore, grant: Grant) -> Grant:
    """Read and return the stored grant, asserting it is not quarantined."""
    result = store.get_grant(grant.principal, grant.actionClass)
    assert result.grant is not None, "expected grant in store"
    assert not result.quarantined, f"unexpected quarantine: {result.quarantine_reason}"
    return result.grant


# ---------------------------------------------------------------------------
# evaluate_demotion_triggers — pure function, no I/O
# ---------------------------------------------------------------------------


def test_tripped_trigger_yields_should_demote_true():
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))

    result = evaluate_demotion_triggers(grant, metrics)

    assert result.should_demote is True
    assert "budget_breach" in result.triggered_by
    assert result.reason


def test_no_breach_yields_should_demote_false():
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    metrics = DemotionMetrics(tripped=frozenset())

    result = evaluate_demotion_triggers(grant, metrics)

    assert result.should_demote is False
    assert result.triggered_by == []
    assert result.reason


def test_only_configured_triggers_are_checked():
    """A tripped trigger not in grant.demotionTriggers does not cause demotion."""
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    # stale_confidence is tripped but not in the grant's configured triggers
    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.stale_confidence}))

    result = evaluate_demotion_triggers(grant, metrics)

    assert result.should_demote is False


def test_multiple_triggers_all_reported():
    grant = make_grant(
        demotionTriggers=[
            DemotionTrigger.budget_breach,
            DemotionTrigger.corroboration_failure,
        ]
    )
    metrics = DemotionMetrics(
        tripped=frozenset({
            DemotionTrigger.budget_breach,
            DemotionTrigger.corroboration_failure,
        })
    )

    result = evaluate_demotion_triggers(grant, metrics)

    assert result.should_demote is True
    assert set(result.triggered_by) == {"budget_breach", "corroboration_failure"}


@pytest.mark.parametrize("trigger", list(DemotionTrigger))
def test_each_trigger_type_fires_demotion(trigger):
    """All three DemotionTrigger variants cause demotion when configured and tripped."""
    grant = make_grant(demotionTriggers=[trigger])
    metrics = DemotionMetrics(tripped=frozenset({trigger}))

    result = evaluate_demotion_triggers(grant, metrics)

    assert result.should_demote is True
    assert trigger.value in result.triggered_by


def test_evaluate_is_pure_same_result_repeated():
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))

    r1 = evaluate_demotion_triggers(grant, metrics)
    r2 = evaluate_demotion_triggers(grant, metrics)

    assert r1.should_demote == r2.should_demote
    assert r1.triggered_by == r2.triggered_by
    assert r1.reason == r2.reason


# ---------------------------------------------------------------------------
# apply_demotion — level lowered to lastSafeLevel
# ---------------------------------------------------------------------------


def test_demotion_lowers_level_to_last_safe_level():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)

    updated, record = apply_demotion(
        stored,
        result,
        store=store,
        record_store=InMemoryPromotionRecordStore(),
        session=None,
        ts="2026-06-28T01:00:00+00:00",
    )

    assert updated.level == AutonomyLevel.on_loop
    assert record.fromLevel == AutonomyLevel.out_of_loop
    assert record.toLevel == AutonomyLevel.on_loop


def test_demotion_persists_to_store():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    persisted = read_back(store, grant)
    assert persisted.level == AutonomyLevel.on_loop


def test_demotion_sets_demotion_reason():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        demotionReason=None,
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, record = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    assert updated.demotionReason == "failing"
    assert record.demotionReason == "failing"


@pytest.mark.parametrize(
    "trigger,expected_reason",
    [
        (DemotionTrigger.stale_confidence, "pending-evidence"),
        (DemotionTrigger.corroboration_failure, "failing"),
        (DemotionTrigger.budget_breach, "failing"),
        (DemotionTrigger.false_action, "failing"),
    ],
    ids=["stale_confidence", "corroboration_failure", "budget_breach", "false_action"],
)
def test_trigger_to_demotion_reason_mapping(trigger, expected_reason):
    """stale_confidence maps to pending-evidence (label-free drift voids the
    certification — the model isn't proven failing); the other two triggers
    indicate an active breach and map to failing."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[trigger],
        demotionReason=None,
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({trigger}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, record = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    assert updated.demotionReason == expected_reason
    assert record.demotionReason == expected_reason


def test_demotion_from_on_loop_to_in_loop():
    grant = make_grant(
        level=AutonomyLevel.on_loop,
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.corroboration_failure],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.corroboration_failure}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, _ = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    assert updated.level == AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# apply_demotion — demotion never raises a level
# ---------------------------------------------------------------------------


def test_demotion_does_not_raise_level_when_already_at_safe_rung():
    """If level == lastSafeLevel, the level stays unchanged — never increases."""
    grant = make_grant(
        level=AutonomyLevel.in_loop,
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, record = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    # Already at lastSafeLevel — level must not go anywhere
    assert updated.level == AutonomyLevel.in_loop
    assert record.fromLevel == AutonomyLevel.in_loop
    assert record.toLevel == AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# apply_demotion — lastSafeLevel handling
# ---------------------------------------------------------------------------


def test_last_safe_level_updated_to_previous_level_when_valid():
    """After demotion from on-loop → in-loop, lastSafeLevel records on-loop."""
    grant = make_grant(
        level=AutonomyLevel.on_loop,
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, _ = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    # Previous level (on-loop) is a valid lastSafeLevel — record it
    assert updated.lastSafeLevel == AutonomyLevel.on_loop


def test_last_safe_level_not_overwritten_when_previous_level_is_out_of_loop():
    """Demoting from out-of-loop: lastSafeLevel stays as configured (can't store out-of-loop)."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, _ = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    # out-of-loop cannot be stored as lastSafeLevel; original value preserved
    assert updated.lastSafeLevel == AutonomyLevel.on_loop


def test_record_only_repeat_breach_preserves_last_safe_level():
    """A repeat breach on an already-demoted grant (level=in-loop below
    lastSafeLevel=on-loop) is record-only: the level stays put AND the
    on-loop re-promotion reference must not be clobbered down to in-loop."""
    grant = make_grant(
        level=AutonomyLevel.in_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, record = apply_demotion(
        stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None
    )

    assert updated.level == AutonomyLevel.in_loop  # unchanged — never raised
    assert updated.lastSafeLevel == AutonomyLevel.on_loop  # preserved, not in-loop
    assert record.fromLevel == AutonomyLevel.in_loop
    assert record.toLevel == AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# apply_demotion — DemotionRecord fields
# ---------------------------------------------------------------------------


def test_demotion_record_ratified_by_system():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    _, record = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    assert record.ratifiedBy == DEMOTION_RATIFIER


def test_demotion_record_triggered_by_matches_result():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach, DemotionTrigger.stale_confidence],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach, DemotionTrigger.stale_confidence}))
    result = evaluate_demotion_triggers(stored, metrics)
    _, record = apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)

    assert set(record.triggeredBy) == {"budget_breach", "stale_confidence"}


# ---------------------------------------------------------------------------
# apply_demotion — error cases
# ---------------------------------------------------------------------------


def test_apply_demotion_raises_value_error_on_no_demote():
    grant = make_grant()
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    no_demote = DemotionResult(should_demote=False, triggered_by=[], reason="no breach")

    with pytest.raises(ValueError, match="should_demote=False"):
        apply_demotion(
            stored, no_demote, store=store, record_store=InMemoryPromotionRecordStore(), session=None
        )


def test_apply_demotion_raises_grant_not_found_when_grant_missing():
    grant = make_grant()
    empty_store = InMemoryGrantStore(hmac_key=TEST_HMAC_KEY)  # nothing stored

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(grant, metrics)

    with pytest.raises(GrantNotFoundError):
        apply_demotion(
            grant, result, store=empty_store, record_store=InMemoryPromotionRecordStore(), session=None
        )


def test_apply_demotion_raises_conflict_on_concurrent_modification():
    """Hash changed between evaluate and apply → DemotionConflictError."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    # Evaluate with the stored grant
    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)

    # Simulate a concurrent modification: overwrite with a different grant
    modified = stored.model_copy(update={"ownerId": "mallory", "ts": "2026-06-28T02:00:00Z"})
    store.put_grant(modified, session=None)

    # apply_demotion sees the hash changed → conflict
    with pytest.raises(DemotionConflictError):
        apply_demotion(stored, result, store=store, record_store=InMemoryPromotionRecordStore(), session=None)


# ---------------------------------------------------------------------------
# apply_demotion — session (IAM role) passthrough
# ---------------------------------------------------------------------------


def test_demotion_session_passed_to_stores():
    """apply_demotion passes the session to the atomic record+grant write
    (demotion IAM role assertion)."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    mock_session = MagicMock(name="demotion-role-session")

    # Wrap the atomic write to capture the session arg without breaking the store
    original_write = store.write_record_and_grant
    grant_sessions: list = []
    record_sessions: list = []

    def capturing_write(record, g, record_store_arg, session=None, *, signature=None, expected=None):
        grant_sessions.append(session)
        record_sessions.append(session)
        original_write(
            record, g, record_store_arg, None, signature=signature, expected=expected
        )

    store.write_record_and_grant = capturing_write

    record_store = InMemoryPromotionRecordStore()

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)
    apply_demotion(stored, result, store=store, record_store=record_store, session=mock_session)

    assert grant_sessions == [mock_session]
    assert record_sessions == [mock_session]


# ---------------------------------------------------------------------------
# apply_demotion — no-op path leaves grant unchanged in store
# ---------------------------------------------------------------------------


def test_no_breach_does_not_modify_grant():
    """When no triggers are breached, the grant in the store is untouched."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    before = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset())  # nothing tripped
    result = evaluate_demotion_triggers(before, metrics)

    assert result.should_demote is False
    # Do not call apply_demotion; verify store is unchanged
    after = read_back(store, grant)
    assert after.level == before.level
    assert after == before


# ---------------------------------------------------------------------------
# apply_demotion — the demotion-typed PromotionRecord on the ledger
# ---------------------------------------------------------------------------


def _demote_with_ledger(grant, tripped, *, ts=None):
    """Run a full evaluate→apply against fresh stores; return (updated, record, record_store)."""
    store = store_with_grant(grant)
    stored = read_back(store, grant)
    record_store = InMemoryPromotionRecordStore()

    metrics = DemotionMetrics(tripped=frozenset(tripped))
    result = evaluate_demotion_triggers(stored, metrics)
    updated, record = apply_demotion(
        stored, result, store=store, record_store=record_store, session=None, ts=ts
    )
    return updated, record, record_store


def test_demotion_record_shape():
    """The ledger record is a demotion-typed PromotionRecord carrying the full trail."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        envelopeHash="sha256:env-001",
    )
    _, record, _ = _demote_with_ledger(
        grant, {DemotionTrigger.budget_breach}, ts="2026-06-28T01:00:00+00:00"
    )

    assert record.recordType == "demotion"
    assert record.proposedBy == DEMOTION_RATIFIER
    assert record.ratifiedBy == DEMOTION_RATIFIER
    assert record.envelopeHash == "sha256:env-001"
    assert record.triggeredBy == ["budget_breach"]
    assert record.demotionReason == "failing"
    assert record.predicate is None
    assert record.ts == "2026-06-28T01:00:00+00:00"
    assert record.evidence  # the evaluator's reason string rides as evidence


def test_demotion_record_appended_to_ledger():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    _, record, record_store = _demote_with_ledger(grant, {DemotionTrigger.budget_breach})

    assert record_store.records == [record]


def test_level_unchanged_still_appends_record():
    """Already at/below lastSafeLevel: the level stays, but the breach event
    itself must land on the ledger."""
    grant = make_grant(
        level=AutonomyLevel.in_loop,
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    updated, record, record_store = _demote_with_ledger(grant, {DemotionTrigger.budget_breach})

    assert updated.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 1
    assert record.fromLevel is AutonomyLevel.in_loop
    assert record.toLevel is AutonomyLevel.in_loop


def test_failed_record_leg_cancels_the_demotion():
    """Atomic record+grant (#244): a failing ledger leg cancels the WHOLE unit
    — the grant stays at its prior level with no ledger hole, and the runner
    retries with a fresh read (superseding the old grant-first ordering)."""

    class _ExplodingRecordStore(InMemoryPromotionRecordStore):
        def put_record(self, record, session=None, signature=None):
            raise RuntimeError("ledger append failed")

    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
    )
    store = store_with_grant(grant)
    stored = read_back(store, grant)

    metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    result = evaluate_demotion_triggers(stored, metrics)

    with pytest.raises(RuntimeError, match="ledger append failed"):
        apply_demotion(
            stored, result, store=store, record_store=_ExplodingRecordStore(), session=None
        )

    # Nothing written: the level did NOT move (both-or-nothing).
    persisted = read_back(store, grant)
    assert persisted.level is AutonomyLevel.out_of_loop


@pytest.mark.parametrize(
    "triggers,expected_reason",
    [
        # stale_confidence declared first: an actually-blown bound (budget_breach)
        # still dominates the lapsed certification.
        ([DemotionTrigger.stale_confidence, DemotionTrigger.budget_breach], "failing"),
        ([DemotionTrigger.stale_confidence, DemotionTrigger.corroboration_failure], "failing"),
        # All fired triggers pending-evidence → pending-evidence.
        ([DemotionTrigger.stale_confidence], "pending-evidence"),
    ],
    ids=["stale+budget", "stale+corroboration", "stale-only"],
)
def test_multi_trigger_reason_precedence(triggers, expected_reason):
    """If ANY fired trigger maps to 'failing', the reason is 'failing'; only when
    all fired triggers are 'pending-evidence' is the reason 'pending-evidence' —
    regardless of declaration order."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=triggers,
    )
    updated, record, _ = _demote_with_ledger(grant, set(triggers))

    assert updated.demotionReason == expected_reason
    assert record.demotionReason == expected_reason
