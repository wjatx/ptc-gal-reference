"""Tests for the out-of-band demotion runner (sa#59).

Coverage:
- metrics_from_signals: matching signal → tripped; mismatched principal (any
  field of the full tuple) or action_class ignored; multi-signal collection
- derive_budget_breach: below / at / above tolerance (the PIP's >= comparison);
  the EXACT scoped_counter_key the PEP meters is the key read; signal field
  population mirrors _emit_demotion_signal; injectable now stamps period/ts
- run_demotion outcome matrix: no-grant / quarantined / no-breach / deduped /
  demoted / conflict (lost write race AND duplicate ledger key) — every path a
  typed RunnerOutcome, no silent None
- record-only same-day dedupe (#191): a repeat breach already recorded today
  returns "deduped" with ZERO writes; a new UTC day, a level-changing
  demotion, or a same-day record for a different trigger/level all still write
- determinism: same inputs twice → equal outcomes
- session/ts passthrough to apply_demotion
- the runner module imports no model/LLM machinery
- CLI plumbing: _build_stores / _build_enforcement_store env sourcing +
  RunnerConfigError on missing config; _parse_args budget-arg coupling
"""

import datetime
import inspect

import pytest

from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.store import GrantUpdateConflictError, InMemoryGrantStore
from safe_agents.broker.grants import runner as runner_module
from safe_agents.broker.grants.runner import (
    FALSE_ACTION_WINDOW_DAYS,
    RunnerConfigError,
    RunnerOutcome,
    _build_enforcement_store,
    _build_stores,
    _parse_args,
    derive_budget_breach,
    derive_corroboration_failure,
    derive_false_action,
    derive_stale_confidence,
    metrics_from_signals,
    run_demotion,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    CorroborationRecord,
    DemotionSignal,
)
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER


# ---------------------------------------------------------------------------
# Shared fixtures (mirrors test_grants_demotion.py)
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-demo", skill="trade", user="alice", tier="A")
ACTION_CLASS = "payments.transfer"
TEST_HMAC_KEY = b"test-hmac-key-runner"
NOW = datetime.datetime(2026, 7, 12, 12, 0, 0, tzinfo=datetime.UTC)


def make_signal(**overrides) -> DemotionSignal:
    defaults = dict(
        trigger=DemotionTrigger.budget_breach,
        principal=PRINCIPAL,
        action_class=ACTION_CLASS,
        period="20260712",
        detail="error budget breached: spent 0.6000 >= tolerance 0.5000",
        ts=NOW.isoformat(),
    )
    defaults.update(overrides)
    return DemotionSignal(**defaults)


def make_grant(**overrides) -> Grant:
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
    store = InMemoryGrantStore(hmac_key=TEST_HMAC_KEY)
    store.put_grant(grant, session=None)
    return store


# ---------------------------------------------------------------------------
# metrics_from_signals — pure
# ---------------------------------------------------------------------------


def test_matching_signal_trips_its_trigger():
    metrics = metrics_from_signals(
        [make_signal()], principal=PRINCIPAL, action_class=ACTION_CLASS
    )
    assert metrics.tripped == frozenset({DemotionTrigger.budget_breach})


def test_no_signals_yields_empty_metrics():
    metrics = metrics_from_signals([], principal=PRINCIPAL, action_class=ACTION_CLASS)
    assert metrics.tripped == frozenset()


def test_mismatched_action_class_ignored():
    metrics = metrics_from_signals(
        [make_signal(action_class="notify.send")],
        principal=PRINCIPAL,
        action_class=ACTION_CLASS,
    )
    assert metrics.tripped == frozenset()


@pytest.mark.parametrize(
    "field,value",
    [
        ("agentId", "agent-other"),
        ("skill", "notify"),
        ("user", "mallory"),
        ("tier", "B"),
    ],
)
def test_principal_match_is_full_tuple(field, value):
    """A signal whose principal differs in ANY of the four fields is a different
    grant coordinate — ignored, not matched on agentId alone."""
    other = PRINCIPAL.model_copy(update={field: value})
    metrics = metrics_from_signals(
        [make_signal(principal=other)], principal=PRINCIPAL, action_class=ACTION_CLASS
    )
    assert metrics.tripped == frozenset()


def test_multiple_signals_collected_and_nonmatching_filtered():
    signals = [
        make_signal(trigger=DemotionTrigger.budget_breach),
        make_signal(trigger=DemotionTrigger.stale_confidence),
        make_signal(trigger=DemotionTrigger.budget_breach),  # duplicate collapses
        make_signal(
            trigger=DemotionTrigger.corroboration_failure, action_class="other.class"
        ),
    ]
    metrics = metrics_from_signals(
        signals, principal=PRINCIPAL, action_class=ACTION_CLASS
    )
    assert metrics.tripped == frozenset(
        {DemotionTrigger.budget_breach, DemotionTrigger.stale_confidence}
    )


# ---------------------------------------------------------------------------
# derive_budget_breach — the PIP's derivation, reused exactly
# ---------------------------------------------------------------------------


def _counter_store_with(principal, tool, op, spent: float) -> InMemoryStore:
    """Meter `spent` onto the EXACT key the PEP uses — asserting, by construction,
    that derive_budget_breach reads through the same scoped_counter_key."""
    store = InMemoryStore()
    if spent:
        key = scoped_counter_key(principal, tool, op, "error_budget")
        assert store.try_increment_counter(key, spent, cap=1e9)
    return store


def test_below_tolerance_returns_none():
    store = _counter_store_with(PRINCIPAL, "payments", "transfer", 0.49)
    signal = derive_budget_breach(
        PRINCIPAL, "payments", "transfer",
        enforcement_store=store, tolerance=0.5, now=NOW,
    )
    assert signal is None


def test_at_tolerance_breaches():
    """spent == tolerance breaches — the same >= comparison the PIP uses."""
    store = _counter_store_with(PRINCIPAL, "payments", "transfer", 0.5)
    signal = derive_budget_breach(
        PRINCIPAL, "payments", "transfer",
        enforcement_store=store, tolerance=0.5, now=NOW,
    )
    assert signal is not None
    assert signal.trigger is DemotionTrigger.budget_breach


def test_above_tolerance_breaches_with_mirrored_fields():
    store = _counter_store_with(PRINCIPAL, "payments", "transfer", 0.75)
    signal = derive_budget_breach(
        PRINCIPAL, "payments", "transfer",
        enforcement_store=store, tolerance=0.5, now=NOW,
    )
    assert signal is not None
    # field population mirrors pep._emit_demotion_signal
    assert signal.principal == PRINCIPAL
    assert signal.action_class == "payments.transfer"
    assert signal.period == "20260712"
    assert signal.ts == NOW.isoformat()
    assert signal.detail == "error budget breached: spent 0.7500 >= tolerance 0.5000"


def test_reads_exactly_the_scoped_counter_key():
    """A counter metered under any OTHER key must not register as a breach."""
    store = InMemoryStore()
    wrong_key = scoped_counter_key(PRINCIPAL, "payments", "transfer", "counter")
    assert store.try_increment_counter(wrong_key, 5.0, cap=1e9)
    other_principal_key = scoped_counter_key(
        PRINCIPAL.model_copy(update={"user": "mallory"}),
        "payments", "transfer", "error_budget",
    )
    assert store.try_increment_counter(other_principal_key, 5.0, cap=1e9)

    assert (
        derive_budget_breach(
            PRINCIPAL, "payments", "transfer",
            enforcement_store=store, tolerance=0.5, now=NOW,
        )
        is None
    )


def test_untouched_counter_reads_zero_and_no_breach():
    signal = derive_budget_breach(
        PRINCIPAL, "payments", "transfer",
        enforcement_store=InMemoryStore(), tolerance=0.5, now=NOW,
    )
    assert signal is None


# ---------------------------------------------------------------------------
# derive_false_action — the #193 owner-flag re-derivation (ships OFF at the grant)
# ---------------------------------------------------------------------------


def _false_action_store_with(
    principal, tool, op, count: float, *, day: str = "20260712"
) -> InMemoryStore:
    """Meter `count` onto the EXACT :false_action key the PEP writes for `day` —
    asserting, by construction, that derive_false_action reads through scoped_counter_key.

    `day` defaults to NOW's UTC day so the window anchored on NOW (real-time default
    aside) includes it; a /flag back-dates to the op's execution day, so tests that
    exercise the window pass an EARLIER day explicitly."""
    store = InMemoryStore()
    if count:
        key = scoped_counter_key(principal, tool, op, "false_action", day=day)
        assert store.try_increment_counter(key, count, cap=1e9)
    return store


def test_false_action_no_flag_returns_none():
    store = _false_action_store_with(PRINCIPAL, "payments", "transfer", 0)
    assert (
        derive_false_action(
            PRINCIPAL, "payments", "transfer", enforcement_store=store, now=NOW
        )
        is None
    )


def test_false_action_one_flag_suffices():
    """One authenticated flag (count >= 1) is a sufficient trigger — the ease
    gradient. Mirrors the budget_breach >= comparison but with a fixed threshold."""
    store = _false_action_store_with(PRINCIPAL, "payments", "transfer", 1)
    signal = derive_false_action(
        PRINCIPAL, "payments", "transfer", enforcement_store=store, now=NOW
    )
    assert signal is not None
    assert signal.trigger is DemotionTrigger.false_action
    assert signal.principal == PRINCIPAL
    assert signal.action_class == "payments.transfer"
    assert signal.period == "20260712"
    assert signal.ts == NOW.isoformat()
    assert "count 1 >= 1" in signal.detail


def test_false_action_reads_exactly_the_scoped_counter_key():
    """A flag metered under any OTHER key (wrong suffix, wrong principal) must not
    register — the derivation is principal+op+UTC-day scoped like the meter."""
    store = InMemoryStore()
    wrong_suffix = scoped_counter_key(PRINCIPAL, "payments", "transfer", "error_budget")
    assert store.try_increment_counter(wrong_suffix, 5.0, cap=1e9)
    other_principal_key = scoped_counter_key(
        PRINCIPAL.model_copy(update={"user": "mallory"}),
        "payments", "transfer", "false_action",
    )
    assert store.try_increment_counter(other_principal_key, 5.0, cap=1e9)

    assert (
        derive_false_action(
            PRINCIPAL, "payments", "transfer", enforcement_store=store, now=NOW
        )
        is None
    )


def test_false_action_flag_on_prior_day_triggers_on_run_day():
    """A /flag back-dates false_action to the op's ORIGINAL day. A point-read of the
    run day would miss it; the day-WINDOW sum catches a flag written on D-1 when the
    runner executes on D."""
    prior_day = "20260711"  # D-1 relative to NOW (2026-07-12)
    store = _false_action_store_with(
        PRINCIPAL, "payments", "transfer", 1, day=prior_day
    )
    # A point read of the run day alone (window_periods=1) misses the back-dated flag.
    assert (
        derive_false_action(
            PRINCIPAL,
            "payments",
            "transfer",
            enforcement_store=store,
            window_periods=1,
            now=NOW,
        )
        is None
    )
    # The default multi-day window sums D-1 into the run day → the flag triggers.
    signal = derive_false_action(
        PRINCIPAL, "payments", "transfer", enforcement_store=store, now=NOW
    )
    assert signal is not None
    assert signal.trigger is DemotionTrigger.false_action
    assert signal.period == "20260712"


# ---------------------------------------------------------------------------
# derive_stale_confidence / derive_corroboration_failure — the #192 typed-evidence
# input paths (detector/producer stays consumer-side; these consume as given)
# ---------------------------------------------------------------------------


def make_artifact(*, stale: bool) -> ConfidenceArtifact:
    return ConfidenceArtifact(
        confidence=0.9,
        error_prob=0.1,
        evidence={"method": "conformal", "coverage": 0.9, "threshold": 0.42,
                  "calibration_size": 500},
        stale=stale,
        computed_at=NOW.isoformat(),
    )


def test_stale_confidence_fresh_artifact_returns_none():
    assert (
        derive_stale_confidence(
            PRINCIPAL, "payments", "transfer", artifact=make_artifact(stale=False), now=NOW
        )
        is None
    )


def test_stale_confidence_stale_artifact_signals_with_mirrored_fields():
    signal = derive_stale_confidence(
        PRINCIPAL, "payments", "transfer", artifact=make_artifact(stale=True), now=NOW
    )
    assert signal is not None
    assert signal.trigger is DemotionTrigger.stale_confidence
    assert signal.principal == PRINCIPAL
    assert signal.action_class == "payments.transfer"
    assert signal.period == "20260712"
    assert "conformal" in signal.detail


def make_corroboration(*, k: int = 2, n: int = 3, agreeing: int, **overrides) -> CorroborationRecord:
    defaults = dict(
        k=k, n=n, agreeing=agreeing, computed_at=NOW.isoformat()
    )
    defaults.update(overrides)
    return CorroborationRecord(**defaults)


def test_corroboration_quorum_met_returns_none():
    for agreeing in (2, 3):  # at and above quorum
        assert (
            derive_corroboration_failure(
                PRINCIPAL,
                "payments",
                "transfer",
                record=make_corroboration(agreeing=agreeing),
                now=NOW,
            )
            is None
        )


def test_corroboration_below_quorum_signals_with_mirrored_fields():
    signal = derive_corroboration_failure(
        PRINCIPAL,
        "payments",
        "transfer",
        record=make_corroboration(agreeing=1, stale_sources=1),
        now=NOW,
    )
    assert signal is not None
    assert signal.trigger is DemotionTrigger.corroboration_failure
    assert signal.principal == PRINCIPAL
    assert signal.action_class == "payments.transfer"
    assert signal.period == "20260712"
    assert "1/3" in signal.detail and "k=2" in signal.detail


def test_stale_confidence_demotes_when_grant_opts_in_with_pending_evidence_reason():
    """stale_confidence alone maps to "pending-evidence" — a lapsed certification,
    not a proven failure (grant-lifecycle §Demotion reason mapping)."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.stale_confidence],
    )
    store = store_with_grant(grant)
    signal = derive_stale_confidence(
        PRINCIPAL, "payments", "transfer", artifact=make_artifact(stale=True), now=NOW
    )

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[signal],
        ts="2026-07-12T12:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert outcome.triggered_by == ("stale_confidence",)
    assert outcome.updated_grant.level is AutonomyLevel.on_loop
    assert outcome.record.demotionReason == "pending-evidence"


def test_corroboration_failure_ships_off_grant_without_trigger_untouched():
    """Structural ships-OFF parity with the other non-floor triggers: a grant not
    listing corroboration_failure is untouched by its signal."""
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    store = store_with_grant(grant)

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[
            derive_corroboration_failure(
                PRINCIPAL,
                "payments",
                "transfer",
                record=make_corroboration(agreeing=0),
                now=NOW,
            )
        ],
    )

    assert outcome.status == "no-breach"
    assert store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.out_of_loop


def test_corroboration_failure_demotes_with_failing_reason():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.corroboration_failure],
    )
    store = store_with_grant(grant)

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[
            derive_corroboration_failure(
                PRINCIPAL,
                "payments",
                "transfer",
                record=make_corroboration(agreeing=1),
                now=NOW,
            )
        ],
        ts="2026-07-12T12:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert outcome.triggered_by == ("corroboration_failure",)
    assert outcome.record.demotionReason == "failing"


# ---------------------------------------------------------------------------
# run_demotion — outcome matrix
# ---------------------------------------------------------------------------


def test_run_demotion_no_grant():
    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=InMemoryGrantStore(hmac_key=TEST_HMAC_KEY),
        record_store=InMemoryPromotionRecordStore(),
        signals=[make_signal()],
    )
    assert outcome.status == "no-grant"
    assert outcome.updated_grant is None
    assert outcome.record is None
    assert outcome.reason


def test_run_demotion_quarantined_grant_not_demoted():
    grant = make_grant()
    store = store_with_grant(grant)
    # Tamper with the stored raw dict without recomputing the hash — the store
    # quarantines it on read (HMAC mismatch), exactly the sa#124 path.
    key = store._record_key(PRINCIPAL, ACTION_CLASS)
    store._store[key]["data"] = store._store[key]["data"].replace(
        '"ownerId":"', '"ownerId":"mallory-', 1
    )
    record_store = InMemoryPromotionRecordStore()

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=record_store,
        signals=[make_signal()],
    )

    assert outcome.status == "quarantined"
    assert "QUARANTINED" in outcome.reason
    assert outcome.updated_grant is None
    # nothing demoted, nothing on the ledger
    assert record_store.records == []
    assert '"level":"out-of-loop"' in store._store[key]["data"]


def test_run_demotion_no_breach():
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    store = store_with_grant(grant)

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[],  # nothing delivered, nothing derived
    )

    assert outcome.status == "no-breach"
    assert "no active breach" in outcome.reason
    assert outcome.triggered_by == ()


def test_run_demotion_signal_for_other_grant_is_no_breach():
    grant = make_grant()
    store = store_with_grant(grant)

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[make_signal(action_class="notify.send")],
    )

    assert outcome.status == "no-breach"


def test_run_demotion_demoted():
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
    )
    store = store_with_grant(grant)
    record_store = InMemoryPromotionRecordStore()

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=record_store,
        signals=[make_signal()],
        ts="2026-07-12T12:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert outcome.triggered_by == ("budget_breach",)
    assert outcome.updated_grant is not None
    assert outcome.updated_grant.level is AutonomyLevel.on_loop
    assert outcome.record is not None
    assert outcome.record.recordType == "demotion"
    assert outcome.record.ts == "2026-07-12T12:00:00+00:00"  # ts threaded through
    assert record_store.records == [outcome.record]
    # persisted, not just returned
    persisted = store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert persisted.grant is not None and not persisted.quarantined
    assert persisted.grant.level is AutonomyLevel.on_loop


def test_false_action_ships_off_grant_without_trigger_untouched():
    """The trigger ships OFF structurally: a false_action signal against a grant
    that does NOT list false_action in demotionTriggers is a no-breach — the
    evaluator only fires triggers the grant configures (no manifest lists it)."""
    grant = make_grant(demotionTriggers=[DemotionTrigger.budget_breach])
    store = store_with_grant(grant)

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[make_signal(trigger=DemotionTrigger.false_action)],
    )

    assert outcome.status == "no-breach"
    assert outcome.triggered_by == ()
    # untouched — still at full level
    persisted = store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert persisted.grant.level is AutonomyLevel.out_of_loop


def test_false_action_demotes_when_grant_opts_in():
    """A consumer that DOES list false_action gets a demotion off one flag, with
    the "failing" reason (an authenticated flag asserts the action was wrong)."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
        demotionTriggers=[DemotionTrigger.false_action],
    )
    store = store_with_grant(grant)
    record_store = InMemoryPromotionRecordStore()

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=record_store,
        signals=[make_signal(trigger=DemotionTrigger.false_action)],
        ts="2026-07-12T12:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert outcome.triggered_by == ("false_action",)
    assert outcome.updated_grant.level is AutonomyLevel.on_loop
    assert outcome.record.recordType == "demotion"
    assert outcome.record.demotionReason == "failing"


def test_run_demotion_conflict_not_auto_retried():
    grant = make_grant()
    store = store_with_grant(grant)
    write_attempts = []

    def conflicting_write(record, g, record_store_arg, session=None, *, signature=None, expected=None):
        write_attempts.append(expected.stored_hash if expected else None)
        raise GrantUpdateConflictError("concurrently modified")

    store.write_record_and_grant = conflicting_write

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[make_signal()],
    )

    assert outcome.status == "conflict"
    assert outcome.triggered_by == ("budget_breach",)
    assert outcome.updated_grant is None
    assert len(write_attempts) == 1  # retry policy is the caller's — exactly one try


def test_run_demotion_duplicate_ledger_key_is_typed_conflict():
    """A RecordAlreadyExistsError from the ledger append returns a typed
    "conflict" outcome (nonzero exit — operator attention), never an unhandled
    exception. Shape: two level-CHANGING passes stamped with the same ts (the
    grant reset in between) — the second record's key collides. A record-only
    repeat breach no longer reaches the collision: the same-day dedupe (#191)
    returns "deduped" first."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop,
        lastSafeLevel=AutonomyLevel.on_loop,
    )
    store = store_with_grant(grant)
    record_store = InMemoryPromotionRecordStore()
    ts = "2026-07-12T12:00:00+00:00"

    first = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts=ts,
    )
    assert first.status == "demoted"

    # Reset to out-of-loop (blind seed-style put) so the second pass is
    # level-changing — never deduped — yet stamps the same record key.
    store.put_grant(grant, session=None)

    second = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts=ts,
    )

    assert second.status == "conflict"
    assert "already exists" in second.reason
    assert second.triggered_by == ("budget_breach",)
    assert second.updated_grant is None
    # the ledger kept exactly the first record; the second unit wrote NOTHING
    # (#244 both-or-nothing), so the reset grant stands unchanged
    assert len(record_store.records) == 1
    persisted = store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert persisted.grant is not None and persisted.grant.level is AutonomyLevel.out_of_loop


# ---------------------------------------------------------------------------
# run_demotion — record-only same-day dedupe (#191)
# ---------------------------------------------------------------------------


def _record_only_setup() -> tuple[InMemoryGrantStore, InMemoryPromotionRecordStore]:
    """Grant already at its lastSafeLevel — every demotion pass is record-only."""
    grant = make_grant(
        level=AutonomyLevel.on_loop, lastSafeLevel=AutonomyLevel.on_loop
    )
    return store_with_grant(grant), InMemoryPromotionRecordStore()


def _seed_demotion_record(record_store, *, triggered_by, from_level, to_level, ts):
    record_store.put_record(
        PromotionRecord(
            recordType="demotion",
            actionClass=ACTION_CLASS,
            principal=PRINCIPAL,
            fromLevel=from_level,
            toLevel=to_level,
            evidence="prior breach",
            predicate=None,
            proposedBy=DEMOTION_RATIFIER,
            ratifiedBy=DEMOTION_RATIFIER,
            envelopeHash="sha256:env-001",
            triggeredBy=triggered_by,
            demotionReason="failing",
            ts=ts,
        ),
        session=None,
    )


def test_record_only_repeat_breach_same_day_deduped_zero_writes():
    store, record_store = _record_only_setup()

    first = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-12T08:00:00+00:00",
    )
    assert first.status == "demoted"  # record-only: level unchanged, breach on the ledger
    assert first.updated_grant.level is AutonomyLevel.on_loop
    after_first = store.get_grant(PRINCIPAL, ACTION_CLASS)

    second = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-12T16:00:00+00:00",
    )

    assert second.status == "deduped"
    assert second.triggered_by == ("budget_breach",)
    assert second.updated_grant is None
    assert second.record is None
    # ZERO writes: the ledger count and the grant content are all unchanged
    assert len(record_store.records) == 1
    after_second = store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert after_second.grant.ts == after_first.grant.ts
    assert after_second.grant == after_first.grant


def test_record_only_breach_next_utc_day_not_deduped():
    store, record_store = _record_only_setup()

    first = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-12T23:00:00+00:00",
    )
    assert first.status == "demoted"

    next_day = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-13T01:00:00+00:00",
    )

    assert next_day.status == "demoted"
    assert len(record_store.records) == 2


def test_level_changing_demotion_never_deduped():
    """Dedupe applies to record-only repeats ONLY: a demotion that lowers the
    level always lands, even with maximally-tempting same-day bait (a demotion
    record at the same target level with the same trigger) on the ledger."""
    grant = make_grant(
        level=AutonomyLevel.out_of_loop, lastSafeLevel=AutonomyLevel.on_loop
    )
    store = store_with_grant(grant)
    record_store = InMemoryPromotionRecordStore()
    _seed_demotion_record(
        record_store,
        triggered_by=["budget_breach"],
        from_level=AutonomyLevel.out_of_loop,
        to_level=AutonomyLevel.on_loop,
        ts="2026-07-12T08:00:00+00:00",
    )

    outcome = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-12T16:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert outcome.updated_grant.level is AutonomyLevel.on_loop
    assert len(record_store.records) == 2


def test_same_day_record_for_different_trigger_or_level_does_not_dedupe():
    """A genuinely new breach event must land: same-day demotion records for a
    DIFFERENT trigger set or a different toLevel never suppress the append."""
    store, record_store = _record_only_setup()  # grant at on-loop
    _seed_demotion_record(
        record_store,
        triggered_by=["stale_confidence"],  # different trigger, same level
        from_level=AutonomyLevel.on_loop,
        to_level=AutonomyLevel.on_loop,
        ts="2026-07-12T08:00:00+00:00",
    )
    _seed_demotion_record(
        record_store,
        triggered_by=["budget_breach"],  # same trigger, different toLevel
        from_level=AutonomyLevel.on_loop,
        to_level=AutonomyLevel.in_loop,
        ts="2026-07-12T09:00:00+00:00",
    )

    outcome = run_demotion(
        PRINCIPAL, ACTION_CLASS,
        grant_store=store, record_store=record_store,
        signals=[make_signal()], ts="2026-07-12T16:00:00+00:00",
    )

    assert outcome.status == "demoted"
    assert len(record_store.records) == 3


def test_run_demotion_session_passed_to_store():
    """The demotion-role session threads through to the conditional write."""
    grant = make_grant()
    store = store_with_grant(grant)
    sentinel_session = object()
    seen_sessions = []

    original_write = store.write_record_and_grant

    def capturing_write(record, g, record_store_arg, session=None, *, signature=None, expected=None):
        seen_sessions.append(session)
        original_write(record, g, record_store_arg, None, signature=signature, expected=expected)

    store.write_record_and_grant = capturing_write

    outcome = run_demotion(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=store,
        record_store=InMemoryPromotionRecordStore(),
        signals=[make_signal()],
        session=sentinel_session,
    )

    assert outcome.status == "demoted"
    assert seen_sessions == [sentinel_session]


def test_run_demotion_deterministic():
    """Same inputs, same outcome — built twice from scratch."""

    def one_pass() -> RunnerOutcome:
        store = store_with_grant(make_grant())
        return run_demotion(
            PRINCIPAL,
            ACTION_CLASS,
            grant_store=store,
            record_store=InMemoryPromotionRecordStore(),
            signals=[make_signal()],
            ts="2026-07-12T12:00:00+00:00",
        )

    assert one_pass() == one_pass()


def test_runner_module_has_no_model_machinery():
    """Determinism is the point: no model/LLM import anywhere in the runner."""
    source = inspect.getsource(runner_module).lower()
    for forbidden in ("bedrock", "anthropic", "openai", "llm"):
        assert forbidden not in source, f"runner module references {forbidden!r}"


# ---------------------------------------------------------------------------
# CLI plumbing — env sourcing + arg coupling (main stays thin)
# ---------------------------------------------------------------------------


def test_build_stores_from_env(monkeypatch):
    monkeypatch.setenv("BROKER_HMAC_KEY", "test-key")
    monkeypatch.setenv("BROKER_GRANTS_TABLE", "safe-agents-development-grants")
    monkeypatch.delenv("GRANTS_TABLE_NAME", raising=False)

    grant_store, record_store = _build_stores(None)

    assert grant_store._table_name == "safe-agents-development-grants"
    assert record_store._table_name == "safe-agents-development-grants"
    assert grant_store._hmac_key == b"test-key"


def test_build_stores_explicit_table_wins(monkeypatch):
    monkeypatch.setenv("BROKER_HMAC_KEY", "test-key")
    monkeypatch.setenv("BROKER_GRANTS_TABLE", "env-table")

    grant_store, _ = _build_stores("arg-table")

    assert grant_store._table_name == "arg-table"


def test_build_stores_requires_hmac_key(monkeypatch):
    monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
    monkeypatch.setenv("BROKER_GRANTS_TABLE", "some-table")

    with pytest.raises(RunnerConfigError, match="BROKER_HMAC_KEY"):
        _build_stores(None)


def test_build_stores_requires_table(monkeypatch):
    monkeypatch.setenv("BROKER_HMAC_KEY", "test-key")
    monkeypatch.delenv("BROKER_GRANTS_TABLE", raising=False)
    monkeypatch.delenv("GRANTS_TABLE_NAME", raising=False)

    with pytest.raises(RunnerConfigError, match="grants table"):
        _build_stores(None)


def test_build_enforcement_store_requires_table(monkeypatch):
    monkeypatch.delenv("BROKER_COUNTERS_TABLE", raising=False)

    with pytest.raises(RunnerConfigError, match="counters table"):
        _build_enforcement_store(None)


def test_build_enforcement_store_from_env(monkeypatch):
    monkeypatch.setenv("BROKER_COUNTERS_TABLE", "safe-agents-development-counters")

    store = _build_enforcement_store(None)

    assert store._table_name == "safe-agents-development-counters"


REQUIRED_ARGS = [
    "--principal-agent-id", "agent-demo",
    "--skill", "trade",
    "--user", "alice",
    "--tier", "A",
    "--action-class", ACTION_CLASS,
]


def test_parse_args_happy_path():
    args = _parse_args(REQUIRED_ARGS)
    assert args.principal_agent_id == "agent-demo"
    assert args.action_class == ACTION_CLASS
    assert args.tolerance is None


def test_parse_args_budget_args_must_come_together():
    with pytest.raises(SystemExit):
        _parse_args(REQUIRED_ARGS + ["--tolerance", "0.5"])  # missing --tool/--op


def test_parse_args_evidence_json_flags_require_tool_op():
    for flag in ("--stale-artifact-json", "--corroboration-json"):
        with pytest.raises(SystemExit):
            _parse_args(REQUIRED_ARGS + [flag, "/tmp/x.json"])


def test_parse_args_evidence_json_flag_satisfies_derivation_guard():
    args = _parse_args(
        REQUIRED_ARGS
        + ["--tool", "payments", "--op", "transfer",
           "--corroboration-json", "/tmp/q.json"]
    )
    assert args.corroboration_json == "/tmp/q.json"
    assert args.tolerance is None


def test_load_evidence_json_unusable_refuses(tmp_path):
    """A bad input is a loud config error — never a silent 'no breach'."""
    from safe_agents.broker.grants.runner import _load_evidence_json

    missing = tmp_path / "nope.json"
    with pytest.raises(RunnerConfigError):
        _load_evidence_json(str(missing), CorroborationRecord, "--corroboration-json")

    malformed = tmp_path / "bad.json"
    malformed.write_text('{"k": 5, "n": 3, "agreeing": 1, "computed_at": "t"}')
    with pytest.raises(RunnerConfigError):
        _load_evidence_json(str(malformed), CorroborationRecord, "--corroboration-json")


def test_parse_args_budget_args_complete():
    args = _parse_args(
        REQUIRED_ARGS + ["--tolerance", "0.5", "--tool", "payments", "--op", "transfer"]
    )
    assert args.tolerance == 0.5
    assert args.tool == "payments"
    assert args.op == "transfer"


def test_parse_args_false_action_requires_tool_and_op():
    with pytest.raises(SystemExit):
        _parse_args(REQUIRED_ARGS + ["--check-false-action"])  # missing --tool/--op


def test_parse_args_false_action_complete():
    args = _parse_args(
        REQUIRED_ARGS + ["--check-false-action", "--tool", "payments", "--op", "transfer"]
    )
    assert args.check_false_action is True
    assert args.tool == "payments"
    assert args.op == "transfer"
    assert args.tolerance is None


def test_parse_args_tool_op_without_derivation_flag_errors():
    """--tool/--op with NO derivation flag would build the counters store and derive
    nothing — a silent no-op that reads like 'no breach'. Reject it."""
    with pytest.raises(SystemExit):
        _parse_args(REQUIRED_ARGS + ["--tool", "payments", "--op", "transfer"])


def test_parse_args_false_action_window_periods_default_and_override():
    default = _parse_args(
        REQUIRED_ARGS + ["--check-false-action", "--tool", "payments", "--op", "transfer"]
    )
    assert default.false_action_window_periods == FALSE_ACTION_WINDOW_DAYS
    assert default.period == "utc-day"
    overridden = _parse_args(
        REQUIRED_ARGS
        + ["--check-false-action", "--tool", "payments", "--op", "transfer",
           "--false-action-window-periods", "3"]
    )
    assert overridden.false_action_window_periods == 3
    # The pre-#212 spelling still parses into the same dest.
    legacy = _parse_args(
        REQUIRED_ARGS
        + ["--check-false-action", "--tool", "payments", "--op", "transfer",
           "--false-action-window-days", "3"]
    )
    assert legacy.false_action_window_periods == 3
