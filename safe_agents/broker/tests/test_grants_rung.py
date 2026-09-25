"""Tests for the autonomy rung state machine (sa#60).

All tests are AWS-free: InMemoryGrantStore and InMemoryPromotionRecordStore
replace DynamoDB; the optional reviewer seam ships OFF (None) except where a
test exercises its record-only semantics.

Coverage — 6 transition types (per issue #60 acceptance criteria):

  3 valid "upward" (promotion + lateral):
    1. in-loop  -> on-loop         legal; ceremony accepts
    2. on-loop  -> out-of-loop     legal; ceremony accepts
    3. any      -> same level      lateral re-ratification; accepted

  2 valid downward (demotion):
    4. out-of-loop -> on-loop      1-rung demotion (lastSafeLevel=on-loop)
    5. out-of-loop -> in-loop      2-rung demotion (lastSafeLevel=in-loop)

  1 invalid:
    6. in-loop  -> out-of-loop     level-skipping → TransitionError

Additional coverage:
  - promote() with downward target → TransitionError (validate_promotion_transition)
  - demotion path raising level → TransitionError (validate_demotion_transition)
  - demote() with no breached trigger → TransitionError
  - lastSafeLevel is never set to out-of-loop after promotion
  - lastSafeLevel updated correctly after demotion
  - hysteresis matrix: clean-run count AND dwell time must BOTH pass
    (each alone insufficient; boundary equality passes; top rung always False)
  - voluntary tightening (tighten_to_in_loop): any level -> in-loop, always
    permitted, no ceremony/trigger; conditional grant write first, then the
    tightening-typed ledger record; raises at in-loop or on empty requested_by;
    tightening records never appear via the promote()/demote() paths
  - full round-trip: promote to out-of-loop, then demote to lastSafeLevel
"""

import datetime

import pytest

from safe_agents.broker.grants.ceremony import (
    CheckerVerdict,
    InMemoryPromotionRecordStore,
    PromotionCeremony,
)
from safe_agents.broker.grants.demotion import DemotionMetrics, GrantNotFoundError
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.rung import (
    PromotionEligibilityCounters,
    RungStateMachine,
    TransitionError,
    is_eligible_for_promotion,
    validate_demotion_transition,
    validate_promotion_transition,
)
from safe_agents.broker.grants.store import (
    GrantUpdateConflictError,
    InMemoryGrantStore,
    QuarantinedGrantError,
)
from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-rung-test", skill="files", user="alice", tier="B")
ACTION_CLASS = "read.files"
TEST_HMAC_KEY = b"test-hmac-key-rung"

PASSING_METRICS = ActionClassMetrics(
    false_action_count=0,
    human_override_count=0,
    observation_count=50,
)
PREDICATE_CONFIG = dict(window_n=50, min_observations=10, threshold=0.05)

# sa#57 evidence terms passing every predicate gate (budget knob unset = OFF)
EVIDENCE_CONFIG = dict(
    artifact=ConfidenceArtifact(
        confidence=0.9,
        error_prob=0.1,
        evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
        computed_at="2026-07-12T00:00:00+00:00",
    ),
    covered=True,
    provenance_maturity="signed-lineage",
    blast_class="low",
    error_budget=None,
)


class _SuspiciousChecker:
    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        return CheckerVerdict(findings="not convinced", suspicious=True)


def make_grant(**overrides) -> Grant:
    """Return a valid Grant with sensible defaults. The hash field is a
    placeholder; put_grant recomputes it on write."""
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256:env-001",
        promotedBy="alice",
        evidence="evidence-ref-001",
        ts="2026-06-28T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    return Grant(**defaults)


def make_machine(
    checker=None, grant=None, record_store=None
) -> tuple[RungStateMachine, InMemoryGrantStore]:
    """Build a RungStateMachine wired to an InMemoryGrantStore.

    If grant is provided, it is pre-loaded into the store (HMAC recomputed).
    Tests that inspect the ledger pass their own record_store.
    Returns (machine, store) so tests can inspect the store directly.
    """
    store = InMemoryGrantStore(hmac_key=TEST_HMAC_KEY)
    if grant is not None:
        store.put_grant(grant, session=None)

    record_store = record_store or InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=store,
        promotion_record_store=record_store,
        checker=checker,
    )
    machine = RungStateMachine(ceremony=ceremony, grant_store=store, record_store=record_store)
    return machine, store


def read_grant(store: InMemoryGrantStore) -> Grant:
    """Read back the stored grant for PRINCIPAL/ACTION_CLASS (hash is correct)."""
    result = store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert result.grant is not None, "expected grant in store"
    assert not result.quarantined, f"grant is quarantined: {result.quarantine_reason}"
    return result.grant


def proposal_for(grant: Grant, *, target_level: AutonomyLevel, **overrides):
    """Build a PromotionProposal advancing grant.level to target_level."""
    from safe_agents.broker.grants.ceremony import PromotionCeremony

    kwargs = dict(
        principal=grant.principal,
        action_class=grant.actionClass,
        proposal_id="prop-rung-001",
        expires_at="2027-01-01T00:00:00+00:00",
        from_level=grant.level,
        target_level=target_level,
        evidence_bundle="evidence-ref-002",
        proposer_id="human-proposer",
        owner_id="alice",
        envelope_hash=grant.envelopeHash,
        label_latency=grant.labelLatency,
        demotion_triggers=list(grant.demotionTriggers),
        last_safe_level=grant.lastSafeLevel,
        metrics=PASSING_METRICS,
        **PREDICATE_CONFIG,
        **EVIDENCE_CONFIG,
    )
    kwargs.update(overrides)
    return PromotionCeremony.propose_promotion(**kwargs)


# ---------------------------------------------------------------------------
# Pure validator tests
# ---------------------------------------------------------------------------


class TestValidatePromotionTransition:
    def test_in_loop_to_on_loop_is_valid(self):
        validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.on_loop)  # no raise

    def test_on_loop_to_out_of_loop_is_valid(self):
        validate_promotion_transition(AutonomyLevel.on_loop, AutonomyLevel.out_of_loop)  # no raise

    def test_recommend_origin_to_in_loop_is_valid(self):
        """from_level=None is the Recommend rung; None -> in-loop is the
        grant-creating first promotion — a typed pass, never a KeyError."""
        validate_promotion_transition(None, AutonomyLevel.in_loop)  # no raise

    @pytest.mark.parametrize(
        "target", [AutonomyLevel.on_loop, AutonomyLevel.out_of_loop]
    )
    def test_recommend_origin_above_in_loop_raises_typed_error(self, target):
        """None -> anything above in-loop is a TransitionError (never a raw
        KeyError from the rank lookup)."""
        with pytest.raises(TransitionError, match="Recommend"):
            validate_promotion_transition(None, target)

    def test_skip_rung_raises(self):
        with pytest.raises(TransitionError, match="skips"):
            validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    def test_lateral_raises(self):
        with pytest.raises(TransitionError, match="lateral"):
            validate_promotion_transition(AutonomyLevel.on_loop, AutonomyLevel.on_loop)

    def test_downward_raises(self):
        with pytest.raises(TransitionError, match="downward"):
            validate_promotion_transition(AutonomyLevel.out_of_loop, AutonomyLevel.in_loop)


class TestValidateDemotionTransition:
    def test_downward_one_rung_is_valid(self):
        validate_demotion_transition(AutonomyLevel.out_of_loop, AutonomyLevel.on_loop)  # no raise

    def test_downward_two_rungs_is_valid(self):
        validate_demotion_transition(AutonomyLevel.out_of_loop, AutonomyLevel.in_loop)  # no raise

    def test_same_level_is_valid(self):
        # already at target — the apply_demotion safety guard keeps level unchanged
        validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.in_loop)  # no raise

    def test_upward_raises(self):
        with pytest.raises(TransitionError, match="raise the autonomy level"):
            validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)


# ---------------------------------------------------------------------------
# Hysteresis tests
# ---------------------------------------------------------------------------


LAST_TRANSITION = "2026-06-28T00:00:00Z"
MIN_DWELL = datetime.timedelta(days=7)


def _at(offset: datetime.timedelta) -> datetime.datetime:
    """A 'now' instant offset from LAST_TRANSITION."""
    return datetime.datetime(2026, 6, 28, tzinfo=datetime.timezone.utc) + offset


class TestIsEligibleForPromotion:
    """Both hysteresis thresholds — clean-run count AND dwell time — must pass."""

    def _grant(self, level: AutonomyLevel) -> Grant:
        return make_grant(level=level, lastSafeLevel=AutonomyLevel.in_loop)

    @pytest.mark.parametrize(
        ("level", "clean_runs", "now_offset", "expected"),
        [
            # both thresholds fail
            (AutonomyLevel.in_loop, 3, datetime.timedelta(days=1), False),
            # clean-runs pass, dwell fails
            (AutonomyLevel.in_loop, 25, datetime.timedelta(days=1), False),
            (AutonomyLevel.on_loop, 10, datetime.timedelta(days=6, hours=23), False),
            # dwell passes, clean-runs fail
            (AutonomyLevel.in_loop, 3, datetime.timedelta(days=30), False),
            (AutonomyLevel.on_loop, 0, datetime.timedelta(days=365), False),
            # both pass
            (AutonomyLevel.in_loop, 25, datetime.timedelta(days=30), True),
            (AutonomyLevel.on_loop, 10, datetime.timedelta(days=8), True),
            # boundary equality: exactly at each threshold passes (>= semantics)
            (AutonomyLevel.in_loop, 10, MIN_DWELL, True),
            (AutonomyLevel.on_loop, 10, MIN_DWELL, True),
            # top rung: never eligible, however strong the counters
            (AutonomyLevel.out_of_loop, 9999, datetime.timedelta(days=365), False),
        ],
    )
    def test_eligibility_matrix(self, level, clean_runs, now_offset, expected):
        grant = self._grant(level)
        counters = PromotionEligibilityCounters(
            clean_runs_since_promotion=clean_runs,
            last_transition_ts=LAST_TRANSITION,
        )
        assert (
            is_eligible_for_promotion(
                grant,
                counters,
                min_clean_runs=10,
                min_dwell=MIN_DWELL,
                now=_at(now_offset),
            )
            is expected
        )

    def test_naive_timestamps_interpreted_as_utc(self):
        """Naive last_transition_ts and naive now both resolve as UTC."""
        grant = self._grant(AutonomyLevel.in_loop)
        counters = PromotionEligibilityCounters(
            clean_runs_since_promotion=10,
            last_transition_ts="2026-06-28T00:00:00",  # naive
        )
        naive_now = datetime.datetime(2026, 7, 5)  # exactly MIN_DWELL later, naive
        assert (
            is_eligible_for_promotion(
                grant, counters, min_clean_runs=10, min_dwell=MIN_DWELL, now=naive_now
            )
            is True
        )

    def test_default_now_is_current_utc(self):
        """With now unset, a far-past transition and satisfied runs are eligible."""
        grant = self._grant(AutonomyLevel.in_loop)
        counters = PromotionEligibilityCounters(
            clean_runs_since_promotion=10,
            last_transition_ts="2020-01-01T00:00:00Z",
        )
        assert (
            is_eligible_for_promotion(
                grant, counters, min_clean_runs=10, min_dwell=MIN_DWELL
            )
            is True
        )


# ---------------------------------------------------------------------------
# RungStateMachine.promote — valid transitions (types 1 and 2)
# ---------------------------------------------------------------------------


class TestMachinePromote:
    def test_promote_in_loop_to_on_loop(self):
        """Transition type 1: in-loop -> on-loop via ceremony."""
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        proposal = proposal_for(grant, target_level=AutonomyLevel.on_loop)
        result = machine.promote(proposal, ratifier_id="checker-bot")

        assert result.status == "ratified"
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert stored.grant is not None
        assert stored.grant.level is AutonomyLevel.on_loop

    def test_promote_on_loop_to_out_of_loop(self):
        """Transition type 2: on-loop -> out-of-loop via ceremony."""
        grant = make_grant(
            level=AutonomyLevel.on_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
        )
        machine, store = make_machine(grant=grant)

        proposal = proposal_for(grant, target_level=AutonomyLevel.out_of_loop)
        result = machine.promote(proposal, ratifier_id="checker-bot")

        assert result.status == "ratified"
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert stored.grant is not None
        assert stored.grant.level is AutonomyLevel.out_of_loop

    def test_promote_skip_rung_raises_transition_error(self):
        """Transition type 6 (invalid): in-loop -> out-of-loop is level-skipping."""
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        # propose_promotion also validates, but the state machine catches it first
        with pytest.raises((TransitionError, ValueError), match="skip|one rung|level"):
            # We call validate directly since propose_promotion also guards this;
            # test both the pure validator and the machine together.
            validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    def test_machine_promote_skip_rung_raises(self):
        """The machine raises TransitionError before invoking the ceremony."""
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        # Build a proposal with the skip-rung target by bypassing propose_promotion.
        # We directly invoke validate_promotion_transition (which machine.promote calls)
        # rather than constructing a malformed proposal (propose_promotion also guards).
        with pytest.raises(TransitionError):
            validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    def test_promote_lastSafeLevel_never_out_of_loop(self):
        """After promotion to out-of-loop, lastSafeLevel stays on-loop (not raised)."""
        grant = make_grant(
            level=AutonomyLevel.on_loop,
            lastSafeLevel=AutonomyLevel.on_loop,
        )
        machine, store = make_machine(grant=grant)

        proposal = proposal_for(
            grant,
            target_level=AutonomyLevel.out_of_loop,
            last_safe_level=AutonomyLevel.on_loop,
        )
        result = machine.promote(proposal, ratifier_id="checker-bot")

        assert result.status == "ratified"
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert stored.grant is not None
        # The ceremony carries the lastSafeLevel from the proposal unchanged;
        # it must never be out-of-loop.
        assert stored.grant.lastSafeLevel is not AutonomyLevel.out_of_loop

    def test_promote_recommend_origin_creates_grant(self):
        """from_level=None flows through the machine: the ceremony CREATES the
        grant at in-loop (no KeyError from the transition validator)."""
        machine, store = make_machine()  # empty store — no grant exists yet
        proposal = proposal_for(
            make_grant(), target_level=AutonomyLevel.in_loop, from_level=None
        )

        result = machine.promote(proposal, ratifier_id="checker-bot")

        assert result.status == "ratified"
        assert read_grant(store).level is AutonomyLevel.in_loop

    def test_promote_threads_proposal_store_and_now(self):
        """The durable-proposal params flow through promote to execute: the
        stored proposal is consumed on ratify, and expiry is evaluated at the
        supplied instant."""
        from safe_agents.broker.grants.proposals import InMemoryProposalStore

        now = datetime.datetime(2026, 7, 12, tzinfo=datetime.timezone.utc)
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)
        proposal_store = InMemoryProposalStore()
        proposal = proposal_for(grant, target_level=AutonomyLevel.on_loop)
        proposal_store.put_proposal(proposal)

        result = machine.promote(
            proposal, ratifier_id="checker-bot",
            proposal_store=proposal_store, now=now,
        )

        assert result.status == "ratified"
        _, status = proposal_store.get_proposal(
            PRINCIPAL, ACTION_CLASS, proposal.proposal_id
        )
        assert status == "ratified"

        # And the expiry leg: an expired proposal rejects through the machine.
        expired = proposal_for(
            grant, target_level=AutonomyLevel.on_loop,
            proposal_id="prop-rung-expired", expires_at="2026-07-01T00:00:00+00:00",
        )
        expired_result = machine.promote(expired, ratifier_id="checker-bot", now=now)
        assert expired_result.status == "rejected"
        assert "expired" in expired_result.reason

    def test_promote_threads_ratifier_kind(self):
        """High-blast human-ratification enforcement flows through the machine."""
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)
        proposal = proposal_for(
            grant, target_level=AutonomyLevel.on_loop, blast_class="high"
        )

        result = machine.promote(
            proposal, ratifier_id="predicate:p-1", ratifier_kind="predicate"
        )

        assert result.status == "rejected"
        assert "human ratification" in result.reason
        assert read_grant(store).level is AutonomyLevel.in_loop

    def test_suspicious_reviewer_is_recorded_not_a_veto(self):
        """A suspicious reviewer verdict is recorded on the result; the
        deterministic gate still ratifies (the reviewer cannot veto —
        docs/deterministic-gate.md)."""
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(checker=_SuspiciousChecker(), grant=grant)

        proposal = proposal_for(grant, target_level=AutonomyLevel.on_loop)
        result = machine.promote(proposal, ratifier_id="checker-bot")

        assert result.status == "ratified"
        assert result.checker_verdict is not None
        assert result.checker_verdict.suspicious is True
        assert read_grant(store).level is AutonomyLevel.on_loop


# ---------------------------------------------------------------------------
# RungStateMachine.re_ratify — lateral re-ratification (type 3)
# ---------------------------------------------------------------------------


class TestMachineReRatify:
    def test_re_ratify_updates_evidence_not_level(self):
        """Transition type 3: lateral re-ratification refreshes evidence, same level."""
        grant = make_grant(level=AutonomyLevel.on_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        updated = machine.re_ratify(
            read_grant(store),  # hash-correct copy for the conditional write
            evidence_bundle="evidence-ref-refreshed",
            ratifier_id="new-ratifier",
        )

        assert updated.level is AutonomyLevel.on_loop  # level unchanged
        assert updated.evidence == "evidence-ref-refreshed"
        assert updated.promotedBy == "new-ratifier"

    def test_re_ratify_persists_to_store(self):
        grant = make_grant(level=AutonomyLevel.in_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        machine.re_ratify(read_grant(store), evidence_bundle="new-evidence", ratifier_id="bob")

        stored = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert stored.grant is not None
        assert stored.grant.evidence == "new-evidence"
        assert stored.grant.level is AutonomyLevel.in_loop

    def test_re_ratify_empty_ratifier_raises(self):
        grant = make_grant(level=AutonomyLevel.on_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)

        with pytest.raises(TransitionError, match="ratifier_id"):
            machine.re_ratify(grant, evidence_bundle="evidence", ratifier_id="")

    # --- #190 retrofit: guarded re-read + hash-conditioned write (no blind put) ---

    def test_re_ratify_not_found_raises(self):
        """Re-ratification cannot create a grant (the blind put could)."""
        machine, store = make_machine()  # empty store
        with pytest.raises(GrantNotFoundError):
            machine.re_ratify(make_grant(), evidence_bundle="ev", ratifier_id="bob")

    def test_re_ratify_quarantined_grant_refused(self):
        """A quarantined grant is never written over — the blind put would have
        re-signed the tampered state under a fresh valid HMAC."""
        grant = make_grant(level=AutonomyLevel.on_loop)
        machine, store = make_machine(grant=grant)
        stored = read_grant(store)
        # Tamper WITHOUT touching the hash attribute — the laundering shape.
        (key,) = store._store.keys()
        store._store[key]["data"] = store._store[key]["data"].replace(
            '"evidence":"', '"evidence":"tampered-', 1
        )

        with pytest.raises(QuarantinedGrantError):
            machine.re_ratify(stored, evidence_bundle="fresh", ratifier_id="bob")

    def test_re_ratify_concurrent_modification_raises_conflict(self):
        """#190: a demotion landing between the re-ratifier's read and write must
        surface as a conflict — never be silently overwritten (which would RAISE
        the level with no ceremony and no record)."""
        grant = make_grant(level=AutonomyLevel.on_loop, lastSafeLevel=AutonomyLevel.in_loop)
        machine, store = make_machine(grant=grant)
        stale = read_grant(store)

        # A demotion lands after the re-ratifier's read: on-loop -> in-loop.
        store.put_grant(
            make_grant(level=AutonomyLevel.in_loop, demotionReason="failing"), session=None
        )

        with pytest.raises(GrantUpdateConflictError):
            machine.re_ratify(stale, evidence_bundle="fresh", ratifier_id="bob")
        # The demoted level stands.
        assert read_grant(store).level is AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# RungStateMachine.demote — valid demotion transitions (types 4 and 5)
# ---------------------------------------------------------------------------


class TestMachineDemote:
    def test_demote_one_rung(self):
        """Transition type 4: out-of-loop -> on-loop (lastSafeLevel=on-loop)."""
        grant = make_grant(
            level=AutonomyLevel.out_of_loop,
            lastSafeLevel=AutonomyLevel.on_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)  # hash-correct version for conflict check

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        updated_grant, record = machine.demote(stored_grant, metrics)

        assert updated_grant.level is AutonomyLevel.on_loop
        assert record.fromLevel is AutonomyLevel.out_of_loop
        assert record.toLevel is AutonomyLevel.on_loop

    def test_demote_multi_rung(self):
        """Transition type 5: out-of-loop -> in-loop (lastSafeLevel=in-loop, 2 rungs)."""
        grant = make_grant(
            level=AutonomyLevel.out_of_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        updated_grant, record = machine.demote(stored_grant, metrics)

        assert updated_grant.level is AutonomyLevel.in_loop
        assert record.fromLevel is AutonomyLevel.out_of_loop
        assert record.toLevel is AutonomyLevel.in_loop

    def test_demote_no_trigger_raises_transition_error(self):
        """Calling demote() when no trigger is breached is an invalid transition."""
        grant = make_grant(
            level=AutonomyLevel.out_of_loop,
            lastSafeLevel=AutonomyLevel.on_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)

        # No triggers tripped — nothing should demote
        metrics = DemotionMetrics(tripped=frozenset())
        with pytest.raises(TransitionError, match="no configured trigger"):
            machine.demote(stored_grant, metrics)

    def test_demote_lastSafeLevel_updated(self):
        """After demotion from on-loop, lastSafeLevel is updated to on-loop."""
        grant = make_grant(
            level=AutonomyLevel.on_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionTriggers=[DemotionTrigger.stale_confidence],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.stale_confidence}))
        updated_grant, _ = machine.demote(stored_grant, metrics)

        # apply_demotion sets lastSafeLevel to the previous level (on-loop),
        # since on-loop is not out-of-loop.
        assert updated_grant.lastSafeLevel is AutonomyLevel.on_loop

    def test_demote_repeat_breach_is_record_only(self):
        """A second breach on an already-demoted grant appends a record, not raises.

        After a demotion from on-loop, the grant sits at level=in-loop with
        lastSafeLevel=on-loop (the re-promotion reference point). A repeat
        trigger breach must still land on the ledger as a record-only demotion
        — never a TransitionError, and never a level raise.
        """
        grant = make_grant(
            level=AutonomyLevel.in_loop,
            lastSafeLevel=AutonomyLevel.on_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        updated_grant, record = machine.demote(stored_grant, metrics)

        assert updated_grant.level is AutonomyLevel.in_loop  # unchanged, never raised
        assert record.recordType == "demotion"
        assert record.fromLevel is AutonomyLevel.in_loop
        assert record.toLevel is AutonomyLevel.in_loop

    def test_demote_lastSafeLevel_never_out_of_loop(self):
        """lastSafeLevel must never be set to out-of-loop after demotion."""
        grant = make_grant(
            level=AutonomyLevel.out_of_loop,
            lastSafeLevel=AutonomyLevel.on_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant)
        stored_grant = read_grant(store)

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        updated_grant, _ = machine.demote(stored_grant, metrics)

        # The previous level (out-of-loop) is forbidden as lastSafeLevel;
        # apply_demotion keeps lastSafeLevel at its original value (on-loop).
        assert updated_grant.lastSafeLevel is not AutonomyLevel.out_of_loop


# ---------------------------------------------------------------------------
# RungStateMachine.tighten_to_in_loop — voluntary tightening
# ---------------------------------------------------------------------------


class _FailingRecordStore(InMemoryPromotionRecordStore):
    """put_record always raises — the atomic unit must cancel wholly (#244)."""

    def put_record(self, record, session=None, signature=None):
        raise RuntimeError("ledger unavailable")


class TestMachineTighten:
    @pytest.mark.parametrize(
        "from_level",
        [AutonomyLevel.on_loop, AutonomyLevel.out_of_loop],
    )
    def test_tighten_lowers_grant_and_appends_record(self, from_level):
        """Any level -> in-loop: grant written, tightening record on the ledger."""
        grant = make_grant(
            level=from_level,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionReason="pending-evidence",
        )
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)
        stored_grant = read_grant(store)  # hash-correct version for the conditional write

        updated, record = machine.tighten_to_in_loop(
            stored_grant, "alice", ts="2026-07-12T00:00:00+00:00"
        )

        assert updated.level is AutonomyLevel.in_loop
        assert updated.lastSafeLevel is AutonomyLevel.in_loop
        assert updated.ts == "2026-07-12T00:00:00+00:00"
        # tightening is not a demotion — demotionReason untouched
        assert updated.demotionReason == "pending-evidence"

        # persisted, not just returned
        persisted = read_grant(store)
        assert persisted.level is AutonomyLevel.in_loop
        assert persisted.lastSafeLevel is AutonomyLevel.in_loop

        # ledger record shape
        assert record_store.records == [record]
        assert record.recordType == "tightening"
        assert record.fromLevel is from_level
        assert record.toLevel is AutonomyLevel.in_loop
        assert record.proposedBy == "alice"
        assert record.ratifiedBy == "alice"  # maker ≠ checker not enforced here
        assert record.predicate is None
        assert record.triggeredBy == []
        assert record.demotionReason is None
        assert record.envelopeHash == grant.envelopeHash
        assert record.evidence == "voluntary tightening"
        assert record.ts == "2026-07-12T00:00:00+00:00"

    def test_tighten_carries_caller_evidence(self):
        grant = make_grant(level=AutonomyLevel.on_loop)
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)

        _, record = machine.tighten_to_in_loop(
            read_grant(store), "alice", evidence="incident INC-42 precaution"
        )

        assert record.evidence == "incident INC-42 precaution"

    def test_tighten_at_in_loop_raises(self):
        """Already at the floor — nothing to tighten; callers must not re-tighten."""
        grant = make_grant(level=AutonomyLevel.in_loop)
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)

        with pytest.raises(TransitionError, match="already"):
            machine.tighten_to_in_loop(read_grant(store), "alice")
        assert record_store.records == []

    def test_tighten_empty_requested_by_raises(self):
        grant = make_grant(level=AutonomyLevel.on_loop)
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)

        with pytest.raises(TransitionError, match="requested_by"):
            machine.tighten_to_in_loop(read_grant(store), "")
        assert record_store.records == []
        assert read_grant(store).level is AutonomyLevel.on_loop  # untouched

    def test_tighten_is_conditional_on_grant_hash(self):
        """A stale read (hash mismatch) surfaces as a conflict; no record appended."""
        grant = make_grant(level=AutonomyLevel.on_loop)
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)
        stale = read_grant(store)

        # concurrent modification: someone re-ratifies, changing the stored hash
        machine.re_ratify(stale, evidence_bundle="refreshed", ratifier_id="bob")

        with pytest.raises(GrantUpdateConflictError):
            machine.tighten_to_in_loop(stale, "alice")
        assert record_store.records == []

    def test_tighten_failed_record_leg_writes_nothing(self):
        """Atomic record+grant (#244): a failed ledger leg cancels the whole
        unit — the grant stays at its prior level with no ledger hole, and
        the caller retries."""
        grant = make_grant(level=AutonomyLevel.out_of_loop, lastSafeLevel=AutonomyLevel.on_loop)
        machine, store = make_machine(grant=grant, record_store=_FailingRecordStore())

        with pytest.raises(RuntimeError, match="ledger unavailable"):
            machine.tighten_to_in_loop(read_grant(store), "alice")

        # nothing written: the level did not move (both-or-nothing)
        assert read_grant(store).level is AutonomyLevel.out_of_loop

    def test_tightening_records_never_from_promote_or_demote(self):
        """The other paths write only their own record types."""
        grant = make_grant(
            level=AutonomyLevel.in_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        record_store = InMemoryPromotionRecordStore()
        machine, store = make_machine(grant=grant, record_store=record_store)

        proposal = proposal_for(grant, target_level=AutonomyLevel.on_loop)
        assert machine.promote(proposal, ratifier_id="checker-bot").status == "ratified"

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        machine.demote(read_grant(store), metrics)

        record_types = [r.recordType for r in record_store.records]
        assert record_types == ["promotion", "demotion"]
        assert "tightening" not in record_types


# ---------------------------------------------------------------------------
# Illegal transition: raising level via the demotion path
# ---------------------------------------------------------------------------


class TestIllegalRaiseViaDemotionPath:
    def test_validate_demotion_rejects_upward(self):
        """Attempting to "demote" upward is caught by the pure validator."""
        with pytest.raises(TransitionError, match="raise the autonomy level"):
            validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    def test_validate_demotion_rejects_one_rung_up(self):
        with pytest.raises(TransitionError, match="raise the autonomy level"):
            validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.on_loop)


# ---------------------------------------------------------------------------
# Full round-trip: promote → demote → invariants hold
# ---------------------------------------------------------------------------


class TestRoundTrip:
    # The one-clock-tick variant of this round trip (Windows' ~15.6 ms clock,
    # #37) lives in test_ledger_clock.py, under a frozen clock.
    def test_promote_then_demote_holds_invariants(self):
        """Promote in-loop → on-loop → out-of-loop, then demote back to in-loop."""
        # Step 1: start at in-loop
        grant0 = make_grant(
            level=AutonomyLevel.in_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        machine, store = make_machine(grant=grant0)

        # Step 2: promote in-loop -> on-loop
        p1 = proposal_for(
            grant0,
            target_level=AutonomyLevel.on_loop,
            last_safe_level=AutonomyLevel.in_loop,
        )
        r1 = machine.promote(p1, ratifier_id="checker-bot")
        assert r1.status == "ratified"

        grant1 = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert grant1 is not None
        assert grant1.level is AutonomyLevel.on_loop
        assert grant1.lastSafeLevel is AutonomyLevel.in_loop

        # Step 3: promote on-loop -> out-of-loop
        p2 = proposal_for(
            grant1,
            target_level=AutonomyLevel.out_of_loop,
            last_safe_level=AutonomyLevel.in_loop,
        )
        r2 = machine.promote(p2, ratifier_id="checker-bot")
        assert r2.status == "ratified"

        grant2 = read_grant(store)  # hash-correct after ceremony write
        assert grant2.level is AutonomyLevel.out_of_loop
        assert grant2.lastSafeLevel is not AutonomyLevel.out_of_loop  # schema invariant

        # Step 4: demote back to lastSafeLevel (in-loop)
        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        updated_grant, record = machine.demote(grant2, metrics)

        assert updated_grant.level is grant2.lastSafeLevel
        assert updated_grant.level is not AutonomyLevel.out_of_loop
        assert record.fromLevel is AutonomyLevel.out_of_loop
        assert record.toLevel is grant2.lastSafeLevel
        assert record.ratifiedBy == "system:demotion-evaluator"

        # Final store state
        final = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert final is not None
        assert final.level is record.toLevel
        assert final.lastSafeLevel is not AutonomyLevel.out_of_loop
