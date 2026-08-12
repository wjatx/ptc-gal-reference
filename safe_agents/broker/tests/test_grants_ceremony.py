"""Tests for the maker-checker promotion ceremony (#123).

Coverage:
- Successful promotion (predicate-pass + distinct proposer/ratifier) writes
  the raised grant and a PromotionRecord.
- proposedBy == ratifiedBy is rejected; no grant is written.
- predicate-fail blocks promotion; the reviewer is never invoked; no grant is
  written.
- The optional checker (evidence reviewer) ships OFF and NEVER gates: a
  suspicious verdict is recorded — on the result and in the record's predicate
  text — and the ceremony still ratifies.
- Missing owner_id is rejected at propose time AND re-checked by execute.
- execute re-validates the proposal's structural claims: a forged proposal
  (built directly, bypassing propose_promotion) with a level skip or an empty
  owner is rejected before any write.
- An expired proposal is always rejected — storeless or not.
- High blast requires a human ratifier: ratifier_kind='predicate' is rejected.
- The resulting grant's level is exactly one rung up (in-loop -> on-loop,
  on-loop -> out-of-loop).
- The grant carries PromotionRecord linkage (promotedBy == ratifiedBy,
  evidence refs match).
- Level-skipping (e.g. in-loop -> out-of-loop) is rejected at propose time.
- Already at top rung cannot be proposed.
- PromotionRecord fields are correctly populated on acceptance.
- Write order is record-first: an interrupted promotion leaves a dangling
  ledger record and NO authority gain (the promotion-safe failure polarity).
"""

import datetime

import pytest

from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.proposals import (
    InMemoryProposalStore,
    ProposalConsumedError,
)
from safe_agents.broker.grants.store import (
    GrantAlreadyExistsError,
    GrantUpdateConflictError,
    InMemoryGrantStore,
    QuarantinedGrantError,
)
from safe_agents.broker.grants.ceremony import (
    CheckerVerdict,
    InMemoryPromotionRecordStore,
    PromotionCeremony,
    PromotionProposal,
    _one_rung_up,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-test", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"

# Metrics that satisfy the predicate (low error rate, sufficient observations)
PASSING_METRICS = ActionClassMetrics(
    false_action_count=1,
    human_override_count=0,
    observation_count=100,
)

# Metrics that fail the predicate (too few observations)
FAILING_METRICS = ActionClassMetrics(
    false_action_count=0,
    human_override_count=0,
    observation_count=3,  # < min_observations=10
)

PREDICATE_CONFIG = dict(
    window_n=100,
    min_observations=10,
    threshold=0.05,
)

# A valid constructed-confidence artifact (#184) satisfying the evidence gates
VALID_ARTIFACT = ConfidenceArtifact(
    confidence=0.9,
    error_prob=0.1,
    evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
    computed_at="2026-07-12T00:00:00+00:00",
)

# sa#57 evidence terms that pass every predicate gate (budget knob unset = OFF)
EVIDENCE_CONFIG = dict(
    artifact=VALID_ARTIFACT,
    covered=True,
    provenance_maturity="signed-lineage",
    blast_class="low",
    error_budget=None,
)

PROPOSAL_BASE = dict(
    principal=PRINCIPAL,
    action_class=ACTION_CLASS,
    proposal_id="prop-001",
    expires_at="2027-01-01T00:00:00+00:00",  # far future: never expired in these tests
    from_level=AutonomyLevel.in_loop,
    target_level=AutonomyLevel.on_loop,  # exactly one rung up
    evidence_bundle="evidence-ref-001",
    proposer_id="human-proposer-alice",
    owner_id="alice",
    envelope_hash="sha256:abc",
    label_latency="P1D",
    demotion_triggers=[DemotionTrigger.stale_confidence],
    last_safe_level=AutonomyLevel.in_loop,
    metrics=PASSING_METRICS,
    **PREDICATE_CONFIG,
    **EVIDENCE_CONFIG,
)


class _FindingsChecker:
    """Fake reviewer that attaches findings and raises no suspicion."""

    def __init__(self) -> None:
        self.call_count = 0

    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        self.call_count += 1
        return CheckerVerdict(findings="evidence looks sound")


class _SuspiciousChecker:
    """Fake reviewer that raises suspicion — recorded, never a veto."""

    def __init__(self) -> None:
        self.call_count = 0

    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        self.call_count += 1
        return CheckerVerdict(
            findings="insufficient coverage in evidence", suspicious=True
        )


def _make_ceremony(
    checker=None,
    hmac_key: bytes = b"test-hmac-key",
) -> tuple[PromotionCeremony, InMemoryGrantStore, InMemoryPromotionRecordStore]:
    """Return a ceremony wired to in-memory fakes. checker=None is the
    shipping default (the reviewer seam OFF)."""
    grant_store = InMemoryGrantStore(hmac_key=hmac_key)
    record_store = InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=grant_store,
        promotion_record_store=record_store,
        checker=checker,
    )
    return ceremony, grant_store, record_store


def _make_proposal(**overrides) -> PromotionProposal:
    kwargs = {**PROPOSAL_BASE, **overrides}
    return PromotionCeremony.propose_promotion(
        kwargs.pop("principal"),
        kwargs.pop("action_class"),
        kwargs.pop("target_level"),
        kwargs.pop("evidence_bundle"),
        kwargs.pop("proposer_id"),
        **kwargs,
    )


def _forge_proposal(**overrides) -> PromotionProposal:
    """Build a proposal DIRECTLY (dataclass construction) — the shape of a
    proposal that never went through propose_promotion, or a PROPOSAL# item
    edited in the table. execute must re-validate it."""
    kwargs = {**PROPOSAL_BASE, **overrides}
    return PromotionProposal(**kwargs)


def _seed_grant(
    grant_store: InMemoryGrantStore,
    *,
    principal: Principal = PRINCIPAL,
    action_class: str = ACTION_CLASS,
    level: AutonomyLevel = AutonomyLevel.in_loop,
    **overrides,
) -> Grant:
    """Seed the store with a grant at `level` (execute's update path re-reads it)."""
    defaults = dict(
        principal=principal,
        actionClass=action_class,
        level=level,
        envelopeHash="sha256:abc",
        promotedBy="seeder",
        evidence="seed-evidence",
        ts="2026-06-28T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.stale_confidence],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    grant = Grant(**defaults)
    grant_store.put_grant(grant, session=None)
    return grant


# ---------------------------------------------------------------------------
# _one_rung_up — rung ordering helper
# ---------------------------------------------------------------------------


def test_one_rung_up_from_in_loop():
    assert _one_rung_up(AutonomyLevel.in_loop) is AutonomyLevel.on_loop


def test_one_rung_up_from_on_loop():
    assert _one_rung_up(AutonomyLevel.on_loop) is AutonomyLevel.out_of_loop


def test_one_rung_up_from_out_of_loop_raises():
    with pytest.raises(ValueError, match="top rung"):
        _one_rung_up(AutonomyLevel.out_of_loop)


# ---------------------------------------------------------------------------
# propose_promotion — input validation
# ---------------------------------------------------------------------------


def test_propose_missing_owner_id_raises():
    """A promotion without a named owner is refused before reaching the checker."""
    with pytest.raises(ValueError, match="owner_id"):
        _make_proposal(owner_id="")


def test_propose_level_skip_raises():
    """Jumping from in-loop to out-of-loop (skipping on-loop) is not allowed."""
    with pytest.raises(ValueError, match="exactly one rung"):
        _make_proposal(
            from_level=AutonomyLevel.in_loop,
            target_level=AutonomyLevel.out_of_loop,
        )


def test_propose_wrong_direction_raises():
    """Proposing a lower or equal target level is not a valid promotion."""
    with pytest.raises(ValueError, match="exactly one rung"):
        _make_proposal(
            from_level=AutonomyLevel.on_loop,
            target_level=AutonomyLevel.in_loop,
        )


def test_propose_same_level_raises():
    with pytest.raises(ValueError, match="exactly one rung"):
        _make_proposal(
            from_level=AutonomyLevel.in_loop,
            target_level=AutonomyLevel.in_loop,
        )


def test_propose_already_at_top_raises():
    """Cannot propose a promotion from out-of-loop."""
    with pytest.raises(ValueError, match="top rung"):
        _make_proposal(
            from_level=AutonomyLevel.out_of_loop,
            target_level=AutonomyLevel.out_of_loop,
        )


def test_propose_valid_returns_proposal():
    proposal = _make_proposal()
    assert proposal.proposer_id == "human-proposer-alice"
    assert proposal.from_level is AutonomyLevel.in_loop
    assert proposal.target_level is AutonomyLevel.on_loop


# ---------------------------------------------------------------------------
# execute — self-promotion guard (proposedBy == ratifiedBy)
# ---------------------------------------------------------------------------


def test_self_promotion_is_rejected():
    """proposedBy == ratifiedBy must be rejected; no write occurs."""
    checker = _FindingsChecker()
    ceremony, grant_store, record_store = _make_ceremony(checker=checker)
    proposal = _make_proposal(
        proposer_id="human-alice",
        metrics=PASSING_METRICS,
    )
    result = ceremony.execute(proposal, ratifier_id="human-alice")

    assert result.status == "rejected"
    assert "differ" in result.reason or "maker" in result.reason.lower()
    assert result.promotion_record is None
    # The reviewer must NOT have been invoked — maker!=checker check runs first
    assert checker.call_count == 0
    # No grant was written
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    # No PromotionRecord was stored
    assert len(record_store.records) == 0


# ---------------------------------------------------------------------------
# execute — predicate gate
# ---------------------------------------------------------------------------


def test_predicate_fail_blocks_promotion():
    """predicate-fail must block promotion; the reviewer is never invoked."""
    checker = _FindingsChecker()
    ceremony, grant_store, record_store = _make_ceremony(checker=checker)
    proposal = _make_proposal(metrics=FAILING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "rejected"
    assert "predicate" in result.reason.lower()
    assert result.promotion_record is None
    # The reviewer must NOT have been invoked — predicate gate comes first
    assert checker.call_count == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    assert len(record_store.records) == 0


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        (dict(artifact=None), "evidence artifact missing"),
        (dict(covered=False), "covered-distribution"),
        (dict(provenance_maturity="lineage"), "provenance maturity"),
    ],
    ids=["artifact-missing", "uncovered", "unsigned-lineage"],
)
def test_evidence_gate_fail_blocks_promotion(overrides, fragment):
    """The sa#57 evidence terms are threaded through: an evidence-gate failure
    rejects before the reviewer is invoked; no write occurs."""
    checker = _FindingsChecker()
    ceremony, grant_store, record_store = _make_ceremony(checker=checker)
    proposal = _make_proposal(metrics=PASSING_METRICS, **overrides)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "rejected"
    assert fragment in result.reason
    assert checker.call_count == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    assert len(record_store.records) == 0


# ---------------------------------------------------------------------------
# execute — the reviewer seam: findings attach, NEVER gate
# (docs/deterministic-gate.md — the reviewer cannot license or veto)
# ---------------------------------------------------------------------------


def test_suspicious_reviewer_records_but_does_not_veto():
    """A suspicious reviewer verdict is RECORDED — the ceremony still ratifies.

    The deterministic gate is predicate=true plus the identity rules; the
    reviewer can raise suspicion and attach findings, never veto."""
    checker = _SuspiciousChecker()
    ceremony, grant_store, record_store = _make_ceremony(checker=checker)
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert checker.call_count == 1
    # The suspicion is attached, not gated on.
    assert result.checker_verdict is not None
    assert result.checker_verdict.suspicious is True
    assert "[suspicion raised]" in record_store.records[0].predicate
    assert "insufficient coverage in evidence" in record_store.records[0].predicate
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.on_loop


def test_reviewer_findings_recorded_on_result_and_record():
    """Reviewer findings land on the CeremonyResult and in the record's
    predicate text as an appended segment."""
    ceremony, grant_store, record_store = _make_ceremony(checker=_FindingsChecker())
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert result.checker_verdict == CheckerVerdict(findings="evidence looks sound")
    assert "reviewer findings: evidence looks sound" in record_store.records[0].predicate


def test_reviewer_ships_off_by_default():
    """checker=None (the shipping default): the ceremony runs with no reviewer;
    nothing reviewer-shaped appears on the result or the record."""
    grant_store = InMemoryGrantStore(hmac_key=b"test-hmac-key")
    record_store = InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    )
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert result.checker_verdict is None
    assert "reviewer findings" not in record_store.records[0].predicate


# ---------------------------------------------------------------------------
# execute — successful promotion (the happy path)
# ---------------------------------------------------------------------------


def test_successful_promotion_writes_grant():
    """predicate-pass + distinct proposer/ratifier -> grant is written."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "ratified"
    grant_result = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert grant_result.grant is not None
    assert not grant_result.quarantined


def test_successful_promotion_writes_promotion_record():
    """A ratified promotion persists a PromotionRecord."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "ratified"
    assert result.promotion_record is not None
    assert len(record_store.records) == 1


def test_successful_promotion_level_is_exactly_one_rung_up():
    """The raised grant's level must be exactly one rung above from_level."""
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store)
    # in-loop -> on-loop
    proposal = _make_proposal(
        from_level=AutonomyLevel.in_loop,
        target_level=AutonomyLevel.on_loop,
        metrics=PASSING_METRICS,
    )
    ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    grant = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert grant is not None
    assert grant.level is AutonomyLevel.on_loop


def test_successful_promotion_from_on_loop_to_out_of_loop():
    """on-loop -> out-of-loop promotion succeeds and writes the correct level."""
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store, level=AutonomyLevel.on_loop)
    proposal = _make_proposal(
        from_level=AutonomyLevel.on_loop,
        target_level=AutonomyLevel.out_of_loop,
        last_safe_level=AutonomyLevel.in_loop,
        metrics=PASSING_METRICS,
    )
    ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    grant = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert grant is not None
    assert grant.level is AutonomyLevel.out_of_loop


def test_successful_promotion_grant_carries_record_linkage():
    """Grant.promotedBy == ratifiedBy and Grant.evidence matches PromotionRecord.evidence."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(
        metrics=PASSING_METRICS,
        evidence_bundle="evidence-ref-007",
    )
    ratifier_id = "checker-model-gpt5"
    ceremony.execute(proposal, ratifier_id=ratifier_id)

    grant = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    pr = record_store.records[0]

    # Grant links back to the ratifier and evidence
    assert grant.promotedBy == ratifier_id
    assert grant.evidence == "evidence-ref-007"

    # PromotionRecord fields match
    assert pr.recordType == "promotion"
    assert pr.ratifiedBy == ratifier_id
    assert pr.proposedBy == "human-proposer-alice"
    assert pr.evidence == "evidence-ref-007"
    assert pr.fromLevel is AutonomyLevel.in_loop
    assert pr.toLevel is AutonomyLevel.on_loop
    assert pr.actionClass == ACTION_CLASS
    assert pr.principal == PRINCIPAL
    assert pr.envelopeHash == "sha256:abc"  # the proposal's in-force envelope hash


def test_high_blast_ratified_record_notes_human_ratification():
    """A ratified high-blast promotion records the per-instance human-
    ratification requirement in the PromotionRecord's predicate string."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(blast_class="high", metrics=PASSING_METRICS)
    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "ratified"
    assert "human ratification" in record_store.records[0].predicate


# ---------------------------------------------------------------------------
# execute — high blast is ALWAYS ratified per-instance by a human
# ---------------------------------------------------------------------------


def test_high_blast_with_predicate_ratifier_is_rejected():
    """A pre-authored-predicate ratifier cannot stand in at high blast:
    predicate-true is necessary but never sufficient there
    (broker/grant-lifecycle.md §Promotion). Structural — no write."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(blast_class="high", metrics=PASSING_METRICS)

    result = ceremony.execute(
        proposal, ratifier_id="predicate:signed-p-001", ratifier_kind="predicate"
    )

    assert result.status == "rejected"
    assert "human ratification" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


def test_below_high_blast_predicate_ratifier_is_valid():
    """Below the high-blast threshold the pre-authored predicate may ratify."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(blast_class="low", metrics=PASSING_METRICS)

    result = ceremony.execute(
        proposal, ratifier_id="predicate:signed-p-001", ratifier_kind="predicate"
    )

    assert result.status == "ratified"
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.on_loop


def test_promotion_record_proposedby_differs_from_ratifiedby():
    """The PromotionRecord schema enforces maker != checker as a structural backstop."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)
    ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    pr = record_store.records[0]
    assert pr.proposedBy != pr.ratifiedBy


def test_successful_result_contains_promotion_record():
    """CeremonyResult.promotion_record is set on acceptance."""
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)
    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.promotion_record is not None
    assert isinstance(result.promotion_record, PromotionRecord)


def test_ratified_result_reason_names_the_ratifier():
    """CeremonyResult.reason for a ratified promotion names the ratifier."""
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)
    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "ratified"
    assert "checker-model-gpt5" in result.reason


# ---------------------------------------------------------------------------
# execute — grant hash integrity (store recomputes it)
# ---------------------------------------------------------------------------


def test_written_grant_has_valid_hash():
    """The store recomputes the HMAC on the ceremony's conditional write; the
    written grant must pass get_grant's check."""
    hmac_key = b"test-hmac-key-ceremony"
    ceremony, grant_store, _ = _make_ceremony(hmac_key=hmac_key)
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)
    ceremony.execute(proposal, ratifier_id="checker-model-id")

    result = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert result.grant is not None
    assert not result.quarantined, f"hash quarantined: {result.quarantine_reason}"


# ---------------------------------------------------------------------------
# execute — write order: record BEFORE grant (the promotion-safe polarity)
# ---------------------------------------------------------------------------


def test_rejection_writes_nothing():
    """On rejection neither a record nor a grant is written."""
    ceremony, grant_store, record_store = _make_ceremony()
    proposal = _make_proposal(metrics=FAILING_METRICS)
    ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert len(record_store.records) == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None


class _FailingGrantWriteStore(InMemoryGrantStore):
    """The atomic write always fails — the whole unit must cancel (#244)."""

    def write_record_and_grant(
        self, record, grant, record_store, session=None, *, signature=None, expected=None
    ):
        raise RuntimeError("grant store unavailable")


def test_interrupted_promotion_writes_nothing():
    """The record and the grant commit as ONE atomic unit (#244): a failed
    unit leaves NO dangling record and NO authority gain — the old
    record-first polarity trade (a dangling record to reconcile) is gone
    because there is no between to be interrupted in."""
    grant_store = _FailingGrantWriteStore(hmac_key=b"test-hmac-key")
    record_store = InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    )
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    with pytest.raises(RuntimeError, match="grant store unavailable"):
        ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    # Nothing written: no record, level never rose.
    assert record_store.records == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# execute — multiple promotions (store accumulates)
# ---------------------------------------------------------------------------


def test_two_promotions_for_different_principals():
    """Two separate promotions for different principals are independent."""
    ceremony, grant_store, record_store = _make_ceremony()

    p1 = Principal(agentId="agent-a", skill="email", user="alice", tier="B")
    p2 = Principal(agentId="agent-b", skill="files", user="bob", tier="A")
    _seed_grant(grant_store, principal=p1, action_class="email.send")
    _seed_grant(grant_store, principal=p2, action_class="files.read", ownerId="bob")

    proposal1 = PromotionCeremony.propose_promotion(
        p1, "email.send", AutonomyLevel.on_loop, "ev-001", "proposer-alice",
        proposal_id="prop-a", expires_at="2027-01-01T00:00:00+00:00",
        owner_id="alice", from_level=AutonomyLevel.in_loop,
        envelope_hash="sha256:aaa", label_latency="P1D",
        demotion_triggers=[DemotionTrigger.budget_breach],
        last_safe_level=AutonomyLevel.in_loop,
        metrics=PASSING_METRICS, **PREDICATE_CONFIG, **EVIDENCE_CONFIG,
    )
    proposal2 = PromotionCeremony.propose_promotion(
        p2, "files.read", AutonomyLevel.on_loop, "ev-002", "proposer-bob",
        proposal_id="prop-b", expires_at="2027-01-01T00:00:00+00:00",
        owner_id="bob", from_level=AutonomyLevel.in_loop,
        envelope_hash="sha256:bbb", label_latency="P7D",
        demotion_triggers=[DemotionTrigger.stale_confidence],
        last_safe_level=AutonomyLevel.in_loop,
        metrics=PASSING_METRICS, **PREDICATE_CONFIG, **EVIDENCE_CONFIG,
    )

    ceremony.execute(proposal1, ratifier_id="checker-model-gpt5")
    ceremony.execute(proposal2, ratifier_id="checker-model-gpt5")

    r1 = grant_store.get_grant(p1, "email.send")
    r2 = grant_store.get_grant(p2, "files.read")

    assert r1.grant is not None and r1.grant.level is AutonomyLevel.on_loop
    assert r2.grant is not None and r2.grant.level is AutonomyLevel.on_loop
    assert len(record_store.records) == 2


# ---------------------------------------------------------------------------
# execute — ownerId propagated to grant
# ---------------------------------------------------------------------------


def test_grant_owner_id_is_preserved():
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(owner_id="bob-the-owner", metrics=PASSING_METRICS)
    ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    grant = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert grant.ownerId == "bob-the-owner"


# ---------------------------------------------------------------------------
# execute — split persistence: Recommend-origin creates, existing updates (#190)
# ---------------------------------------------------------------------------


def test_recommend_origin_execute_creates_grant():
    """from_level=None (Recommend rung): the ceremony CREATES the grant at in-loop."""
    ceremony, grant_store, record_store = _make_ceremony()
    proposal = _make_proposal(from_level=None, target_level=AutonomyLevel.in_loop)

    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "ratified"
    grant = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert grant is not None
    assert grant.level is AutonomyLevel.in_loop
    assert record_store.records[0].fromLevel is None
    assert record_store.records[0].toLevel is AutonomyLevel.in_loop


def test_recommend_origin_only_targets_in_loop():
    """from_level=None with any target above in-loop is refused at propose time."""
    with pytest.raises(ValueError, match="exactly one rung"):
        _make_proposal(from_level=None, target_level=AutonomyLevel.on_loop)


def test_recommend_origin_collision_raises():
    """create_grant never overwrites: a grant minted concurrently surfaces loudly."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)  # the "concurrent" grant already exists
    proposal = _make_proposal(from_level=None, target_level=AutonomyLevel.in_loop)

    with pytest.raises(GrantAlreadyExistsError):
        ceremony.execute(proposal, ratifier_id="checker-model-gpt5")
    # Atomic unit (#244): the failed create cancels the record leg with it —
    # nothing written; the concurrently-minted grant stands.
    assert record_store.records == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.evidence == "seed-evidence"


def test_execute_on_missing_grant_raises_conflict():
    """A non-Recommend proposal whose grant vanished is a loud conflict, not a mint."""
    ceremony, grant_store, record_store = _make_ceremony()  # store left empty
    proposal = _make_proposal(metrics=PASSING_METRICS)

    with pytest.raises(GrantUpdateConflictError, match="not found"):
        ceremony.execute(proposal, ratifier_id="checker-model-gpt5")
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    assert len(record_store.records) == 0


def test_execute_refuses_quarantined_grant():
    """A quarantined stored grant is never promoted (laundering guard)."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    # Tamper without touching the hash attribute — the laundering shape.
    key = (f"{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}", ACTION_CLASS)
    grant_store._store[key]["data"] = grant_store._store[key]["data"].replace(
        '"evidence":"', '"evidence":"tampered-', 1
    )
    proposal = _make_proposal(metrics=PASSING_METRICS)

    with pytest.raises(QuarantinedGrantError):
        ceremony.execute(proposal, ratifier_id="checker-model-gpt5")
    assert len(record_store.records) == 0


# ---------------------------------------------------------------------------
# execute — the #190 regression: a demotion between propose and ratify
# ---------------------------------------------------------------------------


def test_demotion_between_propose_and_ratify_is_refused():
    """#190: a level change landing between propose and ratify changes the premise;
    execute refuses, and the level NEVER rises past what the evidence licensed."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store, level=AutonomyLevel.on_loop)
    proposal = _make_proposal(
        from_level=AutonomyLevel.on_loop,
        target_level=AutonomyLevel.out_of_loop,
        metrics=PASSING_METRICS,
    )

    # A demotion lands after propose: on-loop -> in-loop.
    _seed_grant(grant_store, level=AutonomyLevel.in_loop)

    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    assert result.status == "rejected"
    assert "premise changed" in result.reason
    # The demoted level stands — the ceremony never silently raised it.
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


class _RacingGrantStore(InMemoryGrantStore):
    """A demotion lands between execute's guarded re-read and its conditional write."""

    def __init__(self, race_grant, **kwargs) -> None:
        super().__init__(**kwargs)
        self._race_grant = race_grant

    def write_record_and_grant(
        self, record, grant, record_store, session=None, *, signature=None, expected=None
    ):
        if self._race_grant is not None:
            racing, self._race_grant = self._race_grant, None
            super().put_grant(racing, session)  # changes the stored hash
        super().write_record_and_grant(
            record, grant, record_store, session, signature=signature, expected=expected
        )


def test_conflict_between_reread_and_write_propagates():
    """#190 at the store level: a hash change between the re-read and the write
    surfaces as GrantUpdateConflictError — never retried, the level never rises."""
    demoted = Grant(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256:abc",
        promotedBy="system:demotion-evaluator",
        evidence="demotion",
        ts="2026-07-12T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        demotionReason="failing",
        labelLatency="P1D",
        ownerId="alice",
    )
    grant_store = _RacingGrantStore(demoted, hmac_key=b"test-hmac-key")
    record_store = InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=grant_store,
        promotion_record_store=record_store,
    )
    _seed_grant(grant_store, level=AutonomyLevel.on_loop)
    proposal = _make_proposal(
        from_level=AutonomyLevel.on_loop,
        target_level=AutonomyLevel.out_of_loop,
        metrics=PASSING_METRICS,
    )

    with pytest.raises(GrantUpdateConflictError):
        ceremony.execute(proposal, ratifier_id="checker-model-gpt5")

    # The racing demotion stands; the level never rose, and the atomic unit
    # (#244) canceled the record leg with the conflict — nothing written.
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert record_store.records == []


# ---------------------------------------------------------------------------
# execute — durable-proposal consumption (proposal_store supplied)
# ---------------------------------------------------------------------------

_NOW = datetime.datetime(2026, 7, 12, tzinfo=datetime.timezone.utc)


def test_execute_consumes_stored_proposal_on_ratify():
    ceremony, grant_store, _ = _make_ceremony()
    _seed_grant(grant_store)
    proposal_store = InMemoryProposalStore()
    proposal = _make_proposal(metrics=PASSING_METRICS)
    proposal_store.put_proposal(proposal)

    result = ceremony.execute(
        proposal, ratifier_id="checker-model-gpt5",
        proposal_store=proposal_store, now=_NOW,
    )

    assert result.status == "ratified"
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert status == "ratified"


def test_execute_refuses_already_consumed_proposal():
    """The double-ratify race: the second execute hits the conditional flip."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal_store = InMemoryProposalStore()
    proposal = _make_proposal(metrics=PASSING_METRICS)
    proposal_store.put_proposal(proposal)
    proposal_store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified")

    with pytest.raises(ProposalConsumedError):
        ceremony.execute(
            proposal, ratifier_id="checker-model-gpt5",
            proposal_store=proposal_store, now=_NOW,
        )
    # Refused before the grant write and the ledger append.
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


def test_execute_refuses_expired_proposal():
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal_store = InMemoryProposalStore()
    proposal = _make_proposal(expires_at="2026-07-01T00:00:00+00:00")  # before _NOW
    proposal_store.put_proposal(proposal)

    result = ceremony.execute(
        proposal, ratifier_id="checker-model-gpt5",
        proposal_store=proposal_store, now=_NOW,
    )

    assert result.status == "rejected"
    assert "expired" in result.reason
    # An expired refusal does not consume — the proposal stays pending for audit.
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert status == "pending"
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


def test_consumed_proposal_stays_burned_on_grant_conflict():
    """Documented partial-failure polarity: consume -> ratified precedes the grant
    write, so a write conflict leaves the proposal burned (no replay)."""
    demoted = Grant(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256:abc",
        promotedBy="system:demotion-evaluator",
        evidence="demotion",
        ts="2026-07-12T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[DemotionTrigger.budget_breach],
        demotionReason="failing",
        labelLatency="P1D",
        ownerId="alice",
    )
    grant_store = _RacingGrantStore(demoted, hmac_key=b"test-hmac-key")
    ceremony = PromotionCeremony(
        grant_store=grant_store,
        promotion_record_store=InMemoryPromotionRecordStore(),
    )
    _seed_grant(grant_store)
    proposal_store = InMemoryProposalStore()
    proposal = _make_proposal(metrics=PASSING_METRICS)
    proposal_store.put_proposal(proposal)

    with pytest.raises(GrantUpdateConflictError):
        ceremony.execute(
            proposal, ratifier_id="checker-model-gpt5",
            proposal_store=proposal_store, now=_NOW,
        )

    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert status == "ratified"  # burned — cannot be replayed against the new state


# ---------------------------------------------------------------------------
# execute — structural re-validation (never trust the proposal's own claims)
# ---------------------------------------------------------------------------


def test_execute_rejects_forged_level_skip():
    """A proposal built directly (or a PROPOSAL# item edited in the table)
    claiming in-loop -> out-of-loop must not pass execute end-to-end: the
    one-rung rule is re-derived inside execute, not trusted from propose."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)  # stored level matches the forged from_level
    forged = _forge_proposal(
        from_level=AutonomyLevel.in_loop,
        target_level=AutonomyLevel.out_of_loop,
    )

    result = ceremony.execute(forged, ratifier_id="checker-model-gpt5")

    assert result.status == "rejected"
    assert "exactly one rung" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


def test_execute_rejects_forged_recommend_origin_skip():
    """A forged Recommend-origin proposal (from_level=None) targeting any rung
    above in-loop is rejected before any write."""
    ceremony, grant_store, record_store = _make_ceremony()
    forged = _forge_proposal(from_level=None, target_level=AutonomyLevel.on_loop)

    result = ceremony.execute(forged, ratifier_id="checker-model-gpt5")

    assert result.status == "rejected"
    assert "exactly one rung" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    assert len(record_store.records) == 0


def test_execute_rejects_forged_top_rung_origin():
    """A forged proposal claiming from_level=out-of-loop is rejected — there is
    no rung above the top."""
    ceremony, grant_store, record_store = _make_ceremony()
    forged = _forge_proposal(
        from_level=AutonomyLevel.out_of_loop,
        target_level=AutonomyLevel.out_of_loop,
    )

    result = ceremony.execute(forged, ratifier_id="checker-model-gpt5")

    assert result.status == "rejected"
    assert "top rung" in result.reason
    assert len(record_store.records) == 0


def test_execute_rejects_forged_empty_owner():
    """The owner_id-non-empty rule is re-checked inside execute."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    forged = _forge_proposal(owner_id="")

    result = ceremony.execute(forged, ratifier_id="checker-model-gpt5")

    assert result.status == "rejected"
    assert "owner_id" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0


# ---------------------------------------------------------------------------
# execute — expiry is unconditional (expires_at is ON the proposal)
# ---------------------------------------------------------------------------


def test_execute_refuses_expired_proposal_without_store():
    """An expired proposal is rejected even with NO proposal_store: expiry
    lives on the proposal itself, so the storeless flow cannot replay it."""
    ceremony, grant_store, record_store = _make_ceremony()
    _seed_grant(grant_store)
    proposal = _make_proposal(expires_at="2026-07-01T00:00:00+00:00")  # before _NOW

    result = ceremony.execute(proposal, ratifier_id="checker-model-gpt5", now=_NOW)

    assert result.status == "rejected"
    assert "expired" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 0
