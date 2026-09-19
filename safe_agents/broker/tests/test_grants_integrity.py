"""Grant integrity + ownership CI policy test table (sa#4, issue #62).

Asserts that the grant lifecycle safety properties from ARCHITECTURE.md
§pre-deployment-checklist and broker/grant-lifecycle.md hold across all
built lifecycle modules. Each parametrized row names the invariant it guards;
a failure says exactly which lifecycle guarantee broke.

Two test functions drive the table:
  test_invariant_holds          — positive case: valid state satisfies the invariant.
  test_violation_is_detected    — negative case: a violation is caught / rejected.

Invariants covered (19):
  OWNER_ID_REQUIRED       — every grant carries a non-empty ownerId
  HASH_INTEGRITY          — tampered hash → quarantined; never silently served
  HASH_COVERS_ALL_FIELDS  — hash is live on read; any field change is detected
  MAKER_CHECKER_REQUIRED  — promotion requires distinct proposer and ratifier
  PREDICATE_GATE          — predicate fail blocks promotion before the checker
  CEREMONY_ONLY_PATH      — only the ceremony produces a grant + record pair
  PROMOTION_PRODUCES_RECORD  — every ratified promotion links a PromotionRecord
  ORPHAN_GRANT_DETECTION  — a grant without a PromotionRecord is an integrity violation
  DEMOTION_NO_MODEL       — demotion ratifier is always "system:demotion-evaluator"
  DEMOTION_ONLY_LOWERS    — demotion never raises the autonomy level
  LAST_SAFE_NEVER_OOL     — lastSafeLevel is never out-of-loop (schema + runtime)
  LEGAL_TRANSITIONS       — state machine rejects illegal rung transitions
  DEAD_GRANT_REPORT       — grants inactive 30+ days are surfaced; not auto-pruned
  LEDGER_COUNTERPART      — every grant has a bootstrap/promotion ledger record (auditor)
  LEVEL_LEDGER_CONSISTENT — grant.level never exceeds the ledger-derived level (auditor)
  RECORD_SIGNATURE_VERIFIES — promotion records carry a verifying DSSE envelope (auditor)
  PROPOSAL_LIFECYCLE      — proposal status stays in the closed vocabulary; no resurrection
  QUARANTINED_NO_RAISE    — a quarantined grant is refused write-side and never sits
                            above its ledger-derived level (auditor)
  DEMOTION_RECORD_DEDUPE  — a record-only repeat breach lands ONE ledger record per UTC day

All tests are AWS-free (InMemoryGrantStore, InMemoryPromotionRecordStore; the
auditor rows judge in-memory AuditDatasets with run_audit).
"""

import datetime
import json
from dataclasses import dataclass
from typing import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from safe_agents.broker.grants.audit import (
    AuditDataset,
    AuditedEnvelope,
    AuditedGrant,
    AuditedProposal,
    AuditedRecord,
    AuditReport,
    GRANT_ENVELOPE_IN_FORCE,
    LEDGER_COUNTERPART,
    LEVEL_LEDGER_CONSISTENT,
    PROPOSAL_LIFECYCLE,
    PROPOSAL_TAMPER,
    QUARANTINED_NO_RAISE,
    RECORD_SIGNATURE_VERIFIES,
    run_audit,
)
from safe_agents.broker.grants.ceremony import (
    CheckerVerdict,
    InMemoryPromotionRecordStore,
    PromotionCeremony,
)
from safe_agents.broker.grants.demotion import (
    DemotionMetrics,
    apply_demotion,
    evaluate_demotion_triggers,
)
from safe_agents.broker.grants.proposals import (
    InMemoryProposalStore,
    ProposalConsumedError,
    compute_proposal_hash,
    proposal_to_json,
)
from safe_agents.broker.grants.acknowledgments import (
    AcknowledgmentRecord,
    canonical_ack_payload,
)
from safe_agents.broker.grants.record_signing import canonical_record_payload, signer_from_pem
from safe_agents.broker.mcp.proposals import (
    McpAdmissionProposal,
    canonical_proposal_payload as mcp_canonical_proposal_payload,
)
from safe_agents.broker.mcp.registry import canonical_row_payload
from safe_agents.broker.mcp.signing import (
    McpAdmissionRecord,
    canonical_record_payload as mcp_canonical_record_payload,
)
from safe_agents.broker.schemas.mcp_registry import (
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
)
from safe_agents.broker.grants.runner import run_demotion
from safe_agents.broker.grants.integrity import (
    detect_orphaned_grants,
    report_dead_grants,
)
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.rung import (
    TransitionError,
    validate_demotion_transition,
    validate_promotion_transition,
)
from safe_agents.broker.grants.store import (
    InMemoryGrantStore,
    QuarantinedGrantError,
    canonical_grant_payload,
    compute_grant_hash,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    DemotionSignal,
    SelfConsistencyEvidence,
)
from safe_agents.channels.keys import key_resolver_from_map


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-integrity-test", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
HMAC_KEY = b"test-hmac-key-integrity"

PASSING_METRICS = ActionClassMetrics(
    false_action_count=1,
    human_override_count=0,
    observation_count=100,
)
FAILING_METRICS = ActionClassMetrics(
    false_action_count=0,
    human_override_count=0,
    observation_count=3,  # below min_observations=10
)
PREDICATE_CONFIG = dict(window_n=100, min_observations=10, threshold=0.05)

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

_PROPOSAL_DEFAULTS = dict(
    principal=PRINCIPAL,
    action_class=ACTION_CLASS,
    proposal_id="prop-integrity-001",
    expires_at="2027-01-01T00:00:00+00:00",
    target_level=AutonomyLevel.on_loop,
    evidence_bundle="evidence-ref-001",
    proposer_id="human-proposer",
    from_level=AutonomyLevel.in_loop,
    owner_id="alice",
    envelope_hash="sha256:env-001",
    label_latency="P1D",
    demotion_triggers=[DemotionTrigger.budget_breach],
    last_safe_level=AutonomyLevel.in_loop,
    metrics=PASSING_METRICS,
    **PREDICATE_CONFIG,
    **EVIDENCE_CONFIG,
)

# Internal key for the in-memory store: used by the tamper tests.
_STORE_KEY = (
    f"{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}",
    ACTION_CLASS,
)


class _ApproveChecker:
    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        return CheckerVerdict(findings="evidence looks sound")


def _make_grant(**overrides) -> Grant:
    """Build a valid Grant with sensible defaults. put_grant recomputes the HMAC."""
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


def _make_ceremony(hmac_key: bytes = HMAC_KEY):
    """Return (ceremony, grant_store, record_store) wired to in-memory fakes."""
    store = InMemoryGrantStore(hmac_key=hmac_key)
    record_store = InMemoryPromotionRecordStore()
    ceremony = PromotionCeremony(
        grant_store=store,
        promotion_record_store=record_store,
        checker=_ApproveChecker(),
    )
    return ceremony, store, record_store


def _propose(**overrides):
    """Build a PromotionProposal from defaults, applying any overrides."""
    kwargs = {**_PROPOSAL_DEFAULTS, **overrides}
    return PromotionCeremony.propose_promotion(
        kwargs.pop("principal"),
        kwargs.pop("action_class"),
        kwargs.pop("target_level"),
        kwargs.pop("evidence_bundle"),
        kwargs.pop("proposer_id"),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Auditor-row helpers (#62) — build in-memory AuditDatasets for run_audit
# ---------------------------------------------------------------------------

_RECORD_TS = "2026-07-01T00:00:00+00:00"


def _hashed_grant(**overrides) -> Grant:
    """A Grant as stored (integrity lives at item level since #246 — the grant
    itself carries no hash; _audit_dataset supplies the stored bytes + HMAC)."""
    return _make_grant(**overrides)


def _ledger_record(
    record_type: str = "bootstrap",
    *,
    from_level: AutonomyLevel | None = None,
    to_level: AutonomyLevel = AutonomyLevel.in_loop,
    ts: str = _RECORD_TS,
    **overrides,
) -> PromotionRecord:
    """A PromotionRecord satisfying the per-recordType shape rules."""
    is_promotion = record_type == "promotion"
    defaults = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=from_level,
        toLevel=to_level,
        evidence="evidence-ref-001",
        predicate="predicate passed" if is_promotion else None,
        proposedBy="human-proposer",
        ratifiedBy="checker-distinct" if is_promotion else "human-proposer",
        envelopeHash="sha256:env-001",
        ts=ts,
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


def _audit_dataset(grants=(), records=(), proposals=(), envelopes=()) -> AuditDataset:
    """Assemble an AuditDataset from Grants, (record | (record, signature)),
    AuditedProposal, and AuditedEnvelope entries."""
    entries = []
    for item in records:
        record, signature = item if isinstance(item, tuple) else (item, None)
        # raw_data carries the canonical stored bytes — what the store writes
        # and what signature verification digests verbatim (#246 re-shape C).
        entries.append(
            AuditedRecord(
                record=record,
                signature=signature,
                raw_data=canonical_record_payload(record),
            )
        )
    return AuditDataset(
        grants=tuple(
            AuditedGrant(
                grant=g,
                raw_data=canonical_grant_payload(g),
                stored_hash=compute_grant_hash(g, HMAC_KEY),
            )
            for g in grants
        ),
        records=tuple(entries),
        proposals=tuple(proposals),
        envelopes=tuple(envelopes),
    )


def _proposal_item(status: str = "pending", *, tampered: bool = False) -> AuditedProposal:
    """An AuditedProposal as the store would persist it (valid HMAC unless tampered)."""
    data = proposal_to_json(_propose())
    stored_hash = compute_proposal_hash(data, HMAC_KEY)
    if tampered:
        data = data.replace('"on-loop"', '"out-of-loop"')
    return AuditedProposal(
        coordinate=f"{_STORE_KEY[0]}#{ACTION_CLASS}",
        proposal_id="prop-integrity-001",
        data_json=data,
        stored_hash=stored_hash,
        status=status,
    )


def _rules_fired(report: AuditReport) -> set[str]:
    return {violation.rule for violation in report.violations}


def _issuer_signer_and_resolver():
    """A fresh Ed25519 issuer identity + the resolver that knows its public key."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    signer = signer_from_pem("issuer:integrity-test", "zone-test", private_pem)
    return signer, key_resolver_from_map({"issuer:integrity-test": public_pem})


def _breach_signal(ts: str) -> DemotionSignal:
    return DemotionSignal(
        trigger=DemotionTrigger.budget_breach,
        principal=PRINCIPAL,
        action_class=ACTION_CLASS,
        period="20260712",
        detail="error budget breached: spent 0.6000 >= tolerance 0.5000",
        ts=ts,
    )


# ---------------------------------------------------------------------------
# Invariant row definition
# ---------------------------------------------------------------------------


@dataclass
class IntegrityRow:
    """One row in the CI policy test table.

    invariant: the lifecycle guarantee this row guards (appears in test IDs).
    positive:  callable asserting the invariant holds in a valid lifecycle state.
    negative:  callable asserting a violation of the invariant is caught/rejected.
    """

    invariant: str
    positive: Callable[[], None]
    negative: Callable[[], None]


# ---------------------------------------------------------------------------
# Row factories
# ---------------------------------------------------------------------------


def _row_owner_id_required() -> IntegrityRow:
    """ARCHITECTURE.md: "Each grant has a named owner." """

    def positive():
        # Ceremony accepts a proposal with a non-empty owner_id
        proposal = _propose(owner_id="alice-the-owner")
        assert proposal.owner_id == "alice-the-owner"

    def negative():
        # Empty owner_id is refused by propose_promotion before any checker runs
        with pytest.raises(ValueError, match="owner_id"):
            _propose(owner_id="")

    return IntegrityRow(invariant="OWNER_ID_REQUIRED", positive=positive, negative=negative)


def _row_hash_integrity() -> IntegrityRow:
    """A tampered grant hash surfaces quarantine=True; record returned for audit."""

    def positive():
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        store.put_grant(_make_grant(), session=None)
        result = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert result.grant is not None
        assert not result.quarantined

    def negative():
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        store.put_grant(_make_grant(), session=None)
        # Corrupt the item-level hash (simulates a tampered DynamoDB item)
        store._store[_STORE_KEY]["grantHash"] = "deliberately-tampered"

        result = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert result.quarantined is True, "tampered hash must trigger quarantine"
        assert result.quarantine_reason is not None
        # Tampered bytes are never parsed (#246); the raw bytes ride for audit
        assert result.grant is None
        assert result.raw_data is not None

    return IntegrityRow(invariant="HASH_INTEGRITY", positive=positive, negative=negative)


def _row_hash_covers_all_fields() -> IntegrityRow:
    """Hash is recomputed from stored fields on every read; field changes are detectable."""

    def positive():
        # After put_grant, the item-level hash equals the HMAC over the stored
        # bytes — storage and basis are the same serialization (#246)
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        store.put_grant(_make_grant(), session=None)
        result = store.get_grant(PRINCIPAL, ACTION_CLASS)
        assert result.grant is not None
        assert result.stored_hash == compute_grant_hash(result.grant, HMAC_KEY)
        assert result.raw_data == canonical_grant_payload(result.grant)

    def negative():
        # Any field change produces a different HMAC; if the hash field is not updated
        # the mismatch would be caught on the next read
        g1 = _make_grant(ownerId="alice")
        g2 = _make_grant(ownerId="mallory")
        h1 = compute_grant_hash(g1, HMAC_KEY)
        h2 = compute_grant_hash(g2, HMAC_KEY)
        assert h1 != h2, (
            "a field change must produce a different HMAC — "
            "hash verification is live and covers all non-hash fields"
        )

    return IntegrityRow(
        invariant="HASH_COVERS_ALL_FIELDS", positive=positive, negative=negative
    )


def _row_maker_checker_required() -> IntegrityRow:
    """ARCHITECTURE.md: grant store writable only by maker-checker path."""

    def positive():
        # Distinct proposer and ratifier → ceremony ratifies; record has them differing
        ceremony, store, record_store = _make_ceremony()
        store.put_grant(_make_grant(), session=None)  # execute's update path re-reads
        proposal = _propose(proposer_id="human-proposer")
        result = ceremony.execute(proposal, ratifier_id="checker-model-distinct")
        assert result.status == "ratified"
        record = record_store.records[0]
        assert record.proposedBy != record.ratifiedBy

    def negative():
        # Same proposer and ratifier → rejected; no grant or record written
        ceremony, store, record_store = _make_ceremony()
        proposal = _propose(proposer_id="same-person")
        result = ceremony.execute(proposal, ratifier_id="same-person")
        assert result.status == "rejected"
        assert "differ" in result.reason.lower() or "maker" in result.reason.lower()
        assert store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
        assert len(record_store.records) == 0

    return IntegrityRow(
        invariant="MAKER_CHECKER_REQUIRED", positive=positive, negative=negative
    )


def _row_predicate_gate() -> IntegrityRow:
    """Predicate fail blocks promotion before any checker is invoked."""

    def positive():
        ceremony, store, _ = _make_ceremony()
        store.put_grant(_make_grant(), session=None)
        proposal = _propose(metrics=PASSING_METRICS)
        result = ceremony.execute(proposal, ratifier_id="checker-distinct")
        assert result.status == "ratified"

    def negative():
        checker_calls: list[int] = []

        class _CountingChecker:
            def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
                checker_calls.append(1)
                return CheckerVerdict(findings="ok")

        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        record_store = InMemoryPromotionRecordStore()
        ceremony = PromotionCeremony(
            grant_store=store,
            promotion_record_store=record_store,
            checker=_CountingChecker(),
        )
        proposal = _propose(metrics=FAILING_METRICS)
        result = ceremony.execute(proposal, ratifier_id="checker-distinct")

        assert result.status == "rejected"
        assert "predicate" in result.reason.lower()
        assert len(checker_calls) == 0, (
            "checker must not be invoked when the predicate gate fails"
        )

    return IntegrityRow(invariant="PREDICATE_GATE", positive=positive, negative=negative)


def _row_ceremony_only_path() -> IntegrityRow:
    """Only the ceremony produces a grant + PromotionRecord pair; direct writes are detectable."""

    def positive():
        # Ceremony path: both a grant and a PromotionRecord are written atomically
        ceremony, store, record_store = _make_ceremony()
        store.put_grant(_make_grant(), session=None)
        result = ceremony.execute(_propose(), ratifier_id="checker-distinct")
        assert result.status == "ratified"
        assert store.get_grant(PRINCIPAL, ACTION_CLASS).grant is not None
        assert len(record_store.records) == 1

    def negative():
        # Direct put_grant (simulates an agent-direct or bypass write): grant exists
        # but no PromotionRecord → detected as an orphan by the integrity checker
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        record_store = InMemoryPromotionRecordStore()
        store.put_grant(_make_grant(), session=None)

        grant = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        orphans = detect_orphaned_grants([grant], record_store.records)
        assert len(orphans) == 1, (
            "a grant written outside the ceremony must be detected as an orphan"
        )
        assert orphans[0].grant.actionClass == ACTION_CLASS

    return IntegrityRow(
        invariant="CEREMONY_ONLY_PATH", positive=positive, negative=negative
    )


def _row_promotion_produces_record() -> IntegrityRow:
    """Every ratified promotion produces a signed PromotionRecord linked to the grant."""

    def positive():
        ceremony, store, record_store = _make_ceremony()
        store.put_grant(_make_grant(), session=None)
        result = ceremony.execute(
            _propose(evidence_bundle="evidence-007"), ratifier_id="checker-linked"
        )
        assert result.status == "ratified"
        assert len(record_store.records) == 1

        grant = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        record = record_store.records[0]
        # Grant and record share the accountability trail
        assert grant.promotedBy == record.ratifiedBy == "checker-linked"
        assert grant.evidence == record.evidence == "evidence-007"
        assert record.proposedBy == "human-proposer"
        assert record.proposedBy != record.ratifiedBy
        assert record.fromLevel is AutonomyLevel.in_loop
        assert record.toLevel is AutonomyLevel.on_loop

    def negative():
        # A rejected ceremony must not produce any PromotionRecord
        ceremony, store, record_store = _make_ceremony()
        ceremony.execute(_propose(proposer_id="same-person"), ratifier_id="same-person")
        assert len(record_store.records) == 0, (
            "rejected ceremony must not write any PromotionRecord"
        )

    return IntegrityRow(
        invariant="PROMOTION_PRODUCES_RECORD", positive=positive, negative=negative
    )


def _row_orphan_grant_detection() -> IntegrityRow:
    """A grant without a matching PromotionRecord is an integrity violation."""

    def positive():
        # Ceremony path: the grant has a matching PromotionRecord → not an orphan
        ceremony, store, record_store = _make_ceremony()
        store.put_grant(_make_grant(), session=None)
        ceremony.execute(_propose(), ratifier_id="checker-distinct")
        grant = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert len(detect_orphaned_grants([grant], record_store.records)) == 0

    def negative():
        # Direct store write: grant exists, no PromotionRecord → orphan detected
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        store.put_grant(_make_grant(), session=None)
        grant = store.get_grant(PRINCIPAL, ACTION_CLASS).grant

        orphans = detect_orphaned_grants([grant], records=[])
        assert len(orphans) == 1
        assert orphans[0].grant is grant

    return IntegrityRow(
        invariant="ORPHAN_GRANT_DETECTION", positive=positive, negative=negative
    )


def _row_demotion_no_model() -> IntegrityRow:
    """Demotion ratifier is always 'system:demotion-evaluator' — no model in the loop."""

    def _demote_grant(level: AutonomyLevel, last_safe: AutonomyLevel, trigger: DemotionTrigger):
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        grant = _make_grant(
            level=level,
            lastSafeLevel=last_safe,
            demotionTriggers=[trigger],
        )
        store.put_grant(grant, session=None)
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        metrics = DemotionMetrics(tripped=frozenset({trigger}))
        result = evaluate_demotion_triggers(stored, metrics)
        assert result.should_demote
        _, record = apply_demotion(
            stored, result, store=store, record_store=InMemoryPromotionRecordStore()
        )
        return record

    def positive():
        record = _demote_grant(
            AutonomyLevel.on_loop, AutonomyLevel.in_loop, DemotionTrigger.budget_breach
        )
        assert record.ratifiedBy == "system:demotion-evaluator", (
            "demotion must be ratified by the system identity, never a human or model"
        )

    def negative():
        # Verify the system identity is the sole ratifier produced across trigger types
        for trigger in (
            DemotionTrigger.budget_breach,
            DemotionTrigger.stale_confidence,
            DemotionTrigger.corroboration_failure,
        ):
            record = _demote_grant(
                AutonomyLevel.on_loop, AutonomyLevel.in_loop, trigger
            )
            assert record.ratifiedBy == "system:demotion-evaluator", (
                f"trigger {trigger.value} must produce system ratifier, got {record.ratifiedBy!r}"
            )
            assert record.ratifiedBy != "human-operator"
            assert record.ratifiedBy != "some-llm-model"

    return IntegrityRow(invariant="DEMOTION_NO_MODEL", positive=positive, negative=negative)


def _row_demotion_only_lowers() -> IntegrityRow:
    """Demotion never raises the autonomy level."""

    _RANK = {
        AutonomyLevel.in_loop: 0,
        AutonomyLevel.on_loop: 1,
        AutonomyLevel.out_of_loop: 2,
    }

    def positive():
        # Triggered demotion lowers level to lastSafeLevel — never raises it
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        grant = _make_grant(
            level=AutonomyLevel.out_of_loop,
            lastSafeLevel=AutonomyLevel.in_loop,
            demotionTriggers=[DemotionTrigger.budget_breach],
        )
        store.put_grant(grant, session=None)
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS).grant

        metrics = DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        result = evaluate_demotion_triggers(stored, metrics)
        updated, record = apply_demotion(
            stored, result, store=store, record_store=InMemoryPromotionRecordStore()
        )

        assert updated.level is AutonomyLevel.in_loop
        assert _RANK[updated.level] <= _RANK[stored.level], (
            "demotion must lower or hold the level, never raise it"
        )

    def negative():
        # The pure demotion validator rejects any transition that raises the level
        with pytest.raises(TransitionError, match="raise the autonomy level"):
            validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    return IntegrityRow(
        invariant="DEMOTION_ONLY_LOWERS", positive=positive, negative=negative
    )


def _row_last_safe_never_ool() -> IntegrityRow:
    """lastSafeLevel is never out-of-loop — enforced by the Grant schema validator."""

    def positive():
        # Both supervised rungs are valid lastSafeLevel values
        g1 = _make_grant(lastSafeLevel=AutonomyLevel.in_loop)
        g2 = _make_grant(lastSafeLevel=AutonomyLevel.on_loop)
        assert g1.lastSafeLevel is AutonomyLevel.in_loop
        assert g2.lastSafeLevel is AutonomyLevel.on_loop

    def negative():
        # out-of-loop as lastSafeLevel is rejected by the Grant schema validator
        with pytest.raises(ValidationError, match="out-of-loop"):
            _make_grant(lastSafeLevel=AutonomyLevel.out_of_loop)

    return IntegrityRow(
        invariant="LAST_SAFE_NEVER_OOL", positive=positive, negative=negative
    )


def _row_legal_transitions() -> IntegrityRow:
    """State machine accepts legal transitions and rejects illegal ones."""

    def positive():
        # Both valid one-rung upward transitions are accepted
        validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.on_loop)
        validate_promotion_transition(AutonomyLevel.on_loop, AutonomyLevel.out_of_loop)
        # Downward and same-rank demotion transitions are accepted
        validate_demotion_transition(AutonomyLevel.out_of_loop, AutonomyLevel.on_loop)
        validate_demotion_transition(AutonomyLevel.out_of_loop, AutonomyLevel.in_loop)
        validate_demotion_transition(AutonomyLevel.in_loop, AutonomyLevel.in_loop)

    def negative():
        # Level-skipping on the promotion path is rejected
        with pytest.raises(TransitionError, match="skip|one rung"):
            validate_promotion_transition(AutonomyLevel.in_loop, AutonomyLevel.out_of_loop)

    return IntegrityRow(
        invariant="LEGAL_TRANSITIONS", positive=positive, negative=negative
    )


def _row_dead_grant_report() -> IntegrityRow:
    """Grants inactive 30+ days are surfaced in the report; not auto-pruned."""

    _NOW = datetime.datetime(2026, 6, 28, tzinfo=datetime.timezone.utc)

    def positive():
        # A grant active 10 days ago is not stale
        grant = _make_grant()
        recent_ts = _NOW - datetime.timedelta(days=10)
        report = report_dead_grants([(grant, recent_ts)], window_days=30, as_of=_NOW)
        assert len(report) == 0, (
            "a grant active within the 30-day window must not appear in the dead-grant report"
        )

    def negative():
        # A grant with no activity for 31 days must appear in the report
        grant = _make_grant()
        stale_ts = _NOW - datetime.timedelta(days=31)
        report = report_dead_grants([(grant, stale_ts)], window_days=30, as_of=_NOW)
        assert len(report) == 1, (
            "a grant inactive for 31+ days must be surfaced in the dead-grant report"
        )
        entry = report[0]
        assert entry.grant is grant
        assert entry.days_stale >= 31
        # The report is read-only: callers decide what to do (no auto-prune)

    return IntegrityRow(
        invariant="DEAD_GRANT_REPORT", positive=positive, negative=negative
    )


def _row_ledger_counterpart() -> IntegrityRow:
    """Every grant coordinate has a bootstrap- or promotion-typed ledger record —
    every level was earned through the ceremony ledger (seeds emit bootstrap
    records since #123)."""

    def positive():
        dataset = _audit_dataset(grants=[_hashed_grant()], records=[_ledger_record()])
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert report.violations == ()
        assert report.grants_examined == 1

    def negative():
        # A grant with no ledger counterpart at all — the read-side bypass shape
        dataset = _audit_dataset(grants=[_hashed_grant()])
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert LEDGER_COUNTERPART in _rules_fired(report), (
            "a grant without a bootstrap/promotion record must be flagged"
        )

    return IntegrityRow(
        invariant="LEDGER_COUNTERPART", positive=positive, negative=negative
    )


def _row_level_ledger_consistent() -> IntegrityRow:
    """grant.level never exceeds the ledger-derived level (the chronologically-
    last record's toLevel). A grant BELOW its ledger is not an unaccounted
    RAISE, so this rule stays silent on it; since #255 it is the separate,
    waivable LEVEL_DROP_RECORDED finding (see _row_level_drop_recorded)."""

    _LEDGER = [
        _ledger_record(),  # bootstrap → in-loop
        _ledger_record(
            "promotion",
            from_level=AutonomyLevel.in_loop,
            to_level=AutonomyLevel.on_loop,
            ts="2026-07-02T00:00:00+00:00",
        ),
    ]

    def positive():
        # Grant AT the ledger-derived level is clean; grant BELOW it is never
        # this rule's finding (it is LEVEL_DROP_RECORDED's, #255)
        dataset = _audit_dataset(
            grants=[_hashed_grant(level=AutonomyLevel.on_loop)], records=_LEDGER
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert report.violations == (), (
            "grant at 'on-loop' with ledger topping at on-loop is valid"
        )
        dataset = _audit_dataset(
            grants=[_hashed_grant(level=AutonomyLevel.in_loop)], records=_LEDGER
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert LEVEL_LEDGER_CONSISTENT not in _rules_fired(report), (
            "a grant below its ledger is not an unaccounted raise"
        )

    def negative():
        # Grant ABOVE what the ledger accounts for — an unaccounted raise
        dataset = _audit_dataset(
            grants=[_hashed_grant(level=AutonomyLevel.out_of_loop)], records=_LEDGER
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert LEVEL_LEDGER_CONSISTENT in _rules_fired(report)

    return IntegrityRow(
        invariant="LEVEL_LEDGER_CONSISTENT", positive=positive, negative=negative
    )


def _row_record_signature_verifies() -> IntegrityRow:
    """Every promotion-typed record carries a DSSE envelope verify_record
    confirms; other record types are exempt (only ratify installs the signing
    store). The rule verifies AUTHENTICITY, not the truth of the proposer's
    asserted predicate fields (#193/#174 land their measurement)."""

    _PROMOTION = _ledger_record(
        "promotion",
        from_level=AutonomyLevel.in_loop,
        to_level=AutonomyLevel.on_loop,
        ts="2026-07-02T00:00:00+00:00",
    )

    def positive():
        signer, resolver = _issuer_signer_and_resolver()
        dataset = _audit_dataset(
            grants=[_hashed_grant(level=AutonomyLevel.on_loop)],
            # unsigned bootstrap is exempt; the promotion is issuer-signed
            records=[_ledger_record(), (_PROMOTION, signer.sign_record(_PROMOTION))],
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY, record_key_resolver=resolver)
        assert report.violations == ()
        assert RECORD_SIGNATURE_VERIFIES not in report.skipped_rules

    def negative():
        signer, resolver = _issuer_signer_and_resolver()

        # An unsigned promotion record fails closed
        unsigned = _audit_dataset(records=[_PROMOTION])
        report = run_audit(unsigned, record_key_resolver=resolver)
        assert RECORD_SIGNATURE_VERIFIES in _rules_fired(report)

        # A signature borrowed from a DIFFERENT record breaks the digest binding
        other = _ledger_record(
            "promotion",
            from_level=AutonomyLevel.on_loop,
            to_level=AutonomyLevel.out_of_loop,
            ts="2026-07-03T00:00:00+00:00",
        )
        borrowed = _audit_dataset(records=[(_PROMOTION, signer.sign_record(other))])
        report = run_audit(borrowed, record_key_resolver=resolver)
        assert RECORD_SIGNATURE_VERIFIES in _rules_fired(report), (
            "a signature lifted from a different record must fail verification"
        )

    return IntegrityRow(
        invariant="RECORD_SIGNATURE_VERIFIES", positive=positive, negative=negative
    )


def _row_proposal_lifecycle() -> IntegrityRow:
    """Proposal status stays in the closed pending/ratified/rejected vocabulary
    (read-side), and a consumed proposal can never be resurrected (write-side:
    the single-shot conditional flip)."""

    def positive():
        # Read-side: every closed-vocabulary status is clean
        dataset = _audit_dataset(
            proposals=[_proposal_item(s) for s in ("pending", "ratified", "rejected")]
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert report.violations == ()
        assert report.proposals_examined == 3

        # Write-side no-resurrection: a consumed proposal never flips again
        store = InMemoryProposalStore(hmac_key=HMAC_KEY)
        store.put_proposal(_propose())
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-integrity-001", "ratified")
        with pytest.raises(ProposalConsumedError):
            store.consume_proposal(
                PRINCIPAL, ACTION_CLASS, "prop-integrity-001", "rejected"
            )

    def negative():
        # A hand-edited status outside the vocabulary, and a tampered payload
        dataset = _audit_dataset(
            proposals=[
                _proposal_item("resurrected"),
                _proposal_item("pending", tampered=True),
            ]
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        fired = _rules_fired(report)
        assert PROPOSAL_LIFECYCLE in fired
        assert PROPOSAL_TAMPER in fired, (
            "a tampered proposal payload must fail the keyed HMAC rule"
        )

    return IntegrityRow(
        invariant="PROPOSAL_LIFECYCLE", positive=positive, negative=negative
    )


def _row_quarantined_no_raise() -> IntegrityRow:
    """A quarantined grant is refused by every write path (ceremony re-read),
    and read-side never sits above its ledger-derived level. The ledger does
    not timestamp quarantine, so the auditor approximates 'no post-quarantine
    raise' by the level-vs-ledger bound; the write-side refusal is the primary
    enforcement."""

    def positive():
        # Write-side half: the ceremony refuses to promote a quarantined grant
        ceremony, store, _ = _make_ceremony()
        store.put_grant(_make_grant(), session=None)
        store._store[_STORE_KEY]["grantHash"] = "deliberately-tampered"
        with pytest.raises(QuarantinedGrantError):
            ceremony.execute(_propose(), ratifier_id="checker-distinct")

        # Read-side half: a clean keyed audit reports nothing
        dataset = _audit_dataset(grants=[_hashed_grant()], records=[_ledger_record()])
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert report.violations == ()

    def negative():
        # A quarantined (stored-bytes-mismatched) grant sitting ABOVE its
        # ledger-derived level: flagged as unaccounted authority AND reported
        # for attention. Built as a raw dataset entry — the tamper lives at
        # the item layer (#246), not on the Grant schema.
        grant = _make_grant(level=AutonomyLevel.out_of_loop)
        quarantined_entry = AuditedGrant(
            grant=grant,
            raw_data=canonical_grant_payload(grant),
            stored_hash="deliberately-tampered",
        )
        base = _audit_dataset(
            records=[
                _ledger_record(),
                _ledger_record(
                    "promotion",
                    from_level=AutonomyLevel.in_loop,
                    to_level=AutonomyLevel.on_loop,
                    ts="2026-07-02T00:00:00+00:00",
                ),
            ],
        )
        dataset = AuditDataset(
            grants=(quarantined_entry,),
            records=base.records,
            proposals=base.proposals,
            envelopes=base.envelopes,
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert QUARANTINED_NO_RAISE in _rules_fired(report)

    return IntegrityRow(
        invariant="QUARANTINED_NO_RAISE", positive=positive, negative=negative
    )


def _row_demotion_record_dedupe() -> IntegrityRow:
    """A record-only repeat breach lands exactly ONE demotion record per UTC
    day (#191): the second same-day pass returns "deduped" with zero writes."""

    def _record_only_setup():
        # Grant already at its lastSafeLevel — every demotion pass is record-only
        store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        store.put_grant(
            _make_grant(level=AutonomyLevel.on_loop, lastSafeLevel=AutonomyLevel.on_loop),
            session=None,
        )
        return store, InMemoryPromotionRecordStore()

    def positive():
        store, record_store = _record_only_setup()
        first = run_demotion(
            PRINCIPAL, ACTION_CLASS,
            grant_store=store, record_store=record_store,
            signals=[_breach_signal("2026-07-12T08:00:00+00:00")],
            ts="2026-07-12T08:00:00+00:00",
        )
        second = run_demotion(
            PRINCIPAL, ACTION_CLASS,
            grant_store=store, record_store=record_store,
            signals=[_breach_signal("2026-07-12T16:00:00+00:00")],
            ts="2026-07-12T16:00:00+00:00",
        )
        assert first.status == "demoted"  # the breach event lands on the ledger
        assert second.status == "deduped"
        assert len(record_store.records) == 1, (
            "a same-day record-only repeat breach must not append a second record"
        )

    def negative():
        # Falsification: the one-record-per-day property is the runner's dedupe
        # gate, not a store guarantee — bypassing the gate (apply_demotion
        # directly) accumulates a second same-day record.
        store, record_store = _record_only_setup()
        run_demotion(
            PRINCIPAL, ACTION_CLASS,
            grant_store=store, record_store=record_store,
            signals=[_breach_signal("2026-07-12T08:00:00+00:00")],
            ts="2026-07-12T08:00:00+00:00",
        )
        stored = store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        result = evaluate_demotion_triggers(
            stored, DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
        )
        apply_demotion(
            stored, result, store=store, record_store=record_store,
            ts="2026-07-12T16:00:00+00:00",
        )
        assert len(record_store.records) == 2, (
            "without the runner's dedupe gate, same-day duplicates accumulate — "
            "the invariant is load-bearing, not vacuous"
        )
        # The gate stays live even after the churn: the next pass still dedupes
        third = run_demotion(
            PRINCIPAL, ACTION_CLASS,
            grant_store=store, record_store=record_store,
            signals=[_breach_signal("2026-07-12T20:00:00+00:00")],
            ts="2026-07-12T20:00:00+00:00",
        )
        assert third.status == "deduped"
        assert len(record_store.records) == 2

    return IntegrityRow(
        invariant="DEMOTION_RECORD_DEDUPE", positive=positive, negative=negative
    )


def _row_grant_envelope_in_force() -> IntegrityRow:
    """A grant's envelopeHash matches the stored in-force envelope for its
    principal (#201). A mismatched grant is broker-quarantined on every call
    (sa#122) — operationally dead — yet HMAC-clean, so only this rule sees it
    (the #199 incident shape)."""

    def positive():
        dataset = _audit_dataset(
            grants=[_hashed_grant()],
            records=[_ledger_record()],
            envelopes=[
                AuditedEnvelope(principal_key=_STORE_KEY[0], envelope_hash="sha256:env-001")
            ],
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert report.violations == ()

    def negative():
        # In-force envelope moved (far-jump redeploy / wrong-manifest ceremony);
        # the grant honestly records the old hash — dead, and now flagged.
        dataset = _audit_dataset(
            grants=[_hashed_grant()],
            records=[_ledger_record()],
            envelopes=[
                AuditedEnvelope(principal_key=_STORE_KEY[0], envelope_hash="sha256:env-002")
            ],
        )
        report = run_audit(dataset, hmac_key=HMAC_KEY)
        assert GRANT_ENVELOPE_IN_FORCE in _rules_fired(report), (
            "a grant stamped under a non-in-force envelope must be flagged"
        )

    return IntegrityRow(
        invariant="GRANT_ENVELOPE_IN_FORCE", positive=positive, negative=negative
    )


# ---------------------------------------------------------------------------
# The CI policy test table
# ---------------------------------------------------------------------------

TABLE: list[IntegrityRow] = [
    _row_owner_id_required(),
    _row_hash_integrity(),
    _row_hash_covers_all_fields(),
    _row_maker_checker_required(),
    _row_predicate_gate(),
    _row_ceremony_only_path(),
    _row_promotion_produces_record(),
    _row_orphan_grant_detection(),
    _row_demotion_no_model(),
    _row_demotion_only_lowers(),
    _row_last_safe_never_ool(),
    _row_legal_transitions(),
    _row_dead_grant_report(),
    _row_ledger_counterpart(),
    _row_level_ledger_consistent(),
    _row_record_signature_verifies(),
    _row_proposal_lifecycle(),
    _row_quarantined_no_raise(),
    _row_demotion_record_dedupe(),
    _row_grant_envelope_in_force(),
]

_TABLE_IDS = [row.invariant for row in TABLE]


@pytest.mark.parametrize("row", TABLE, ids=_TABLE_IDS)
def test_invariant_holds(row: IntegrityRow) -> None:
    """Valid lifecycle state satisfies each invariant.

    If a deliberately-introduced violation in a fixture causes this test to fail,
    the test ID names exactly which lifecycle guarantee was broken.
    """
    row.positive()


@pytest.mark.parametrize("row", TABLE, ids=_TABLE_IDS)
def test_violation_is_detected(row: IntegrityRow) -> None:
    """Each lifecycle violation is caught or rejected.

    Asserts that the enforcement mechanism for each invariant is live and active —
    no path silently accepts a violation.
    """
    row.negative()


# ---------------------------------------------------------------------------
# CANONICAL_SERIALIZATION — one rule, every stored-bytes integrity basis
# ---------------------------------------------------------------------------
#
# `channels/SIGNING.md` states the canonical rule once, for the whole platform:
# **sorted keys, no whitespace, ASCII**. Every stored-bytes integrity basis
# (#246) has to obey it, because those bytes become a WIRE format the moment a
# second implementation — a normative spec, a non-Python verifier, a
# re-implemented ceremony leg — recomputes the HMAC or digest from the spec
# instead of from this code.
#
# Until that moment a divergence is invisible: each function HMACs bytes its own
# process just wrote and reads back verbatim, so it is perfectly self-consistent
# and perfectly wrong. `canonical_grant_payload` and `proposal_to_json` were
# exactly that — sorted and ASCII but NOT compact, emitting Python's default
# `", "` / `": "`. Pinned here so the next one cannot be added silently.


def _string_literal_spans(payload: str) -> list[tuple[int, int]]:
    """Half-open [start, end) spans of every quoted string literal in `payload`.

    A hand-rolled scan rather than a regex: JSON escapes are simple (a
    backslash always consumes the next character) and the whitespace assertion
    below must be exact — a space inside a value must never be mistaken for a
    missing `separators`.
    """
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(payload):
        if payload[i] != '"':
            i += 1
            continue
        start = i
        i += 1
        while payload[i] != '"':
            i += 2 if payload[i] == "\\" else 1
        spans.append((start, i + 1))
        i += 1
    return spans


def _structure_only(payload: str) -> str:
    """`payload` with every string literal removed — punctuation and numbers."""
    kept, cursor = [], 0
    for start, end in _string_literal_spans(payload):
        kept.append(payload[cursor:start])
        cursor = end
    kept.append(payload[cursor:])
    return "".join(kept)


def _recanonicalize(payload: str) -> str:
    """The canonical rule, re-applied to a payload's own parsed content.

    Equality with the payload proves all three clauses at once: sorted keys, no
    whitespace between tokens, ASCII-escaped. Whitespace *inside* string values
    survives the round trip, so this cannot be satisfied by stripping content —
    only by serializing correctly.
    """
    return json.dumps(json.loads(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# A value carrying both a space and a non-ASCII character: a serializer that
# drops the space, or emits the character raw, fails the round trip.
_AWKWARD = "ré-vet evidence, batch 2"


def _mcp_tool_def() -> McpToolDef:
    return McpToolDef(
        server_id="ledger",
        tool_name="get_entry",
        input_schema={"type": "object", "properties": {"entry_id": {"type": "string"}}},
        description=f"Return one ledger entry by id. {_AWKWARD}",
    )


def _mcp_admission_proposal() -> McpAdmissionProposal:
    return McpAdmissionProposal(
        proposal_id="mcp-prop-001",
        expires_at="2027-01-01T00:00:00+00:00",
        tool_def=_mcp_tool_def(),
        def_hash="b" * 64,
        kind="admission",
        proposed_by="arn:aws:sts::111111111111:assumed-role/MakerRole/maker",
    )


def _mcp_registered_tool() -> RegisteredTool:
    return RegisteredTool(
        tool_def=_mcp_tool_def(),
        def_hash="b" * 64,
        status=RegistryStatus.ACTIVE,
        admitted_by="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker",
        admitted_at="2026-07-28T00:00:00+00:00",
    )


def _mcp_admission_record() -> McpAdmissionRecord:
    return McpAdmissionRecord(
        recordType="admission",
        serverId="ledger",
        toolName="get_entry",
        defHash="b" * 64,
        proposedBy="arn:aws:sts::111111111111:assumed-role/MakerRole/maker",
        ratifiedBy="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker",
        ts="2026-07-28T00:00:00+00:00",
    )


def _acknowledgment() -> AcknowledgmentRecord:
    return AcknowledgmentRecord(
        rule=GRANT_ENVELOPE_IN_FORCE,
        coordinate=f"{_STORE_KEY[0]}#{ACTION_CLASS}",
        detailDigest="sha256:" + "0" * 64,
        rationale=_AWKWARD,
        acknowledgedBy="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker",
        ts="2026-07-28T00:00:00+00:00",
    )


# One row per canonical serializer: a zero-arg factory returning the STORED
# string. Data-driven, so a new canonical serializer is a new row and never a
# new assert.
CANONICAL_SERIALIZERS = [
    pytest.param(
        lambda: canonical_grant_payload(_make_grant(evidence=_AWKWARD)),
        id="grants.store.canonical_grant_payload",
    ),
    pytest.param(
        lambda: canonical_record_payload(_ledger_record(evidence=_AWKWARD)),
        id="grants.record_signing.canonical_record_payload",
    ),
    pytest.param(
        lambda: proposal_to_json(_propose(evidence_bundle=_AWKWARD)),
        id="grants.proposals.proposal_to_json",
    ),
    pytest.param(
        lambda: canonical_ack_payload(_acknowledgment()),
        id="grants.acknowledgments.canonical_ack_payload",
    ),
    pytest.param(
        lambda: mcp_canonical_record_payload(_mcp_admission_record()),
        id="mcp.signing.canonical_record_payload",
    ),
    pytest.param(
        lambda: mcp_canonical_proposal_payload(_mcp_admission_proposal()),
        id="mcp.proposals.canonical_proposal_payload",
        marks=pytest.mark.xfail(
            strict=True,
            reason=(
                "KNOWN DIVERGENCE, deliberately unfixed here: omits "
                "separators=(',', ':'), so the stored payload carries Python's default "
                "whitespace — the same defect the grant basis had. Fixing it re-mints "
                "every stored MCP proposal HMAC and needs its own re-vet ceremony, so it "
                "is scoped out rather than left unpinned. When it IS fixed, delete this "
                "xfail: strict=True turns the suite red if the row starts passing."
            ),
        ),
    ),
    pytest.param(
        lambda: canonical_row_payload(_mcp_registered_tool()),
        id="mcp.registry.canonical_row_payload",
        marks=pytest.mark.xfail(
            strict=True,
            reason=(
                "KNOWN DIVERGENCE, deliberately unfixed here: omits "
                "separators=(',', ':'). Fixing it moves GOLDEN_ROW_HMAC "
                "(test_mcp_row_integrity.py) and quarantines every registry row until "
                "re-vet, so it is a separate ceremony-bearing change. When it IS fixed, "
                "delete this xfail: strict=True turns the suite red if the row starts "
                "passing."
            ),
        ),
    ),
]


@pytest.mark.parametrize("produce", CANONICAL_SERIALIZERS)
def test_canonical_payload_is_sorted_compact_ascii(produce: Callable[[], str]) -> None:
    """Every canonical payload is sorted-keys, whitespace-free, ASCII JSON.

    Two assertions, because the whitespace clause is the one that rots
    silently: the round trip pins all three clauses together, and the second
    assertion names whitespace specifically so the failure message points at
    the missing `separators` rather than at "not canonical".
    """
    payload = produce()
    assert payload == _recanonicalize(payload), (
        "not canonical (sorted keys, no whitespace, ASCII — channels/SIGNING.md). "
        "These bytes are an integrity basis, so a second implementation computing "
        "the same HMAC from the spec would disagree byte for byte."
    )
    structure = _structure_only(payload)
    assert not any(char.isspace() for char in structure), (
        "whitespace between JSON tokens — the serializer is missing "
        'separators=(",", ":")'
    )
