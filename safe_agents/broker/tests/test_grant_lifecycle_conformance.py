"""Conformance suite for the grant lifecycle (#60/#59/#55) — clauses L1–L8.

Contract-tier surface requires a conformance suite (`docs/contract-vs-reference.md`);
this is it, certifying `broker/grant-lifecycle.md` (the normative state machine),
`docs/GAL.md` §§3–6, and `broker/SCHEMAS.md` §1 (Grant) / §7 (PromotionRecord) —
in the E1–E10 style of `test_evidence_contract.py` and the C6–C8 precedent of
`test_iam_scoping.py`. Plain pytest, one class per clause, no AWS/network/model.
The per-module suites (`test_grants_*.py`) own implementation detail; each clause
here is certified by its sharpest witness, not an exhaustive matrix.

| Clause | Guarantee |
|---|---|
| **L1** | Transition unconstructibility: every structurally-invalid transition raises the typed `TransitionError` (level-skip up, non-+1 promotion, demotion never raises); the valid set (one-rung promotion, fall-to-lastSafeLevel, any-level→in-loop tightening, lateral re-ratification, repeat-breach record-only demotion) passes. |
| **L2** | The ledger records every level change: promotion/demotion/tightening each append their typed record; the four recordTypes' shape rules hold (maker≠checker for promotion only; `DEMOTION_RATIFIER`; bootstrap `fromLevel=None`; tightening `toLevel=in-loop`). |
| **L3** | Demotion determinism: same grant+metrics → same outcome; no model import anywhere on the demotion path; the trigger vocabulary is closed and the evaluator ignores unconfigured/untripped triggers. |
| **L4** | The two reasons never collapse: `stale_confidence`→`pending-evidence`; `budget_breach`/`corroboration_failure`/`false_action`→`failing`; multi-trigger — failing dominates. |
| **L5** | `lastSafeLevel` invariants: never `out-of-loop` (schema + demote defence-in-depth); demotion falls to `lastSafeLevel`; post-demotion it updates to the prior level (the re-promotion reference point). |
| **L6** | Write discipline: demotion write is conditional (concurrent modification → `DemotionConflictError`, the stale write cannot land); demotion never CREATES a grant (`GrantNotFoundError`); the ledger is append-only (`RecordAlreadyExistsError`); a quarantined grant is never written over — refused with a typed error on every write path (`run_demotion`, `apply_demotion`, `tighten_to_in_loop`). |
| **L7** | Hysteresis: promotion eligibility needs BOTH clean-runs and dwell; demotion has NO dwell/grace — a fired trigger demotes immediately and the demote path exposes no suppression parameter. |
| **L8** | Budget-breach derivation parity: `derive_budget_breach` reads exactly `scoped_counter_key(principal, tool, op, "error_budget")` with the PIP's `spent >= tolerance` comparison (`prototype/broker_server.py`). |
"""

from __future__ import annotations

import ast
import datetime
import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

from safe_agents.broker.enforcement import scoped_counter_key
from safe_agents.broker.grants.ceremony import (
    InMemoryPromotionRecordStore,
    PromotionCeremony,
    PromotionProposal,
)
from safe_agents.broker.grants.demotion import (
    DemotionConflictError,
    DemotionMetrics,
    GrantNotFoundError,
    apply_demotion,
    evaluate_demotion_triggers,
)
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.runner import (
    derive_budget_breach,
    run_demotion,
)
from safe_agents.broker.grants.rung import (
    PromotionEligibilityCounters,
    RungStateMachine,
    TransitionError,
    is_eligible_for_promotion,
    validate_demotion_transition,
    validate_promotion_transition,
)
from safe_agents.broker.grants.store import (
    InMemoryGrantStore,
    QuarantinedGrantError,
    RecordAlreadyExistsError,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    DemotionSignal,
    SelfConsistencyEvidence,
)
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER

IN = AutonomyLevel.in_loop
ON = AutonomyLevel.on_loop
OUT = AutonomyLevel.out_of_loop

_TS = "2026-07-12T00:00:00+00:00"
_ACTION_CLASS = "email.send"
_ALL_TRIGGERS = [
    DemotionTrigger.stale_confidence,
    DemotionTrigger.corroboration_failure,
    DemotionTrigger.budget_breach,
    DemotionTrigger.false_action,
]

_PRINCIPAL = Principal(agentId="agent-1", skill="notify", user="maintainer", tier="B")


# ---------------------------------------------------------------------------
# Builders — via the real schemas and in-memory stores
# ---------------------------------------------------------------------------


def _grant(
    level: AutonomyLevel = ON,
    last_safe: AutonomyLevel = IN,
    triggers: list[DemotionTrigger] | None = None,
    demotion_reason: str | None = None,
) -> Grant:
    return Grant(
        principal=_PRINCIPAL,
        actionClass=_ACTION_CLASS,
        level=level,
        envelopeHash="env-hash-1",
        promotedBy="human:maintainer",
        evidence="evidence-window-ref",
        ts=_TS,
        lastSafeLevel=last_safe,
        demotionTriggers=list(triggers if triggers is not None else _ALL_TRIGGERS),
        demotionReason=demotion_reason,
        labelLatency="P1D",
        ownerId="maintainer",
    )


def _seeded_store(grant: Grant) -> tuple[InMemoryGrantStore, Grant]:
    """Put the grant and return (store, grant-as-read) — the read carries the real hash."""
    store = InMemoryGrantStore()
    store.put_grant(grant)
    read = store.get_grant(grant.principal, grant.actionClass)
    assert read.grant is not None and not read.quarantined
    return store, read.grant


def _machine(
    store: InMemoryGrantStore, records: InMemoryPromotionRecordStore
) -> RungStateMachine:
    # The optional reviewer seam ships OFF (checker=None) — the conformance
    # suite certifies the deterministic gate, which never involves a model.
    ceremony = PromotionCeremony(grant_store=store, promotion_record_store=records)
    return RungStateMachine(ceremony=ceremony, grant_store=store, record_store=records)


def _proposal(
    from_level: AutonomyLevel, target_level: AutonomyLevel
) -> PromotionProposal:
    # Built directly (dataclass, no validation) so structurally-invalid transitions
    # reach the state machine's own guard rather than the proposal validator.
    return PromotionProposal(
        proposal_id="prop-conformance-001",
        expires_at="2027-01-01T00:00:00+00:00",
        principal=_PRINCIPAL,
        action_class=_ACTION_CLASS,
        from_level=from_level,
        target_level=target_level,
        evidence_bundle="evidence-window-ref",
        proposer_id="human:maker",
        owner_id="maintainer",
        envelope_hash="env-hash-1",
        label_latency="P1D",
        demotion_triggers=list(_ALL_TRIGGERS),
        last_safe_level=IN,
        metrics=ActionClassMetrics(
            false_action_count=0, human_override_count=0, observation_count=30
        ),
        window_n=30,
        min_observations=10,
        threshold=0.05,
        # sa#57 evidence terms passing every predicate gate (budget knob unset)
        artifact=ConfidenceArtifact(
            confidence=0.9,
            error_prob=0.1,
            evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
            computed_at=_TS,
        ),
        covered=True,
        provenance_maturity="signed-lineage",
        blast_class="low",
        error_budget=None,
    )


def _tripped(*triggers: DemotionTrigger) -> DemotionMetrics:
    return DemotionMetrics(tripped=frozenset(triggers))


def _record_payload(record_type: str, **overrides) -> dict:
    """A valid payload for each of the four recordTypes; override to break shape."""
    base = {
        "recordType": record_type,
        "actionClass": _ACTION_CLASS,
        "principal": _PRINCIPAL,
        "evidence": "evidence-window-ref",
        "envelopeHash": "env-hash-1",
        "ts": _TS,
    }
    per_type: dict[str, dict] = {
        "promotion": {
            "fromLevel": IN,
            "toLevel": ON,
            "predicate": "error_rate<0.05 over 30 obs",
            "proposedBy": "human:maker",
            "ratifiedBy": "human:checker",
        },
        "demotion": {
            "fromLevel": ON,
            "toLevel": IN,
            "proposedBy": DEMOTION_RATIFIER,
            "ratifiedBy": DEMOTION_RATIFIER,
            "triggeredBy": ["budget_breach"],
            "demotionReason": "failing",
        },
        "bootstrap": {
            "fromLevel": None,
            "toLevel": IN,
            "proposedBy": "human:maintainer",
            "ratifiedBy": "human:maintainer",
        },
        "tightening": {
            "fromLevel": ON,
            "toLevel": IN,
            "proposedBy": "human:maintainer",
            "ratifiedBy": "human:maintainer",
        },
    }
    return {**base, **per_type[record_type], **overrides}


# ---------------------------------------------------------------------------
# L1 — transition unconstructibility
# ---------------------------------------------------------------------------


class TestL1TransitionUnconstructibility:
    """Every structurally-invalid transition raises the typed TransitionError;
    the valid transition set passes.

    Normative: broker/grant-lifecycle.md §"The ladder" (promotion is exactly one
    rung, recorded; demotion falls to lastSafeLevel) + docs/GAL.md §4 (any level →
    in-loop is always permitted — voluntary tightening needs no ceremony).
    """

    @pytest.mark.parametrize(
        "from_level,to_level",
        [
            (IN, OUT),  # level-skip up
            (IN, IN), (ON, ON), (OUT, OUT),  # lateral is not a promotion
            (ON, IN), (OUT, ON), (OUT, IN),  # downward is not a promotion
        ],
    )
    def test_invalid_promotion_raises_typed_error(self, from_level, to_level) -> None:
        with pytest.raises(TransitionError):
            validate_promotion_transition(from_level, to_level)

    @pytest.mark.parametrize("from_level,to_level", [(IN, ON), (ON, OUT)])
    def test_one_rung_promotions_are_the_valid_set(self, from_level, to_level) -> None:
        validate_promotion_transition(from_level, to_level)  # does not raise

    @pytest.mark.parametrize(
        "from_level,to_level", [(IN, ON), (IN, OUT), (ON, OUT)]
    )
    def test_demotion_path_never_raises_a_level(self, from_level, to_level) -> None:
        with pytest.raises(TransitionError):
            validate_demotion_transition(from_level, to_level)

    def test_level_skip_through_the_machine_writes_nothing(self) -> None:
        # The skip is unconstructible even when smuggled past the proposal
        # validator: the machine raises before the ceremony touches any store.
        store, _ = _seeded_store(_grant(level=IN))
        records = InMemoryPromotionRecordStore()
        with pytest.raises(TransitionError):
            _machine(store, records).promote(_proposal(IN, OUT), "human:checker")
        assert records.records == []
        assert store.get_grant(_PRINCIPAL, _ACTION_CLASS).grant.level is IN

    def test_fall_to_last_safe_level_is_valid(self) -> None:
        store, grant = _seeded_store(_grant(level=OUT, last_safe=ON))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.level is ON

    @pytest.mark.parametrize("from_level", [ON, OUT])
    def test_any_level_to_in_loop_tightening_is_valid(self, from_level) -> None:
        store, grant = _seeded_store(_grant(level=from_level, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).tighten_to_in_loop(
            grant, "human:maintainer", ts=_TS
        )
        assert updated.level is IN

    def test_lateral_re_ratification_is_valid_and_writes_no_record(self) -> None:
        store, grant = _seeded_store(_grant(level=ON))
        records = InMemoryPromotionRecordStore()
        updated = _machine(store, records).re_ratify(
            grant, "fresh-evidence-ref", "human:checker", ts=_TS
        )
        assert updated.level is grant.level
        assert records.records == []

    def test_repeat_breach_is_record_only_never_a_raise(self) -> None:
        # After a demotion, lastSafeLevel holds the PRIOR level, which sits above
        # the current level. A repeat breach must clamp (level stays), never raise.
        store, grant = _seeded_store(
            _grant(level=IN, last_safe=ON, demotion_reason="failing")
        )
        records = InMemoryPromotionRecordStore()
        updated, record = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.level is IN  # unchanged — no raise through the demote path
        assert record.recordType == "demotion"  # the breach still lands on the ledger


# ---------------------------------------------------------------------------
# L2 — the ledger records every level change
# ---------------------------------------------------------------------------


class TestL2LedgerRecordsEveryLevelChange:
    """Every level change appends its typed record on the ONE ceremony ledger, and
    the four recordTypes' shape rules hold.

    Normative: SCHEMAS.md §7 (four types, shape-rule table) + grant-lifecycle.md
    §"Record why you demoted" (demotion is recorded, not approved — ratified by
    system:demotion-evaluator) + docs/GAL.md §3 (no-record exemption superseded).
    """

    def test_promotion_writes_a_promotion_record(self) -> None:
        store, _ = _seeded_store(_grant(level=IN))
        records = InMemoryPromotionRecordStore()
        result = _machine(store, records).promote(_proposal(IN, ON), "human:checker")
        assert result.status == "ratified"
        (record,) = records.records
        assert record.recordType == "promotion"
        assert (record.fromLevel, record.toLevel) == (IN, ON)

    def test_demotion_appends_a_demotion_typed_record(self) -> None:
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        _, record = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert records.records == [record]
        assert record.recordType == "demotion"
        assert record.ratifiedBy == DEMOTION_RATIFIER

    def test_level_unchanged_repeat_breach_still_appends(self) -> None:
        store, grant = _seeded_store(
            _grant(level=IN, last_safe=IN, demotion_reason="failing")
        )
        records = InMemoryPromotionRecordStore()
        updated, record = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.level is IN
        assert [r.recordType for r in records.records] == ["demotion"]

    def test_tightening_appends_a_tightening_typed_record(self) -> None:
        store, grant = _seeded_store(_grant(level=OUT, last_safe=ON))
        records = InMemoryPromotionRecordStore()
        _, record = _machine(store, records).tighten_to_in_loop(
            grant, "human:maintainer", ts=_TS
        )
        assert records.records == [record]
        assert record.recordType == "tightening"
        assert record.toLevel is IN

    # --- the four shape rules (SCHEMAS.md §7 table) ---

    @pytest.mark.parametrize("record_type", ["promotion", "demotion", "bootstrap", "tightening"])
    def test_valid_shape_per_type_validates(self, record_type: str) -> None:
        assert PromotionRecord.model_validate(_record_payload(record_type)).recordType == record_type

    def test_promotion_maker_must_differ_from_checker(self) -> None:
        with pytest.raises(ValidationError):
            PromotionRecord.model_validate(
                _record_payload("promotion", ratifiedBy="human:maker")
            )

    @pytest.mark.parametrize("record_type", ["bootstrap", "tightening"])
    def test_maker_checker_not_enforced_off_the_promotion_path(self, record_type: str) -> None:
        record = PromotionRecord.model_validate(_record_payload(record_type))
        assert record.proposedBy == record.ratifiedBy  # sanctioned single-operator

    def test_demotion_must_be_ratified_by_the_system_evaluator(self) -> None:
        with pytest.raises(ValidationError):
            PromotionRecord.model_validate(
                _record_payload("demotion", ratifiedBy="human:maintainer", proposedBy="human:maintainer")
            )

    def test_bootstrap_from_level_must_be_none(self) -> None:
        with pytest.raises(ValidationError):
            PromotionRecord.model_validate(_record_payload("bootstrap", fromLevel=IN))

    def test_tightening_to_level_must_be_in_loop(self) -> None:
        with pytest.raises(ValidationError):
            PromotionRecord.model_validate(_record_payload("tightening", toLevel=ON))


# ---------------------------------------------------------------------------
# L3 — demotion determinism
# ---------------------------------------------------------------------------


class TestL3DemotionDeterminism:
    """Demotion is automatic, deterministic, and has no model in the loop —
    same inputs, same outcome; the trigger vocabulary is closed at three.

    Normative: grant-lifecycle.md §"Demotion — automatic, deterministic, no model
    in the loop" ("NO model call anywhere in this path") + §"The demotion triggers"
    ("Exactly three deterministic conditions") + docs/GAL.md §6.
    """

    def _run_once(self) -> tuple:
        store, _ = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        signal = DemotionSignal(
            trigger=DemotionTrigger.budget_breach,
            principal=_PRINCIPAL,
            action_class=_ACTION_CLASS,
            period="20260712",
            detail="error budget exceeded",
            ts=_TS,
        )
        outcome = run_demotion(
            _PRINCIPAL,
            _ACTION_CLASS,
            grant_store=store,
            record_store=records,
            signals=[signal],
            ts=_TS,
        )
        return outcome, records.records

    def test_same_inputs_same_outcome(self) -> None:
        first_outcome, first_records = self._run_once()
        second_outcome, second_records = self._run_once()
        assert first_outcome.status == second_outcome.status == "demoted"
        assert first_outcome.updated_grant.model_dump() == second_outcome.updated_grant.model_dump()
        assert first_records == second_records

    def test_pure_evaluator_is_referentially_transparent(self) -> None:
        grant = _grant(level=ON)
        metrics = _tripped(DemotionTrigger.stale_confidence)
        assert evaluate_demotion_triggers(grant, metrics) == evaluate_demotion_triggers(grant, metrics)

    def test_no_model_import_on_the_demotion_path(self) -> None:
        # The path that must run when the model is confused cannot import one:
        # scan demotion.py + runner.py + rung.py (the state machine the demotion
        # path flows through) for model-SDK modules and for the ceremony's
        # LLM checker seam. AST-level, so lazy in-function imports are caught too.
        model_modules = {
            "anthropic", "openai", "litellm", "langchain", "google.generativeai",
        }
        grants_dir = Path(inspect.getfile(evaluate_demotion_triggers)).parent
        for module_file in ("demotion.py", "runner.py", "rung.py"):
            tree = ast.parse((grants_dir / module_file).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or "", *(alias.name for alias in node.names)]
                else:
                    continue
                for name in names:
                    assert name.split(".")[0] not in model_modules, (
                        f"{module_file} imports model SDK {name!r} on the demotion path"
                    )
                    assert "Checker" not in name, (
                        f"{module_file} imports the LLM checker seam ({name!r}) — "
                        "no model belongs on the demotion path"
                    )

    def test_trigger_vocabulary_is_closed(self) -> None:
        assert {t.value for t in DemotionTrigger} == {
            "stale_confidence", "corroboration_failure", "budget_breach",
            "false_action",
        }

    def test_evaluator_ignores_unconfigured_tripped_triggers(self) -> None:
        # Tripped but not in the grant's demotionTriggers → no demotion.
        grant = _grant(level=ON, triggers=[DemotionTrigger.budget_breach])
        result = evaluate_demotion_triggers(grant, _tripped(DemotionTrigger.stale_confidence))
        assert result.should_demote is False

    def test_evaluator_ignores_configured_but_untripped_triggers(self) -> None:
        grant = _grant(level=ON, triggers=list(_ALL_TRIGGERS))
        result = evaluate_demotion_triggers(grant, _tripped())
        assert result.should_demote is False
        assert result.triggered_by == []


# ---------------------------------------------------------------------------
# L4 — the two reasons never collapse
# ---------------------------------------------------------------------------


class TestL4ReasonsNeverCollapse:
    """demotionReason keeps "failing" and "pending-evidence" distinct — they demand
    opposite responses (fix it vs gather data).

    Normative: grant-lifecycle.md §"Record *why* you demoted — and don't collapse
    the two reasons" (stale_confidence → pending-evidence; corroboration_failure
    and budget_breach → failing).
    """

    @pytest.mark.parametrize(
        "trigger,expected_reason",
        [
            (DemotionTrigger.stale_confidence, "pending-evidence"),
            (DemotionTrigger.corroboration_failure, "failing"),
            (DemotionTrigger.budget_breach, "failing"),
            (DemotionTrigger.false_action, "failing"),
        ],
    )
    def test_trigger_to_reason_mapping(self, trigger, expected_reason) -> None:
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        updated, record = _machine(store, records).demote(grant, _tripped(trigger), ts=_TS)
        assert updated.demotionReason == expected_reason
        assert record.demotionReason == expected_reason

    def test_multi_trigger_failing_dominates(self) -> None:
        # An actually-blown bound dominates a lapsed certification.
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        updated, record = _machine(store, records).demote(
            grant,
            _tripped(DemotionTrigger.stale_confidence, DemotionTrigger.budget_breach),
            ts=_TS,
        )
        assert updated.demotionReason == "failing"
        assert sorted(record.triggeredBy) == ["budget_breach", "stale_confidence"]


# ---------------------------------------------------------------------------
# L5 — lastSafeLevel invariants
# ---------------------------------------------------------------------------


class TestL5LastSafeLevelInvariants:
    """lastSafeLevel is never out-of-loop; demotion falls to it; after demotion it
    updates to the prior level as the re-promotion reference point.

    Normative: grant-lifecycle.md §"The ladder" ("always in-loop or on-loop, never
    out-of-loop") + SCHEMAS.md §1 lastSafeLevel note.
    """

    def test_schema_rejects_out_of_loop_last_safe_level(self) -> None:
        with pytest.raises(ValidationError):
            _grant(level=OUT, last_safe=OUT)

    def test_demote_defence_in_depth_rejects_bypassed_out_of_loop(self) -> None:
        # A record that dodged the schema validator (direct construction) must
        # still be refused by the demote path — never silently landed on
        # an unsupervised rung.
        bypassed = _grant(level=OUT, last_safe=ON).model_copy(
            update={"lastSafeLevel": OUT}
        )
        store = InMemoryGrantStore()
        records = InMemoryPromotionRecordStore()
        with pytest.raises(TransitionError, match="out-of-loop"):
            _machine(store, records).demote(
                bypassed, _tripped(DemotionTrigger.budget_breach), ts=_TS
            )

    @pytest.mark.parametrize(
        "level,last_safe", [(OUT, ON), (OUT, IN), (ON, IN)]
    )
    def test_demotion_falls_to_last_safe_level(self, level, last_safe) -> None:
        store, grant = _seeded_store(_grant(level=level, last_safe=last_safe))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.level is last_safe

    def test_post_demotion_reference_point_updates_to_prior_level(self) -> None:
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.lastSafeLevel is ON  # the prior level, for re-promotion

    def test_prior_level_out_of_loop_never_becomes_the_reference(self) -> None:
        # Demoting FROM out-of-loop cannot stamp out-of-loop into lastSafeLevel.
        store, grant = _seeded_store(_grant(level=OUT, last_safe=ON))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.lastSafeLevel is ON  # unchanged, not out-of-loop


# ---------------------------------------------------------------------------
# L6 — write discipline
# ---------------------------------------------------------------------------


class TestL6WriteDiscipline:
    """Demotion writes are conditional (UpdateItem semantics: lower, never mint),
    the ledger is append-only, and a quarantined grant is never demoted.

    Normative: grant-lifecycle.md §"The grant-store write-protection seam" +
    SCHEMAS.md §7 Storage note (conditioned UpdateItem, never overwritten).
    """

    def _concurrent_modification(self) -> tuple[InMemoryGrantStore, Grant]:
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        # Concurrent writer lands between our read and the demotion write.
        store.put_grant(_grant(level=OUT, last_safe=ON))
        return store, grant

    def test_concurrent_modification_raises_conflict(self) -> None:
        store, stale_grant = self._concurrent_modification()
        with pytest.raises(DemotionConflictError):
            apply_demotion(
                stale_grant,
                evaluate_demotion_triggers(stale_grant, _tripped(DemotionTrigger.budget_breach)),
                store=store,
                record_store=InMemoryPromotionRecordStore(),
                ts=_TS,
            )

    def test_stale_hash_write_cannot_land(self) -> None:
        store, stale_grant = self._concurrent_modification()
        records = InMemoryPromotionRecordStore()
        with pytest.raises(DemotionConflictError):
            apply_demotion(
                stale_grant,
                evaluate_demotion_triggers(stale_grant, _tripped(DemotionTrigger.budget_breach)),
                store=store,
                record_store=records,
                ts=_TS,
            )
        # The concurrently-written grant is untouched and nothing hit the ledger.
        assert store.get_grant(_PRINCIPAL, _ACTION_CLASS).grant.level is OUT
        assert records.records == []

    def test_demotion_never_creates_a_grant(self) -> None:
        absent = _grant(level=ON, last_safe=IN)  # never put into the store
        store = InMemoryGrantStore()
        with pytest.raises(GrantNotFoundError):
            apply_demotion(
                absent,
                evaluate_demotion_triggers(absent, _tripped(DemotionTrigger.budget_breach)),
                store=store,
                record_store=InMemoryPromotionRecordStore(),
                ts=_TS,
            )
        assert store.get_grant(_PRINCIPAL, _ACTION_CLASS).grant is None

    def test_ledger_is_append_only(self) -> None:
        records = InMemoryPromotionRecordStore()
        record = PromotionRecord.model_validate(_record_payload("demotion"))
        records.put_record(record)
        with pytest.raises(RecordAlreadyExistsError):
            records.put_record(record)

    def test_quarantined_grant_is_never_demoted(self) -> None:
        store, _ = _seeded_store(_grant(level=OUT, last_safe=ON))
        # Tamper with the stored record so the HMAC no longer verifies.
        (key,) = store._store.keys()
        store._store[key]["data"] = store._store[key]["data"].replace(
            '"evidence":"', '"evidence":"tampered-', 1
        )
        records = InMemoryPromotionRecordStore()
        outcome = run_demotion(
            _PRINCIPAL,
            _ACTION_CLASS,
            grant_store=store,
            record_store=records,
            signals=[
                DemotionSignal(
                    trigger=DemotionTrigger.budget_breach,
                    principal=_PRINCIPAL,
                    action_class=_ACTION_CLASS,
                    period="20260712",
                    detail="error budget exceeded",
                    ts=_TS,
                )
            ],
            ts=_TS,
        )
        assert outcome.status == "quarantined"
        assert outcome.updated_grant is None
        assert records.records == []

    @staticmethod
    def _tamper_stored(store: InMemoryGrantStore) -> None:
        """Tamper the stored record WITHOUT touching its hash attribute — the
        laundering shape: a caller-held copy still hash-matches the store, so
        only the quarantine check (not hash equality) can refuse the write."""
        (key,) = store._store.keys()
        store._store[key]["data"] = store._store[key]["data"].replace(
            '"evidence":"', '"evidence":"tampered-', 1
        )

    def test_quarantined_grant_refused_by_apply_demotion(self) -> None:
        # Without the quarantine check, apply_demotion would re-write the
        # tampered grant under a fresh valid HMAC — laundering the quarantine.
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        self._tamper_stored(store)
        records = InMemoryPromotionRecordStore()
        with pytest.raises(QuarantinedGrantError):
            apply_demotion(
                grant,
                evaluate_demotion_triggers(grant, _tripped(DemotionTrigger.budget_breach)),
                store=store,
                record_store=records,
                ts=_TS,
            )
        assert records.records == []

    def test_quarantined_grant_refused_by_tighten_to_in_loop(self) -> None:
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        self._tamper_stored(store)
        records = InMemoryPromotionRecordStore()
        with pytest.raises(QuarantinedGrantError):
            _machine(store, records).tighten_to_in_loop(grant, "human:maintainer", ts=_TS)
        assert records.records == []


# ---------------------------------------------------------------------------
# L7 — hysteresis
# ---------------------------------------------------------------------------


class TestL7Hysteresis:
    """Promotion eligibility needs BOTH clean runs and dwell; demotion has no
    dwell/grace — a fired trigger demotes immediately (fast demotion is a safety
    property).

    Normative: grant-lifecycle.md §"Hysteresis — so it can't flap" (different
    thresholds + dwell time on the way UP) + §Demotion (automatic — no waiting
    period is specified or permitted on the way DOWN).
    """

    _NOW = datetime.datetime(2026, 7, 12, tzinfo=datetime.timezone.utc)
    _DWELL = datetime.timedelta(days=7)

    def _eligible(self, clean_runs: int, held_for: datetime.timedelta) -> bool:
        counters = PromotionEligibilityCounters(
            clean_runs_since_promotion=clean_runs,
            last_transition_ts=(self._NOW - held_for).isoformat(),
        )
        return is_eligible_for_promotion(
            _grant(level=ON, last_safe=IN),
            counters,
            min_clean_runs=10,
            min_dwell=self._DWELL,
            now=self._NOW,
        )

    def test_clean_runs_alone_are_not_enough(self) -> None:
        assert self._eligible(clean_runs=100, held_for=datetime.timedelta(days=1)) is False

    def test_dwell_alone_is_not_enough(self) -> None:
        assert self._eligible(clean_runs=3, held_for=datetime.timedelta(days=30)) is False

    def test_both_thresholds_met_is_eligible(self) -> None:
        assert self._eligible(clean_runs=10, held_for=self._DWELL) is True

    def test_a_fired_trigger_demotes_immediately(self) -> None:
        # The grant transitioned THIS instant (ts = now); demotion still lands —
        # there is no implicit grace period on the way down.
        store, grant = _seeded_store(_grant(level=ON, last_safe=IN))
        records = InMemoryPromotionRecordStore()
        updated, _ = _machine(store, records).demote(
            grant, _tripped(DemotionTrigger.budget_breach), ts=_TS
        )
        assert updated.level is IN

    def test_demote_path_exposes_no_suppression_parameter(self) -> None:
        # The asymmetry is structural: the promotion side takes min_dwell /
        # min_clean_runs; no demotion-path callable accepts any dwell, grace,
        # cooldown, or suppression knob.
        suppression_tokens = ("dwell", "grace", "cooldown", "suppress", "delay", "min_")
        for path_callable in (
            evaluate_demotion_triggers,
            apply_demotion,
            run_demotion,
            RungStateMachine.demote,
        ):
            for param in inspect.signature(path_callable).parameters:
                assert not any(token in param for token in suppression_tokens), (
                    f"{path_callable.__qualname__} exposes suppression parameter {param!r}"
                )


# ---------------------------------------------------------------------------
# L8 — budget-breach derivation parity
# ---------------------------------------------------------------------------


class _RecordingEnforcementStore:
    """EnforcementStore fake recording exactly which counter key was read."""

    def __init__(self, value: float) -> None:
        self.value = value
        self.requested: list[str] = []

    def read_counter(self, counter_key: str) -> float:
        self.requested.append(counter_key)
        return self.value


class TestL8BudgetBreachDerivationParity:
    """derive_budget_breach reads the PIP's exact counter key and comparison, so
    the runner and the PIP can never disagree about what "breached" means.

    Normative: SCHEMAS.md §1 DemotionSignal note + the PIP's error_budget_breached
    fact (prototype/broker_server.py: scoped_counter_key(principal, tool, op,
    "error_budget"), spent >= tolerance).
    """

    _NOW = datetime.datetime(2026, 7, 12, tzinfo=datetime.timezone.utc)

    def _derive(self, spent: float, tolerance: float = 0.5):
        store = _RecordingEnforcementStore(spent)
        signal = derive_budget_breach(
            _PRINCIPAL,
            "email",
            "send",
            enforcement_store=store,
            tolerance=tolerance,
            now=self._NOW,
        )
        return signal, store

    def test_reads_exactly_the_scoped_error_budget_key(self) -> None:
        _, store = self._derive(spent=0.0)
        assert store.requested == [
            scoped_counter_key(_PRINCIPAL, "email", "send", "error_budget")
        ]

    def test_comparison_is_greater_or_equal(self) -> None:
        at_tolerance, _ = self._derive(spent=0.5)
        assert at_tolerance is not None  # spent == tolerance breaches (>=, not >)
        just_under, _ = self._derive(spent=0.4999)
        assert just_under is None

    def test_signal_mirrors_the_pep_field_population(self) -> None:
        signal, _ = self._derive(spent=0.7)
        assert signal.trigger is DemotionTrigger.budget_breach
        assert signal.principal == _PRINCIPAL
        assert signal.action_class == "email.send"
        assert signal.period == "20260712"
