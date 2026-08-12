"""Conformance suite for the evidence contract (#184) — clauses E1–E10.

Contract-tier surface requires a conformance suite (`docs/contract-vs-reference.md`);
this is it, mirroring `broker/EVIDENCE.md`'s clause table (and the C6–C8 style of
`broker/CONNECTOR-AUTH.md` / `test_iam_scoping.py`). Plain pytest, one class per
clause, no AWS/network/model.

| Clause | Guarantee |
|---|---|
| **E1** | `ConfidenceArtifact` round-trips; rejects unknown keys and out-of-range values; per-method evidence discriminates. |
| **E2** | The `ConfidenceMethod` catalog is closed — an unknown/import-path `method` is rejected. |
| **E3** | `derive_blast_class` truth table: high = write∧external∧¬reversible; medium = other write; low = read. |
| **E4** | The `Envelope.confidence` knob ships OFF — absent knob validates; `meets_bar(None-knob)` is always True. |
| **E5** | `effective_blast_class` is tighten-only — an override forces high; nothing lowers a derived class. |
| **E6** | `meets_bar`: stale → False, method-not-accepted → False, no-artifact-with-bar → False, at/above bar → True. |
| **E7** | `error_budget_draw` = error_prob × weight; a missing weight raises loudly (ValueError). |
| **E8** | Caps `actions_per_run` rename (#163): both spellings load to one field; canonical dump; both-at-once rejected; no extra-key leak; hash equal. |
| **E9** | `DemotionSignal` round-trips; trigger vocabulary is exactly the four `DemotionTrigger` values; extra keys rejected. |
| **E15** | `CorroborationRecord` (#192) round-trips; incoherent counts rejected; `failed` ⇔ `agreeing < k`. |
| **E10** | Loud legacy rejection: a retired `abstention_thresholds` key fails validation; an incoherent `Confidence` knob is rejected. |
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from safe_agents.broker.schemas import (
    BlastClass,
    Confidence,
    ConfidenceArtifact,
    CorroborationRecord,
    DemotionSignal,
    Envelope,
    ToolOp,
    compute_envelope_hash,
    derive_blast_class,
    effective_blast_class,
    error_budget_draw,
    meets_bar,
)

# ---------------------------------------------------------------------------
# Builders — via the real schemas
# ---------------------------------------------------------------------------

_TS = "2026-07-12T00:00:00Z"


def _op(effect: str = "write", external: bool = True, reversible: bool | None = None,
        tool: str = "email", op: str = "send") -> ToolOp:
    return ToolOp.model_validate(
        {"tool": tool, "op": op, "effect": effect, "external": external, "reversible": reversible}
    )


def _artifact(confidence: float = 0.9, error_prob: float = 0.1, stale: bool = False,
              method: str = "self-consistency") -> ConfidenceArtifact:
    evidence: dict = {"method": method}
    if method == "conformal":
        evidence.update(coverage=0.9, threshold=0.4, calibration_size=500)
    else:
        evidence.update(samples=5, agreement=0.8) if method == "self-consistency" \
            else evidence.update(members=3, agreement=0.8)
    return ConfidenceArtifact.model_validate(
        {"confidence": confidence, "error_prob": error_prob, "stale": stale,
         "evidence": evidence, "computed_at": _TS}
    )


# ---------------------------------------------------------------------------
# E1 — artifact shape
# ---------------------------------------------------------------------------


class TestE1ArtifactShape:
    def test_round_trips(self) -> None:
        art = _artifact()
        assert ConfidenceArtifact.model_validate(art.model_dump()) == art

    def test_rejects_unknown_key(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceArtifact.model_validate(
                {"confidence": 0.9, "error_prob": 0.1, "computed_at": _TS,
                 "evidence": {"method": "ensemble", "members": 2, "agreement": 1.0},
                 "surprise": True}
            )

    @pytest.mark.parametrize("field", ["confidence", "error_prob"])
    @pytest.mark.parametrize("bad", [-0.01, 1.01])
    def test_rejects_out_of_range(self, field: str, bad: float) -> None:
        payload = {"confidence": 0.9, "error_prob": 0.1, "computed_at": _TS,
                   "evidence": {"method": "ensemble", "members": 2, "agreement": 1.0}}
        payload[field] = bad
        with pytest.raises(ValidationError):
            ConfidenceArtifact.model_validate(payload)

    def test_per_method_evidence_discriminates(self) -> None:
        for method in ("self-consistency", "ensemble", "conformal"):
            art = _artifact(method=method)
            assert art.evidence.method == method

    def test_wrong_fields_for_method_rejected(self) -> None:
        # conformal fields on a self-consistency evidence must be rejected
        with pytest.raises(ValidationError):
            ConfidenceArtifact.model_validate(
                {"confidence": 0.9, "error_prob": 0.1, "computed_at": _TS,
                 "evidence": {"method": "self-consistency", "coverage": 0.9,
                              "threshold": 0.4, "calibration_size": 5}}
            )

    def test_annotations_default_empty_and_attach_only(self) -> None:
        art = _artifact()
        assert art.annotations == []
        art2 = ConfidenceArtifact.model_validate(
            {**art.model_dump(), "annotations": ["reviewer: suspicious phrasing"]}
        )
        assert art2.annotations == ["reviewer: suspicious phrasing"]


# ---------------------------------------------------------------------------
# E2 — closed catalog
# ---------------------------------------------------------------------------


class TestE2ClosedCatalog:
    def test_unknown_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceArtifact.model_validate(
                {"confidence": 0.9, "error_prob": 0.1, "computed_at": _TS,
                 "evidence": {"method": "vibes", "samples": 5, "agreement": 0.8}}
            )

    def test_import_path_is_not_a_method(self) -> None:
        # the config-provenance "store cannot inject code" genre: a dotted path is
        # not a selectable method.
        with pytest.raises(ValidationError):
            ConfidenceArtifact.model_validate(
                {"confidence": 0.9, "error_prob": 0.1, "computed_at": _TS,
                 "evidence": {"method": "my.module:Thing", "samples": 5, "agreement": 0.8}}
            )


# ---------------------------------------------------------------------------
# E3 — blast-derivation truth table
# ---------------------------------------------------------------------------

# (effect, external, reversible) → expected BlastClass
_BLAST_TRUTH: list[tuple[str, bool, bool | None, BlastClass]] = [
    ("write", True, False, "high"),
    ("write", True, None, "high"),
    ("write", True, True, "medium"),
    ("write", False, False, "medium"),
    ("write", False, None, "medium"),
    ("write", False, True, "medium"),
    ("read", True, None, "low"),
    ("read", False, None, "low"),
    ("read", True, True, "low"),
    ("read", False, False, "low"),
]


class TestE3BlastDerivation:
    @pytest.mark.parametrize("effect,external,reversible,expected", _BLAST_TRUTH)
    def test_truth_table(self, effect, external, reversible, expected) -> None:
        assert derive_blast_class(_op(effect=effect, external=external, reversible=reversible)) == expected


# ---------------------------------------------------------------------------
# E4 — knob ships OFF
# ---------------------------------------------------------------------------


class TestE4KnobShipsOff:
    def test_envelope_without_confidence_validates(self) -> None:
        env = Envelope.model_validate({"polarity": "abstain"})
        assert env.confidence is None

    def test_no_bar_means_no_gate(self) -> None:
        # knob None → any artifact (and no artifact) meets the (absent) bar.
        assert meets_bar(_artifact(confidence=0.0), None) is True
        assert meets_bar(None, None) is True

    def test_knob_with_only_a_budget_has_no_per_call_bar(self) -> None:
        knob = Confidence.model_validate(
            {"error_budget_tolerance": 0.5,
             "blast_weights": {"low": 1.0, "medium": 2.0, "high": 5.0}}
        )
        # min_confidence unset → meets_bar is always True (no per-call bar).
        assert meets_bar(_artifact(confidence=0.0), knob) is True
        assert meets_bar(None, knob) is True


# ---------------------------------------------------------------------------
# E5 — tighten-only override
# ---------------------------------------------------------------------------


class TestE5TightenOnly:
    def test_override_forces_high(self) -> None:
        op = _op(effect="read", tool="crm", op="list_deals")  # derives low
        assert derive_blast_class(op) == "low"
        assert effective_blast_class(op, {"email.send"}) == "low"  # unrelated override, unchanged
        assert effective_blast_class(op, {"email.send"} | {f"{op.tool}.{op.op}"}) == "high"

    def test_no_input_lowers_a_derived_class(self) -> None:
        # By exhaustion over the truth table: for every op, effective_blast_class is
        # either the derived class (no matching override) or "high" (matching
        # override) — never anything lower than derived. There is no lowering input.
        for effect, external, reversible, expected in _BLAST_TRUTH:
            op = _op(effect=effect, external=external, reversible=reversible)
            # no override → derived
            assert effective_blast_class(op, set()) == expected
            # matching override → high (never below derived)
            assert effective_blast_class(op, {f"{op.tool}.{op.op}"}) == "high"


# ---------------------------------------------------------------------------
# E6 — meets_bar semantics
# ---------------------------------------------------------------------------


class TestE6MeetsBar:
    def _bar(self, methods: list[str] | None = None) -> Confidence:
        payload: dict = {"min_confidence": 0.8}
        if methods is not None:
            payload["methods"] = methods
        return Confidence.model_validate(payload)

    def test_at_or_above_bar_true(self) -> None:
        assert meets_bar(_artifact(confidence=0.8), self._bar()) is True
        assert meets_bar(_artifact(confidence=0.95), self._bar()) is True

    def test_below_bar_false(self) -> None:
        assert meets_bar(_artifact(confidence=0.5), self._bar()) is False

    @pytest.mark.parametrize("method", ["self-consistency", "conformal"])
    def test_stale_voids_even_above_bar(self, method: str) -> None:
        art = _artifact(confidence=1.0, stale=True, method=method)
        assert meets_bar(art, self._bar()) is False

    def test_method_not_accepted_false(self) -> None:
        art = _artifact(confidence=1.0, method="ensemble")
        assert meets_bar(art, self._bar(methods=["conformal"])) is False

    def test_method_accepted_true(self) -> None:
        art = _artifact(confidence=0.9, method="conformal")
        assert meets_bar(art, self._bar(methods=["conformal"])) is True

    def test_no_artifact_with_bar_false(self) -> None:
        assert meets_bar(None, self._bar()) is False


# ---------------------------------------------------------------------------
# E7 — budget draw
# ---------------------------------------------------------------------------


class TestE7BudgetDraw:
    _WEIGHTS = {"low": 1.0, "medium": 2.0, "high": 5.0}

    @pytest.mark.parametrize("blast_class,weight", [("low", 1.0), ("medium", 2.0), ("high", 5.0)])
    def test_draw_is_error_prob_times_weight(self, blast_class: BlastClass, weight: float) -> None:
        art = _artifact(error_prob=0.1)
        assert error_budget_draw(art, blast_class, self._WEIGHTS) == pytest.approx(0.1 * weight)

    def test_missing_weight_raises(self) -> None:
        art = _artifact(error_prob=0.1)
        with pytest.raises(ValueError, match="blast_radius weight"):
            error_budget_draw(art, "high", {"low": 1.0, "medium": 2.0})


# ---------------------------------------------------------------------------
# E8 — caps rename (#163)
# ---------------------------------------------------------------------------


class TestE8CapsRename:
    def test_both_spellings_load_same_value(self) -> None:
        from safe_agents.broker.schemas.envelope import Caps

        old = Caps.model_validate({"actions_per_run": 40})
        new = Caps.model_validate({"actions_per_utc_day": 40})
        assert old.actions_per_utc_day == 40
        assert new.actions_per_utc_day == 40

    def test_canonical_dump_key(self) -> None:
        from safe_agents.broker.schemas.envelope import Caps

        dumped = Caps.model_validate({"actions_per_run": 40}).model_dump()
        assert dumped["actions_per_utc_day"] == 40
        assert "actions_per_run" not in dumped, "legacy spelling must not leak as an extra key"

    def test_both_spellings_at_once_rejected(self) -> None:
        from safe_agents.broker.schemas.envelope import Caps

        with pytest.raises(ValidationError):
            Caps.model_validate({"actions_per_run": 40, "actions_per_utc_day": 40})

    def test_envelope_hash_equal_across_spellings(self) -> None:
        old = Envelope.model_validate({"polarity": "abstain", "caps": {"actions_per_run": 40}})
        new = Envelope.model_validate({"polarity": "abstain", "caps": {"actions_per_utc_day": 40}})
        assert compute_envelope_hash(old) == compute_envelope_hash(new)

    def test_period_spelling_loads_dumps_canonically_and_hash_equal(self) -> None:
        """#212: `actions_per_period` is the honest spelling under a non-day
        counter_period — same field, canonical dump key, same envelope hash."""
        from safe_agents.broker.schemas.envelope import Caps

        per_period = Caps.model_validate({"actions_per_period": 40})
        assert per_period.actions_per_utc_day == 40
        dumped = per_period.model_dump()
        assert dumped["actions_per_utc_day"] == 40
        assert "actions_per_period" not in dumped
        env = Envelope.model_validate(
            {"polarity": "abstain", "caps": {"actions_per_period": 40}}
        )
        canonical = Envelope.model_validate(
            {"polarity": "abstain", "caps": {"actions_per_utc_day": 40}}
        )
        assert compute_envelope_hash(env) == compute_envelope_hash(canonical)

    @pytest.mark.parametrize(
        "pair",
        [
            {"actions_per_period": 40, "actions_per_utc_day": 40},
            {"actions_per_period": 40, "actions_per_run": 40},
        ],
        ids=["period+canonical", "period+legacy"],
    )
    def test_period_spelling_double_declaration_rejected(self, pair: dict) -> None:
        from safe_agents.broker.schemas.envelope import Caps

        with pytest.raises(ValidationError):
            Caps.model_validate(pair)


# ---------------------------------------------------------------------------
# E9 — demotion signal
# ---------------------------------------------------------------------------

_PRINCIPAL = {"agentId": "agent-1", "skill": "trade", "user": "maintainer", "tier": "B"}


class TestE9DemotionSignal:
    def _signal(self, trigger: str = "budget_breach") -> dict:
        return {"trigger": trigger, "principal": _PRINCIPAL, "action_class": "example.read",
                "period": "20260712", "detail": "error budget exceeded", "ts": _TS}

    def test_round_trips(self) -> None:
        sig = DemotionSignal.model_validate(self._signal())
        assert DemotionSignal.model_validate(sig.model_dump(mode="json")) == sig

    @pytest.mark.parametrize(
        "trigger",
        ["stale_confidence", "corroboration_failure", "budget_breach", "false_action"],
    )
    def test_all_triggers_accepted(self, trigger: str) -> None:
        assert DemotionSignal.model_validate(self._signal(trigger)).trigger.value == trigger

    def test_unknown_trigger_rejected(self) -> None:
        with pytest.raises(ValidationError):
            DemotionSignal.model_validate(self._signal("some_new_trigger"))

    def test_extra_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            DemotionSignal.model_validate({**self._signal(), "extra": 1})


# ---------------------------------------------------------------------------
# E10 — loud legacy rejection + incoherent-knob rejection
# ---------------------------------------------------------------------------


class TestE10LoudLegacyRejection:
    def test_retired_abstention_thresholds_key_rejected(self) -> None:
        # A pre-#184 stored dump carries "abstention_thresholds": null. extra="forbid"
        # rejects it loudly (the intended fail-closed path — re-seed cures it),
        # rather than silently coercing.
        with pytest.raises(ValidationError):
            Envelope.model_validate({"polarity": "abstain", "abstention_thresholds": None})

    def test_budget_without_weights_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Confidence.model_validate({"error_budget_tolerance": 0.5})

    def test_budget_with_incomplete_weights_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Confidence.model_validate(
                {"error_budget_tolerance": 0.5, "blast_weights": {"low": 1.0, "high": 5.0}}
            )

    def test_empty_knob_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Confidence.model_validate({})

    def test_nonpositive_weight_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Confidence.model_validate(
                {"error_budget_tolerance": 0.5,
                 "blast_weights": {"low": 0.0, "medium": 2.0, "high": 5.0}}
            )


# ---------------------------------------------------------------------------
# E15 — corroboration record (#192): the corroboration_failure typed input
# ---------------------------------------------------------------------------


class TestE15CorroborationRecord:
    def _base(self, **overrides) -> dict:
        d = {"k": 2, "n": 3, "agreeing": 1, "computed_at": "2026-07-14T00:00:00+00:00"}
        d.update(overrides)
        return d

    def test_round_trips(self) -> None:
        rec = CorroborationRecord.model_validate(self._base(stale_sources=1))
        assert CorroborationRecord.model_validate_json(rec.model_dump_json()) == rec

    def test_extra_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CorroborationRecord.model_validate(self._base(passed=True))

    def test_incoherent_counts_rejected(self) -> None:
        for bad in (
            {"k": 5},          # quorum exceeds sources
            {"agreeing": 4},   # agreement exceeds sources
            {"stale_sources": 4},
            {"k": 0},
            {"n": 0},
            {"agreeing": -1},
        ):
            with pytest.raises(ValidationError):
                CorroborationRecord.model_validate(self._base(**bad))

    def test_failed_predicate_boundaries(self) -> None:
        assert CorroborationRecord.model_validate(self._base(agreeing=1)).failed
        assert not CorroborationRecord.model_validate(self._base(agreeing=2)).failed
        assert not CorroborationRecord.model_validate(self._base(agreeing=3)).failed
