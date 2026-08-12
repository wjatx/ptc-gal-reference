"""Tests for the promotion predicate (sa#57).

The predicate is a pure function; no mocks, no I/O. All test data is injected
directly. One data-driven table drives the eligibility cases; each row names
the gate it exercises:

- Rate gates: below/at/above threshold; counter decomposition
- Sample gates: insufficient/zero observations; boundary at min_observations
- Evidence gates (sa#57): artifact missing; artifact stale; uncovered
- Provenance ceiling (docs/PTC.md §9): every maturity × both acting rungs
- Error budget: unset knob passes; at/over tolerance fails
- Blast class: high-blast eligible carries requires_human_ratification=True;
  low/medium do not; an ineligible result never sets the flag
- Invalid args raise ValueError (window_n, threshold, counters,
  provenance_maturity)
- in-loop target (the Recommend-origin grant-creating first promotion): no
  provenance ceiling, evidence gates still apply
"""

import pytest

from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.broker.grants.predicate import (
    ActionClassMetrics,
    PredicateResult,
    REQUIRED_PROVENANCE_MATURITY,
    evaluate_promotion_predicate,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-test", skill="email", user="alice", tier="B")
ACTION_CLASS = "read.files"


def _artifact(*, stale: bool = False) -> ConfidenceArtifact:
    """A valid constructed-confidence artifact (#184)."""
    return ConfidenceArtifact(
        confidence=0.9,
        error_prob=0.1,
        evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
        stale=stale,
        computed_at="2026-07-12T00:00:00+00:00",
    )


VALID_ARTIFACT = _artifact()
STALE_ARTIFACT = _artifact(stale=True)


def _eval(
    false_action: int = 0,
    human_override: int = 0,
    obs: int = 50,
    *,
    window_n: int = 100,
    min_observations: int = 10,
    threshold: float = 0.05,
    target_level: AutonomyLevel = AutonomyLevel.on_loop,
    artifact: ConfidenceArtifact | None = VALID_ARTIFACT,
    covered: bool = True,
    provenance_maturity: str = "signed-lineage",
    blast_class: str = "low",
    error_budget: ErrorBudget | None = None,
    principal: Principal = PRINCIPAL,
    action_class: str = ACTION_CLASS,
) -> PredicateResult:
    """Convenience wrapper: passing evidence terms by default, so each case
    only overrides the gate it exercises."""
    return evaluate_promotion_predicate(
        principal,
        action_class,
        metrics=ActionClassMetrics(
            false_action_count=false_action,
            human_override_count=human_override,
            observation_count=obs,
        ),
        window_n=window_n,
        min_observations=min_observations,
        threshold=threshold,
        target_level=target_level,
        artifact=artifact,
        covered=covered,
        provenance_maturity=provenance_maturity,
        blast_class=blast_class,
        error_budget=error_budget,
    )


# ---------------------------------------------------------------------------
# Data-driven eligibility table — (label, kwargs, expected_eligible,
# expected_reason_fragment). The fragment pins WHICH gate answered.
# ---------------------------------------------------------------------------

ON = AutonomyLevel.on_loop
OUT = AutonomyLevel.out_of_loop

ELIGIBILITY_CASES = [
    # --- rate gate: True cases ---
    ("perfect record", dict(), True, "error_rate=0.0000"),
    ("1 error in 50 → 0.02 < 0.05", dict(false_action=1), True, "error_rate"),
    ("2 false_action in 100 → 0.02 < 0.05", dict(false_action=2, obs=100), True, "error_rate"),
    ("2 human_override in 100 → 0.02 < 0.05", dict(human_override=2, obs=100), True, "error_rate"),
    ("combined 2/100 → 0.02 < 0.05", dict(false_action=1, human_override=1, obs=100), True, "error_rate"),
    ("exactly min_observations, zero errors", dict(obs=10), True, "error_rate"),
    ("large window, no errors", dict(obs=1000, window_n=1000), True, "error_rate"),
    ("combined 2+2=4/100 → 0.04 < 0.05", dict(false_action=2, human_override=2, obs=100), True, "error_rate"),
    ("9/100 = 0.09 < threshold 0.10", dict(false_action=9, obs=100, threshold=0.10), True, "error_rate"),
    ("1 obs >= min 1, zero errors", dict(obs=1, min_observations=1), True, "error_rate"),
    # --- rate gate: at/above threshold ---
    ("rate exactly at threshold", dict(false_action=5, obs=100), False, ">= threshold"),
    ("rate 0.06 > 0.05", dict(false_action=6, obs=100), False, ">= threshold"),
    ("combined 15/100 → 0.15 >> 0.05", dict(false_action=10, human_override=5, obs=100), False, ">= threshold"),
    ("human_override alone at threshold", dict(human_override=5, obs=100), False, ">= threshold"),
    ("combined 3+3=6/100 → 0.06 > 0.05", dict(false_action=3, human_override=3, obs=100), False, ">= threshold"),
    ("1 error in 10 → 0.10 > 0.05", dict(false_action=1, obs=10), False, ">= threshold"),
    ("10/100 = 0.10 == threshold 0.10", dict(false_action=10, obs=100, threshold=0.10), False, ">= threshold"),
    ("1 error in 1 obs → rate 1.0", dict(false_action=1, obs=1, min_observations=1), False, ">= threshold"),
    # --- sample gate ---
    ("9 obs < min 10", dict(obs=9), False, "insufficient observations"),
    ("zero observations", dict(obs=0), False, "insufficient observations"),
    ("1 obs << min 10", dict(obs=1), False, "insufficient observations"),
    ("5 obs < min 10, error present", dict(false_action=1, obs=5), False, "insufficient observations"),
    # --- evidence gates (sa#57) ---
    ("artifact missing", dict(artifact=None), False, "evidence artifact missing"),
    ("artifact stale", dict(artifact=STALE_ARTIFACT), False, "stale"),
    ("uncovered", dict(covered=False), False, "covered-distribution"),
    # --- provenance ceiling: every maturity × both acting rungs ---
    ("taint-bit → on-loop fails", dict(provenance_maturity="taint-bit", target_level=ON), False, "provenance maturity"),
    ("taint-bit → out-of-loop fails", dict(provenance_maturity="taint-bit", target_level=OUT), False, "provenance maturity"),
    ("lineage → on-loop fails", dict(provenance_maturity="lineage", target_level=ON), False, "provenance maturity"),
    ("lineage → out-of-loop fails", dict(provenance_maturity="lineage", target_level=OUT), False, "provenance maturity"),
    ("signed-lineage → on-loop passes", dict(provenance_maturity="signed-lineage", target_level=ON), True, "error_rate"),
    ("signed-lineage → out-of-loop passes", dict(provenance_maturity="signed-lineage", target_level=OUT), True, "error_rate"),
    # --- error budget: None passes (knob OFF); spent >= tolerance fails ---
    ("budget unset → no gate", dict(error_budget=None), True, "error_rate"),
    ("budget under tolerance passes", dict(error_budget=ErrorBudget(tolerance=1.0, spent=0.5)), True, "error_rate"),
    ("budget at tolerance fails", dict(error_budget=ErrorBudget(tolerance=1.0, spent=1.0)), False, "error budget in breach"),
    ("budget over tolerance fails", dict(error_budget=ErrorBudget(tolerance=1.0, spent=1.5)), False, "error budget in breach"),
    # --- blast class never blocks eligibility by itself ---
    ("high blast, clean record → still eligible", dict(blast_class="high"), True, "human ratification"),
    ("medium blast, clean record → eligible", dict(blast_class="medium"), True, "error_rate"),
]


@pytest.mark.parametrize(
    "label, kwargs, expected_eligible, reason_fragment",
    ELIGIBILITY_CASES,
    ids=[c[0] for c in ELIGIBILITY_CASES],
)
def test_predicate_cases(label, kwargs, expected_eligible, reason_fragment):
    result = _eval(**kwargs)
    assert result.eligible == expected_eligible, (
        f"case '{label}': expected eligible={expected_eligible}, got {result}"
    )
    assert reason_fragment in result.reason, (
        f"case '{label}': expected reason to contain {reason_fragment!r}, "
        f"got {result.reason!r}"
    )


# ---------------------------------------------------------------------------
# Gate order — an earlier gate answers before a later one gets a say
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label, kwargs, winning_fragment",
    [
        # provenance ceiling beats a missing artifact
        (
            "provenance before artifact",
            dict(provenance_maturity="taint-bit", artifact=None),
            "provenance maturity",
        ),
        # missing artifact beats uncovered
        ("artifact before covered", dict(artifact=None, covered=False), "evidence artifact missing"),
        # stale beats uncovered
        ("stale before covered", dict(artifact=STALE_ARTIFACT, covered=False), "stale"),
        # budget breach beats insufficient observations
        (
            "budget before sample size",
            dict(error_budget=ErrorBudget(tolerance=1.0, spent=2.0), obs=1),
            "error budget in breach",
        ),
        # insufficient observations beats error rate
        ("sample size before rate", dict(false_action=1, obs=1), "insufficient observations"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_gate_order(label, kwargs, winning_fragment):
    result = _eval(**kwargs)
    assert not result.eligible
    assert winning_fragment in result.reason


# ---------------------------------------------------------------------------
# requires_human_ratification — set only on an ELIGIBLE high-blast result
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label, kwargs, expected_flag",
    [
        ("high blast + eligible → True", dict(blast_class="high"), True),
        ("medium blast + eligible → False", dict(blast_class="medium"), False),
        ("low blast + eligible → False", dict(blast_class="low"), False),
        # an ineligible result never needs the flag, whatever the blast class
        ("high blast + ineligible → False", dict(blast_class="high", artifact=None), False),
        ("high blast + rate fail → False", dict(blast_class="high", false_action=10, obs=100), False),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_requires_human_ratification(label, kwargs, expected_flag):
    result = _eval(**kwargs)
    assert result.requires_human_ratification == expected_flag, (
        f"case '{label}': got {result}"
    )


def test_high_blast_eligible_reason_names_the_requirement():
    result = _eval(blast_class="high")
    assert result.eligible
    assert result.requires_human_ratification
    assert "human ratification" in result.reason


# ---------------------------------------------------------------------------
# Reason string content
# ---------------------------------------------------------------------------


def test_reason_mentions_insufficient_when_too_few_observations():
    result = _eval(obs=5)
    assert "insufficient" in result.reason.lower()
    assert "5" in result.reason
    assert "10" in result.reason


def test_reason_mentions_error_rate_when_above_threshold():
    result = _eval(false_action=10, obs=100)
    assert "0.1000" in result.reason
    assert not result.eligible


def test_reason_mentions_observation_count_on_success():
    result = _eval(false_action=1, human_override=1, obs=100)
    assert result.eligible
    assert "100" in result.reason


def test_provenance_reason_names_the_ceiling():
    result = _eval(provenance_maturity="lineage", target_level=OUT)
    assert "signed-lineage" in result.reason
    assert "out-of-loop" in result.reason


def test_budget_reason_carries_both_numbers():
    result = _eval(error_budget=ErrorBudget(tolerance=0.5, spent=0.75))
    assert "0.7500" in result.reason
    assert "0.5000" in result.reason


# ---------------------------------------------------------------------------
# Invalid argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"window_n": 0}, "window_n"),
        ({"window_n": -1}, "window_n"),
        ({"min_observations": 0}, "min_observations"),
        ({"min_observations": -1}, "min_observations"),
        ({"threshold": 0.0}, "threshold"),
        ({"threshold": -0.01}, "threshold"),
        ({"threshold": 1.01}, "threshold"),
        # unknown maturity is a caller logic error, not a failing gate
        ({"provenance_maturity": "vibes"}, "provenance_maturity"),
        # unknown blast class must fail loudly — silently treating it as
        # not-high would drop the human-ratification requirement
        ({"blast_class": "hgih"}, "blast_class"),
    ],
)
def test_invalid_config_raises_value_error(kwargs, match):
    """Caller config errors raise ValueError with a descriptive message."""
    with pytest.raises(ValueError, match=match):
        _eval(**kwargs)


def test_in_loop_target_has_no_provenance_ceiling():
    """The Recommend-origin grant-creating first promotion targets in-loop:
    no provenance ceiling is declared for the approval-gated floor, so even a
    bare taint bit passes gate 1 (an unset ceiling is no gate)."""
    result = _eval(target_level=AutonomyLevel.in_loop, provenance_maturity="taint-bit")
    assert result.eligible is True


def test_in_loop_target_still_runs_the_evidence_gates():
    """No ceiling does not mean no gates: a Recommend-origin promotion without
    an evidence artifact is still ineligible."""
    result = _eval(target_level=AutonomyLevel.in_loop, artifact=None)
    assert result.eligible is False
    assert "evidence artifact missing" in result.reason


def test_observation_count_exceeds_window_n_raises():
    with pytest.raises(ValueError, match="window_n"):
        _eval(obs=101, window_n=100)


def test_negative_counter_raises():
    with pytest.raises(ValueError, match="non-negative"):
        _eval(false_action=-1)


def test_error_count_exceeds_observation_count_raises():
    with pytest.raises(ValueError, match="cannot exceed observation_count"):
        _eval(false_action=60, human_override=60, obs=100, window_n=100)


# ---------------------------------------------------------------------------
# Pure / no side effects — repeated calls with same args produce same result
# ---------------------------------------------------------------------------


def test_predicate_is_pure_same_result_on_repeated_calls():
    kwargs = dict(false_action=2, human_override=1, obs=100, blast_class="high")
    r1 = _eval(**kwargs)
    r2 = _eval(**kwargs)
    assert r1 == r2


# ---------------------------------------------------------------------------
# principal and action_class are threaded through (don't affect computation)
# ---------------------------------------------------------------------------


def test_different_principals_same_metrics_same_outcome():
    p1 = Principal(agentId="agent-a", skill="email", user="alice", tier="A")
    p2 = Principal(agentId="agent-b", skill="files", user="bob", tier="C")
    r1 = _eval(false_action=1, principal=p1)
    r2 = _eval(false_action=1, principal=p2)
    assert r1.eligible == r2.eligible


# ---------------------------------------------------------------------------
# The ceiling mapping itself — both acting rungs pinned at signed-lineage
# ---------------------------------------------------------------------------


def test_required_maturity_covers_exactly_the_acting_rungs():
    assert set(REQUIRED_PROVENANCE_MATURITY) == {ON, OUT}
    assert all(v == "signed-lineage" for v in REQUIRED_PROVENANCE_MATURITY.values())
