"""Deterministic promotion predicate (sa#57).

Answers a single boolean question: does the accumulated track record for a
(principal, action_class) warrant moving up to the next autonomy rung?

Design constraints:
- PURE: no I/O, no LLM call, no side effects. All inputs are pre-fetched and
  injected by the caller (who owns the DynamoDB read and the HMAC verification).
- DETERMINISTIC: same inputs → same output, every time.
- CONFIG-DRIVEN: threshold, window_n, and min_observations are caller-supplied
  per-class config, never hardcoded here. The safe-default polarity (abstain-is-safe
  vs positive-safe-action) is NOT baked in — that's per-agent config.
- FAIL-SAFE: ambiguity (insufficient data, no observations, missing or stale
  evidence artifact, unasserted coverage) always resolves to False. A predicate
  cannot pass on the absence of disconfirming evidence.

The rate formula:
    error_rate = (false_action_count + human_override_count) / observation_count

Eligibility requires, in gate order:
    provenance maturity meets the target rung's ceiling (docs/PTC.md §9)
    AND a fresh (non-stale) ConfidenceArtifact is present (#184)
    AND covered-distribution soundness is asserted by the proposer
    AND the error budget (if configured) is not in breach
    AND observation_count >= min_observations
    AND error_rate < threshold

A True result at high blast class carries requires_human_ratification=True:
predicate-true is necessary but never sufficient there — a per-instance human
ratification is always required (the ceremony enforces the ratifier identity;
this predicate only surfaces the flag).

See broker/grant-lifecycle.md for the promotion protocol that calls this predicate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.evidence import BlastClass, ConfidenceArtifact


# ---------------------------------------------------------------------------
# Provenance maturity — the PTC rung ceiling (docs/PTC.md §9)
# ---------------------------------------------------------------------------

# How far the deployment's provenance machinery has matured: a bare taint bit,
# an asserted (unsigned) lineage chain, or a receiver-verifiable signed chain.
ProvenanceMaturity = Literal["taint-bit", "lineage", "signed-lineage"]

# Ordering for ceiling comparison — later entries strictly dominate earlier ones.
_MATURITY_RANK: dict[ProvenanceMaturity, int] = {
    "taint-bit": 0,
    "lineage": 1,
    "signed-lineage": 2,
}

# The minimum maturity each acting rung requires. BOTH acting rungs require
# signed lineage (locked 2026-07-12): the strict reading of docs/PTC.md §9 —
# unsigned lineage ⇒ approval-gated, so no acting-autonomy rung is reachable
# without receiver-verifiable signed provenance.
REQUIRED_PROVENANCE_MATURITY: dict[AutonomyLevel, ProvenanceMaturity] = {
    AutonomyLevel.on_loop: "signed-lineage",
    AutonomyLevel.out_of_loop: "signed-lineage",
}


# ---------------------------------------------------------------------------
# Input type — pre-fetched counter snapshot for one (principal, action_class)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionClassMetrics:
    """Counter snapshot for a (principal, action_class) over a window of runs.

    Callers are responsible for reading from the counters table, verifying
    tamper-evidence, and supplying a fresh snapshot. This predicate never reads.

    Attributes:
        false_action_count: number of actions in the window flagged as false
            positives by a human reviewer (the agent acted; it shouldn't have).
        human_override_count: number of actions in the window where a human
            intervened to reverse or block the action after the fact.
        observation_count: total run records within the window (denominator).
            Must be <= window_n. On the counter seam this cannot be capped to
            the last window_n records (a counter sums, it cannot return the last
            N rows); window_n is an upper bound the caller reconciles by widening
            window_n or narrowing the evidence window, not a query LIMIT.
    """

    false_action_count: int
    human_override_count: int
    observation_count: int


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PredicateResult:
    """Return value of evaluate_promotion_predicate.

    Attributes:
        eligible: True iff the track record warrants promotion. The ceremony
            (#58) gates the actual grant write on this value; a True here is
            necessary but not sufficient — maker-checker and blast-radius
            ceremony still apply.
        reason: human-readable explanation, suitable for a PromotionRecord's
            'predicate' field or an audit log entry.
        requires_human_ratification: True only on an eligible=True result for a
            high blast class — predicate-true is never sufficient at high blast;
            a per-instance human ratification is always required. Below high
            blast a pre-authored signed predicate may stand in as ratifier —
            not this function's concern. An ineligible result never sets it.
    """

    eligible: bool
    reason: str
    requires_human_ratification: bool = False


# ---------------------------------------------------------------------------
# The predicate
# ---------------------------------------------------------------------------


def evaluate_promotion_predicate(
    principal: Principal,
    action_class: str,
    *,
    metrics: ActionClassMetrics,
    window_n: int,
    min_observations: int,
    threshold: float,
    target_level: AutonomyLevel,
    artifact: ConfidenceArtifact | None,
    covered: bool,
    provenance_maturity: ProvenanceMaturity,
    blast_class: BlastClass,
    error_budget: ErrorBudget | None,
) -> PredicateResult:
    """Decide whether (principal, action_class) is eligible for promotion.

    Args:
        principal: the (agentId, skill, user, tier) tuple being evaluated.
        action_class: the action class name, e.g. "read.files".
        metrics: pre-fetched counter snapshot — see ActionClassMetrics.
        window_n: the operator-declared maximum sample the evidence may
            represent. On the counter seam this is NOT a query LIMIT — a counter
            sums and cannot return the last N records — but an upper bound used
            here for validation: a windowed observation_count exceeding it means
            the declared max sample is smaller than the evidence summed over the
            window, and the predicate refuses (widen --window-n or narrow
            --window-days). observation_count must be <= window_n.
        min_observations: minimum number of observations required before the
            predicate can return True. Fewer than this → False regardless of
            the error rate. Guards against promoting on a thin sample.
        threshold: the error rate upper bound (exclusive). The predicate returns
            True only when error_rate < threshold. Must be in (0.0, 1.0].
        target_level: the rung being promoted TO. The acting rungs (on-loop,
            out-of-loop) carry a provenance ceiling; in-loop is valid only as
            the Recommend-origin grant-creating first promotion — it declares
            no ceiling, but every evidence gate still applies.
        artifact: the #184 constructed-confidence artifact backing the proposal.
            None → ineligible (no evidence, no promotion); stale → ineligible
            (label-free drift voids the certification).
        covered: proposer-asserted covered-distribution soundness — an explicit
            assertion recorded on the ceremony record, not derived from the
            method. False → ineligible.
        provenance_maturity: the deployment's provenance maturity, compared
            against REQUIRED_PROVENANCE_MATURITY for target_level
            (docs/PTC.md §9's rung ceiling).
        blast_class: the decision's blast class, derived by the CALLER via
            effective_blast_class from ToolOp fields — never derived here.
            "high" never blocks eligibility by itself, but the result carries
            requires_human_ratification=True.
        error_budget: the configured error budget, or None when the knob is not
            configured — an unset knob is no gate (docs/friction-doctrine.md).
            If present and spent >= tolerance (the same polarity as
            runner.derive_budget_breach) → ineligible.

    Returns:
        PredicateResult; eligible=True only when every gate above passes.

    All ambiguous cases — zero observations, sample too small, rate at or above
    threshold, missing/stale artifact, unasserted coverage — resolve to
    eligible=False. This is a fail-safe, not a judgment call; callers should
    not override it.
    """
    # --- argument sanity (logic errors in the caller, not data errors) ---
    if window_n < 1:
        raise ValueError(f"window_n must be >= 1, got {window_n}")
    if min_observations < 1:
        raise ValueError(f"min_observations must be >= 1, got {min_observations}")
    if not (0.0 < threshold <= 1.0):
        raise ValueError(f"threshold must be in (0.0, 1.0], got {threshold}")
    if metrics.observation_count > window_n:
        raise ValueError(
            f"windowed observation_count ({metrics.observation_count}) exceeds "
            f"window_n ({window_n}): the declared max sample (--window-n) is smaller "
            "than the evidence summed over the window. A counter cannot be capped to "
            "the last N records — declare a larger --window-n or narrow --window-days"
        )
    if metrics.false_action_count < 0 or metrics.human_override_count < 0 or metrics.observation_count < 0:
        raise ValueError("counter values must be non-negative")
    if (metrics.false_action_count + metrics.human_override_count) > metrics.observation_count:
        raise ValueError(
            "sum of false_action_count and human_override_count cannot exceed observation_count"
        )
    if provenance_maturity not in _MATURITY_RANK:
        raise ValueError(
            f"unknown provenance_maturity {provenance_maturity!r}; "
            f"must be one of {sorted(_MATURITY_RANK)}"
        )
    if blast_class not in ("low", "medium", "high"):
        # Fail loudly: an unknown blast class must never be silently treated as
        # not-high — that would drop the human-ratification requirement.
        raise ValueError(
            f"unknown blast_class {blast_class!r}; must be one of ['low', 'medium', 'high']"
        )

    # --- gate 1: provenance maturity ceiling (docs/PTC.md §9) ---
    # in-loop declares no ceiling: it is only reachable as the Recommend-origin
    # grant-creating first promotion (broker/grant-lifecycle.md — "the same
    # recorded maker-checker path as every later climb"), and the approval-gated
    # floor needs no provenance to act. An unset ceiling is no gate; every
    # evidence gate below still applies.
    required_maturity = REQUIRED_PROVENANCE_MATURITY.get(target_level)
    if (
        required_maturity is not None
        and _MATURITY_RANK[provenance_maturity] < _MATURITY_RANK[required_maturity]
    ):
        return PredicateResult(
            eligible=False,
            reason=(
                f"provenance maturity {provenance_maturity!r} is below the "
                f"{required_maturity!r} ceiling for target level "
                f"{AutonomyLevel(target_level).value!r}: no acting rung is reachable "
                "without receiver-verifiable signed provenance (docs/PTC.md §9)"
            ),
        )

    # --- gate 2: evidence artifact present ---
    if artifact is None:
        return PredicateResult(
            eligible=False,
            reason=(
                "evidence artifact missing: promotion requires a constructed "
                "ConfidenceArtifact; absence of evidence is not evidence"
            ),
        )

    # --- gate 3: evidence artifact fresh ---
    if artifact.stale:
        return PredicateResult(
            eligible=False,
            reason=(
                "evidence artifact is stale: label-free drift voids the "
                "certification; re-construct the artifact before proposing"
            ),
        )

    # --- gate 4: covered-distribution soundness asserted ---
    if not covered:
        return PredicateResult(
            eligible=False,
            reason=(
                "covered-distribution soundness not asserted (covered=False): "
                "the proposer must explicitly assert the evidence window covers "
                "the distribution the promoted class will act on"
            ),
        )

    # --- gate 5: error budget (unset knob is no gate) ---
    if error_budget is not None and error_budget.spent >= error_budget.tolerance:
        return PredicateResult(
            eligible=False,
            reason=(
                f"error budget in breach: spent {error_budget.spent:.4f} >= "
                f"tolerance {error_budget.tolerance:.4f}"
            ),
        )

    # --- gate 6: insufficient sample size ---
    if metrics.observation_count < min_observations:
        return PredicateResult(
            eligible=False,
            reason=(
                f"insufficient observations: {metrics.observation_count} < "
                f"min_observations={min_observations}; cannot promote without evidence"
            ),
        )

    # --- gate 7: error rate ---
    error_count = metrics.false_action_count + metrics.human_override_count
    # observation_count >= 1 is guaranteed by the min_observations gate above
    error_rate = error_count / metrics.observation_count

    if error_rate >= threshold:
        return PredicateResult(
            eligible=False,
            reason=(
                f"error_rate={error_rate:.4f} >= threshold={threshold:.4f} "
                f"(false_actions={metrics.false_action_count}, "
                f"human_overrides={metrics.human_override_count}, "
                f"observations={metrics.observation_count})"
            ),
        )

    # --- eligible; high blast always needs a per-instance human ratifier ---
    needs_human = blast_class == "high"
    reason = (
        f"error_rate={error_rate:.4f} < threshold={threshold:.4f} "
        f"over {metrics.observation_count} observations in window_n={window_n} "
        f"(false_actions={metrics.false_action_count}, "
        f"human_overrides={metrics.human_override_count})"
    )
    if needs_human:
        reason += (
            "; blast class is high — predicate-true is necessary but not "
            "sufficient: per-instance human ratification required"
        )
    return PredicateResult(
        eligible=True,
        reason=reason,
        requires_human_ratification=needs_human,
    )
