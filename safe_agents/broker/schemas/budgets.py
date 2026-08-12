"""Budgets schema — per-period typed budgets, decremented atomically.

Two are foundational and non-fungible: error and attention. The binding one switches
by action class, so "decisions per period" is a vector per class, never a scalar.
See SCHEMAS.md §6.
"""

from pydantic import BaseModel, ConfigDict


class ErrorBudget(BaseModel):
    """Bounded cumulative tolerable error per period.

    Drawn down by each decision as error_prob × blast_radius. Decision volume inflates
    aggregate error, so scaling volume forces higher per-decision confidence to hold
    the bound fixed (alpha-spending / SRE error budget).
    """

    model_config = ConfigDict(extra="forbid")

    tolerance: float
    spent: float


class CapacityBudget(BaseModel):
    """A capacity + spent counter for attention, escalation, or fallback budgets."""

    model_config = ConfigDict(extra="forbid")

    capacity: float
    spent: float


class Budgets(BaseModel):
    """Per-period typed budgets.

    All four are non-fungible; an adversary can drain escalation with decoys.
    Autonomy level is the exchange rate between error and attention: graduating a class
    to out-of-loop spends machine error-budget to save human attention; keeping it
    in-loop spends attention to conserve error-budget.
    """

    model_config = ConfigDict(extra="forbid")

    # Σ error_prob × blast_radius — bounded cumulative tolerable error
    error: ErrorBudget
    # Σ cognitive_cost — the human's finite quality-decisions per period
    attention: CapacityBudget
    # asks are rationed (adversary DoSes this channel)
    escalation: CapacityBudget
    # the safe action is NOT free — abstaining to a safe action is itself capped
    fallback: CapacityBudget
