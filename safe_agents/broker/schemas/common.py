"""Shared types used across multiple schemas."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict


class AutonomyLevel(str, Enum):
    """The three human-oversight rungs (Grant.level, PromotionRecord.fromLevel/toLevel).

    Orthogonal to the Decision verb (allow/deny/transform/require_approval/abstain);
    level is state on the grant, the verb is per-call. See ARCHITECTURE.md §"The seven base schemas".
    """

    in_loop = "in-loop"       # human approves each action of the class
    on_loop = "on-loop"       # agent acts but human monitors and can veto
    out_of_loop = "out-of-loop"  # fully autonomous within the envelope


class DemotionTrigger(str, Enum):
    """Deterministic conditions that trip automatic demotion. See SCHEMAS.md §1."""

    stale_confidence = "stale_confidence"
    corroboration_failure = "corroboration_failure"
    budget_breach = "budget_breach"
    # a single authenticated owner flag (false_action) is a sufficient demotion
    # trigger — but only when a consumer LISTS it on the grant's demotionTriggers
    # (ships OFF: no manifest lists it). No accumulation of flags can promote
    # anything; the runner re-derives it from the durable counter, never a message.
    false_action = "false_action"


# The closed catalog of budget/evidence counter periods (#212). A Literal,
# deliberately — the period is authority-shaping (it scopes every cap and every
# evidence window), so it is manifest-named and image-baked, never store-mutable
# (docs/config-provenance.md). "utc-day" is the default and is byte-for-byte the
# pre-#212 key format; "utc-hour" exists so an example agent can run the full
# lifecycle at development speed with genuinely elapsed periods. Real time always
# elapses; only the bucket size is configurable — there is deliberately NO
# clock-injection seam (the 2026-07-15 triggers-vs-effects doctrine).
CounterPeriod = Literal["utc-day", "utc-hour"]


class Principal(BaseModel):
    """The (agentId, skill, user, tier) tuple that a grant is issued to."""

    model_config = ConfigDict(extra="forbid")

    agentId: str
    skill: str
    user: str
    # coarse trust tier (A–D) used by capability-scoping and policy
    tier: Literal["A", "B", "C", "D"]
