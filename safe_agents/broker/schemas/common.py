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


# The order of the rungs: a higher rank is more autonomy and less supervision.
# The one definition every comparison of two levels reads.
AUTONOMY_RANK: dict[AutonomyLevel, int] = {
    AutonomyLevel.in_loop: 0,
    AutonomyLevel.on_loop: 1,
    AutonomyLevel.out_of_loop: 2,
}


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


# The closed catalog of budget/evidence counter periods. A Literal,
# deliberately — the period is authority-shaping (it scopes every cap and every
# evidence window), so it is manifest-named and image-baked, never store-mutable
# (docs/config-provenance.md). "utc-day" is the default and is byte-for-byte the
# pre-counter-period key format; "utc-hour" exists so an example agent can run the full
# lifecycle at development speed with genuinely elapsed periods. Real time always
# elapses; only the bucket size is configurable — there is deliberately NO
# clock-injection seam (the 2026-07-15 triggers-vs-effects doctrine).
CounterPeriod = Literal["utc-day", "utc-hour"]

# The closed catalog of fetched inputs a broker decision can depend on (PTC §6.13,
# GAL §6.15, #176). Each is fetched from a source, so each has an as-of instant on
# the audit record of a decision that used it, and the deployment may declare a
# maximum age for it (AgentManifest.input_max_age_seconds). Closed, so a typo in a
# manifest refuses at load instead of declaring an age for nothing.
#
#   manifest  - the AgentManifest file, read once at launch.
#   envelope  - the risk envelope in force: from the manifest (manifest mode, same
#               fetch) or the envelope store (store mode, read once at startup).
#   hmac_key  - the key the broker verifies grant and intent rows with, read once
#               at startup.
#   grant     - the grant row, read per call.
#   counters  - the budget and evidence counters the PIP reads, per call.
#   sub_grants - the delegation store, read per call where delegation is on.
#   intent    - the frozen call a release runs, read at release.
#   mcp_admission - an MCP server's two-key admission snapshot (the registry rows
#               and the advertised tool definitions), read when the session is
#               spawned and again when it passes its declared age; recorded by
#               the MCP host on the decision of each call that reaches it.
#   issuer_standing - the issuer's signed standing document (GAL §6.10, GAL-41,
#               #179): which issuer keys are active, retired or withdrawn. Its
#               maximum age is bound at deploy (ISSUER_STANDING_MAX_AGE_SECONDS,
#               no default); a value here may only shorten it, and a longer one
#               is refused at startup (grants/standing_keys.py). Its as-of is
#               the earlier of the fetch and the document's issuedAt.
InputName = Literal[
    "manifest",
    "envelope",
    "hmac_key",
    "grant",
    "counters",
    "sub_grants",
    "intent",
    "mcp_admission",
    "issuer_standing",
]

# The longest maximum age a deployment may declare for an input: one hundred
# years. Larger is no bound anyone means, and large enough would put an input's
# end past the last instant a datetime holds (#176).
MAX_DECLARABLE_AGE_SECONDS = 100 * 366 * 24 * 3600


class Principal(BaseModel):
    """The (agentId, skill, user, tier) tuple that a grant is issued to."""

    model_config = ConfigDict(extra="forbid")

    agentId: str
    skill: str
    user: str
    # coarse trust tier (A–D) used by capability-scoping and policy
    tier: Literal["A", "B", "C", "D"]
