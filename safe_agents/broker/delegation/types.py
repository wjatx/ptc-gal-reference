"""broker.delegation.types — schema and supporting types for sub-grant delegation.

Sub-grants are always computed by the broker from a parent grant and a requested
DelegationScope. An agent cannot author a sub-grant directly; it can only request
one and the broker enforces strict attenuation on every dimension.

See broker/sub-grants.md for the authoritative design narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from safe_agents.broker.schemas import AuditRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal

# ---------------------------------------------------------------------------
# Oversight-rung ordering: lower index = more supervised
# ---------------------------------------------------------------------------

LEVEL_ORDER: dict[AutonomyLevel, int] = {
    AutonomyLevel.in_loop: 0,
    AutonomyLevel.on_loop: 1,
    AutonomyLevel.out_of_loop: 2,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AttenuationError(ValueError):
    """Raised when a requested sub-grant would widen any dimension of the parent.

    Widening is always rejected, never silently clamped. The rejection is logged
    by the broker as an AuditRecord with outcome="denied" and
    reason="sub-grant-would-widen".
    """


class ExpiredSubGrantError(ValueError):
    """Raised when a sub-grant's absolute expiry has passed.

    Sub-grant TTL cannot be extended by the agent or sub-agent; the broker
    rejects all calls from an expired sub-grant without exception.
    """


class FurtherDelegationForbiddenError(ValueError):
    """Raised when a sub-agent attempts to delegate but allowFurtherDelegation=False."""


# ---------------------------------------------------------------------------
# DelegationScope — what the parent agent requests
# ---------------------------------------------------------------------------


class DelegationScope(BaseModel):
    """The delegation request sent by a parent agent to the broker.

    The broker validates and enforces the attenuation invariant before issuing
    the SubGrant. Any dimension that would widen the parent's authority is rejected
    with an AttenuationError; the broker never silently clamps.
    """

    model_config = ConfigDict(extra="forbid")

    # The identity the sub-grant will be issued to
    subAgentPrincipal: Principal
    # Action classes the sub-agent should be granted (must be a subset of parent's)
    actionClasses: list[str]
    # Requested autonomy level; must be ≤ parent's on the oversight rung
    requestedLevel: AutonomyLevel
    # Requested spend cap; must be ≤ parent's remaining cap at delegation time
    requestedSpendCap: float
    # Requested TTL in seconds from the delegation timestamp
    ttlSeconds: float
    # Whether the sub-agent may further delegate; can only be True if the parent also permits it
    allowFurtherDelegation: bool = False


# ---------------------------------------------------------------------------
# SubGrant — the broker-issued, strictly-attenuating delegation record
# ---------------------------------------------------------------------------


class SubGrant(BaseModel):
    """A computed, strictly-attenuating sub-grant issued by the broker.

    Every dimension of this record is ≤ the parent's authority at issuance time.
    The agent holds no credentials; it presents its sub-grant ID to the broker,
    which looks up this record from its own store (not the agent's working memory).

    The hash field covers all other fields and detects any post-issuance tampering.
    """

    model_config = ConfigDict(extra="forbid")

    # Unique identifier for this sub-grant
    id: str
    # The parent grant (or sub-grant) this was derived from
    parentGrantId: str
    # Delegation chain, ordered from the root human-owned grant ID outward to
    # the parent. Does not include this sub-grant's own ID (use id for that).
    # Full lineage = delegationChain + [id].
    delegationChain: list[str]

    # Sub-agent identity
    principal: Principal
    # Action classes authorized (⊆ parent's action classes)
    actionClasses: list[str]
    # Autonomy level (≤ parent's on the oversight rung)
    level: AutonomyLevel
    # Spend cap (≤ parent's remaining cap at issuance time)
    spendCap: float
    # Absolute expiry (ISO-8601 UTC) — cannot be extended by agent or sub-agent
    expiry: str
    # Whether this sub-agent may further delegate; False unless parent also permits it
    allowFurtherDelegation: bool

    # Broker bookkeeping
    issuedAt: str
    issuedBy: str
    # SHA-256 over the core fields — post-issuance tampering is detectable
    hash: str


# ---------------------------------------------------------------------------
# ParentAuthority — abstraction over a root Grant or a SubGrant acting as parent
# ---------------------------------------------------------------------------


@dataclass
class ParentAuthority:
    """Normalized view of whatever is acting as the parent in a delegation.

    Callers (the broker) produce this from either a root Grant (via
    parent_from_grant()) or an existing SubGrant (via parent_from_sub_grant()).
    The pure computation functions depend only on this type, not on Grant or SubGrant
    directly, which keeps them AWS-free and schema-version–agnostic.
    """

    id: str
    action_classes: list[str]
    level: AutonomyLevel
    # Parent's remaining spend cap (cap - already_spent), at delegation time
    remaining_spend: float
    # Parent's absolute expiry; datetime in UTC
    expiry: datetime
    # Whether this parent permits the sub-agent to further delegate
    allow_further_delegation: bool
    # Chain of grant IDs from root to this parent (empty for a root Grant)
    delegation_chain: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AttributedAuditRecord — AuditRecord bundled with delegation lineage
# ---------------------------------------------------------------------------


@dataclass
class AttributedAuditRecord:
    """An AuditRecord paired with the delegation chain that authorized the action.

    The base AuditRecord schema uses extra="forbid" (it cannot be modified without
    breaking the broker/schemas/ contract). The delegation layer wraps it here so
    the attribution chain is always derivable without touching the schema.

    delegation_chain is the FULL lineage, ordered from the root human-owned grant ID
    outward through each delegation to the sub-grant that directly authorized the call:
      [root_grant_id, ..., parent_grant_id, sub_grant_id]

    "Why did this happen?" unwinds the chain to the accountable human.
    """

    audit_record: AuditRecord
    # Full lineage: [root_grant_id, ..., parent_grant_id, sub_grant_id]
    delegation_chain: list[str]
    # The immediate sub-grant that authorized the call (== delegation_chain[-1])
    sub_grant_id: str
