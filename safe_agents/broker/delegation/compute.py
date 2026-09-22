"""broker.delegation.compute — pure sub-grant computation.

All functions here are deterministic and AWS-free. They depend only on the types
defined in broker.delegation.types and broker.schemas.common. Tests can call them
directly with no store, no credentials, no mocking of external services.

The canonical entry point is compute_sub_grant(). assert_attenuates() is the
complementary check you can call to validate an existing (parent, child) pair.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from safe_agents.broker.schemas import AuditRecord
from safe_agents.broker.schemas.common import AutonomyLevel

from .types import (
    AttenuationError,
    AttributedAuditRecord,
    DelegationScope,
    ExpiredSubGrantError,
    FurtherDelegationForbiddenError,
    LEVEL_ORDER,
    ParentAuthority,
    SubGrant,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_sub_grant(
    parent: ParentAuthority,
    scope: DelegationScope,
    *,
    now: datetime | None = None,
    issued_by: str = "broker",
) -> SubGrant:
    """Compute a strictly-attenuating sub-grant from a parent authority and a scope.

    This is the broker's entry point for creating sub-grants. The delegating agent
    does NOT call this; it submits a DelegationScope, and the broker calls this.

    Attenuation invariants — all enforced before returning:
      - level ≤ parent's level (on the oversight rung)
      - actionClasses ⊆ parent's action_classes
      - spendCap ≤ parent's remaining_spend at delegation time
      - expiry ≤ parent's expiry
      - allowFurtherDelegation may only be True if parent also permits it

    Any violation raises AttenuationError. The broker never silently clamps.

    Parameters
    ----------
    parent:
        The authority the sub-grant is derived from. Produced by parent_from_grant()
        or parent_from_sub_grant() in the calling broker code.
    scope:
        The delegation request from the parent agent.
    now:
        The current time, for TTL computation. Defaults to datetime.now(UTC).
        Inject a fixed value in tests for determinism.
    issued_by:
        The broker identity that issues the sub-grant. Recorded for auditability.

    Raises
    ------
    AttenuationError
        If any requested dimension would widen the parent's authority.
    FurtherDelegationForbiddenError
        If allowFurtherDelegation=True is requested but the parent forbids it.
    """
    now_dt = now if now is not None else datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # 1. Validate action classes: requested set must be ⊆ parent's
    # ------------------------------------------------------------------
    requested_classes = set(scope.actionClasses)
    parent_classes = set(parent.action_classes)
    if not requested_classes:
        raise AttenuationError("DelegationScope.actionClasses must not be empty")
    extra = requested_classes - parent_classes
    if extra:
        raise AttenuationError(
            f"Sub-grant actionClasses {sorted(extra)!r} are not in the parent's "
            f"authorized action classes {sorted(parent_classes)!r}. "
            "A sub-grant may only narrow, never widen, the parent's scope."
        )

    # ------------------------------------------------------------------
    # 2. Validate level: must not be more autonomous than parent's
    # ------------------------------------------------------------------
    if LEVEL_ORDER[scope.requestedLevel] > LEVEL_ORDER[parent.level]:
        raise AttenuationError(
            f"Requested level '{scope.requestedLevel.value}' is more autonomous "
            f"than the parent's level '{parent.level.value}'. "
            "A sub-grant level can only be equal to or more supervised than the parent's."
        )

    # ------------------------------------------------------------------
    # 3. Validate spend cap: must be ≤ parent's remaining cap
    # ------------------------------------------------------------------
    if scope.requestedSpendCap > parent.remaining_spend:
        raise AttenuationError(
            f"Requested spendCap {scope.requestedSpendCap} exceeds the parent's "
            f"remaining spend cap {parent.remaining_spend}. "
            "A sub-grant cap can only be ≤ the parent's remaining cap at issuance."
        )

    # ------------------------------------------------------------------
    # 4. Compute and validate expiry: ttlSeconds from now, capped at parent's expiry
    # ------------------------------------------------------------------
    requested_expiry = now_dt.timestamp() + scope.ttlSeconds
    parent_expiry_ts = parent.expiry.timestamp()
    if requested_expiry > parent_expiry_ts:
        raise AttenuationError(
            f"Requested TTL of {scope.ttlSeconds}s would set expiry past the parent's "
            f"expiry ({parent.expiry.isoformat()}). "
            "A sub-grant expiry must not exceed the parent's remaining TTL."
        )
    expiry_dt = datetime.fromtimestamp(requested_expiry, tz=timezone.utc)
    expiry_str = expiry_dt.isoformat()

    # ------------------------------------------------------------------
    # 5. Validate further-delegation permission
    # ------------------------------------------------------------------
    if scope.allowFurtherDelegation and not parent.allow_further_delegation:
        raise FurtherDelegationForbiddenError(
            "allowFurtherDelegation=True requested, but the parent does not permit "
            "the sub-agent to further delegate."
        )

    # ------------------------------------------------------------------
    # 6. Build the SubGrant
    # ------------------------------------------------------------------
    sub_grant_id = str(uuid.uuid4())
    issued_at_str = now_dt.isoformat()
    # Full delegation chain = parent's chain + parent's own ID
    delegation_chain = parent.delegation_chain + [parent.id]

    core_fields = {
        "id": sub_grant_id,
        "parentGrantId": parent.id,
        "delegationChain": delegation_chain,
        "principal": scope.subAgentPrincipal.model_dump(),
        "actionClasses": sorted(scope.actionClasses),
        "level": scope.requestedLevel.value,
        "spendCap": scope.requestedSpendCap,
        "expiry": expiry_str,
        "allowFurtherDelegation": scope.allowFurtherDelegation,
        # Inherited, never requested -- see ParentAuthority.tree_pool_cap.
        "treePoolCap": parent.tree_pool_cap,
        "issuedAt": issued_at_str,
        "issuedBy": issued_by,
    }
    record_hash = _hash_fields(core_fields)

    return SubGrant(
        id=sub_grant_id,
        parentGrantId=parent.id,
        delegationChain=delegation_chain,
        principal=scope.subAgentPrincipal,
        actionClasses=sorted(scope.actionClasses),
        level=scope.requestedLevel,
        spendCap=scope.requestedSpendCap,
        expiry=expiry_str,
        allowFurtherDelegation=scope.allowFurtherDelegation,
        treePoolCap=parent.tree_pool_cap,
        issuedAt=issued_at_str,
        issuedBy=issued_by,
        hash=record_hash,
    )


def assert_attenuates(parent: ParentAuthority, child: SubGrant) -> None:
    """Assert that a SubGrant strictly attenuates its parent's authority.

    Raises AttenuationError with a descriptive message if any dimension of the
    child is wider than the parent's authority at issuance. This function is the
    complement to compute_sub_grant(): compute_sub_grant() enforces attenuation
    at creation time; assert_attenuates() re-checks an existing (parent, child) pair
    and is useful in tests and in broker pre-flight validation.

    Parameters
    ----------
    parent:
        The authority the child was derived from.
    child:
        The sub-grant to validate.

    Raises
    ------
    AttenuationError
        If any dimension of child is wider than parent's authority.
    """
    # Level check
    if LEVEL_ORDER[child.level] > LEVEL_ORDER[parent.level]:
        raise AttenuationError(
            f"Child level '{child.level.value}' is more autonomous than parent level "
            f"'{parent.level.value}'."
        )

    # Action class check
    child_classes = set(child.actionClasses)
    parent_classes = set(parent.action_classes)
    extra = child_classes - parent_classes
    if extra:
        raise AttenuationError(
            f"Child actionClasses {sorted(extra)!r} are not in parent's "
            f"authorized action classes {sorted(parent_classes)!r}."
        )

    # Spend cap check: child.spendCap ≤ parent.remaining_spend
    if child.spendCap > parent.remaining_spend:
        raise AttenuationError(
            f"Child spendCap {child.spendCap} exceeds parent's remaining spend "
            f"{parent.remaining_spend}."
        )

    # Expiry check: child expiry ≤ parent expiry
    child_expiry_dt = _parse_iso(child.expiry)
    if child_expiry_dt > parent.expiry:
        raise AttenuationError(
            f"Child expiry {child.expiry} is after parent's expiry "
            f"{parent.expiry.isoformat()}."
        )

    # Further-delegation check: child cannot grant what parent did not grant
    if child.allowFurtherDelegation and not parent.allow_further_delegation:
        raise AttenuationError(
            "Child has allowFurtherDelegation=True but parent does not permit it."
        )


def check_action_authorized(sub_grant: SubGrant, action_class: str) -> bool:
    """Return True if action_class is within the sub-grant's authorized scope.

    The broker calls this before dispatching any BrokeredCall emitted by a sub-agent.
    An action class not in the sub-grant's actionClasses is denied regardless of
    what the parent grant authorizes; the sub-grant is the binding authority.
    """
    return action_class in sub_grant.actionClasses


def verify_not_expired(
    sub_grant: SubGrant,
    *,
    now: datetime | None = None,
) -> None:
    """Raise ExpiredSubGrantError if the sub-grant's absolute expiry has passed.

    The broker calls this on every BrokeredCall from a sub-agent. If the sub-grant
    has expired the call is rejected; the TTL cannot be extended.

    Parameters
    ----------
    sub_grant:
        The sub-grant to check.
    now:
        Current time (UTC). Defaults to datetime.now(UTC). Inject a fixed value
        in tests for determinism.

    Raises
    ------
    ExpiredSubGrantError
        If the sub-grant's expiry is at or before now.
    """
    now_dt = now if now is not None else datetime.now(timezone.utc)
    expiry_dt = _parse_iso(sub_grant.expiry)
    if now_dt >= expiry_dt:
        raise ExpiredSubGrantError(
            f"Sub-grant {sub_grant.id!r} expired at {sub_grant.expiry}; "
            f"current time is {now_dt.isoformat()}. "
            "Sub-grant TTL cannot be extended."
        )


def build_attributed_record(
    sub_grant: SubGrant,
    audit_record: AuditRecord,
) -> AttributedAuditRecord:
    """Wrap an AuditRecord with the full delegation lineage from this sub-grant.

    The broker calls this when emitting an audit record for a sub-agent action.
    The resulting AttributedAuditRecord answers "why did this happen?" by carrying
    the full chain from the root human-owned grant ID down to the sub-grant.

    The delegation_chain on the returned record is ordered outermost-first:
      [root_grant_id, ..., parent_grant_id, sub_grant_id]

    Parameters
    ----------
    sub_grant:
        The sub-grant that authorized the action.
    audit_record:
        The broker-emitted AuditRecord for the action.
    """
    full_chain = sub_grant.delegationChain + [sub_grant.id]
    return AttributedAuditRecord(
        audit_record=audit_record,
        delegation_chain=full_chain,
        sub_grant_id=sub_grant.id,
    )


# ---------------------------------------------------------------------------
# Convenience factories for producing a ParentAuthority
# ---------------------------------------------------------------------------


def parent_from_grant(
    grant_id: str,
    action_classes: list[str],
    level: AutonomyLevel,
    remaining_spend: float,
    expiry: datetime,
    *,
    tree_pool_cap: float,
    allow_further_delegation: bool = True,
) -> ParentAuthority:
    """Produce a ParentAuthority from a root Grant's parameters.

    Root grants have an empty delegation_chain — they are the trust anchor.
    The broker derives remaining_spend from the enforcement store's counter balance.

    Parameters
    ----------
    grant_id:
        The Grant's stable identifier (broker-assigned or grant-store key).
    action_classes:
        The action classes the Grant authorizes.
    level:
        The Grant's current autonomy level.
    remaining_spend:
        How much of the cap is still available (cap - spent), at delegation time.
    expiry:
        The Grant's absolute expiry, UTC-aware. Root grants may have a far-future expiry.
    tree_pool_cap:
        The budget the WHOLE delegation tree rooted here may spend on one op in
        one period -- normally this grant's own per-op cap, since a tree may not
        outspend its root. Keyword-only and required: defaulting it would produce
        an unbounded sibling set silently, which is the defect #11 records.
    allow_further_delegation:
        Whether the Grant permits sub-agents to further delegate. Defaults True
        (root grants are issued by humans who may choose to permit recursive delegation).
    """
    if tree_pool_cap <= 0:
        raise ValueError(
            f"tree_pool_cap must be positive; got {tree_pool_cap!r}. A tree whose "
            "shared pool is zero or negative can never act, and a pool of None is "
            "not a bound at all."
        )
    return ParentAuthority(
        id=grant_id,
        action_classes=action_classes,
        level=level,
        remaining_spend=remaining_spend,
        expiry=expiry,
        tree_pool_cap=tree_pool_cap,
        allow_further_delegation=allow_further_delegation,
        delegation_chain=[],  # root: no prior chain
    )


def parent_from_sub_grant(
    sub_grant: SubGrant,
    remaining_spend: float,
) -> ParentAuthority:
    """Produce a ParentAuthority from an existing SubGrant.

    Used when a sub-agent that holds allowFurtherDelegation=True requests to issue
    a sub-sub-grant. The delegation_chain is extended with the sub-grant's own ID
    so that the resulting sub-sub-grant traces back through the full lineage.

    Parameters
    ----------
    sub_grant:
        The existing sub-grant acting as the parent.
    remaining_spend:
        How much of the sub-grant's spendCap is still available at delegation time.
        The broker computes this from the enforcement store.
    """
    if not sub_grant.allowFurtherDelegation:
        raise FurtherDelegationForbiddenError(
            f"Sub-grant {sub_grant.id!r} does not permit further delegation "
            "(allowFurtherDelegation=False)."
        )
    # delegation_chain for the ParentAuthority is the chain LEADING UP TO the parent
    # (not including the parent itself). compute_sub_grant appends parent.id when it
    # builds the child's delegationChain. For a SubGrant acting as parent, the chain
    # leading up to it is exactly sub_grant.delegationChain (which already ends just
    # before sub_grant.id, because compute_sub_grant built it that way).
    return ParentAuthority(
        id=sub_grant.id,
        action_classes=sub_grant.actionClasses,
        level=sub_grant.level,
        remaining_spend=remaining_spend,
        expiry=_parse_iso(sub_grant.expiry),
        # PROPAGATED, never re-declared: a grandchild inherits the root's pool, so
        # depth cannot raise the tree's shared bound. This is what makes the pool
        # un-widenable by construction rather than by a validation rule.
        tree_pool_cap=sub_grant.treePoolCap,
        allow_further_delegation=sub_grant.allowFurtherDelegation,
        delegation_chain=sub_grant.delegationChain,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp into a timezone-aware datetime."""
    return datetime.fromisoformat(ts)


def _hash_fields(fields: dict) -> str:
    """SHA-256 of the canonical JSON of the given fields."""
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
