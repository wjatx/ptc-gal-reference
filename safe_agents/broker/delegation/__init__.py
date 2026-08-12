"""broker.delegation — strictly-attenuating sub-grants + attribution chain.

The broker's delegation subsystem enforces that any sub-grant derived from a
parent grant can only narrow authority, never widen it. An agent cannot author
a sub-grant directly; it submits a DelegationScope and the broker computes the
SubGrant via compute_sub_grant().

Public API:

  Types:
    DelegationScope        — the agent's delegation request (what it's asking for)
    SubGrant               — the broker-issued, strictly-attenuating sub-grant
    ParentAuthority        — normalized parent (built from a Grant or SubGrant)
    AttributedAuditRecord  — AuditRecord bundled with the full delegation lineage
    AttenuationError       — raised when any dimension would widen parent authority
    ExpiredSubGrantError   — raised when a sub-grant's TTL has passed
    FurtherDelegationForbiddenError — raised when further delegation is not allowed

  Computation (pure, AWS-free):
    compute_sub_grant()     — compute a SubGrant from a parent + scope
    assert_attenuates()     — validate that (parent, child) satisfies attenuation
    check_action_authorized() — check if an action class is in a sub-grant's scope
    verify_not_expired()    — check TTL and raise if expired
    build_attributed_record() — wrap an AuditRecord with delegation lineage

  Factories:
    parent_from_grant()     — build a ParentAuthority from a root Grant's params
    parent_from_sub_grant() — build a ParentAuthority from an existing SubGrant

  Store:
    SubGrantStore           — persistence protocol
    InMemorySubGrantStore   — test / local-dev implementation

See broker/sub-grants.md for the design narrative and broker/SCHEMAS.md for
the canonical schema contract.
"""

from .compute import (
    assert_attenuates,
    build_attributed_record,
    check_action_authorized,
    compute_sub_grant,
    parent_from_grant,
    parent_from_sub_grant,
    verify_not_expired,
)
from .store import InMemorySubGrantStore, SubGrantStore
from .types import (
    AttenuationError,
    AttributedAuditRecord,
    DelegationScope,
    ExpiredSubGrantError,
    FurtherDelegationForbiddenError,
    ParentAuthority,
    SubGrant,
)

__all__ = [
    # types
    "DelegationScope",
    "SubGrant",
    "ParentAuthority",
    "AttributedAuditRecord",
    "AttenuationError",
    "ExpiredSubGrantError",
    "FurtherDelegationForbiddenError",
    # computation
    "compute_sub_grant",
    "assert_attenuates",
    "check_action_authorized",
    "verify_not_expired",
    "build_attributed_record",
    # factories
    "parent_from_grant",
    "parent_from_sub_grant",
    # store
    "SubGrantStore",
    "InMemorySubGrantStore",
]
