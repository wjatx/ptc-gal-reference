"""broker.delegation.keys — naming the trust anchor of a delegation tree.

``Grant`` carries no ``id`` field: its identity is ``(principal, actionClass)``,
and the grant store keys it that way (``GRANT#<agentId>#<skill>#<user>#<tier>``
plus the action class). But ``SubGrant.parentGrantId`` and
``SubGrant.delegationChain`` hold grant IDs as opaque strings, and
``parent_from_grant`` takes one as a caller-supplied argument documented only as
"broker-assigned or grant-store key". Nothing in the tree derived it, so nothing
in the tree agreed on it.

That is fine while no execution path issues a sub-grant, and stops being fine the
moment a bound is enforced against the anchor: the issuer writing a chain, the
enforcer drawing a pool counter, and any later auditor reading it have to name the
same root or the bound protects a coordinate nobody writes. This module is that
one derivation, for the same reason ``enforcement.store.scoped_counter_key`` is
one derivation.

The pool key built ON TOP of a root id lives in ``enforcement.store`` as
``tree_counter_key``, deliberately not here: it is a counter-key derivation, and
the PEP must be able to draw a counter without importing the delegation package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import Principal

# The grant store's partition-key prefix for a grant record. Matched here rather
# than imported because `grants.store._principal_key` is private to that module;
# `test_root_grant_id_matches_the_grant_stores_key_shape` pins the agreement, so
# drift fails a test instead of silently splitting the anchor in two.
GRANT_KEY_PREFIX = "GRANT"


def principal_key(principal: "Principal") -> str:
    """Render a principal as its stable key segment.

    Byte-identical to ``grants.store._principal_key`` and to the principal
    segment ``enforcement.store.scoped_counter_key`` builds inline. The three
    renderings are pinned equal by test; this is the public one.
    """
    return f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"


def root_grant_id(principal: "Principal", action_class: str) -> str:
    """The derived, stable ID of a root Grant — the anchor of a delegation tree.

    A root Grant is the trust anchor: ``parent_from_grant`` gives it an empty
    ``delegation_chain``, so this ID is what every descendant's chain starts
    with and what the tree's budget pool is keyed on.

    ``action_class`` is part of the identity because authority is per
    ``(principal, action-class)`` (GAL-1: a grant SHALL bind exactly one pair).
    Keying a tree pool on the principal alone would merge the pools of two
    unrelated grants held by the same agent, which is a different and wrong
    bound.

    A '#' in ``action_class`` would make the rendering ambiguous against the
    principal segments, so it is refused rather than producing an ID that two
    different inputs could share.
    """
    if not action_class:
        raise ValueError("action_class must be non-empty")
    if "#" in action_class:
        raise ValueError(
            f"action_class must not contain '#' (it would make the derived root "
            f"grant id ambiguous); got {action_class!r}"
        )
    return f"{GRANT_KEY_PREFIX}#{principal_key(principal)}#{action_class}"
