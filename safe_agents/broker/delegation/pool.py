"""broker.delegation.pool — resolving a call's delegation-tree budget draw.

``scoped_counter_key`` carries an obligation in its docstring: the PEP (which
increments) and the PIP (which reads facts) MUST key through one derivation, or
the cap rule evaluates a different counter than ``enforce()`` draws. The tree pool
inherits that obligation and adds a second one, because a pool draw needs a CAP as
well as a key, and a cap that two callers compute differently enforces two
different bounds on one counter.

So this module is the single resolution both sides call. The PIP uses the returned
draw's ``key`` and ``cap`` to derive its fact; the PEP hands the same object to
``enforce(ancestor_draws=...)``.

WHY THE POOL EXISTS. A per-principal counter isolates budgets, which is right for
peers and wrong for a delegation tree: a parent and each of its children are
distinct principals, so their draws never meet and no bound spans them. Each
child's own cap bounds that child; nothing bounds the set. Two siblings that each
fit their own cap can jointly exceed the ancestor's remaining budget. That is
reference-implementation issue #11, reported as a code-review finding.

WHY IT SHIPS OFF. ``sub_grant_store=None`` disables every pool draw, so a
deployment that never delegates behaves exactly as it did before this existed and
pays no extra write per call. This follows the friction doctrine: the floor stays
tiny and every other bound is a knob. The knob is not "should the tree be bounded"
-- once delegation is configured the pool is drawn unconditionally -- it is
"is this deployment delegating at all".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from safe_agents.broker.enforcement.store import (
    ACTION_CAP_SUFFIX,
    tree_counter_key,
)
from safe_agents.broker.enforcement.types import CounterDraw

from .keys import root_grant_id

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import CounterPeriod, Principal

    from .store import SubGrantStore


def resolve_tree_pool(
    principal: "Principal",
    tool: str,
    op: str,
    *,
    sub_grant_store: "SubGrantStore | None",
    own_cap: float,
    period: "CounterPeriod" = "utc-day",
    delta: float = 1.0,
) -> CounterDraw | None:
    """The ONE resolution of a call's delegation-tree pool draw.

    Returns None when no pool bound applies -- delegation is not configured for
    this deployment -- and a ``CounterDraw`` otherwise. Both the PIP and the PEP
    call this, which is what makes the fact and the draw agree by construction
    rather than by two matching edits.

    THE ACTING PRINCIPAL IS NEVER ASKED. The sub-grant is resolved from the
    broker's own store by the principal the broker already authenticated, exactly
    as a Grant is. A child zone's principal is image-baked in its manifest and its
    sub-grant row is broker-written, so nothing about the tree is read from the
    call and a fully compromised child has nothing to assert. This is why a
    sub-agent presents no token: under a per-zone runtime there is nothing to
    present.

    ROOT AND CHILD RESOLVE THE SAME COORDINATE FROM DIFFERENT SIDES:

    * A principal holding no sub-grant is a ROOT. Its anchor is derived from its
      own (principal, action-class) via ``root_grant_id``, and the pool cap is its
      own per-op cap -- a tree may not outspend its root. The root draws the pool
      too, or "everything the tree spent" would exclude the root's own spend and
      the parent could spend a full cap beside its children.
    * A principal holding a sub-grant is a DESCENDANT. Its anchor is
      ``delegationChain[0]``, the root the issuer recorded, and the cap is the
      broker-stamped ``treePoolCap`` it inherited. It never recomputes either, so
      depth cannot move the bound.

    Both land on the identical key for the same tree and op, which is the whole
    point: that shared coordinate is what makes siblings contend.

    ``own_cap`` is used ONLY in the root case. Passing a descendant's own cap here
    is harmless because it is ignored; the inherited ``treePoolCap`` wins.
    """
    if sub_grant_store is None:
        return None

    sub_grant = sub_grant_store.get_by_principal(principal)
    if sub_grant is None:
        anchor = root_grant_id(principal, f"{tool}.{op}")
        cap = own_cap
    else:
        # A sub-grant with an empty chain is a malformed record rather than a
        # root: compute_sub_grant always appends the parent's id, so the chain of
        # a real sub-grant is never empty. Falling back to the child's own id
        # would silently give it a private pool -- its own tree of one -- which is
        # exactly the unbounded-sibling state the pool exists to prevent.
        if not sub_grant.delegationChain:
            raise ValueError(
                f"sub-grant {sub_grant.id!r} has an empty delegationChain; it "
                "names no root, so the tree pool it should charge is undefined"
            )
        anchor = sub_grant.delegationChain[0]
        cap = sub_grant.treePoolCap

    return CounterDraw(
        key=tree_counter_key(anchor, tool, op, ACTION_CAP_SUFFIX, period=period),
        delta=delta,
        cap=cap,
    )
