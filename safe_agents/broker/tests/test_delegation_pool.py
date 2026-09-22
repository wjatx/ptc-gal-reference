"""The delegation-tree budget pool (#11) — the bound that spans siblings.

`test_delegation.py` covers the attenuation COMPUTATION: a sub-grant may not
widen its parent on any dimension. Everything there is about one child versus one
parent, and all of it passed while the defect this file pins was live.

The defect: a per-principal counter isolates budgets, and a parent and each of
its children are distinct principals, so their draws never meet. Each child's own
cap bounds that child. Nothing bounded the SET. Two siblings that each stay
inside their own cap could jointly spend more than the ancestor had left, which
is an aggregate-budget escape that every per-child assertion reports as fine.

An outside review of `9ca1523` reported it as a code-review finding and was
explicit that it had NOT reproduced it, asking for "an integration test where
individually permitted sibling actions collectively exceed the ancestor's
remaining budget". `test_siblings_cannot_jointly_exceed_the_ancestors_budget` is
that test, and it is the one to break first when changing any of this: with
`ancestor_draws` removed from the PEP it goes red while every other delegation
test stays green, which is the shape the original defect had.
"""

from __future__ import annotations

import threading

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.delegation import root_grant_id
from safe_agents.broker.delegation.compute import compute_sub_grant, parent_from_grant
from safe_agents.broker.delegation.pool import resolve_tree_pool
from safe_agents.broker.delegation.store import InMemorySubGrantStore
from safe_agents.broker.delegation.types import (
    AmbiguousSubGrantError,
    DelegationScope,
)
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.enforcement.store import (
    ACTION_CAP_SUFFIX,
    scoped_counter_key,
    tree_counter_key,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
)
from safe_agents.broker.schemas import BrokeredCall, Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map
from safe_agents.connectors import StubConnector
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, make_pip

# The tree may create three events a period, no matter how the work is divided.
# A benign reversible op is used deliberately: the pool is about the BUDGET,
# and a high-blast op would route to require_approval and test the wrong rule.
TREE_POOL_CAP = 3.0
# Each sibling's OWN cap is deliberately generous: if a sibling ever refuses on
# its own bound the test would pass for the wrong reason and prove nothing about
# the pool.
SIBLING_OWN_CAP = 100.0

ACTION_CLASS = "calendar.create_event"
# The high-blast class used to reach the out-of-band approval release path.
HELD_CLASS = "payments.transfer"

ROOT = Principal(agentId="root-agent", skill="orchestrator", user="owner", tier="B")
SIB_A = Principal(agentId="worker-a", skill="sender", user="owner", tier="B")
SIB_B = Principal(agentId="worker-b", skill="sender", user="owner", tier="B")

_FAR_FUTURE = "2099-01-01T00:00:00+00:00"


def _grant(principal: Principal, action_class: str = ACTION_CLASS) -> Grant:
    return Grant.model_validate(
        {
            "principal": principal.model_dump(),
            "actionClass": action_class,
            "level": AutonomyLevel.on_loop,
            "envelopeHash": ENVELOPE_HASH,
            "promotedBy": "human-reviewer",
            "evidence": "test-evidence-ref",
            "ts": "2026-09-21T00:00:00Z",
            "lastSafeLevel": "in-loop",
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "test-owner",
        }
    )


def _sub_grant_for(principal: Principal, sub_grant_store, *, pool=TREE_POOL_CAP):
    """Issue a real sub-grant for a sibling and persist it broker-side.

    Goes through compute_sub_grant rather than hand-building a SubGrant so the
    delegationChain and treePoolCap are produced the way issuance will produce
    them: the chain anchored on the DERIVED root id, the pool inherited.
    """
    parent = parent_from_grant(
        grant_id=root_grant_id(ROOT, ACTION_CLASS),
        action_classes=[ACTION_CLASS],
        level=AutonomyLevel.on_loop,
        remaining_spend=1000.0,
        expiry=__import__("datetime").datetime.fromisoformat(_FAR_FUTURE),
        tree_pool_cap=pool,
    )
    sg = compute_sub_grant(
        parent,
        DelegationScope(
            subAgentPrincipal=principal,
            actionClasses=[ACTION_CLASS],
            requestedLevel=AutonomyLevel.on_loop,
            requestedSpendCap=500.0,
            ttlSeconds=86_400.0,
        ),
    )
    sub_grant_store.save(sg)
    return sg


def _runtime_for(principal, *, enforcement_store, sub_grant_store, sink=None):
    """One zone, one runtime, one principal — sharing the broker's stores.

    This is the per-zone model the pool assumes: each sibling builds its own
    runtime from its own image-baked manifest (its principal is a constructor
    argument, never anything a call can carry), and they reach each other only
    through the shared enforcement and sub-grant stores.
    """
    connector = StubConnector(result={"event_id": "evt-1"})
    payments = StubConnector(result={"tx_id": "tx-released"})
    intents = InMemoryIntentStore()
    runtime = BrokerRuntime(
        principal=principal,
        grants=[_grant(principal), _grant(principal, action_class=HELD_CLASS)],
        optable=ToolOpTable(
            [
                ToolOp(
                    tool="calendar",
                    op="create_event",
                    effect="write",
                    external=False,
                    reversible=True,
                ),
                # external + irreversible -> the PDP always returns
                # require_approval, which is how the release path is reached.
                ToolOp(
                    tool="payments",
                    op="transfer",
                    effect="write",
                    external=True,
                    reversible=False,
                ),
            ]
        ),
        doer=Doer(
            connectors={"calendar": connector, "payments": payments},
            secrets=FakeSecretsProvider(
                {"calendar": "cred-calendar", "payments": "cred-payments"}
            ),
        ),
        pip=make_pip(grant_level=AutonomyLevel.on_loop),
        enforcement_store=enforcement_store,
        intent_store=intents,
        audit_sink=sink or InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=SIBLING_OWN_CAP,
        sub_grant_store=sub_grant_store,
    )
    return runtime, connector, payments, intents



def _probe_call(principal: Principal) -> BrokeredCall:
    """A minimal BrokeredCall for driving the PIP directly."""
    return BrokeredCall.model_validate(
        {
            "principal": principal.model_dump(),
            "tool": "calendar",
            "op": "create_event",
            "args": {"title": "sync"},
            "manifest": {
                "tool": "calendar",
                "op": "create_event",
                "effect": "write",
                "external": False,
                "reversible": True,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "probe-turn", "ingestedSources": []},
            "ts": "2026-09-21T00:00:00+00:00",
        }
    )


def _send(runtime):
    return runtime.handle_request(AgentRequest(tool="calendar", op="create_event", args={"title": "sync"}))


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


def test_siblings_cannot_jointly_exceed_the_ancestors_budget():
    """Two siblings, each well inside its OWN cap, are bounded as a set.

    The assertion that matters is the connector count: the bound has to stop the
    side effect, not merely report a denial afterwards.
    """
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants)
    _sub_grant_for(SIB_B, sub_grants)

    rt_a, conn_a, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=sub_grants)
    rt_b, conn_b, _, _ = _runtime_for(SIB_B, enforcement_store=counters, sub_grant_store=sub_grants)

    # Each sibling spends twice: four attempts against a tree pool of three.
    results = [_send(rt_a), _send(rt_a), _send(rt_b), _send(rt_b)]

    executed = [r for r in results if r.decision_kind == "allow"]
    refused = [r for r in results if r.decision_kind == "deny"]

    assert len(executed) == int(TREE_POOL_CAP), (
        f"the tree pool is {TREE_POOL_CAP}; {len(executed)} calls were allowed"
    )
    assert len(refused) == 1

    # The side effect is what the bound exists to stop.
    assert len(conn_a.calls) + len(conn_b.calls) == int(TREE_POOL_CAP)

    # Neither sibling came anywhere near its own cap, so nothing here was
    # bounded by the per-principal counter. Without the pool all four execute.
    for principal in (SIB_A, SIB_B):
        own = counters.read_counter(
            scoped_counter_key(principal, "calendar", "create_event", ACTION_CAP_SUFFIX)
        )
        assert own <= 2.0 < SIBLING_OWN_CAP

    assert "delegation-tree budget exceeded" in (refused[0].reason or "")


def test_refusal_names_the_pool_not_the_childs_own_cap():
    """The two denials call for opposite responses, so they must read differently.

    A child's own cap is a knob on that child. A pool refusal means a SIBLING
    spent the shared budget, and raising this child's cap would change nothing.
    Collapsing them into one reason would send an operator to the wrong knob.
    """
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=1.0)
    rt, _, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=sub_grants)

    assert _send(rt).decision_kind == "allow"
    refusal = _send(rt)

    assert refusal.decision_kind == "deny"
    assert "delegation-tree budget exceeded" in (refusal.reason or "")
    assert "capacity budget exceeded" not in (refusal.reason or "")


def test_pool_refusal_is_recorded_in_the_audit():
    """A refused call is auditable as a refusal, with the pool named."""
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=1.0)
    sink = InMemorySink()
    rt, _, _, _ = _runtime_for(
        SIB_A, enforcement_store=counters, sub_grant_store=sub_grants, sink=sink
    )

    _send(rt)
    _send(rt)

    denied = [r for r in sink.records() if r.decision == "deny"]
    assert len(denied) == 1
    assert "delegation-tree" in (denied[0].reason or "")


def test_concurrent_siblings_cannot_both_take_the_last_unit():
    """The pool's bound is a compare-and-set, not a read-then-write.

    Two siblings racing for one remaining unit is the case a read-then-write
    would let both win, which is how an aggregate bound leaks under exactly the
    concurrency it is supposed to hold under.
    """
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=1.0)
    _sub_grant_for(SIB_B, sub_grants, pool=1.0)
    rt_a, conn_a, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=sub_grants)
    rt_b, conn_b, _, _ = _runtime_for(SIB_B, enforcement_store=counters, sub_grant_store=sub_grants)

    results: list = []
    barrier = threading.Barrier(2)

    def go(rt):
        barrier.wait()
        results.append(_send(rt))

    threads = [threading.Thread(target=go, args=(rt,)) for rt in (rt_a, rt_b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for r in results if r.decision_kind == "allow") == 1
    assert len(conn_a.calls) + len(conn_b.calls) == 1


# ---------------------------------------------------------------------------
# The coordinate
# ---------------------------------------------------------------------------


def test_root_and_child_resolve_the_same_pool_key():
    """A parent's own spend and its children's land on ONE counter.

    If they did not, "everything the tree spent" would exclude the root's own
    calls and a parent could spend a full cap beside its children.
    """
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants)

    root_draw = resolve_tree_pool(
        ROOT, "calendar", "create_event", sub_grant_store=sub_grants, own_cap=TREE_POOL_CAP
    )
    child_draw = resolve_tree_pool(
        SIB_A, "calendar", "create_event", sub_grant_store=sub_grants, own_cap=SIBLING_OWN_CAP
    )

    assert root_draw is not None and child_draw is not None
    assert root_draw.key == child_draw.key
    # The child inherits the pool cap; it never re-derives one from its own
    # envelope, which is what stops depth from moving the bound.
    assert child_draw.cap == TREE_POOL_CAP
    assert child_draw.cap != SIBLING_OWN_CAP


def test_tree_key_can_never_collide_with_a_principal_key():
    """Collision-free by construction, not by convention.

    A principal key always renders exactly three '#' separators; the tree
    namespace literal contains none, so no principal can occupy the first
    segment of a tree key. Pinned because a collision would silently merge an
    unrelated principal's budget into a tree pool.
    """
    principal_scoped = scoped_counter_key(ROOT, "calendar", "create_event", ACTION_CAP_SUFFIX)
    tree_scoped = tree_counter_key(
        root_grant_id(ROOT, ACTION_CLASS), "calendar", "create_event", ACTION_CAP_SUFFIX
    )
    assert principal_scoped != tree_scoped
    assert tree_scoped.startswith("tree:")
    assert not principal_scoped.startswith("tree:")


def test_root_grant_id_matches_the_grant_stores_key_shape():
    """The derived anchor agrees with how the grant store names a grant.

    `grants.store._principal_key` is private, so the agreement cannot be had by
    import. Pinning it here makes drift a failing test rather than a silently
    split anchor, where the issuer writes one root id and the enforcer keys
    another.
    """
    from safe_agents.broker.grants.store import _principal_key

    assert root_grant_id(ROOT, ACTION_CLASS) == f"GRANT#{_principal_key(ROOT)}#{ACTION_CLASS}"


def test_tree_key_refuses_an_anchor_that_would_shift_segments():
    with pytest.raises(ValueError, match="must not contain ':'"):
        tree_counter_key("bad:anchor", "calendar", "create_event", ACTION_CAP_SUFFIX)


# ---------------------------------------------------------------------------
# Ships OFF, and fails loudly
# ---------------------------------------------------------------------------


def test_no_store_means_no_pool_draw():
    """An undelegated deployment is unchanged and pays no extra write."""
    assert (
        resolve_tree_pool(
            ROOT, "calendar", "create_event", sub_grant_store=None, own_cap=SIBLING_OWN_CAP
        )
        is None
    )


def test_undelegated_runtime_behaviour_is_unchanged():
    """With no sub-grant store the per-principal cap is the only bound."""
    counters = InMemoryStore()
    rt, conn, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=None)

    for _ in range(int(TREE_POOL_CAP) + 2):
        assert _send(rt).decision_kind == "allow"

    assert len(conn.calls) == int(TREE_POOL_CAP) + 2


def test_two_sub_grants_for_one_principal_refuse_rather_than_choose():
    """One zone holds one derived authority.

    A second row does not widen anything; it makes "which pool does this call
    charge" undefined. Choosing one would enforce against a pool the issuer never
    meant, so the store refuses.
    """
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=3.0)
    _sub_grant_for(SIB_A, sub_grants, pool=99.0)

    with pytest.raises(AmbiguousSubGrantError, match="one derived authority"):
        sub_grants.get_by_principal(SIB_A)


def test_sub_grant_without_a_chain_refuses_rather_than_inventing_a_root():
    """A chainless sub-grant names no root, so its pool is undefined.

    Falling back to the child's own id would hand it a private pool — a tree of
    one — which is exactly the unbounded state the pool exists to prevent.
    """
    sub_grants = InMemorySubGrantStore()
    sg = _sub_grant_for(SIB_A, sub_grants)
    broken = sg.model_copy(update={"delegationChain": []})
    sub_grants.save(broken)

    with pytest.raises(ValueError, match="empty delegationChain"):
        resolve_tree_pool(
            SIB_A, "calendar", "create_event", sub_grant_store=sub_grants, own_cap=SIBLING_OWN_CAP
        )


def test_depth_cannot_raise_the_pool():
    """A grandchild inherits the root's pool rather than restating one."""
    from safe_agents.broker.delegation.compute import parent_from_sub_grant

    sub_grants = InMemorySubGrantStore()
    child = _sub_grant_for(SIB_A, sub_grants)
    # The child is allowed to delegate onward only if the root permitted it.
    child = child.model_copy(update={"allowFurtherDelegation": True})

    grandparent = parent_from_sub_grant(child, remaining_spend=100.0)
    assert grandparent.tree_pool_cap == TREE_POOL_CAP

    grandchild = compute_sub_grant(
        grandparent,
        DelegationScope(
            subAgentPrincipal=SIB_B,
            actionClasses=[ACTION_CLASS],
            requestedLevel=AutonomyLevel.in_loop,
            requestedSpendCap=1.0,
            ttlSeconds=60.0,
        ),
    )
    assert grandchild.treePoolCap == TREE_POOL_CAP
    assert grandchild.delegationChain[0] == root_grant_id(ROOT, ACTION_CLASS)


def test_a_held_call_refuses_when_a_sibling_drained_the_pool_while_it_waited():
    """An approval was never authority, and the pool is a bound the world can move.

    This covers the out-of-band RELEASE path, which is a second, separate draw
    site from the inline one. It earns its own test because removing the release
    draw passed the entire suite: every other pool test drives the inline path,
    so the release site had no coverage at all and could have been deleted
    silently.
    """
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=2.0)
    _sub_grant_for(SIB_B, sub_grants, pool=2.0)

    rt_a, _, pay_a, intents_a = _runtime_for(
        SIB_A, enforcement_store=counters, sub_grant_store=sub_grants
    )
    rt_b, _, pay_b, intents_b = _runtime_for(
        SIB_B, enforcement_store=counters, sub_grant_store=sub_grants
    )

    def hold(rt):
        resp = rt.handle_request(
            AgentRequest(tool="payments", op="transfer", args={"amount": 5, "to": "acct"})
        )
        assert resp.decision_kind == "require_approval"
        return resp.intent_id

    # A's call is held first, before any of the pool is spent.
    a_intent = hold(rt_a)

    # B then spends the whole tree pool through two approved releases.
    for _ in range(2):
        assert rt_b.approve_intent(hold(rt_b), approved_by="owner:maintainer").executed

    assert len(pay_b.calls) == 2

    # A's approval is genuine and its stored bytes are untouched, but the tree
    # has nothing left. The release must refuse rather than execute.
    released = rt_a.approve_intent(a_intent, approved_by="owner:maintainer")

    assert released.executed is False
    assert "delegation-tree budget exceeded" in (released.rejection_reason or "")
    assert pay_a.calls == []


def test_a_pool_refusal_at_the_draw_stage_overcharges_the_child_not_the_pool():
    """The documented partial-draw semantics, pinned rather than assumed.

    The two draws are separate compare-and-sets and there is no multi-key
    transaction on the EnforcementStore protocol, so a call whose primary draw
    succeeds and whose pool draw refuses leaves the CHILD charged for an action
    that never ran. Nothing is compensated, deliberately: a decrement is a write
    that can itself fail, and it hands the enforcement path an operation that
    RELEASES authority.

    This is the fail-toward-less-authority direction, and the primary is drawn
    first precisely so the over-charge lands on the one child rather than on the
    pool every sibling shares. It ages out at the next period rollover.

    Reaching this state needs the PDP to allow, which is why the test drives it
    with the fixed-Facts PIP: with the real PIP the pool read denies first and no
    draw is attempted (test_real_pip_reports_a_full_pool_as_a_cap_breach).
    """
    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=1.0)
    _sub_grant_for(SIB_B, sub_grants, pool=1.0)
    rt_a, _, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=sub_grants)
    rt_b, conn_b, _, _ = _runtime_for(SIB_B, enforcement_store=counters, sub_grant_store=sub_grants)

    assert _send(rt_a).decision_kind == "allow"
    assert _send(rt_b).decision_kind == "deny"

    # B never executed ...
    assert conn_b.calls == []
    # ... and yet B's own counter carries the refused attempt. Less authority for
    # B, none for anyone else, and the shared pool is untouched beyond A's call.
    assert (
        counters.read_counter(
            scoped_counter_key(SIB_B, "calendar", "create_event", ACTION_CAP_SUFFIX)
        )
        == 1.0
    )
    pool = tree_counter_key(
        root_grant_id(ROOT, ACTION_CLASS), "calendar", "create_event", ACTION_CAP_SUFFIX
    )
    assert counters.read_counter(pool) == 1.0


def test_real_pip_reports_a_full_pool_as_a_cap_breach():
    """The PIP half of the bound — the advisory read the PDP denies on.

    Every other test here drives the fixed-Facts PIP, so the real PIP's widened
    cap fact would otherwise have no coverage at all: the enforcement draw would
    carry the whole bound and a deployment would only ever refuse AFTER charging
    the child. This pins the read that makes a pool refusal the ordinary,
    no-draw path.
    """
    from safe_agents.broker.grants.store import InMemoryGrantStore
    from safe_agents.broker.prototype.broker_server import _make_pip

    counters = InMemoryStore()
    sub_grants = InMemorySubGrantStore()
    _sub_grant_for(SIB_A, sub_grants, pool=1.0)

    grant_store = InMemoryGrantStore()
    grant_store.put_grant(_grant(SIB_A))

    pip = _make_pip(
        grant_store,
        counters,
        SIBLING_OWN_CAP,
        ENVELOPE_HASH,
        sub_grant_store=sub_grants,
    )

    rt, _, _, _ = _runtime_for(SIB_A, enforcement_store=counters, sub_grant_store=sub_grants)

    # One real call fills the pool (cap 1.0).
    assert _send(rt).decision_kind == "allow"

    pool_key = tree_counter_key(
        root_grant_id(ROOT, ACTION_CLASS), "calendar", "create_event", ACTION_CAP_SUFFIX
    )
    assert counters.read_counter(pool_key) == 1.0  # pool now full

    probe = _probe_call(SIB_A)
    facts = pip(probe)
    assert facts.cap_budget_breached is True, (
        "a full tree pool must read as a capacity breach even though this "
        "principal's own counter is nowhere near its cap"
    )
    own = counters.read_counter(
        scoped_counter_key(SIB_A, "calendar", "create_event", ACTION_CAP_SUFFIX)
    )
    assert own < SIBLING_OWN_CAP

    # And with delegation not configured the same state reads as no breach.
    pip_off = _make_pip(
        grant_store, counters, SIBLING_OWN_CAP, ENVELOPE_HASH, sub_grant_store=None
    )
    assert pip_off(probe).cap_budget_breached is False
