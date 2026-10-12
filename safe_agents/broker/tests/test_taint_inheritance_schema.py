"""PTC-51 (#177): the cause declaration, the inheritance record, and sub-grant issuance.

What is pinned here is the image-baked half of the inheritance ledger:

  - ``ToolOp.causes_context`` accepts exactly two target shapes, the literal
    ``"self"`` and a child principal spelled in full, and a positive horizon.
    Every other shape is refused at load with a message naming ``tool.op``.
  - ``AgentManifest`` refuses a child target equal to its own principal, and a
    declaration in a manifest that names no principal.
  - ``InheritanceRecord`` refuses an instant with no offset and a record born
    expired, and ``resolve_not_after`` fixes the lifetime at write time.
  - Sub-grant issuance refuses a child the causing op does not declare.

The PEP hooks and the mint read that use these are tested where they live.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from safe_agents.broker.delegation import (
    DelegationScope,
    UndeclaredDelegationTargetError,
    compute_sub_grant,
    parent_from_grant,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.schemas import (
    AgentManifest,
    CausesContext,
    InheritanceRecord,
    Principal,
    Taint,
    ToolOp,
)
from safe_agents.broker.schemas.common import MAX_DECLARABLE_AGE_SECONDS, AutonomyLevel
from safe_agents.broker.taint import inheritance_target, resolve_not_after
from safe_agents.broker.tests.scaffold import cause_op_for

OWN = Principal(agentId="parent-agent", skill="planner", user="owner", tier="B")
CHILD = Principal(agentId="child-agent", skill="worker", user="owner", tier="C")
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def _op(causes_context=None, tool: str = "worker", op: str = "launch") -> ToolOp:
    return ToolOp(
        tool=tool,
        op=op,
        effect="write",
        external=False,
        reversible=True,
        causes_context=causes_context,
    )


def _manifest(tool_ops: list, principal: Principal | None = OWN) -> AgentManifest:
    return AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain"},
            "principal": principal.model_dump() if principal else None,
            "tool_ops": tool_ops,
        }
    )


# ---------------------------------------------------------------------------
# The declaration's shape, refused at load and naming the entry
# ---------------------------------------------------------------------------


def test_self_and_full_child_targets_are_accepted() -> None:
    assert _op({"target": "self", "horizon_seconds": 60}).causes_context.target == "self"
    decl = _op({"target": CHILD.model_dump(), "horizon_seconds": 60}).causes_context
    assert decl.target == CHILD


def test_an_undeclared_op_dumps_the_field_as_null() -> None:
    # Pre-release structure rule: a new field dumps like every other.
    assert _op().model_dump()["causes_context"] is None
    assert ToolOpTable([_op()]).cause_entries() == []


@pytest.mark.parametrize(
    ("decl", "names"),
    [
        ({"target": "Self", "horizon_seconds": 60}, "target"),
        ({"target": "", "horizon_seconds": 60}, "target"),
        ({"target": "child-agent", "horizon_seconds": 60}, "target"),
        ({"target": {"agentId": "c", "skill": "w", "user": "o"}, "horizon_seconds": 60}, "tier"),
        ({"target": {**CHILD.model_dump(), "agentId": ""}, "horizon_seconds": 60}, "agentId"),
        ({"target": {**CHILD.model_dump(), "skill": " worker"}, "horizon_seconds": 60}, "skill"),
        ({"target": {**CHILD.model_dump(), "user": "owner "}, "horizon_seconds": 60}, "user"),
        ({"target": {**CHILD.model_dump(), "role": "x"}, "horizon_seconds": 60}, "role"),
        ({"target": "self"}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": 0}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": -5}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": "60"}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": 60.0}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": MAX_DECLARABLE_AGE_SECONDS + 1}, "horizon_seconds"),
        ({"target": "self", "horizon_seconds": 60, "via": "args"}, "via"),
    ],
)
def test_a_malformed_declaration_is_refused_naming_the_entry(decl, names) -> None:
    with pytest.raises(ValidationError) as exc:
        _op(decl, tool="sched", op="defer")
    message = str(exc.value)
    assert "tool_ops entry 'sched.defer'" in message
    assert names in message


def test_a_child_target_equal_to_the_manifest_principal_is_refused() -> None:
    with pytest.raises(ValidationError) as exc:
        _manifest(
            [_op({"target": OWN.model_dump(), "horizon_seconds": 60}, tool="w", op="spawn")]
        )
    assert "tool_ops entry 'w.spawn'" in str(exc.value)
    assert "spelled 'self'" in str(exc.value)


def test_a_declaration_needs_the_manifest_to_name_its_principal() -> None:
    with pytest.raises(ValidationError) as exc:
        _manifest([_op({"target": "self", "horizon_seconds": 60})], principal=None)
    assert "tool_ops entry 'worker.launch'" in str(exc.value)
    assert "names no principal" in str(exc.value)


def test_a_manifest_with_valid_declarations_loads_and_the_table_finds_them() -> None:
    manifest = _manifest(
        [
            _op({"target": "self", "horizon_seconds": 60}, tool="sched", op="defer"),
            _op(None, tool="notes", op="write"),
            _op({"target": CHILD.model_dump(), "horizon_seconds": 600}),
        ]
    )
    causes = ToolOpTable.from_manifest(manifest).cause_entries()
    assert [(e.tool, e.op) for e in causes] == [("sched", "defer"), ("worker", "launch")]


# ---------------------------------------------------------------------------
# The record and its lifetime
# ---------------------------------------------------------------------------


def _record(**overrides) -> InheritanceRecord:
    fields = {
        "id": "rec-1",
        "target": CHILD,
        "causingPrincipal": OWN,
        "causingTurnId": "turn:abc",
        "taint": Taint(tainted=True, sources=["connector:search.query"]),
        "tool": "worker",
        "op": "launch",
        "issuedAt": NOW.isoformat(),
        "notAfter": (NOW + timedelta(hours=1)).isoformat(),
    }
    fields.update(overrides)
    return InheritanceRecord(**fields)


def test_a_record_is_live_until_not_after_and_not_at_it() -> None:
    record = _record()
    assert record.live_at(NOW)
    assert record.live_at(NOW + timedelta(minutes=59))
    assert not record.live_at(NOW + timedelta(hours=1))


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuedAt": "2026-10-12T12:00:00"},
        {"notAfter": "2026-10-12T13:00:00"},
        {"notAfter": NOW.isoformat()},
        {"notAfter": (NOW - timedelta(seconds=1)).isoformat()},
        {"extra": "field"},
    ],
)
def test_a_record_with_no_offset_or_born_expired_is_refused(overrides) -> None:
    with pytest.raises(ValidationError):
        _record(**overrides)


def test_self_resolves_to_the_causing_principal_and_a_child_to_itself() -> None:
    assert inheritance_target(CausesContext(target="self", horizon_seconds=1), OWN) == OWN
    assert inheritance_target(CausesContext(target=CHILD, horizon_seconds=1), OWN) == CHILD


def _sub_grant_for(principal: Principal, ttl_seconds: float = 7200.0):
    parent = parent_from_grant(
        grant_id="grant-root",
        action_classes=["worker.launch"],
        level=AutonomyLevel.out_of_loop,
        remaining_spend=10.0,
        expiry=NOW + timedelta(days=1),
        tree_pool_cap=10.0,
    )
    scope = DelegationScope(
        subAgentPrincipal=principal,
        actionClasses=["worker.launch"],
        requestedLevel=AutonomyLevel.in_loop,
        requestedSpendCap=1.0,
        ttlSeconds=ttl_seconds,
    )
    return compute_sub_grant(parent, scope, causing_op=cause_op_for(principal), now=NOW)


@pytest.mark.parametrize(
    ("target", "sub_grant_principal", "expected"),
    [
        # A deferred own run: the horizon, always.
        ("self", None, NOW + timedelta(seconds=900)),
        ("self", CHILD, NOW + timedelta(seconds=900)),
        # A child with no sub-grant yet: the horizon.
        (CHILD, None, NOW + timedelta(seconds=900)),
        # A child with a sub-grant: the sub-grant's expiry.
        (CHILD, CHILD, NOW + timedelta(seconds=7200)),
    ],
)
def test_not_after_is_the_sub_grant_expiry_for_a_child_else_the_horizon(
    target, sub_grant_principal, expected
) -> None:
    decl = CausesContext(target=target, horizon_seconds=900)
    sub_grant = _sub_grant_for(sub_grant_principal) if sub_grant_principal else None
    assert resolve_not_after(decl, issued_at=NOW, sub_grant=sub_grant) == expected


def test_a_sub_grant_held_by_another_principal_is_refused_as_a_lifetime() -> None:
    other = Principal(agentId="other", skill="worker", user="owner", tier="C")
    decl = CausesContext(target=CHILD, horizon_seconds=900)
    with pytest.raises(ValueError, match="bound the wrong context"):
        resolve_not_after(decl, issued_at=NOW, sub_grant=_sub_grant_for(other))


def test_resolving_against_a_naive_instant_is_refused() -> None:
    decl = CausesContext(target="self", horizon_seconds=900)
    with pytest.raises(ValueError, match="offset"):
        resolve_not_after(decl, issued_at=NOW.replace(tzinfo=None))


# ---------------------------------------------------------------------------
# Sub-grant issuance: the requested child must be the declared target (ruling 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("causing_op", "reason"),
    [
        (_op(None), "declares no causes_context"),
        (_op({"target": "self", "horizon_seconds": 60}), "'self'"),
        (
            _op(
                {
                    "target": {**CHILD.model_dump(), "agentId": "a-different-child"},
                    "horizon_seconds": 60,
                }
            ),
            "is not the target",
        ),
        (
            _op({"target": {**CHILD.model_dump(), "tier": "A"}, "horizon_seconds": 60}),
            "is not the target",
        ),
    ],
)
def test_issuance_refuses_a_child_the_causing_op_does_not_declare(causing_op, reason) -> None:
    parent = parent_from_grant(
        grant_id="grant-root",
        action_classes=["worker.launch"],
        level=AutonomyLevel.out_of_loop,
        remaining_spend=10.0,
        expiry=NOW + timedelta(days=1),
        tree_pool_cap=10.0,
    )
    scope = DelegationScope(
        subAgentPrincipal=CHILD,
        actionClasses=["worker.launch"],
        requestedLevel=AutonomyLevel.in_loop,
        requestedSpendCap=1.0,
        ttlSeconds=60.0,
    )
    with pytest.raises(UndeclaredDelegationTargetError, match=reason):
        compute_sub_grant(parent, scope, causing_op=causing_op, now=NOW)
    # The declared child itself is issued.
    issued = compute_sub_grant(parent, scope, causing_op=cause_op_for(CHILD), now=NOW)
    assert issued.principal == CHILD
