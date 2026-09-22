"""Tests for broker.delegation — strictly-attenuating sub-grants + attribution.

All tests are AWS-free: no boto3, no moto, no network. The pure computation
functions are exercised directly; the InMemorySubGrantStore provides the
persistence fake.

Acceptance criteria from #54:
  1. Attenuation test — sub-grant for email.draft only; sub-agent attempting
     email.send is denied (not in sub-grant scope).
  2. Cap attenuation test — sub-grant spendCap ≤ parent remaining at creation,
     by value; requesting more is rejected.
  3. Expiry test — past-TTL sub-grant rejected; expiry cannot be extended by
     requesting a TTL that exceeds the parent's remaining.
  4. Attribution test — AttributedAuditRecord for a sub-agent action carries the
     full lineage [root_grant_id, parent_grant_id, sub_grant_id].
  5. Widening-attempt test — any attempt to widen level / cap / scope is rejected
     with AttenuationError.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from safe_agents.broker.delegation import (
    AttenuationError,
    AttributedAuditRecord,
    DelegationScope,
    ExpiredSubGrantError,
    FurtherDelegationForbiddenError,
    InMemorySubGrantStore,
    SubGrant,
    assert_attenuates,
    build_attributed_record,
    check_action_authorized,
    compute_sub_grant,
    parent_from_grant,
    parent_from_sub_grant,
    verify_not_expired,
)
from safe_agents.broker.schemas import AuditRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
_PARENT_EXPIRY = _NOW + timedelta(hours=8)
_TS = _NOW.isoformat()

_PARENT_PRINCIPAL = Principal(agentId="parent-agent", skill="email", user="alice", tier="B")
_SUB_PRINCIPAL = Principal(agentId="sub-agent-1", skill="email-draft", user="alice", tier="C")


# The tree pool is required at issuance (no safe default in production); the
# suite pins one value so attenuation tests stay about the dimension they name.
_DEFAULT_TREE_POOL_CAP = 100.0


def _parent(
    grant_id: str = "grant-root-1",
    action_classes: list[str] | None = None,
    level: AutonomyLevel = AutonomyLevel.out_of_loop,
    remaining_spend: float = 100.0,
    expiry: datetime | None = None,
    allow_further_delegation: bool = True,
    tree_pool_cap: float = _DEFAULT_TREE_POOL_CAP,
) -> object:
    """Build a ParentAuthority with sensible defaults."""
    return parent_from_grant(
        grant_id=grant_id,
        action_classes=action_classes or ["email.send", "email.draft"],
        level=level,
        remaining_spend=remaining_spend,
        expiry=expiry or _PARENT_EXPIRY,
        tree_pool_cap=tree_pool_cap,
        allow_further_delegation=allow_further_delegation,
    )


def _scope(
    action_classes: list[str] | None = None,
    level: AutonomyLevel = AutonomyLevel.in_loop,
    spend_cap: float = 50.0,
    ttl_seconds: float = 3600.0,
    allow_further_delegation: bool = False,
) -> DelegationScope:
    """Build a DelegationScope with sensible defaults."""
    return DelegationScope(
        subAgentPrincipal=_SUB_PRINCIPAL,
        actionClasses=action_classes or ["email.draft"],
        requestedLevel=level,
        requestedSpendCap=spend_cap,
        ttlSeconds=ttl_seconds,
        allowFurtherDelegation=allow_further_delegation,
    )


def _make_sub_grant(**scope_overrides) -> SubGrant:
    """Issue a sub-grant with defaults, optionally overriding scope fields."""
    return compute_sub_grant(
        _parent(),
        _scope(**scope_overrides),
        now=_NOW,
    )


def _minimal_audit_record(principal: Principal | None = None) -> AuditRecord:
    """Construct a minimal valid AuditRecord for attribution tests."""
    p = principal or _SUB_PRINCIPAL
    return AuditRecord(
        seq=1,
        ts=_TS,
        principal=p,
        tool="email",
        op="draft",
        argsDigest="sha256:abcdef",
        decision="allow",
        reason=None,
        envelopeHash="sha256:envelope1",
        approvedBy=None,
        outcome="executed",
        error=None,
        seed=None,
        prevHash="sha256:0000",
        hash="sha256:1111",
    )


# ---------------------------------------------------------------------------
# Acceptance test 1 — Attenuation: scope enforcement
#
# Sub-grant is issued for email.draft only.  Sub-agent attempting email.send
# is denied (the action class is not in the sub-grant's scope).
# ---------------------------------------------------------------------------


class TestScopeAttenuation:
    def test_sub_grant_authorizes_requested_class(self) -> None:
        """email.draft is in the sub-grant's actionClasses."""
        sg = _make_sub_grant(action_classes=["email.draft"])
        assert check_action_authorized(sg, "email.draft") is True

    def test_email_send_denied_when_not_in_scope(self) -> None:
        """email.send is NOT in a sub-grant issued for email.draft only."""
        sg = _make_sub_grant(action_classes=["email.draft"])
        assert check_action_authorized(sg, "email.send") is False

    def test_action_class_not_in_sub_grant_is_denied(self) -> None:
        """Any action class outside the sub-grant's list is unauthorized."""
        sg = _make_sub_grant(action_classes=["email.draft"])
        assert check_action_authorized(sg, "payments.transfer") is False
        assert check_action_authorized(sg, "calendar.create") is False

    def test_sub_grant_action_classes_are_sorted_subset(self) -> None:
        """The issued sub-grant's actionClasses is the sorted requested subset."""
        sg = _make_sub_grant(action_classes=["email.draft"])
        assert sg.actionClasses == ["email.draft"]
        # The parent also authorizes email.send — sub-grant does not include it
        assert "email.send" not in sg.actionClasses

    def test_multiple_action_classes_all_authorized(self) -> None:
        """A sub-grant with two classes authorizes both."""
        sg = _make_sub_grant(action_classes=["email.draft", "email.send"])
        assert check_action_authorized(sg, "email.draft") is True
        assert check_action_authorized(sg, "email.send") is True


# ---------------------------------------------------------------------------
# Acceptance test 2 — Cap attenuation
#
# sub-grant spendCap ≤ parent remaining at creation time, by value.
# Requesting a cap above the remaining is rejected.
# ---------------------------------------------------------------------------


class TestCapAttenuation:
    def test_sub_grant_cap_equals_requested_when_within_remaining(self) -> None:
        """spendCap is set to the requested value when it's within the remaining."""
        parent = _parent(remaining_spend=100.0)
        sg = compute_sub_grant(parent, _scope(spend_cap=60.0), now=_NOW)
        assert sg.spendCap == 60.0

    def test_sub_grant_cap_le_parent_remaining(self) -> None:
        """Sub-grant spendCap ≤ parent remaining at creation."""
        parent = _parent(remaining_spend=100.0)
        sg = compute_sub_grant(parent, _scope(spend_cap=100.0), now=_NOW)
        assert sg.spendCap <= 100.0

    def test_requesting_cap_equal_to_remaining_succeeds(self) -> None:
        """Exactly consuming the remaining cap is allowed (not a widening)."""
        parent = _parent(remaining_spend=50.0)
        sg = compute_sub_grant(parent, _scope(spend_cap=50.0), now=_NOW)
        assert sg.spendCap == 50.0

    def test_requesting_cap_above_remaining_raises(self) -> None:
        """Requesting more cap than the parent has remaining is rejected."""
        parent = _parent(remaining_spend=50.0)
        with pytest.raises(AttenuationError, match="spendCap"):
            compute_sub_grant(parent, _scope(spend_cap=51.0), now=_NOW)

    def test_zero_remaining_any_nonzero_cap_raises(self) -> None:
        """When parent has zero remaining, any nonzero cap request is rejected."""
        parent = _parent(remaining_spend=0.0)
        with pytest.raises(AttenuationError):
            compute_sub_grant(parent, _scope(spend_cap=1.0), now=_NOW)


# ---------------------------------------------------------------------------
# Acceptance test 3 — Expiry: past-TTL rejected; not extendable
#
# A sub-grant whose absolute expiry has passed is rejected on every call.
# Requesting a TTL that would set expiry past the parent's expiry is rejected.
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_valid_sub_grant_not_expired(self) -> None:
        """A freshly issued sub-grant with future expiry passes verify_not_expired."""
        sg = _make_sub_grant(ttl_seconds=3600.0)
        future = _NOW + timedelta(minutes=30)
        verify_not_expired(sg, now=future)  # should not raise

    def test_expired_sub_grant_raises(self) -> None:
        """A past-TTL sub-grant is rejected by verify_not_expired."""
        sg = _make_sub_grant(ttl_seconds=60.0)
        # Advance time past the expiry
        after_expiry = _NOW + timedelta(seconds=120)
        with pytest.raises(ExpiredSubGrantError, match=sg.id):
            verify_not_expired(sg, now=after_expiry)

    def test_exactly_at_expiry_is_expired(self) -> None:
        """At the exact expiry instant the sub-grant is considered expired."""
        sg = _make_sub_grant(ttl_seconds=3600.0)
        expiry_dt = datetime.fromisoformat(sg.expiry)
        with pytest.raises(ExpiredSubGrantError):
            verify_not_expired(sg, now=expiry_dt)

    def test_ttl_exceeding_parent_expiry_raises(self) -> None:
        """Requesting a TTL that would set expiry past the parent's expiry is rejected."""
        parent_expiry = _NOW + timedelta(hours=1)
        parent = _parent(expiry=parent_expiry)
        # Request 2 hours — past the parent's 1-hour remaining
        with pytest.raises(AttenuationError, match="expiry"):
            compute_sub_grant(parent, _scope(ttl_seconds=7201.0), now=_NOW)

    def test_ttl_exactly_at_parent_expiry_succeeds(self) -> None:
        """A TTL exactly matching the parent's remaining window is valid."""
        parent_expiry = _NOW + timedelta(hours=1)
        parent = _parent(expiry=parent_expiry)
        # 3600s = exactly 1 hour, matching the parent expiry
        sg = compute_sub_grant(parent, _scope(ttl_seconds=3600.0), now=_NOW)
        sg_expiry = datetime.fromisoformat(sg.expiry)
        assert sg_expiry <= parent_expiry


# ---------------------------------------------------------------------------
# Acceptance test 4 — Attribution chain
#
# AttributedAuditRecord for a sub-agent action carries the full lineage:
# [root_grant_id, parent_grant_id, sub_grant_id]
# ---------------------------------------------------------------------------


class TestAttributionChain:
    def test_root_grant_attribution(self) -> None:
        """Sub-grant from a root grant: chain = [root_grant_id, sub_grant_id]."""
        root_grant_id = "grant-root-42"
        parent = _parent(grant_id=root_grant_id)
        sg = compute_sub_grant(parent, _scope(), now=_NOW)

        record = _minimal_audit_record()
        attributed = build_attributed_record(sg, record)

        assert isinstance(attributed, AttributedAuditRecord)
        assert attributed.sub_grant_id == sg.id
        assert attributed.delegation_chain == [root_grant_id, sg.id]

    def test_full_lineage_root_to_sub_grant(self) -> None:
        """Chain contains both the root grant ID and the sub-grant ID."""
        root_grant_id = "grant-root-99"
        parent = _parent(grant_id=root_grant_id)
        sg = compute_sub_grant(parent, _scope(), now=_NOW)

        attributed = build_attributed_record(sg, _minimal_audit_record())

        # Root is first, sub-grant is last
        assert attributed.delegation_chain[0] == root_grant_id
        assert attributed.delegation_chain[-1] == sg.id

    def test_recursive_attribution_three_levels(self) -> None:
        """A sub-sub-grant carries [root, parent_sg, sub_sg] as full lineage."""
        root_grant_id = "grant-root-7"
        parent = _parent(
            grant_id=root_grant_id,
            allow_further_delegation=True,
        )
        parent_sg = compute_sub_grant(
            parent,
            _scope(allow_further_delegation=True, action_classes=["email.draft"]),
            now=_NOW,
        )
        assert parent_sg.allowFurtherDelegation is True

        # Sub-agent issues a sub-sub-grant
        grandchild_principal = Principal(
            agentId="sub-sub-agent", skill="draft-worker", user="alice", tier="D"
        )
        grandchild_scope = DelegationScope(
            subAgentPrincipal=grandchild_principal,
            actionClasses=["email.draft"],
            requestedLevel=AutonomyLevel.in_loop,
            requestedSpendCap=10.0,
            ttlSeconds=1800.0,
            allowFurtherDelegation=False,
        )
        sub_parent = parent_from_sub_grant(parent_sg, remaining_spend=50.0)
        sub_sg = compute_sub_grant(sub_parent, grandchild_scope, now=_NOW)

        attributed = build_attributed_record(sub_sg, _minimal_audit_record())
        # Full lineage: root → parent_sg → sub_sg
        assert attributed.delegation_chain == [root_grant_id, parent_sg.id, sub_sg.id]

    def test_attributed_record_contains_audit_record(self) -> None:
        """The wrapped audit record is the one passed in."""
        parent = _parent()
        sg = compute_sub_grant(parent, _scope(), now=_NOW)
        record = _minimal_audit_record()
        attributed = build_attributed_record(sg, record)
        assert attributed.audit_record is record

    def test_chain_unwinds_to_human_owner(self) -> None:
        """The first element of the chain is the root human-owned grant ID."""
        human_grant_id = "human-grant-alice"
        parent = _parent(grant_id=human_grant_id)
        sg = compute_sub_grant(parent, _scope(), now=_NOW)
        attributed = build_attributed_record(sg, _minimal_audit_record())
        # First link in the chain is always the root (human) grant
        assert attributed.delegation_chain[0] == human_grant_id


# ---------------------------------------------------------------------------
# Acceptance test 5 — Widening-attempt test
#
# Any attempt to widen level / cap / scope is rejected with AttenuationError.
# ---------------------------------------------------------------------------


class TestWideningAttempt:
    def test_widening_level_rejected(self) -> None:
        """Requesting a more-autonomous level than the parent is rejected."""
        parent = _parent(level=AutonomyLevel.in_loop)
        with pytest.raises(AttenuationError, match="level"):
            compute_sub_grant(
                parent,
                _scope(level=AutonomyLevel.out_of_loop),
                now=_NOW,
            )

    def test_widening_level_from_on_loop_to_out_of_loop_rejected(self) -> None:
        """on-loop parent cannot produce an out-of-loop sub-grant."""
        parent = _parent(level=AutonomyLevel.on_loop)
        with pytest.raises(AttenuationError, match="level"):
            compute_sub_grant(
                parent,
                _scope(level=AutonomyLevel.out_of_loop),
                now=_NOW,
            )

    def test_widening_cap_rejected(self) -> None:
        """Requesting a cap above parent remaining is rejected."""
        parent = _parent(remaining_spend=30.0)
        with pytest.raises(AttenuationError, match="spendCap"):
            compute_sub_grant(parent, _scope(spend_cap=31.0), now=_NOW)

    def test_widening_scope_to_unauthorized_class_rejected(self) -> None:
        """Requesting an action class the parent doesn't hold is rejected."""
        parent = _parent(action_classes=["email.draft"])
        with pytest.raises(AttenuationError, match="actionClasses"):
            compute_sub_grant(
                parent,
                _scope(action_classes=["email.send"]),
                now=_NOW,
            )

    def test_widening_scope_to_completely_different_class_rejected(self) -> None:
        """Requesting a class outside any parent authorization is rejected."""
        parent = _parent(action_classes=["email.draft"])
        with pytest.raises(AttenuationError):
            compute_sub_grant(
                parent,
                _scope(action_classes=["payments.transfer"]),
                now=_NOW,
            )

    def test_widening_ttl_rejected(self) -> None:
        """Requesting a TTL that extends past parent's expiry is rejected."""
        parent = _parent(expiry=_NOW + timedelta(hours=1))
        with pytest.raises(AttenuationError, match="expiry"):
            compute_sub_grant(parent, _scope(ttl_seconds=7201.0), now=_NOW)

    def test_assert_attenuates_catches_widened_level(self) -> None:
        """assert_attenuates raises for a child with a wider level."""
        parent = parent_from_grant(
            grant_id="g1",
            action_classes=["email.draft"],
            level=AutonomyLevel.in_loop,
            remaining_spend=100.0,
            expiry=_PARENT_EXPIRY,
            tree_pool_cap=_DEFAULT_TREE_POOL_CAP,
        )
        # Manually build a sub-grant with a wider level (bypassing compute_sub_grant)
        # to test assert_attenuates independently.
        bad_sg = _make_sub_grant()  # produces a valid one first
        # Override the level field to be wider than parent (in_loop parent)
        bad_sg_wider = SubGrant(
            **{**bad_sg.model_dump(), "level": AutonomyLevel.out_of_loop}
        )
        # Parent is in-loop; child claiming out-of-loop is a widening
        with pytest.raises(AttenuationError, match="level"):
            assert_attenuates(parent, bad_sg_wider)

    def test_assert_attenuates_catches_widened_cap(self) -> None:
        """assert_attenuates raises for a child with a wider spend cap."""
        parent = parent_from_grant(
            grant_id="g1",
            action_classes=["email.draft"],
            level=AutonomyLevel.out_of_loop,
            remaining_spend=10.0,
            expiry=_PARENT_EXPIRY,
            tree_pool_cap=_DEFAULT_TREE_POOL_CAP,
        )
        valid_sg = compute_sub_grant(parent, _scope(spend_cap=10.0), now=_NOW)
        bad_sg = SubGrant(**{**valid_sg.model_dump(), "spendCap": 11.0})
        with pytest.raises(AttenuationError, match="spendCap"):
            assert_attenuates(parent, bad_sg)

    def test_assert_attenuates_catches_widened_scope(self) -> None:
        """assert_attenuates raises for a child with an action class the parent lacks."""
        parent = parent_from_grant(
            grant_id="g1",
            action_classes=["email.draft"],
            level=AutonomyLevel.out_of_loop,
            remaining_spend=100.0,
            expiry=_PARENT_EXPIRY,
            tree_pool_cap=_DEFAULT_TREE_POOL_CAP,
        )
        valid_sg = compute_sub_grant(parent, _scope(action_classes=["email.draft"]), now=_NOW)
        bad_sg = SubGrant(**{**valid_sg.model_dump(), "actionClasses": ["email.send"]})
        with pytest.raises(AttenuationError, match="actionClasses"):
            assert_attenuates(parent, bad_sg)

    def test_further_delegation_widening_rejected(self) -> None:
        """allowFurtherDelegation=True is rejected when the parent forbids it."""
        parent = _parent(allow_further_delegation=False)
        with pytest.raises((AttenuationError, FurtherDelegationForbiddenError)):
            compute_sub_grant(
                parent,
                _scope(allow_further_delegation=True),
                now=_NOW,
            )


# ---------------------------------------------------------------------------
# Recursive attenuation
# ---------------------------------------------------------------------------


class TestRecursiveAttenuation:
    def test_sub_agent_cannot_delegate_without_permission(self) -> None:
        """parent_from_sub_grant raises if allowFurtherDelegation=False."""
        sg = _make_sub_grant(allow_further_delegation=False)
        with pytest.raises(FurtherDelegationForbiddenError):
            parent_from_sub_grant(sg, remaining_spend=50.0)

    def test_recursive_sub_grant_is_strictly_attenuating(self) -> None:
        """A sub-sub-grant must still attenuate on every dimension."""
        parent = _parent(
            action_classes=["email.draft"],
            level=AutonomyLevel.out_of_loop,
            remaining_spend=100.0,
            allow_further_delegation=True,
        )
        parent_sg = compute_sub_grant(
            parent,
            _scope(
                action_classes=["email.draft"],
                level=AutonomyLevel.on_loop,
                spend_cap=50.0,
                ttl_seconds=3600.0,
                allow_further_delegation=True,
            ),
            now=_NOW,
        )
        assert parent_sg.allowFurtherDelegation is True

        sub_parent = parent_from_sub_grant(parent_sg, remaining_spend=50.0)
        grandchild_scope = DelegationScope(
            subAgentPrincipal=Principal(
                agentId="grand-sub", skill="draft", user="alice", tier="D"
            ),
            actionClasses=["email.draft"],
            requestedLevel=AutonomyLevel.in_loop,
            requestedSpendCap=25.0,
            ttlSeconds=1800.0,
            allowFurtherDelegation=False,
        )
        sub_sg = compute_sub_grant(sub_parent, grandchild_scope, now=_NOW)

        # Level must not exceed parent sub-grant's level (on-loop)
        from safe_agents.broker.delegation.types import LEVEL_ORDER
        assert LEVEL_ORDER[sub_sg.level] <= LEVEL_ORDER[parent_sg.level]
        # Cap ≤ parent sub-grant remaining
        assert sub_sg.spendCap <= 50.0
        # Action classes ⊆ parent sub-grant's
        assert set(sub_sg.actionClasses) <= set(parent_sg.actionClasses)

    def test_sub_sub_grant_cannot_widen_cap_beyond_parent_sub_grant(self) -> None:
        """A sub-sub-grant cannot claim more cap than the sub-grant's remaining."""
        parent_sg = _make_sub_grant(
            action_classes=["email.draft"],
            spend_cap=40.0,
            allow_further_delegation=True,
        )
        sub_parent = parent_from_sub_grant(parent_sg, remaining_spend=40.0)
        grandchild_scope = DelegationScope(
            subAgentPrincipal=_SUB_PRINCIPAL,
            actionClasses=["email.draft"],
            requestedLevel=AutonomyLevel.in_loop,
            requestedSpendCap=41.0,  # more than remaining — should be rejected
            ttlSeconds=1800.0,
            allowFurtherDelegation=False,
        )
        with pytest.raises(AttenuationError, match="spendCap"):
            compute_sub_grant(sub_parent, grandchild_scope, now=_NOW)


# ---------------------------------------------------------------------------
# Store behaviour
# ---------------------------------------------------------------------------


class TestSubGrantStore:
    def test_save_and_retrieve(self) -> None:
        """Save a sub-grant and retrieve it by ID."""
        store = InMemorySubGrantStore()
        sg = _make_sub_grant()
        store.save(sg)
        assert store.get(sg.id) is sg

    def test_get_unknown_id_returns_none(self) -> None:
        """Getting an unknown ID returns None."""
        store = InMemorySubGrantStore()
        assert store.get("nonexistent-id") is None

    def test_get_by_parent(self) -> None:
        """get_by_parent returns only sub-grants for that parent."""
        store = InMemorySubGrantStore()
        parent1 = _parent(grant_id="parent-A")
        parent2 = _parent(grant_id="parent-B")
        sg1 = compute_sub_grant(parent1, _scope(), now=_NOW)
        sg2 = compute_sub_grant(parent2, _scope(), now=_NOW)
        store.save(sg1)
        store.save(sg2)
        assert store.get_by_parent("parent-A") == [sg1]
        assert store.get_by_parent("parent-B") == [sg2]

    def test_sub_grant_not_in_agents_memory(self) -> None:
        """The store is the only place sub-grants live; agent cannot hold them directly.

        This is a structural test: InMemorySubGrantStore is the broker's store, not the
        agent's. compute_sub_grant returns a SubGrant value that the broker persists;
        the agent receives only the sub-grant ID. This test verifies the store holds the
        canonical copy.
        """
        store = InMemorySubGrantStore()
        sg = _make_sub_grant()
        # Broker saves it
        store.save(sg)
        # Agent "forgets" its local reference (simulated by del)
        sg_id = sg.id
        del sg
        # Broker can still retrieve it
        retrieved = store.get(sg_id)
        assert retrieved is not None
        assert retrieved.id == sg_id


# ---------------------------------------------------------------------------
# Structural / integrity checks
# ---------------------------------------------------------------------------


class TestSubGrantIntegrity:
    def test_hash_is_present_and_hex(self) -> None:
        """The issued sub-grant has a non-empty SHA-256 hex hash."""
        sg = _make_sub_grant()
        assert len(sg.hash) == 64  # SHA-256 produces 64 hex chars
        assert all(c in "0123456789abcdef" for c in sg.hash)

    def test_two_sub_grants_have_distinct_ids(self) -> None:
        """Each compute_sub_grant call produces a unique ID."""
        sg1 = _make_sub_grant()
        sg2 = _make_sub_grant()
        assert sg1.id != sg2.id

    def test_delegation_chain_starts_with_parent_id(self) -> None:
        """The sub-grant's delegationChain contains the parent's ID."""
        parent = _parent(grant_id="parent-xyz")
        sg = compute_sub_grant(parent, _scope(), now=_NOW)
        assert "parent-xyz" in sg.delegationChain

    def test_level_same_as_parent_is_allowed(self) -> None:
        """A sub-grant may match the parent's level (not strictly narrower)."""
        parent = _parent(level=AutonomyLevel.out_of_loop)
        sg = compute_sub_grant(parent, _scope(level=AutonomyLevel.out_of_loop), now=_NOW)
        assert sg.level == AutonomyLevel.out_of_loop

    def test_empty_action_classes_rejected(self) -> None:
        """DelegationScope with empty actionClasses is rejected."""
        empty_scope = DelegationScope(
            subAgentPrincipal=_SUB_PRINCIPAL,
            actionClasses=[],
            requestedLevel=AutonomyLevel.in_loop,
            requestedSpendCap=50.0,
            ttlSeconds=3600.0,
            allowFurtherDelegation=False,
        )
        with pytest.raises(AttenuationError, match="empty"):
            compute_sub_grant(_parent(), empty_scope, now=_NOW)
