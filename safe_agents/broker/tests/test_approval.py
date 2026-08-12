"""Tests for broker.approval — Intent materialization, WYSIWYE, and expiry.

All tests use InMemoryIntentStore — no AWS credentials, no moto, no network.

Acceptance criteria from #47:
  - require_approval: broker returns pending, Intent persisted, no connector call this turn.
  - WYSIWYE: after approval, executor receives the stored materializedRequest, not a
    re-issued call from a (hypothetically compromised) agent.
  - Expiry: an unactioned Intent's expiry causes approve() to reject; status → expired.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock


from safe_agents.broker.approval import (
    ApprovalResult,
    ExecutionResult,
    InMemoryIntentStore,
    NotifierEvent,
    approve,
    materialize,
)
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.schemas.common import AutonomyLevel


# ---------------------------------------------------------------------------
# Shared builders — mirrors the style used in test_enforcement.py
# ---------------------------------------------------------------------------

_PRINCIPAL = {"agentId": "agent-1", "skill": "finance", "user": "alice", "tier": "B"}
_SESSION = {"turnId": "turn-47", "ingestedSources": []}
_TS = "2026-06-28T00:00:00Z"


def _call(
    effect: str = "write",
    external: bool = True,
    reversible: bool | None = False,
    tainted: bool = False,
    tool: str = "payments",
    op: str = "transfer",
    args: dict | None = None,
) -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL,
            "tool": tool,
            "op": op,
            "args": args or {"amount": 100, "to": "acct-xyz"},
            "manifest": {
                "tool": tool,
                "op": op,
                "effect": effect,
                "external": external,
                "reversible": reversible,
            },
            "taint": {"tainted": tainted, "sources": []},
            "session": _SESSION,
            "ts": _TS,
        }
    )


def _facts(**overrides) -> Facts:
    defaults = {
        "grant_present": True,
        "grant_level": AutonomyLevel.in_loop,
        "error_budget_breached": False,
        "cap_budget_breached": False,
        "escalation_budget_available": True,
        "human_reachable": True,
        "transform_op": None,
    }
    defaults.update(overrides)
    return Facts(**defaults)


def _require_approval_decision(call: BrokeredCall):
    """Produce a require_approval decision via the PDP (in-loop write, human reachable)."""
    facts = _facts(grant_level=AutonomyLevel.in_loop, human_reachable=True)
    decision = decide(call, facts)
    assert decision.kind == "require_approval", f"unexpected decision kind: {decision.kind}"
    return decision


def _past_expiry() -> str:
    """ISO-8601 UTC timestamp 60 seconds in the past — simulates an expired intent TTL."""
    return (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()


def _put_expired_intent(store: InMemoryIntentStore, call: BrokeredCall, intent_id: str) -> Intent:
    """Write an intent with a past expiry directly into the store (bypasses materialize())."""
    intent = Intent(
        id=intent_id,
        materializedRequest=call,
        renderedForHuman="test rendered intent",
        status="pending",
        expiry=_past_expiry(),
        approvedBy=None,
        ts=_TS,
    )
    store.put_intent(intent)
    return intent


# ---------------------------------------------------------------------------
# Acceptance test 1 — require_approval: pending, persisted, no connector call
# ---------------------------------------------------------------------------


class TestMaterialize:
    def test_returns_pending_result(self) -> None:
        """materialize() returns ApprovalResult with status=pending and the intent_id."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)

        result = materialize(call, decision, store)

        assert isinstance(result, ApprovalResult)
        assert result.status == "pending"
        assert result.intent_id == decision.renderedIntent.id

    def test_intent_persisted_with_pending_status(self) -> None:
        """The Intent is written to the store with status=pending and no approvedBy."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)

        result = materialize(call, decision, store)

        intent = store.get_intent(result.intent_id)
        assert intent is not None
        assert intent.status == "pending"
        assert intent.approvedBy is None

    def test_materializes_frozen_brokered_call(self) -> None:
        """materializedRequest is the exact BrokeredCall frozen at creation time."""
        store = InMemoryIntentStore()
        call = _call(args={"amount": 9999, "to": "acct-danger"})
        decision = _require_approval_decision(call)

        result = materialize(call, decision, store)

        intent = store.get_intent(result.intent_id)
        assert intent.materializedRequest.tool == call.tool
        assert intent.materializedRequest.op == call.op
        assert intent.materializedRequest.args == call.args

    def test_broker_renders_for_human_not_agent(self) -> None:
        """renderedForHuman comes from the PDP's decision — the agent never supplies it."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)

        result = materialize(call, decision, store)

        intent = store.get_intent(result.intent_id)
        # Must exactly match the PDP-rendered text from the decision.
        assert intent.renderedForHuman == decision.renderedIntent.renderedForHuman
        # The broker-rendered text references the call's typed tool/op fields.
        assert call.tool in intent.renderedForHuman or call.op in intent.renderedForHuman

    def test_no_connector_call_this_turn(self) -> None:
        """materialize() makes no connector call — the turn ends after returning pending."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)

        # materialize() has no executor parameter; this confirms no side effect runs.
        result = materialize(call, decision, store)

        assert result.status == "pending"
        # The intent stays pending — nothing was executed.
        intent = store.get_intent(result.intent_id)
        assert intent.status == "pending"

    def test_notifier_hook_called_with_event(self) -> None:
        """The notifier hook receives a NotifierEvent carrying the broker-rendered text."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        notifier = MagicMock()

        materialize(call, decision, store, notifier)

        notifier.assert_called_once()
        event: NotifierEvent = notifier.call_args[0][0]
        assert isinstance(event, NotifierEvent)
        assert event.intent_id == decision.renderedIntent.id
        assert event.rendered_for_human == decision.renderedIntent.renderedForHuman

    def test_notifier_none_does_not_raise(self) -> None:
        """materialize() with notifier=None succeeds without error."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)

        result = materialize(call, decision, store, notifier=None)

        assert result.status == "pending"


# ---------------------------------------------------------------------------
# Acceptance test 2 — WYSIWYE: executor receives stored call, not a re-issued one
# ---------------------------------------------------------------------------


class TestWYSIWYE:
    def test_executor_receives_stored_materialized_request(self) -> None:
        """approve() passes the STORED materializedRequest to the executor — never re-derived."""
        store = InMemoryIntentStore()
        # call_a is frozen at materialization time.
        call_a = _call(args={"amount": 100, "to": "acct-original"})
        decision = _require_approval_decision(call_a)
        result = materialize(call_a, decision, store)

        received: list[BrokeredCall] = []
        approve(result.intent_id, approved_by="alice@example.com", store=store, executor=received.append)

        assert len(received) == 1
        executed = received[0]
        assert executed.tool == call_a.tool
        assert executed.op == call_a.op
        assert executed.args == call_a.args

    def test_compromised_agent_cannot_inject_different_call(self) -> None:
        """approve() has no parameter to accept a new call; the stored call always executes.

        A compromised agent could re-issue a different call post-approval, but approve()
        reads materializedRequest from the store — the agent injection path does not exist.
        """
        store = InMemoryIntentStore()
        call_a = _call(args={"amount": 1, "to": "acct-safe"})
        # call_b represents what a compromised agent might try to inject.
        call_b = _call(args={"amount": 1_000_000, "to": "acct-attacker"})

        decision = _require_approval_decision(call_a)
        result = materialize(call_a, decision, store)

        received: list[BrokeredCall] = []
        # approve() accepts intent_id, approved_by, store, executor — no "new_call" param.
        approve(result.intent_id, approved_by="alice@example.com", store=store, executor=received.append)

        assert len(received) == 1
        executed = received[0]
        # The stored call_a was executed, not the attacker's call_b.
        assert executed.args == call_a.args
        assert executed.args != call_b.args

    def test_approve_returns_executed_true(self) -> None:
        """approve() returns ExecutionResult with executed=True on success."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        pending = materialize(call, decision, store)

        exec_result = approve(pending.intent_id, approved_by="bob@example.com", store=store)

        assert isinstance(exec_result, ExecutionResult)
        assert exec_result.executed is True
        assert exec_result.intent_id == pending.intent_id

    def test_approve_without_executor_succeeds(self) -> None:
        """approve() without an executor still transitions status — connector call is optional."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        pending = materialize(call, decision, store)

        exec_result = approve(pending.intent_id, approved_by="carol@example.com", store=store)

        assert exec_result.executed is True

    def test_intent_status_executed_after_approval(self) -> None:
        """After approve(), the intent status is 'executed' and approvedBy is recorded."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        pending = materialize(call, decision, store)

        approve(pending.intent_id, approved_by="dave@example.com", store=store)

        intent = store.get_intent(pending.intent_id)
        assert intent.status == "executed"
        assert intent.approvedBy == "dave@example.com"

    def test_double_approval_rejected(self) -> None:
        """A second approval attempt on the same intent is rejected (already executed)."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        pending = materialize(call, decision, store)

        first = approve(pending.intent_id, approved_by="eve@example.com", store=store)
        second = approve(pending.intent_id, approved_by="eve@example.com", store=store)

        assert first.executed is True
        assert second.executed is False
        assert second.rejection_reason is not None

    def test_executor_result_returned(self) -> None:
        """The executor's return value is propagated in ExecutionResult.result."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        pending = materialize(call, decision, store)

        exec_result = approve(
            pending.intent_id,
            approved_by="frank@example.com",
            store=store,
            executor=lambda c: {"connector_ref": "txn-42"},
        )

        assert exec_result.result == {"connector_ref": "txn-42"}


# ---------------------------------------------------------------------------
# Acceptance test 3 — Expiry: unactioned Intent TTLs; approval attempt rejected
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_expired_intent_rejects_approval(self) -> None:
        """approve() on an expired intent returns executed=False with reason 'intent expired'."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        _put_expired_intent(store, call, decision.renderedIntent.id)

        exec_result = approve(
            decision.renderedIntent.id, approved_by="grace@example.com", store=store
        )

        assert exec_result.executed is False
        assert exec_result.rejection_reason == "intent expired"

    def test_expired_intent_transitions_to_expired_status(self) -> None:
        """approve() on an expired intent transitions status from 'pending' to 'expired'."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        _put_expired_intent(store, call, decision.renderedIntent.id)

        approve(decision.renderedIntent.id, approved_by="henry@example.com", store=store)

        stored = store.get_intent(decision.renderedIntent.id)
        assert stored.status == "expired"

    def test_executor_not_called_for_expired_intent(self) -> None:
        """The executor is NOT called when an intent has expired."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        _put_expired_intent(store, call, decision.renderedIntent.id)

        executor = MagicMock()
        approve(
            decision.renderedIntent.id,
            approved_by="ivan@example.com",
            store=store,
            executor=executor,
        )

        executor.assert_not_called()

    def test_unexpired_intent_can_be_approved(self) -> None:
        """An intent with a future expiry can be approved successfully."""
        store = InMemoryIntentStore()
        call = _call()
        decision = _require_approval_decision(call)
        # materialize() sets a 1-hour expiry by default — well in the future.
        result = materialize(call, decision, store, expiry_seconds=3600)

        exec_result = approve(result.intent_id, approved_by="judy@example.com", store=store)

        assert exec_result.executed is True

    def test_approval_of_nonexistent_intent_rejected(self) -> None:
        """Approving a nonexistent intent_id returns executed=False."""
        store = InMemoryIntentStore()

        exec_result = approve(
            "intent-does-not-exist", approved_by="karen@example.com", store=store
        )

        assert exec_result.executed is False
        assert "not found" in exec_result.rejection_reason


# ---------------------------------------------------------------------------
# DynamoIntentStore import — verifies lazy boto3 doesn't break module load
# ---------------------------------------------------------------------------


def test_dynamo_intent_store_importable_without_aws() -> None:
    """DynamoIntentStore can be imported without AWS credentials."""
    from safe_agents.broker.approval.store import DynamoIntentStore

    ds = DynamoIntentStore("some-intents-table", hmac_key=b"test-hmac-key")
    assert ds._table_name == "some-intents-table"
    # DO NOT access ds._table — that triggers the lazy boto3 import
