"""Approval expiry is judged at an EXPLICIT evaluation instant, never a record's own.

An implementer reviewing delegated-authority resolvers found expiry judged
against an instant nobody supplied: "now" read from somewhere implicit. The
engine's rule is that the evaluation instant is an input. approve(), reject()
and materialize() each take ``now`` and fall back to the wall clock only when a
caller omits it; nothing inside derives "now" from the intent's ``ts``, its
``expiry``, or any other stored record, because a record's timestamps are
claims its writer chose.

These tests pin both halves:

* the verdict follows the explicit instant, in both directions, and does so
  whether the hold sits in the wall-clock past or future (so a silent fallback
  to the wall clock goes red in one of the two parametrizations);
* record timestamps do not move it: an intent whose ``ts`` postdates its expiry,
  and a store full of later records, still release at an instant before expiry,
  and an intent whose ``ts`` predates its expiry still expires at an instant
  after it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
from unittest.mock import MagicMock

import pytest

from safe_agents.broker.approval import (
    InMemoryIntentStore,
    approve,
    materialize,
    reject,
)
from safe_agents.broker.approval.engine import REJECTED_BY_OWNER_REASON
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.schemas.common import AutonomyLevel

_EXPIRY_SECONDS = 60
# One hold instant far in the wall-clock past, one far in the future: an engine
# that ignored ``now`` and read the wall clock would get one of them wrong.
_HOLD_INSTANTS = [
    pytest.param(datetime(2020, 1, 1, tzinfo=timezone.utc), id="hold-in-past"),
    pytest.param(datetime(2100, 1, 1, tzinfo=timezone.utc), id="hold-in-future"),
]
_EXPIRED = "intent expired"


def _call(turn: str = "turn-instant") -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": {"agentId": "agent-1", "skill": "finance", "user": "alice", "tier": "B"},
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 100, "to": "acct-xyz"},
            "manifest": {
                "tool": "payments",
                "op": "transfer",
                "effect": "write",
                "external": True,
                "reversible": False,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": turn, "ingestedSources": []},
            "ts": "2026-06-28T00:00:00Z",
        }
    )


def _hold(store: InMemoryIntentStore, hold_at: datetime) -> str:
    call = _call()
    facts = Facts(
        grant_present=True,
        grant_level=AutonomyLevel.in_loop,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=True,
        human_reachable=True,
        transform_op=None,
    )
    decision = decide(call, facts)
    assert decision.kind == "require_approval"
    return materialize(
        call, decision, store, expiry_seconds=_EXPIRY_SECONDS, now=hold_at
    ).intent_id


def _put(store: InMemoryIntentStore, intent_id: str, *, expiry: datetime, ts: datetime) -> None:
    """Write a pending intent with chosen record timestamps (bypasses materialize())."""
    store.put_intent(
        Intent(
            id=intent_id,
            materializedRequest=_call(turn=intent_id),
            renderedForHuman="instant test",
            status="pending",
            expiry=expiry.isoformat(),
            approvedBy=None,
            ts=ts.isoformat(),
        )
    )


def _approve(store: InMemoryIntentStore, intent_id: str, now: datetime):
    executor = MagicMock(return_value="ran")
    result = approve(intent_id, "owner@example.com", store, executor=executor, now=now)
    return result, executor


def _reject(store: InMemoryIntentStore, intent_id: str, now: datetime):
    return reject(intent_id, "owner@example.com", store, now=now), None


_ACTIONS: list = [
    pytest.param(_approve, id="approve"),
    pytest.param(_reject, id="reject"),
]


def _released(action: Callable, result) -> bool:
    """Did the action take effect (not refused as expired)?"""
    if action is _approve:
        return result.executed is True
    return result.rejection_reason == REJECTED_BY_OWNER_REASON


@pytest.mark.parametrize("hold_at", _HOLD_INSTANTS)
def test_materialize_stamps_ts_and_expiry_from_the_explicit_instant(hold_at: datetime) -> None:
    store = InMemoryIntentStore()
    intent = store.get_intent(_hold(store, hold_at))
    assert datetime.fromisoformat(intent.ts) == hold_at
    assert datetime.fromisoformat(intent.expiry) == hold_at + timedelta(seconds=_EXPIRY_SECONDS)


@pytest.mark.parametrize("action", _ACTIONS)
@pytest.mark.parametrize("hold_at", _HOLD_INSTANTS)
def test_expiry_verdict_follows_the_explicit_instant(action: Callable, hold_at: datetime) -> None:
    """Past expiry with no other activity refuses as expired; before it, the action lands."""
    expires_at = hold_at + timedelta(seconds=_EXPIRY_SECONDS)

    late = InMemoryIntentStore()
    late_id = _hold(late, hold_at)
    result, executor = action(late, late_id, expires_at + timedelta(seconds=1))
    assert result.rejection_reason == _EXPIRED
    assert late.get_intent(late_id).status == "expired"
    if executor is not None:
        executor.assert_not_called()

    # Exact equality is expired too (the boundary is inclusive).
    edge = InMemoryIntentStore()
    edge_id = _hold(edge, hold_at)
    assert action(edge, edge_id, expires_at)[0].rejection_reason == _EXPIRED

    early = InMemoryIntentStore()
    early_id = _hold(early, hold_at)
    result, executor = action(early, early_id, expires_at - timedelta(seconds=1))
    assert _released(action, result), result
    if executor is not None:
        executor.assert_called_once()


@pytest.mark.parametrize("action", _ACTIONS)
def test_record_timestamps_do_not_move_the_verdict(action: Callable) -> None:
    """The intent's own ts, and every other record's, are not the evaluation instant.

    ``post_dated`` claims to have been written a day AFTER it expired, and the
    store holds other records later still; judged at an instant before expiry it
    must still land. ``back_dated`` claims a ts a day before expiry; judged at an
    instant after expiry it must still refuse. An engine that took "now" from the
    intent's ts, or from the latest record, fails one of the two.
    """
    expiry = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
    store = InMemoryIntentStore()
    _put(store, "post_dated", expiry=expiry, ts=expiry + timedelta(days=1))
    _put(store, "back_dated", expiry=expiry, ts=expiry - timedelta(days=1))
    for n in range(3):
        _put(
            store,
            f"later-{n}",
            expiry=expiry + timedelta(days=30),
            ts=expiry + timedelta(days=2 + n),
        )

    result, _ = action(store, "post_dated", expiry - timedelta(seconds=1))
    assert _released(action, result), result

    result, _ = action(store, "back_dated", expiry + timedelta(seconds=1))
    assert result.rejection_reason == _EXPIRED
    assert store.get_intent("back_dated").status == "expired"

    # The bystander records were read by nobody and moved nowhere.
    assert {store.get_intent(f"later-{n}").status for n in range(3)} == {"pending"}
