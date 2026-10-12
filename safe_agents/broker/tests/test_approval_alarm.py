"""The approval-queue alarm under expiry, and the sweep's schedule (#163, PTC §6.12).

"Where a queue-depth alarm is raised, each approval that expires while it is raised
MUST be reported to the approver, by count at least." Pinned here:

  * the alarm gains state: raised once per op and period, cleared once every hold
    made in the flooded period has been decided or has expired;
  * each undecided expiry under it is counted and delivered to the approver, one
    delivery per op per sweep carrying the count;
  * the alarm ships OFF with Envelope.approval_queue.max_pending_per_op_day;
  * alarm machinery never gates: a failed count is named on the expiry record, a
    raising delivery is logged;
  * expiry is found on a schedule: the sweeper the broker server and the gateway
    run between requests, on the thread that owns the runtime.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging

import pytest

from safe_agents.broker.approval.engine import DEFAULT_APPROVAL_EXPIRY_SECONDS
from safe_agents.broker.approval.expiry import (
    ALARM_COUNT_WRITE_FAILED,
    ALARM_EXPIRED_SUFFIX,
    ALARM_LOG_EVENT,
    ExpirySweeper,
)
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.enforcement.store import period_bucket_of
from safe_agents.broker.gateway.sweep import SweepTask
from safe_agents.broker.schemas.envelope import ApprovalQueue
from safe_agents.broker.tests.test_approval_expiry import (
    _OWNER,
    _expiry_of,
    _hold,
    _outcomes,
    _past_due,
)
from safe_agents.broker.tests.test_runtime import _make_grant, _make_pip, _make_runtime
from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.runtime import StubConnector
from safe_agents.broker.schemas.common import AutonomyLevel

_SECOND = datetime.timedelta(seconds=1)
_WINDOW = datetime.timedelta(seconds=DEFAULT_APPROVAL_EXPIRY_SECONDS)


class _CountWriteFails(InMemoryStore):
    """An enforcement store whose alarm-expiry count write faults."""

    def try_increment_counter(self, counter_key, delta, cap):
        if counter_key.endswith(ALARM_EXPIRED_SUFFIX):
            raise RuntimeError("simulated counter-store fault")
        return super().try_increment_counter(counter_key, delta, cap)


def _runtime(cap=1, *, store=None, intent_store=None, period="utc-day", deliver=True):
    events: list = []
    runtime, sink, _ = _make_runtime(
        [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)],
        connectors={"payments": StubConnector(result={"tx_id": "tx"})},
        intent_store=intent_store if intent_store is not None else InMemoryIntentStore(),
        enforcement_store=store if store is not None else InMemoryStore(),
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        approval_queue=None if cap is None else ApprovalQueue(max_pending_per_op_day=cap),
        counter_period=period,
        on_approval_alarm=events.append if deliver else None,
    )
    return runtime, sink, runtime._intent_store, events


def _states(events):
    return [(e.state, e.new_expiries, e.expired_count) for e in events]


def _flood(runtime, holds: int) -> list[str]:
    return [_hold(runtime, amount=n + 1) for n in range(holds)]


def test_alarm_is_raised_once_per_op_and_period():
    runtime, _, _, events = _runtime(cap=1)
    _flood(runtime, 4)  # three holds past the cap
    assert _states(events) == [("raised", 0, 0)]
    assert (events[0].tool, events[0].op, events[0].cap) == ("payments", "transfer", 1)


def test_each_expiry_under_the_alarm_is_counted_and_delivered_once_per_sweep():
    runtime, sink, intent_store, events = _runtime(cap=1)
    ids = _flood(runtime, 3)
    expiry = max(_expiry_of(intent_store, i) for i in ids)

    assert runtime.sweep_expired_intents(now=expiry + _SECOND) == 3

    assert _states(events) == [("raised", 0, 0), ("expired", 3, 3)]
    assert all(r.error is None for r in _outcomes(sink, "expired"))


def test_alarm_clears_only_after_every_flooded_hold_has_settled():
    runtime, _, intent_store, events = _runtime(cap=1)
    ids = _flood(runtime, 2)
    expiry = max(_expiry_of(intent_store, i) for i in ids)
    runtime.sweep_expired_intents(now=expiry + _SECOND)
    assert [e.state for e in events] == ["raised", "expired"]  # not cleared yet

    runtime.sweep_expired_intents(now=expiry + datetime.timedelta(days=2))
    assert _states(events)[-1] == ("cleared", 0, 2)
    runtime.sweep_expired_intents(now=expiry + datetime.timedelta(days=3))
    assert [e.state for e in events].count("cleared") == 1


def test_a_hold_made_while_raised_counts_when_it_expires_in_a_later_period():
    """utc-hour: every hold expires in the NEXT period. A clear at period end would
    miss exactly the expiries the approver under a flood needs to hear about."""
    runtime, _, intent_store, events = _runtime(cap=1, period="utc-hour")
    ids = _flood(runtime, 2)
    expiry = max(_expiry_of(intent_store, i) for i in ids)
    runtime.sweep_expired_intents(now=expiry + _SECOND)
    assert _states(events) == [("raised", 0, 0), ("expired", 2, 2)]


def test_an_expiry_in_a_raised_period_counts_though_its_hold_was_made_before_it():
    """utc-hour: a hold made in hour H, under the cap, expires in hour H+1, and the
    flood is raised in H+1. The approval that mattered, made before the flood, aged
    out under it: the expiry's own period is checked, not only the hold's."""
    runtime, _, intent_store, events = _runtime(cap=5, period="utc-hour")
    intent_id = _hold(runtime)
    held_at = datetime.datetime.fromisoformat(intent_store.get_intent(intent_id).ts)
    expiry = _expiry_of(intent_store, intent_id)
    alarm = runtime._approval_alarm
    held_bucket, expired_bucket = (
        period_bucket_of(moment, "utc-hour") for moment in (held_at, expiry)
    )
    assert held_bucket != expired_bucket
    alarm.raise_for("payments", "transfer", expiry)
    assert not alarm.is_raised("payments", "transfer", held_bucket)

    runtime.sweep_expired_intents(now=expiry + _SECOND)

    expired_events = [e for e in events if e.state == "expired"]
    assert [(e.bucket, e.new_expiries, e.expired_count) for e in expired_events] == [
        (expired_bucket, 1, 1)
    ], "an expiry in a raised period was not counted because its hold was made before the raise"


def test_no_report_when_the_alarm_was_never_raised():
    runtime, sink, intent_store, events = _runtime(cap=5)
    ids = _flood(runtime, 2)  # under the cap
    runtime.sweep_expired_intents(now=max(_expiry_of(intent_store, i) for i in ids) + _SECOND)
    assert events == []
    assert len(_outcomes(sink, "expired")) == 2


def test_alarm_ships_off_with_the_knob():
    runtime, sink, intent_store, events = _runtime(cap=None)
    ids = _flood(runtime, 4)
    runtime.sweep_expired_intents(now=max(_expiry_of(intent_store, i) for i in ids) + _SECOND)
    assert runtime._approval_alarm is None
    assert events == []
    assert len(_outcomes(sink, "expired")) == 4


def test_late_approval_under_the_alarm_is_counted_and_delivered():
    runtime, sink, intent_store, events = _runtime(cap=1)
    _flood(runtime, 2)
    late = _past_due(intent_store)
    # Its hold instant is two hours back; mark that period flooded the way a
    # flood two hours ago would have.
    runtime._approval_alarm.raise_for(
        "payments", "transfer", datetime.datetime.fromisoformat(late.ts)
    )
    runtime.approve_intent(late.id, approved_by=_OWNER)
    expired_events = [e for e in events if e.state == "expired"]
    assert [(e.new_expiries, e.expired_count) for e in expired_events] == [(1, 1)]
    assert len(_outcomes(sink, "expired")) == 1


def test_a_restarted_runtime_still_counts_under_a_raised_alarm():
    store, intents = InMemoryStore(), InMemoryIntentStore()
    first, _, _, _ = _runtime(cap=1, store=store, intent_store=intents)
    ids = _flood(first, 2)
    second, _, _, events = _runtime(cap=1, store=store, intent_store=intents)
    expiry = max(_expiry_of(intents, i) for i in ids)
    second.sweep_expired_intents(now=expiry + _SECOND)
    assert _states(events) == [("expired", 2, 2)]
    second.sweep_expired_intents(now=expiry + datetime.timedelta(days=2))
    assert _states(events)[-1] == ("cleared", 0, 2)


def test_a_failed_count_is_named_on_the_record_and_never_gates():
    runtime, sink, intent_store, events = _runtime(cap=1, store=_CountWriteFails())
    ids = _flood(runtime, 2)
    assert runtime.sweep_expired_intents(
        now=max(_expiry_of(intent_store, i) for i in ids) + _SECOND
    ) == 2
    records = _outcomes(sink, "expired")
    assert [r.error for r in records] == [ALARM_COUNT_WRITE_FAILED] * 2
    assert [e.state for e in events] == ["raised"]


def test_a_raising_delivery_never_gates_the_sweep(caplog):
    runtime, sink, intent_store, _ = _runtime(cap=1, deliver=False)

    def _boom(_event):
        raise RuntimeError("approver channel down")

    runtime._approval_alarm._deliver = _boom
    ids = _flood(runtime, 2)
    with caplog.at_level(logging.ERROR):
        recorded = runtime.sweep_expired_intents(
            now=max(_expiry_of(intent_store, i) for i in ids) + _SECOND
        )
    assert recorded == 2 and len(_outcomes(sink, "expired")) == 2
    lines = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert {"raised", "expired"} <= {
        line["state"] for line in lines if line.get("event") == ALARM_LOG_EVENT
    }


# ---------------------------------------------------------------------------
# The schedule
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_sweeper_runs_first_then_once_per_interval_and_survives_a_fault():
    clock, calls = _Clock(), []

    def sweep() -> int:
        calls.append(clock.now)
        if len(calls) == 2:
            raise RuntimeError("store unavailable")
        return 0

    sweeper = ExpirySweeper(sweep, interval_seconds=60, clock=clock)
    assert sweeper.maybe_sweep() == 0  # immediately: expiries from downtime
    assert sweeper.maybe_sweep() is None
    clock.now += 59.9
    assert sweeper.maybe_sweep() is None
    clock.now += 0.1
    assert sweeper.maybe_sweep() is None  # ran, raised, logged
    clock.now += 60
    assert sweeper.maybe_sweep() == 0
    assert len(calls) == 3


def test_broker_server_sweeps_from_its_serving_loop():
    from safe_agents.broker.prototype.broker_server import _Handler, _SweepingHTTPServer

    calls: list[int] = []
    sweeper = ExpirySweeper(lambda: calls.append(1) or 0, interval_seconds=60)
    srv = _SweepingHTTPServer(("127.0.0.1", 0), _Handler, sweeper=sweeper)
    try:
        srv.service_actions()
        srv.service_actions()
    finally:
        srv.server_close()
    assert calls == [1]


def test_gateway_sweep_task_sweeps_through_the_serialized_surface_and_stops():
    from safe_agents.broker.gateway.network import SerializedSurface

    class _Surface:
        server_name = "t"

        def __init__(self) -> None:
            self.sweeps = 0

        def sweep_expired_intents(self) -> int:
            self.sweeps += 1
            task.request_stop()
            return 0

    surface = _Surface()
    task = SweepTask(SerializedSurface(surface), interval_seconds=30)
    asyncio.run(asyncio.wait_for(task.serve(), timeout=5))
    assert surface.sweeps == 1


@pytest.mark.parametrize("interval", [0, -1])
def test_sweeper_refuses_a_non_positive_interval(interval):
    with pytest.raises(ValueError):
        ExpirySweeper(lambda: 0, interval_seconds=interval)


def test_window_constant_matches_the_alarm_hold_window():
    runtime, _, _, _ = _runtime(cap=1)
    assert runtime._approval_alarm._hold_window == _WINDOW
