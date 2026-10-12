"""broker.approval.expiry — an approval that expires undecided is an event (#163).

PTC §6.12: a held approval MAY expire, its expiry period MUST NOT shorten as the
queue grows, an expiry with no human decision MUST be recorded as expired and be
told apart from a human denial, it MUST NOT count as a human decision in any
evidence the grant lifecycle reads, and while a queue-depth alarm is raised each
expiry MUST be reported to the approver, by count at least.

The runtime (``runtime/pep.py``) owns the record and the sweep. This module holds
the two pieces that are not the record:

  * ``ApprovalQueueAlarm`` — the flood alarm's raised and cleared state, the count
    of expiries while it is raised, and the delivery of both to the approver. It
    exists only when ``Envelope.approval_queue.max_pending_per_op_day`` is set, so
    it ships OFF with that knob.
  * ``ExpirySweeper`` — the schedule a long-lived host runs the runtime's sweep
    on, so expiry is found by a sweep rather than discovered on the next touch.

What this buys and no more: an undecided hold leaves a distinct record, and an
approver under a flood learns how many holds aged out. It does not pause or extend
expiry (approving a stale request is its own harm), it never executes an expired
intent, and whether an expiry should trigger anything further is a per-agent
question that stays out of the base.
"""

from __future__ import annotations

import datetime
import json
import logging
import time
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Literal

from safe_agents.broker.enforcement.store import (
    UNBOUNDED_COUNTER_CAP,
    period_bucket_of,
    scoped_counter_key,
)

if TYPE_CHECKING:
    from safe_agents.broker.enforcement.store import EnforcementStore
    from safe_agents.broker.schemas.common import CounterPeriod, Principal

logger = logging.getLogger(__name__)

# The reason on an expiry's audit record. Never REJECTED_BY_OWNER_REASON and never
# a deny reason: no person decided anything.
APPROVAL_EXPIRED_REASON = "approval expired undecided"

# The `error` on an expiry record whose alarm count write failed. The expiry is
# recorded anyway; the record says the count did not land (log, never gate).
ALARM_COUNT_WRITE_FAILED = "approval alarm count write failed"

# Counter suffixes for the alarm. Deliberately not any evidence suffix the
# promotion predicate reads (observations, human_override, false_action): an
# expiry is no human decision and must not move that evidence.
ALARM_RAISED_SUFFIX = "approval_alarm_raised"
ALARM_EXPIRED_SUFFIX = "approval_alarm_expired"

# A one-shot marker: the first raise in a period wins 0 -> 1, later raises refuse.
_RAISED_MARKER_CAP = 1.0

# The structured log line every delivery also writes (the log-metric surface, the
# approval_queue_flood precedent). A separate event name, so readers of the flood
# line are unchanged.
ALARM_LOG_EVENT = "approval_queue_alarm"

# How often a long-lived host sweeps for expired holds. An expiry is recorded at
# most this long after it happens.
DEFAULT_SWEEP_INTERVAL_SECONDS = 60.0

AlarmState = Literal["raised", "expired", "cleared"]


@dataclass(frozen=True)
class ApprovalAlarmEvent:
    """One delivery to the approver about the approval-queue alarm.

    ``raised``  — new holds for this op passed the cap in counter period ``bucket``.
    ``expired`` — ``new_expiries`` holds for this op expired undecided while the
                  alarm was raised; ``expired_count`` is the running total in
                  ``bucket``. One delivery per op per sweep, never one per hold, so
                  a flood of expiries does not become a flood of messages.
    ``cleared`` — every hold made in ``bucket`` has been decided or has expired,
                  so the alarm is no longer raised; ``expired_count`` is the total
                  that expired undecided under it.

    PII-safe by construction: the principal's agent id, the op and counts.
    """

    state: AlarmState
    agent_id: str
    tool: str
    op: str
    bucket: str
    cap: int
    expired_count: int = 0
    new_expiries: int = 0


class ApprovalQueueAlarm:
    """Raised and cleared state for the approval-queue flood alarm, per op.

    RAISED: once new holds for an op pass the cap in a counter period (the window
    the flood counter itself counts in). The raise is a one-shot marker per op and
    period in the enforcement store, so a restarted broker still knows it.

    CLEARED: once that period has ended AND one hold window has passed after it,
    so every hold made in the flooded period has been decided or has expired. A
    period-end clear alone would be wrong: a hold made late in the flooded period
    expires in the next one, and that is exactly the expiry an approver under a
    flood must hear about.

    COUNTED: an undecided expiry is counted under the alarm when the alarm was
    raised in the period its hold was made in, or in the period it expired in.
    That can include an expiry earlier in a flooded period than the raise itself;
    the clause asks for a report by count AT LEAST, and the over-count is toward
    telling the approver more.

    The set of alarms this process has seen raised is kept in memory only to
    notice a clear; a broker restarted after a raise reports the clear once it has
    counted an expiry under that alarm.

    Every store write and delivery here is guarded: alarm machinery never gates a
    hold, an expiry, or a sweep. A failed write is logged, and the expiry record
    names it in ``error``.
    """

    def __init__(
        self,
        *,
        principal: "Principal",
        store: "EnforcementStore",
        cap: int,
        period: "CounterPeriod",
        hold_window_seconds: int,
        deliver: Callable[[ApprovalAlarmEvent], None] | None = None,
    ) -> None:
        self._hold_window = datetime.timedelta(seconds=hold_window_seconds)
        self._principal = principal
        self._store = store
        self._cap = cap
        self._period = period
        self._deliver = deliver
        # (tool, op) -> the bucket its alarm was raised in, as seen by this process.
        self._raised: dict[tuple[str, str], str] = {}
        # (tool, op, bucket) -> expiries counted since the last delivery.
        self._unreported: Counter[tuple[str, str, str]] = Counter()

    def _key(self, tool: str, op: str, suffix: str, bucket: str) -> str:
        return scoped_counter_key(
            self._principal, tool, op, suffix, period=self._period, bucket=bucket
        )

    def raise_for(self, tool: str, op: str, at: datetime.datetime) -> None:
        """A hold for ``tool.op`` passed the cap at ``at``: raise the alarm."""
        bucket = period_bucket_of(at, self._period)
        try:
            first = self._store.try_increment_counter(
                self._key(tool, op, ALARM_RAISED_SUFFIX, bucket), 1.0, _RAISED_MARKER_CAP
            )
        except Exception:  # noqa: BLE001 — alarm state must never gate the hold
            logger.warning(
                "approval alarm raise marker write failed for %s.%s", tool, op, exc_info=True
            )
            return
        self._raised[(tool, op)] = bucket
        if first:
            self._send(ApprovalAlarmEvent("raised", self._principal.agentId, tool, op, bucket, self._cap))

    def is_raised(self, tool: str, op: str, bucket: str) -> bool:
        """True when the alarm for ``tool.op`` was raised in ``bucket`` (durable read)."""
        return self._store.read_counter(self._key(tool, op, ALARM_RAISED_SUFFIX, bucket)) >= 1

    def count_expiry(
        self,
        tool: str,
        op: str,
        *,
        held_at: datetime.datetime,
        expired_at: datetime.datetime,
    ) -> bool:
        """Count one undecided expiry if the alarm was raised when it was held or expired.

        Judged on the hold's and the expiry's own instants (from the verified
        intent), never on when the sweep happens to run. Returns False only when a
        store read or write failed; the caller records that on the expiry record.
        Raises nothing.
        """
        try:
            bucket = None
            for moment in (held_at, expired_at):
                candidate = period_bucket_of(moment, self._period)
                if self.is_raised(tool, op, candidate):
                    bucket = candidate
                    break
            if bucket is None:
                return True
            self._store.try_increment_counter(
                self._key(tool, op, ALARM_EXPIRED_SUFFIX, bucket), 1.0, UNBOUNDED_COUNTER_CAP
            )
        except Exception:  # noqa: BLE001 — a count must never gate the expiry it counts
            logger.warning(
                "approval alarm expiry count failed for %s.%s", tool, op, exc_info=True
            )
            return False
        self._raised.setdefault((tool, op), bucket)
        self._unreported[(tool, op, bucket)] += 1
        return True

    def flush(self, now: datetime.datetime) -> None:
        """Deliver the expiry counts gathered since the last flush, then any clears."""
        pending, self._unreported = self._unreported, Counter()
        for (tool, op, bucket), new in sorted(pending.items()):
            total = self._read_total(tool, op, bucket, fallback=new)
            self._send(ApprovalAlarmEvent(
                "expired", self._principal.agentId, tool, op, bucket, self._cap,
                expired_count=total, new_expiries=new,
            ))
        # Buckets are fixed-width UTC timestamps, so string order is time order.
        settled = period_bucket_of(now - self._hold_window, self._period)
        for (tool, op), bucket in sorted(self._raised.items()):
            if not settled > bucket:
                continue
            del self._raised[(tool, op)]
            total = self._read_total(tool, op, bucket, fallback=0)
            self._send(ApprovalAlarmEvent(
                "cleared", self._principal.agentId, tool, op, bucket, self._cap,
                expired_count=total,
            ))

    def _read_total(self, tool: str, op: str, bucket: str, *, fallback: int) -> int:
        try:
            return int(self._store.read_counter(self._key(tool, op, ALARM_EXPIRED_SUFFIX, bucket)))
        except Exception:  # noqa: BLE001 — report what is known rather than nothing
            logger.warning("approval alarm count read failed for %s.%s", tool, op, exc_info=True)
            return fallback

    def _send(self, event: ApprovalAlarmEvent) -> None:
        logger.error(json.dumps({
            "event": ALARM_LOG_EVENT,
            "state": event.state,
            "agentId": event.agent_id,
            "op": f"{event.tool}.{event.op}",
            "bucket": event.bucket,
            "cap": event.cap,
            "expired": event.expired_count,
            "newExpiries": event.new_expiries,
        }))
        if self._deliver is None:
            return
        try:
            self._deliver(event)
        except Exception:  # noqa: BLE001 — a delivery fault never gates the broker
            logger.exception("approval alarm delivery raised; the broker continues")


class ExpirySweeper:
    """Run a sweep at most once per interval; the first call sweeps immediately.

    A host calls ``maybe_sweep()`` from its own serving loop, on the thread that
    owns the runtime, so the sweep is serialized with every call exactly as a
    request is. A failed sweep is logged and retried on the next interval: expiry
    is still a predicate at use, so a missed pass delays a record and never lets an
    expired intent execute.
    """

    def __init__(
        self,
        sweep: Callable[[], int],
        *,
        interval_seconds: float = DEFAULT_SWEEP_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._sweep = sweep
        self._interval = interval_seconds
        self._clock = clock
        self._last: float | None = None

    @property
    def interval_seconds(self) -> float:
        return self._interval

    def due(self) -> bool:
        return self._last is None or self._clock() - self._last >= self._interval

    def maybe_sweep(self) -> int | None:
        """Sweep if an interval has passed; the count recorded, or None when not run."""
        if not self.due():
            return None
        self._last = self._clock()
        try:
            return self._sweep()
        except Exception:  # noqa: BLE001 — a sweep fault never takes the host down
            logger.warning("expired-approval sweep failed; retrying next interval", exc_info=True)
            return None
