"""Boundary-carry unit tests over the two base time mechanisms (sa#213):

  - ``period_bucket_of`` (safe_agents/broker/enforcement/store.py) — the one
    derivation of a period-bucket key from an aware datetime.
  - ``read_counter_window`` — the bounded loop of bucket keys walked backward
    from an anchor.

Nasty instants (leap day, month-end, year edge, exact-midnight) exercise the
ONE derivation directly, with fixed inputs throughout — no wall-clock reads.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.enforcement import (
    OBSERVATIONS_SUFFIX,
    UNBOUNDED_COUNTER_CAP,
    InMemoryStore,
    read_counter_window,
    scoped_counter_key,
)
from safe_agents.broker.enforcement.store import period_bucket_of
from safe_agents.broker.schemas.common import Principal

PRINCIPAL = Principal(agentId="agent-1", skill="digest", user="maintainer", tier="B")

UTC = datetime.UTC


def _dt(*args, **kwargs) -> datetime.datetime:
    return datetime.datetime(*args, tzinfo=UTC, **kwargs)


# ---------------------------------------------------------------------------
# Class A(a) — period_bucket_of at nasty instants, both periods
# ---------------------------------------------------------------------------


class TestPeriodBucketOfNastyInstants:
    """One derivation, one table: every entry names an instant that has broken
    a hand-rolled date/time calculation somewhere before (leap day, month-end,
    year rollover, the midnight boundary itself)."""

    LEAP_DAY = _dt(2024, 2, 29, 12, 0, 0)
    MONTH_END = _dt(2026, 1, 31, 23, 0, 0)
    NEXT_DAY_AFTER_MONTH_END = _dt(2026, 2, 1, 1, 0, 0)
    YEAR_EDGE_BEFORE = _dt(2026, 12, 31, 23, 59, 59)
    YEAR_EDGE_AFTER = _dt(2027, 1, 1, 0, 0, 0)
    EXACT_MIDNIGHT = _dt(2026, 7, 16, 0, 0, 0)

    @pytest.mark.parametrize(
        ("moment", "period", "expected"),
        [
            (LEAP_DAY, "utc-day", "20240229"),
            (LEAP_DAY, "utc-hour", "20240229T12"),
            (MONTH_END, "utc-day", "20260131"),
            (MONTH_END, "utc-hour", "20260131T23"),
            (NEXT_DAY_AFTER_MONTH_END, "utc-day", "20260201"),
            (NEXT_DAY_AFTER_MONTH_END, "utc-hour", "20260201T01"),
            (YEAR_EDGE_BEFORE, "utc-day", "20261231"),
            (YEAR_EDGE_BEFORE, "utc-hour", "20261231T23"),
            (YEAR_EDGE_AFTER, "utc-day", "20270101"),
            (YEAR_EDGE_AFTER, "utc-hour", "20270101T00"),
            # Exact midnight belongs to the NEW day bucket, not the prior one.
            (EXACT_MIDNIGHT, "utc-day", "20260716"),
            (EXACT_MIDNIGHT, "utc-hour", "20260716T00"),
        ],
    )
    def test_bucket_at_boundary(
        self, moment: datetime.datetime, period: str, expected: str
    ) -> None:
        assert period_bucket_of(moment, period) == expected

    def test_non_utc_tz_aware_input_renders_utc_bucket(self) -> None:
        # 2026-07-16T02:30+05:30 is 2026-07-15T21:00 UTC — a naive port of this
        # mechanism (formatting the local wall-clock fields) would emit the
        # WRONG day/hour bucket. astimezone(UTC) inside period_bucket_of is
        # what makes this render the UTC bucket regardless of input offset.
        plus_530 = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        moment = datetime.datetime(2026, 7, 16, 2, 30, 0, tzinfo=plus_530)
        assert period_bucket_of(moment, "utc-day") == "20260715"
        assert period_bucket_of(moment, "utc-hour") == "20260715T21"

    def test_midnight_boundary_belongs_to_new_bucket_not_prior(self) -> None:
        one_second_before = _dt(2026, 7, 15, 23, 59, 59)
        assert period_bucket_of(one_second_before, "utc-day") == "20260715"
        assert period_bucket_of(self.EXACT_MIDNIGHT, "utc-day") == "20260716"


# ---------------------------------------------------------------------------
# Class A(b) — window stepping across month/year edges, absolute timedelta
# ---------------------------------------------------------------------------


class TestWindowSteppingAcrossEdges:
    """read_counter_window walks (anchor - offset*step) for offset in
    range(window_periods) — an absolute-timedelta step, never a calendar-aware
    "previous month" calculation. These pin that arithmetic across a month AND
    a year boundary for both periods."""

    def test_day_window_of_three_anchored_new_year_covers_both_sides(self) -> None:
        store = InMemoryStore()
        for bucket, value in [
            ("20270101", 1.0),
            ("20261231", 10.0),
            ("20261230", 100.0),
            ("20261229", 1000.0),  # offset 3 — outside a window of 3
        ]:
            key = scoped_counter_key(
                PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket=bucket
            )
            assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 3,
            anchor_bucket="20270101",
        )
        assert total == 111.0

    def test_hour_window_across_midnight_covers_both_days(self) -> None:
        store = InMemoryStore()
        for bucket, value in [
            ("20260716T00", 1.0),
            ("20260715T23", 10.0),
            ("20260715T22", 100.0),  # offset 2 — outside a window of 2
        ]:
            key = scoped_counter_key(
                PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX,
                period="utc-hour", bucket=bucket,
            )
            assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 2,
            period="utc-hour", anchor_bucket="20260716T00",
        )
        assert total == 11.0

    def test_day_window_across_month_end_covers_both_sides(self) -> None:
        store = InMemoryStore()
        for bucket, value in [
            ("20260201", 1.0),
            ("20260131", 10.0),
            ("20260130", 100.0),  # offset 2 — outside a window of 2
        ]:
            key = scoped_counter_key(
                PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket=bucket
            )
            assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 2,
            anchor_bucket="20260201",
        )
        assert total == 11.0

    def test_bucket_enumeration_arithmetic_matches_absolute_timedelta(self) -> None:
        # Direct pin on the enumeration itself (offset in range(window_periods),
        # bucket = (anchor - offset*step)), independent of the store — the
        # arithmetic read_counter_window performs internally.
        anchor = datetime.datetime.strptime("20270101", "%Y%m%d")
        step = datetime.timedelta(days=1)
        buckets = [(anchor - offset * step).strftime("%Y%m%d") for offset in range(3)]
        assert buckets == ["20270101", "20261231", "20261230"]

        anchor_hour = datetime.datetime.strptime("20260716T00", "%Y%m%dT%H")
        step_hour = datetime.timedelta(hours=1)
        hour_buckets = [
            (anchor_hour - offset * step_hour).strftime("%Y%m%dT%H") for offset in range(2)
        ]
        assert hour_buckets == ["20260716T00", "20260715T23"]


# ---------------------------------------------------------------------------
# Class D — window semantics: anchor-inclusive, never a future bucket
# ---------------------------------------------------------------------------


class TestWindowSemanticsAnchorInclusive:
    """window_periods=1 reads exactly the anchor bucket; window_periods=N reads
    anchor + (N-1) prior periods — never a future bucket (offset never goes
    negative in the enumeration)."""

    def test_window_of_one_reads_exactly_anchor_bucket(self) -> None:
        store = InMemoryStore()
        anchor_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket="20260716"
        )
        future_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket="20260717"
        )
        assert store.try_increment_counter(anchor_key, 5.0, UNBOUNDED_COUNTER_CAP)
        assert store.try_increment_counter(future_key, 999.0, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 1,
            anchor_bucket="20260716",
        )
        assert total == 5.0

    def test_window_of_n_reads_anchor_plus_n_minus_one_prior(self) -> None:
        store = InMemoryStore()
        for bucket, value in [
            ("20260716", 1.0),
            ("20260715", 2.0),
            ("20260714", 4.0),
            ("20260713", 8.0),  # offset 3 — outside window_periods=3 (offsets 0,1,2)
        ]:
            key = scoped_counter_key(
                PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket=bucket
            )
            assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 3,
            anchor_bucket="20260716",
        )
        assert total == 7.0  # 1 + 2 + 4, never the offset-3 row

    def test_window_never_reads_a_future_bucket(self) -> None:
        store = InMemoryStore()
        future_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bucket="20260717"
        )
        assert store.try_increment_counter(future_key, 42.0, UNBOUNDED_COUNTER_CAP)
        total = read_counter_window(
            store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 366,
            anchor_bucket="20260716",
        )
        assert total == 0.0
