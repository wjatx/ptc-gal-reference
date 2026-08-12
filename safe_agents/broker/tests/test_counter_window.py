"""Multi-period evidence-window reads on the scoped counter seam (#193, #212).

Before #193, read_counter was a single-period point read, so a ceremony
``window_n`` silently meant "the current period only". read_counter_window walks
the bucket-keyed coordinates so ``min_observations`` means what it says. #212
generalized the bucket from UTC-day to a manifest-named period; the utc-day
default must stay byte-for-byte the pre-#212 key.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.enforcement import (
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    UNBOUNDED_COUNTER_CAP,
    InMemoryStore,
    current_period_bucket,
    current_utc_day,
    period_step,
    read_counter_window,
    scoped_counter_key,
)
from safe_agents.broker.enforcement.store import (
    MAX_WINDOW_DAYS,
    MAX_WINDOW_PERIODS,
    period_bucket_of,
)
from safe_agents.broker.schemas.common import Principal

PRINCIPAL = Principal(agentId="agent-1", skill="digest", user="maintainer", tier="B")

# One anchor per test run, so seeds and reads always agree on "today" even if
# the UTC day rolls over mid-test (the review's midnight-flake finding).
ANCHOR = current_utc_day()


def _day(offset: int) -> str:
    anchor_date = datetime.datetime.strptime(ANCHOR, "%Y%m%d").date()
    return (anchor_date - datetime.timedelta(days=offset)).strftime("%Y%m%d")


def _seed(store: InMemoryStore, suffix: str, day_offset: int, value: float) -> None:
    key = scoped_counter_key(
        PRINCIPAL, "notify", "send", suffix, day=_day(day_offset)
    )
    assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)


def _window(store: InMemoryStore, suffix: str, days: int) -> float:
    return read_counter_window(
        store, PRINCIPAL, "notify", "send", suffix, days, anchor_bucket=ANCHOR
    )


class TestScopedCounterKeyDayParam:
    def test_explicit_day_lands_in_key(self) -> None:
        key = scoped_counter_key(PRINCIPAL, "notify", "send", "counter", day="20260101")
        assert ":20260101:" in key

    def test_default_day_matches_current_utc_day_derivation(self) -> None:
        # Compare against an explicit-day key rather than parsing: the two
        # derivations must be the same function of the same clock.
        now_day = current_utc_day()
        assert scoped_counter_key(
            PRINCIPAL, "notify", "send", "counter", day=now_day
        ) == scoped_counter_key(PRINCIPAL, "notify", "send", "counter")

    @pytest.mark.parametrize("bad_day", ["", "2026-01-01", "202601", "yyyymmdd"])
    def test_malformed_day_raises(self, bad_day: str) -> None:
        with pytest.raises(ValueError, match="YYYYMMDD"):
            scoped_counter_key(PRINCIPAL, "notify", "send", "counter", day=bad_day)


class TestReadCounterWindow:
    def test_single_day_window_matches_point_read(self) -> None:
        store = InMemoryStore()
        _seed(store, OBSERVATIONS_SUFFIX, 0, 3.0)
        _seed(store, OBSERVATIONS_SUFFIX, 1, 5.0)  # yesterday — outside window
        assert _window(store, OBSERVATIONS_SUFFIX, 1) == 3.0

    def test_window_sums_across_days_and_excludes_older(self) -> None:
        store = InMemoryStore()
        _seed(store, OBSERVATIONS_SUFFIX, 0, 1.0)
        _seed(store, OBSERVATIONS_SUFFIX, 3, 10.0)
        _seed(store, OBSERVATIONS_SUFFIX, 6, 100.0)
        _seed(store, OBSERVATIONS_SUFFIX, 7, 1000.0)  # day 8 — outside a 7-day window
        assert _window(store, OBSERVATIONS_SUFFIX, 7) == 111.0

    def test_suffixes_are_independent_coordinates(self) -> None:
        store = InMemoryStore()
        _seed(store, OBSERVATIONS_SUFFIX, 0, 4.0)
        _seed(store, HUMAN_OVERRIDE_SUFFIX, 0, 1.0)
        assert _window(store, HUMAN_OVERRIDE_SUFFIX, 7) == 1.0

    def test_empty_window_reads_zero(self) -> None:
        assert _window(InMemoryStore(), OBSERVATIONS_SUFFIX, 14) == 0.0

    def test_default_anchor_is_today(self) -> None:
        store = InMemoryStore()
        # Seed under the current UTC day WITHOUT an explicit day, read with the
        # default anchor: the sub-second midnight race here is negligible and
        # this guards the writer-side default coordinate.
        key = scoped_counter_key(PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX)
        assert store.try_increment_counter(key, 2.0, UNBOUNDED_COUNTER_CAP)
        assert (
            read_counter_window(
                store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 2
            )
            == 2.0
        )

    @pytest.mark.parametrize("bad_days", [0, -1, MAX_WINDOW_DAYS + 1])
    def test_out_of_range_window_raises(self, bad_days: int) -> None:
        with pytest.raises(ValueError, match="window_periods"):
            read_counter_window(
                InMemoryStore(), PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, bad_days
            )


class TestCounterPeriods:
    """#212 — the time-scale knob on the one key derivation."""

    def test_day_default_is_byte_for_byte_pre_212(self) -> None:
        # THE back-compat invariant: the default (period unset) key is exactly
        # the historical format — existing table rows keep reading.
        key = scoped_counter_key(PRINCIPAL, "notify", "send", "counter", day="20260101")
        assert key == "agent-1#digest#maintainer#B:notify.send:20260101:counter"
        assert key == scoped_counter_key(
            PRINCIPAL, "notify", "send", "counter", period="utc-day", bucket="20260101"
        )

    def test_hour_bucket_carries_T_and_is_disjoint_from_day(self) -> None:
        hour_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", "counter", period="utc-hour",
            bucket="20260101T05",
        )
        assert ":20260101T05:" in hour_key
        day_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", "counter", day="20260101"
        )
        assert hour_key != day_key  # period-in-key: the formats are disjoint

    def test_hour_window_walks_across_a_day_boundary(self) -> None:
        store = InMemoryStore()
        for bucket, value in [("20260102T01", 1.0), ("20260102T00", 10.0), ("20260101T23", 100.0)]:
            key = scoped_counter_key(
                PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX,
                period="utc-hour", bucket=bucket,
            )
            assert store.try_increment_counter(key, value, UNBOUNDED_COUNTER_CAP)
        assert (
            read_counter_window(
                store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 3,
                period="utc-hour", anchor_bucket="20260102T01",
            )
            == 111.0
        )

    def test_period_mismatch_reads_zero_never_wrong_sum(self) -> None:
        # Evidence written at day period is INVISIBLE to an hour-period read —
        # failing toward less authority, never a wrong sum.
        store = InMemoryStore()
        day_key = scoped_counter_key(
            PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, day="20260101"
        )
        assert store.try_increment_counter(day_key, 5.0, UNBOUNDED_COUNTER_CAP)
        assert (
            read_counter_window(
                store, PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX, 48,
                period="utc-hour", anchor_bucket="20260101T23",
            )
            == 0.0
        )

    @pytest.mark.parametrize("bad_bucket", ["20260101", "20260101X05", "2026010105", ""])
    def test_malformed_hour_bucket_raises(self, bad_bucket: str) -> None:
        with pytest.raises(ValueError, match="YYYYMMDDTHH"):
            scoped_counter_key(
                PRINCIPAL, "notify", "send", "counter",
                period="utc-hour", bucket=bad_bucket,
            )

    def test_day_param_refuses_non_day_period(self) -> None:
        with pytest.raises(ValueError, match="day="):
            scoped_counter_key(
                PRINCIPAL, "notify", "send", "counter",
                period="utc-hour", day="20260101",
            )

    def test_day_and_bucket_together_refused(self) -> None:
        with pytest.raises(ValueError, match="not both"):
            scoped_counter_key(
                PRINCIPAL, "notify", "send", "counter",
                bucket="20260101", day="20260101",
            )

    def test_unknown_period_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown counter period"):
            scoped_counter_key(PRINCIPAL, "notify", "send", "counter", period="utc-week")

    def test_current_period_bucket_formats(self) -> None:
        assert current_period_bucket("utc-day") == current_utc_day()
        hour_bucket = current_period_bucket("utc-hour")
        assert len(hour_bucket) == 11 and hour_bucket[8] == "T"
        assert hour_bucket.startswith(current_utc_day())

    def test_period_bucket_of_naive_vs_aware(self) -> None:
        moment = datetime.datetime(2026, 1, 1, 23, 59, tzinfo=datetime.UTC)
        assert period_bucket_of(moment, "utc-day") == "20260101"
        assert period_bucket_of(moment, "utc-hour") == "20260101T23"

    def test_period_step_and_window_bounds(self) -> None:
        assert period_step("utc-day") == datetime.timedelta(days=1)
        assert period_step("utc-hour") == datetime.timedelta(hours=1)
        assert MAX_WINDOW_PERIODS["utc-day"] == MAX_WINDOW_DAYS
        with pytest.raises(ValueError, match="window_periods"):
            read_counter_window(
                InMemoryStore(), PRINCIPAL, "notify", "send", OBSERVATIONS_SUFFIX,
                MAX_WINDOW_PERIODS["utc-hour"] + 1, period="utc-hour",
            )


def test_suffix_constants_shared_with_grants() -> None:
    """The ceremony's re-exported constants ARE the enforcement constants —
    one coordinate vocabulary, never two."""
    from safe_agents.broker.grants import commands

    assert commands.OBSERVATIONS_SUFFIX == OBSERVATIONS_SUFFIX
    assert commands.HUMAN_OVERRIDE_SUFFIX == HUMAN_OVERRIDE_SUFFIX
