"""Time-representation unit tests (sa#213, class B) — how timestamps are
encoded and compared across the platform's several ts-bearing surfaces:

  - the PromotionRecord ledger sort key (grants/store.py's ``_item_key``),
    where chronological order MUST equal lexicographic order
  - ``proposal_expired`` (grants/proposals.py) — deterministic, fail-closed
  - ``EventTrigger.is_expired`` (channels/schemas/event_trigger.py)
  - ``Liveness.overdue`` (schemas/envelope.py)

Fixed inputs throughout; no wall-clock reads.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.grants.proposals import proposal_expired
from safe_agents.broker.grants.store import (
    DynamoDBPromotionRecordStore,
    RecordTimestampFormatError,
    validate_record_ts,
)
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.envelope import Liveness
from safe_agents.channels.schemas.event_trigger import EventTrigger, ProvenanceEntry, SenderIdentity

PRINCIPAL = Principal(agentId="agent-1", skill="notify", user="maintainer", tier="B")
ACTION_CLASS = "email.send"


def _record(ts: str) -> PromotionRecord:
    # bootstrap: fromLevel=None, maker==checker sanctioned, no predicate needed.
    return PromotionRecord(
        recordType="bootstrap",
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        fromLevel=None,
        toLevel=AutonomyLevel.in_loop,
        ts=ts,
        evidence="bootstrap-evidence",
        proposedBy="human:maintainer",
        ratifiedBy="human:maintainer",
        envelopeHash="env-hash-1",
    )


# ---------------------------------------------------------------------------
# Class B(a) — RECORD# sk sortability
# ---------------------------------------------------------------------------


class TestRecordSkSortability:
    """The ledger sort key is "<ts>#<recordType>" (grants/store.py's
    _item_key); Query's ScanIndexForward relies on LEXICAL sort matching
    CHRONOLOGICAL order. This only holds if every ts is the canonical
    tz-aware UTC '+00:00' form (validate_record_ts's job)."""

    # A day, month, and year boundary set — the same nasty instants as
    # test_time_boundaries.py, in the record ts spelling.
    CHRONOLOGICAL_TS = [
        "2026-01-31T23:59:59+00:00",
        "2026-02-01T00:00:00+00:00",
        "2026-12-31T23:59:59+00:00",
        "2027-01-01T00:00:00+00:00",
    ]

    def test_item_key_sk_lexical_order_matches_chronological(self) -> None:
        store = DynamoDBPromotionRecordStore.__new__(DynamoDBPromotionRecordStore)
        records = [_record(ts) for ts in self.CHRONOLOGICAL_TS]
        sks = [store._item_key(r)["sk"] for r in records]
        assert sks == sorted(sks)

    def test_z_suffix_breaks_lexical_chronological_equivalence(self) -> None:
        # The hazard this whole class exists to document. Python's isoformat()
        # OMITS the fractional-second component entirely when it is zero, but
        # includes it (as ".NNNNNN") when nonzero. So an earlier, exactly-on-
        # the-second instant spelled with a bare 'Z' can sort AFTER a later
        # instant one microsecond on, spelled '+00:00' with its fraction —
        # because at the point the strings diverge, 'Z' (0x5A) > '.' (0x2E).
        earlier_on_the_second = "2026-07-16T00:00:00Z"  # :00.000000 exactly
        later_by_one_microsecond = "2026-07-16T00:00:00.000001+00:00"

        parsed_earlier = datetime.datetime.fromisoformat(
            earlier_on_the_second.replace("Z", "+00:00")
        )
        parsed_later = datetime.datetime.fromisoformat(later_by_one_microsecond)
        assert parsed_earlier < parsed_later  # chronologically first, as named

        # The counterexample: lexical order disagrees.
        assert earlier_on_the_second > later_by_one_microsecond

    def test_validate_record_ts_rejects_z_suffix(self) -> None:
        with pytest.raises(RecordTimestampFormatError, match="'Z'|non-UTC offset"):
            validate_record_ts("2026-07-16T00:00:00Z")

    def test_validate_record_ts_rejects_naive(self) -> None:
        with pytest.raises(RecordTimestampFormatError, match="naive"):
            validate_record_ts("2026-07-16T00:00:00")

    def test_validate_record_ts_rejects_non_utc_offset(self) -> None:
        with pytest.raises(RecordTimestampFormatError, match="UTC"):
            validate_record_ts("2026-07-16T05:30:00+05:30")

    def test_validate_record_ts_accepts_canonical_form(self) -> None:
        validate_record_ts("2026-07-16T00:00:00+00:00")  # does not raise

    def test_real_producer_emits_canonical_plus_00_00_form(self) -> None:
        # commands.py/_utc_now + runner.py both stamp
        # datetime.datetime.now(datetime.UTC).isoformat() — pin that THIS
        # emits the canonical form validate_record_ts requires (never 'Z').
        now = datetime.datetime(2026, 7, 16, 12, 0, 0, tzinfo=datetime.UTC)
        emitted = now.isoformat()
        assert emitted == "2026-07-16T12:00:00+00:00"
        validate_record_ts(emitted)  # does not raise — the producer stays canonical


# ---------------------------------------------------------------------------
# Class B(b) — proposal_expired
# ---------------------------------------------------------------------------


class TestProposalExpired:
    NOW = datetime.datetime(2026, 7, 16, 12, 0, 0, tzinfo=datetime.UTC)

    def test_naive_expires_at_coerced_utc(self) -> None:
        # Naive "2026-07-16T13:00:00" is treated as UTC — one hour after NOW,
        # so not yet expired.
        assert proposal_expired("2026-07-16T13:00:00", self.NOW) is False
        # An hour before NOW (still naive) — expired.
        assert proposal_expired("2026-07-16T11:00:00", self.NOW) is True

    @pytest.mark.parametrize("garbage", ["not-a-date", "", "2026-13-45T99:99:99"])
    def test_unparseable_expires_at_fails_closed(self, garbage: str) -> None:
        assert proposal_expired(garbage, self.NOW) is True

    def test_none_expires_at_fails_closed(self) -> None:
        assert proposal_expired(None, self.NOW) is True  # type: ignore[arg-type]

    def test_at_exactly_expiry_is_expired(self) -> None:
        exact = self.NOW.isoformat()
        assert proposal_expired(exact, self.NOW) is True  # >= comparison, boundary inclusive


# ---------------------------------------------------------------------------
# Class B(c) — EventTrigger.is_expired
# ---------------------------------------------------------------------------


def _event_trigger(expiry: str, ts: str = "2026-07-16T00:00:00+00:00") -> EventTrigger:
    return EventTrigger(
        event_id="evt-1",
        principal="agent-1",
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer-1"),
        payload={},
        provenance=[
            ProvenanceEntry(
                zone="external", source="webhook:peer-1", label="untrusted", ts=ts
            )
        ],
        ts=ts,
        expiry=expiry,
    )


class TestEventTriggerIsExpired:
    def test_naive_now_raises(self) -> None:
        trigger = _event_trigger(expiry="2026-07-16T01:00:00+00:00")
        naive_now = datetime.datetime(2026, 7, 16, 0, 30, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            trigger.is_expired(naive_now)

    def test_aware_now_works(self) -> None:
        trigger = _event_trigger(expiry="2026-07-16T01:00:00+00:00")
        not_yet = datetime.datetime(2026, 7, 16, 0, 30, 0, tzinfo=datetime.UTC)
        past = datetime.datetime(2026, 7, 16, 2, 0, 0, tzinfo=datetime.UTC)
        assert trigger.is_expired(not_yet) is False
        assert trigger.is_expired(past) is True

    def test_z_suffix_expiry_parses_on_py311_plus(self) -> None:
        # datetime.fromisoformat gained 'Z' support in 3.11; this repo requires
        # >=3.12 (pyproject.toml), so this is expected to parse cleanly. If it
        # does NOT parse, that is a finding, not something to paper over here.
        trigger = _event_trigger(expiry="2026-07-16T01:00:00Z")
        aware_now = datetime.datetime(2026, 7, 16, 0, 30, 0, tzinfo=datetime.UTC)
        assert trigger.is_expired(aware_now) is False


# ---------------------------------------------------------------------------
# Class B(d) — Liveness.overdue
# ---------------------------------------------------------------------------


class TestLivenessOverdue:
    LIVENESS = Liveness(expected_op="notify.send", deadline_seconds=3600)

    def test_none_last_seen_is_overdue(self) -> None:
        assert self.LIVENESS.overdue(last_seen_epoch=None, now_epoch=1_000_000.0) is True

    def test_exactly_at_deadline_is_not_overdue(self) -> None:
        # Strict > : elapsed == deadline_seconds is NOT overdue.
        now = 1_000_000.0
        last_seen = now - 3600
        assert self.LIVENESS.overdue(last_seen_epoch=last_seen, now_epoch=now) is False

    def test_past_deadline_is_overdue(self) -> None:
        now = 1_000_000.0
        last_seen = now - 3601
        assert self.LIVENESS.overdue(last_seen_epoch=last_seen, now_epoch=now) is True
