"""The ledger's record timestamp: a hybrid logical clock per coordinate (#37).

A PromotionRecord's ``ts`` leads its sort key (``<ts>#<recordType>``), so the
ledger's order IS the order of its ts values. The raw wall clock cannot carry
that on its own: two records for one coordinate inside one clock tick (about
15.6 ms on Windows, 1 us elsewhere) either share a key, and the second
legitimate write is refused as a duplicate, or sort by recordType instead of by
write order, and the audit reads the level from the wrong record.

The fix is a hybrid logical clock (Kulkarni et al., "Logical Physical Clocks",
2014), reduced to what one partition needs: every writer stamps

    ts = max(wall-clock now, last ts recorded for this coordinate + 1 us)

so ts stays within a tick of wall time and is strictly increasing per
coordinate. The sort-key format, the signed bytes and the record schema are all
unchanged: the output is the same canonical isoformat the ledger always held
(validate_record_ts), and it is computed BEFORE the record is built, so the
signature binds the stored ts.

What it does not do: serialize concurrent writers. Two writers that read the
same last ts compute the same next ts, and the append-only conditional put
refuses the second. That race still fails toward less authority, exactly as
before; the clock only removes the collisions a single writer caused itself.

Every path that appends a ledger record goes through ``next_ledger_ts``. A
writer that stamps ts from the wall clock directly reintroduces #37.
"""

from __future__ import annotations

import datetime
from typing import Protocol

from safe_agents.broker.grants.store import validate_record_ts
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import Principal

# The logical increment. One microsecond is the finest step isoformat renders,
# so it is the smallest nudge that still yields a distinct, correctly-sorting sk.
LEDGER_TS_TICK = datetime.timedelta(microseconds=1)


class LedgerReader(Protocol):
    """The one read the clock needs: a coordinate's records, by partition.

    A Query on the record partition, never a Scan (no acting role holds
    dynamodb:Scan). Every PromotionRecordStore implementation provides it."""

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        ...


def _system_now() -> datetime.datetime:
    """The one wall-clock read behind a ledger ts (tests freeze it here)."""
    return datetime.datetime.now(datetime.UTC)


def _wall_clock(now: datetime.datetime | str | None) -> datetime.datetime:
    """The physical reading as tz-aware UTC.

    A string is a caller-supplied instant (the demotion runner and the CLI pass
    one) and must already be canonical; a naive datetime is refused rather than
    guessed at, since interpreting it in local time would move the ledger."""
    if now is None:
        return _system_now()
    if isinstance(now, str):
        validate_record_ts(now)
        return datetime.datetime.fromisoformat(now)
    if now.tzinfo is None:
        raise ValueError(
            f"ledger clock reading {now.isoformat()!r} is naive; pass a tz-aware UTC instant"
        )
    return now.astimezone(datetime.UTC)


def _recorded_instant(ts: str) -> datetime.datetime:
    """A stored record's ts as tz-aware UTC.

    put_record refuses a non-canonical ts (validate_record_ts), so a naive
    value could only be history from before that check. It is read as UTC (the
    same reading rung._parse_ts gives a naive ts) rather than refused: refusing
    would block every future write to the coordinate over a record nobody can
    re-mint."""
    parsed = datetime.datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC)


def next_ledger_ts(
    record_store: LedgerReader,
    principal: Principal,
    action_class: str,
    *,
    now: datetime.datetime | str | None = None,
    session: object = None,
) -> str:
    """The ts for the next record appended to (principal, action_class).

    ``now`` is the wall-clock reading (defaults to the system clock). The last
    recorded ts is found by parsing every record's ts and taking the maximum,
    never by comparing strings or trusting list order: those agree for
    canonical values, but the clock should not depend on that holding.

    Clock skew: if the last recorded ts is AHEAD of ``now`` (a writer whose
    clock ran fast), the result advances from it rather than from ``now``, as
    an HLC must, so the ledger keeps its order and ts runs ahead of wall time
    until the wall clock catches up. That is deliberate and uncapped: capping
    it would reintroduce the collision, and a skewed record is visible in the
    ledger for what it is.
    """
    wall = _wall_clock(now)
    records = record_store.list_records(principal, action_class, session)
    if records:
        last = max(_recorded_instant(r.ts) for r in records)
        wall = max(wall, last + LEDGER_TS_TICK)
    return wall.astimezone(datetime.UTC).isoformat()
