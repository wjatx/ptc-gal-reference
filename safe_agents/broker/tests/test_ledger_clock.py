"""The ledger clock (#37): record ts is strictly increasing per coordinate.

Two ledger records for one coordinate inside one wall-clock tick used to share
a ts. Same-type pairs collided (the second legitimate write was refused) and
different-type pairs sorted by recordType instead of write order, so the audit
read the level from the wrong record. Windows' ~15.6 ms clock made that routine;
here the clock is frozen instead, so every platform sees the same tick.
"""

from __future__ import annotations

import datetime
import itertools

import pytest

from safe_agents.broker.grants import commands, ledger_clock
from safe_agents.broker.grants.audit import (
    LEVEL_DROP_RECORDED,
    LEVEL_LEDGER_CONSISTENT,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore, PromotionCeremony
from safe_agents.broker.grants.demotion import DemotionMetrics
from safe_agents.broker.grants.lapse import run_lapse
from safe_agents.broker.grants.ledger_clock import LEDGER_TS_TICK, next_ledger_ts
from safe_agents.broker.grants.store import InMemoryGrantStore, RecordTimestampFormatError
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger
from safe_agents.broker.tests.test_grants_rung import (
    ACTION_CLASS,
    PRINCIPAL,
    TEST_HMAC_KEY,
    make_grant,
    make_machine,
    proposal_for,
    read_grant,
)
from safe_agents.broker.tests import test_grant_term_lapse as term_lapse

FROZEN = datetime.datetime(2026, 9, 25, 3, 9, 24, 421563, tzinfo=datetime.UTC)
# A whole second: isoformat drops the fraction, the shape most likely to sort
# wrongly against a nudged ts that carries one.
WHOLE_SECOND = datetime.datetime(2026, 9, 25, 3, 9, 24, tzinfo=datetime.UTC)
LEVEL_RULES = {LEVEL_DROP_RECORDED, LEVEL_LEDGER_CONSISTENT}


def _record(ts: str, record_type: str = "bootstrap") -> PromotionRecord:
    return PromotionRecord(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=None,
        toLevel=AutonomyLevel.in_loop,
        evidence="seed",
        predicate=None,
        proposedBy="alice",
        ratifiedBy="alice",
        envelopeHash="sha256:env-001",
        ts=ts,
    )


def _iso(instant: datetime.datetime) -> str:
    return instant.isoformat()


# ---------------------------------------------------------------------------
# The clock itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("recorded", "now", "expected"),
    [
        pytest.param([], FROZEN, FROZEN, id="empty-ledger-is-wall-clock"),
        pytest.param(
            [FROZEN - datetime.timedelta(seconds=5)], FROZEN, FROZEN, id="advancing-clock-is-wall-clock"
        ),
        pytest.param([FROZEN], FROZEN, FROZEN + LEDGER_TS_TICK, id="same-tick-nudges-one-us"),
        pytest.param(
            [FROZEN, FROZEN + LEDGER_TS_TICK],
            FROZEN,
            FROZEN + 2 * LEDGER_TS_TICK,
            id="nudges-past-the-latest-not-the-first",
        ),
        pytest.param(
            [FROZEN + datetime.timedelta(hours=1)],
            FROZEN,
            FROZEN + datetime.timedelta(hours=1) + LEDGER_TS_TICK,
            id="skewed-future-last-ts-advances-from-it",
        ),
        pytest.param(
            [WHOLE_SECOND], WHOLE_SECOND, WHOLE_SECOND + LEDGER_TS_TICK, id="whole-second-last-ts"
        ),
    ],
)
def test_next_ledger_ts(recorded, now, expected):
    store = InMemoryPromotionRecordStore()
    for instant in recorded:
        store.put_record(_record(_iso(instant)))
    ts = next_ledger_ts(store, PRINCIPAL, ACTION_CLASS, now=now)
    assert ts == _iso(expected)
    # The canonical shape the sk ordering depends on, and it sorts last.
    store.put_record(_record(ts))
    assert [r.ts for r in store.list_records(PRINCIPAL, ACTION_CLASS)][-1] == ts


def test_other_coordinates_do_not_advance_the_clock():
    store = InMemoryPromotionRecordStore()
    store.put_record(_record(_iso(FROZEN)))
    assert next_ledger_ts(store, PRINCIPAL, "write.files", now=FROZEN) == _iso(FROZEN)


@pytest.mark.parametrize(
    "now",
    [
        pytest.param(FROZEN.replace(tzinfo=None), id="naive-datetime"),
        pytest.param("2026-09-25T03:09:24Z", id="non-canonical-string"),
    ],
)
def test_ambiguous_wall_readings_are_refused(now):
    with pytest.raises((ValueError, RecordTimestampFormatError)):
        next_ledger_ts(InMemoryPromotionRecordStore(), PRINCIPAL, ACTION_CLASS, now=now)


# ---------------------------------------------------------------------------
# Every writer, inside one clock tick
# ---------------------------------------------------------------------------


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(ledger_clock, "_system_now", lambda: FROZEN)


def _promote_to(level):
    def step(machine, store):
        grant = read_grant(store)
        result = machine.promote(
            proposal_for(grant, target_level=level, last_safe_level=AutonomyLevel.in_loop),
            ratifier_id="checker-bot",
        )
        assert result.status == "ratified", result.reason

    return step


def _demote(machine, store):
    machine.demote(
        read_grant(store), DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    )


def _tighten(machine, store):
    machine.tighten_to_in_loop(read_grant(store), "alice")


SEQUENCES = [
    pytest.param(
        AutonomyLevel.in_loop,
        [_promote_to(AutonomyLevel.on_loop), _promote_to(AutonomyLevel.out_of_loop)],
        ["promotion", "promotion"],
        id="same-type-twice",
    ),
    pytest.param(
        AutonomyLevel.in_loop,
        [_promote_to(AutonomyLevel.on_loop), _demote],
        ["promotion", "demotion"],
        id="promote-then-demote",
    ),
    pytest.param(
        AutonomyLevel.on_loop,
        [_tighten, _promote_to(AutonomyLevel.on_loop)],
        ["tightening", "promotion"],
        id="tighten-then-promote",
    ),
    pytest.param(
        AutonomyLevel.in_loop,
        [_promote_to(AutonomyLevel.on_loop), _tighten],
        ["promotion", "tightening"],
        id="promote-then-tighten",
    ),
    pytest.param(
        AutonomyLevel.in_loop,
        [
            _promote_to(AutonomyLevel.on_loop),
            _promote_to(AutonomyLevel.out_of_loop),
            _demote,
        ],
        ["promotion", "promotion", "demotion"],
        id="round-trip",
    ),
]


def _run(start_level, steps):
    record_store = InMemoryPromotionRecordStore()
    machine, store = make_machine(
        grant=make_grant(level=start_level, lastSafeLevel=AutonomyLevel.in_loop),
        record_store=record_store,
    )
    for step in steps:
        step(machine, store)
    return store, record_store.list_records(PRINCIPAL, ACTION_CLASS)


@pytest.mark.parametrize(("start_level", "steps", "written"), SEQUENCES)
def test_one_tick_ledger_keeps_write_order(frozen_clock, start_level, steps, written):
    store, records = _run(start_level, steps)

    # Every write landed, and the ledger lists them in the order written.
    assert [r.recordType for r in records] == written
    # Strictly increasing, one tick apart, starting at the wall clock.
    assert [r.ts for r in records] == [
        _iso(FROZEN + i * LEDGER_TS_TICK) for i in range(len(written))
    ]
    # The grant carries the stamp of the record that wrote it.
    assert read_grant(store).ts == records[-1].ts

    read = store.get_grant(PRINCIPAL, ACTION_CLASS)
    report = run_audit(
        AuditDataset(
            grants=(
                AuditedGrant(
                    grant=read.grant, raw_data=read.raw_data, stored_hash=read.stored_hash
                ),
            ),
            records=tuple(AuditedRecord(record=r) for r in records),
        ),
        hmac_key=TEST_HMAC_KEY,
    )
    assert [v for v in report.violations if v.rule in LEVEL_RULES] == []


def test_advancing_clock_stamps_wall_time_exactly(monkeypatch):
    instants = [FROZEN + datetime.timedelta(seconds=s) for s in range(3)]
    clock = itertools.chain(instants, itertools.repeat(instants[-1]))
    monkeypatch.setattr(ledger_clock, "_system_now", lambda: next(clock))

    _, records = _run(
        AutonomyLevel.in_loop,
        [
            _promote_to(AutonomyLevel.on_loop),
            _promote_to(AutonomyLevel.out_of_loop),
            _demote,
        ],
    )
    assert [r.ts for r in records] == [_iso(i) for i in instants]


def test_one_tick_lapse_then_re_promotion(frozen_clock):
    """The lapse path, from the second Windows run: promote with a term, lapse
    it, re-promote, all in one tick. The re-promotion used to collide with the
    first promotion. The lapse evaluator's ``now`` (AFTER) is a month BEHIND
    the frozen wall clock, which is the skew case in the other direction: the
    lapse record is stamped after the promotion it lapses, not before it."""
    grant_store, record_store = term_lapse._promote_with_term(
        term_lapse.TERM, ratify_at=term_lapse.BEFORE
    )
    lapse = run_lapse(
        term_lapse.PRINCIPAL,
        term_lapse.ACTION_CLASS,
        grant_store=grant_store,
        record_store=record_store,
        now=term_lapse.AFTER,
    )
    assert lapse.status == "lapsed"
    result = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    ).execute(
        term_lapse._reproposal(
            certified_until=(term_lapse.AFTER + datetime.timedelta(days=90)).isoformat()
        ),
        "checker-bob",
        now=term_lapse.AFTER,
    )
    assert result.status == "ratified", result.reason

    records = record_store.list_records(term_lapse.PRINCIPAL, term_lapse.ACTION_CLASS)
    assert [r.recordType for r in records] == ["bootstrap", "promotion", "lapse", "promotion"]
    assert [r.ts for r in records[1:]] == [
        _iso(FROZEN + i * LEDGER_TS_TICK) for i in range(3)
    ]


def test_windows_lapse_repro_passes_in_one_tick(frozen_clock):
    term_lapse.test_re_promotion_sets_a_new_term_and_clears_the_lapse()


def test_one_tick_seed_onto_a_ledger_that_already_has_a_record(frozen_clock, monkeypatch):
    """seed's bootstrap goes through the clock too: a coordinate whose grant is
    gone but whose ledger holds a record from this tick (a grant deleted out of
    band, then re-seeded) gets a bootstrap ts after it rather than a refusal."""
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: "seeder")
    record_store = InMemoryPromotionRecordStore()
    record_store.put_record(_record(_iso(FROZEN)))
    grant_store = InMemoryGrantStore(hmac_key=TEST_HMAC_KEY)

    rc = commands.seed_command(
        grant_store=grant_store,
        record_store=record_store,
        grants=[make_grant()],
        now=FROZEN,
    )

    assert rc == 0
    records = record_store.list_records(PRINCIPAL, ACTION_CLASS)
    assert [r.ts for r in records] == [_iso(FROZEN), _iso(FROZEN + LEDGER_TS_TICK)]
    assert read_grant(grant_store).ts == records[-1].ts
