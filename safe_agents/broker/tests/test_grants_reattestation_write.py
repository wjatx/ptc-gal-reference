"""Re-attestation appends a record: the write itself (#164; GAL §5.2, §6.6).

R1 (one atomic write of grant and record), R2 (one ts, from the ledger clock)
and R3 (the record's shape).

The clause table and the shared harness are in reattestation_scaffold.py.
"""

from __future__ import annotations

import datetime

import pytest
from pydantic import ValidationError

from safe_agents.broker.grants import commands
from safe_agents.broker.grants.commands import seed_command
from safe_agents.broker.grants.ledger_clock import LEDGER_TS_TICK, next_ledger_ts
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.rung import RungStateMachine
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.tests import reattestation_scaffold as harness
from safe_agents.broker.tests.reattestation_scaffold import (
    ACTION_CLASS,
    IN,
    NEW_HASH,
    OLD_HASH,
    ON,
    OPERATOR,
    OTHER_CLASS,
    OUT,
    PRINCIPAL,
    RESEEDED_AT,
    SEEDED_AT,
    SEEDER,
    STAMP,
    TERM,
    _as,
    _ledger,
    _reattest,
    _reattestation,
    _reattestations,
    _refused,
    _reseed,
    _seed,
    _writer_pair,
    make_grant,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
backend = harness.backend


# ===========================================================================
# R1 — one atomic write
# ===========================================================================


class TestR1Atomic:
    def test_reseed_writes_the_grant_and_exactly_one_record(self, backend, monkeypatch):
        _seed(backend, monkeypatch, level=ON)

        _reattest(backend, monkeypatch)

        assert [r.recordType for r in _ledger(backend)] == ["bootstrap", "reattestation"]
        (record,) = _reattestations(backend)
        assert backend.raw_record_exists(record)
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert not read.quarantined and read.grant.envelopeHash == NEW_HASH

    def test_a_refused_record_leg_leaves_the_grant_bytes_unchanged(
        self, backend, monkeypatch, capsys
    ):
        _seed(backend, monkeypatch, level=ON)
        # Occupy the exact key the re-attestation will ask for, and pin the
        # clock to it: the record leg is refused as a duplicate.
        collide = RESEEDED_AT.isoformat()
        backend.records.put_record(_reattestation(ts=collide, envelopeHash="sha256:other"), None)
        monkeypatch.setattr(commands, "next_ledger_ts", lambda *a, **k: collide)
        before = backend.raw_grant_data()

        _refused(backend, monkeypatch, "I1 ATOMIC (record leg refused)")

        assert backend.raw_grant_data() == before
        assert len(_reattestations(backend)) == 1  # the occupant, nothing new
        assert "nothing written" in capsys.readouterr().err

    def test_a_conflicting_grant_leg_leaves_no_record(self, backend, monkeypatch, capsys):
        _seed(backend, monkeypatch, level=ON)
        real_get = backend.grants.get_grant

        def read_then_lose_the_race(principal, action_class):
            read = real_get(principal, action_class)
            # Another writer lands between the guarded read and the write.
            backend.grants.put_grant(read.grant.model_copy(update={"ownerId": "mallory"}), None)
            return read

        monkeypatch.setattr(backend.grants, "get_grant", read_then_lose_the_race)

        _refused(backend, monkeypatch, "I1 ATOMIC (grant leg lost the race)")

        monkeypatch.setattr(backend.grants, "get_grant", real_get)
        assert _reattestations(backend) == []
        stored = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert stored.ownerId == "mallory" and stored.envelopeHash == OLD_HASH
        assert "nothing written" in capsys.readouterr().err

    def test_a_second_reseed_appends_nothing(self, backend, monkeypatch):
        _seed(backend, monkeypatch)
        _reattest(backend, monkeypatch)
        rc, _ = _reseed(backend, monkeypatch, now=RESEEDED_AT + datetime.timedelta(hours=1))
        assert rc == 0
        assert len(_reattestations(backend)) == 1, (
            "I9: a grant already under the in-force hash is skipped with no record"
        )


# ===========================================================================
# R2 — one ts, from the ledger clock
# ===========================================================================


class TestR2Clock:
    def test_grant_and_record_carry_the_ledger_clock_s_stamp(self, backend, monkeypatch):
        _seed(backend, monkeypatch)
        stamp = STAMP
        asked = []

        def ledger_clock(record_store, principal, action_class, **kwargs):
            asked.append((record_store, principal, action_class))
            return stamp

        monkeypatch.setattr(commands, "next_ledger_ts", ledger_clock)

        _reattest(backend, monkeypatch)

        (record,) = _reattestations(backend)
        why = "I2 CLOCK: the stamp is the ledger clock's, never a direct wall-clock read"
        assert record.ts == stamp, f"{why}; the record carries {record.ts}"
        stored = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert stored.ts == stamp, f"{why}; the grant carries {stored.ts}"
        assert asked == [(backend.records, PRINCIPAL, ACTION_CLASS)], (
            "I2 CLOCK: the ledger clock is asked once, for this coordinate"
        )

    def test_the_stamp_is_after_every_record_when_the_wall_clock_reads_earlier(
        self, backend, monkeypatch
    ):
        _seed(backend, monkeypatch)
        (bootstrap,) = _ledger(backend)
        behind = SEEDED_AT - datetime.timedelta(days=3)

        _reattest(backend, monkeypatch, now=behind)

        (record,) = _reattestations(backend)
        last = datetime.datetime.fromisoformat(bootstrap.ts)
        assert datetime.datetime.fromisoformat(record.ts) == last + LEDGER_TS_TICK
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant.ts == record.ts
        assert _ledger(backend)[-1] == record  # and the ledger sorts it last

    def test_each_coordinate_is_stamped_from_its_own_ledger(self, backend, monkeypatch):
        """Two classes in one re-seed, the second with a ledger that already
        runs ahead of the wall clock. A clock read for the wrong coordinate
        stamps that class's reattestation BEFORE its own bootstrap record."""
        _seed(backend, monkeypatch)
        ahead = RESEEDED_AT + datetime.timedelta(days=1)
        _as(monkeypatch, SEEDER)
        assert seed_command(
            grant_store=backend.grants,
            record_store=backend.records,
            grants=[make_grant(actionClass=OTHER_CLASS, envelopeHash=OLD_HASH)],
            now=ahead,
        ) == 0

        _reattest(backend, monkeypatch, classes=(ACTION_CLASS, OTHER_CLASS))

        for action_class, expected_ts in (
            (ACTION_CLASS, RESEEDED_AT.isoformat()),
            (OTHER_CLASS, (ahead + LEDGER_TS_TICK).isoformat()),
        ):
            ledger = backend.records.list_records(PRINCIPAL, action_class, None)
            bootstrap, record = ledger
            assert (bootstrap.recordType, record.recordType) == ("bootstrap", "reattestation"), (
                f"I2 CLOCK: {action_class} was stamped from another coordinate's ledger, so "
                f"its reattestation sorts before its own bootstrap: {[r.recordType for r in ledger]}"
            )
            assert record.ts == expected_ts, (
                f"I2 CLOCK: {action_class}'s stamp must come from the ledger clock read for "
                f"THAT coordinate, got {record.ts}, expected {expected_ts}"
            )
            assert backend.grants.get_grant(PRINCIPAL, action_class).grant.ts == record.ts

    def test_the_clock_does_not_pass_over_a_reattestation(self, backend, monkeypatch):
        """The one ledger reader that must NOT pass over the type. A
        reattestation moves no level, and it is still a record at the
        coordinate: the next write is stamped strictly after it. With a wall
        clock at or behind it, a clock that skipped the type would hand the
        next record the reattestation's own ts."""
        _seed(backend, monkeypatch, level=ON)
        behind = SEEDED_AT - datetime.timedelta(days=3)
        _reattest(backend, monkeypatch, now=behind)
        (record,) = _reattestations(backend)
        after_it = (datetime.datetime.fromisoformat(record.ts) + LEDGER_TS_TICK).isoformat()

        assert next_ledger_ts(backend.records, PRINCIPAL, ACTION_CLASS, now=behind) == after_it, (
            "I2 CLOCK: the ledger clock passed over a reattestation record. The next "
            "write must be stamped strictly later than EVERY record at the coordinate"
        )

        # And through a real writer: the tightening that follows sorts last.
        from safe_agents.broker.grants.ceremony import PromotionCeremony

        machine = RungStateMachine(
            ceremony=PromotionCeremony(
                grant_store=backend.grants, promotion_record_store=backend.records
            ),
            grant_store=backend.grants,
            record_store=backend.records,
        )
        grant = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant
        _, tightening = machine.tighten_to_in_loop(grant, OPERATOR, ts=behind.isoformat())
        assert tightening.ts == after_it, (
            "I2 CLOCK: a write after a reattestation must be stamped strictly after it, "
            f"got {tightening.ts} against the reattestation's {record.ts}"
        )
        assert [r.recordType for r in _ledger(backend)] == [
            "bootstrap", "reattestation", "tightening"
        ]

    def test_the_writer_gives_grant_and_record_one_ts(self):
        _before, after, record = _writer_pair()
        assert record.ts == STAMP, f"I2 CLOCK: the record's ts must be the stamp handed in, got {record.ts}"
        assert after.ts == record.ts, (
            f"I2 CLOCK: grant and record must carry one ts, got grant {after.ts} "
            f"and record {record.ts}"
        )


# ===========================================================================
# R3 — the record's shape
# ===========================================================================


class TestR3Shape:
    def test_reseed_writes_the_specified_shape(self, backend, monkeypatch):
        _seed(backend, monkeypatch, level=ON)
        _reattest(backend, monkeypatch)

        (record,) = _reattestations(backend)
        assert record.fromLevel is ON and record.toLevel is ON
        assert record.envelopeHash == NEW_HASH  # the NEW hash, not the one replaced
        assert record.ratifiedBy == OPERATOR  # who re-attested, not who seeded
        assert record.predicate is None
        assert record.triggeredBy == []
        assert record.demotionReason is None
        assert record.certifiedUntil is None
        assert record.principal == PRINCIPAL and record.actionClass == ACTION_CLASS

    def test_the_writer_builds_the_specified_record(self):
        """The same shape, judged on what the writer builds and not through
        the store guard that would refuse a wrong one."""
        before, _after, record = _writer_pair()
        assert record.recordType == "reattestation"
        assert record.fromLevel is before.level and record.toLevel is before.level, (
            "I3 SHAPE: fromLevel and toLevel must both be the grant's level, got "
            f"{record.fromLevel} -> {record.toLevel} for a grant at {before.level}"
        )
        assert record.envelopeHash == NEW_HASH, (
            "I3 SHAPE: envelopeHash must be the NEW hash the grant was re-issued under, "
            f"got {record.envelopeHash}"
        )
        assert record.ratifiedBy == OPERATOR, (
            "I3 SHAPE: ratifiedBy must be the identity that re-attested, "
            f"got {record.ratifiedBy}"
        )
        assert (record.predicate, record.triggeredBy, record.demotionReason) == (None, [], None), (
            "I3 SHAPE: a reattestation carries no predicate, triggers or demotion reason"
        )
        assert record.certifiedUntil is None, "I3 SHAPE: certifiedUntil is null on a reattestation"
        assert (record.principal, record.actionClass) == (before.principal, before.actionClass)

    @pytest.mark.parametrize(
        "broken",
        [
            dict(fromLevel=IN, toLevel=ON),
            dict(fromLevel=OUT, toLevel=ON),
            dict(fromLevel=None, toLevel=IN),
            dict(predicate="passed"),
            dict(triggeredBy=["budget_breach"]),
            dict(demotionReason="pending-evidence"),
            dict(certifiedUntil=TERM),
        ],
        ids=["raises", "lowers", "from-recommend", "predicate", "triggers", "reason", "term"],
    )
    def test_a_record_breaking_the_shape_is_refused_by_writer_and_reader(self, broken):
        with pytest.raises(ValidationError):
            _reattestation(**broken)
        # The reader's side: the same bytes, arriving from a store.
        stored = _reattestation().model_dump(mode="json") | {
            key: (value.value if isinstance(value, AutonomyLevel) else value)
            for key, value in broken.items()
        }
        with pytest.raises(ValidationError):
            PromotionRecord.model_validate(stored)

    def test_maker_and_checker_are_not_compared(self):
        assert _reattestation(proposedBy=OPERATOR, ratifiedBy=OPERATOR)
        assert _reattestation(proposedBy="someone-else", ratifiedBy=OPERATOR)

    def test_the_term_stays_out_of_the_canonical_bytes(self):
        assert "certifiedUntil" not in canonical_record_payload(_reattestation())
