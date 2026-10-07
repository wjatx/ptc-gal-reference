"""Re-attestation appends a record: what its readers make of it.

#164; GAL §4.3, §6.8.

R6 (every reader that derives a level, or looks for the record that earned it,
passes over the type) and R7 (dwell is measured from the ledger and a
`reattestation` record does not restart it).

The clause table and the shared harness are in reattestation_scaffold.py.
"""

from __future__ import annotations

import datetime

from safe_agents.broker.grants.audit import (
    EVALUATOR_RECORD_CONTINUOUS,
    GRANT_TERM_RATIFIED,
    LEDGER_COUNTERPART,
    LEVEL_DROP_RECORDED,
    LEVEL_LEDGER_CONSISTENT,
    QUARANTINED_NO_RAISE,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.integrity import detect_orphaned_grants
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.rung import (
    PromotionEligibilityCounters,
    RungStateMachine,
    dwell_start_ts,
    is_eligible_for_promotion,
)
from safe_agents.broker.grants.runner import _same_day_demotion_recorded
from safe_agents.broker.grants.store import canonical_grant_payload
from safe_agents.broker.tests import reattestation_scaffold as harness
from safe_agents.broker.tests.reattestation_scaffold import (
    ACTION_CLASS,
    IN,
    NEW_HASH,
    ON,
    OPERATOR,
    OUT,
    PRINCIPAL,
    RESEEDED_AT,
    TERM,
    _audit,
    _bootstrap,
    _demotion,
    _ledger,
    _planted,
    _promotion,
    _reattest,
    _seed,
    make_grant,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
backend = harness.backend


# ===========================================================================
# R6 — readers pass over the type
# ===========================================================================


class TestR6ReadersPassOver:
    def test_the_derived_level_is_the_one_before_a_reattestation(self):
        """The attack the pass-over exists for: a same-level record restating
        a level the ledger never reached. Read off the last record, the
        ledger would say out-of-loop and the raised grant would audit clean."""
        grant = make_grant(level=OUT, envelopeHash=NEW_HASH)
        ledger = [_bootstrap(), _planted("2026-07-03T00:00:00+00:00", OUT)]
        assert LEVEL_LEDGER_CONSISTENT in _audit(grant, ledger)

    def test_a_quarantined_grant_is_bounded_by_the_level_before_a_reattestation(self):
        """QUARANTINED_NO_RAISE reads the same derived level: a planted
        reattestation restating out-of-loop must not lift the bound a
        quarantined grant is held to."""
        grant = make_grant(level=OUT, envelopeHash=NEW_HASH)
        dataset = AuditDataset(
            grants=(
                AuditedGrant(
                    grant=grant, raw_data=canonical_grant_payload(grant), stored_hash="0" * 64
                ),
            ),
            records=tuple(
                AuditedRecord(record=r, raw_data=canonical_record_payload(r))
                for r in (_bootstrap(), _planted("2026-07-03T00:00:00+00:00", OUT))
            ),
        )
        rules = {v.rule for v in run_audit(dataset, hmac_key=b"audit-key").violations}
        assert QUARANTINED_NO_RAISE in rules, (
            "I6 READERS PASS OVER: the quarantine bound took the ledger's level from a "
            "reattestation record"
        )

    def test_a_reattestation_does_not_explain_a_drop_either(self):
        grant = make_grant(level=IN, envelopeHash=NEW_HASH)
        ledger = [_bootstrap(), _promotion(), _planted("2026-07-03T00:00:00+00:00", IN)]
        assert LEVEL_DROP_RECORDED in _audit(grant, ledger)

    def test_a_reattestation_is_not_a_grant_s_ledger_counterpart(self):
        grant = make_grant(level=ON, envelopeHash=NEW_HASH)
        rules = _audit(grant, [_planted("2026-07-03T00:00:00+00:00", ON)])
        assert LEDGER_COUNTERPART in rules
        # With nothing level-bearing on the ledger there is no derived level
        # for the grant to exceed: the orphan finding is the whole story.
        assert LEVEL_LEDGER_CONSISTENT not in rules

    def test_the_orphan_check_does_not_count_one_as_cover(self):
        grant = make_grant(level=ON)
        lone = _planted("2026-07-03T00:00:00+00:00", ON)
        assert [o.grant for o in detect_orphaned_grants([grant], [lone])] == [grant]
        assert detect_orphaned_grants([grant], [_bootstrap(to_level=ON), lone]) == []

    def test_evaluator_continuity_is_judged_against_the_level_before_it(self):
        """A planted reattestation must not move what "the ledger held": a
        demotion that starts from the level it restates is still a break."""
        ledger = [
            _bootstrap(),
            _planted("2026-07-03T00:00:00+00:00", ON),
            _demotion("2026-07-04T00:00:00+00:00", ON, IN),
        ]
        assert EVALUATOR_RECORD_CONTINUOUS in _audit(None, ledger)

    def test_an_honest_reattestation_does_not_break_evaluator_continuity(self):
        ledger = [
            _bootstrap(),
            _promotion(),
            _planted("2026-07-03T00:00:00+00:00", ON),
            _demotion("2026-07-04T00:00:00+00:00", ON, IN),
        ]
        assert EVALUATOR_RECORD_CONTINUOUS not in _audit(None, ledger)

    def test_the_ratified_term_is_still_the_promotion_s(self):
        ledger = [
            _bootstrap(),
            _promotion(certifiedUntil=TERM),
            _planted("2026-07-03T00:00:00+00:00", ON),
        ]
        # The grant carries the ts of the latest record, which is the
        # re-attestation: the one rule that does not pass over the type.
        stamped = dict(level=ON, envelopeHash=NEW_HASH, ts=ledger[-1].ts)
        assert _audit(make_grant(certifiedUntil=TERM, **stamped), ledger) == set()
        assert GRANT_TERM_RATIFIED in _audit(make_grant(**stamped), ledger)

    def test_a_reseeded_coordinate_audits_as_it_did_before(self, backend, monkeypatch):
        """End to end on each backend: the level and the earning record are
        the ones the ledger held before the re-attestation."""
        _seed(backend, monkeypatch, level=ON)
        before = _audit(backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant, _ledger(backend))

        _reattest(backend, monkeypatch)

        after = _audit(backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant, _ledger(backend))
        assert before == after == set()

    def test_the_runner_s_same_day_dedupe_does_not_mistake_one_for_a_demotion(
        self, backend, monkeypatch
    ):
        _seed(backend, monkeypatch, level=IN)
        _reattest(backend, monkeypatch)
        grant = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant

        assert not _same_day_demotion_recorded(
            backend.records, grant, [], day=RESEEDED_AT.date().isoformat(), session=None
        )

    def test_the_next_ceremony_write_starts_from_the_grant_s_level(self, backend, monkeypatch):
        """Tightening after a re-attestation: its record leaves from the level
        the grant holds, and the ledger still audits clean."""
        from safe_agents.broker.grants.ceremony import PromotionCeremony

        _seed(backend, monkeypatch, level=ON)
        _reattest(backend, monkeypatch)
        machine = RungStateMachine(
            ceremony=PromotionCeremony(
                grant_store=backend.grants, promotion_record_store=backend.records
            ),
            grant_store=backend.grants,
            record_store=backend.records,
        )
        grant = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant

        _, tightening = machine.tighten_to_in_loop(grant, OPERATOR)

        assert (tightening.fromLevel, tightening.toLevel) == (ON, IN)
        assert [r.recordType for r in _ledger(backend)] == [
            "bootstrap", "reattestation", "tightening"
        ]
        assert _audit(backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant, _ledger(backend)) == set()


# ===========================================================================
# R7 — dwell
# ===========================================================================


class TestR7Dwell:
    def test_dwell_starts_at_the_latest_level_bearing_record(self):
        promoted = _promotion("2026-07-02T00:00:00+00:00")
        ledger = [_bootstrap(), promoted, _planted("2026-07-09T00:00:00+00:00", ON)]
        assert dwell_start_ts(ledger) == promoted.ts
        assert dwell_start_ts(reversed(ledger)) == promoted.ts  # order is not trusted
        assert dwell_start_ts([_planted("2026-07-09T00:00:00+00:00", ON)]) is None
        assert dwell_start_ts([]) is None

    def test_a_reattestation_does_not_restart_dwell(self, backend, monkeypatch):
        _seed(backend, monkeypatch, level=IN)
        (bootstrap,) = _ledger(backend)
        _reattest(backend, monkeypatch)
        grant = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert grant.ts != bootstrap.ts  # the grant's ts moved; the dwell must not

        start = dwell_start_ts(_ledger(backend))
        assert start == bootstrap.ts

        # One hour after the re-attestation, a day and more after the seed.
        now = RESEEDED_AT + datetime.timedelta(hours=1)
        min_dwell = datetime.timedelta(hours=12)

        def eligible(since: str) -> bool:
            return is_eligible_for_promotion(
                grant,
                PromotionEligibilityCounters(clean_runs_since_promotion=5, last_transition_ts=since),
                min_clean_runs=5,
                min_dwell=min_dwell,
                now=now,
            )

        assert eligible(start)
        # What reading dwell off the grant would have said.
        assert not eligible(grant.ts)
