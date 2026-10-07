"""A lapse record carries the term that expired: what the writer puts on it.

#165; GAL §5.2, §6.7.6.

L1: the record carries the grant's term as the exact stored string, on all
three backends. L2: the field is accepted on a promotion and a lapse record and
refused on every other type, at construction. L5: the record's `ts` is the
ledger clock's write instant, equal to the grant's, and never the term.

The clause table and the shared harness are in lapse_term_scaffold.py.
"""

from __future__ import annotations

import datetime
import json

import pytest
from pydantic import ValidationError

from safe_agents.broker.grants.lapse import build_lapse, run_lapse
from safe_agents.broker.grants.ledger_clock import LEDGER_TS_TICK, next_ledger_ts
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.promotion_record import TERM_BEARING_RECORD_TYPES
from safe_agents.broker.tests import lapse_term_scaffold as harness
from safe_agents.broker.tests.lapse_term_scaffold import (
    _SHAPES,
    ODD_TERM,
    PROMOTED_AT,
    _lapse_record,
    _lapses,
    _must_refuse,
    _seeded,
    _typed,
)
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    AFTER,
    PRINCIPAL,
    TERM,
    TERM_DT,
    _grant,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
stores = harness.stores


# ===========================================================================
# L1 — carried, as the exact stored string
# ===========================================================================


@pytest.mark.parametrize("term", [TERM, ODD_TERM], ids=["canonical", "odd-spelling"])
class TestL1Carried:
    def test_the_writer_builds_the_record_with_the_grants_term(self, term):
        grant = _grant(certifiedUntil=term)
        _, record = build_lapse(grant, AFTER)
        assert record.certifiedUntil == term, (
            "L1 CARRIED: build_lapse must copy the grant's certifiedUntil onto the "
            f"lapse record verbatim, got {record.certifiedUntil!r} for {term!r}"
        )

    def test_the_stored_record_carries_it_on_every_backend(self, stores, term):
        grant_store, record_store = _seeded(stores, _grant(certifiedUntil=term))
        stored_term = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.certifiedUntil

        outcome = run_lapse(
            PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
        )

        assert outcome.status == "lapsed", f"L1 CARRIED: the lapse did not land: {outcome.reason}"
        (record,) = _lapses(record_store)
        assert record.certifiedUntil == stored_term == term, (
            "L1 CARRIED: the stored lapse record's certifiedUntil must be the exact "
            f"string stored on the grant that lapsed ({stored_term!r}), got "
            f"{record.certifiedUntil!r}"
        )
        # Where the backend exposes the stored bytes, the term is in them
        # under its own key, and not only inside the evidence string.
        if hasattr(record_store, "stored_data_for"):
            stored = json.loads(record_store.stored_data_for(record))
            assert stored.get("certifiedUntil") == term, (
                "L1 CARRIED: the stored bytes of the lapse record must hold the term "
                f"under the certifiedUntil key, got {stored.get('certifiedUntil')!r}"
            )


# ===========================================================================
# L2 — where the field is allowed
# ===========================================================================

class TestL2WhereAllowed:
    def test_the_matrix_covers_every_record_type(self):
        declared = set(PromotionRecord.model_fields["recordType"].annotation.__args__)
        assert declared == set(_SHAPES), (
            "L2 WHERE ALLOWED: a record type exists that this matrix does not judge: "
            f"{sorted(declared ^ set(_SHAPES))}"
        )
        assert TERM_BEARING_RECORD_TYPES == {"promotion", "lapse"}, (
            "L2 WHERE ALLOWED: only a promotion and a lapse record may carry "
            f"certifiedUntil, the schema names {sorted(TERM_BEARING_RECORD_TYPES)}"
        )

    @pytest.mark.parametrize("record_type", sorted(_SHAPES))
    def test_accepted_on_promotion_and_lapse_and_nowhere_else(self, record_type):
        fields = _typed(record_type)
        without = PromotionRecord(**fields)  # every type validates without a term
        as_stored = json.dumps({**json.loads(canonical_record_payload(without)), "certifiedUntil": TERM})

        if record_type in {"promotion", "lapse"}:
            try:
                built = PromotionRecord(**fields, certifiedUntil=TERM)
                parsed = PromotionRecord.model_validate_json(as_stored)
            except ValidationError as exc:
                pytest.fail(
                    f"L2 WHERE ALLOWED: a {record_type} record must accept "
                    f"certifiedUntil, and the schema refused it: {exc}"
                )
            assert built.certifiedUntil == parsed.certifiedUntil == TERM, (
                f"L2 WHERE ALLOWED: a {record_type} record must accept certifiedUntil, "
                "from its writer and from a reader parsing stored bytes"
            )
            return
        _must_refuse(
            f"L2 WHERE ALLOWED: a {record_type} record must refuse certifiedUntil at construction",
            ValidationError,
            lambda: PromotionRecord(**fields, certifiedUntil=TERM),
        )
        _must_refuse(
            f"L2 WHERE ALLOWED: a reader parsing a stored {record_type} record must refuse "
            "one that carries certifiedUntil",
            ValidationError,
            lambda: PromotionRecord.model_validate_json(as_stored),
        )

    @pytest.mark.parametrize("bad", ["2026-08-01T01:00:00", "2026-08-01T01:00:00+02:00", "soon"])
    def test_a_lapse_records_term_is_still_an_explicit_utc_instant(self, bad):
        _must_refuse(
            f"L2 WHERE ALLOWED: a lapse record must refuse the non-UTC term {bad!r}",
            ValidationError,
            lambda: _lapse_record(certifiedUntil=bad),
        )


# ===========================================================================
# L5 — ts is the write instant, never the term
# ===========================================================================


class TestL5TsIsNotTheTerm:
    @pytest.mark.parametrize(
        "stamp",
        [None, "2031-01-01T00:00:00.000007+00:00", "2026-07-20T00:00:00+00:00"],
        ids=["defaulted", "after-the-term", "before-the-term"],
    )
    def test_the_writer_stamps_the_write_instant(self, stamp):
        """The stamp is the caller's, or ``now``. Nothing floors or caps it at
        the term: a pure caller's stamp earlier than the term is written as
        given, where one derived from the term would come out as the term."""
        grant = _grant()
        updated, record = build_lapse(grant, AFTER, ts=stamp)
        expected = stamp if stamp is not None else AFTER.isoformat()
        assert record.ts == updated.ts == expected, (
            "L5 TS IS NOT THE TERM: build_lapse must stamp record and grant with the "
            f"write instant {expected!r} and derive nothing from the term, got record "
            f"{record.ts!r}, grant {updated.ts!r}"
        )
        assert record.certifiedUntil == TERM, (
            "L5 TS IS NOT THE TERM: the term belongs in certifiedUntil, got "
            f"{record.certifiedUntil!r}"
        )

    @pytest.mark.parametrize("term", [TERM, ODD_TERM], ids=["canonical", "odd-spelling"])
    def test_at_the_boundary_the_stamp_is_still_read_from_the_clock(self, term):
        """Evaluated at the instant the term passes, the two fields name the
        same instant, and honestly so. The stamp is still ``now`` in the
        ledger's spelling: against a term spelled otherwise it is a different
        string, which a stamp copied from the term would not be."""
        updated, record = build_lapse(_grant(certifiedUntil=term), TERM_DT)
        assert record.ts == updated.ts == TERM_DT.isoformat(), (
            "L5 TS IS NOT THE TERM: at now == certifiedUntil the stamp must be the "
            f"evaluation instant {TERM_DT.isoformat()!r} as the ledger spells it, got "
            f"{record.ts!r} beside certifiedUntil {record.certifiedUntil!r}"
        )
        assert record.certifiedUntil == term, (
            "L5 TS IS NOT THE TERM: the term is carried as stored, got "
            f"{record.certifiedUntil!r} for {term!r}"
        )

    @pytest.mark.parametrize(
        "promoted_at",
        [PROMOTED_AT, (AFTER + datetime.timedelta(days=15)).isoformat()],
        ids=["wall-clock-leads", "ledger-leads"],
    )
    def test_the_stored_ts_is_the_ledger_clocks(self, stores, promoted_at):
        """Also where the ledger runs ahead of the wall clock: the stamp then
        advances from the latest record, and still is not the term."""
        grant_store, record_store = _seeded(stores, _grant(), promoted_at=promoted_at)
        expected = next_ledger_ts(record_store, PRINCIPAL, ACTION_CLASS, now=AFTER)
        latest = max(
            datetime.datetime.fromisoformat(r.ts)
            for r in record_store.list_records(PRINCIPAL, ACTION_CLASS)
        )
        assert expected == max(AFTER, latest + LEDGER_TS_TICK).isoformat()

        outcome = run_lapse(
            PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
        )

        assert outcome.status == "lapsed", outcome.reason
        (record,) = _lapses(record_store)
        stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert record.ts == expected, (
            "L5 TS IS NOT THE TERM: the lapse record's ts must be the ledger clock's "
            f"write instant {expected!r}, got {record.ts!r}"
        )
        assert stored.ts == record.ts, (
            "L5 TS IS NOT THE TERM: the grant's ts must equal the lapse record's, got "
            f"grant {stored.ts!r}, record {record.ts!r}"
        )
        assert record.ts != TERM and record.certifiedUntil == TERM, (
            "L5 TS IS NOT THE TERM: the term belongs in certifiedUntil and the write "
            f"instant in ts, got ts {record.ts!r}, certifiedUntil {record.certifiedUntil!r}"
        )

