"""A lapse record carries the term that expired: what it may not do.

#165; GAL §5.2, §6.7.6.

L7: a lapse leaves the grant's `certifiedUntil` and `lastSafeLevel` alone, a
lapse record carrying a longer term buys no extension, and the stores refuse a
lapse write whose record misstates the term or whose grant moves either field.
L8: the audit's ratified-term rule reads promotion records only, and no reader
depends on the `evidence` string.

The clause table and the shared harness are in lapse_term_scaffold.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import safe_agents
from safe_agents.broker.grants.audit import GRANT_TERM_RATIFIED
from safe_agents.broker.grants.lapse import build_lapse, run_lapse
from safe_agents.broker.grants.store import (
    LapseRefusedError,
    TermExtensionRefusedError,
    refuse_lapse_drift,
    refuse_term_extension,
)
from safe_agents.broker.tests import lapse_term_scaffold as harness
from safe_agents.broker.tests import test_grant_term_lapse as base
from safe_agents.broker.tests.lapse_term_scaffold import (
    _SHAPES,
    EARLIER_TERM,
    LATER_TERM,
    ODD_TERM,
    PROMOTED_AT,
    _lapse_record,
    _lapses,
    _must_refuse,
    _seeded,
)
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    AFTER,
    IN,
    ON,
    OUT,
    PRINCIPAL,
    TERM,
    _bootstrap_record,
    _grant,
    _promotion_record,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
stores = harness.stores


# ===========================================================================
# L7 — a lapse still cannot move the term
# ===========================================================================


class TestL7ALapseCannotMoveTheTerm:
    @pytest.mark.parametrize(
        ("level", "floor"), [(ON, IN), (OUT, IN), (OUT, ON)], ids=["on-in", "out-in", "out-on"]
    )
    def test_the_writer_moves_neither_the_term_nor_the_floor(self, level, floor):
        grant = _grant(level=level, lastSafeLevel=floor, certifiedUntil=ODD_TERM)
        updated, _ = build_lapse(grant, AFTER)
        assert (updated.certifiedUntil, updated.lastSafeLevel) == (ODD_TERM, floor), (
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: build_lapse must leave the grant's "
            f"certifiedUntil and lastSafeLevel unchanged, got {updated.certifiedUntil!r} "
            f"and {updated.lastSafeLevel.value!r}"
        )

    def test_the_stored_grant_keeps_both_on_every_backend(self, stores):
        grant_store, record_store = _seeded(stores, _grant(level=OUT, lastSafeLevel=ON))
        run_lapse(
            PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
        )
        stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
        assert (stored.level, stored.certifiedUntil, stored.lastSafeLevel) == (ON, TERM, ON), (
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: after a lapse the stored grant must "
            "carry the same certifiedUntil and lastSafeLevel, got "
            f"{stored.certifiedUntil!r} and {stored.lastSafeLevel.value!r}"
        )

    @pytest.mark.parametrize(
        ("record_term", "grant_changes", "error"),
        [
            # the record and the grant agree on a longer term: the lapse
            # record carrying the field must not read as leave to extend
            (LATER_TERM, {"certifiedUntil": LATER_TERM}, TermExtensionRefusedError),
            (None, {"certifiedUntil": None}, TermExtensionRefusedError),
            # the grant is left alone and the record misstates the term
            (LATER_TERM, {}, LapseRefusedError),
            (EARLIER_TERM, {}, LapseRefusedError),
            # a lapse may not shorten the term, with or without saying so
            (EARLIER_TERM, {"certifiedUntil": EARLIER_TERM}, LapseRefusedError),
            (None, {"certifiedUntil": EARLIER_TERM}, LapseRefusedError),
            # the same instant in another spelling is still another string:
            # the record's term is the grant's stored bytes, and a lapse does
            # not respell what the checker ratified
            (ODD_TERM, {}, LapseRefusedError),
            (ODD_TERM, {"certifiedUntil": ODD_TERM}, LapseRefusedError),
            (None, {"certifiedUntil": ODD_TERM}, LapseRefusedError),
        ],
        ids=[
            "both-longer", "both-dropped", "record-longer", "record-earlier",
            "both-shorter", "grant-shorter-record-silent", "record-respelled",
            "both-respelled", "grant-respelled-record-silent",
        ],
    )
    def test_the_stores_refuse_a_lapse_write_that_moves_or_misstates_the_term(
        self, stores, record_term, grant_changes, error
    ):
        self._refused(
            stores, _grant(level=OUT, lastSafeLevel=ON), record_term, grant_changes, error
        )

    @pytest.mark.parametrize(
        ("floor", "moved_to"), [(ON, IN), (IN, ON)], ids=["lowered", "raised"]
    )
    def test_the_stores_refuse_a_lapse_write_that_moves_the_floor(self, stores, floor, moved_to):
        """In both directions. Raised is the one that confers authority: every
        later lapse or standing failure would land on the higher floor."""
        self._refused(
            stores,
            _grant(level=OUT, lastSafeLevel=floor),
            TERM,
            {"lastSafeLevel": moved_to},
            LapseRefusedError,
        )

    @staticmethod
    def _refused(stores, grant, record_term, grant_changes, error):
        grant_store, record_store = _seeded(stores, grant)
        read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
        updated, honest = build_lapse(grant, AFTER)
        record = honest.model_copy(update={"certifiedUntil": record_term})
        written = updated.model_copy(update=grant_changes)

        _must_refuse(
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: the store must refuse a lapse write "
            f"with record term {record_term!r} and grant changes {grant_changes!r}",
            error,
            lambda: grant_store.write_record_and_grant(
                record, written, record_store, expected=read
            ),
        )
        assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).raw_data == read.raw_data, (
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: a refused lapse write must leave "
            "the stored grant's bytes unchanged"
        )
        assert _lapses(record_store) == [], (
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: a refused lapse write must append "
            "no record"
        )

    def test_the_term_rule_exempts_a_promotion_by_type_and_nothing_else(self):
        """refuse_term_extension is keyed on the record's type. A lapse record
        carrying certifiedUntil is still a lapse record."""
        stored = base.canonical_grant_payload(_grant())
        longer = _grant(certifiedUntil=LATER_TERM)
        refuse_term_extension(stored, longer, record_type="promotion")
        for record_type in sorted(set(_SHAPES) - {"promotion"}):
            _must_refuse(
                f"L7 A LAPSE STILL CANNOT MOVE THE TERM: a {record_type} write must not "
                "lengthen a term",
                TermExtensionRefusedError,
                lambda record_type=record_type: refuse_term_extension(
                    stored, longer, record_type=record_type
                ),
            )

    def test_the_lapse_guard_is_a_no_op_for_other_record_types(self):
        """It holds a lapse write. It must not start refusing the ceremony,
        which is the one path that does set a term."""
        stored = base.canonical_grant_payload(_grant(level=IN))
        promoted = _grant(certifiedUntil=LATER_TERM)
        refuse_lapse_drift(stored, _promotion_record(PROMOTED_AT, certified_until=LATER_TERM), promoted)
        _must_refuse(
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: the same write under a lapse record "
            "is refused",
            LapseRefusedError,
            lambda: refuse_lapse_drift(stored, _lapse_record(certifiedUntil=LATER_TERM), promoted),
        )

    def test_a_lapse_that_creates_a_grant_cannot_name_a_term_it_lacks(self):
        _must_refuse(
            "L7 A LAPSE STILL CANNOT MOVE THE TERM: with no stored grant, a lapse "
            "record's term must still be the term on the grant written beside it",
            LapseRefusedError,
            lambda: refuse_lapse_drift(
                None, _lapse_record(certifiedUntil=LATER_TERM), _grant(level=IN)
            ),
        )


# ===========================================================================
# L8 — nobody misreads it
# ===========================================================================

_BOOT = _bootstrap_record(_grant())
_PROMO = _promotion_record(PROMOTED_AT)
_BARE_PROMO = _promotion_record(PROMOTED_AT, certified_until=None)
_LAPSED = dict(level=IN, demotionReason="pending-evidence")
# A term a second ceremony ratifies, after the first one lapsed.
RENEWED_AT = "2026-09-02T00:00:00+00:00"
RENEWED_TERM = "2027-01-01T00:00:00+00:00"


def _ledger(*promotions, lapse_term):
    """Deferred, so the lapse record is built when a test runs and a schema
    that refused it fails that test by name instead of the module's collection."""
    return lambda: [_BOOT, *promotions, _lapse_record(certifiedUntil=lapse_term)]


class TestL8NobodyMisreadsIt:
    @pytest.mark.parametrize(
        ("grant_term", "ledger", "fires"),
        [
            # the honest ledger: promotion and lapse both carry the grant's term
            (TERM, _ledger(_PROMO, lapse_term=TERM), False),
            # a lapse record naming another term does not un-ratify the grant's
            (TERM, _ledger(_PROMO, lapse_term=LATER_TERM), False),
            # a term nobody ratified is not excused by a lapse record naming it
            (LATER_TERM, _ledger(_PROMO, lapse_term=LATER_TERM), True),
            (EARLIER_TERM, _ledger(_PROMO, lapse_term=EARLIER_TERM), True),
            # nor where the promotion ratified NO term: the lapse record's is
            # not a fallback for the one the checker left unset
            (TERM, _ledger(_BARE_PROMO, lapse_term=TERM), True),
            (None, _ledger(_BARE_PROMO, lapse_term=TERM), False),
            # no promotion at all: a lapse record's term ratifies nothing
            (TERM, _ledger(lapse_term=TERM), True),
            (None, _ledger(lapse_term=TERM), False),
        ],
        ids=[
            "honest", "lapse-names-another-term", "unratified-longer", "unratified-shorter",
            "promotion-bare-grant-termed", "promotion-bare-grant-bare",
            "no-promotion-grant-termed", "no-promotion-grant-bare",
        ],
    )
    def test_the_ratified_term_rule_reads_promotion_records_only(self, grant_term, ledger, fires):
        found = GRANT_TERM_RATIFIED in base._term_audit(
            _grant(certifiedUntil=grant_term, **_LAPSED), ledger()
        )
        assert found is fires, (
            "L8 NOBODY MISREADS IT: GRANT_TERM_RATIFIED must judge the grant's term "
            "against the latest promotion record and never against a lapse record's "
            f"certifiedUntil (grant term {grant_term!r}, expected finding: {fires})"
        )

    @pytest.mark.parametrize(
        ("grant_term", "fires"),
        [(RENEWED_TERM, False), (TERM, True), (None, True)],
        ids=["renewed-term", "the-lapsed-term", "no-term"],
    )
    def test_after_a_re_promotion_the_ratified_term_is_the_latest_promotions(
        self, grant_term, fires
    ):
        """A term lapses and a second ceremony ratifies a new one. The ledger
        then holds three terms in order: the first promotion's, the lapse
        record's restatement of it, and the second promotion's. The grant is
        held to the last of those, which is neither the first promotion's nor
        the latest record's that happens to carry a term."""
        records = [
            _BOOT,
            _PROMO,
            _lapse_record(certifiedUntil=TERM),
            _promotion_record(RENEWED_AT, certified_until=RENEWED_TERM),
            # a second lapse record, so the latest term-bearing record on the
            # ledger is not a promotion either
            _lapse_record(certifiedUntil=RENEWED_TERM, ts="2027-01-02T00:00:00+00:00"),
        ]
        found = GRANT_TERM_RATIFIED in base._term_audit(
            _grant(certifiedUntil=grant_term, **_LAPSED), records
        )
        assert found is fires, (
            "L8 NOBODY MISREADS IT: GRANT_TERM_RATIFIED must hold the grant to the "
            "term on the chronologically-latest promotion record, not an earlier "
            f"promotion's and not a lapse record's (grant term {grant_term!r}, "
            f"expected finding: {fires})"
        )

    def test_the_audit_does_not_depend_on_the_evidence_string(self):
        """Two ledgers that differ only in what the lapse record's evidence
        says, one of them naming a different term, audit the same."""
        grant = _grant(**_LAPSED)
        verdicts = [
            base._term_audit(grant, [_BOOT, _PROMO, _lapse_record(certifiedUntil=TERM, evidence=text)])
            for text in (
                f"certification term expired: certifiedUntil={TERM}",
                f"certification term expired: certifiedUntil={LATER_TERM}",
                "nothing a parser could use",
            )
        ]
        assert verdicts[0] == verdicts[1] == verdicts[2] == set(), (
            "L8 NOBODY MISREADS IT: the audit must not read a term out of a lapse "
            f"record's evidence string, got {verdicts}"
        )

    def test_only_the_writer_knows_the_evidence_wording(self):
        """Source-level: the phrase build_lapse writes into evidence appears in
        one shipped module, the one that writes it. A reader that matched on it
        would have to spell it. This catches a parser of that wording and not
        one that splits evidence some other way."""
        package = Path(safe_agents.__file__).parent
        naming = sorted(
            path.relative_to(package).as_posix()
            for path in package.rglob("*.py")
            if "tests" not in path.parts
            and "certification term expired:" in path.read_text(encoding="utf-8")
        )
        assert naming == ["broker/grants/lapse.py"], (
            "L8 NOBODY MISREADS IT: only the lapse writer may know the wording of a "
            f"lapse record's evidence, it appears in {naming}"
        )
