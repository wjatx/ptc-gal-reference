"""The audit holds a stored lapse record's term to the ratified one (#183).

GAL §6.11, GAL-44. The lapse writer copies the grant's term onto the record,
and the stores' paired write refuses a lapse record naming any other. Neither
sees a lapse record that reached the ledger another way, so the audit rule
LAPSE_TERM_RATIFIED re-derives the term from the ledger. Each clause below is
one property of that rule, and each assertion names its clause when it fails.

| Clause | Guarantee |
|---|---|
| **A1** | RATIFIED: a lapse record whose `certifiedUntil` is not, as the stored string, the term on the latest promotion record before it at its coordinate is a finding that names the coordinate and both terms. A promotion that ratified no term counts as ratifying none. |
| **A2** | NOTHING RATIFIED: a lapse record carrying a term at a coordinate with no promotion record before it is a finding. |
| **A3** | NOT AFTER ITSELF: a lapse record whose `certifiedUntil` is later than its own `ts` is a finding, whatever the promotion ratified. Equal is not. |
| **A4** | AN HONEST LEDGER PASSES: lapse records carrying the term their promotion ratified, carrying none, or following a re-promotion are not findings. |
| **A5** | BY INSTANT: "before" and "latest" are by parsed `ts`, never by list order or string order, and a `ts` the judgement needs that is not an instant is a finding, never a crash and never a skip. A lapse record carrying no term is not judged. |
| **A6** | UN-WAIVABLE, AND ALWAYS RUN: the rule is outside the closed waivable vocabulary, a verified acknowledgment naming it waives nothing, and it runs with no key of any kind. |

A1 to A5 are pinned here over hand-built ledgers, A6 here and over the real
acknowledgment ceremony in test_grants_lapse_term_audit_ledger.py, which also
pins A1 and A4 over the real writers on all three store backends.

Each hand-built ledger is judged three ways: through ``run_audit``, and by
``lapse_term_findings`` directly over the records as written and reversed.
``run_audit`` hands the rule a coordinate's records sorted by stored ``ts``
string, so only a direct call can show that list order decides nothing.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.grants.acknowledgments import WAIVABLE_RULES
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_NOT_WAIVABLE,
    LAPSE_TERM_RATIFIED,
    AuditDataset,
    run_audit,
)
from safe_agents.broker.grants.audit_lapse_term import lapse_term_findings
from safe_agents.broker.grants.store import _principal_key
from safe_agents.broker.tests import test_record_signing_roles as signing_roles
from safe_agents.broker.tests.grant_ts_scaffold import dataset
from safe_agents.broker.tests.lapse_term_scaffold import (
    EARLIER_TERM,
    LATER_TERM,
    ODD_TERM,
    PROMOTED_AT,
    _lapse_record,
)
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    AFTER,
    PRINCIPAL,
    TERM,
    _bootstrap_record,
    _grant,
    _promotion_record,
)
from safe_agents.broker.tests.test_record_signing_roles import _acknowledgment

#: The two-key fixture, re-bound so pytest resolves it by name here.
roles = signing_roles.roles

COORDINATE = f"{_principal_key(PRINCIPAL)}#{ACTION_CLASS}"

# The fragment of a finding's detail that names each branch of the rule. A
# test reads the branch from the detail, so a mutant that reports the wrong
# reason fails as surely as one that reports nothing.
RATIFIED = "but the latest promotion record before it"
NOTHING_RATIFIED = "no promotion record precedes it"
AFTER_ITSELF = "later than the record's own ts"
UNESTABLISHED = "cannot be held to the ledger"
_BRANCHES = {
    RATIFIED: "A1",
    NOTHING_RATIFIED: "A2",
    AFTER_ITSELF: "A3",
    UNESTABLISHED: "A5",
}

LAPSED_AT = AFTER.isoformat()  # 2026-08-31T01:00:00+00:00, a month after TERM
LATE_LAPSE = "2026-09-02T00:00:00+00:00"  # after LATER_TERM, so A3 stays quiet
DISTANT_TERM = "2026-12-01T00:00:00+00:00"  # after LAPSED_AT
RENEWED_AT = "2026-09-02T00:00:00+00:00"
RENEWED_TERM = "2027-01-01T00:00:00+00:00"
RENEWED_LAPSE = "2027-01-02T00:00:00+00:00"
NOT_AN_INSTANT = "the day after the term"
# Two stamps whose string order is the reverse of their instant order:
# STRING_LATEST sorts last and is midnight UTC on the 10th, INSTANT_LATEST
# sorts first and is 04:00 UTC on the 10th.
STRING_LATEST = "2026-07-10T00:00:00+00:00"
INSTANT_LATEST = "2026-07-09T23:00:00-05:00"
# A naive stamp is read as UTC by the ledger clock (ledger_clock._recorded_instant).
NAIVE_BEFORE_THE_TERM = "2026-08-01T00:59:59.999999"
NAIVE_AT_THE_TERM = "2026-08-01T01:00:00"
# Past datetime's range once the offset is applied.
OVERFLOWS = "9999-12-31T23:59:59-05:00"

_BOOT = _bootstrap_record(_grant())


def _promo(ts: str = PROMOTED_AT, term: str | None = TERM):
    return _promotion_record(ts, certified_until=term)


def _lapse(term: str | None = TERM, ts: str = LAPSED_AT):
    return _lapse_record(certifiedUntil=term, ts=ts)


def _clauses(details) -> list[str]:
    """The clause each finding detail was reported under."""
    found = []
    for detail in details:
        named = [clause for fragment, clause in _BRANCHES.items() if fragment in detail]
        assert len(named) == 1, f"one branch per finding, got {named}: {detail}"
        found.extend(named)
    return sorted(found)


def _branches(report) -> list[str]:
    """The clause each LAPSE_TERM_RATIFIED finding in a report was reported under."""
    findings = [v for v in report.violations if v.rule == LAPSE_TERM_RATIFIED]
    for violation in findings:
        assert violation.coordinate == COORDINATE, (
            f"A1: the finding must name the coordinate {COORDINATE!r}, got "
            f"{violation.coordinate!r}"
        )
    return _clauses(v.detail for v in findings)


def _audit(records, **kwargs):
    return run_audit(dataset(None, records), **kwargs)


# (id, records, the clauses its findings must be reported under)
LEDGERS = [
    # A4 — honest ledgers
    ("honest", lambda: [_BOOT, _promo(), _lapse()], []),
    ("honest-lapse-names-no-term", lambda: [_BOOT, _promo(), _lapse(None)], []),
    ("honest-written-at-the-term", lambda: [_BOOT, _promo(), _lapse(ts=TERM)], []),
    ("honest-bare-promotion-bare-lapse", lambda: [_BOOT, _promo(term=None), _lapse(None)], []),
    ("honest-no-promotion-bare-lapse", lambda: [_BOOT, _lapse(None)], []),
    (
        # a lapse, a second ceremony, a second lapse: each lapse record is held
        # to the promotion before IT, never to a later one
        "honest-renewed",
        lambda: [
            _BOOT,
            _promo(),
            _lapse(),
            _promo(RENEWED_AT, RENEWED_TERM),
            _lapse(RENEWED_TERM, ts=RENEWED_LAPSE),
        ],
        [],
    ),
    # A1 — the term is not the one ratified before it
    ("later-term", lambda: [_BOOT, _promo(), _lapse(LATER_TERM, ts=LATE_LAPSE)], ["A1"]),
    (
        # the attack, then an honest renewal and its lapse: every lapse record
        # is judged, not only the coordinate's latest one
        "planted-lapse-then-an-honest-one",
        lambda: [
            _BOOT,
            _promo(),
            _lapse(LATER_TERM, ts=LATE_LAPSE),
            _promo("2026-09-03T00:00:00+00:00", RENEWED_TERM),
            _lapse(RENEWED_TERM, ts=RENEWED_LAPSE),
        ],
        ["A1"],
    ),
    (
        "planted-lapse-replayed",
        lambda: [
            _BOOT,
            _promo(),
            _lapse(LATER_TERM, ts=LATE_LAPSE),
            _lapse(LATER_TERM, ts=LATE_LAPSE),
        ],
        ["A1", "A1"],
    ),
    ("earlier-term", lambda: [_BOOT, _promo(), _lapse(EARLIER_TERM)], ["A1"]),
    # the same instant in another spelling is another string: the writer copies
    # the term verbatim, so a respelled one was not written by it
    ("respelled-term", lambda: [_BOOT, _promo(), _lapse(ODD_TERM)], ["A1"]),
    ("promotion-ratified-no-term", lambda: [_BOOT, _promo(term=None), _lapse()], ["A1"]),
    (
        # the latest promotion before it, not the first
        "names-an-earlier-promotions-term",
        lambda: [
            _BOOT,
            _promo(),
            _promo("2026-07-10T00:00:00+00:00", EARLIER_TERM),
            _lapse(TERM),
        ],
        ["A1"],
    ),
    (
        # two promotions at one instant that disagree: no single term was
        # ratified, so neither of them excuses the lapse record
        "two-promotions-at-one-instant-disagree",
        lambda: [
            _BOOT,
            _promo("2026-07-10T00:00:00+00:00", TERM),
            _promo("2026-07-10T00:00:00Z", EARLIER_TERM),
            _lapse(TERM),
        ],
        ["A1"],
    ),
    # A2 — nothing before it ratified a term
    ("no-promotion", lambda: [_BOOT, _lapse()], ["A2"]),
    ("no-record-but-the-lapse", lambda: [_lapse()], ["A2"]),
    ("only-a-later-promotion", lambda: [_BOOT, _lapse(), _promo(RENEWED_AT, TERM)], ["A2"]),
    # "before" is strict: the writer stamps every record past the last one
    ("promotion-at-the-same-instant", lambda: [_BOOT, _promo(LAPSED_AT), _lapse()], ["A2"]),
    # A3 — the term follows the record that says it passed
    (
        "term-after-the-record",
        lambda: [_BOOT, _promo(term=DISTANT_TERM), _lapse(DISTANT_TERM)],
        ["A3"],
    ),
    ("later-term-before-it-passed", lambda: [_BOOT, _promo(), _lapse(LATER_TERM)], ["A1", "A3"]),
    ("no-promotion-and-after-the-record", lambda: [_BOOT, _lapse(LATER_TERM)], ["A2", "A3"]),
    (
        # written at the promotion's own instant in another spelling: not
        # before it, and before the term
        "lapse-at-the-promotions-instant-respelled",
        lambda: [_BOOT, _promo(), _lapse(ts="2026-07-02T00:00:00Z")],
        ["A2", "A3"],
    ),
    (
        "naive-ts-a-microsecond-before-the-term",
        lambda: [_BOOT, _promo(), _lapse(ts=NAIVE_BEFORE_THE_TERM)],
        ["A3"],
    ),
    ("naive-ts-at-the-term", lambda: [_BOOT, _promo(), _lapse(ts=NAIVE_AT_THE_TERM)], []),
    # A5 — by instant, never by string; unreadable is a finding
    (
        # "...T05:00:00+05:00" sorts after the lapse's ts as a string and is
        # midnight UTC, an hour before it
        "before-by-instant-not-string",
        lambda: [_BOOT, _promo("2026-08-31T05:00:00+05:00"), _lapse()],
        [],
    ),
    (
        # "...-30T23:00:00-05:00" sorts before the lapse's ts as a string and
        # is 04:00 UTC on the 31st, three hours after it: the renewed term is
        # not the one before the lapse
        "after-by-instant-not-string",
        lambda: [_BOOT, _promo(), _promo("2026-08-30T23:00:00-05:00", RENEWED_TERM), _lapse()],
        [],
    ),
    (
        # two promotions before the lapse whose string order is the reverse of
        # their instant order: the latest is INSTANT_LATEST's. Written with the
        # instant-earlier one last, and run_audit sorts it last as well.
        "latest-by-instant-not-string",
        lambda: [
            _BOOT,
            _promo(INSTANT_LATEST, EARLIER_TERM),
            _promo(STRING_LATEST, TERM),
            _lapse(EARLIER_TERM),
        ],
        [],
    ),
    (
        "names-the-string-latest-promotions-term",
        lambda: [
            _BOOT,
            _promo(INSTANT_LATEST, EARLIER_TERM),
            _promo(STRING_LATEST, TERM),
            _lapse(TERM),
        ],
        ["A1"],
    ),
    ("lapse-ts-not-an-instant", lambda: [_BOOT, _promo(), _lapse(ts=NOT_AN_INSTANT)], ["A5"]),
    ("promotion-ts-not-an-instant", lambda: [_BOOT, _promo(NOT_AN_INSTANT), _lapse()], ["A5"]),
    ("lapse-ts-empty", lambda: [_BOOT, _promo(), _lapse(ts="")], ["A5"]),
    ("lapse-ts-overflows", lambda: [_BOOT, _promo(), _lapse(ts=OVERFLOWS)], ["A5"]),
    (
        "a-lapse-with-no-term-is-not-judged",
        lambda: [_BOOT, _promo(NOT_AN_INSTANT), _lapse(None, ts=NOT_AN_INSTANT)],
        [],
    ),
]


_JUDGED = {
    "run_audit": lambda ledger: _branches(_audit(ledger)),
    "direct-as-written": lambda ledger: _clauses(lapse_term_findings(ledger)),
    "direct-reversed": lambda ledger: _clauses(lapse_term_findings(ledger[::-1])),
}


@pytest.mark.parametrize("judged", list(_JUDGED))
@pytest.mark.parametrize(("records", "expected"), [row[1:] for row in LEDGERS], ids=[row[0] for row in LEDGERS])
def test_each_lapse_record_is_held_to_the_term_ratified_before_it(records, expected, judged):
    clauses = ", ".join(expected) or "A4"
    try:
        found = _JUDGED[judged](records())
    except AssertionError:
        raise
    except Exception as exc:
        pytest.fail(
            f"{clauses}: LAPSE_TERM_RATIFIED raised instead of reporting {expected} "
            f"({judged}): {exc!r}"
        )
    assert found == expected, (
        f"{clauses}: LAPSE_TERM_RATIFIED reported under {found}, expected {expected} ({judged})"
    )


@pytest.mark.parametrize(
    ("ratified", "named", "lapsed_at"),
    [
        (TERM, LATER_TERM, LATE_LAPSE),
        (TERM, EARLIER_TERM, LAPSED_AT),
        (None, TERM, LAPSED_AT),
    ],
    ids=["later", "earlier", "ratified-none"],
)
def test_the_finding_names_both_terms(ratified, named, lapsed_at):
    report = _audit([_BOOT, _promo(term=ratified), _lapse(named, ts=lapsed_at)])
    (detail,) = [v.detail for v in report.violations if v.rule == LAPSE_TERM_RATIFIED]
    ratified_label = repr(ratified) if ratified is not None else "no term"
    assert repr(named) in detail and f"ratified {ratified_label}" in detail, (
        f"A1: the finding must name the term the lapse record states ({named!r}) and "
        f"the one ratified before it ({ratified_label}): {detail}"
    )
    assert repr(PROMOTED_AT) in detail and repr(lapsed_at) in detail, (
        f"A1: the finding must name the lapse record and the promotion it was held to: {detail}"
    )


def test_a_ts_that_is_not_an_instant_is_named_and_does_not_crash():
    report = _audit([_BOOT, _promo(NOT_AN_INSTANT), _lapse(ts=NOT_AN_INSTANT)])
    (detail,) = [v.detail for v in report.violations if v.rule == LAPSE_TERM_RATIFIED]
    assert detail.count(repr(NOT_AN_INSTANT)) >= 2, (
        f"A5: both unreadable stamps must be named, the lapse's and the promotion's: {detail}"
    )


def test_where_latest_is_not_established_the_finding_still_names_the_terms():
    """A planted promotion whose ts is not an instant leaves "latest" unknown,
    and the finding still names the term the lapse record states beside every
    term a promotion record at the coordinate ratified."""
    report = _audit(
        [_BOOT, _promo(), _promo(NOT_AN_INSTANT, EARLIER_TERM), _lapse(LATER_TERM, ts=LATE_LAPSE)]
    )
    (detail,) = [v.detail for v in report.violations if v.rule == LAPSE_TERM_RATIFIED]
    missing = [t for t in (LATER_TERM, TERM, EARLIER_TERM) if repr(t) not in detail]
    assert not missing, (
        f"A1, A5: with latest unestablished the finding must still name the lapse's term "
        f"and every term ratified at the coordinate, missing {missing}: {detail}"
    )


# ===========================================================================
# A6 — un-waivable, and always run
# ===========================================================================


def test_the_rule_is_not_in_the_waivable_vocabulary():
    assert LAPSE_TERM_RATIFIED not in WAIVABLE_RULES, (
        "A6 UN-WAIVABLE: GAL §6.11 forbids acknowledging a lapse record that "
        "misstates its term, and the rule is in WAIVABLE_RULES"
    )


def test_it_runs_with_no_key_of_any_kind():
    report = _audit([_BOOT, _promo(), _lapse(LATER_TERM, ts=LATE_LAPSE)])
    assert LAPSE_TERM_RATIFIED not in report.skipped_rules
    assert _branches(report) == ["A1"], (
        "A6 ALWAYS RUN: with no HMAC key and no verify keys the rule must still "
        f"report the planted term, got {report.violations}"
    )


def test_a_verified_acknowledgment_waives_nothing(roles):
    issuer_signer, _, resolvers = roles
    planted = [_BOOT, _promo(), _lapse(LATER_TERM, ts=LATE_LAPSE)]
    (finding,) = [
        v for v in _audit(planted).violations if v.rule == LAPSE_TERM_RATIFIED
    ]
    base = dataset(None, planted)
    acknowledged = AuditDataset(
        records=base.records, acknowledgments=(_acknowledgment(finding, issuer_signer),)
    )
    report = run_audit(acknowledged, record_key_resolver=resolvers)

    assert finding in report.violations, (
        "A6 UN-WAIVABLE: a lapse record misstating its term must stay a violation "
        f"under an issuer-signed acknowledgment of its exact detail: {report.violations}"
    )
    assert not report.acknowledged, f"A6: nothing may be acknowledged: {report.acknowledged}"
    assert ACKNOWLEDGMENT_NOT_WAIVABLE in {v.rule for v in report.violations}, (
        "A6: the acknowledgment naming an un-waivable rule must itself be reported"
    )
