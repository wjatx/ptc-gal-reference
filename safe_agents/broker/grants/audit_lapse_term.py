"""grants.audit_lapse_term — a stored lapse record's term is the ratified one.

GAL §6.11, GAL-44 (#183). Since #165 a ``lapse`` record may carry the term that
expired as ``certifiedUntil``, and GAL §5.2 tells a reader to take the instant
enforcement fell from that field. On the sanctioned path the value is held true
twice: the lapse writer copies the grant's stored term (``grants.lapse``), and
every backend's paired grant-and-record write refuses a lapse record naming any
other term (``store.refuse_lapse_drift``). Neither sees a record that reached
the ledger another way: appended through a record store alone, by a holder of
the evaluator's key, or by anyone with write access to a ledger that has not
adopted signing. This module is the read-side check that does see it, run by
``grants.audit.run_audit`` as LAPSE_TERM_RATIFIED.

For each lapse record that carries a term, three things are judged:

  * the term equals, as the stored string, the term on the latest
    ``promotion`` record before it at its coordinate. "Before" and "latest" are
    by parsed instant, never list order or string order. A promotion that
    ratified no term ratifies no term here either: a lapse record after it may
    carry none;
  * where no promotion record precedes it, it carries no term, because nothing
    at its coordinate ratified one;
  * the term is not later than the record's own ``ts``. A lapse is owed once
    the evaluation instant reaches the term (``term.term_passed``) and its
    record is stamped at or after that instant (GAL §5.2), so a term after the
    record says enforcement fell after the record that says it fell.

Where a ``ts`` this judgement depends on (the lapse record's own, or a
promotion record's at the coordinate) is not an instant, "before" is not
established, and that is a finding rather than a skip: a planted row must not
decide for itself whether it is counted. That finding names the term the lapse
record states and every term a promotion record at the coordinate ratified,
since which of them is latest is the thing it cannot say.

A lapse record that carries no term is not judged. The field is optional
(GAL §5.2), and lapse records written before it existed carry none.

What this buys, and no more: the ledger cannot state a lapse term that its own
promotion records do not account for. It does not say the promotion record is
genuine (RECORD_SIGNATURE_VERIFIES asks that), and it does not say a lapse was
owed at all. The auditor takes no clock.

Read-side limit, stated for the next change to the evaluator: the third check
reads the writer as it stands, with no skew allowance. GAL §6.7.6's skew rule
(#175, not implemented) lets a term be treated as effective up to a declared
bound early, and a writer built on it may stamp a lapse record before the term
by up to that bound. That change has to carry the bound into this check.

Pure: no store, no key, no clock. It runs in every audit mode, keyless
included. Every finding it returns is un-waivable (the rule is not in
``acknowledgments.WAIVABLE_RULES``), as GRANT_TERM_RATIFIED's is: a misstated
term is a misstatement of authority, and GAL §6.11 forbids a waiver for it.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

from safe_agents.broker.grants.ledger_clock import (
    _recorded_instant,  # the SAME reading of a stored ts the ledger clock takes
)
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.grant import parse_certified_until

LAPSE_RECORD_TYPE = "lapse"
PROMOTION_RECORD_TYPE = "promotion"


def _instant(value: object) -> datetime.datetime | None:
    """A stored ts as an instant, or None where it names none (never a crash)."""
    try:
        return _recorded_instant(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _term_instant(value: str) -> datetime.datetime | None:
    """A term as an instant, by the parser every term reader uses.

    The schema already refuses a record whose term this rejects, so None is
    reachable only for an entry built in memory without validation."""
    try:
        return parse_certified_until(value)
    except (TypeError, ValueError):
        return None


def _term_label(term: str | None) -> str:
    return "no term" if term is None else repr(term)


def lapse_term_findings(coordinate_records: Sequence[PromotionRecord]) -> list[str]:
    """One detail string per breach, for the lapse records at ONE coordinate.

    ``coordinate_records`` is every record at the coordinate, in any order:
    nothing here depends on it. An empty list means no breach.
    """
    promotions = [
        (record, _instant(record.ts))
        for record in coordinate_records
        if record.recordType == PROMOTION_RECORD_TYPE
    ]
    unreadable_promotions = sorted(repr(r.ts) for r, at in promotions if at is None)
    # Where "latest" cannot be established, the finding still names every term
    # a promotion record here ratified, so a reader sees the candidates beside
    # the term the lapse record states.
    candidates = (
        "the promotion records there ratified "
        + ", ".join(sorted({_term_label(r.certifiedUntil) for r, _ in promotions}))
        if promotions
        else "there is no promotion record there"
    )
    findings: list[str] = []
    for lapse in coordinate_records:
        if lapse.recordType != LAPSE_RECORD_TYPE or lapse.certifiedUntil is None:
            continue
        named = lapse.certifiedUntil
        at = _instant(lapse.ts)
        from_level = lapse.fromLevel.value if lapse.fromLevel is not None else "no grant"
        where = (
            f"lapse record ts={lapse.ts!r} ({from_level} -> {lapse.toLevel.value}) "
            f"names the term {named!r}"
        )

        unreadable = ([repr(lapse.ts)] if at is None else []) + unreadable_promotions
        if unreadable:
            findings.append(
                f"{where}, which cannot be held to the ledger: the ts "
                f"{', '.join(unreadable)} at its coordinate is not an instant, so the "
                f"latest promotion record before it is not established ({candidates})"
            )
            continue

        term_at = _term_instant(named)
        if term_at is None:
            findings.append(f"{where}, which is not an explicit UTC instant")
        elif term_at > at:
            findings.append(
                f"{where}, which is later than the record's own ts: a lapse is written "
                "at or after the instant its term passed, so the term it names cannot "
                "follow the record"
            )

        earlier = [(record, when) for record, when in promotions if when < at]
        if not earlier:
            findings.append(
                f"{where}, but no promotion record precedes it at its coordinate, so no "
                "term was ratified there and a lapse record carries none"
            )
            continue
        latest = max(when for _, when in earlier)
        latest_promotions = [record for record, when in earlier if when == latest]
        ratified = {record.certifiedUntil for record in latest_promotions}
        if ratified != {named}:
            # Two promotion records at one instant is not a ledger the writer
            # makes (the ledger clock stamps each record past the last one), so
            # where they disagree no single ratified term exists and the
            # lapse record cannot match it.
            stamps = ", ".join(sorted(repr(record.ts) for record in latest_promotions))
            terms = ", ".join(sorted(_term_label(term) for term in ratified))
            findings.append(
                f"{where}, but the latest promotion record before it (ts={stamps}) "
                f"ratified {terms}; a lapse record names the term that expired, which "
                "is the one the checker ratified"
            )
    return findings
