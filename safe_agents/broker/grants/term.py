"""grants.term — the certification term, judged against an explicit instant (#255).

GAL §6.7.6: a grant MAY carry a term (``Grant.certifiedUntil``). Once the term
has passed, the level it certified is no longer certified and the grant lapses
to ``lastSafeLevel``. This module holds the PURE half of that arc: whether a
term has passed, what level a grant is effectively at, and whether a proposed
change would lengthen a term. The write half (appending the lapse record) is
``grants.lapse``.

The evaluation instant is an INPUT, never derived.
    Every function here takes ``now`` explicitly and has no default. Whether a
    term has passed is judged against that instant alone — never against the
    grant's ``ts``, any ledger record's ``ts``, the audit tape, or "the latest
    record seen". Those timestamps say when something was WRITTEN; a quiet log
    writes nothing, and a quiet log is exactly the case this arc exists for (an
    idle grant nobody renews). An evaluator that read time from the records
    would never see an idle grant's term pass. Only the outermost caller (the
    broker's PIP, the lapse runner's CLI) falls back to the wall clock, the same
    shape as ``commands._utc_now`` and ``PromotionCeremony.execute(now=...)``.

The boundary is inclusive: the term has passed iff ``now >= certifiedUntil``
(the same comparison ``proposals.proposal_expired`` uses for proposal expiry).
"""

from __future__ import annotations

import datetime

from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.grant import parse_certified_until

_LEVEL_RANK: dict[AutonomyLevel, int] = {
    AutonomyLevel.in_loop: 0,
    AutonomyLevel.on_loop: 1,
    AutonomyLevel.out_of_loop: 2,
}


def _require_aware(now: datetime.datetime) -> datetime.datetime:
    """Refuse a naive instant: a lapse boundary must not depend on local time."""
    if not isinstance(now, datetime.datetime):
        raise TypeError(
            f"now must be a datetime.datetime, got {type(now).__name__}; the "
            "evaluation instant is an explicit input (grants/term.py)"
        )
    if now.tzinfo is None:
        raise ValueError(
            "now must be timezone-aware (UTC); a naive instant would make the "
            "lapse boundary depend on the host's local time"
        )
    return now


def term_passed(grant: Grant, now: datetime.datetime) -> bool:
    """True iff the grant carries a term and ``now >= certifiedUntil``.

    Pure. A grant with no term never lapses, at any ``now`` (GAL-34).
    """
    _require_aware(now)
    if grant.certifiedUntil is None:
        return False
    return now >= parse_certified_until(grant.certifiedUntil)


def lapse_pending(grant: Grant, now: datetime.datetime) -> bool:
    """True iff the term has passed AND the stored level is above lastSafeLevel.

    That is exactly "a lapse record is owed": a grant already at or below its
    lastSafeLevel has nothing to lapse, and re-evaluating a grant the lapse
    writer already lowered is a no-op (idempotence falls out of the stored
    level, never out of reading the ledger).
    """
    return term_passed(grant, now) and (
        _LEVEL_RANK[grant.level] > _LEVEL_RANK[grant.lastSafeLevel]
    )


def effective_level(grant: Grant, now: datetime.datetime) -> AutonomyLevel:
    """The level per-call enforcement must act on at instant ``now``.

    Before the term passes (or with no term) this is the stored level. Once it
    has passed, it is the LOWER of the stored level and lastSafeLevel — without
    waiting for any writer, so an idle grant nobody sweeps still falls at its
    boundary. ``min`` rather than lastSafeLevel outright because the demotion
    path can leave lastSafeLevel ABOVE a demoted level (it records the prior
    level as the re-promotion reference, demotion.apply_demotion): a lapse must
    never raise anything. Pure — no write, no store, no clock.
    """
    if not term_passed(grant, now):
        return grant.level
    if _LEVEL_RANK[grant.lastSafeLevel] < _LEVEL_RANK[grant.level]:
        return grant.lastSafeLevel
    return grant.level


def extends_term(previous: str | None, proposed: str | None) -> bool:
    """True iff replacing term ``previous`` with ``proposed`` lengthens it.

    ``None`` is "no term", i.e. unbounded, so dropping an existing term is the
    longest extension there is. Setting a term where there was none, keeping
    it, or shortening it are not extensions (each only narrows authority).
    """
    if previous is None:
        return False
    if proposed is None:
        return True
    return parse_certified_until(proposed) > parse_certified_until(previous)
