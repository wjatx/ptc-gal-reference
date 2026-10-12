"""Clock skew fails toward less authority (PTC-49 / GAL-42, #175).

Wherever the broker, the lapse writer, the ceremony or a delegation check
compares its evaluation instant with a time another party's clock stamped, a
declared bound is applied in the direction that confers LESS authority: an end
(expiry, term) is taken up to the bound EARLY, a start (the instant dwell is
counted from) up to the bound LATE. A bound of zero is today's comparison.

The site table below is the inventory: every comparison the rule governs on the
broker side, each driven through its own entry point. Every row runs the same
five-way matrix, so each of these mutants turns at least one row red, and the
test id names the site:

  * bound ignored                     -> ("inside", 30) expects a refusal
  * bound applied the wrong way       -> ("inside", 30) expects a refusal
  * symmetric leeway (the end extended)-> ("outside", 30) expects a refusal
  * bound inflated or always refusing -> ("inside", 5) and ("inside", 0) expect none
  * a negative bound accepted         -> the negative-bound test expects a refusal to load

The channels sites (airlock gate 4, the drain) are in
``safe_agents/channels/tests/test_clock_skew_channels.py``; the places a bound
is READ from configuration are in ``test_clock_skew_wiring.py``.
"""

from __future__ import annotations

import argparse
import datetime
from dataclasses import dataclass
from typing import Callable

import pytest
from pydantic import ValidationError

from safe_agents.broker.approval import InMemoryIntentStore, approve
from safe_agents.broker.delegation import (
    AttenuationError,
    ExpiredSubGrantError,
    SubGrant,
    compute_sub_grant,
    verify_not_expired,
)
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.ceremony import PromotionCeremony
from safe_agents.broker.grants.lapse import run_lapse
from safe_agents.broker.grants.proposals import proposal_expired
from safe_agents.broker.grants.rung import PromotionEligibilityCounters, is_eligible_for_promotion
from safe_agents.broker.grants.term import effective_level, lapse_pending, term_passed
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.schemas import AgentManifest, Envelope, Grant, Intent
from safe_agents.broker.schemas.clock_skew import (
    MAX_CLOCK_SKEW_SECONDS,
    ZERO_SKEW,
    end_judged_at,
    skew_bound,
    skew_seconds_arg,
    start_judged_at,
)
from safe_agents.broker.tests.test_approval_instant import _hold
from safe_agents.broker.tests.test_delegation import _parent, _scope
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    COUNTER_CAP,
    ENV_HASH,
    IN,
    ON,
    OUT,
    PRINCIPAL,
    TERM,
    TERM_DT,
    _call,
    _grant,
    _promote_with_term,
    _reproposal,
)

UTC = datetime.UTC
END = TERM_DT  # every "end" site below is built to end at this instant
GAP = datetime.timedelta(seconds=10)
_S = datetime.timedelta(seconds=1)


@dataclass(frozen=True)
class Site:
    """One comparison the rule governs.

    ``refused(at, bound)`` drives the site at instant ``at`` with declared bound
    ``bound`` and says whether it conferred the LESS-authority outcome.
    ``boundary`` is where authority ends with a zero bound; ``kind`` says which
    side of it holds authority: before it for an "end", after it for a "start".
    ``refused_at_boundary`` is today's (zero-bound) outcome AT the boundary
    instant itself: True where the comparison is inclusive (``now >= end``),
    False where it is strict (``requested > parent expiry``; dwell elapsed
    ``>= min_dwell`` is eligible).
    """

    name: str
    kind: str  # "end" | "start"
    boundary: datetime.datetime
    refused: Callable[[datetime.datetime, datetime.timedelta], bool]
    refused_at_boundary: bool = True

    def instant(self, where: str) -> datetime.datetime:
        inside = where == "inside"
        if self.kind == "end":
            return self.boundary - GAP if inside else self.boundary + GAP
        return self.boundary + GAP if inside else self.boundary - GAP


# --- the probes --------------------------------------------------------------


def _term_passed(at, bound):
    return term_passed(_grant(), at, skew=bound)


def _effective_level(at, bound):
    return effective_level(_grant(), at, skew=bound) is IN


def _lapse_pending(at, bound):
    return lapse_pending(_grant(), at, skew=bound)


def _pip(at, bound):
    grant_store, _ = _promote_with_term(TERM, ratify_at=TERM_DT - _S)
    pip = _make_pip(
        grant_store, InMemoryStore(), COUNTER_CAP, ENV_HASH, clock=lambda: at, clock_skew=bound
    )
    facts = pip(_call())
    assert facts.grant_present and not facts.quarantined
    return facts.grant_level is IN


def _lapse_writer(at, bound):
    grant_store, record_store = _promote_with_term(TERM, ratify_at=TERM_DT - _S)
    outcome = run_lapse(
        PRINCIPAL,
        ACTION_CLASS,
        grant_store=grant_store,
        record_store=record_store,
        now=at,
        skew=bound,
    )
    lapsed = outcome.status == "lapsed"
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    # The write agrees with the verdict: lowered exactly when it lapsed.
    assert (stored.level is IN) == lapsed, outcome.reason
    return lapsed


def _execute(proposal, at, bound, *, stores=None):
    from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
    from safe_agents.broker.grants.store import InMemoryGrantStore
    from safe_agents.broker.tests.test_grant_term_lapse import HMAC_KEY, _bootstrap_record

    if stores is None:
        grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
        record_store = InMemoryPromotionRecordStore()
        seed = _grant(level=IN, certifiedUntil=None)
        grant_store.write_record_and_grant(_bootstrap_record(seed), seed, record_store)
    else:
        grant_store, record_store = stores
    return PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store, clock_skew=bound
    ).execute(proposal, "checker-bob", now=at)


def _ceremony_proposal_expiry(at, bound):
    result = _execute(_reproposal(expires_at=TERM), at, bound)
    return result.status == "rejected" and "expired" in result.reason


def _ceremony_proposed_term(at, bound):
    result = _execute(_reproposal(certified_until=TERM), at, bound)
    return result.status == "rejected" and "lapsed on arrival" in result.reason


def _ceremony_stored_term(at, bound):
    stores = _promote_with_term(TERM, ratify_at=TERM_DT - datetime.timedelta(hours=1))
    proposal = _reproposal(from_level=ON, target_level=OUT, last_safe_level=ON)
    result = _execute(proposal, at, bound, stores=stores)
    return result.status == "rejected" and "lapse is not yet recorded" in result.reason


def _proposal_expired(at, bound):
    return proposal_expired(TERM, at, skew=bound)


def _approval_release(at, bound):
    store = InMemoryIntentStore()
    intent_id = _hold(store, END - datetime.timedelta(seconds=60))  # TTL 60s -> expiry END
    result = approve(
        intent_id, "owner:a", store, executor=lambda call: {"ok": True}, now=at, skew=bound
    )
    return result.rejection_reason == "intent expired"


def _subgrant_use(at, bound):
    sub = compute_sub_grant(
        _parent(expiry=END + datetime.timedelta(hours=1)),
        _scope(ttl_seconds=3600.0),
        now=END - datetime.timedelta(hours=1),
    )
    assert datetime.datetime.fromisoformat(sub.expiry) == END
    try:
        verify_not_expired(sub, now=at, skew=bound)
    except ExpiredSubGrantError:
        return True
    return False


_SUBGRANT_TTL = 600.0


def _subgrant_issuance(at, bound):
    # The requested child expiry lands at ``at``; the parent's expiry is END.
    try:
        compute_sub_grant(
            _parent(expiry=END),
            _scope(ttl_seconds=_SUBGRANT_TTL),
            now=at - datetime.timedelta(seconds=_SUBGRANT_TTL),
            skew=bound,
        )
    except AttenuationError as exc:
        assert "past the parent's expiry" in str(exc)
        return True
    return False


_DWELL = datetime.timedelta(hours=1)


def _dwell(at, bound):
    counters = PromotionEligibilityCounters(
        clean_runs_since_promotion=10,
        last_transition_ts=(END - _DWELL).isoformat(),
    )
    return not is_eligible_for_promotion(
        _grant(level=ON),
        counters,
        min_clean_runs=1,
        min_dwell=_DWELL,
        now=at,
        skew=bound,
    )


SITES = [
    Site("grants.term.term_passed", "end", END, _term_passed),
    Site("grants.term.effective_level", "end", END, _effective_level),
    Site("grants.term.lapse_pending", "end", END, _lapse_pending),
    Site("broker_server._make_pip (enforced level)", "end", END, _pip),
    Site("grants.lapse.run_lapse (lapse writer)", "end", END, _lapse_writer),
    Site("ceremony.execute: proposal expiry", "end", END, _ceremony_proposal_expiry),
    Site("ceremony.execute: proposed term", "end", END, _ceremony_proposed_term),
    Site("ceremony.execute: stored grant's term", "end", END, _ceremony_stored_term),
    Site("grants.proposals.proposal_expired", "end", END, _proposal_expired),
    Site("approval.engine.approve (hold expiry)", "end", END, _approval_release),
    Site("delegation.verify_not_expired", "end", END, _subgrant_use),
    Site(
        "delegation.compute_sub_grant (parent expiry)",
        "end",
        END,
        _subgrant_issuance,
        refused_at_boundary=False,
    ),
    Site(
        "grants.rung.is_eligible_for_promotion (dwell)",
        "start",
        END,
        _dwell,
        refused_at_boundary=False,
    ),
]

# (where, bound in seconds, refused?) — GAP is 10s.
_MATRIX = [
    pytest.param("inside", 0, False, id="zero-bound-is-todays-comparison"),
    pytest.param("inside", 30, True, id="bound-applies-toward-less-authority"),
    pytest.param("inside", 5, False, id="a-bound-narrower-than-the-gap-changes-nothing"),
    # Just wider than GAP: only the FULL bound reaches past the boundary, so a
    # site applying part of it (half, say) keeps authority here.
    pytest.param("inside", 11, True, id="a-bound-just-wider-than-the-gap-refuses"),
    pytest.param("outside", 30, True, id="no-symmetric-leeway-past-the-boundary"),
    pytest.param("outside", 0, True, id="past-the-boundary-with-no-bound"),
]


@pytest.mark.parametrize("where,bound_s,expected", _MATRIX)
@pytest.mark.parametrize("site", SITES, ids=lambda s: s.name)
def test_every_site_applies_the_bound_toward_less_authority(site, where, bound_s, expected):
    at = site.instant(where)
    bound = datetime.timedelta(seconds=bound_s)
    got = site.refused(at, bound)
    assert got is expected, (
        f"{site.name}: at {where} ({at.isoformat()}, {site.kind} boundary "
        f"{site.boundary.isoformat()}) with a {bound_s}s bound, expected "
        f"{'the less-authority outcome' if expected else 'authority to hold'}, got the "
        f"{'less-authority outcome' if got else 'authority'}"
    )


_US = datetime.timedelta(microseconds=1)


@pytest.mark.parametrize("site", SITES, ids=lambda s: s.name)
def test_every_site_moves_its_edge_by_exactly_the_bound(site):
    """Zero is today's comparison AT the boundary; a bound shifts that edge by its width.

    GAP inside the boundary, a bound of GAP lands exactly on the edge and must
    reproduce today's at-boundary outcome (inclusive or strict, per site); a
    microsecond less keeps authority and a microsecond more refuses. A partial
    bound, an inflated one, or a flipped ``>``/``>=`` each miss one of these.
    """
    inside = site.instant("inside")
    cases = [
        ("zero bound at the boundary", site.boundary, ZERO_SKEW, site.refused_at_boundary),
        ("a bound just short of GAP", inside, GAP - _US, False),
        ("a bound of exactly GAP", inside, GAP, site.refused_at_boundary),
        ("a bound just past GAP", inside, GAP + _US, True),
    ]
    for label, at, bound, expected in cases:
        got = site.refused(at, bound)
        assert got is expected, (
            f"{site.name}: {label} ({at.isoformat()}, bound {bound}, {site.kind} boundary "
            f"{site.boundary.isoformat()}, comparison "
            f"{'inclusive' if site.refused_at_boundary else 'strict'}): expected "
            f"{'the less-authority outcome' if expected else 'authority to hold'}, got the "
            f"{'less-authority outcome' if got else 'authority'}"
        )


@pytest.mark.parametrize("site", SITES, ids=lambda s: s.name)
def test_every_site_refuses_a_negative_bound(site):
    """A negative bound would apply the skew toward MORE authority."""
    with pytest.raises(ValueError, match="must not be negative") as info:
        site.refused(site.instant("inside"), datetime.timedelta(seconds=-30))
    assert "MORE authority" in str(info.value), site.name


# --- the bound itself ---------------------------------------------------------


def test_the_helpers_move_ends_earlier_and_starts_later():
    now = datetime.datetime(2026, 1, 1, tzinfo=UTC)
    bound = datetime.timedelta(seconds=7)
    assert end_judged_at(now, bound) == now + bound
    assert start_judged_at(now, bound) == now - bound
    assert end_judged_at(now, ZERO_SKEW) == now == start_judged_at(now, ZERO_SKEW)


@pytest.mark.parametrize("bad", [-1, True, 1.5, "30", None, MAX_CLOCK_SKEW_SECONDS + 1])
def test_skew_bound_refuses_anything_but_a_non_negative_int(bad):
    with pytest.raises((TypeError, ValueError)):
        skew_bound(bad)


@pytest.mark.parametrize("text", ["-1", "x", "1.5", "", str(MAX_CLOCK_SKEW_SECONDS + 1)])
def test_the_cli_flag_refuses_a_negative_or_non_integer_bound(text):
    with pytest.raises(argparse.ArgumentTypeError):
        skew_seconds_arg(text)
    assert skew_seconds_arg("30") == 30
    assert skew_seconds_arg(str(MAX_CLOCK_SKEW_SECONDS)) == MAX_CLOCK_SKEW_SECONDS


def test_a_bound_wider_than_a_day_is_refused_before_it_can_overflow():
    """An operator typo is refused naming the bound, not left to overflow later.

    Without the cap, 10**13 seconds loads and then every comparison raises
    OverflowError at evaluation time; 10**15 fails inside the timedelta.
    """
    assert skew_bound(MAX_CLOCK_SKEW_SECONDS) == datetime.timedelta(days=1)
    for seconds in (MAX_CLOCK_SKEW_SECONDS + 1, 10**13, 10**15):
        with pytest.raises(ValueError, match="at most 86400 seconds"):
            skew_bound(seconds)
    with pytest.raises(ValueError, match="at most 86400 seconds"):
        end_judged_at(datetime.datetime(2026, 1, 1, tzinfo=UTC), datetime.timedelta(days=2))


def _manifest(**fields) -> AgentManifest:
    return AgentManifest(envelope=Envelope(polarity="abstain"), **fields)


def test_the_manifest_bound_ships_off():
    assert _manifest().clock_skew_seconds == 0
    assert skew_bound(_manifest().clock_skew_seconds) == ZERO_SKEW


@pytest.mark.parametrize("bad", [-1, True, "30", 1.5, MAX_CLOCK_SKEW_SECONDS + 1, 10**13])
def test_the_manifest_refuses_a_negative_or_non_integer_bound(bad):
    with pytest.raises(ValidationError, match="clock_skew_seconds"):
        _manifest(clock_skew_seconds=bad)
    assert _manifest(clock_skew_seconds=MAX_CLOCK_SKEW_SECONDS).clock_skew_seconds == (
        MAX_CLOCK_SKEW_SECONDS
    )


def test_the_manifest_bound_stays_out_of_the_envelope_hash():
    """Declared outside Envelope, so setting it never churns a grant's
    envelopeHash (the counter_period precedent)."""
    from safe_agents.broker.schemas import compute_envelope_hash

    a, b = _manifest(), _manifest(clock_skew_seconds=60)
    assert compute_envelope_hash(a.envelope) == compute_envelope_hash(b.envelope)


@pytest.mark.parametrize(
    "model,base",
    [
        pytest.param(Grant, lambda: _grant().model_dump(mode="json"), id="Grant"),
        pytest.param(
            SubGrant,
            lambda: compute_sub_grant(
                _parent(expiry=END + datetime.timedelta(hours=2)), _scope(), now=END
            ).model_dump(mode="json"),
            id="SubGrant",
        ),
        pytest.param(
            Intent,
            lambda: _stored_intent().model_dump(mode="json"),
            id="Intent",
        ),
    ],
)
def test_no_presented_record_can_carry_a_bound(model, base):
    """The bound is the receiver's configuration. None of the records a site
    judges can even carry one, so no site could read it from the presenter."""
    with pytest.raises(ValidationError):
        model.model_validate({**base(), "clock_skew_seconds": 3600})


def _stored_intent() -> Intent:
    store = InMemoryIntentStore()
    return store.get_intent(_hold(store, END))


def test_a_rejection_is_not_reclassified_as_an_expiry_by_the_bound():
    """reject() takes no bound: both of its outcomes refuse, so the bound would
    decide no authority, and the owner's in-time "no" stays a rejection."""
    from safe_agents.broker.approval import reject

    store = InMemoryIntentStore()
    intent_id = _hold(store, END - datetime.timedelta(seconds=60))
    result = reject(intent_id, "owner:a", store, now=END - GAP)
    assert result.rejection_reason != "intent expired"
    assert store.get_intent(intent_id).status == "rejected"
