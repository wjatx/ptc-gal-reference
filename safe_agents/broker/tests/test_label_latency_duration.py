"""Grant.labelLatency is a VALIDATED ISO-8601 duration (sa#214, whenever-backed).

This file supersedes the sa#213 landmine pin (test_label_latency_opaque.py):
the field now refuses at construction instead of accepting anything. The
accepted grammar is pinned here as the conformance row sa#214 asked for:
parseable ISO-8601 duration, nonnegative, no calendar-ambiguous year/month
units (a month has no deterministic length as a time span; weeks/days are
exact and allowed). The value is validated but NEVER normalized — grant
hashes and proposal HMACs cover the exact bytes, so "P3W" must survive as
"P3W", not "P21D".

Chokepoints under test: the Grant field validator (closes the mint/load
path) and propose_promotion (refuses the maker before a checker is
summoned).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from safe_agents.broker.grants.ceremony import PromotionCeremony
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.durations import validate_label_latency

PRINCIPAL = Principal(agentId="agent-1", skill="notify", user="maintainer", tier="B")

GRANT_BASE = {
    "principal": PRINCIPAL,
    "actionClass": "email.send",
    "level": AutonomyLevel.in_loop,
    "envelopeHash": "env-hash-1",
    "promotedBy": "human:maintainer",
    "evidence": "evidence-ref-001",
    "ts": "2026-07-16T00:00:00+00:00",
    "lastSafeLevel": AutonomyLevel.in_loop,
    "demotionTriggers": [],
    "demotionReason": None,
    "ownerId": "maintainer",
}

# The accepted grammar, pinned. Values must survive BYTE-IDENTICAL.
ACCEPTED = [
    "PT1H",  # the floor default every live grant carries
    "P7D",
    "P1DT2H30M",
    "PT0S",  # immediate ground truth is coherent
    "P3W",  # weeks are exact; must NOT normalize to P21D
    "PT90M",  # must NOT normalize to PT1H30M
]

# The refused grammar, pinned: (value, reason-fragment expected in the error).
REFUSED = [
    ("not-a-duration", "ISO-8601"),
    ("1 hour", "ISO-8601"),
    ("PT", "ISO-8601"),  # designator with no digits
    ("3", "ISO-8601"),
    ("", "ISO-8601"),
    ("PT1H ", "ISO-8601"),  # trailing whitespace is not tolerated
    ("PT1.5H", "ISO-8601"),  # fractional hours are refused by parse_iso
    ("1h", "ISO-8601"),
    ("-PT1H", "nonnegative"),
    ("P1M", "calendar-ambiguous"),
    ("P1Y", "calendar-ambiguous"),
    ("P1Y2M", "calendar-ambiguous"),
    ("P1MT2H", "calendar-ambiguous"),
]


def _grant_with_label_latency(value: str) -> Grant:
    return Grant(**{**GRANT_BASE, "labelLatency": value})


class TestValidateLabelLatency:
    @pytest.mark.parametrize("value", ACCEPTED)
    def test_accepted_values_return_byte_identical(self, value: str) -> None:
        assert validate_label_latency(value) == value

    @pytest.mark.parametrize(("value", "reason"), REFUSED)
    def test_refused_values_raise_with_reason(self, value: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            validate_label_latency(value)


class TestGrantChokepoint:
    @pytest.mark.parametrize("value", ACCEPTED)
    def test_valid_duration_round_trips_unchanged(self, value: str) -> None:
        grant = _grant_with_label_latency(value)
        assert grant.labelLatency == value
        assert Grant.model_validate_json(grant.model_dump_json()).labelLatency == value

    @pytest.mark.parametrize(("value", "reason"), REFUSED)
    def test_invalid_duration_refuses_at_construction(self, value: str, reason: str) -> None:
        with pytest.raises(ValidationError, match=reason):
            _grant_with_label_latency(value)

    def test_missing_label_latency_rejected(self) -> None:
        with pytest.raises(ValidationError, match="labelLatency"):
            Grant(**{k: v for k, v in GRANT_BASE.items()})


class TestProposeChokepoint:
    """The maker is refused before a checker is summoned."""

    def _propose(self, label_latency: str):
        return PromotionCeremony.propose_promotion(
            PRINCIPAL,
            "email.send",
            AutonomyLevel.in_loop,
            "evidence-ref-001",
            "maker:maintainer",
            proposal_id="prop-1",
            expires_at="2026-07-16T01:00:00+00:00",
            owner_id="maintainer",
            from_level=None,
            envelope_hash="env-hash-1",
            label_latency=label_latency,
            demotion_triggers=[],
            last_safe_level=AutonomyLevel.in_loop,
            metrics=ActionClassMetrics(
                false_action_count=0, human_override_count=0, observation_count=5
            ),
            window_n=5,
            min_observations=1,
            threshold=0.25,
            artifact=None,
            covered=False,
            provenance_maturity="taint-bit",
            blast_class="low",
            error_budget=None,
        )

    def test_valid_duration_proposes(self) -> None:
        proposal = self._propose("PT1H")
        assert proposal.label_latency == "PT1H"

    @pytest.mark.parametrize(
        ("value", "reason"),
        [("not-a-duration", "ISO-8601"), ("-PT1H", "nonnegative"), ("P1M", "calendar-ambiguous")],
    )
    def test_invalid_duration_refuses_the_maker(self, value: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            self._propose(value)
