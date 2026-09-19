"""Grant schema — per (principal × action-class) authority record.

Autonomy level is stored state, not a constant; this record is where it lives
and what the grant lifecycle moves on a ratchet. See SCHEMAS.md §1 and
broker/grant-lifecycle.md.
"""

import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from .common import AutonomyLevel, DemotionTrigger, Principal
from .durations import validate_label_latency


class Grant(BaseModel):
    """Per (principal × action-class) authority.

    Invariants enforced here:
    - lastSafeLevel may never be 'out-of-loop' — demotion must land on a supervised rung.
    """

    model_config = ConfigDict(extra="forbid")

    principal: Principal
    # the class of action this grant authorizes, e.g. "email.send", "payments.transfer"
    actionClass: str
    # current autonomy rung — STORED STATE, moves on the ratchet
    level: AutonomyLevel
    # hash of the signed envelope in force (caps, thresholds, quorum, fallback budgets)
    envelopeHash: str
    # accountable identity that ratified the current level (maker-checker)
    promotedBy: str
    # ref to the covered-distribution evidence the promotion cited
    evidence: str
    # when this level took effect
    ts: str
    # demotion target — NEVER out-of-loop (validated below)
    lastSafeLevel: AutonomyLevel
    # deterministic conditions that trip demotion
    demotionTriggers: list[DemotionTrigger]
    # why currently demoted; null if at full level
    # "pending-evidence" vs "failing" demand opposite responses — do not collapse them
    demotionReason: Literal["failing", "pending-evidence"] | None
    # how long until an action of this class yields ground truth (caps re-promotion speed).
    # ISO-8601 duration, validated at construction (sa#214, whenever-backed): must parse,
    # be nonnegative, and carry no calendar-ambiguous year/month units. Stored as the
    # exact string given — never normalized (grant hashes cover these bytes).
    labelLatency: str
    # the named human accountable for this grant
    ownerId: str
    # GAL §5.1/§6.7.6 (#255): the term of the current certification — the instant
    # at which this level stops being certified and the grant lapses to
    # lastSafeLevel. None = no term (the default; terms ship unset, so a
    # deployment setting none behaves exactly as before the lapse arc). Stored
    # as the exact string given, never normalized (grant hashes cover these
    # bytes), and OMITTED from the canonical payload when None so every grant
    # written before the field existed keeps byte-identical canonical bytes
    # (store.canonical_grant_payload). Set only by the promotion ceremony;
    # nothing extends it in place (store.refuse_term_extension).
    certifiedUntil: str | None = None

    @field_validator("labelLatency")
    @classmethod
    def label_latency_is_a_duration(cls, v: str) -> str:
        """A malformed duration refuses at load, not at first use (sa#214)."""
        return validate_label_latency(v)

    @field_validator("certifiedUntil")
    @classmethod
    def certified_until_is_utc_instant(cls, v: str | None) -> str | None:
        """A term must be an unambiguous UTC instant, refused at load otherwise.

        A naive or non-UTC value is refused rather than interpreted: whether a
        term has passed must not depend on the reader's timezone assumption.
        """
        if v is None:
            return v
        parse_certified_until(v)
        return v

    @field_validator("lastSafeLevel")
    @classmethod
    def last_safe_level_not_out_of_loop(cls, v: AutonomyLevel) -> AutonomyLevel:
        """Demotion must always land on a supervised rung, never out-of-loop.

        In abstention-kills domains the safe rung must execute a positive deterministic
        action (SCRAM/failsafe), not mere inaction — but that polarity is per-agent config,
        not baked here. See ARCHITECTURE.md §"The one thing that must NEVER be in the base".
        """
        if v is AutonomyLevel.out_of_loop:
            raise ValueError(
                "lastSafeLevel may never be 'out-of-loop': demotion must land "
                "on a supervised rung (in-loop or on-loop)."
            )
        return v


def parse_certified_until(value: str) -> datetime.datetime:
    """Parse a certifiedUntil string into an aware UTC datetime, or raise ValueError.

    Accepts ISO-8601 with a zero UTC offset ('Z' or '+00:00'). Naive values and
    non-UTC offsets are refused, never assumed: the lapse boundary must mean the
    same instant to every reader.
    """
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"certifiedUntil {value!r} is not a parseable ISO-8601 instant; "
            "give a UTC instant such as '2026-10-01T00:00:00+00:00'"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError(
            f"certifiedUntil {value!r} must be an explicit UTC instant "
            "(offset 'Z' or '+00:00'); naive and non-UTC values are refused"
        )
    return parsed
