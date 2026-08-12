"""Grant schema — per (principal × action-class) authority record.

Autonomy level is stored state, not a constant; this record is where it lives
and what the grant lifecycle moves on a ratchet. See SCHEMAS.md §1 and
broker/grant-lifecycle.md.
"""

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

    @field_validator("labelLatency")
    @classmethod
    def label_latency_is_a_duration(cls, v: str) -> str:
        """A malformed duration refuses at load, not at first use (sa#214)."""
        return validate_label_latency(v)

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
