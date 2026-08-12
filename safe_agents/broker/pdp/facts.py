"""Facts — the PIP-supplied pre-fetched facts the PDP receives before deciding.

This is a PDP input type, not one of the seven canonical schemas. All fields are
resolved by the PIP before decide() is called; decide() itself does no I/O.
See broker/SCHEMAS.md §3 (Decision) for where Facts is referenced.
"""

from dataclasses import dataclass

from safe_agents.broker.schemas.common import AutonomyLevel


@dataclass(frozen=True)
class Facts:
    """Pre-fetched facts the PIP supplies to decide().

    All fields are resolved before the PDP is invoked. The PDP is pure:
    it reads Facts, reads the BrokeredCall, and returns a Decision — no I/O.
    """

    # Whether the principal's grant for this tool/action-class is present.
    # A tool absent from the capability-scoped registry should never reach decide()
    # (the PEP enforces this upstream), but the PDP guards defensively.
    grant_present: bool

    # The current autonomy rung from the principal's grant record.
    grant_level: AutonomyLevel

    # Is the error budget (Σ error_prob × blast_radius) spent >= tolerance this period?
    error_budget_breached: bool

    # Is any capacity budget (attention, rate, etc.) fully spent this period?
    cap_budget_breached: bool

    # Is the escalation budget still available for an abstain+escalate outcome?
    # Escalation spends the escalation budget; an adversary can drain this channel.
    escalation_budget_available: bool

    # Is a human reachable to service a require_approval decision right now?
    # If False and require_approval would fire, the PDP falls back to deny.
    human_reachable: bool

    # When the PIP has determined a safer op to substitute (e.g. "draft" for "send"),
    # it sets this field. None means no transform is indicated.
    transform_op: str | None = None

    # The principal's grant read back QUARANTINED (HMAC mismatch — tampering, a
    # mis-seeded key, or key-rotation drift). The PIP sets this so the PEP can
    # surface the tamper event LOUDLY at a single point (sa#124), rather than the
    # deny being indistinguishable from an un-provisioned capability. Orthogonal to
    # grant_present: a quarantined grant is treated as absent for the decision
    # (grant_present=False) but is NOT the same event as never-granted.
    quarantined: bool = False
    quarantine_reason: str | None = None

    # sa#137 — read rung-gating + query-exfil bound. All three are resolved by the
    # PIP and consumed by the read-path rules in engine.py; defaulted so existing
    # Facts(...) call-sites (writes, older tests) stay valid without change.
    #
    # Is this external read's source in the consumer's trusted_read_sources set?
    # When True the in-loop read rung-gate is bypassed (a trusted source needs no
    # per-read approval) and the read also does NOT self-taint the turn (pep.py).
    read_source_trusted: bool = False

    # Did the egress arg (the agent-composed query string) exceed the per-call byte
    # cap (Envelope.max_query_bytes)? A read with this set is denied before it can
    # egress an over-large query to the provider.
    query_bytes_exceeded: bool = False

    # Has cumulative egress-byte spend for this op reached the per-period budget
    # (Envelope.query_egress_budget)? Bounds the query string as an exfil channel.
    query_egress_breached: bool = False

    # #184: the constructed-confidence artifact failed the Envelope.confidence bar
    # (meets_bar returned False). False when the knob/bar is unset — no bar, no gate.
    confidence_below_bar: bool = False
