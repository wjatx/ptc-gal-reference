"""Deterministic demotion evaluator (sa#59).

Fires when a grant's demotionTriggers conditions are breached. No model is
consulted — demotion is automatic and deterministic. Fast demotion is a
safety property; it must run even when the model is confused.

Public API:
    DemotionMetrics       — pre-fetched trigger breach states (injected by caller)
    DemotionResult        — evaluate_demotion_triggers return value
    DemotionConflictError — concurrent grant modification detected on write
    GrantNotFoundError    — demotion attempted on a non-existent grant
    evaluate_demotion_triggers(grant, metrics) -> DemotionResult   # pure
    apply_demotion(grant, result, *, store, record_store, session, ts)
        -> tuple[Grant, PromotionRecord]

apply_demotion appends a demotion-typed PromotionRecord to the ceremony ledger
(SCHEMAS.md §7) in the same atomic unit as the lowered grant (#244). The record
is signed by the EVALUATOR identity when one is configured — a second signing
role, never the issuer's key, because an evaluator that could sign promotions
would collapse the ceremony boundary (GAL §6.7.2, §6.10).

See broker/grant-lifecycle.md §"Demotion — automatic, deterministic, no model in the loop".
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Literal

from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.grants.ceremony import PromotionRecordStore
from safe_agents.broker.grants.store import (
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
)


# ---------------------------------------------------------------------------
# Level ordering — demotion moves toward lower autonomy (higher supervision)
# ---------------------------------------------------------------------------

_LEVEL_RANK: dict[AutonomyLevel, int] = {
    AutonomyLevel.in_loop: 0,       # lowest autonomy (most supervised)
    AutonomyLevel.on_loop: 1,
    AutonomyLevel.out_of_loop: 2,   # highest autonomy
}


def _rank(level: AutonomyLevel) -> int:
    return _LEVEL_RANK[level]


def demotion_target_level(grant: Grant) -> AutonomyLevel:
    """The level a demotion would move this grant to.

    Single source for apply_demotion AND the runner's record-only dedupe
    predicate — a drift between the two would let the dedupe skip a
    level-changing demotion. Falls back to in-loop if lastSafeLevel is somehow
    absent (schema requires it, but be defensive against direct dict
    construction bypassing validation).
    """
    return grant.lastSafeLevel or AutonomyLevel.in_loop


# ---------------------------------------------------------------------------
# Trigger → demotionReason mapping
# ---------------------------------------------------------------------------

# stale_confidence is "pending-evidence": label-free drift voids the certification —
# the model is not proven failing; the operator response is gather-labels/recalibrate,
# not fix-the-model. corroboration_failure, budget_breach and false_action indicate an
# active breach ("failing") — false_action because an authenticated owner flag asserts
# the action WAS wrong, not that its certification lapsed. Never collapse the two
# reasons (broker/grant-lifecycle.md).
_TRIGGER_REASON: dict[DemotionTrigger, Literal["failing", "pending-evidence"]] = {
    DemotionTrigger.stale_confidence: "pending-evidence",
    DemotionTrigger.corroboration_failure: "failing",
    DemotionTrigger.budget_breach: "failing",
    DemotionTrigger.false_action: "failing",
}


# ---------------------------------------------------------------------------
# Input type — pre-fetched trigger breach states
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DemotionMetrics:
    """Which demotion triggers are currently breached.

    Callers evaluate each condition externally (reading counters, checking
    distribution drift, verifying corroboration quorum) and inject the results
    here. evaluate_demotion_triggers performs no I/O of its own.

    Attributes:
        tripped: the set of DemotionTrigger values currently in breach.
            An empty set means no active breach; the evaluator will return
            should_demote=False.
    """

    tripped: frozenset[DemotionTrigger] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Result and record types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DemotionResult:
    """Return value of evaluate_demotion_triggers.

    Attributes:
        should_demote: True iff at least one trigger in grant.demotionTriggers
            is present in metrics.tripped.
        triggered_by: names of the triggers that fired (subset of
            grant.demotionTriggers values, as strings).
        reason: human-readable explanation; suitable for audit logs.
    """

    should_demote: bool
    triggered_by: list[str]
    reason: str


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

class DemotionConflictError(Exception):
    """Grant was modified between evaluate and apply.

    The caller must re-read the grant from the store and re-evaluate triggers
    against fresh metrics before retrying apply_demotion.
    """


class GrantNotFoundError(Exception):
    """Demotion attempted on a grant that does not exist in the store.

    apply_demotion uses UpdateItem semantics: it can lower an existing grant,
    but it must never create a new one.
    """


# ---------------------------------------------------------------------------
# Pure evaluation step
# ---------------------------------------------------------------------------

def evaluate_demotion_triggers(
    grant: Grant,
    metrics: DemotionMetrics,
) -> DemotionResult:
    """Decide whether grant.demotionTriggers are currently breached.

    Pure: no I/O, no LLM call, no side effects. Same inputs → same output.
    Ambiguous cases (no triggers configured, no breach) always resolve to
    should_demote=False — this is a fail-safe, not a judgment call.

    Args:
        grant: the grant record, already read and hash-verified by the caller.
        metrics: pre-fetched trigger breach states.

    Returns:
        DemotionResult. If should_demote=True, pass the result to apply_demotion.
    """
    triggered = [
        t.value
        for t in grant.demotionTriggers
        if t in metrics.tripped
    ]

    if not triggered:
        return DemotionResult(
            should_demote=False,
            triggered_by=[],
            reason=(
                f"no active breach for {grant.principal.agentId}/{grant.actionClass}: "
                f"configured={[t.value for t in grant.demotionTriggers]}, "
                f"tripped={[t.value for t in metrics.tripped]}"
            ),
        )

    return DemotionResult(
        should_demote=True,
        triggered_by=triggered,
        reason=(
            f"demotion triggered for {grant.principal.agentId}/{grant.actionClass}: "
            f"breached={triggered}; "
            f"level {grant.level.value!r} → {grant.lastSafeLevel.value!r}"
        ),
    )


# ---------------------------------------------------------------------------
# Write step — applies the demotion to the grant store
# ---------------------------------------------------------------------------

def apply_demotion(
    grant: Grant,
    demotion_result: DemotionResult,
    *,
    store: GrantStore,
    record_store: PromotionRecordStore,
    session: object = None,
    ts: str | None = None,
    record_signer: object = None,
) -> tuple[Grant, PromotionRecord]:
    """Lower grant.level to grant.lastSafeLevel and persist via the store.

    Must be called only when demotion_result.should_demote is True.

    Write discipline (UpdateItem semantics):
    - Re-reads the grant before writing — a cheap check that distinguishes
      not-found (GrantNotFoundError) from concurrent modification
      (DemotionConflictError).
    - The real atomicity guard is the conditional store.update_grant: the
      write succeeds only if the stored grant is still the one evaluated
      (no race window between the re-read and the write). A demotion-scoped
      IAM role needs only UpdateItem (no PutItem API) — but UpdateItem can
      still create items, so the lower-never-mint guarantee is the store's
      attribute_exists ConditionExpression, with IAM limiting blast radius
      rather than proving it.
    - Never raises the autonomy level: if the current level is already at or
      below lastSafeLevel in rank, the level stays unchanged while still
      recording the trigger event.
    - After the grant update, a demotion-typed PromotionRecord is appended to
      the ceremony ledger. Grant lowered FIRST, record second — if the record
      append fails, the system is already in the safe (lowered) state and the
      error surfaces loudly. The record is appended even when the level was
      already at/below lastSafeLevel: the breach event itself must be on the
      ledger.

    lastSafeLevel handling: after a level-lowering demotion, lastSafeLevel is
    updated to the previous level (so a subsequent promotion has a reference
    point), unless the previous level was out-of-loop — which the schema
    forbids as a lastSafeLevel value. When the level did not change (a
    record-only repeat breach), lastSafeLevel is left untouched: a second
    breach at the floor must not overwrite the re-promotion reference (e.g.
    an on-loop reference clobbered down to in-loop).

    Args:
        grant: the grant as read at evaluation time (used for hash comparison).
        demotion_result: result of evaluate_demotion_triggers (must have
            should_demote=True).
        store: the grant store to write to.
        record_store: the PromotionRecord ledger the demotion record is
            appended to.
        session: boto3 Session carrying the demotion IAM role; passed through
            to store.update_grant and record_store.put_record. The stores
            never assume roles themselves.
        ts: ISO-8601 timestamp string; defaults to current UTC time.
        record_signer: the EVALUATOR's RecordSigner (GAL §6.7.2's separate
            system identity), or None. When supplied, the demotion record is
            signed and the signature rides the same atomic write — a configured
            evaluator never writes an unsigned record. Deliberately NOT the
            issuer signer: an evaluator holding that key could mint promotion
            records, which is the boundary the separate identity exists to draw.

    Returns:
        (updated_grant, demotion_record) — the record is the demotion-typed
        PromotionRecord already appended to the ledger.

    Raises:
        ValueError: if demotion_result.should_demote is False.
        DemotionConflictError: if the grant changed between evaluate and apply
            (from the re-read, or from the conditional write losing the race).
        GrantNotFoundError: if the grant does not exist in the store.
        QuarantinedGrantError: if the re-read found the stored grant
            quarantined — writing over it would launder the tampered state
            under a fresh valid hash.
    """
    if not demotion_result.should_demote:
        raise ValueError(
            "apply_demotion called with should_demote=False; "
            "only call this after evaluate_demotion_triggers returns True"
        )

    effective_ts = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()

    # --- consistent re-read: distinguishes not-found from conflict cheaply ---
    current = store.get_grant(grant.principal, grant.actionClass)
    if current.quarantined:
        # Checked FIRST: a quarantined read carries grant=None (#246 —
        # tampered bytes are never parsed), so the not-found check below
        # would otherwise mislabel a tamper as absence and invite a re-seed
        # over the evidence.
        raise QuarantinedGrantError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is quarantined "
            f"({current.quarantine_reason}); it must not be written until the "
            "quarantine is resolved"
        )
    if current.grant is None:
        raise GrantNotFoundError(
            f"grant {grant.principal.agentId}/{grant.actionClass} not found in store; "
            "demotion uses UpdateItem semantics and cannot create a new grant"
        )
    if current.grant != grant:
        # Content equality IS the staleness check under the stored-bytes basis
        # (#246): identical fields ⇒ identical canonical bytes ⇒ the decision's
        # premises still hold.
        raise DemotionConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} was modified "
            "between evaluate and apply; re-read and re-evaluate"
        )

    from_level = grant.level
    new_level = demotion_target_level(grant)

    # Safety invariant: demotion must never raise the autonomy level.
    # If we're already at or below lastSafeLevel, stay put.
    if _rank(new_level) >= _rank(from_level):
        new_level = from_level

    # Reason precedence: an actually-blown bound dominates a lapsed certification —
    # if ANY fired trigger maps to "failing", the reason is "failing"; only when
    # all fired triggers map to "pending-evidence" is it "pending-evidence".
    fired_reasons = {
        _TRIGGER_REASON[DemotionTrigger(name)] for name in demotion_result.triggered_by
    }
    demotion_reason: Literal["failing", "pending-evidence"] = (
        "failing" if "failing" in fired_reasons else "pending-evidence"
    )

    # Update lastSafeLevel to the previous level so a subsequent promotion
    # knows the high-water mark. Two exceptions keep the stored value: a
    # record-only repeat breach (level unchanged — updating would clobber the
    # re-promotion reference, e.g. on-loop down to in-loop on a second breach
    # at the floor), and a previous level of out-of-loop (forbidden as a
    # lastSafeLevel value by the schema).
    if new_level is from_level or from_level is AutonomyLevel.out_of_loop:
        new_last_safe_level = grant.lastSafeLevel
    else:
        new_last_safe_level = from_level

    updated = grant.model_copy(update={
        "level": new_level,
        "lastSafeLevel": new_last_safe_level,
        "demotionReason": demotion_reason,
        "ts": effective_ts,
    })

    record = PromotionRecord(
        recordType="demotion",
        actionClass=grant.actionClass,
        principal=grant.principal,
        fromLevel=from_level,
        toLevel=new_level,
        evidence=demotion_result.reason,
        predicate=None,
        proposedBy=DEMOTION_RATIFIER,
        ratifiedBy=DEMOTION_RATIFIER,
        envelopeHash=grant.envelopeHash,
        triggeredBy=demotion_result.triggered_by,
        demotionReason=demotion_reason,
        ts=effective_ts,
    )

    # Atomic record+grant (#244): the old grant-first ordering (fail toward
    # the lowered level, at the cost of a possible ledger hole) is superseded —
    # a failed unit leaves BOTH untouched and the runner retries with a fresh
    # read. The conditional grant leg is the real atomicity guard, not the
    # re-read above.
    signature = record_signer.sign_record(record) if record_signer is not None else None
    try:
        store.write_record_and_grant(
            record, updated, record_store, session, signature=signature, expected=current
        )
    except GrantUpdateConflictError as exc:
        raise DemotionConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} was modified "
            "between evaluate and apply (conditional write failed); "
            "re-read and re-evaluate"
        ) from exc

    return updated, record
