"""broker.approval.engine — Intent materialization and the WYSIWYE approval path.

Two entry points:

  materialize(call, decision, store, notifier, *, expiry_seconds)
      Called immediately when decide() returns require_approval. Freezes the
      BrokeredCall as a pending Intent, persists it, emits the notifier event,
      and returns {status: pending, intent_id}. The agent's turn ends here.
      The agent holds no tool that can approve or release the intent.

  approve(intent_id, approved_by, store, executor)
      Called by the out-of-band approval path (authenticated to the human, never
      to the agent). Reads materializedRequest from the store and executes EXACTLY
      those bytes — never anything the agent re-sends after the turn ended.
      This is the WYSIWYE (what-you-see-is-what-you-execute) guarantee.

      The executor may refuse by raising ReleaseRefusedError (#9): the human's
      ratification satisfies the approval requirement and nothing else, so a
      release still has to clear the authority the call needs at release time.
      A refused release lands the intent in the terminal "refused" state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.schemas.decision import RequireApproval

from .store import IntentAlreadyPendingError, IntentStore
from .types import ApprovalResult, ExecutionResult, NotifierEvent

# The rejection_reason reject() returns on a clean CAS win — the ONE signal that
# an owner rejection actually transitioned the intent (every refusal path returns
# a distinct reason). The PEP's human_override evidence writer keys on it (#193).
REJECTED_BY_OWNER_REASON = "rejected by owner"

# Prefix of the rejection_reason approve() returns when the executor refused the
# release (#9). Callers key on it the way they key on REJECTED_BY_OWNER_REASON.
RELEASE_REFUSED_REASON_PREFIX = "release refused"


class ReleaseRefusedError(Exception):
    """The release executor refused to run the approved call (#9).

    Raised by the PEP's approved-executor when revalidating current authority at
    release time yields deny or abstain: the grant was revoked or demoted, the
    per-op budget is exhausted, or the world otherwise moved between the hold and
    the human's ratification. A human approval answers the approval requirement;
    it does not stand in for the authority the approved call still needs.

    approve() catches this and moves the intent to the terminal "refused" state
    rather than "executed", so the record says the release was refused and why.
    The connector is never reached, which fails toward less authority.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Internal helpers — pure, no I/O
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_now(now: datetime | None) -> datetime:
    """The evaluation instant: the caller's explicit ``now``, else the wall clock.

    Called ONCE, at the top of each public entry point, so every verdict inside
    that call is judged against the same instant and that instant is always an
    input — never derived from anything stored on the intent (its ``ts``, its
    ``expiry``, or any other record). A record's own timestamps are claims about
    the past; letting one stand in for "now" would let whoever wrote the record
    choose when it expires.
    """
    return now if now is not None else datetime.now(timezone.utc)


def _expiry_iso(expiry_seconds: int, now: datetime) -> str:
    """Compute an ISO-8601 UTC expiry timestamp from ``now`` + expiry_seconds."""
    return (now + timedelta(seconds=expiry_seconds)).isoformat()


def _is_expired(expiry: str, now: datetime) -> bool:
    """True when ``expiry`` is at or before ``now`` (inclusive of exact equality).

    Pure: the evaluation instant is an explicit argument, supplied by the public
    entry point via _resolve_now(). Nothing here reads a clock.
    """
    expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    return now >= expiry_dt


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def materialize(
    call: BrokeredCall,
    decision: RequireApproval,
    store: IntentStore,
    notifier: Callable[[NotifierEvent], None] | None = None,
    *,
    expiry_seconds: int = 3600,
    dedup_id: str | None = None,
    now: datetime | None = None,
) -> ApprovalResult:
    """Materialize the BrokeredCall as a pending Intent and hold it for human approval.

    Called immediately when decide() returns require_approval. The broker persists
    the Intent and returns {status: pending, intent_id} to the caller. After this
    the agent's turn ends — the agent has no mechanism to approve or release the intent.

    The broker renders renderedForHuman from the typed BrokeredCall through the PDP's
    RequireApproval decision. The agent never supplies this field.

    Parameters
    ----------
    call:
        The typed BrokeredCall to materialize and hold. This is written into
        materializedRequest and never re-derived from anything the agent sends later.
    decision:
        The RequireApproval returned by decide(). Carries the broker-rendered
        renderedForHuman text and the stable intent ID derived from the typed call.
    store:
        The IntentStore to persist the pending intent in.
    notifier:
        Optional hook for emitting the notifier event. Called with a NotifierEvent
        carrying renderedForHuman. Channel-specific delivery belongs in channels/.
        Pass None to skip notification (e.g., in tests that check only persistence).
    expiry_seconds:
        How long before the intent auto-denies (defaults to 3600 s = 1 hour).
        Unactioned intents become expired at this TTL; approve() rejects them.
    dedup_id:
        Optional content-derived intent id (sa#160 approval-queue dedup). When
        supplied, the Intent is held under THIS id instead of the PDP's ts-based
        id, and — if an equal-id Intent is already pending — this call coalesces
        onto it: no second hold, no second notification, status "coalesced". Pure
        de-amplification of identical re-submissions; None = today's behavior.
    now:
        The hold instant: the Intent's ``ts`` and the base its ``expiry`` is
        computed from. Defaults to the wall clock. Both derive from this one
        instant, so ``expiry - ts`` is exactly ``expiry_seconds``.

    Raises
    ------
    IntentAlreadyPendingError
        Without dedup, when a pending intent already holds the PDP's intent id
        (#39). That intent is a different call and is left intact; nothing is
        held and nobody is notified for this one.

    Returns
    -------
    ApprovalResult
        {status, intent_id}. "pending" = a new Intent was held; "coalesced" = an
        identical pending Intent already existed and this call de-amplified onto
        it. Either way the turn ENDS here — the agent cannot self-approve or
        modify what will execute.
    """
    intent_id = dedup_id if dedup_id is not None else decision.renderedIntent.id

    # Dedup coalescing: if an identical Intent is already pending under this
    # content id, do not re-hold or re-notify — de-amplify onto it. The status
    # check means a resolved (approved/expired/…) intent does NOT block a fresh
    # hold: only a still-pending duplicate coalesces.
    if dedup_id is not None:
        existing = store.get_intent(dedup_id)
        if existing is not None and existing.status == "pending":
            return ApprovalResult(status="coalesced", intent_id=dedup_id)
    # The broker renders renderedForHuman from the typed BrokeredCall via the PDP —
    # never from anything the agent supplies.
    rendered_for_human = decision.renderedIntent.renderedForHuman
    hold_at = _resolve_now(now)
    expiry = _expiry_iso(expiry_seconds, hold_at)
    ts = hold_at.isoformat()

    intent = Intent(
        id=intent_id,
        # FROZEN: written once at creation; never re-derived from agent input.
        materializedRequest=call,
        renderedForHuman=rendered_for_human,
        status="pending",
        expiry=expiry,
        approvedBy=None,
        ts=ts,
    )
    try:
        store.put_intent(intent)
    except IntentAlreadyPendingError:
        # The put is conditional on the id not holding a pending intent (#39).
        # Under dedup the id is content-derived, so a pending intent here is an
        # identical hold that won a race past the check above: coalesce onto
        # it, exactly as if the check had seen it. Without dedup the id is
        # ts-based and a pending intent under it is a DIFFERENT call; the
        # refusal propagates and the caller must not report a hold.
        if dedup_id is not None:
            return ApprovalResult(status="coalesced", intent_id=dedup_id)
        raise

    if notifier is not None:
        notifier(
            NotifierEvent(
                intent_id=intent_id,
                rendered_for_human=rendered_for_human,
                expiry=expiry,
                ts=ts,
            )
        )

    return ApprovalResult(status="pending", intent_id=intent_id)


def approve(
    intent_id: str,
    approved_by: str,
    store: IntentStore,
    executor: Callable[[BrokeredCall], Any] | None = None,
    *,
    now: datetime | None = None,
) -> ExecutionResult:
    """Execute an intent after a human approves it through an authenticated path.

    Reads materializedRequest from the store — NEVER from anything the agent re-sends
    after the turn ended. This is the WYSIWYE guarantee: what the human saw in
    renderedForHuman is exactly what the broker executes.

    Two concurrent approval attempts on the same intent cannot both succeed: the
    transition_status() call is a compare-and-set that only one caller can win.

    Unactioned intents auto-deny at expiry. The check happens at call time; DynamoDB
    TTL may have already removed the item before this is called in production.

    Parameters
    ----------
    intent_id:
        The ID of the pending intent to approve and execute.
    approved_by:
        The authenticated human identity from the approval channel (e.g., the IAM
        principal or email address from the approver's authenticated session). Never
        sourced from anything the agent provided.
    store:
        The IntentStore holding the pending intent.
    executor:
        Optional callback that performs the actual connector call. Receives the
        STORED materializedRequest — not any agent-supplied call. Omit in tests
        that check only approval mechanics without executing side effects.
    now:
        The instant the expiry verdict is judged at. Defaults to the wall clock,
        resolved once here. Never derived from the intent's own ``ts`` or any
        other stored record. (``executed_at`` stays a wall-clock observation of
        when the release actually ran; it is not an input to any verdict here.)

    Returns
    -------
    ExecutionResult
        executed=True on success; executed=False with rejection_reason on refusal.
        A refusal raised by the executor itself (ReleaseRefusedError — current
        authority no longer covers the approved call, #9) moves the intent to the
        terminal "refused" state and reports
        "release refused: <reason>"; the connector was never reached.

    Raises
    ------
    QuarantinedIntentError
        Propagated from the store's verify-then-parse read (#349) — a tampered
        row must never execute, and this function deliberately does NOT catch
        it: an uncaught quarantine fails loudly toward less authority, and the
        runtime seam (pep.approve_intent) owns the recorded surfacing.
    """
    evaluated_at = _resolve_now(now)
    intent = store.get_intent(intent_id)
    if intent is None:
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason="intent not found",
        )

    # Check expiry before claiming the intent. Unactioned intents auto-deny at expiry;
    # this mirrors the DynamoDB TTL that removes expired items in production.
    if _is_expired(intent.expiry, evaluated_at):
        # Best-effort status update; may race with another caller but that is fine —
        # both will refuse to execute, which is the correct outcome.
        store.transition_status(intent_id, "pending", "expired")
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason="intent expired",
        )

    # Atomically claim the approval slot. Only one concurrent caller can win.
    transitioned = store.transition_status(
        intent_id, "pending", "approved", approved_by=approved_by
    )
    if not transitioned:
        # Status was not "pending" — already approved, executed, rejected, or expired.
        current = store.get_intent(intent_id)
        current_status = current.status if current is not None else "unknown"
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason=f"intent not pending (current status: {current_status})",
        )

    # WYSIWYE: execute EXACTLY the stored materializedRequest.
    # The stored call was frozen at intent creation — the agent cannot inject
    # anything here, because approve() does not accept a new call parameter.
    stored_call = intent.materializedRequest
    result = None
    if executor is not None:
        try:
            result = executor(stored_call)
        except ReleaseRefusedError as exc:
            # #9 — the executor revalidated current authority and refused. Nothing
            # ran. Move the intent to its own terminal state so a reader can tell
            # a refused release from an executed one and from a release whose
            # connector crashed after the side effect (which stays "approved").
            store.transition_status(intent_id, "approved", "refused")
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason=f"{RELEASE_REFUSED_REASON_PREFIX}: {exc.reason}",
            )

    # Stamp the execution timestamp on the executed transition: it extends the item
    # TTL (executed intents outlive their approval window for the /flag review, #193)
    # and pins the op's UTC day for after-the-fact false_action metering.
    store.transition_status(
        intent_id, "approved", "executed", executed_at=_now_iso()
    )

    return ExecutionResult(
        intent_id=intent_id,
        executed=True,
        result=result,
    )


def reject(
    intent_id: str,
    rejected_by: str,
    store: IntentStore,
    *,
    now: datetime | None = None,
) -> ExecutionResult:
    """Reject a pending intent through an authenticated out-of-band path — NO execution.

    The owner-said-"no" counterpart of approve(): it mirrors approve()'s
    not-found / expired / not-pending guard structure exactly, minus the
    execution step. There is no executor parameter and none is synthesized — a
    rejected intent moves straight to the terminal "rejected" state and the
    stored materializedRequest is never handed to any Doer.

    Two out-of-band actions on the same intent cannot both win: transition_status()
    is a compare-and-set, so a concurrent approve()/reject() race resolves to
    whichever flips "pending" first — the loser refuses.

    Parameters
    ----------
    intent_id:
        The ID of the pending intent to reject.
    rejected_by:
        The authenticated human identity from the approval channel (recorded on
        the intent's approvedBy field as the actor who resolved it). Never sourced
        from anything the agent provided.
    store:
        The IntentStore holding the pending intent.
    now:
        The instant the expiry verdict is judged at; defaults to the wall clock,
        resolved once here, exactly as in approve().

    Returns
    -------
    ExecutionResult
        Always executed=False. rejection_reason is "rejected by owner" on a clean
        rejection, or the matching not-found / expired / not-pending reason.
    """
    evaluated_at = _resolve_now(now)
    intent = store.get_intent(intent_id)
    if intent is None:
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason="intent not found",
        )

    # Symmetric with approve(): an already-expired intent has auto-denied; report
    # that rather than flipping it to "rejected".
    if _is_expired(intent.expiry, evaluated_at):
        store.transition_status(intent_id, "pending", "expired")
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason="intent expired",
        )

    # Atomically claim the intent for rejection. Only one concurrent caller wins;
    # a non-pending intent (already approved/executed/rejected/expired) refuses.
    transitioned = store.transition_status(
        intent_id, "pending", "rejected", approved_by=rejected_by
    )
    if not transitioned:
        current = store.get_intent(intent_id)
        current_status = current.status if current is not None else "unknown"
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason=f"intent not pending (current status: {current_status})",
        )

    return ExecutionResult(
        intent_id=intent_id,
        executed=False,
        rejection_reason=REJECTED_BY_OWNER_REASON,
    )
