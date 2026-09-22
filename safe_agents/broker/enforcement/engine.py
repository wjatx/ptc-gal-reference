"""broker.enforcement.engine — execution-integrity wrapper around the PDP.

enforce() sits between an initial decide() call and the actual connector
execution. It provides:

  1. Idempotency        — a caller-supplied key deduplicates replays, by
                          CLAIMING the key before the executor runs rather than
                          recording it afterwards. A read-then-execute-then-write
                          record deduplicates nothing under concurrency: two
                          callers both read an absent key and both execute the
                          side effect. So step 1 conditionally puts an
                          "in_flight" record, and a caller that loses that put
                          is refused instead of executing. The claim then
                          transitions to "executed" (replayable) or "failed"
                          (the key is burned — a local claim cannot know whether
                          the external effect happened, and re-executing is the
                          double-effect harm). A crash between claim and
                          transition strands an "in_flight" row that refuses its
                          key until an operator clears it with
                          store.delete_idempotency(key); the record's ts is the
                          claim time, so the age of a stuck claim is readable.
                          There is deliberately NO timeout-based auto-release:
                          it would re-open the double-execution window.
  2. Premise revalidation — re-reads facts and re-decides; if the world
                            changed (grant demoted, cap exhausted) the
                            enforcement uses the tighter outcome, never
                            blindly executing the initial decision.
  3. Atomic counter     — budget cap decremented with compare-and-set
                          semantics before any side effect executes;
                          two concurrent callers cannot both slip under.
  4. Write-ahead ledger — intent journaled (status="uncommitted") before
                          the executor is called; committed after success;
                          uncommitted entries on restart trigger saga
                          compensation or escalation.
  5. HITL gate          — for require_approval decisions the ledger entry
                          is NOT committed until a human approves (that
                          approval path is issue #47); the entry waits as
                          "uncommitted" representing the held intent.

The executor callback is optional so the enforcement layer can be tested
and used independently of the connector implementations.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from safe_agents.broker.marshal import marshal_connector_result
from safe_agents.broker.pdp import Facts
from safe_agents.broker.schemas import BrokeredCall, Decision, Deny

from .store import EnforcementStore
from .types import (
    IN_FLIGHT_DECISION_JSON,
    EnforcementResult,
    CounterDraw,
    IdempotencyRecord,
    LedgerEntry,
    decision_to_json,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def enforce(
    call: BrokeredCall,
    initial_decision: Decision,
    *,
    idempotency_key: str | None,
    counter_key: str,
    counter_delta: float,
    counter_cap: float,
    ancestor_draws: "Sequence[CounterDraw]" = (),
    decider: Callable[[BrokeredCall, Facts], Decision],
    fresh_facts: Callable[[BrokeredCall], Facts],
    store: EnforcementStore,
    executor: Callable[[BrokeredCall, Decision], Any] | None = None,
) -> EnforcementResult:
    """Execute the enforcement pipeline for a brokered call.

    Parameters
    ----------
    call:
        The typed BrokeredCall to enforce.
    initial_decision:
        The Decision returned by the first decide() call in the PDP flow.
    idempotency_key:
        Caller-supplied deduplication key. The key is CLAIMED before any side
        effect and settled after it. A prior executed outcome replays without
        re-executing; a claim another caller still holds, or one whose executor
        failed, is refused with a deny. Only executed outcomes (allow/transform)
        survive as records (#148); a deny/abstain/require_approval releases the
        claim, so a retry re-evaluates against fresh facts. Pass None to skip
        idempotency deduplication entirely, which also skips the claim.
    counter_key:
        Identifies which budget counter to decrement (e.g. the error-budget
        or a per-period capacity counter for this action class).
    counter_delta:
        Amount to add to the counter. For error budgets: error_prob × blast_radius.
        For capacity budgets: 1 per call, or the declared cost.
    counter_cap:
        The hard cap. The decrement is refused (→ deny) if the result would
        exceed this value.
    ancestor_draws:
        Additional budget draws this call must ALSO satisfy, drawn after the
        primary one. For a delegated call these are the delegation-tree pools
        keyed by ``enforcement.store.tree_counter_key``, which is the only bound
        that spans siblings: each child's own cap bounds that child, and nothing
        bounds the set (#11). Empty for a root principal, which is why an
        undelegated deployment behaves exactly as before.

        Refusing ANY draw refuses the call, so authority is the intersection of
        every bound rather than the acting principal's alone.

        ORDER AND PARTIAL DRAWS. ``try_increment_counter`` is atomic per key and
        there is no multi-key transaction on the EnforcementStore protocol, so a
        sequence of draws is not atomic as a group: the primary can succeed and
        an ancestor then refuse. Nothing is compensated, deliberately. A refused
        call may leave the primary counter charged for an action that never ran,
        which spends the CHILD's own headroom -- the fail-toward-less-authority
        direction -- and ages out at the next period rollover. The primary is
        drawn first precisely so the over-charge lands on the single child rather
        than on the pool every sibling shares; the reverse order would let one
        child's refusal eat the whole tree's budget. A decrement primitive would
        be the alternative and is worse: it is a write that can itself fail, and
        it hands the enforcement path an operation that RELEASES authority.
    decider:
        The PDP's decide() function. Used for premise revalidation.
    fresh_facts:
        A callable that re-reads current Facts from the PIP (grant state,
        counter balances, human reachability). Called once during revalidation.
    store:
        The EnforcementStore implementation (InMemoryStore in tests; DynamoStore
        in production).
    executor:
        Optional callback that performs the actual connector call and RETURNS the
        connector's (JSON-serializable) result. Called only when the effective
        decision is allow or transform and premise revalidation passed. The returned
        result is persisted on the idempotency record and replayed on future hits.
        Omit (or pass None) when testing or when the caller will execute separately.

    Returns
    -------
    EnforcementResult
        Carries the effective decision, an idempotent flag, and the WAL entry ID.
    """

    # ------------------------------------------------------------------
    # Step 1 — idempotency claim (executed outcomes ONLY replay — #148)
    #
    # Read, then CLAIM. The read answers the three settled cases: an executed
    # allow/transform replays; a claim someone else holds is refused; a failed
    # claim is refused as an uncertain outcome. A stored non-executed outcome
    # (deny/abstain/require_approval) is a pre-#148 record — no step here writes
    # one any more — or one written by a not-yet-updated broker. It must not
    # replay: the refusal was time-dependent, and replaying it forever defeats
    # the retry semantics the key exists for. Delete it so the table self-heals
    # (leaving it would also block the claim below — every later retry would
    # then re-execute).
    #
    # The claim itself is the fix for the concurrency defect: the read alone
    # cannot deduplicate, because two callers can both read an absent key before
    # either writes. Only the conditional put is atomic, so it has to happen
    # BEFORE the side effect rather than after it.
    # ------------------------------------------------------------------
    # The key this call holds a claim on, or None when it holds none (no key was
    # supplied, or the put lost). Carrying the key rather than a bool keeps every
    # settle site unambiguous about WHICH key it is settling.
    claimed_key: str | None = None
    if idempotency_key is not None:
        stored = store.get_idempotency(idempotency_key)
        if stored is not None:
            settled = _settled_outcome(stored, idempotency_key)
            if settled is not None:
                return settled
            store.delete_idempotency(idempotency_key)

        won_claim = store.put_idempotency_if_absent(
            IdempotencyRecord(
                key=idempotency_key,
                decision_json=IN_FLIGHT_DECISION_JSON,
                ts=_now_iso(),
                status="in_flight",
            )
        )
        if not won_claim:
            # Someone claimed (or settled) the key between the get and the put.
            # Re-read and apply the same three settled cases; anything else means
            # a racer is mid-flight on a row we cannot interpret, so refuse rather
            # than execute. Failing toward less authority is the whole point of
            # claiming first.
            stored = store.get_idempotency(idempotency_key)
            settled = (
                None if stored is None else _settled_outcome(stored, idempotency_key)
            )
            if settled is not None:
                return settled
            return _refusal(
                f"idempotency key {idempotency_key!r} is contended; another call "
                "claimed it concurrently. Retry later."
            )
        claimed_key = idempotency_key

    # Steps 2-4 run BEFORE any side effect, so a fault in them cannot have
    # executed anything: release the claim rather than stranding the key. Only a
    # fault at or after the executor leaves an uncertain outcome, and that one is
    # settled as "failed" in Step 5.
    try:
        # ------------------------------------------------------------------
        # Step 2 — premise revalidation
        # Re-read facts and re-decide. If the world changed since the initial
        # decide() (grant demoted, cap exhausted, human unreachable) use the
        # tighter outcome rather than blindly executing the stale decision.
        # ------------------------------------------------------------------
        current_facts = fresh_facts(call)
        revalidated = decider(call, current_facts)

        # Derive the effective decision.  The revalidated decision takes
        # precedence whenever it is more restrictive than the initial one.
        # "More restrictive" means: deny/abstain beats allow/transform;
        # require_approval beats allow/transform; anything beats allow.
        effective = _pick_stricter(initial_decision, revalidated)

        # --------------------------------------------------------------
        # Step 3 — atomic budget counter decrement
        # Only decrement when the decision would actually execute an action.
        # Deny / abstain / require_approval do not consume budget here.
        # --------------------------------------------------------------
        if effective.kind in ("allow", "transform"):
            incremented = store.try_increment_counter(
                counter_key, counter_delta, counter_cap
            )
            if not incremented:
                effective = Deny(kind="deny", reason="capacity budget exceeded")
            else:
                # Every ancestor pool must also have headroom. The reason names
                # the tree pool rather than reusing "capacity budget exceeded",
                # because the two denials call for opposite responses: the
                # child's own cap is a knob on the child, while a pool refusal
                # means a SIBLING spent the shared budget and raising this
                # child's cap would change nothing.
                for draw in ancestor_draws:
                    if not store.try_increment_counter(
                        draw.key, draw.delta, draw.cap
                    ):
                        effective = Deny(
                            kind="deny",
                            reason=(
                                "delegation-tree budget exceeded "
                                f"(pool {draw.key})"
                            ),
                        )
                        break

        # --------------------------------------------------------------
        # Step 4 — write-ahead ledger (intent journaled BEFORE execution)
        # --------------------------------------------------------------
        entry_id = str(uuid.uuid4())
        ledger_entry = LedgerEntry(
            entry_id=entry_id,
            idempotency_key=idempotency_key,
            call_json=call.model_dump_json(),
            decision_kind=effective.kind,
            status="uncommitted",
            ts_created=_now_iso(),
        )
        store.write_ledger(ledger_entry)
    except BaseException:
        if claimed_key is not None:
            _release_claim(store, claimed_key)
        raise

    # ------------------------------------------------------------------
    # Step 5 — execute / HITL gate / saga
    #
    # allow / transform  → call executor, then commit the ledger entry.
    # require_approval   → HITL gate: ledger stays "uncommitted" until a
    #                      human approves via the approval flow (#47).
    # deny / abstain     → no side effect; still commit the WAL so the
    #                      record of refusal is durable.
    # ------------------------------------------------------------------
    # The connector's opaque result, captured from the executor so it can be
    # persisted for replay and returned to the caller. None whenever no executor
    # runs (deny / abstain / require_approval, or no executor supplied).
    exec_result: Any = None
    if effective.kind in ("allow", "transform"):
        if executor is not None:
            try:
                exec_result = executor(call, effective)
            except Exception as exc:  # noqa: BLE001
                # Execution failed: mark the ledger entry for saga handling.
                # Reversible actions: compensate; irreversible: escalate.
                reversible = call.manifest.reversible is True
                if reversible:
                    store.compensate_ledger(entry_id, str(exc))
                else:
                    store.escalate_ledger(entry_id, str(exc))
                # Burn the key. The connector raised, so whether the external
                # effect landed is unknowable from here — a timeout on a transfer
                # looks identical whether the transfer went through or not.
                # Re-executing under the same key is the double-effect harm, so a
                # retry is refused until an operator reconciles and issues a new
                # key. Guarded: a store fault settling the claim must not replace
                # the connector's exception, which is the one the caller needs.
                if claimed_key is not None:
                    _fail_claim(store, claimed_key, str(exc))
                # Re-raise so the caller knows the execution failed.
                raise

        store.commit_ledger(entry_id, _now_iso())

    elif effective.kind == "require_approval":
        # HITL gate: the ledger entry waits as "uncommitted".
        # The approval flow (#47) will commit it once a human approves.
        # The entry itself is the durable "draft and hold" record.
        pass

    else:
        # deny / abstain — no action taken; commit the record of refusal.
        store.commit_ledger(entry_id, _now_iso())

    # ------------------------------------------------------------------
    # Step 6 — settle the claim (executed outcomes ONLY survive — #148)
    # Transition the in_flight claim to executed, carrying the final decision AND
    # the connector result, so a future replay with the same key returns the same
    # outcome (result included) without re-executing. result_json is None unless
    # an executor actually ran; if the connector result is not JSON-serializable
    # json.dumps raises loudly here — that is a connector-contract violation worth
    # surfacing, not swallowing.
    #
    # The record's purpose is exactly-once SIDE EFFECTS, and only allow/transform
    # execute one. A deny/abstain/require_approval executed nothing and is
    # time-dependent (a cap resets next UTC day, a grant gets promoted, an
    # envelope knob changes) — recording it would replay the stale refusal
    # forever and defeat the retry semantics a deterministic idempotency key is
    # chosen for. So those RELEASE the claim instead, and a retry re-enters
    # premise revalidation above; duplicate require_approval holds are
    # de-amplified by the approval-queue dedup knob (sa#160), not by this record.
    # ------------------------------------------------------------------
    if claimed_key is not None:
        if effective.kind in ("allow", "transform"):
            _complete_claim(
                store,
                claimed_key,
                decision_json=decision_to_json(effective),
                # marshal first: a typed connector result (MCP's CallToolResult)
                # is not JSON-native, and crashing HERE would fail a call the
                # connector already executed — the worst place to discover it.
                result_json=(
                    json.dumps(marshal_connector_result(exec_result))
                    if exec_result is not None
                    else None
                ),
            )
        else:
            _release_claim(store, claimed_key)

    return EnforcementResult(
        decision=effective,
        idempotent=False,
        ledger_entry_id=entry_id,
        result=exec_result,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _refusal(reason: str) -> EnforcementResult:
    """A deny that executed nothing and journaled nothing.

    ledger_entry_id is None because the call never reached Step 4 — there is no
    intent to journal when the broker refuses on the idempotency record alone.
    idempotent is False because nothing was replayed: this is a fresh refusal,
    not a cached outcome.
    """
    return EnforcementResult(
        decision=Deny(kind="deny", reason=reason),
        idempotent=False,
        ledger_entry_id=None,
        result=None,
    )


def _settled_outcome(
    stored: IdempotencyRecord, key: str
) -> EnforcementResult | None:
    """The outcome to return for an existing record, or None to re-claim the key.

    Three settled cases, and one that is not settled at all:

      in_flight — another caller holds the claim and may be executing right now.
        REFUSE. This is the whole point of claiming: the alternative is to
        execute, which is exactly the double side effect the key exists to stop.
      failed    — the previous attempt's executor raised, so the external effect
        may or may not have landed. REFUSE, and say what the operator has to do,
        because no local state can settle that question.
      executed allow/transform — replay the stored outcome verbatim.
      anything else — a pre-#148 non-executed record. Not settled: return None so
        the caller deletes it and claims the key afresh.
    """
    if stored.status == "in_flight":
        return _refusal(
            f"idempotency key {key!r} is in flight (claimed at {stored.ts}); "
            "retry later. A stale claim left by a crashed broker is cleared with "
            "delete_idempotency."
        )
    if stored.status == "failed":
        return _refusal(
            f"idempotency key {key!r} was already attempted and its executor "
            f"failed with an uncertain outcome ({stored.error}); the side effect "
            "may or may not have landed. Reconcile with the connector, then retry "
            "under a NEW key."
        )
    decision = stored.decision()
    if decision.kind in ("allow", "transform"):
        return EnforcementResult(
            decision=decision,
            idempotent=True,
            ledger_entry_id=None,
            result=stored.result(),
        )
    return None


def _complete_claim(
    store: EnforcementStore,
    key: str,
    *,
    decision_json: str,
    result_json: str | None,
) -> None:
    """Settle this call's claim as executed, so a retry replays it.

    A False return means the row is gone or was settled by someone else, which
    can only happen if an operator deleted it mid-flight. The side effect already
    ran, so there is nothing to undo and nothing to fail the call over — but the
    outcome is now unrecorded, and a retry under this key would re-execute. Log
    it loudly rather than gate the op that already succeeded.
    """
    if not store.complete_idempotency(
        key, decision_json=decision_json, result_json=result_json
    ):
        logger.error(
            "idempotency claim %r vanished before its executed outcome could be "
            "recorded; a retry under this key will re-execute",
            key,
        )


def _fail_claim(store: EnforcementStore, key: str, error: str) -> None:
    """Burn this call's claim after a connector error.

    Guarded in full: the connector's exception is the one the caller must see, so
    a store fault here is logged and swallowed rather than allowed to replace it.
    """
    try:
        settled = store.fail_idempotency(key, error=error)
    except Exception:  # noqa: BLE001 — never mask the connector's exception
        logger.exception(
            "idempotency claim %r could not be marked failed after a connector "
            "error; a retry under this key may double-execute",
            key,
        )
        return
    if not settled:
        logger.error(
            "idempotency claim %r was already settled when a connector error "
            "tried to mark it failed; a retry under this key may double-execute",
            key,
        )


def _release_claim(store: EnforcementStore, key: str) -> None:
    """Drop this call's claim so the key is retryable.

    Used for the non-executed outcomes (#148) and for a fault before any side
    effect could have happened. Guarded for the fault path: a store error here
    must not replace the exception that caused it, and the cost of a leaked claim
    is a refused retry, never a double effect.
    """
    try:
        store.delete_idempotency(key)
    except Exception:  # noqa: BLE001 — never mask the original failure
        logger.exception(
            "idempotency claim %r could not be released; the key stays in flight "
            "until an operator clears it with delete_idempotency",
            key,
        )

# Priority order for "which decision is stricter".
# Lower value = more permissive; higher = more restrictive.
_STRICTNESS: dict[str, int] = {
    "allow": 0,
    "transform": 1,
    "require_approval": 2,
    "abstain": 3,
    "deny": 4,
}


def _pick_stricter(a: Decision, b: Decision) -> Decision:
    """Return whichever decision is more restrictive (deny > abstain > require_approval > ...)."""
    if _STRICTNESS.get(b.kind, 0) > _STRICTNESS.get(a.kind, 0):
        return b
    return a
