"""broker.enforcement.engine — execution-integrity wrapper around the PDP.

enforce() sits between an initial decide() call and the actual connector
execution. It provides:

  1. Idempotency        — a caller-supplied key deduplicates replays.
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
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from safe_agents.broker.marshal import marshal_connector_result
from safe_agents.broker.pdp import Facts
from safe_agents.broker.schemas import BrokeredCall, Decision, Deny

from .store import EnforcementStore
from .types import EnforcementResult, IdempotencyRecord, LedgerEntry, decision_to_json


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
        Caller-supplied deduplication key. If a prior outcome is stored
        under this key the function returns that outcome immediately without
        re-executing. Only executed outcomes (allow/transform) are ever
        stored (#148); a retry after a deny/abstain/require_approval
        re-evaluates against fresh facts. Pass None to skip idempotency
        deduplication.
    counter_key:
        Identifies which budget counter to decrement (e.g. the error-budget
        or a per-period capacity counter for this action class).
    counter_delta:
        Amount to add to the counter. For error budgets: error_prob × blast_radius.
        For capacity budgets: 1 per call, or the declared cost.
    counter_cap:
        The hard cap. The decrement is refused (→ deny) if the result would
        exceed this value.
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
    # Step 1 — idempotency check (executed outcomes ONLY replay — #148)
    # A stored non-executed outcome (deny/abstain/require_approval) is a
    # pre-#148 record — Step 6 no longer writes them — or one written by a
    # not-yet-updated broker. It must not replay: the refusal was
    # time-dependent, and replaying it forever defeats the retry semantics
    # the key exists for. Delete it so the table self-heals (leaving it
    # would also block Step 6's put_if_absent from recording the executed
    # outcome of THIS retry — every later retry would then re-execute).
    # ------------------------------------------------------------------
    if idempotency_key is not None:
        stored = store.get_idempotency(idempotency_key)
        if stored is not None:
            stored_decision = stored.decision()
            if stored_decision.kind in ("allow", "transform"):
                return EnforcementResult(
                    decision=stored_decision,
                    idempotent=True,
                    ledger_entry_id=None,
                    result=stored.result(),
                )
            store.delete_idempotency(idempotency_key)

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

    # ------------------------------------------------------------------
    # Step 3 — atomic budget counter decrement
    # Only decrement when the decision would actually execute an action.
    # Deny / abstain / require_approval do not consume budget here.
    # ------------------------------------------------------------------
    if effective.kind in ("allow", "transform"):
        incremented = store.try_increment_counter(counter_key, counter_delta, counter_cap)
        if not incremented:
            effective = Deny(kind="deny", reason="capacity budget exceeded")

    # ------------------------------------------------------------------
    # Step 4 — write-ahead ledger (intent journaled BEFORE execution)
    # ------------------------------------------------------------------
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
    # Step 6 — record idempotency outcome (executed outcomes ONLY — #148)
    # Store the final decision AND the connector result so a future replay with
    # the same key returns the same outcome (result included) without re-executing.
    # result_json is None unless an executor actually ran; if the connector result
    # is not JSON-serializable json.dumps raises loudly here — that is a
    # connector-contract violation worth surfacing, not swallowing.
    #
    # The record's purpose is exactly-once SIDE EFFECTS, and only allow/transform
    # execute one. A deny/abstain/require_approval executed nothing and is
    # time-dependent (a cap resets next UTC day, a grant gets promoted, an
    # envelope knob changes) — recording it would replay the stale refusal
    # forever and defeat the retry semantics a deterministic idempotency key is
    # chosen for. Retries of non-executed outcomes re-enter premise revalidation
    # above instead; duplicate require_approval holds are de-amplified by the
    # approval-queue dedup knob (sa#160), not by this record.
    # ------------------------------------------------------------------
    if idempotency_key is not None and effective.kind in ("allow", "transform"):
        idem_record = IdempotencyRecord(
            key=idempotency_key,
            decision_json=decision_to_json(effective),
            ts=_now_iso(),
            # marshal first: a typed connector result (MCP's CallToolResult)
            # is not JSON-native, and crashing HERE would fail a call the
            # connector already executed — the worst place to discover it.
            result_json=(
                json.dumps(marshal_connector_result(exec_result))
                if exec_result is not None
                else None
            ),
        )
        store.put_idempotency_if_absent(idem_record)

    return EnforcementResult(
        decision=effective,
        idempotent=False,
        ledger_entry_id=entry_id,
        result=exec_result,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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
