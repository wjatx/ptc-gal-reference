"""Supporting types for the enforcement layer.

These are internal types for broker.enforcement — not canonical schemas.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import TypeAdapter

from safe_agents.broker.schemas import Decision, Deny

# Lazily initialized — avoids a module-level TypeAdapter instance being shared
# across tests that may not have schemas available, and is cheap (once per use).
_decision_adapter: TypeAdapter[Decision] | None = None


def _get_adapter() -> TypeAdapter[Decision]:
    global _decision_adapter
    if _decision_adapter is None:
        _decision_adapter = TypeAdapter(Decision)
    return _decision_adapter


def decision_to_json(decision: Decision) -> str:
    """Serialize a Decision to a JSON string."""
    return _get_adapter().dump_json(decision).decode()


def json_to_decision(json_str: str) -> Decision:
    """Deserialize a Decision from a JSON string."""
    return _get_adapter().validate_json(json_str)


LedgerStatus = Literal["uncommitted", "committed", "compensated", "escalated"]

IdempotencyStatus = Literal["in_flight", "executed", "failed"]

# A record read back without a status attribute predates the claim lifecycle and
# is by definition a completed outcome: the only writer that ever existed wrote
# the row AFTER its executor returned. Every backend applies this default so a
# pre-existing row keeps replaying exactly as it did (the same tolerate-absence
# pattern result_json uses).
DEFAULT_IDEMPOTENCY_STATUS: IdempotencyStatus = "executed"

# The placeholder a claim carries until its real outcome is known. An in_flight
# row is never consulted for a Decision, so there is nothing honest to put here.
IN_FLIGHT_DECISION_JSON = ""


@dataclass
class IdempotencyRecord:
    """Stored claim-and-outcome for an idempotency key.

    The row is written in two steps, because a record written only after
    execution cannot deduplicate anything: two concurrent callers both read an
    absent key and both execute. So ``enforce()`` CLAIMS the key with a
    conditional put BEFORE the executor runs (status ``in_flight``) and
    transitions the same row afterwards with a compare-and-set:

      ``in_flight`` — claimed, executor may be running right now. A second
        caller arriving on this key is REFUSED (deny), never executed.
      ``executed``  — the side effect completed; decision_json and result_json
        carry the real outcome and a retry replays it.
      ``failed``    — the executor raised. Whether the external effect happened
        is unknowable locally, so the key is burned: a retry is refused and the
        caller must reconcile and use a new key.

    A crash between claim and transition leaves an ``in_flight`` row that
    refuses the key until an operator clears it with ``delete_idempotency``.
    That is deliberate: a timeout-based auto-release would re-open the
    double-execution window it exists to close. ``ts`` is the CLAIM time, so the
    age of a stuck claim is readable straight off the row.

    Only EXECUTED outcomes (allow/transform) survive as records (#148): the
    record's purpose is exactly-once side effects, and a
    deny/abstain/require_approval executed nothing, so ``enforce()`` deletes the
    claim on those outcomes. Non-executed outcomes are time-dependent and must
    re-evaluate on retry, never replay.

    decision_json is the serialized Decision that was returned for this key;
    callers retrieve the Decision via decision(). It is the empty placeholder
    while the record is a claim.

    result_json is the JSON-serialized connector result that was returned on the
    original allow/transform call, so a replay hands the caller the SAME outcome
    instead of None. It is None only when no executor was supplied (the caller
    executes separately) or the executor returned None. This is connector return
    data at rest in the broker-owned idempotency table (KMS-encrypted, brokerRole
    only) — consistent with the broker already owning decision and ledger state.
    DynamoDB's 400KB item limit bounds the result size; no truncation is applied.

    error carries the executor's exception string on a ``failed`` record, for the
    operator reconciling the uncertain outcome. It is None otherwise.
    """

    key: str
    decision_json: str
    ts: str
    result_json: str | None = None
    status: IdempotencyStatus = DEFAULT_IDEMPOTENCY_STATUS
    error: str | None = None

    def decision(self) -> Decision:
        """The stored Decision.

        A claim carries no decision yet, so the placeholder reads back as a deny
        rather than raising on empty JSON: every caller that reaches a Decision
        for an in_flight row is asking "may this proceed", and the answer is no.
        """
        if not self.decision_json:
            return Deny(
                kind="deny",
                reason=f"idempotency key {self.key!r} is claimed but has no recorded outcome",
            )
        return json_to_decision(self.decision_json)

    def result(self) -> Any:
        """The cached connector result for this key, or None if none was stored."""
        if self.result_json is None:
            return None
        return json.loads(self.result_json)


@dataclass
class LedgerEntry:
    """Write-ahead ledger (WAL) record for a broker operation.

    Written before execution (status="uncommitted"); committed after successful
    execution or after human approval for require_approval decisions.
    Uncommitted entries on restart trigger saga compensation or escalation.
    """

    entry_id: str
    idempotency_key: str | None
    # JSON-serialized BrokeredCall — the frozen intent that will execute
    call_json: str
    decision_kind: str
    status: LedgerStatus
    ts_created: str
    ts_committed: str | None = None
    error: str | None = None


@dataclass
class EnforcementResult:
    """Outcome of enforce() — carries the final decision and WAL reference."""

    # The effective decision after idempotency check + premise revalidation.
    # May differ from the initial_decision passed to enforce() if the world changed.
    decision: Decision
    # True if a prior outcome was replayed (idempotency_key was already seen).
    # The executor was NOT called in this case.
    idempotent: bool
    # The WAL entry ID written for this call. None only on idempotent replay.
    # For require_approval decisions this entry stays "uncommitted" until HITL approval.
    ledger_entry_id: str | None
    # The connector's opaque result on the allow/transform execute path, and the
    # cached result replayed on idempotent hits. None for deny / abstain /
    # require_approval, which run no connector call.
    result: Any = None
