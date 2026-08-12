"""Supporting types for the enforcement layer.

These are internal types for broker.enforcement — not canonical schemas.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import TypeAdapter

from safe_agents.broker.schemas import Decision

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


@dataclass
class IdempotencyRecord:
    """Stored outcome for a previously seen idempotency key.

    Only EXECUTED outcomes (allow/transform) are recorded (#148): the record's
    purpose is exactly-once side effects, and a deny/abstain/require_approval
    executed nothing. Non-executed outcomes are time-dependent and must
    re-evaluate on retry, never replay.

    decision_json is the serialized Decision that was returned for this key;
    callers retrieve the Decision via decision().

    result_json is the JSON-serialized connector result that was returned on the
    original allow/transform call, so a replay hands the caller the SAME outcome
    instead of None. It is None only when no executor was supplied (the caller
    executes separately) or the executor returned None. This is connector return
    data at rest in the broker-owned idempotency table (KMS-encrypted, brokerRole
    only) — consistent with the broker already owning decision and ledger state.
    DynamoDB's 400KB item limit bounds the result size; no truncation is applied.
    """

    key: str
    decision_json: str
    ts: str
    result_json: str | None = None

    def decision(self) -> Decision:
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
