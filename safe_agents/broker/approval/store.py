"""IntentStore — persistence interface for the approval layer.

Two implementations here (a third, SqliteIntentStore, lives in sqlite_store.py):
  InMemoryIntentStore  — thread-safe in-process fake for tests; no AWS, no creds
  DynamoIntentStore    — production DynamoDB with conditional writes; boto3 is imported
                         lazily (inside method bodies) so this module loads without credentials

The Protocol is the contract; callers depend only on it.

STORED-BYTES integrity basis (#349, the grants/store.py #246 idiom): the intent's
FROZEN half — id, materializedRequest, renderedForHuman, expiry, ts — is
serialized ONCE (canonical_intent_payload), that exact string is stored as the
item's ``data`` attribute AND HMAC'd into the item-level ``intentHash``
attribute. On read the stored bytes are verified VERBATIM before parsing
(verify-then-parse); tampered bytes are evidence, never an Intent, and are
NEVER parsed. The mutable lifecycle attrs (status, approvedBy, executedAt) stay
OUTSIDE the basis: they are CAS-transitioned by the broker and never authorize
what executes — the frozen call does — so a transition never re-mints the HMAC
(re-minting on every status flip would be an auto-repair surface).

Unlike the grants stores (which RETURN a quarantine result for the ceremony's
conditional-update flow), get_intent RAISES QuarantinedIntentError on a
verification failure. The intent Protocol's ``Intent | None`` contract has many
callers, and a tamper surfaced as None would read as "not found" — the silent
drop #349 forbids. An exception fails toward LESS authority by construction:
an oblivious caller propagates loudly instead of executing.

The HMAC key is injected at store construction from the same surface the
grants/registry stores use (boot_config.resolve_hmac_key on the broker boot).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import threading
from typing import Mapping, Protocol, runtime_checkable

from safe_agents.broker.schemas import BrokeredCall, Intent

# How long an EXECUTED intent is retained past its approval-window TTL (#193 Phase 6c).
# A pending intent's TTL is the short approval window; once it executes, the item must
# survive long enough for an after-the-fact owner /flag review — an executed intent that
# auto-deleted at the approval TTL is unflaggable. This extends the TTL at the executed
# transition. The durable LONG-TERM referent of an executed op stays the audit record
# (#204); this is only the /flag review window, so a week, not forever.
EXECUTED_INTENT_RETENTION_DAYS = 7


class QuarantinedIntentError(Exception):
    """Read refused: the stored intent bytes failed HMAC verification (#349).

    An A4 attacker (store write access) who rewrites the frozen call between
    hold and release must never get the rewritten call executed. The stored
    bytes are untrusted evidence — never parsed, never served, never
    auto-repaired — and every caller's refusal fails toward less authority:
    the action simply does not run. Surfacing loudly is the runtime's job
    (pep.py mirrors the sa#124 grant-quarantine surfacing).
    """

    def __init__(self, intent_id: str, reason: str) -> None:
        self.intent_id = intent_id
        self.reason = reason
        super().__init__(f"intent {intent_id!r} quarantined: {reason}")


def canonical_intent_payload(intent: Intent) -> str:
    """The ONE serialization of an intent's frozen half — stored AND HMAC'd.

    Storage and the integrity basis must be the same bytes (#246): serialize
    once, store this exact string, HMAC this exact string, and on read HMAC
    the stored bytes verbatim without ever re-serializing — so additive schema
    growth never makes an intact old row read as tampered.

    Canonical form matches canonical_grant_payload: JSON with sorted keys,
    compact separators, ASCII, values via Pydantic's JSON mode. Only the
    creation-frozen fields are inside the basis; status/approvedBy/executedAt
    are lifecycle state the broker CAS-transitions and live at item level,
    like the intentHash slot itself.
    """
    return json.dumps(
        {
            "id": intent.id,
            "materializedRequest": intent.materializedRequest.model_dump(mode="json"),
            "renderedForHuman": intent.renderedForHuman,
            "expiry": intent.expiry,
            "ts": intent.ts,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _hmac_payload(payload: str, hmac_key: bytes) -> str:
    return _hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def intent_item_attrs(intent: Intent, hmac_key: bytes) -> dict:
    """The stored item attrs shared by every backend's put path.

    Serialize once; the stored ``data`` string IS the HMAC basis (#246/#349).
    """
    payload = canonical_intent_payload(intent)
    attrs: dict = {
        "data": payload,
        "intentHash": _hmac_payload(payload, hmac_key),
        "status": intent.status,
    }
    if intent.approvedBy is not None:
        attrs["approvedBy"] = intent.approvedBy
    if intent.executedAt is not None:
        attrs["executedAt"] = intent.executedAt
    return attrs


def intent_from_item(intent_id: str, attrs: Mapping, hmac_key: bytes) -> Intent:
    """Verify-then-parse a stored intent item (shared by all backends).

    The stored bytes are HMAC'd VERBATIM against the item-level intentHash
    before any parse; a mismatch — or a missing/non-string half, or a payload
    whose embedded id does not match the row key (a valid row replayed under
    another intent's key) — raises QuarantinedIntentError. Tampered bytes are
    untrusted input and never parsed.
    """
    data = attrs.get("data")
    stored_hash = attrs.get("intentHash")
    if not isinstance(data, str) or not isinstance(stored_hash, str):
        raise QuarantinedIntentError(
            intent_id,
            "stored item is missing its data or intentHash attribute; the "
            "item cannot be verified and must not release anything",
        )
    expected = _hmac_payload(data, hmac_key)
    if stored_hash != expected:
        raise QuarantinedIntentError(
            intent_id,
            f"HMAC mismatch over stored intent bytes: stored={stored_hash!r} "
            f"expected={expected!r}",
        )
    payload = json.loads(data)
    if payload.get("id") != intent_id:
        raise QuarantinedIntentError(
            intent_id,
            f"stored payload identity {payload.get('id')!r} does not match the "
            f"row key {intent_id!r} (cross-row replay)",
        )
    return Intent(
        id=intent_id,
        materializedRequest=BrokeredCall.model_validate(payload["materializedRequest"]),
        renderedForHuman=payload["renderedForHuman"],
        status=attrs["status"],
        expiry=payload["expiry"],
        approvedBy=attrs.get("approvedBy"),
        ts=payload["ts"],
        executedAt=attrs.get("executedAt"),
    )


@runtime_checkable
class IntentStore(Protocol):
    """Persistence interface for the approval layer.

    Status transitions must be atomic — two concurrent approvals of the same intent
    cannot both succeed. Implementations use conditional writes (DynamoDB) or
    per-intent locks (InMemory) to enforce this.
    """

    def put_intent(self, intent: Intent) -> None:
        """Persist a new intent. Called once at creation (status=pending)."""
        ...

    def get_intent(self, intent_id: str) -> Intent | None:
        """Retrieve the intent by ID, or None if not found.

        Raises QuarantinedIntentError when the stored bytes fail HMAC
        verification (#349) — tampered bytes are never parsed or returned.
        """
        ...

    def transition_status(
        self,
        intent_id: str,
        expected_status: str,
        new_status: str,
        approved_by: str | None = None,
        executed_at: str | None = None,
    ) -> bool:
        """Atomically transition the intent's status from expected_status to new_status.

        Returns True when the transition succeeded (the stored status matched expected_status).
        Returns False when the stored status did not match (already approved, expired, etc.).

        Must be atomic: two concurrent callers with the same intent_id cannot both return True.

        ``executed_at`` is the ISO-8601 UTC execution timestamp, passed ONLY on the
        approved→executed transition. When present it is stamped onto the intent's
        executedAt field and (in the durable store) the item TTL is extended to now +
        EXECUTED_INTENT_RETENTION_DAYS so the executed intent stays flaggable past its
        short approval window.
        """
        ...


# ---------------------------------------------------------------------------
# InMemoryIntentStore — thread-safe fake; atomicity via per-intent Lock
# ---------------------------------------------------------------------------


class InMemoryIntentStore:
    """Thread-safe in-memory implementation for tests and local development.

    ITEM-SHAPED to mirror the DynamoDB semantics (the InMemoryGrantStore
    precedent): each entry is the intent_item_attrs dict, so stored-bytes
    tamper tests exercise the same verify-then-parse path as production.

    Status transitions are protected by a per-intent threading.Lock that wraps a
    check → mutate cycle, exercising the same compare-and-set semantics as DynamoDB's
    ConditionExpression without requiring AWS credentials or network access.
    """

    def __init__(self, hmac_key: bytes = b"test-hmac-key") -> None:
        self._hmac_key = hmac_key
        # intent_id -> {"data", "intentHash", "status"[, "approvedBy"][, "executedAt"]}
        self._items: dict[str, dict] = {}
        # Per-intent locks protect status transitions; the registry lock protects
        # the lock map itself so new intents can be added safely under concurrency.
        self._locks: dict[str, threading.Lock] = {}
        self._registry_lock = threading.Lock()

    def _get_lock(self, intent_id: str) -> threading.Lock:
        with self._registry_lock:
            if intent_id not in self._locks:
                self._locks[intent_id] = threading.Lock()
            return self._locks[intent_id]

    def put_intent(self, intent: Intent) -> None:
        lock = self._get_lock(intent.id)
        with lock:
            self._items[intent.id] = intent_item_attrs(intent, self._hmac_key)

    def get_intent(self, intent_id: str) -> Intent | None:
        lock = self._get_lock(intent_id)
        with lock:
            item = self._items.get(intent_id)
            if item is None:
                return None
            return intent_from_item(intent_id, item, self._hmac_key)

    def transition_status(
        self,
        intent_id: str,
        expected_status: str,
        new_status: str,
        approved_by: str | None = None,
        executed_at: str | None = None,
    ) -> bool:
        lock = self._get_lock(intent_id)
        with lock:
            item = self._items.get(intent_id)
            if item is None or item["status"] != expected_status:
                return False
            # Mutable lifecycle attrs only — data/intentHash are carried through
            # untouched (a transition must never re-mint the integrity basis).
            update: dict = {"status": new_status}
            if approved_by is not None:
                update["approvedBy"] = approved_by
            # No TTL in the in-memory fake (nothing auto-expires items), but executedAt
            # still records so /flag day-derivation matches production.
            if executed_at is not None:
                update["executedAt"] = executed_at
            self._items[intent_id] = {**item, **update}
            return True


# ---------------------------------------------------------------------------
# DynamoIntentStore — production implementation with conditional writes
# ---------------------------------------------------------------------------


class DynamoIntentStore:
    """DynamoDB-backed intent store for production.

    boto3 is imported lazily (inside each method body) so importing this class does
    not require AWS credentials or the boto3 package to be importable at load time.
    Unit tests use InMemoryIntentStore and never instantiate DynamoIntentStore.

    Table layout (single-table design; pk=partition key, sk=sort key):

      Intent items:
        pk = "INTENT#{intent_id}"  sk = "v0"
        data = str                 (canonical frozen-half payload — the #349 HMAC basis:
                                    id + materializedRequest + renderedForHuman + expiry + ts)
        intentHash = str           (HMAC-SHA-256 over the exact stored data bytes)
        status = str               ("pending" | "approved" | "rejected" | "expired" | "executed")
        ttl = int                  (epoch seconds — DynamoDB TTL attribute for auto-expiry)
        approvedBy = str | absent
        executedAt = str | absent

    The table name is resolved from the CDK StateStack export (ImportValue);
    callers pass it as a string, e.g. os.environ["INTENTS_TABLE"].
    """

    def __init__(self, table_name: str, hmac_key: bytes) -> None:
        self._table_name = table_name
        self._hmac_key = hmac_key
        self.__table = None  # resolved lazily on first access

    @property
    def _table(self):
        if self.__table is None:
            import boto3  # noqa: PLC0415 — lazy: no creds needed at import time

            dynamodb = boto3.resource("dynamodb")
            self.__table = dynamodb.Table(self._table_name)
        return self.__table

    def put_intent(self, intent: Intent) -> None:
        from datetime import datetime  # noqa: PLC0415

        # Compute epoch seconds from the ISO-8601 expiry for DynamoDB TTL.
        expiry_dt = datetime.fromisoformat(intent.expiry.replace("Z", "+00:00"))
        ttl = int(expiry_dt.timestamp())

        item: dict = {
            "pk": f"INTENT#{intent.id}",
            "sk": "v0",
            "ttl": ttl,
            **intent_item_attrs(intent, self._hmac_key),
        }
        self._table.put_item(Item=item)

    def get_intent(self, intent_id: str) -> Intent | None:
        resp = self._table.get_item(Key={"pk": f"INTENT#{intent_id}", "sk": "v0"})
        item = resp.get("Item")
        if item is None:
            return None
        # Verify-then-parse over the STORED bytes (#349) — the shared helper,
        # so all three backends quarantine identically.
        return intent_from_item(intent_id, item, self._hmac_key)

    def transition_status(
        self,
        intent_id: str,
        expected_status: str,
        new_status: str,
        approved_by: str | None = None,
        executed_at: str | None = None,
    ) -> bool:
        from datetime import datetime, timedelta, timezone  # noqa: PLC0415

        from botocore.exceptions import ClientError  # noqa: PLC0415

        update_expression = "SET #status = :new_status"
        expr_names: dict = {"#status": "status"}
        expr_values: dict = {
            ":expected_status": expected_status,
            ":new_status": new_status,
        }
        if approved_by is not None:
            update_expression += ", approvedBy = :approved_by"
            expr_values[":approved_by"] = approved_by
        if executed_at is not None:
            # Stamp executedAt AND extend the TTL so the executed intent survives its
            # short approval window for the after-the-fact /flag review (#193 Phase 6c).
            # The TTL derives from executed_at itself — the retention window is 7 days
            # past EXECUTION (the same anchor the /flag false_action back-write keys
            # off), so ttl == executedAt + retention holds structurally, not just when
            # this write races the caller's clock inside one second (sa#213 pin).
            executed_dt = datetime.fromisoformat(executed_at.replace("Z", "+00:00"))
            if executed_dt.tzinfo is None:
                # A tz-naive timestamp is UTC, never broker-local (#193 finding 6).
                executed_dt = executed_dt.replace(tzinfo=timezone.utc)
            new_ttl = int(
                (executed_dt + timedelta(days=EXECUTED_INTENT_RETENTION_DAYS)).timestamp()
            )
            update_expression += ", executedAt = :executed_at, #ttl = :new_ttl"
            expr_names["#ttl"] = "ttl"
            expr_values[":executed_at"] = executed_at
            expr_values[":new_ttl"] = new_ttl

        try:
            self._table.update_item(
                Key={"pk": f"INTENT#{intent_id}", "sk": "v0"},
                UpdateExpression=update_expression,
                ConditionExpression="#status = :expected_status",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
