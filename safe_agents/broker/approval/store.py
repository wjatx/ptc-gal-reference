"""IntentStore — persistence interface for the approval layer.

Two implementations here (a third, SqliteIntentStore, lives in sqlite_store.py):
  InMemoryIntentStore  — thread-safe in-process fake for tests; no AWS, no creds
  DynamoIntentStore    — production DynamoDB with conditional writes; boto3 is imported
                         lazily (inside method bodies) so this module loads without credentials

The Protocol is the contract; callers depend only on it.

STORED-BYTES integrity basis (the intent-row HMAC, the grants/store.py stored-bytes idiom): the intent's
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
drop the intent-row HMAC forbids. An exception fails toward LESS authority by construction:
an oblivious caller propagates loudly instead of executing.

The HMAC key is injected at store construction from the same surface the
grants/registry stores use (boot_config.resolve_hmac_key on the broker boot).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Mapping, Protocol, runtime_checkable

from safe_agents.broker.schemas import BrokeredCall, Intent

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import Principal

# How long an EXECUTED intent is retained past its approval-window TTL (evidence labeling).
# A pending intent's TTL is the short approval window; once it executes, the item must
# survive long enough for an after-the-fact owner /flag review — an executed intent that
# auto-deleted at the approval TTL is unflaggable. This extends the TTL at the executed
# transition. The durable LONG-TERM referent of an executed op stays the audit record
# (#83); this is only the /flag review window, so a week, not forever.
EXECUTED_INTENT_RETENTION_DAYS = 7

# The one status put_intent refuses to overwrite (#39). A pending intent is a
# live hold that a human may be looking at; replacing it would make approving
# its id release a different call. Resolved intents (approved, rejected,
# expired, executed, refused) may be overwritten, because the approval-queue
# dedup path re-holds identical content under the same id once the
# earlier hold has resolved.
PENDING_STATUS = "pending"

# The expiry sweep's index (#163). An undecided hold that expires is an EVENT the
# broker records, so the sweep has to find pending intents whose expiry has passed
# without a table scan (no acting role holds dynamodb:Scan). Every backend carries
# the same two item-level attributes while, and only while, an intent is pending:
# the owning principal's key and the expiry as epoch seconds. On DynamoDB they are
# the keys of a sparse global secondary index, so a Query per principal returns
# exactly the expiry candidates; a transition out of pending removes them, which
# drops the row from the index. They sit OUTSIDE the HMAC basis, like status:
# the sweep treats what they return as candidates only and verify-then-parses
# each one before acting on it.
PENDING_INDEX_NAME = "pending-by-principal"
PENDING_PRINCIPAL_ATTR = "pendingPrincipal"
PENDING_EXPIRY_ATTR = "pendingExpiry"

# How long a PENDING intent's DynamoDB time-to-live outlasts its expiry (#163).
# Time-to-live deletes a row with no hook, so a ttl at the expiry instant could
# remove an undecided hold before the sweep records its expiry, and the tape would
# show a hold followed by nothing. The grace is how long a broker can be down and
# still record every expiry when it comes back. The same retention the executed
# path uses, for the same reason: a record has to be writable before the row goes.
PENDING_TTL_GRACE_DAYS = EXECUTED_INTENT_RETENTION_DAYS


def principal_index_key(principal: "Principal") -> str:
    """The pending index's partition value for one principal.

    The same agentId#skill#user#tier tuple scoped_counter_key and dedup_intent_id
    key on, so the sweep of one runtime only ever sees its own principal's holds.
    """
    return f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"


def expiry_epoch(expiry: str) -> int:
    """An ISO-8601 expiry as whole epoch seconds, rounded DOWN.

    Rounding down keeps the index a superset: an intent whose expiry is at or
    before ``now`` always has ``expiry_epoch(expiry) <= floor(now)``. The sweep
    re-checks the exact instant on the verified intent, so a candidate expiring
    later inside the same second is simply skipped until the next pass. A
    tz-naive expiry is UTC.
    """
    dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() // 1)


def _now_epoch(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return int(now.timestamp() // 1)


def _is_expiry_candidate(attrs: Mapping, principal_key: str, now_epoch: int) -> bool:
    """Shared candidate filter over the unauthenticated index attributes."""
    if attrs.get("status") != PENDING_STATUS:
        return False
    if attrs.get(PENDING_PRINCIPAL_ATTR) != principal_key:
        return False
    stored = attrs.get(PENDING_EXPIRY_ATTR)
    try:
        return int(stored) <= now_epoch
    except (TypeError, ValueError):
        return False


class IntentAlreadyPendingError(Exception):
    """Create refused: a pending intent already holds this id (#39).

    Every backend's put_intent is conditional on the id NOT holding a pending
    intent. Two distinct held calls sharing an id is a defect upstream (#38
    removed the known source), and a blind put would silently replace the
    first hold: the human approves one call and the broker releases another,
    while the first can never run. Refusing keeps the first hold intact and
    approvable to its own call. The caller decides what the refusal means:
    materialize() treats it as coalescing when the id is content-derived
    (dedup), and the PEP otherwise denies the new call with an audit record.
    """

    def __init__(self, intent_id: str) -> None:
        self.intent_id = intent_id
        super().__init__(
            f"intent {intent_id!r} is already pending; refusing to overwrite it"
        )


class QuarantinedIntentError(Exception):
    """Read refused: the stored intent bytes failed HMAC verification.

    An A4 attacker (store write access) who rewrites the frozen call between
    hold and release must never get the rewritten call executed. The stored
    bytes are untrusted evidence — never parsed, never served, never
    auto-repaired — and every caller's refusal fails toward less authority:
    the action simply does not run. Surfacing loudly is the runtime's job
    (pep.py mirrors the loud grant-quarantine surfacing).
    """

    def __init__(self, intent_id: str, reason: str) -> None:
        self.intent_id = intent_id
        self.reason = reason
        super().__init__(f"intent {intent_id!r} quarantined: {reason}")


def canonical_intent_payload(intent: Intent) -> str:
    """The ONE serialization of an intent's frozen half — stored AND HMAC'd.

    Storage and the integrity basis must be the same bytes: serialize
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

    Serialize once; the stored ``data`` string IS the HMAC basis.
    """
    payload = canonical_intent_payload(intent)
    attrs: dict = {
        "data": payload,
        "intentHash": _hmac_payload(payload, hmac_key),
        "status": intent.status,
    }
    if intent.status == PENDING_STATUS:
        # The expiry sweep's index attributes (#163), present only while pending.
        attrs[PENDING_PRINCIPAL_ATTR] = principal_index_key(
            intent.materializedRequest.principal
        )
        attrs[PENDING_EXPIRY_ATTR] = expiry_epoch(intent.expiry)
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
        """Persist a new intent. Called once at creation (status=pending).

        Conditional and atomic (#39): raises IntentAlreadyPendingError when an
        intent with this id is already pending, leaving that intent untouched.
        An absent id or a resolved intent under the id is written over.
        """
        ...

    def get_intent(self, intent_id: str) -> Intent | None:
        """Retrieve the intent by ID, or None if not found.

        Raises QuarantinedIntentError when the stored bytes fail HMAC
        verification — tampered bytes are never parsed or returned.
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

        A transition OUT of pending removes the pending index attributes, so an
        intent stops being an expiry candidate the moment anything resolves it.
        """
        ...

    def expired_pending_candidates(self, principal_key: str, now: datetime) -> list[str]:
        """Ids of this principal's pending intents whose expiry is at or before ``now``.

        The expiry sweep's read (#163). Answered from the pending index
        attributes alone, which are outside the HMAC basis, so the result is a
        list of CANDIDATES: the caller reads each through get_intent
        (verify-then-parse) and re-checks status, owner and expiry on the
        verified intent before it acts. Never a DynamoDB Scan: on DynamoDB it is
        a Query on the sparse pending index. The sqlite and in-memory backends,
        which have no IAM boundary to respect, read every intent row's index
        attributes and filter in process.
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
            # The check and the write share the per-intent lock, so this is the
            # in-memory mirror of Dynamo's conditional put (#39).
            existing = self._items.get(intent.id)
            if existing is not None and existing.get("status") == PENDING_STATUS:
                raise IntentAlreadyPendingError(intent.id)
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
            merged = {**item, **update}
            if new_status != PENDING_STATUS:
                merged.pop(PENDING_PRINCIPAL_ATTR, None)
                merged.pop(PENDING_EXPIRY_ATTR, None)
            self._items[intent_id] = merged
            return True

    def expired_pending_candidates(self, principal_key: str, now: datetime) -> list[str]:
        now_epoch = _now_epoch(now)
        with self._registry_lock:
            snapshot = list(self._items.items())
        return [
            intent_id
            for intent_id, item in snapshot
            if _is_expiry_candidate(item, principal_key, now_epoch)
        ]


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
        data = str                 (canonical frozen-half payload — the intent HMAC basis:
                                    id + materializedRequest + renderedForHuman + expiry + ts)
        intentHash = str           (HMAC-SHA-256 over the exact stored data bytes)
        status = str               ("pending" | "approved" | "rejected" | "expired" |
                                    "executed" | "refused" | "permitted")
        ttl = int                  (epoch seconds — DynamoDB TTL attribute; expiry + a grace
                                    while pending so the expiry sweep records first, #163)
        pendingPrincipal = str     (only while pending — the sparse expiry index's key)
        pendingExpiry = int        (only while pending — expiry epoch, the index's sort key)
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
        from botocore.exceptions import ClientError  # noqa: PLC0415

        # Epoch seconds for the DynamoDB time-to-live. A pending intent's ttl is its
        # expiry PLUS a grace (#163): the daemon deletes with no hook, and the
        # expiry sweep must record the expiry before the row can go.
        ttl = expiry_epoch(intent.expiry)
        if intent.status == PENDING_STATUS:
            ttl += int(timedelta(days=PENDING_TTL_GRACE_DAYS).total_seconds())

        item: dict = {
            "pk": f"INTENT#{intent.id}",
            "sk": "v0",
            "ttl": ttl,
            **intent_item_attrs(intent, self._hmac_key),
        }
        # Conditional put (#39): refuse to replace a pending intent. The
        # condition is evaluated server-side against the stored item, so two
        # racing puts of one id cannot both land on a pending slot. Needs only
        # dynamodb:PutItem; a ConditionExpression is not a separate action.
        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) OR #status <> :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":pending": PENDING_STATUS},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise IntentAlreadyPendingError(intent.id) from exc
            raise

    def get_intent(self, intent_id: str) -> Intent | None:
        resp = self._table.get_item(Key={"pk": f"INTENT#{intent_id}", "sk": "v0"})
        item = resp.get("Item")
        if item is None:
            return None
        # Verify-then-parse over the STORED bytes — the shared helper,
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
            # short approval window for the after-the-fact /flag review (evidence labeling).
            # The TTL derives from executed_at itself — the retention window is 7 days
            # past EXECUTION (the same anchor the /flag false_action back-write keys
            # off), so ttl == executedAt + retention holds structurally, not just when
            # this write races the caller's clock inside one second (trigger-range pin).
            executed_dt = datetime.fromisoformat(executed_at.replace("Z", "+00:00"))
            if executed_dt.tzinfo is None:
                # A tz-naive timestamp is UTC, never broker-local (an evidence-labeling finding).
                executed_dt = executed_dt.replace(tzinfo=timezone.utc)
            new_ttl = int(
                (executed_dt + timedelta(days=EXECUTED_INTENT_RETENTION_DAYS)).timestamp()
            )
            update_expression += ", executedAt = :executed_at, #ttl = :new_ttl"
            expr_names["#ttl"] = "ttl"
            expr_values[":executed_at"] = executed_at
            expr_values[":new_ttl"] = new_ttl
        if new_status != PENDING_STATUS:
            # Leaving pending drops the row from the sparse expiry index (#163).
            update_expression += " REMOVE #pendingPrincipal, #pendingExpiry"
            expr_names["#pendingPrincipal"] = PENDING_PRINCIPAL_ATTR
            expr_names["#pendingExpiry"] = PENDING_EXPIRY_ATTR

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

    def expired_pending_candidates(self, principal_key: str, now: datetime) -> list[str]:
        # A Query on the sparse pending index, never a Scan: the broker role holds
        # dynamodb:Query on the table's indexes and no acting role holds Scan.
        from boto3.dynamodb.conditions import Key  # noqa: PLC0415

        condition = Key(PENDING_PRINCIPAL_ATTR).eq(principal_key) & Key(
            PENDING_EXPIRY_ATTR
        ).lte(_now_epoch(now))
        ids: list[str] = []
        kwargs: dict = {"IndexName": PENDING_INDEX_NAME, "KeyConditionExpression": condition}
        while True:
            resp = self._table.query(**kwargs)
            for item in resp.get("Items", []):
                pk = item.get("pk", "")
                if isinstance(pk, str) and pk.startswith("INTENT#"):
                    ids.append(pk[len("INTENT#"):])
            last = resp.get("LastEvaluatedKey")
            if not last:
                return ids
            kwargs["ExclusiveStartKey"] = last
