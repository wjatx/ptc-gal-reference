"""Grant store client + PromotionRecord ledger store.

Protocol + InMemoryGrantStore (for tests) + DynamoDBGrantStore (production),
plus DynamoDBPromotionRecordStore — the durable append-only ceremony ledger,
co-located in the grants table as RECORD# items (SCHEMAS.md §7).

Design notes:
- The client does NOT manage IAM role assumption. Callers supply the boto3
  Session carrying the appropriate role (promotion role, demotion role, etc.).
  Which role is appropriate is the ceremony's job (#58), not ours.
- STORED-BYTES integrity basis (#246, the mcp/proposals.py idiom): the grant is
  serialized ONCE (canonical_grant_payload), that exact string is stored as the
  item's data AND HMAC'd into the item-level grantHash attribute — the hash
  lives at item level ONLY, never inside the payload. On read the stored bytes
  are verified VERBATIM before parsing (verify-then-parse); the basis is
  therefore immune to schema evolution — additive Grant growth never makes an
  intact old row read as tampered (integrity indicts tampering, never
  evolution). The HMAC key is injected at store construction; callers are
  responsible for sourcing it (e.g. from AWS Secrets Manager in prod).
- On read, if the stored bytes fail verification, the store sets
  quarantined=True and returns grant=None with the raw bytes on the result —
  tampered bytes are evidence, not a Grant, and are NEVER parsed or served as
  authoritative. Callers must check quarantined BEFORE not-found.
- Table name for DynamoDB is read from GRANTS_TABLE_NAME env var, ImportValue'd
  from the infra stack (sa#11). Never hardcoded.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac as _hmac
import json
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import Principal


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

class GrantUpdateConflictError(Exception):
    """Conditional grant update failed: the stored grant is not the one evaluated.

    Raised when update_grant's condition (stored grantHash == expected) fails —
    either the grant was concurrently modified or it no longer exists. Callers
    must re-read and re-evaluate before retrying; never retry the write blind.
    """


class GrantAlreadyExistsError(Exception):
    """Conditional grant creation failed: a grant already exists under this key.

    Raised when create_grant's condition (attribute_not_exists(pk)) fails.
    The ceremony's Recommend-origin path creates grants and must never
    overwrite one minted concurrently — re-read and re-propose from the
    current state instead.
    """


class RecordAlreadyExistsError(Exception):
    """Append-only ledger violation: a record with this key already exists.

    The PromotionRecord ledger is append-only — an existing (pk, sk) item is
    NEVER overwritten. This surfacing loudly is the tamper-evidence property.
    """


class RecordTimestampFormatError(Exception):
    """Record ts rejected: not the canonical tz-aware UTC ISO-8601 '+00:00' form.

    The ledger sort key is "<ts>#<recordType>" and chronological ordering is
    LEXICAL — a 'Z' suffix (or a naive/non-UTC ts) sorts differently from
    '+00:00' and silently breaks list_records ordering and its same-day
    ts_prefix filter. Records may also be DSSE-signed over their stored bytes,
    so a non-canonical ts is REJECTED, never normalized: normalizing after
    signing would break the digest binding.
    """


class QuarantinedGrantError(Exception):
    """Write refused: the stored grant is quarantined (failed hash verification).

    A quarantined grant's contents are untrusted; writing over it would launder
    the tampered state into an accepted grant under a fresh valid HMAC. The
    grant must not be written until the quarantine is resolved (root-caused and
    re-seeded through the sanctioned path).
    """


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _principal_key(principal: Principal) -> str:
    """Stable string key for a principal; used as part of DynamoDB PK."""
    return f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"


def validate_record_ts(ts: str) -> None:
    """Reject a non-canonical PromotionRecord ts before it reaches the ledger.

    Canonical form: datetime.fromisoformat-parseable, tz-aware UTC, ending in
    '+00:00' — never 'Z', never naive, never a non-UTC offset. Shared by both
    put_record implementations; see RecordTimestampFormatError for why the
    ts is rejected rather than normalized.
    """
    try:
        parsed = datetime.datetime.fromisoformat(ts)
    except ValueError as exc:
        raise RecordTimestampFormatError(
            f"record ts {ts!r} is not parseable ISO-8601; the canonical form is "
            "tz-aware UTC ending '+00:00'"
        ) from exc
    if parsed.tzinfo is None:
        raise RecordTimestampFormatError(
            f"record ts {ts!r} is naive; the canonical form is tz-aware UTC "
            "ending '+00:00'"
        )
    if parsed.utcoffset() != datetime.timedelta(0) or not ts.endswith("+00:00"):
        raise RecordTimestampFormatError(
            f"record ts {ts!r} must be UTC and end with '+00:00' — never 'Z' or "
            "a non-UTC offset (they break the ledger's lexical sk ordering)"
        )


def canonical_grant_payload(grant: Grant) -> str:
    """The ONE serialization of a grant — what gets stored AND what gets HMAC'd.

    Storage and the integrity basis must be the same bytes (#246, the
    mcp/proposals.py idiom). When they diverge, verification has to
    re-serialize the parsed model, which silently re-derives the basis from
    whatever the model class looks like *today* — so any additive schema
    change invalidates every historical row and reports it as a tamper. A
    ceremony that cries tamper when a schema grows teaches operators to
    dismiss the alarm that matters.

    So: serialize once, store this exact string, HMAC this exact string, and
    on read HMAC the stored bytes verbatim without ever re-serializing. The
    integrity slot (the item-level grantHash attribute) is deliberately
    OUTSIDE the payload.

    Canonical form: JSON with sorted keys, NO whitespace (compact
    ``separators=(",", ":")``), ASCII, all types serialized via Pydantic's JSON
    mode (enums -> str, nested models -> dict). The whitespace half is
    load-bearing and was missing until it was pinned: while the only
    implementation was this one, the omission was invisible (the HMAC covered
    bytes this process had just written and read back verbatim), but a SECOND
    implementation computing a grant HMAC from the normative spec — which
    states "sorted keys, no whitespace, ASCII" — would have disagreed byte for
    byte. It is the same rule ``canonical_record_payload`` and
    ``channels.signing`` already used; all three now agree.
    """
    return json.dumps(
        grant.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def compute_grant_hash(grant: Grant, hmac_key: bytes) -> str:
    """HMAC-SHA-256 over the canonical grant payload (write path)."""
    return _hmac_payload(canonical_grant_payload(grant), hmac_key)


def _hmac_payload(payload: str, hmac_key: bytes) -> str:
    return _hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Result type — wraps the Grant with a quarantine flag
# ---------------------------------------------------------------------------

@dataclass
class GrantReadResult:
    """Result of a get_grant call.

    If quarantined=True the stored bytes failed verification against the
    item-level grantHash (or the attribute was absent): grant is None —
    tampered bytes are evidence, not a Grant, and are never parsed — and
    raw_data carries the bytes for audit. Callers must check quarantined
    BEFORE not-found: tamper dominates absence, and a quarantine surfacing
    as "not found" would invite a re-seed over the evidence.

    raw_data is the exact stored serialization (the DynamoDB 'data'
    attribute — the integrity basis itself); stored_hash is the item-level
    grantHash. Together they are what a conditional update conditions on.
    """

    grant: Grant | None
    quarantined: bool = False
    quarantine_reason: str | None = None
    raw_data: str | None = None
    stored_hash: str | None = None


def _read_result_from_item(
    data: object, stored_hash: object, hmac_key: bytes
) -> GrantReadResult:
    """Verify-then-parse a stored grant item (shared by both backends).

    The stored bytes are HMAC'd VERBATIM against the item-level grantHash
    before any parse; a mismatch — or a missing/non-string half — quarantines
    with grant=None (the bytes are untrusted input and never parsed).
    """
    if not isinstance(data, str) or not isinstance(stored_hash, str):
        return GrantReadResult(
            grant=None,
            quarantined=True,
            quarantine_reason=(
                "stored item is missing its data or grantHash attribute; the "
                "item cannot be verified and must not authorize anything"
            ),
            raw_data=data if isinstance(data, str) else None,
        )
    expected = _hmac_payload(data, hmac_key)
    if stored_hash != expected:
        return GrantReadResult(
            grant=None,
            quarantined=True,
            quarantine_reason=(
                f"hash mismatch: stored={stored_hash!r} expected={expected!r}"
            ),
            raw_data=data,
            stored_hash=stored_hash,
        )
    return GrantReadResult(
        grant=Grant.model_validate_json(data), raw_data=data, stored_hash=stored_hash
    )


def _require_prev_raw_data(prev_raw_data: str | None) -> None:
    """update_grant's prev_raw_data is required since #246 (no legacy fallback)."""
    if prev_raw_data is None:
        raise ValueError(
            "update_grant requires prev_raw_data (the stored bytes from the "
            "guarded re-read, GrantReadResult.raw_data); the pre-#246 "
            "legacy-item fallback is retired"
        )


# ---------------------------------------------------------------------------
# Store interface
# ---------------------------------------------------------------------------

@runtime_checkable
class GrantStore(Protocol):
    """Injectable store interface. Tests supply InMemoryGrantStore; prod uses DynamoDBGrantStore."""

    def get_grant(self, principal: Principal, action_class: str) -> GrantReadResult:
        ...

    def put_grant(self, grant: Grant, session: object) -> None:
        """Persist a grant under the supplied boto3 Session (or None for in-memory).

        WARNING: this is a blind upsert — it overwrites whatever is stored and
        can resurrect a deleted grant. It exists for the sanctioned bootstrap
        path (seed_grants) only; ceremony paths must never call it. Level
        changes go through create_grant (Recommend-origin) or the conditional
        update_grant (broker/grant-lifecycle.md).
        """
        ...

    def create_grant(self, grant: Grant, session: object) -> None:
        """Create a NEW grant; never overwrites an existing one.

        The write succeeds only if no item exists under the grant's key
        (attribute_not_exists(pk)). Raises GrantAlreadyExistsError on
        collision — the Recommend-origin ceremony path's race guard.
        """
        ...

    def update_grant(
        self,
        updated: Grant,
        expected_hash: str,
        session: object,
        prev_raw_data: str | None = None,
    ) -> None:
        """Conditionally update an EXISTING grant (UpdateItem semantics).

        The write succeeds only if the stored grant is still the one the caller
        evaluated: the item-level grantHash equals expected_hash AND the stored
        data bytes equal prev_raw_data (both from the caller's guarded re-read,
        GrantReadResult.stored_hash / .raw_data). prev_raw_data is REQUIRED —
        supplying None is a ValueError, failing toward writing nothing (the
        pre-#246 legacy-item fallback is retired; every item carries grantHash
        after the re-shape B re-seed).

        The attribute_exists(pk) ConditionExpression is what makes this
        update-only: IAM UpdateItem-only means no PutItem API, but UpdateItem
        can still create items — the no-mint guarantee is the store's
        condition, with IAM limiting blast radius rather than proving it.

        Raises GrantUpdateConflictError if the condition fails (concurrent
        modification, or the item no longer exists).
        """
        ...

    def write_record_and_grant(
        self,
        record: PromotionRecord,
        grant: Grant,
        record_store: object,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: GrantReadResult | None = None,
    ) -> None:
        """Append the ledger record AND write the grant as ONE atomic unit (#244).

        The grants mirror of the MCP registry's ``admit_tool_with_record``:
        either BOTH legs commit or NOTHING is written, closing the
        record-without-grant (and grant-without-record) artifact structurally
        at every ceremony write-pair site — seed/bootstrap, promotion,
        demotion, and tightening. The old per-site write orderings (record
        -before-grant on promotion, grant-before-record on demotion/tighten)
        are superseded: their failure-polarity trade-offs existed only because
        the pair could be interrupted between writes.

        Each leg keeps its own condition:
        - record leg: append-only (``attribute_not_exists``), canonical-ts
          validated, ``signature`` stored beside the record when present —
          signing is CALLER-side (the ceremony signs before this call).
        - grant leg: ``expected is None`` or ``expected.grant is None`` ⇒
          create (``attribute_not_exists``, GrantAlreadyExistsError on
          collision); otherwise a conditional update on the guarded re-read's
          stored bytes + item hash (GrantUpdateConflictError on conflict).

        ``record_store`` must be the matching backend's record store (the two
        item kinds co-locate in one table); a mismatched pairing is a
        TypeError, refusing before any write.
        """
        ...


# ---------------------------------------------------------------------------
# In-memory fake — for unit tests
# ---------------------------------------------------------------------------

class InMemoryGrantStore:
    """Fake store backed by a plain dict, ITEM-SHAPED to mirror the DynamoDB
    semantics byte-for-byte: each entry is {"data": <canonical payload str>,
    "grantHash": <hmac str>} — so stored-bytes tamper tests exercise the same
    verify-then-parse path as production. Thread-unsafe; unit tests only."""

    def __init__(self, hmac_key: bytes = b"test-hmac-key") -> None:
        self._hmac_key = hmac_key
        # (principal_key, action_class) -> {"data": str, "grantHash": str}
        self._store: dict[tuple[str, str], dict] = {}

    def _record_key(self, principal: Principal, action_class: str) -> tuple[str, str]:
        return (_principal_key(principal), action_class)

    def get_grant(self, principal: Principal, action_class: str) -> GrantReadResult:
        item = self._store.get(self._record_key(principal, action_class))
        if item is None:
            return GrantReadResult(grant=None)
        return _read_result_from_item(item.get("data"), item.get("grantHash"), self._hmac_key)

    def put_grant(self, grant: Grant, session: object = None) -> None:
        """Serialize once, HMAC the stored bytes, persist. Session arg unused.

        Blind upsert — bootstrap/seed path only; ceremony paths must never
        call it (see the GrantStore Protocol docstring).
        """
        self._store[self._record_key(grant.principal, grant.actionClass)] = (
            self._build_item(grant)
        )

    def create_grant(self, grant: Grant, session: object = None) -> None:
        """Create a new grant; raises GrantAlreadyExistsError on collision."""
        key = self._record_key(grant.principal, grant.actionClass)
        if key in self._store:
            raise GrantAlreadyExistsError(
                f"grant {grant.principal.agentId}/{grant.actionClass} already exists; "
                "create_grant never overwrites — re-read and re-propose from the current state"
            )
        self.put_grant(grant, session)

    def update_grant(
        self,
        updated: Grant,
        expected_hash: str,
        session: object = None,
        prev_raw_data: str | None = None,
    ) -> None:
        """Conditionally replace an existing grant; never creates one."""
        _require_prev_raw_data(prev_raw_data)
        key = self._check_update_conditions(updated, expected_hash, prev_raw_data)
        self._store[key] = self._build_item(updated)

    def _build_item(self, grant: Grant) -> dict:
        payload = canonical_grant_payload(grant)
        return {"data": payload, "grantHash": _hmac_payload(payload, self._hmac_key)}

    def _check_update_conditions(
        self, updated: Grant, expected_hash: str, prev_raw_data: str | None
    ) -> tuple[str, str]:
        """Validate the conditional-update conditions WITHOUT mutating; return
        the storage key. Shared by update_grant and the atomic op so the
        latter cannot drift from single-write semantics."""
        key = self._record_key(updated.principal, updated.actionClass)
        item = self._store.get(key)
        if item is None:
            raise GrantUpdateConflictError(
                f"grant {updated.principal.agentId}/{updated.actionClass} does not "
                "exist; update_grant cannot create items (UpdateItem semantics)"
            )
        if item.get("grantHash") != expected_hash or item.get("data") != prev_raw_data:
            # Either half failing means the stored item is not the one the
            # caller evaluated (concurrent write, or a tamper of the data or
            # the hash attribute alone). Refuse: writing over it would destroy
            # the tamper evidence.
            raise GrantUpdateConflictError(
                f"grant {updated.principal.agentId}/{updated.actionClass}: "
                "stored item is not the one evaluated (tampered or concurrently "
                "modified); re-read and re-evaluate before retrying"
            )
        return key

    def write_record_and_grant(
        self,
        record: PromotionRecord,
        grant: Grant,
        record_store: object,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: GrantReadResult | None = None,
    ) -> None:
        """Atomic record+grant write (#244) — check BOTH legs, then commit both.

        Mirrors MemoryToolRegistry.admit_tool_with_record: every condition is
        validated without mutation first, so a failing leg cancels the whole
        unit with nothing written.
        """
        # Backend pairing is structural: the memory grant store composes only
        # with the memory record store (duck-checked to avoid a circular
        # import; ceremony.py owns InMemoryPromotionRecordStore).
        if not hasattr(record_store, "_records") or not hasattr(record_store, "put_record"):
            raise TypeError(
                "write_record_and_grant on InMemoryGrantStore requires an "
                f"InMemoryPromotionRecordStore, got {type(record_store).__name__}"
            )
        # Grant leg — validate without mutating.
        key = self._record_key(grant.principal, grant.actionClass)
        if expected is None or expected.grant is None:
            if key in self._store:
                raise GrantAlreadyExistsError(
                    f"grant {grant.principal.agentId}/{grant.actionClass} already "
                    "exists; create never overwrites — re-read and re-propose from "
                    "the current state"
                )
        else:
            self._check_update_conditions(grant, expected.stored_hash, expected.raw_data)
        # Record leg — put_record validates ts + append-only and raises before
        # the grant leg commits; a record failure therefore writes nothing.
        record_store.put_record(record, session, signature=signature)
        self._store[key] = self._build_item(grant)


# ---------------------------------------------------------------------------
# DynamoDB implementation — production
# ---------------------------------------------------------------------------

class DynamoDBGrantStore:
    """DynamoDB-backed grant store.

    Table name: read from GRANTS_TABLE_NAME env var (ImportValue from infra/sa#11).
    Callers supply a boto3 Session for writes — this client never assumes roles.

    Item layout:
        pk  = "GRANT#<agentId>#<skill>#<user>#<tier>"
        sk  = "CLASS#<actionClass>"
        data = the canonical grant payload (canonical_grant_payload) — the
            stored bytes ARE the integrity basis (#246)
        grantHash = HMAC over the data bytes, at item level ONLY (the hash is
            not inside the payload); the sole integrity slot.
    """

    def __init__(self, hmac_key: bytes, table_name: str | None = None) -> None:
        self._hmac_key = hmac_key
        self._table_name = table_name or os.environ["GRANTS_TABLE_NAME"]

    def _item_key(self, principal: Principal, action_class: str) -> dict:
        return {
            "pk": f"GRANT#{_principal_key(principal)}",
            "sk": f"CLASS#{action_class}",
        }

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    def get_grant(self, principal: Principal, action_class: str) -> GrantReadResult:
        table = self._get_table()
        response = table.get_item(Key=self._item_key(principal, action_class))
        item = response.get("Item")
        if item is None:
            return GrantReadResult(grant=None)
        return _read_result_from_item(item.get("data"), item.get("grantHash"), self._hmac_key)

    def put_grant(self, grant: Grant, session) -> None:
        """Write a grant using the supplied boto3 Session.

        Blind upsert — bootstrap/seed path only; ceremony paths must never
        call it (see the GrantStore Protocol docstring). The session must
        carry a role that has PutItem permission on the grant table.
        AccessDenied is NOT caught here — a failed write must be visible to
        the caller.
        """
        table = self._get_table(session)
        table.put_item(Item=self._build_item(grant))

    def _build_item(self, grant: Grant) -> dict:
        """The stored item shape shared by put_grant and create_grant.

        Serialize once; the stored data string IS the HMAC basis (#246).
        """
        payload = canonical_grant_payload(grant)
        return {
            **self._item_key(grant.principal, grant.actionClass),
            "data": payload,
            "grantHash": _hmac_payload(payload, self._hmac_key),
        }

    def create_grant(self, grant: Grant, session) -> None:
        """Create a new grant via a conditional PutItem; never overwrites.

        attribute_not_exists(pk) is the race guard for the Recommend-origin
        ceremony path: a grant minted concurrently surfaces as
        GrantAlreadyExistsError, never silently replaced.
        """
        from botocore.exceptions import ClientError  # lazy, like boto3

        table = self._get_table(session)
        try:
            table.put_item(
                Item=self._build_item(grant),
                ConditionExpression="attribute_not_exists(pk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise GrantAlreadyExistsError(
                    f"grant {grant.principal.agentId}/{grant.actionClass} already exists; "
                    "create_grant never overwrites — re-read and re-propose from the "
                    "current state"
                ) from exc
            raise

    def update_grant(
        self,
        updated: Grant,
        expected_hash: str,
        session,
        prev_raw_data: str | None = None,
    ) -> None:
        """Conditionally update an existing grant via UpdateItem.

        The condition asserts the stored item is still the one the caller
        evaluated: its grantHash attribute equals expected_hash AND the stored
        'data' string is byte-identical to prev_raw_data (both from the
        guarded re-read). The data clause closes the quarantine race: a tamper
        of the data payload alone (hash attribute untouched) landing between a
        guarded re-read and this write would pass a hash-only condition and be
        silently overwritten, destroying the tamper evidence. prev_raw_data is
        REQUIRED — the pre-#246 legacy-item fallback (items written before
        grantHash existed) is retired; every item carries grantHash after the
        re-shape B re-seed.

        Runs under UpdateItem permission only (no PutItem API) — but UpdateItem
        authorizes upsert-creation, so the no-mint guarantee is the
        attribute_exists(pk) clause of the ConditionExpression, with IAM
        limiting blast radius rather than proving it. AccessDenied is NOT
        caught here; a ConditionalCheckFailedException becomes
        GrantUpdateConflictError.
        """
        from botocore.exceptions import ClientError  # lazy, like boto3

        _require_prev_raw_data(prev_raw_data)
        table = self._get_table(session)
        condition, _, values = self._prepare_grant_write(
            updated, expected_hash=expected_hash, prev_raw_data=prev_raw_data
        )

        try:
            table.update_item(
                Key=self._item_key(updated.principal, updated.actionClass),
                UpdateExpression="SET #data = :data, grantHash = :new_hash",
                ConditionExpression=condition,
                ExpressionAttributeNames={"#data": "data"},  # 'data' is DynamoDB-reserved
                ExpressionAttributeValues=values,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise GrantUpdateConflictError(
                    f"grant {updated.principal.agentId}/{updated.actionClass}: "
                    "stored grant is not the one evaluated (concurrently modified "
                    "or missing); re-read and re-evaluate before retrying"
                ) from exc
            raise

    _GRANT_UPDATE_EXPRESSION = "SET #data = :data, grantHash = :new_hash"

    def _prepare_grant_write(
        self,
        grant: Grant,
        *,
        expected_hash: str | None = None,
        prev_raw_data: str | None = None,
    ) -> tuple[str, dict, dict]:
        """ConditionExpression/names/values (plain) for a grant write leg.

        ``expected_hash is None`` ⇒ create (``attribute_not_exists``); else the
        conditional-update condition over the guarded re-read's item hash AND
        stored bytes. Shared by update_grant and write_record_and_grant so the
        transact path cannot drift from single-write semantics.
        """
        payload = canonical_grant_payload(grant)
        names = {"#data": "data"}  # 'data' is DynamoDB-reserved
        values: dict = {
            ":data": payload,
            ":new_hash": _hmac_payload(payload, self._hmac_key),
        }
        if expected_hash is None:
            condition = "attribute_not_exists(pk)"
        else:
            condition = "attribute_exists(pk) AND grantHash = :expected AND #data = :prev_data"
            values[":expected"] = expected_hash
            values[":prev_data"] = prev_raw_data
        return condition, names, values

    def _get_client(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        return session.client("dynamodb") if session is not None else boto3.client("dynamodb")

    def write_record_and_grant(
        self,
        record: PromotionRecord,
        grant: Grant,
        record_store: object,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: GrantReadResult | None = None,
    ) -> None:
        """Atomic record+grant write (#244): ONE Update-only TransactWriteItems.

        Both legs' expressions come from the SAME builders the single-item
        writes use, so this path cannot drift from put_record/create_grant/
        update_grant semantics. Update-only means the ceremony and demotion
        identities need only dynamodb:UpdateItem (the #244 feasibility claim,
        exercised live by the MCP twin 2026-07-24).
        """
        from botocore.exceptions import ClientError  # lazy, like boto3

        if not isinstance(record_store, DynamoDBPromotionRecordStore):
            raise TypeError(
                "write_record_and_grant on DynamoDBGrantStore requires a "
                f"DynamoDBPromotionRecordStore, got {type(record_store).__name__}"
            )
        if record_store._table_name != self._table_name:
            raise ValueError(
                "write_record_and_grant requires both stores on the SAME table "
                f"(grant: {self._table_name!r}, record: {record_store._table_name!r})"
            )
        validate_record_ts(record.ts)

        creating = expected is None or expected.grant is None
        grant_condition, grant_names, grant_values = self._prepare_grant_write(
            grant,
            expected_hash=None if creating else expected.stored_hash,
            prev_raw_data=None if creating else expected.raw_data,
        )
        rec_update, rec_names, rec_values = record_store._prepare_record_write(
            record, signature
        )
        record_key = record_store._item_key(record)

        def typed(plain: dict) -> dict:
            # Every attribute this store writes is a string; the low-level
            # transact API needs typed AttributeValues.
            return {k: {"S": v} for k, v in plain.items()}

        # Item order is load-bearing for error mapping: index 0 = record leg,
        # index 1 = grant leg (matches CancellationReasons positionally).
        transact_items = [
            {
                "Update": {
                    "TableName": self._table_name,
                    "Key": typed(record_key),
                    "UpdateExpression": rec_update,
                    "ConditionExpression": "attribute_not_exists(pk)",
                    "ExpressionAttributeNames": rec_names,
                    "ExpressionAttributeValues": typed(rec_values),
                }
            },
            {
                "Update": {
                    "TableName": self._table_name,
                    "Key": typed(self._item_key(grant.principal, grant.actionClass)),
                    "UpdateExpression": self._GRANT_UPDATE_EXPRESSION,
                    "ConditionExpression": grant_condition,
                    "ExpressionAttributeNames": grant_names,
                    "ExpressionAttributeValues": typed(grant_values),
                }
            },
        ]
        try:
            self._get_client(session).transact_write_items(TransactItems=transact_items)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            # A canceled transaction wrote NOTHING — map the failing leg to the
            # same error vocabulary the single-item writes use. Grant conflict
            # takes precedence when both legs fail: it is the signal the caller
            # must re-read and re-evaluate on either way.
            reasons = exc.response.get("CancellationReasons") or []
            codes = [reason.get("Code") for reason in reasons]
            if len(codes) > 1 and codes[1] == "ConditionalCheckFailed":
                if creating:
                    raise GrantAlreadyExistsError(
                        f"grant {grant.principal.agentId}/{grant.actionClass} already "
                        "exists; create never overwrites — re-read and re-propose "
                        "from the current state (the record leg was canceled with "
                        "it — nothing was written)"
                    ) from exc
                raise GrantUpdateConflictError(
                    f"grant {grant.principal.agentId}/{grant.actionClass}: stored "
                    "grant is not the one evaluated (concurrently modified or "
                    "missing); re-read and re-evaluate before retrying (the record "
                    "leg was canceled with it — nothing was written)"
                ) from exc
            if codes and codes[0] == "ConditionalCheckFailed":
                raise RecordAlreadyExistsError(
                    f"ledger record {record_key['pk']}/{record_key['sk']} already "
                    "exists; the PromotionRecord ledger is append-only and never "
                    "overwrites (the grant leg was canceled with it — nothing was "
                    "written)"
                ) from exc
            raise


# ---------------------------------------------------------------------------
# PromotionRecord ledger — DynamoDB implementation (same table as grants)
# ---------------------------------------------------------------------------

class DynamoDBPromotionRecordStore:
    """DynamoDB-backed append-only PromotionRecord ledger.

    Records live in the SAME grants table as a distinct item type. Table name:
    GRANTS_TABLE_NAME env var, like DynamoDBGrantStore. Callers supply the
    boto3 Session — this client never assumes roles.

    Item layout:
        pk  = "RECORD#<agentId>#<skill>#<user>#<tier>#<actionClass>"
        sk  = "<ts>#<recordType>"      (ts first → chronological Query)
        data = entire PromotionRecord as a JSON string

    Writes use update_item (NOT put_item) so they run under an UpdateItem-only
    IAM role (the demotion role has no PutItem on the grants table) — UpdateItem
    authorizes item creation, which is exactly how appends land. The
    attribute_not_exists(pk) ConditionExpression is what makes the ledger
    append-only — an existing item is never overwritten
    (RecordAlreadyExistsError).
    """

    def __init__(self, table_name: str | None = None) -> None:
        self._table_name = table_name or os.environ["GRANTS_TABLE_NAME"]

    @staticmethod
    def _record_pk(principal: Principal, action_class: str) -> str:
        return f"RECORD#{_principal_key(principal)}#{action_class}"

    def _item_key(self, record: PromotionRecord) -> dict:
        return {
            "pk": self._record_pk(record.principal, record.actionClass),
            "sk": f"{record.ts}#{record.recordType}",
        }

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    @staticmethod
    def _prepare_record_write(
        record: PromotionRecord, signature: dict | None
    ) -> tuple[str, dict, dict]:
        """UpdateExpression/names/values (plain) for the append-only record leg.

        Shared by put_record and DynamoDBGrantStore.write_record_and_grant so
        the transact path cannot drift from single-write semantics (#244).
        The stored data is the CANONICAL record payload — the same bytes the
        DSSE signature binds, so verification digests the stored string
        verbatim (#246 re-shape C).
        """
        from safe_agents.broker.grants.record_signing import canonical_record_payload

        update_expression = "SET #data = :data"
        names = {"#data": "data"}
        values: dict = {":data": canonical_record_payload(record)}
        if signature is not None:
            update_expression += ", #sig = :sig"
            names["#sig"] = "signature"
            values[":sig"] = json.dumps(signature, sort_keys=True, ensure_ascii=True)
        return update_expression, names, values

    def put_record(
        self, record: PromotionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        """Append one record; raises RecordAlreadyExistsError on a key collision.

        signature: optional DSSE envelope (grants/record_signing.py), stored as
        a `signature` attribute JSON string on the SAME item — beside the
        record blob, never a field on the PromotionRecord schema (the schema is
        frozen; the signature wraps the record). None = unsigned append.
        """
        from botocore.exceptions import ClientError  # lazy, like boto3

        # Rejected before any write: a non-canonical ts would land in the sk
        # and silently break lexical-chronological ordering (validate_record_ts).
        validate_record_ts(record.ts)

        table = self._get_table(session)
        key = self._item_key(record)
        update_expression, names, values = self._prepare_record_write(record, signature)
        try:
            table.update_item(
                Key=key,
                UpdateExpression=update_expression,
                ConditionExpression="attribute_not_exists(pk)",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise RecordAlreadyExistsError(
                    f"ledger record {key['pk']}/{key['sk']} already exists; "
                    "the PromotionRecord ledger is append-only and never overwrites"
                ) from exc
            raise

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        """All ledger records for (principal, action_class), chronological.

        ts_prefix narrows the Query to sk values beginning with the prefix —
        e.g. a UTC day ("2026-07-12") for the demotion runner's same-day
        dedupe read. Prefix matching is lexical over the sk, which is why
        record ts must stay canonical (validate_record_ts).
        """
        table = self._get_table(session)
        pk = self._record_pk(principal, action_class)
        records: list[PromotionRecord] = []
        key_condition = "pk = :pk"
        values: dict = {":pk": pk}
        if ts_prefix is not None:
            key_condition += " AND begins_with(sk, :prefix)"
            values[":prefix"] = ts_prefix
        kwargs: dict = {
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeValues": values,
            "ScanIndexForward": True,  # sk starts with ts → chronological
        }
        while True:
            response = table.query(**kwargs)
            records.extend(
                PromotionRecord.model_validate_json(item["data"])
                for item in response.get("Items", [])
            )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return records
            kwargs["ExclusiveStartKey"] = last_key
