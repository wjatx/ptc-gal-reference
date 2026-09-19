"""SQLite implementations of the grant store + PromotionRecord ledger (product-wrapper Phase 1).

The durable LOCAL backend behind the grants store contract — the third backend
after InMemoryGrantStore and DynamoDBGrantStore, filling the same GrantStore
Protocol with the same error vocabulary, the same #246 stored-bytes integrity
basis, and the same #190 conditional-write discipline. Durability comes from
``sqlite_substrate`` (one ``broker.db``, WAL, item-shaped rows keyed exactly like
the DynamoDB single-table items so ``example-wrapper migrate`` stays a row pump — sqlite
row → Dynamo item, attribute map verbatim).

Integrity is the STORED BYTES (#246): the grant is serialized ONCE
(``canonical_grant_payload``), that exact string is stored as the item's
``data`` AND HMAC'd into the item-level ``grantHash`` attribute; on read the
stored bytes are verified VERBATIM before parsing (the shared
``_read_result_from_item`` helper, so all three backends quarantine
identically). Records store the canonical record payload — the same bytes a
DSSE signature binds (#246 re-shape C) — with the signature envelope beside
the blob, never inside it.

Conditional writes have no ConditionExpression here: every write runs inside
``BEGIN IMMEDIATE`` (the substrate's ``transaction``), which holds the single
writer lock from BEGIN — a read-check-write inside the transaction is
serialized against every other writer, so the in-transaction check IS the
condition, evaluated atomically against current state. There is no REPLACE
anywhere: creates are guarded INSERTs, updates are guarded UPDATEs on a row
the same transaction just evaluated. ``write_record_and_grant`` (#244) is a
NATIVE transaction: both legs' checks and both legs' writes inside one BEGIN
IMMEDIATE — any failure rolls back to nothing written, with the same
less-authority error mapping as the other backends.

The ``session`` parameters exist for Protocol parity and are ignored — there
is no boto3 here; identity on the local arm is the solo-ceremony resolver's
concern (#226), not the store's.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.grants.store import (
    GrantAlreadyExistsError,
    GrantReadResult,
    GrantUpdateConflictError,
    RecordAlreadyExistsError,
    _hmac_payload,
    _principal_key,
    _read_result_from_item,
    _require_prev_raw_data,
    canonical_grant_payload,
    refuse_term_extension,
    validate_record_ts,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import Principal


class SqliteGrantStore(substrate.SqliteStoreBase):
    """SQLite-backed ``GrantStore``.

    Item layout mirrors ``DynamoDBGrantStore`` key-for-key:
        pk = "GRANT#<agentId>#<skill>#<user>#<tier>"
        sk = "CLASS#<actionClass>"
        attrs {"data": <canonical grant payload>, "grantHash": <hmac over
        those exact bytes — the #246 stored-bytes basis>}

    Like both twins, this store never raises QuarantinedGrantError itself:
    get_grant RETURNS the quarantine (grant=None + raw bytes as evidence) and
    a conditional update against a tampered item surfaces as
    GrantUpdateConflictError — raising on quarantine is the caller's job
    (rung.py / ceremony.py), never the store's.
    """

    def __init__(
        self,
        hmac_key: bytes,
        db_path: str | Path,
        *,
        journal_mode: str = substrate.JOURNAL_WAL,
        read_only: bool = False,
    ) -> None:
        super().__init__(db_path, journal_mode=journal_mode, read_only=read_only)
        self._hmac_key = hmac_key

    @staticmethod
    def _item_key(principal: Principal, action_class: str) -> tuple[str, str]:
        return f"GRANT#{_principal_key(principal)}", f"CLASS#{action_class}"

    def _build_attrs(self, grant: Grant) -> dict:
        """The stored item attrs shared by every grant write.

        Serialize once; the stored data string IS the HMAC basis (#246).
        """
        payload = canonical_grant_payload(grant)
        return {"data": payload, "grantHash": _hmac_payload(payload, self._hmac_key)}

    def get_grant(self, principal: Principal, action_class: str) -> GrantReadResult:
        attrs = substrate.get_item(self._connection(), *self._item_key(principal, action_class))
        if attrs is None:
            return GrantReadResult(grant=None)
        # Verify-then-parse over the STORED bytes (#246) — the shared helper,
        # so all three backends quarantine identically.
        return _read_result_from_item(attrs.get("data"), attrs.get("grantHash"), self._hmac_key)

    def put_grant(self, grant: Grant, session: object = None) -> None:
        """Serialize once, HMAC the stored bytes, persist. Session arg unused.

        Blind upsert — bootstrap/seed path only; ceremony paths must never
        call it (see the GrantStore Protocol docstring). Upsert semantics come
        from a read-check inside the transaction, never REPLACE: the substrate
        has no blind-overwrite primitive.
        """
        pk, sk = self._item_key(grant.principal, grant.actionClass)
        attrs = self._build_attrs(grant)
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is None:
                substrate.put_new_item(conn, pk, sk, attrs)
            else:
                substrate.update_existing_item(conn, pk, sk, attrs)

    def create_grant(self, grant: Grant, session: object = None) -> None:
        """Create a new grant; raises GrantAlreadyExistsError on collision.

        The read-inside-BEGIN-IMMEDIATE is the attribute_not_exists condition:
        serialized against every other writer, a grant minted concurrently
        surfaces loudly, never silently replaced.
        """
        pk, sk = self._item_key(grant.principal, grant.actionClass)
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise GrantAlreadyExistsError(
                    f"grant {grant.principal.agentId}/{grant.actionClass} already exists; "
                    "create_grant never overwrites — re-read and re-propose from the "
                    "current state"
                )
            substrate.put_new_item(conn, pk, sk, self._build_attrs(grant))

    def update_grant(
        self,
        updated: Grant,
        expected_hash: str,
        session: object = None,
        prev_raw_data: str | None = None,
    ) -> None:
        """Conditionally replace an existing grant; never creates one.

        The in-transaction re-read is the ConditionExpression: the stored item
        must still be the one the caller evaluated — grantHash equals
        expected_hash AND the stored data bytes equal prev_raw_data (both from
        the guarded re-read). prev_raw_data is REQUIRED (#246; the legacy-item
        fallback is retired) — supplying None is a ValueError, failing toward
        writing nothing.
        """
        _require_prev_raw_data(prev_raw_data)
        conn = self._connection()
        with substrate.transaction(conn):
            pk, sk = self._check_update_conditions(conn, updated, expected_hash, prev_raw_data)
            refuse_term_extension(prev_raw_data, updated, record_type=None)
            substrate.update_existing_item(conn, pk, sk, self._build_attrs(updated))

    def _check_update_conditions(
        self,
        conn: sqlite3.Connection,
        updated: Grant,
        expected_hash: str | None,
        prev_raw_data: str | None,
    ) -> tuple[str, str]:
        """Validate the conditional-update conditions WITHOUT mutating; return
        the item key. Evaluated INSIDE the caller's transaction so the read is
        serialized against every other writer. Shared by update_grant and the
        atomic op so the latter cannot drift from single-write semantics —
        mirrors InMemoryGrantStore._check_update_conditions and the Dynamo
        ConditionExpression clause-for-clause."""
        pk, sk = self._item_key(updated.principal, updated.actionClass)
        item = substrate.get_item(conn, pk, sk)
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
        return pk, sk

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
        """Atomic record+grant write (#244): ONE native BEGIN IMMEDIATE.

        Both legs' checks, then both legs' writes, inside a single transaction
        — any raise rolls back to NOTHING written. The record leg is written
        on THIS store's connection via the record store's shared key/attrs
        builders (one transaction = one connection; calling
        record_store.put_record would run on a second connection OUTSIDE the
        transaction), the same shape as SqliteToolRegistry's
        admit_tool_with_record. The grant leg is checked FIRST so a both-legs
        failure surfaces as the grant conflict — matching the Dynamo
        CancellationReasons mapping's precedence and the memory twin's
        check order (it is the signal the caller must re-read and re-evaluate
        on either way).
        """
        # Backend pairing is structural: both item kinds must land in the same
        # database file, or the "atomic" pair silently splits across stores.
        if not isinstance(record_store, SqlitePromotionRecordStore):
            raise TypeError(
                "write_record_and_grant on SqliteGrantStore requires a "
                f"SqlitePromotionRecordStore, got {type(record_store).__name__}"
            )
        if record_store._db_path.resolve() != self._db_path.resolve():
            raise ValueError(
                "write_record_and_grant requires both stores on the SAME database "
                f"(grant: {str(self._db_path)!r}, record: {str(record_store._db_path)!r})"
            )
        # Rejected before any write, like both twins: a non-canonical ts would
        # land in the sk and silently break lexical-chronological ordering.
        validate_record_ts(record.ts)

        creating = expected is None or expected.grant is None
        grant_pk, grant_sk = self._item_key(grant.principal, grant.actionClass)
        record_pk, record_sk = SqlitePromotionRecordStore._item_key(record)
        record_attrs = SqlitePromotionRecordStore._record_attrs(record, signature)

        conn = self._connection()
        with substrate.transaction(conn):
            # Grant leg — validate without mutating (precedence: see docstring).
            if creating:
                if substrate.get_item(conn, grant_pk, grant_sk) is not None:
                    raise GrantAlreadyExistsError(
                        f"grant {grant.principal.agentId}/{grant.actionClass} already "
                        "exists; create never overwrites — re-read and re-propose from "
                        "the current state"
                    )
            else:
                self._check_update_conditions(conn, grant, expected.stored_hash, expected.raw_data)
                refuse_term_extension(expected.raw_data, grant, record_type=record.recordType)
            # Record leg — append-only.
            if substrate.get_item(conn, record_pk, record_sk) is not None:
                raise RecordAlreadyExistsError(
                    f"ledger record {record_pk}/{record_sk} already exists; "
                    "the PromotionRecord ledger is append-only and never overwrites"
                )
            # Both checks passed — write both legs; a raise from either write
            # (unreachable given the checks, guarded anyway) still rolls back.
            substrate.put_new_item(conn, record_pk, record_sk, record_attrs)
            grant_attrs = self._build_attrs(grant)
            if creating:
                substrate.put_new_item(conn, grant_pk, grant_sk, grant_attrs)
            else:
                substrate.update_existing_item(conn, grant_pk, grant_sk, grant_attrs)


class SqlitePromotionRecordStore(substrate.SqliteStoreBase):
    """SQLite-backed append-only PromotionRecord ledger.

    Records live in the SAME database file as grants, as a distinct item type
    mirroring DynamoDBPromotionRecordStore key-for-key:
        pk = "RECORD#<agentId>#<skill>#<user>#<tier>#<actionClass>"
        sk = "<ts>#<recordType>"      (ts first → chronological partition scan)
        attrs {"data": <canonical record payload — the #246 re-shape C basis,
        the same bytes a DSSE signature binds>[, "signature": <DSSE JSON>]}

    Like the memory twin (and unlike Dynamo, which does not carry the read
    surface yet — #245), the stored signature and stored bytes are readable
    back via signature_for / stored_data_for.
    """

    @staticmethod
    def _item_key(record: PromotionRecord) -> tuple[str, str]:
        return (
            f"RECORD#{_principal_key(record.principal)}#{record.actionClass}",
            f"{record.ts}#{record.recordType}",
        )

    @staticmethod
    def _record_attrs(record: PromotionRecord, signature: dict | None) -> dict:
        """The record item's attrs — the stored data is the CANONICAL record
        payload (the DSSE signing basis, #246 re-shape C), the signature JSON
        beside it, byte-matching DynamoDBPromotionRecordStore._prepare_record_write.
        Shared with SqliteGrantStore.write_record_and_grant so the transact
        path cannot drift from single-write semantics (#244)."""
        from safe_agents.broker.grants.record_signing import canonical_record_payload

        attrs = {"data": canonical_record_payload(record)}
        if signature is not None:
            attrs["signature"] = json.dumps(signature, sort_keys=True, ensure_ascii=True)
        return attrs

    def put_record(
        self, record: PromotionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        """Append one record; raises RecordAlreadyExistsError on a key collision.

        signature: optional DSSE envelope (grants/record_signing.py), stored
        beside the record blob — never a field on the PromotionRecord schema
        (the schema is frozen; the signature wraps the record). None = unsigned.
        """
        # Rejected before any write: a non-canonical ts would land in the sk
        # and silently break lexical-chronological ordering (validate_record_ts).
        validate_record_ts(record.ts)
        pk, sk = self._item_key(record)
        attrs = self._record_attrs(record, signature)
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise RecordAlreadyExistsError(
                    f"ledger record {pk}/{sk} already exists; "
                    "the PromotionRecord ledger is append-only and never overwrites"
                )
            substrate.put_new_item(conn, pk, sk, attrs)

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        """All ledger records for (principal, action_class), chronological.

        get_partition returns sk-ascending (the DynamoDB Query mirror), which
        is chronological because record ts is canonical (validate_record_ts).
        ts_prefix narrows lexically over the sk, e.g. a UTC day ("2026-07-12")
        for the demotion runner's same-day dedupe read.
        """
        pk = f"RECORD#{_principal_key(principal)}#{action_class}"
        return [
            PromotionRecord.model_validate_json(attrs["data"])
            for sk, attrs in substrate.get_partition(self._connection(), pk)
            if ts_prefix is None or sk.startswith(ts_prefix)
        ]

    def signature_for(self, record: PromotionRecord) -> dict | None:
        """The DSSE envelope stored beside the record, or None (audit/test seam)."""
        attrs = substrate.get_item(self._connection(), *self._item_key(record))
        if attrs is None or "signature" not in attrs:
            return None
        return json.loads(attrs["signature"])

    def stored_data_for(self, record: PromotionRecord) -> str | None:
        """The exact stored serialization — the verify basis (#246; audit/test seam)."""
        attrs = substrate.get_item(self._connection(), *self._item_key(record))
        return attrs["data"] if attrs is not None else None
