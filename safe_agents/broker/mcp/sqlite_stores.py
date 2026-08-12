"""SQLite implementations of the MCP registry + admission-proposal stores (product-wrapper Phase 1).

The first durable LOCAL backend behind the existing store Protocols — the two
stores cut B (the ``example-wrapper`` lockfile CLI) needs, born against the transactional
contract that landed with ``admit_tool_with_record``. One contract, three
backends: these classes fill ``ToolRegistryStore`` and ``AdmissionProposalStore``
exactly as ``MemoryToolRegistry``/``DynamoToolRegistry`` and their proposal
siblings do — same error vocabulary, same HMAC quarantine-on-read semantics,
same #190 conditional-write discipline — with durability coming from
``sqlite_substrate`` (one ``broker.db``, WAL, item-shaped rows keyed exactly like
the DynamoDB single-table items so ``example-wrapper migrate`` stays a row pump).

Conditional writes have no ConditionExpression here: every write runs inside
``BEGIN IMMEDIATE`` (the substrate's :func:`~safe_agents.broker.sqlite_substrate.transaction`),
which holds the single writer lock from BEGIN — a read-check-write inside the
transaction is serialized against every other writer, so the in-transaction
check IS the condition, evaluated atomically against current state.
``admit_tool_with_record`` is a NATIVE transaction: both legs' checks and both
legs' writes inside one BEGIN IMMEDIATE — any failure rolls back to nothing
written, the same less-authority error mapping as the other backends.

Proposals keep the d1b98ee stored-bytes integrity basis: serialize once
(``canonical_proposal_payload``), HMAC that string, store that string, and on
read verify the stored bytes verbatim BEFORE parsing.

The ``session`` parameters exist for Protocol parity and are ignored — there is
no boto3 here; identity on the local arm is the solo-ceremony resolver's
concern (#226), not the store's.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.mcp.proposals import (
    McpAdmissionProposal,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    _check_new_status,
    _hmac_payload,
    _proposal_pk,
    _verify_proposal_payload,
    canonical_proposal_payload,
)
from safe_agents.broker.mcp.registry import (
    QuarantinedToolRowError,
    RecordAlreadyExistsError,
    ToolReadResult,
    ToolRowConflictError,
    _read_result_from_item,
    canonical_row_payload,
    compute_row_hmac,
)
from safe_agents.broker.mcp.signing import McpAdmissionRecord, canonical_record_payload
from safe_agents.broker.schemas.mcp_registry import RegisteredTool


class _SqliteStoreBase(substrate.SqliteStoreBase):
    """The substrate's connection lifecycle plus the HMAC key both MCP stores
    carry (the row/proposal integrity basis)."""

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


class SqliteToolRegistry(_SqliteStoreBase):
    """SQLite-backed ``ToolRegistryStore``.

    Item layout mirrors ``DynamoToolRegistry`` key-for-key:
        row     pk="TOOLDEF#<server_id>#<tool_name>"  sk="ROW"
                attrs {"data": <canonical row payload>, "rowHash": <hmac over
                those exact bytes — the #246 stored-bytes basis>}
        record  pk="TOOLREC#<server_id>#<tool_name>"  sk=<ts>
                attrs {"data": <record JSON>[, "signature": <DSSE JSON>]}
    """

    @staticmethod
    def _row_key(server_id: str, tool_name: str) -> tuple[str, str]:
        return f"TOOLDEF#{server_id}#{tool_name}", "ROW"

    @staticmethod
    def _record_key(server_id: str, tool_name: str, ts: str) -> tuple[str, str]:
        return f"TOOLREC#{server_id}#{tool_name}", ts

    def _read_row(self, conn: sqlite3.Connection, server_id: str, tool_name: str) -> ToolReadResult:
        attrs = substrate.get_item(conn, *self._row_key(server_id, tool_name))
        if attrs is None:
            return ToolReadResult(tool=None)
        # Verify-then-parse over the STORED bytes (#246) — the shared registry
        # helper, so all three backends quarantine identically.
        return _read_result_from_item(attrs.get("data"), attrs.get("rowHash"), self._hmac_key)

    def get_tool(self, server_id: str, tool_name: str) -> ToolReadResult:
        return self._read_row(self._connection(), server_id, tool_name)

    def _check_row_write(
        self,
        conn: sqlite3.Connection,
        row: RegisteredTool,
        expected: ToolReadResult | None,
    ) -> tuple[dict, bool]:
        """The row leg's conditions, evaluated INSIDE the caller's transaction
        (so the read is serialized against every other writer — the #190
        conditional evaluated atomically against current state). Returns the
        item attrs to store (stored-bytes basis, #246: serialize once, HMAC
        that exact string) and whether a row currently exists. Same checks,
        same error vocabulary as the other backends.
        """
        current = self._read_row(conn, row.server_id, row.tool_name)
        if current.quarantined:
            raise QuarantinedToolRowError(
                f"row {row.server_id}/{row.tool_name} is HMAC-quarantined "
                f"({current.quarantine_reason}); it is NEVER auto-overwritten — "
                "root-cause the tamper before re-admitting (M6)"
            )
        baseline = expected if expected is not None else current
        if baseline.tool is None:
            if current.tool is not None:
                raise ToolRowConflictError(
                    f"row {row.server_id}/{row.tool_name}: expected no existing row "
                    "(first admission) but one exists — a row was admitted "
                    "concurrently; re-read and re-vet before retrying"
                )
        elif current.tool is None or (
            current.stored_hash != baseline.stored_hash
            or current.raw_data != baseline.raw_data
        ):
            raise ToolRowConflictError(
                f"row {row.server_id}/{row.tool_name}: the stored row is not the one "
                "evaluated (concurrently modified, or a data/HMAC tamper landed "
                "between the re-read and the write); re-read and re-vet before retrying"
            )
        payload = canonical_row_payload(row)
        attrs = {"data": payload, "rowHash": compute_row_hmac(row, self._hmac_key)}
        return attrs, current.tool is not None

    def _write_row(
        self, conn: sqlite3.Connection, row: RegisteredTool, attrs: dict, row_exists: bool
    ) -> None:
        pk, sk = self._row_key(row.server_id, row.tool_name)
        if row_exists:
            substrate.update_existing_item(conn, pk, sk, attrs)
        else:
            substrate.put_new_item(conn, pk, sk, attrs)

    def _check_record_write(
        self, conn: sqlite3.Connection, record: McpAdmissionRecord
    ) -> tuple[str, str]:
        pk, sk = self._record_key(record.serverId, record.toolName, record.ts)
        if substrate.get_item(conn, pk, sk) is not None:
            raise RecordAlreadyExistsError(
                f"admission record {pk}/{sk} already exists; the ledger is "
                "append-only and never overwrites"
            )
        return pk, sk

    @staticmethod
    def _record_attrs(record: McpAdmissionRecord, signature: dict | None) -> dict:
        # canonical_record_payload, NOT model_dump_json: the DSSE subject digest
        # is the sha256 of the CANONICAL (sorted-key) serialization, and
        # verification digests the STORED bytes verbatim (#246). pydantic's
        # model_dump_json emits declaration order, so a record stored that way
        # can never verify against its own signature — the Dynamo arm has
        # always written canonical_record_payload, and the two arms must store
        # byte-identical bytes or the store becomes the integrity basis's
        # weakest link.
        attrs = {"data": canonical_record_payload(record)}
        if signature is not None:
            attrs["signature"] = json.dumps(signature, sort_keys=True, ensure_ascii=True)
        return attrs

    def admit_tool(
        self,
        row: RegisteredTool,
        session: object = None,
        *,
        expected: ToolReadResult | None = None,
    ) -> None:
        conn = self._connection()
        with substrate.transaction(conn):
            attrs, row_exists = self._check_row_write(conn, row, expected)
            self._write_row(conn, row, attrs, row_exists)

    def put_record(
        self, record: McpAdmissionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        conn = self._connection()
        with substrate.transaction(conn):
            pk, sk = self._check_record_write(conn, record)
            substrate.put_new_item(conn, pk, sk, self._record_attrs(record, signature))

    def admit_tool_with_record(
        self,
        record: McpAdmissionRecord,
        row: RegisteredTool,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: ToolReadResult | None = None,
    ) -> None:
        # ONE native transaction: both legs' checks, then both legs' writes,
        # inside a single BEGIN IMMEDIATE — any raise rolls back to NOTHING
        # written. The row check runs first so a both-legs failure surfaces as
        # ToolRowConflictError, matching the Dynamo mapping's precedence.
        conn = self._connection()
        with substrate.transaction(conn):
            attrs, row_exists = self._check_row_write(conn, row, expected)
            record_pk, record_sk = self._check_record_write(conn, record)
            substrate.put_new_item(
                conn, record_pk, record_sk, self._record_attrs(record, signature)
            )
            self._write_row(conn, row, attrs, row_exists)

    def list_records(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[McpAdmissionRecord]:
        pk = f"TOOLREC#{server_id}#{tool_name}"
        return [
            McpAdmissionRecord.model_validate_json(attrs["data"])
            for _sk, attrs in substrate.get_partition(self._connection(), pk)
        ]

    def get_record_signature(self, server_id: str, tool_name: str, ts: str) -> dict | None:
        attrs = substrate.get_item(
            self._connection(), *self._record_key(server_id, tool_name, ts)
        )
        if attrs is None or "signature" not in attrs:
            return None
        return json.loads(attrs["signature"])


class SqliteAdmissionProposalStore(_SqliteStoreBase):
    """SQLite-backed ``AdmissionProposalStore``.

    Item layout mirrors ``DynamoAdmissionProposalStore``:
        pk = "TOOLPROP#<server_id>#<tool_name>"   sk = <proposal_id>
        attrs {"data": <canonical payload>, "proposalHash": <hmac>,
               "status": pending|ratified|rejected, "expires_at": <ISO-8601>}
    ``expires_at`` also rides the indexed substrate column (expiry stays a
    predicate at use — ``proposal_expired`` — the column only serves a future
    documented-lag sweep). The integrity basis is the STORED BYTES: the
    canonical payload is serialized once, HMAC'd as that string, and verified
    verbatim on every read before parsing (the d1b98ee discipline).
    """

    @staticmethod
    def _item_key(server_id: str, tool_name: str, proposal_id: str) -> tuple[str, str]:
        return _proposal_pk(server_id, tool_name), proposal_id

    def put_proposal(self, proposal: McpAdmissionProposal, session: object = None) -> None:
        pk, sk = self._item_key(
            proposal.tool_def.server_id, proposal.tool_def.tool_name, proposal.proposal_id
        )
        payload = canonical_proposal_payload(proposal)
        attrs = {
            "data": payload,
            "proposalHash": _hmac_payload(payload, self._hmac_key),
            "status": "pending",
            "expires_at": proposal.expires_at,
        }
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise ProposalAlreadyExistsError(
                    f"admission proposal {pk}/{sk} already exists; proposals are "
                    "never overwritten — mint a fresh proposal_id"
                )
            substrate.put_new_item(conn, pk, sk, attrs, expires_at=proposal.expires_at)

    def get_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, session: object = None
    ) -> tuple[McpAdmissionProposal, str] | None:
        attrs = substrate.get_item(
            self._connection(), *self._item_key(server_id, tool_name, proposal_id)
        )
        if attrs is None:
            return None
        _verify_proposal_payload(
            attrs.get("proposalHash"), attrs["data"], self._hmac_key,
            coordinate=f"{server_id}/{tool_name}/{proposal_id}",
        )
        proposal = McpAdmissionProposal.model_validate_json(attrs["data"])
        return proposal, attrs["status"]

    def list_pending(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[tuple[McpAdmissionProposal, str]]:
        pending: list[tuple[McpAdmissionProposal, str]] = []
        for sk, attrs in substrate.get_partition(
            self._connection(), _proposal_pk(server_id, tool_name)
        ):
            # Verify EVERY row on the partition, not just the pending ones: a
            # tamper must not be able to hide behind a status flip.
            _verify_proposal_payload(
                attrs.get("proposalHash"), attrs["data"], self._hmac_key,
                coordinate=f"{server_id}/{tool_name}/{sk}",
            )
            if attrs["status"] == "pending":
                pending.append(
                    (McpAdmissionProposal.model_validate_json(attrs["data"]), attrs["status"])
                )
        return pending

    def consume_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, new_status: str,
        session: object = None,
    ) -> None:
        _check_new_status(new_status)
        pk, sk = self._item_key(server_id, tool_name, proposal_id)
        conn = self._connection()
        with substrate.transaction(conn):
            # The read-inside-BEGIN-IMMEDIATE is the conditional status flip:
            # only pending → ratified|rejected, serialized against every other
            # writer, so the double-ratify race dies at the store.
            attrs = substrate.get_item(conn, pk, sk)
            if attrs is None or attrs["status"] != "pending":
                found = "absent" if attrs is None else f"status={attrs['status']!r}"
                raise ProposalConsumedError(
                    f"admission proposal {proposal_id} for {server_id}/{tool_name} is not "
                    f"pending ({found}); it was already consumed or never existed"
                )
            attrs["status"] = new_status
            substrate.update_existing_item(
                conn, pk, sk, attrs, expires_at=attrs.get("expires_at")
            )
