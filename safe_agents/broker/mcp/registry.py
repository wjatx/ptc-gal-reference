"""Admitted-tool registry store: the HMAC row + the append-only admission ledger (#174).

The reference store binding MCP-HOST.md defers to (§"Tier split"). It MIRRORS
``grants/store.py`` one-for-one — the same HMAC-over-canonical-fields,
quarantine-on-read, refuse-to-overwrite-a-quarantined-row, and
append-only-ledger mechanisms — because the registry defends the same class of
tamper the grant store does (M13, M6, M8). Its siblings mirror the rest of the
grants split: ``mcp/proposals.py`` (the single-shot admission proposal, mirroring
``grants/proposals.py``) and ``mcp/signing.py`` (the issuer-DSSE admission-record
signing, mirroring ``grants/record_signing.py``).

Load-bearing invariants:
- **The broker/agent NEVER writes the registry** (mirrors "the broker cannot
  write grants"). The admission ceremony (``mcp/commands.py``) is the only writer.
  Drift → QUARANTINED status is COMPUTED at discovery time by ``mcp/discovery.py``,
  not here.
- **Store-integrity HMAC (M13), stored-bytes basis (#246).** The row is
  serialized ONCE (``canonical_row_payload``), that exact string is stored as
  the item's ``data`` AND HMAC'd into the item-level ``rowHash`` attribute —
  exactly like ``compute_grant_hash``/``canonical_grant_payload``. On read the
  stored bytes are verified VERBATIM before parsing; a mismatch yields a
  quarantined ``ToolReadResult`` with ``tool=None`` (tampered bytes are
  evidence, never parsed) and the raw bytes riding along for audit.
- **A quarantined row is never auto-overwritten (M6).** ``admit_tool`` refuses to
  write over an HMAC-tampered row (``QuarantinedToolRowError``), mirroring
  ``reseed_command``'s "an HMAC-tamper quarantine is an incident, not a
  ceremony". A discovery-drift row (status QUARANTINED but HMAC intact) IS
  resolvable: the re-vet ceremony writes a fresh ACTIVE row over it.
- **Record+row commit as ONE atomic unit** (``admit_tool_with_record``, the
  ceremony's write path since 2026-07-24 — either both legs land or nothing is
  written, superseding the old record-before-row ordering and its orphan-record
  artifact). The single-leg ``put_record`` / ``admit_tool`` remain for
  conformance and tooling, with the same conditions the atomic op composes.

Table name: ``MCP_REGISTRY_TABLE_NAME`` env var (ImportValue'd from infra, never
hardcoded — same convention as ``GRANTS_TABLE_NAME``). Distinct item-key prefixes
so rows/records/proposals co-locate: ``TOOLDEF#``, ``TOOLREC#`` (``TOOLPROP#`` in
``mcp/proposals.py``).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from safe_agents.broker.mcp.signing import McpAdmissionRecord, canonical_record_payload
from safe_agents.broker.schemas.mcp_registry import RegisteredTool


# ---------------------------------------------------------------------------
# Error types (mirror grants/store.py)
# ---------------------------------------------------------------------------


class QuarantinedToolRowError(Exception):
    """Write refused: the stored row is HMAC-quarantined (failed verification).

    A quarantined row's contents are untrusted; writing over it would launder
    the tampered state under a fresh valid HMAC (mirrors QuarantinedGrantError).
    An HMAC-tamper quarantine is an incident, not a ceremony — root-cause it
    before touching the row.
    """


class RecordAlreadyExistsError(Exception):
    """Append-only ledger violation: an admission record with this key exists.

    The admission ledger is append-only — an existing item is NEVER overwritten;
    surfacing loudly is the tamper-evidence property.
    """


class ToolRowConflictError(Exception):
    """Conditional row write refused: the stored row is not the one evaluated.

    Raised when ``admit_tool``'s conditional write fails — a first admission
    found a row created concurrently, or a re-vet found the row changed
    underfoot (concurrent write, or a data/HMAC tamper landing between the
    guarded re-read and the write). Mirrors GrantUpdateConflictError /
    GrantAlreadyExistsError (#190): each write is conditional and fails toward
    LESS authority; the caller must re-read and re-vet, never overwrite blind.
    """


# ---------------------------------------------------------------------------
# Store-integrity HMAC (M13) — stored-bytes basis (#246, the grants/store.py idiom)
# ---------------------------------------------------------------------------


def canonical_row_payload(row: RegisteredTool) -> str:
    """The ONE serialization of a row — what gets stored AND what gets HMAC'd.

    Storage and the integrity basis must be the same bytes (#246 re-shape A,
    the mcp/proposals.py idiom). When they diverge, verification has to
    re-serialize the parsed model, which silently re-derives the basis from
    whatever the model class looks like *today* — so any additive schema
    change invalidates every historical row and reports it as a tamper. A
    ceremony that cries tamper when a schema grows teaches operators to
    dismiss the alarm that matters.

    So: serialize once, store this exact string, HMAC this exact string, and
    on read HMAC the stored bytes verbatim without ever re-serializing. The
    integrity slot (the item-level ``rowHash`` attribute) is deliberately
    OUTSIDE the payload — the pre-#246 in-payload ``hash`` slot, and the #223
    ``exclude_none`` patch that existed only to keep the parse-then-
    re-serialize basis stable under additive widening, are both retired:
    nesting + stored-bytes make them unnecessary.

    Canonical form: JSON with sorted keys, ASCII, all types serialized via
    Pydantic's JSON mode (enums -> str, nested models -> dict).
    """
    return json.dumps(row.model_dump(mode="json"), sort_keys=True, ensure_ascii=True)


def compute_row_hmac(row: RegisteredTool, hmac_key: bytes) -> str:
    """HMAC-SHA-256 over the canonical row payload (write path)."""
    return _hmac_payload(canonical_row_payload(row), hmac_key)


def _hmac_payload(payload: str, hmac_key: bytes) -> str:
    return _hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class ToolReadResult:
    """Result of a get_tool call (mirror GrantReadResult).

    If quarantined=True the stored bytes failed verification against the
    item-level rowHash (or the attribute was absent): tool is None — tampered
    bytes are evidence, not a RegisteredTool, and are never parsed — and
    raw_data carries the bytes for audit. Callers must check quarantined
    BEFORE not-found.

    raw_data is the exact stored serialization (the item's 'data' attribute —
    the integrity basis itself); stored_hash is the item-level rowHash.
    Together they are what a conditional re-vet write conditions on.
    """

    tool: RegisteredTool | None
    quarantined: bool = False
    quarantine_reason: str | None = None
    raw_data: str | None = None
    stored_hash: str | None = None


def _read_result_from_item(
    data: object, stored_hash: object, hmac_key: bytes
) -> ToolReadResult:
    """Verify-then-parse a stored row item (shared by all backends).

    The stored bytes are HMAC'd VERBATIM against the item-level rowHash
    before any parse; a mismatch — or a missing/non-string half — quarantines
    with tool=None (the bytes are untrusted input and never parsed). Mirrors
    grants/store.py's helper of the same name (#246).
    """
    if not isinstance(data, str) or not isinstance(stored_hash, str):
        return ToolReadResult(
            tool=None,
            quarantined=True,
            quarantine_reason=(
                "stored item is missing its data or rowHash attribute; the "
                "item cannot be verified and must not activate anything"
            ),
            raw_data=data if isinstance(data, str) else None,
        )
    expected = _hmac_payload(data, hmac_key)
    if stored_hash != expected:
        return ToolReadResult(
            tool=None,
            quarantined=True,
            quarantine_reason=(
                f"hash mismatch: stored={stored_hash!r} expected={expected!r}"
            ),
            raw_data=data,
            stored_hash=stored_hash,
        )
    return ToolReadResult(
        tool=RegisteredTool.model_validate_json(data),
        raw_data=data,
        stored_hash=stored_hash,
    )


# ---------------------------------------------------------------------------
# Store interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ToolRegistryStore(Protocol):
    """Injectable registry store. Tests use MemoryToolRegistry; prod DynamoToolRegistry."""

    def get_tool(self, server_id: str, tool_name: str) -> ToolReadResult: ...

    def admit_tool(
        self,
        row: RegisteredTool,
        session: object = None,
        *,
        expected: ToolReadResult | None = None,
    ) -> None:
        """The ONLY sanctioned row write (create or re-vet-overwrite).

        Refuses (QuarantinedToolRowError) to write over an HMAC-tampered row —
        the M6 no-auto-overwrite guarantee. A discovery-drift row (status
        QUARANTINED, HMAC intact) IS overwritten: that is the re-vet resolving
        it. Stamps a fresh HMAC on the written row.

        The write is CONDITIONAL (#190): ``expected`` is the caller's guarded
        re-read of this coordinate (its ToolReadResult). A first admission
        (``expected.tool is None``, or unset on an empty coordinate) conditions
        on ``attribute_not_exists``; a re-vet conditions on the stored row still
        being byte-for-byte the one ``expected`` saw (its rowHash AND data). A
        row that changed underfoot — a concurrent write, or a tamper landing
        between the re-read and the write — raises ToolRowConflictError instead
        of silently overwriting (which would launder the change under a fresh
        HMAC and destroy M6's tamper evidence). When ``expected`` is omitted the
        store takes its own guarded re-read as the baseline.
        """
        ...

    def put_record(
        self, record: McpAdmissionRecord, session: object = None, signature: dict | None = None
    ) -> None: ...

    def admit_tool_with_record(
        self,
        record: McpAdmissionRecord,
        row: RegisteredTool,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: ToolReadResult | None = None,
    ) -> None:
        """Append the admission record AND write the row as ONE atomic unit.

        The transactional form of ``put_record`` + ``admit_tool`` — closes the
        record-without-row gap structurally (#221 Phase 6's orphan-``TOOLREC#``):
        either BOTH legs commit or NOTHING is written. Each leg keeps its own
        condition — the record leg stays append-only (``attribute_not_exists``),
        the row leg carries the full ``admit_tool`` conditional semantics
        (``expected`` is the caller's #190 guarded-re-read baseline; first
        admission vs. re-vet exactly as documented on ``admit_tool``).

        Error mapping — every failure lands on the LESS-authority side, meaning
        nothing written, in ALL failure cases:

        - ``QuarantinedToolRowError``: the M6 pre-flight refusal, before any
          write is attempted.
        - ``RecordAlreadyExistsError``: the record leg's append-only condition
          failed; the whole write canceled — the row was NOT touched.
        - ``ToolRowConflictError``: the row leg's conditional failed (concurrent
          write, or a tamper landing between the re-read and the write); the
          whole write canceled — the record was NOT appended.
        - Any other cancellation (throttle, transaction conflict) propagates as
          the backend's own error; the unit still wrote nothing.
        """
        ...

    def list_records(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[McpAdmissionRecord]: ...


# ---------------------------------------------------------------------------
# In-memory fake — for unit tests (mirrors the DynamoDB item semantics)
# ---------------------------------------------------------------------------


class MemoryToolRegistry:
    """Fake registry backed by plain dicts, ITEM-SHAPED to mirror the DynamoDB
    semantics byte-for-byte (#246): each row entry is {"data": <canonical
    payload str>, "rowHash": <hmac str>} — so stored-bytes tamper tests
    exercise the same verify-then-parse path as production. Thread-unsafe;
    unit tests only."""

    def __init__(self, hmac_key: bytes = b"test-hmac-key") -> None:
        self._hmac_key = hmac_key
        # (server_id, tool_name) -> {"data": str, "rowHash": str}
        self._rows: dict[tuple[str, str], dict] = {}
        self._records: dict[tuple[str, str, str], dict] = {}

    def get_tool(self, server_id: str, tool_name: str) -> ToolReadResult:
        item = self._rows.get((server_id, tool_name))
        if item is None:
            return ToolReadResult(tool=None)
        return _read_result_from_item(item.get("data"), item.get("rowHash"), self._hmac_key)

    def _build_item(self, row: RegisteredTool) -> dict:
        """Serialize once; the stored data string IS the HMAC basis (#246)."""
        payload = canonical_row_payload(row)
        return {"data": payload, "rowHash": _hmac_payload(payload, self._hmac_key)}

    def _check_row_write(
        self, row: RegisteredTool, expected: ToolReadResult | None
    ) -> dict:
        """Validate the row write's conditions WITHOUT mutating; return the
        item to store. Shared by admit_tool and the atomic op so the latter can
        check both legs before committing either."""
        current = self.get_tool(row.server_id, row.tool_name)
        if current.quarantined:
            raise QuarantinedToolRowError(
                f"row {row.server_id}/{row.tool_name} is HMAC-quarantined "
                f"({current.quarantine_reason}); it is NEVER auto-overwritten — "
                "root-cause the tamper before re-admitting (M6)"
            )
        baseline = expected if expected is not None else current
        # Conditional write (#190 mirror): the stored row must still be exactly
        # what `baseline` saw — its item-level rowHash AND its stored bytes
        # (#246: the baseline is the guarded re-read's stored_hash/raw_data,
        # never a field of the parsed row). In DynamoDB this is a
        # ConditionExpression evaluated atomically; here it is the same check
        # against the current dict state.
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
        return self._build_item(row)

    def _check_record_write(self, record: McpAdmissionRecord) -> tuple[str, str, str]:
        """Validate the record leg's append-only condition WITHOUT mutating."""
        key = (record.serverId, record.toolName, record.ts)
        if key in self._records:
            raise RecordAlreadyExistsError(
                f"admission record {key} already exists; the ledger is append-only "
                "and never overwrites"
            )
        return key

    @staticmethod
    def _record_item(record: McpAdmissionRecord, signature: dict | None) -> dict:
        return {
            # Canonical payload — the same bytes the DSSE signature binds (#246 C)
            "data": canonical_record_payload(record),
            "signature": json.dumps(signature, sort_keys=True, ensure_ascii=True)
            if signature is not None
            else None,
        }

    def admit_tool(
        self,
        row: RegisteredTool,
        session: object = None,
        *,
        expected: ToolReadResult | None = None,
    ) -> None:
        item = self._check_row_write(row, expected)
        self._rows[(row.server_id, row.tool_name)] = item

    def put_record(
        self, record: McpAdmissionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        key = self._check_record_write(record)
        self._records[key] = self._record_item(record, signature)

    def admit_tool_with_record(
        self,
        record: McpAdmissionRecord,
        row: RegisteredTool,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: ToolReadResult | None = None,
    ) -> None:
        # Check BOTH legs before committing EITHER — the memory mirror of the
        # DynamoDB transaction: any raise above the commit lines writes nothing.
        item = self._check_row_write(row, expected)
        key = self._check_record_write(record)
        self._records[key] = self._record_item(record, signature)
        self._rows[(row.server_id, row.tool_name)] = item

    def list_records(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[McpAdmissionRecord]:
        return [
            McpAdmissionRecord.model_validate_json(item["data"])
            for (sid, tname, _ts), item in sorted(self._records.items())
            if sid == server_id and tname == tool_name
        ]

    def get_record_signature(self, server_id: str, tool_name: str, ts: str) -> dict | None:
        item = self._records.get((server_id, tool_name, ts))
        if item is None or item["signature"] is None:
            return None
        return json.loads(item["signature"])


# ---------------------------------------------------------------------------
# DynamoDB implementation — production
# ---------------------------------------------------------------------------


class DynamoToolRegistry:
    """DynamoDB-backed registry store.

    Table name: MCP_REGISTRY_TABLE_NAME env var (ImportValue from infra). Callers
    supply a boto3 Session for writes — this client never assumes roles. Item
    layout:
        row     pk="TOOLDEF#<server_id>#<tool_name>"  sk="ROW"
        record  pk="TOOLREC#<server_id>#<tool_name>"  sk="<ts>"
    'data' holds the canonical row payload — the stored bytes ARE the integrity
    basis (#246); rowHash (the HMAC over those exact bytes) lives at item level
    ONLY, the sole integrity slot. BOTH
    writes go through update_item under a ConditionExpression — rows condition on
    attribute_not_exists (first admission) or rowHash+data (re-vet, the #190
    guarded-re-read mirror); records condition on attribute_not_exists
    (append-only), like the PromotionRecord ledger. Because neither write uses
    put_item, the store needs only UpdateItem on the table (UpdateItem authorizes
    the creating upsert; the ConditionExpression, not the IAM verb, is what makes
    a row non-overwritable and the ledger append-only).
    """

    def __init__(self, hmac_key: bytes, table_name: str | None = None) -> None:
        self._hmac_key = hmac_key
        self._table_name = table_name or os.environ["MCP_REGISTRY_TABLE_NAME"]

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    def _get_client(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        return session.client("dynamodb") if session is not None else boto3.client("dynamodb")

    @staticmethod
    def _row_key(server_id: str, tool_name: str) -> dict:
        return {"pk": f"TOOLDEF#{server_id}#{tool_name}", "sk": "ROW"}

    @staticmethod
    def _record_key(server_id: str, tool_name: str, ts: str) -> dict:
        return {"pk": f"TOOLREC#{server_id}#{tool_name}", "sk": ts}

    def get_tool(self, server_id: str, tool_name: str) -> ToolReadResult:
        table = self._get_table()
        item = table.get_item(Key=self._row_key(server_id, tool_name)).get("Item")
        if item is None:
            return ToolReadResult(tool=None)
        return _read_result_from_item(item.get("data"), item.get("rowHash"), self._hmac_key)

    def _prepare_row_write(
        self, row: RegisteredTool, expected: ToolReadResult | None
    ) -> tuple[str, dict, dict]:
        """M6 pre-flight + the #190 conditional-write pieces for the row leg.

        Returns (ConditionExpression, ExpressionAttributeNames,
        ExpressionAttributeValues) with PLAIN string values — the resource-level
        ``admit_tool`` uses them as-is; the transactional op wraps them in typed
        AttributeValues. Sharing this builder is what keeps the two paths'
        semantics identical by construction.
        """
        current = self.get_tool(row.server_id, row.tool_name)
        if current.quarantined:
            raise QuarantinedToolRowError(
                f"row {row.server_id}/{row.tool_name} is HMAC-quarantined "
                f"({current.quarantine_reason}); it is NEVER auto-overwritten — "
                "root-cause the tamper before re-admitting (M6)"
            )
        baseline = expected if expected is not None else current
        # Serialize once; the stored data string IS the HMAC basis (#246).
        payload = canonical_row_payload(row)

        # The write is conditioned on the stored row still being the one the
        # caller evaluated (#190). A first admission conditions on
        # attribute_not_exists; a re-vet conditions on rowHash AND the data
        # string (a tamper of data alone — rowHash untouched — landing between
        # the guarded re-read and this write would pass a rowHash-only condition
        # and be silently overwritten, destroying the tamper evidence, exactly
        # the update_grant data clause), with values from the guarded re-read's
        # item-level stored_hash/raw_data (#246). DynamoDB evaluates the
        # condition atomically against CURRENT state, so it also closes the
        # get_tool→write gap above. 'data' is a DynamoDB reserved word → #data.
        names = {"#data": "data"}
        values: dict = {
            ":data": payload,
            ":new_hash": _hmac_payload(payload, self._hmac_key),
        }
        if baseline.tool is None:
            condition = "attribute_not_exists(pk)"
        else:
            condition = "attribute_exists(pk) AND rowHash = :expected AND #data = :prev_data"
            values[":expected"] = baseline.stored_hash
            values[":prev_data"] = baseline.raw_data
        return condition, names, values

    @staticmethod
    def _prepare_record_write(
        record: McpAdmissionRecord, signature: dict | None
    ) -> tuple[str, dict, dict]:
        """UpdateExpression/names/values (plain) for the append-only record leg.

        The stored data is the CANONICAL record payload — the same bytes the
        DSSE signature binds, so verification digests the stored string
        verbatim (#246 re-shape C).
        """
        update_expression = "SET #data = :data"
        names = {"#data": "data"}
        values: dict = {":data": canonical_record_payload(record)}
        if signature is not None:
            update_expression += ", #sig = :sig"
            names["#sig"] = "signature"
            values[":sig"] = json.dumps(signature, sort_keys=True, ensure_ascii=True)
        return update_expression, names, values

    _ROW_UPDATE_EXPRESSION = "SET #data = :data, rowHash = :new_hash"

    def _row_conflict_error(self, row: RegisteredTool) -> ToolRowConflictError:
        return ToolRowConflictError(
            f"row {row.server_id}/{row.tool_name}: the stored row is not the "
            "one evaluated (concurrently modified, or a data/HMAC tamper "
            "landed between the re-read and the write); re-read and re-vet "
            "before retrying"
        )

    def admit_tool(
        self,
        row: RegisteredTool,
        session: object = None,
        *,
        expected: ToolReadResult | None = None,
    ) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        condition, names, values = self._prepare_row_write(row, expected)
        table = self._get_table(session)
        try:
            table.update_item(
                Key=self._row_key(row.server_id, row.tool_name),
                UpdateExpression=self._ROW_UPDATE_EXPRESSION,
                ConditionExpression=condition,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise self._row_conflict_error(row) from exc
            raise

    def put_record(
        self, record: McpAdmissionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        table = self._get_table(session)
        key = self._record_key(record.serverId, record.toolName, record.ts)
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
                    f"admission record {key['pk']}/{key['sk']} already exists; the "
                    "ledger is append-only and never overwrites"
                ) from exc
            raise

    def admit_tool_with_record(
        self,
        record: McpAdmissionRecord,
        row: RegisteredTool,
        session: object = None,
        *,
        signature: dict | None = None,
        expected: ToolReadResult | None = None,
    ) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        # Both legs' expressions come from the SAME builders the single-item
        # writes use, so this path cannot drift from admit_tool/put_record
        # semantics. Update-only TransactWriteItems: the store still needs only
        # dynamodb:UpdateItem (no IAM change — the #221 close-out claim, now
        # exercised).
        row_condition, row_names, row_values = self._prepare_row_write(row, expected)
        rec_update, rec_names, rec_values = self._prepare_record_write(record, signature)
        record_key = self._record_key(record.serverId, record.toolName, record.ts)

        def typed(plain: dict) -> dict:
            # Every attribute this store writes is a string; the low-level
            # transact API needs typed AttributeValues.
            return {k: {"S": v} for k, v in plain.items()}

        # Item order is load-bearing for error mapping: index 0 = record leg,
        # index 1 = row leg (matches CancellationReasons positionally).
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
                    "Key": typed(self._row_key(row.server_id, row.tool_name)),
                    "UpdateExpression": self._ROW_UPDATE_EXPRESSION,
                    "ConditionExpression": row_condition,
                    "ExpressionAttributeNames": row_names,
                    "ExpressionAttributeValues": typed(row_values),
                }
            },
        ]
        try:
            self._get_client(session).transact_write_items(TransactItems=transact_items)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            # A canceled transaction wrote NOTHING — map the failing leg to the
            # same error vocabulary the single-item writes use. Row conflict
            # takes precedence when both legs fail: it is the signal the caller
            # must re-read and re-vet on either way.
            reasons = exc.response.get("CancellationReasons") or []
            codes = [reason.get("Code") for reason in reasons]
            if len(codes) > 1 and codes[1] == "ConditionalCheckFailed":
                raise self._row_conflict_error(row) from exc
            if codes and codes[0] == "ConditionalCheckFailed":
                raise RecordAlreadyExistsError(
                    f"admission record {record_key['pk']}/{record_key['sk']} already "
                    "exists; the ledger is append-only and never overwrites (the "
                    "row leg was canceled with it — nothing was written)"
                ) from exc
            raise

    def list_records(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[McpAdmissionRecord]:
        table = self._get_table(session)
        pk = f"TOOLREC#{server_id}#{tool_name}"
        records: list[McpAdmissionRecord] = []
        kwargs: dict = {
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": {":pk": pk},
            "ScanIndexForward": True,
        }
        while True:
            response = table.query(**kwargs)
            records.extend(
                McpAdmissionRecord.model_validate_json(item["data"])
                for item in response.get("Items", [])
            )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return records
            kwargs["ExclusiveStartKey"] = last_key
