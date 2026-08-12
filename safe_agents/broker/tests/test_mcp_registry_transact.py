"""admit_tool_with_record — the atomic record+row write (product-wrapper Phase 1, work item 1).

The transactional form of ``put_record`` + ``admit_tool``: either BOTH legs
commit or NOTHING is written, closing #221 Phase 6's orphan-``TOOLREC#`` gap
structurally. Failure injection runs on BOTH backends — MemoryToolRegistry
(check-then-commit) and the real DynamoToolRegistry against moto's DynamoDB,
whose expression evaluator enforces ``TransactWriteItems`` conditions and
atomicity for real (verified this session: a failing leg raises
``TransactionCanceledException`` with per-item ``CancellationReasons`` and the
passing leg is NOT written). The memory tests carry no AWS dependency; the moto
half importorskips like test_dynamo_stores.py.

Covered, per backend:
- happy path: row AND record both present after one call (signature stored).
- record leg fails (append-only violation) -> RecordAlreadyExistsError, row NOT
  written.
- row leg fails (concurrent first admission) -> ToolRowConflictError, record
  NOT appended.
- row leg fails on a stale re-vet baseline -> ToolRowConflictError, record NOT
  appended.
- HMAC-quarantined row -> QuarantinedToolRowError pre-flight, nothing written.
- both legs fail -> ToolRowConflictError takes precedence (Dynamo mapping).
"""

from __future__ import annotations

import os

import pytest

from safe_agents.broker.mcp.registry import (
    MemoryToolRegistry,
    QuarantinedToolRowError,
    RecordAlreadyExistsError,
    ToolRowConflictError,
)
from safe_agents.broker.mcp.signing import McpAdmissionRecord
from safe_agents.broker.schemas.mcp_registry import (
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)

SERVER_ID = "market-data"
TOOL_NAME = "quote"
MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/maker-session"
CHECKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/checker-session"
TS = "2026-07-24T12:00:00+00:00"
SIGNATURE = {"payloadType": "application/vnd.test+json", "payload": "e30=", "signatures": []}


def make_tool_def(description: str = "return a quote") -> McpToolDef:
    return McpToolDef(
        server_id=SERVER_ID,
        tool_name=TOOL_NAME,
        input_schema={"type": "object", "properties": {"symbol": {"type": "string"}}},
        description=description,
    )


def make_row(tool_def: McpToolDef | None = None) -> RegisteredTool:
    tool_def = tool_def or make_tool_def()
    return RegisteredTool(
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        status=RegistryStatus.ACTIVE,
        admitted_by=CHECKER_ARN,
        admitted_at=TS,
    )


def make_record(tool_def: McpToolDef | None = None, ts: str = TS) -> McpAdmissionRecord:
    tool_def = tool_def or make_tool_def()
    return McpAdmissionRecord(
        recordType="admission",
        serverId=tool_def.server_id,
        toolName=tool_def.tool_name,
        defHash=compute_tool_def_hash(tool_def),
        proposedBy=MAKER_ARN,
        ratifiedBy=CHECKER_ARN,
        ts=ts,
    )


# ===========================================================================
# Memory backend
# ===========================================================================


class TestMemoryAtomicAdmit:
    def test_happy_path_writes_row_and_record(self):
        store = MemoryToolRegistry()
        store.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        read = store.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool is not None and not read.quarantined
        records = store.list_records(SERVER_ID, TOOL_NAME)
        assert [r.ts for r in records] == [TS]
        assert store.get_record_signature(SERVER_ID, TOOL_NAME, TS) == SIGNATURE

    def test_record_exists_cancels_row_write(self):
        store = MemoryToolRegistry()
        store.put_record(make_record())  # occupy the record key
        with pytest.raises(RecordAlreadyExistsError):
            store.admit_tool_with_record(make_record(), make_row())
        assert store.get_tool(SERVER_ID, TOOL_NAME).tool is None  # row NOT written

    def test_row_conflict_cancels_record_write(self):
        from safe_agents.broker.mcp.registry import ToolReadResult

        store = MemoryToolRegistry()
        store.admit_tool(make_row())  # row admitted concurrently
        # `expected` says first admission (no row) — the row leg must conflict.
        with pytest.raises(ToolRowConflictError):
            store.admit_tool_with_record(
                make_record(), make_row(), expected=ToolReadResult(tool=None)
            )
        assert store.list_records(SERVER_ID, TOOL_NAME) == []  # record NOT appended

    def test_stale_revet_baseline_cancels_record_write(self):
        store = MemoryToolRegistry()
        store.admit_tool(make_row())
        stale = store.get_tool(SERVER_ID, TOOL_NAME)
        # The row changes underfoot after the guarded re-read...
        store.admit_tool(
            make_row(make_tool_def("changed underfoot")),
            expected=store.get_tool(SERVER_ID, TOOL_NAME),
        )
        # ...so a write conditioned on the stale baseline must cancel whole.
        with pytest.raises(ToolRowConflictError):
            store.admit_tool_with_record(
                make_record(ts="2026-07-24T13:00:00+00:00"),
                make_row(make_tool_def("revet")),
                expected=stale,
            )
        assert store.list_records(SERVER_ID, TOOL_NAME) == []

    def test_quarantined_row_writes_nothing(self):
        store = MemoryToolRegistry()
        store.admit_tool(make_row())
        # Tamper the stored data STRING (#246: rows are item-shaped).
        item = store._rows[(SERVER_ID, TOOL_NAME)]
        item["data"] = item["data"].replace("return a quote", "tampered")
        with pytest.raises(QuarantinedToolRowError):
            store.admit_tool_with_record(make_record(), make_row())
        assert store.list_records(SERVER_ID, TOOL_NAME) == []


# ===========================================================================
# DynamoDB backend (moto) — the real store methods, real expressions,
# real transaction semantics.
# ===========================================================================

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

moto = pytest.importorskip("moto", reason="moto is required for real-DynamoDB store tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for real-DynamoDB store tests")

from moto import mock_aws  # noqa: E402

from safe_agents.broker.mcp.registry import DynamoToolRegistry  # noqa: E402

REGION = "us-east-1"
TABLE = "safe-agents-mcp-registry-test"
HMAC_KEY = b"test-hmac-key"


@pytest.fixture
def dynamo_store():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.Table(TABLE).wait_until_exists()
        yield DynamoToolRegistry(hmac_key=HMAC_KEY, table_name=TABLE)


def _raw_item(pk: str, sk: str) -> dict | None:
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    return table.get_item(Key={"pk": pk, "sk": sk}).get("Item")


def _record_item() -> dict | None:
    return _raw_item(f"TOOLREC#{SERVER_ID}#{TOOL_NAME}", TS)


def _row_item() -> dict | None:
    return _raw_item(f"TOOLDEF#{SERVER_ID}#{TOOL_NAME}", "ROW")


class TestDynamoAtomicAdmit:
    def test_happy_path_writes_row_and_record(self, dynamo_store):
        dynamo_store.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        read = dynamo_store.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool is not None and not read.quarantined
        assert [r.ts for r in dynamo_store.list_records(SERVER_ID, TOOL_NAME)] == [TS]
        assert _record_item()["signature"] is not None

    def test_happy_revet_appends_second_record_and_updates_row(self, dynamo_store):
        dynamo_store.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        baseline = dynamo_store.get_tool(SERVER_ID, TOOL_NAME)
        new_def = make_tool_def("re-vetted description")
        ts2 = "2026-07-24T13:00:00+00:00"
        dynamo_store.admit_tool_with_record(
            make_record(new_def, ts=ts2), make_row(new_def), expected=baseline
        )
        read = dynamo_store.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool.def_hash == compute_tool_def_hash(new_def)
        assert not read.quarantined  # fresh HMAC stamped by the transact path
        assert [r.ts for r in dynamo_store.list_records(SERVER_ID, TOOL_NAME)] == [TS, ts2]

    def test_record_exists_cancels_row_write(self, dynamo_store):
        dynamo_store.put_record(make_record())
        with pytest.raises(RecordAlreadyExistsError):
            dynamo_store.admit_tool_with_record(make_record(), make_row())
        assert _row_item() is None  # the row leg was canceled with the record leg

    def test_row_conflict_cancels_record_write(self, dynamo_store):
        dynamo_store.admit_tool(make_row())
        with pytest.raises(ToolRowConflictError):
            # `expected` (implicit re-read) is taken BEFORE the concurrent row in
            # real races; simulate by passing a first-admission baseline.
            from safe_agents.broker.mcp.registry import ToolReadResult

            dynamo_store.admit_tool_with_record(
                make_record(), make_row(), expected=ToolReadResult(tool=None)
            )
        assert _record_item() is None  # the record leg was canceled with the row leg

    def test_both_legs_fail_maps_to_row_conflict(self, dynamo_store):
        from safe_agents.broker.mcp.registry import ToolReadResult

        dynamo_store.admit_tool(make_row())
        dynamo_store.put_record(make_record())
        with pytest.raises(ToolRowConflictError):
            dynamo_store.admit_tool_with_record(
                make_record(), make_row(), expected=ToolReadResult(tool=None)
            )

    def test_stale_revet_baseline_cancels_record_write(self, dynamo_store):
        dynamo_store.admit_tool(make_row())
        stale = dynamo_store.get_tool(SERVER_ID, TOOL_NAME)
        dynamo_store.admit_tool(
            make_row(make_tool_def("changed underfoot")),
            expected=dynamo_store.get_tool(SERVER_ID, TOOL_NAME),
        )
        ts2 = "2026-07-24T13:00:00+00:00"
        with pytest.raises(ToolRowConflictError):
            dynamo_store.admit_tool_with_record(
                make_record(ts=ts2), make_row(make_tool_def("revet")), expected=stale
            )
        assert _raw_item(f"TOOLREC#{SERVER_ID}#{TOOL_NAME}", ts2) is None

    def test_quarantined_row_writes_nothing(self, dynamo_store):
        dynamo_store.admit_tool(make_row())
        # Tamper the stored bytes out-of-band -> HMAC quarantine on read (M6).
        table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
        item = _row_item()
        tampered = item["data"].replace("return a quote", "tampered description")
        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #data = :d",
            ExpressionAttributeNames={"#data": "data"},
            ExpressionAttributeValues={":d": tampered},
        )
        with pytest.raises(QuarantinedToolRowError):
            dynamo_store.admit_tool_with_record(make_record(), make_row())
        assert _record_item() is None
