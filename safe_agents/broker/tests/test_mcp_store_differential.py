"""Differential store suite: ONE contract, THREE backends (product-wrapper Phase 1, work item 2).

Every registry + proposal conformance behavior, parametrized across
MemoryToolRegistry / SqliteToolRegistry / DynamoToolRegistry (moto) and their
proposal-store siblings — including the ``admit_tool_with_record`` failure-
injection set from test_mcp_registry_transact.py. If sqlite wants a Protocol
change memory doesn't need, the Protocol is wrong, not the impl; this suite is
where that shows up.

The DynamoDB-Local lesson (fakes that are too permissive hide real backend
behavior) points AT sqlite here: a single shared connection would hide
locking/visibility behavior, so the sqlite-specific proofs open REAL second
connections — durability across a process restart (write, close, fresh
connection, read) and cross-connection visibility (two live connections on one
WAL file: the gateway-daemon + ceremony-CLI shape).

Each backend harness also exposes OUT-OF-BAND tamper/raw-read helpers (poking
the dict / raw SQL / raw DynamoDB item) — tamper must bypass the store API by
definition, and nothing-was-written assertions must not trust the API under
test. The moto backend importorskips per-param, so the memory/sqlite rows run
AWS-free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from safe_agents.broker.mcp.proposals import (
    McpAdmissionProposal,
    MemoryAdmissionProposalStore,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    ProposalIntegrityError,
)
from safe_agents.broker.mcp.registry import (
    MemoryToolRegistry,
    QuarantinedToolRowError,
    RecordAlreadyExistsError,
    ToolReadResult,
    ToolRowConflictError,
)
from safe_agents.broker.mcp.signing import McpAdmissionRecord
from safe_agents.broker.mcp.sqlite_stores import (
    SqliteAdmissionProposalStore,
    SqliteToolRegistry,
)
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
TS2 = "2026-07-24T13:00:00+00:00"
SIGNATURE = {"payloadType": "application/vnd.test+json", "payload": "e30=", "signatures": []}
HMAC_KEY = b"test-hmac-key"
BASE_DESCRIPTION = "return a quote"


def make_tool_def(description: str = BASE_DESCRIPTION) -> McpToolDef:
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


def make_proposal(
    proposal_id: str = "prop-1", description: str = BASE_DESCRIPTION
) -> McpAdmissionProposal:
    tool_def = make_tool_def(description)
    return McpAdmissionProposal(
        proposal_id=proposal_id,
        expires_at="2027-01-01T00:00:00+00:00",
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        kind="admission",
        proposed_by=MAKER_ARN,
    )


# ===========================================================================
# Backend harnesses — the store pair under test + out-of-band tamper/raw reads
# ===========================================================================


class MemoryBackend:
    name = "memory"
    supports_record_signature = True

    def __init__(self) -> None:
        self.registry = MemoryToolRegistry(hmac_key=HMAC_KEY)
        self.proposals = MemoryAdmissionProposalStore(hmac_key=HMAC_KEY)

    def tamper_row(self, server_id: str, tool_name: str) -> None:
        # #246: rows are item-shaped ({"data": str, "rowHash": str}); tamper
        # the stored data STRING, like the other backends.
        item = self.registry._rows[(server_id, tool_name)]
        item["data"] = item["data"].replace(BASE_DESCRIPTION, "tampered")

    def tamper_proposal(self, server_id: str, tool_name: str, proposal_id: str) -> None:
        item = self.proposals._items[(server_id, tool_name, proposal_id)]
        item["data"] = item["data"].replace(BASE_DESCRIPTION, "tampered")

    def raw_row_exists(self, server_id: str, tool_name: str) -> bool:
        return (server_id, tool_name) in self.registry._rows

    def raw_record_exists(self, server_id: str, tool_name: str, ts: str) -> bool:
        return (server_id, tool_name, ts) in self.registry._records

    def raw_record_data(self, server_id: str, tool_name: str, ts: str) -> str:
        return self.registry._records[(server_id, tool_name, ts)]["data"]


class SqliteBackend:
    name = "sqlite"
    supports_record_signature = True

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.registry = SqliteToolRegistry(HMAC_KEY, db_path)
        self.proposals = SqliteAdmissionProposalStore(HMAC_KEY, db_path)

    def _raw_conn(self):
        # A REAL second connection, deliberately: out-of-band tamper and raw
        # reads must not ride the store's own handle, or a single-connection
        # implementation could hide visibility bugs (the too-permissive-fake
        # lesson pointed at sqlite).
        import sqlite3

        return sqlite3.connect(str(self.db_path))

    def _rewrite_item(self, pk: str, sk: str, mutate) -> None:
        with self._raw_conn() as conn:
            (item,) = conn.execute(
                "SELECT item FROM items WHERE pk = ? AND sk = ?", (pk, sk)
            ).fetchone()
            attrs = json.loads(item)
            mutate(attrs)
            conn.execute(
                "UPDATE items SET item = ? WHERE pk = ? AND sk = ?",
                (json.dumps(attrs, sort_keys=True, ensure_ascii=True), pk, sk),
            )

    def tamper_row(self, server_id: str, tool_name: str) -> None:
        def mutate(attrs):
            attrs["data"] = attrs["data"].replace(BASE_DESCRIPTION, "tampered")

        self._rewrite_item(f"TOOLDEF#{server_id}#{tool_name}", "ROW", mutate)

    def tamper_proposal(self, server_id: str, tool_name: str, proposal_id: str) -> None:
        def mutate(attrs):
            attrs["data"] = attrs["data"].replace(BASE_DESCRIPTION, "tampered")

        self._rewrite_item(f"TOOLPROP#{server_id}#{tool_name}", proposal_id, mutate)

    def _raw_exists(self, pk: str, sk: str) -> bool:
        with self._raw_conn() as conn:
            return (
                conn.execute(
                    "SELECT 1 FROM items WHERE pk = ? AND sk = ?", (pk, sk)
                ).fetchone()
                is not None
            )

    def raw_row_exists(self, server_id: str, tool_name: str) -> bool:
        return self._raw_exists(f"TOOLDEF#{server_id}#{tool_name}", "ROW")

    def raw_record_exists(self, server_id: str, tool_name: str, ts: str) -> bool:
        return self._raw_exists(f"TOOLREC#{server_id}#{tool_name}", ts)

    def raw_record_data(self, server_id: str, tool_name: str, ts: str) -> str:
        with self._raw_conn() as conn:
            (item,) = conn.execute(
                "SELECT item FROM items WHERE pk = ? AND sk = ?",
                (f"TOOLREC#{server_id}#{tool_name}", ts),
            ).fetchone()
        return json.loads(item)["data"]


class DynamoBackend:
    name = "dynamo"
    supports_record_signature = False  # DynamoToolRegistry has no get_record_signature

    REGION = "us-east-1"
    TABLE = "safe-agents-mcp-registry-differential"

    def __init__(self, boto3_module, registry, proposals) -> None:
        self._boto3 = boto3_module
        self.registry = registry
        self.proposals = proposals

    def _table(self):
        return self._boto3.resource("dynamodb", region_name=self.REGION).Table(self.TABLE)

    def _rewrite_data(self, key: dict) -> None:
        item = self._table().get_item(Key=key)["Item"]
        tampered = item["data"].replace(BASE_DESCRIPTION, "tampered")
        self._table().update_item(
            Key=key,
            UpdateExpression="SET #data = :d",
            ExpressionAttributeNames={"#data": "data"},
            ExpressionAttributeValues={":d": tampered},
        )

    def tamper_row(self, server_id: str, tool_name: str) -> None:
        self._rewrite_data({"pk": f"TOOLDEF#{server_id}#{tool_name}", "sk": "ROW"})

    def tamper_proposal(self, server_id: str, tool_name: str, proposal_id: str) -> None:
        self._rewrite_data({"pk": f"TOOLPROP#{server_id}#{tool_name}", "sk": proposal_id})

    def _raw_exists(self, pk: str, sk: str) -> bool:
        return "Item" in self._table().get_item(Key={"pk": pk, "sk": sk})

    def raw_row_exists(self, server_id: str, tool_name: str) -> bool:
        return self._raw_exists(f"TOOLDEF#{server_id}#{tool_name}", "ROW")

    def raw_record_exists(self, server_id: str, tool_name: str, ts: str) -> bool:
        return self._raw_exists(f"TOOLREC#{server_id}#{tool_name}", ts)

    def raw_record_data(self, server_id: str, tool_name: str, ts: str) -> str:
        key = {"pk": f"TOOLREC#{server_id}#{tool_name}", "sk": ts}
        return self._table().get_item(Key=key)["Item"]["data"]


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def backend(request, tmp_path):
    if request.param == "memory":
        yield MemoryBackend()
        return
    if request.param == "sqlite":
        yield SqliteBackend(tmp_path / "broker.db")
        return
    pytest.importorskip("moto", reason="moto is required for the dynamo differential row")
    boto3 = pytest.importorskip("boto3", reason="boto3 is required for the dynamo differential row")
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    ):
        os.environ.setdefault(var, "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    from moto import mock_aws

    from safe_agents.broker.mcp.proposals import DynamoAdmissionProposalStore
    from safe_agents.broker.mcp.registry import DynamoToolRegistry

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=DynamoBackend.REGION)
        ddb.create_table(
            TableName=DynamoBackend.TABLE,
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
        ddb.Table(DynamoBackend.TABLE).wait_until_exists()
        yield DynamoBackend(
            boto3,
            DynamoToolRegistry(hmac_key=HMAC_KEY, table_name=DynamoBackend.TABLE),
            DynamoAdmissionProposalStore(hmac_key=HMAC_KEY, table_name=DynamoBackend.TABLE),
        )


# ===========================================================================
# Registry conformance — every backend
# ===========================================================================


class TestRegistryConformance:
    def test_admit_tool_round_trip_unquarantined(self, backend):
        backend.registry.admit_tool(make_row())
        read = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool is not None and not read.quarantined
        assert read.tool.def_hash == compute_tool_def_hash(make_tool_def())

    def test_tampered_row_quarantines_on_read(self, backend):
        backend.registry.admit_tool(make_row())
        backend.tamper_row(SERVER_ID, TOOL_NAME)
        read = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        assert read.quarantined and "hash mismatch" in read.quarantine_reason

    def test_write_over_quarantined_row_refused(self, backend):
        backend.registry.admit_tool(make_row())
        backend.tamper_row(SERVER_ID, TOOL_NAME)
        with pytest.raises(QuarantinedToolRowError):
            backend.registry.admit_tool(make_row())

    def test_admit_refuses_stale_expected_state(self, backend):
        backend.registry.admit_tool(make_row())
        stale = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        backend.registry.admit_tool(
            make_row(make_tool_def("changed underfoot")),
            expected=backend.registry.get_tool(SERVER_ID, TOOL_NAME),
        )
        with pytest.raises(ToolRowConflictError):
            backend.registry.admit_tool(make_row(make_tool_def("revet")), expected=stale)

    def test_revet_with_correct_expected_succeeds(self, backend):
        backend.registry.admit_tool(make_row())
        baseline = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        new_def = make_tool_def("re-vetted")
        backend.registry.admit_tool(make_row(new_def), expected=baseline)
        read = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        assert not read.quarantined
        assert read.tool.def_hash == compute_tool_def_hash(new_def)

    def test_first_admission_refuses_concurrent_create(self, backend):
        backend.registry.admit_tool(make_row())
        with pytest.raises(ToolRowConflictError):
            backend.registry.admit_tool(make_row(), expected=ToolReadResult(tool=None))

    def test_record_ledger_is_append_only(self, backend):
        backend.registry.put_record(make_record())
        with pytest.raises(RecordAlreadyExistsError):
            backend.registry.put_record(make_record())

    def test_list_records_ordered_by_ts(self, backend):
        backend.registry.put_record(make_record(ts=TS2))
        backend.registry.put_record(make_record(ts=TS))
        assert [r.ts for r in backend.registry.list_records(SERVER_ID, TOOL_NAME)] == [TS, TS2]

    def test_record_signature_round_trip(self, backend):
        if not backend.supports_record_signature:
            pytest.skip(f"{backend.name} store does not expose get_record_signature")
        backend.registry.put_record(make_record(), signature=SIGNATURE)
        assert backend.registry.get_record_signature(SERVER_ID, TOOL_NAME, TS) == SIGNATURE
        backend.registry.put_record(make_record(ts=TS2))
        assert backend.registry.get_record_signature(SERVER_ID, TOOL_NAME, TS2) is None


# ===========================================================================
# admit_tool_with_record — the failure-injection set, every backend
# ===========================================================================


class TestAtomicAdmitDifferential:
    def test_happy_path_writes_row_and_record(self, backend):
        backend.registry.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        read = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool is not None and not read.quarantined
        assert [r.ts for r in backend.registry.list_records(SERVER_ID, TOOL_NAME)] == [TS]

    def test_happy_revet_appends_second_record_and_updates_row(self, backend):
        backend.registry.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        baseline = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        new_def = make_tool_def("re-vetted description")
        backend.registry.admit_tool_with_record(
            make_record(new_def, ts=TS2), make_row(new_def), expected=baseline
        )
        read = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool.def_hash == compute_tool_def_hash(new_def)
        assert not read.quarantined
        assert [r.ts for r in backend.registry.list_records(SERVER_ID, TOOL_NAME)] == [TS, TS2]

    def test_record_exists_cancels_row_write(self, backend):
        backend.registry.put_record(make_record())
        with pytest.raises(RecordAlreadyExistsError):
            backend.registry.admit_tool_with_record(make_record(), make_row())
        assert not backend.raw_row_exists(SERVER_ID, TOOL_NAME)

    def test_row_conflict_cancels_record_write(self, backend):
        backend.registry.admit_tool(make_row())
        with pytest.raises(ToolRowConflictError):
            backend.registry.admit_tool_with_record(
                make_record(), make_row(), expected=ToolReadResult(tool=None)
            )
        assert not backend.raw_record_exists(SERVER_ID, TOOL_NAME, TS)

    def test_stale_revet_baseline_cancels_record_write(self, backend):
        backend.registry.admit_tool(make_row())
        stale = backend.registry.get_tool(SERVER_ID, TOOL_NAME)
        backend.registry.admit_tool(
            make_row(make_tool_def("changed underfoot")),
            expected=backend.registry.get_tool(SERVER_ID, TOOL_NAME),
        )
        with pytest.raises(ToolRowConflictError):
            backend.registry.admit_tool_with_record(
                make_record(ts=TS2), make_row(make_tool_def("revet")), expected=stale
            )
        assert not backend.raw_record_exists(SERVER_ID, TOOL_NAME, TS2)

    def test_quarantined_row_writes_nothing(self, backend):
        backend.registry.admit_tool(make_row())
        backend.tamper_row(SERVER_ID, TOOL_NAME)
        with pytest.raises(QuarantinedToolRowError):
            backend.registry.admit_tool_with_record(make_record(), make_row())
        assert not backend.raw_record_exists(SERVER_ID, TOOL_NAME, TS)

    def test_both_legs_fail_maps_to_row_conflict(self, backend):
        backend.registry.admit_tool(make_row())
        backend.registry.put_record(make_record())
        with pytest.raises(ToolRowConflictError):
            backend.registry.admit_tool_with_record(
                make_record(), make_row(), expected=ToolReadResult(tool=None)
            )


# ===========================================================================
# Proposal-store conformance — every backend
# ===========================================================================


class TestProposalConformance:
    def test_put_get_round_trip_pending(self, backend):
        proposal = make_proposal()
        backend.proposals.put_proposal(proposal)
        got, status = backend.proposals.get_proposal(SERVER_ID, TOOL_NAME, "prop-1")
        assert status == "pending"
        assert got == proposal

    def test_get_absent_returns_none(self, backend):
        assert backend.proposals.get_proposal(SERVER_ID, TOOL_NAME, "nope") is None

    def test_duplicate_put_refused(self, backend):
        backend.proposals.put_proposal(make_proposal())
        with pytest.raises(ProposalAlreadyExistsError):
            backend.proposals.put_proposal(make_proposal())

    def test_tampered_proposal_refused_on_get(self, backend):
        backend.proposals.put_proposal(make_proposal())
        backend.tamper_proposal(SERVER_ID, TOOL_NAME, "prop-1")
        with pytest.raises(ProposalIntegrityError):
            backend.proposals.get_proposal(SERVER_ID, TOOL_NAME, "prop-1")

    def test_tamper_cannot_hide_behind_status_flip_in_list_pending(self, backend):
        backend.proposals.put_proposal(make_proposal("prop-1"))
        backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "ratified")
        backend.proposals.put_proposal(make_proposal("prop-2", description="other tool desc"))
        backend.tamper_proposal(SERVER_ID, TOOL_NAME, "prop-1")
        with pytest.raises(ProposalIntegrityError):
            backend.proposals.list_pending(SERVER_ID, TOOL_NAME)

    def test_consume_flips_pending_once(self, backend):
        backend.proposals.put_proposal(make_proposal())
        backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "ratified")
        _, status = backend.proposals.get_proposal(SERVER_ID, TOOL_NAME, "prop-1")
        assert status == "ratified"
        assert backend.proposals.list_pending(SERVER_ID, TOOL_NAME) == []
        with pytest.raises(ProposalConsumedError):
            backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "rejected")

    def test_consume_absent_refused(self, backend):
        with pytest.raises(ProposalConsumedError):
            backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "nope", "ratified")

    def test_consume_invalid_status_refused(self, backend):
        backend.proposals.put_proposal(make_proposal())
        with pytest.raises(ValueError, match="pending"):
            backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "approved")

    def test_list_pending_filters_status(self, backend):
        backend.proposals.put_proposal(make_proposal("prop-1"))
        backend.proposals.put_proposal(make_proposal("prop-2"))
        backend.proposals.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "rejected")
        pending = backend.proposals.list_pending(SERVER_ID, TOOL_NAME)
        assert [p.proposal_id for p, _ in pending] == ["prop-2"]


# ===========================================================================
# SQLite-only proofs: durability + cross-connection visibility (real second
# connections — the gateway-daemon + ceremony-CLI shape)
# ===========================================================================


class TestSqliteDurability:
    def test_rows_and_records_survive_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteToolRegistry(HMAC_KEY, db)
        first.admit_tool_with_record(make_record(), make_row(), signature=SIGNATURE)
        first.close()

        fresh = SqliteToolRegistry(HMAC_KEY, db)
        read = fresh.get_tool(SERVER_ID, TOOL_NAME)
        assert read.tool is not None and not read.quarantined
        assert [r.ts for r in fresh.list_records(SERVER_ID, TOOL_NAME)] == [TS]
        assert fresh.get_record_signature(SERVER_ID, TOOL_NAME, TS) == SIGNATURE

    def test_proposals_survive_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteAdmissionProposalStore(HMAC_KEY, db)
        first.put_proposal(make_proposal())
        first.close()

        fresh = SqliteAdmissionProposalStore(HMAC_KEY, db)
        got, status = fresh.get_proposal(SERVER_ID, TOOL_NAME, "prop-1")
        assert status == "pending" and got == make_proposal()

    def test_rolled_back_transaction_survives_nothing(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteToolRegistry(HMAC_KEY, db)
        first.put_record(make_record())  # occupy the record key → atomic op cancels
        with pytest.raises(RecordAlreadyExistsError):
            first.admit_tool_with_record(make_record(), make_row())
        first.close()

        fresh = SqliteToolRegistry(HMAC_KEY, db)
        assert fresh.get_tool(SERVER_ID, TOOL_NAME).tool is None


class TestSqliteCrossConnectionVisibility:
    def test_write_on_one_connection_reads_on_another(self, tmp_path):
        db = tmp_path / "broker.db"
        writer = SqliteToolRegistry(HMAC_KEY, db)
        reader = SqliteToolRegistry(HMAC_KEY, db)
        assert reader.get_tool(SERVER_ID, TOOL_NAME).tool is None  # both connections live
        writer.admit_tool_with_record(make_record(), make_row())
        read = reader.get_tool(SERVER_ID, TOOL_NAME)  # NO reopen — WAL visibility
        assert read.tool is not None and not read.quarantined
        assert [r.ts for r in reader.list_records(SERVER_ID, TOOL_NAME)] == [TS]

    def test_proposal_consume_visible_across_connections(self, tmp_path):
        db = tmp_path / "broker.db"
        cli = SqliteAdmissionProposalStore(HMAC_KEY, db)
        daemon = SqliteAdmissionProposalStore(HMAC_KEY, db)
        cli.put_proposal(make_proposal())
        assert [p.proposal_id for p, _ in daemon.list_pending(SERVER_ID, TOOL_NAME)] == ["prop-1"]
        cli.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "ratified")
        assert daemon.list_pending(SERVER_ID, TOOL_NAME) == []
        with pytest.raises(ProposalConsumedError):
            daemon.consume_proposal(SERVER_ID, TOOL_NAME, "prop-1", "ratified")

    def test_concurrent_first_admission_conflicts_across_connections(self, tmp_path):
        db = tmp_path / "broker.db"
        a = SqliteToolRegistry(HMAC_KEY, db)
        b = SqliteToolRegistry(HMAC_KEY, db)
        # Both evaluated an empty coordinate; A wins the write, B's conditional
        # write must CONFLICT (not silently overwrite) — the #190 property
        # across two real connections.
        empty = ToolReadResult(tool=None)
        a.admit_tool(make_row(), expected=empty)
        with pytest.raises(ToolRowConflictError):
            b.admit_tool(make_row(make_tool_def("the other ceremony")), expected=empty)


# ===========================================================================
# The stored bytes ARE the signature's basis (#246), on EVERY backend
#
# Found live by the #226 no-AWS ceremony drill: the sqlite arm stored records
# via pydantic's model_dump_json (DECLARATION order) while the DSSE subject
# digest binds canonical_record_payload (SORTED keys), so every signed
# admission record written on that arm was unverifiable — the Dynamo arm had
# always written the canonical form.
#
# Why the existing suites missed it: they verify
# `verify_admission_record(canonical_record_payload(record), ...)` — a
# RE-SERIALIZATION of the parsed record, which is correct by construction no
# matter what the store actually wrote. Verifying a re-serialization cannot
# detect a store that writes different bytes; only reading the stored bytes
# back can. That is the whole point of #246's stored-bytes basis, so the pin
# reads them.
# ===========================================================================


class TestStoredRecordBytesAreCanonical:
    def test_stored_record_bytes_are_the_canonical_serialization(self, backend):
        from safe_agents.broker.mcp.signing import canonical_record_payload

        record = make_record()
        backend.registry.admit_tool_with_record(
            record, make_row(), signature=SIGNATURE, expected=ToolReadResult(tool=None)
        )
        stored = backend.raw_record_data(SERVER_ID, TOOL_NAME, TS)
        assert stored == canonical_record_payload(record), (
            f"{backend.name} stored a non-canonical serialization; the DSSE "
            "subject digest binds the canonical form, so this record could "
            "never verify against its own signature"
        )

    def test_a_signed_record_verifies_from_the_STORED_bytes(self, backend):
        """End-to-end over the real sign/verify pair, from what the store holds."""
        from safe_agents.broker.grants.record_signing import signer_from_pem
        from safe_agents.broker.mcp.signing import (
            sign_admission_record,
            verify_admission_record,
        )
        from safe_agents.channels.keys import key_resolver_from_map

        crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
        from cryptography.hazmat.primitives import serialization

        key = crypto.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        signer = signer_from_pem("issuer-1", "test", pem)

        record = make_record()
        envelope = sign_admission_record(record, signer)
        backend.registry.admit_tool_with_record(
            record, make_row(), signature=envelope, expected=ToolReadResult(tool=None)
        )

        stored = backend.raw_record_data(SERVER_ID, TOOL_NAME, TS)
        resolver = key_resolver_from_map({"issuer-1": public_pem})
        assert verify_admission_record(stored, envelope, resolver).ok

        # ...and a tampered byte still breaks it (the pin is not vacuous).
        assert not verify_admission_record(
            stored.replace(TOOL_NAME, "other_tool"), envelope, resolver
        ).ok

    def test_the_attestation_marker_rides_the_stored_bytes(self, backend):
        """#226: a solo-attested record's marker is inside the signed basis, so
        stripping it breaks the signature rather than quietly upgrading the
        record's apparent provenance."""
        from safe_agents.broker.mcp.signing import canonical_record_payload

        record = make_record().model_copy(update={"attestation": "solo-local"})
        backend.registry.admit_tool_with_record(
            record, make_row(), signature=SIGNATURE, expected=ToolReadResult(tool=None)
        )
        stored = backend.raw_record_data(SERVER_ID, TOOL_NAME, TS)
        assert '"attestation":"solo-local"' in stored
        assert stored == canonical_record_payload(record)
