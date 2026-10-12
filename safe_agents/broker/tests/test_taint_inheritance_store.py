"""PTC-51 (#177): the inheritance ledger's three stores and the build-time floor.

The store contract, run identically against all three implementations:

  - a record is read back by its target principal and by no other;
  - expiry is a predicate at use, so a record stops at its ``notAfter``;
  - writes are create-only;
  - a stored row that does not parse fails the read (the caller mints tainted).

DynamoDB runs under moto, and its read is checked to be a strongly consistent
Query on the target's partition, never a Scan. sqlite and DynamoDB key the rows
identically, so a row pump moves them verbatim.

The floor: a manifest that declares a cause op builds no runtime without an
inheritance store; the sqlite arm puts the ledger in the broker-writable
database and never in the grant space's own file; the DynamoDB arm puts it in
the grants table.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime import BrokerRuntime
from safe_agents.broker.schemas import AgentManifest, InheritanceRecord, Principal, Taint
from safe_agents.broker.taint import (
    DynamoInheritanceStore,
    InheritanceRecordExistsError,
    InheritanceStore,
    InheritanceStoreRequiredError,
    InMemoryInheritanceStore,
    build_trust_map,
)
from safe_agents.broker.taint.inheritance import record_pk, record_sk
from safe_agents.broker.taint.inheritance_sqlite import SqliteInheritanceStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, cause_op_for

OWN = Principal(agentId="parent-agent", skill="planner", user="owner", tier="B")
CHILD = Principal(agentId="child-agent", skill="worker", user="owner", tier="C")
OTHER = Principal(agentId="other-agent", skill="worker", user="owner", tier="C")
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
TABLE = "inheritance-test-grants"


def _record(rec_id: str, target: Principal, minutes: int, sources=("connector:search.query",)):
    return InheritanceRecord(
        id=rec_id,
        target=target,
        causingPrincipal=OWN,
        causingTurnId="turn:abc",
        taint=Taint(tainted=bool(sources), sources=list(sources)),
        tool="worker",
        op="launch",
        issuedAt=NOW.isoformat(),
        notAfter=(NOW + timedelta(minutes=minutes)).isoformat(),
    )


# ---------------------------------------------------------------------------
# One fixture, three backends
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _moto_table(monkeypatch):
    """A moto DynamoDB table keyed (pk, sk), as the grants table is."""
    pytest.importorskip("moto", reason="moto is required for the DynamoDB store")
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    for var, value in (
        ("AWS_ACCESS_KEY_ID", "testing"),
        ("AWS_SECRET_ACCESS_KEY", "testing"),
        ("AWS_SESSION_TOKEN", "testing"),
        ("AWS_DEFAULT_REGION", "us-east-1"),
    ):
        monkeypatch.setenv(var, value)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
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
        yield ddb.Table(TABLE)


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def backend(request, tmp_path, monkeypatch):
    """(store, inject_raw) where inject_raw(pk, sk, data) writes a row past the store."""
    if request.param == "memory":
        store = InMemoryInheritanceStore()

        def inject(pk, sk, data):
            store._rows.setdefault(pk, {})[sk] = data

        yield store, inject
    elif request.param == "sqlite":
        store = SqliteInheritanceStore(tmp_path / "broker.db")

        def inject(pk, sk, data):
            conn = store._connection()
            with substrate.transaction(conn):
                substrate.put_new_item(conn, pk, sk, {"data": data})

        yield store, inject
    else:
        with _moto_table(monkeypatch) as table:

            def inject(pk, sk, data):
                table.put_item(Item={"pk": pk, "sk": sk, "data": data})

            yield DynamoInheritanceStore(TABLE), inject


def test_every_backend_fills_the_protocol(backend) -> None:
    store, _inject = backend
    assert isinstance(store, InheritanceStore)


def test_records_are_read_back_by_their_target_and_no_other(backend) -> None:
    store, _inject = backend
    later = _record("rec-later", CHILD, minutes=90)
    sooner = _record("rec-sooner", CHILD, minutes=30, sources=("harness:x/web-fetch/remote",))
    store.put_record(later)
    store.put_record(sooner)
    store.put_record(_record("rec-other", OTHER, minutes=60))
    assert store.live_records(CHILD, NOW) == [sooner, later]
    assert [r.id for r in store.live_records(OTHER, NOW)] == ["rec-other"]
    assert store.live_records(OWN, NOW) == []


def test_a_record_stops_tainting_at_its_not_after(backend) -> None:
    store, _inject = backend
    store.put_record(_record("rec-30", CHILD, minutes=30))
    store.put_record(_record("rec-90", CHILD, minutes=90))
    assert [r.id for r in store.live_records(CHILD, NOW + timedelta(minutes=29))] == [
        "rec-30",
        "rec-90",
    ]
    assert [r.id for r in store.live_records(CHILD, NOW + timedelta(minutes=30))] == ["rec-90"]
    assert store.live_records(CHILD, NOW + timedelta(minutes=90)) == []


def test_a_write_is_create_only(backend) -> None:
    store, _inject = backend
    record = _record("rec-1", CHILD, minutes=30)
    store.put_record(record)
    with pytest.raises(InheritanceRecordExistsError):
        store.put_record(record)
    assert store.live_records(CHILD, NOW) == [record]


def test_a_stored_row_that_does_not_parse_fails_the_read(backend) -> None:
    store, inject = backend
    record = _record("rec-1", CHILD, minutes=30)
    inject(record_pk(CHILD), record_sk(record), '{"not": "a record"}')
    with pytest.raises(ValueError):
        store.live_records(CHILD, NOW)


def test_rows_are_keyed_the_same_on_every_backend() -> None:
    record = _record("rec-1", CHILD, minutes=30)
    assert record_pk(CHILD) == "INHERIT#child-agent#worker#owner#C"
    assert record_sk(record) == "2026-10-12T12:30:00.000000Z#rec-1"


def test_the_sqlite_row_carries_the_shared_key_and_the_record_json(tmp_path) -> None:
    db = tmp_path / "broker.db"
    record = _record("rec-1", CHILD, minutes=30)
    SqliteInheritanceStore(db).put_record(record)
    pk, sk, item = sqlite3.connect(db).execute("SELECT pk, sk, item FROM items").fetchone()
    assert (pk, sk) == (record_pk(CHILD), record_sk(record))
    assert InheritanceRecord.model_validate_json(json.loads(item)["data"]) == record


class _RecordingTable:
    """A table proxy that records which methods a store called, and with what."""

    def __init__(self, table) -> None:
        self._table = table
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name):
        method = getattr(self._table, name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            return method(**kwargs)

        return call


def test_the_dynamo_store_writes_with_a_conditional_update_and_reads_by_query(
    monkeypatch,
) -> None:
    with _moto_table(monkeypatch):
        store = DynamoInheritanceStore(TABLE)
        _assert_update_then_query(store)


def _assert_update_then_query(store: DynamoInheritanceStore) -> None:
    proxy = _RecordingTable(store._table)
    store._DynamoInheritanceStore__table = proxy
    store.put_record(_record("rec-1", CHILD, minutes=30))
    store.live_records(CHILD, NOW)
    methods = [m for m, _ in proxy.calls]
    assert methods == ["update_item", "query"]  # no put_item, no scan
    update = proxy.calls[0][1]
    assert update["Key"]["pk"].startswith("INHERIT#")
    assert update["ConditionExpression"] == "attribute_not_exists(pk)"
    assert proxy.calls[1][1]["ConsistentRead"] is True


# ---------------------------------------------------------------------------
# The floor: no cause op runs without a store
# ---------------------------------------------------------------------------

_ENV_VARS = (
    "BROKER_STORE",
    "BROKER_SQLITE_PATH",
    "BROKER_SQLITE_GRANTS_PATH",
    "BROKER_SQLITE_GRANTS_READONLY",
    "BROKER_MANIFEST",
    "BROKER_HMAC_KEY",
    "BROKER_GRANT_CLASSES",
    "BROKER_GRANT_LOAD",
    "BROKER_SKIP_GRANT_LOAD",
    "BROKER_ENVELOPE_LOAD",
    "BROKER_AUDIT_BUCKET",
    "BROKER_AUDIT_PATH",
    "BROKER_SECRETS",
    "BROKER_SECRETS_FILE",
    "BROKER_SECRETS_DIR",
    "BROKER_TABLE",
    "BROKER_GRANTS_TABLE",
    "BROKER_COUNTERS_TABLE",
    "BROKER_INTENTS_TABLE",
)


@pytest.fixture
def clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    if "_MANIFEST" in vars(broker_server):
        monkeypatch.delattr(broker_server, "_MANIFEST")
    return monkeypatch


def _manifest(declare: bool) -> AgentManifest:
    ops = [{"tool": "search", "op": "query", "effect": "read", "external": True}]
    if declare:
        ops.append(cause_op_for(CHILD, tool="worker", op="launch").model_dump())
    return AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain"},
            "principal": OWN.model_dump(),
            "grant_classes": ["search.query"],
            "connectors": ["search"],
            "tool_ops": ops,
        }
    )


def _name_durable_arm(monkeypatch, tmp_path: Path, arm: str) -> None:
    secrets = tmp_path / "secrets.json"
    secrets.write_text(json.dumps({"search": "cred-search"}), encoding="utf-8")
    monkeypatch.setenv("BROKER_STORE", arm)
    monkeypatch.setenv("BROKER_HMAC_KEY", "named-inheritance-test-key")
    monkeypatch.setenv("BROKER_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BROKER_SECRETS_FILE", str(secrets))
    monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")


def test_a_declared_cause_op_with_no_store_refuses_to_build(clean_env) -> None:
    with pytest.raises(InheritanceStoreRequiredError, match="worker.launch"):
        build_runtime(_manifest(declare=True))


def test_a_declared_cause_op_builds_with_an_injected_store(clean_env) -> None:
    store = InMemoryInheritanceStore()
    runtime, _sink = build_runtime(_manifest(declare=True), inheritance_store=store)
    assert runtime._inheritance_store is store


def test_no_declaration_on_the_memory_arm_builds_with_no_ledger(clean_env) -> None:
    runtime, _sink = build_runtime(_manifest(declare=False))
    assert runtime._inheritance_store is None


def test_the_runtime_itself_refuses_a_cause_op_without_a_store() -> None:
    table = ToolOpTable([cause_op_for(CHILD)])
    with pytest.raises(InheritanceStoreRequiredError, match="worker.launch"):
        BrokerRuntime(
            principal=OWN,
            grants=[],
            optable=table,
            doer=None,
            pip=None,
            enforcement_store=None,
            intent_store=None,
            audit_sink=None,
            trust_map=build_trust_map(trusted_prefixes=["internal:"]),
            envelope_hash=ENVELOPE_HASH,
        )


@pytest.mark.parametrize("declare", [True, False])
def test_the_sqlite_arm_keeps_the_ledger_in_the_broker_writable_file(
    clean_env, tmp_path, declare
) -> None:
    _name_durable_arm(clean_env, tmp_path, "sqlite")
    broker_db = tmp_path / "broker.db"
    grants_db = tmp_path / "grants.db"
    clean_env.setenv("BROKER_SQLITE_PATH", str(broker_db))
    clean_env.setenv("BROKER_SQLITE_GRANTS_PATH", str(grants_db))
    runtime, _sink = build_runtime(_manifest(declare=declare))
    store = runtime._inheritance_store
    # Built whether or not this manifest declares a cause op: a child reads its
    # ledger at every mint, and a child usually declares nothing.
    assert isinstance(store, SqliteInheritanceStore)
    assert store._db_path == broker_db
    store.put_record(_record("rec-1", CHILD, minutes=30))
    rows = sqlite3.connect(broker_db).execute(
        "SELECT pk FROM items WHERE pk LIKE 'INHERIT#%'"
    ).fetchall()
    assert rows == [(record_pk(CHILD),)]
    if grants_db.exists():
        assert sqlite3.connect(grants_db).execute(
            "SELECT count(*) FROM items WHERE pk LIKE 'INHERIT#%'"
        ).fetchone() == (0,)


@pytest.mark.parametrize("declare", [True, False])
def test_the_dynamo_arm_keeps_the_ledger_in_the_grants_table(clean_env, tmp_path, declare) -> None:
    _name_durable_arm(clean_env, tmp_path, "dynamo")
    clean_env.setenv("BROKER_GRANTS_TABLE", "the-grants-table")
    clean_env.setenv("BROKER_TABLE", "the-single-table")
    runtime, _sink = build_runtime(_manifest(declare=declare))
    store = runtime._inheritance_store
    assert isinstance(store, DynamoInheritanceStore)
    assert store._table_name == "the-grants-table"
