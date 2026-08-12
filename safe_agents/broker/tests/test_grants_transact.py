"""write_record_and_grant — the atomic record+grant write (#244).

The grants mirror of ``admit_tool_with_record``: either BOTH legs commit or
NOTHING is written, closing the record-without-grant (and grant-without-
record) artifact structurally at every ceremony write-pair site. Failure
injection runs on BOTH backends — InMemoryGrantStore (check-then-commit) and
the real DynamoDBGrantStore against moto's DynamoDB, whose expression
evaluator enforces ``TransactWriteItems`` conditions and atomicity for real
(the lesson from the MCP twin: a failing leg raises
``TransactionCanceledException`` with per-item ``CancellationReasons`` and
the passing leg is NOT written). The memory tests carry no AWS dependency;
the moto half importorskips like test_dynamo_stores.py.

Covered, per backend:
- happy path CREATE: grant AND record both present after one call (signature
  stored beside the record when supplied).
- happy path UPDATE: conditional grant leg from the guarded re-read.
- record leg fails (append-only violation) -> RecordAlreadyExistsError, grant
  NOT written.
- grant leg fails (create collision) -> GrantAlreadyExistsError, record NOT
  appended.
- grant leg fails (stale update baseline) -> GrantUpdateConflictError, record
  NOT appended.
- non-canonical record ts -> RecordTimestampFormatError before any write.
- mismatched backend pairing -> TypeError, nothing written.
"""

from __future__ import annotations

import os

import pytest

from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.store import (
    GrantAlreadyExistsError,
    GrantUpdateConflictError,
    InMemoryGrantStore,
    RecordAlreadyExistsError,
    RecordTimestampFormatError,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal

PRINCIPAL = Principal(agentId="agent-tx", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
HMAC_KEY = b"test-hmac-key-transact"
TS = "2026-07-25T12:00:00+00:00"
SIGNATURE = {"payloadType": "application/vnd.test+json", "payload": "e30=", "signatures": []}


def make_grant(**overrides) -> Grant:
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256:env-001",
        promotedBy="alice",
        evidence="evidence-ref-001",
        ts="2026-07-25T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    return Grant(**defaults)


def make_record(**overrides) -> PromotionRecord:
    defaults = dict(
        recordType="bootstrap",
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=None,
        toLevel=AutonomyLevel.in_loop,
        evidence="seed",
        proposedBy="alice",
        ratifiedBy="alice",
        envelopeHash="sha256:env-001",
        ts=TS,
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


# ---------------------------------------------------------------------------
# Memory backend — check-then-commit
# ---------------------------------------------------------------------------


def _memory_pair() -> tuple[InMemoryGrantStore, InMemoryPromotionRecordStore]:
    return InMemoryGrantStore(hmac_key=HMAC_KEY), InMemoryPromotionRecordStore()


def test_memory_create_happy_path_writes_both():
    grant_store, record_store = _memory_pair()

    grant_store.write_record_and_grant(
        make_record(), make_grant(), record_store, None, signature=SIGNATURE
    )

    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert read.grant is not None and not read.quarantined
    records = record_store.list_records(PRINCIPAL, ACTION_CLASS)
    assert [r.recordType for r in records] == ["bootstrap"]
    # the signature rides the same append
    stored_record, stored_sig = next(iter(record_store._records.values()))
    assert stored_sig == SIGNATURE


def test_memory_update_happy_path():
    grant_store, record_store = _memory_pair()
    grant_store.put_grant(make_grant())
    current = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)

    raised = make_grant(level=AutonomyLevel.on_loop, ts=TS)
    grant_store.write_record_and_grant(
        make_record(recordType="promotion", fromLevel=AutonomyLevel.in_loop,
                    toLevel=AutonomyLevel.on_loop, predicate="passed",
                    ratifiedBy="checker-bob"),
        raised,
        record_store,
        None,
        expected=current,
    )

    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.on_loop
    assert len(record_store.list_records(PRINCIPAL, ACTION_CLASS)) == 1


def test_memory_record_leg_failure_writes_nothing():
    grant_store, record_store = _memory_pair()
    record_store.put_record(make_record(), None)  # occupy the record key

    with pytest.raises(RecordAlreadyExistsError):
        grant_store.write_record_and_grant(make_record(), make_grant(), record_store, None)

    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None


def test_memory_create_collision_writes_nothing():
    grant_store, record_store = _memory_pair()
    grant_store.put_grant(make_grant())

    with pytest.raises(GrantAlreadyExistsError):
        grant_store.write_record_and_grant(
            make_record(), make_grant(ownerId="bob"), record_store, None, expected=None
        )

    assert record_store.list_records(PRINCIPAL, ACTION_CLASS) == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "alice"


def test_memory_stale_update_baseline_writes_nothing():
    grant_store, record_store = _memory_pair()
    grant_store.put_grant(make_grant())
    current = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)

    # concurrent modification after the guarded re-read
    grant_store.put_grant(make_grant(ownerId="mallory"))

    with pytest.raises(GrantUpdateConflictError):
        grant_store.write_record_and_grant(
            make_record(), make_grant(level=AutonomyLevel.on_loop), record_store, None,
            expected=current,
        )

    assert record_store.list_records(PRINCIPAL, ACTION_CLASS) == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "mallory"


def test_memory_non_canonical_ts_refused_before_any_write():
    grant_store, record_store = _memory_pair()

    with pytest.raises(RecordTimestampFormatError):
        grant_store.write_record_and_grant(
            make_record(ts="2026-07-25T12:00:00Z"), make_grant(), record_store, None
        )

    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
    assert record_store._records == {}


def test_memory_mismatched_backend_pairing_refused():
    grant_store, _ = _memory_pair()

    class _NotARecordStore:
        pass

    with pytest.raises(TypeError, match="InMemoryPromotionRecordStore"):
        grant_store.write_record_and_grant(
            make_record(), make_grant(), _NotARecordStore(), None
        )
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None


# ---------------------------------------------------------------------------
# DynamoDB backend (moto) — the real transact, real expressions, real atomicity
# ---------------------------------------------------------------------------

moto = pytest.importorskip("moto", reason="moto is required for real-DynamoDB store tests")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from safe_agents.broker.grants.store import (  # noqa: E402
    DynamoDBGrantStore,
    DynamoDBPromotionRecordStore,
)

REGION = "us-east-1"
TABLE = "grants-transact-test"


@pytest.fixture
def dynamo_pair():
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
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
        yield (
            DynamoDBGrantStore(hmac_key=HMAC_KEY, table_name=TABLE),
            DynamoDBPromotionRecordStore(table_name=TABLE),
        )


def _record_count(record_store) -> int:
    return len(record_store.list_records(PRINCIPAL, ACTION_CLASS, boto3.Session()))


def test_dynamo_create_happy_path_writes_both(dynamo_pair):
    grant_store, record_store = dynamo_pair

    grant_store.write_record_and_grant(
        make_record(), make_grant(), record_store, boto3.Session(), signature=SIGNATURE
    )

    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert read.grant is not None and not read.quarantined
    assert _record_count(record_store) == 1
    # the signature landed on the record item
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    items = table.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={
            ":pk": f"RECORD#{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}#{ACTION_CLASS}"
        },
    )["Items"]
    assert len(items) == 1 and "signature" in items[0]


def test_dynamo_update_happy_path(dynamo_pair):
    grant_store, record_store = dynamo_pair
    grant_store.put_grant(make_grant(), boto3.Session())
    current = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)

    grant_store.write_record_and_grant(
        make_record(recordType="promotion", fromLevel=AutonomyLevel.in_loop,
                    toLevel=AutonomyLevel.on_loop, predicate="passed",
                    ratifiedBy="checker-bob"),
        make_grant(level=AutonomyLevel.on_loop, ts=TS),
        record_store,
        boto3.Session(),
        expected=current,
    )

    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.on_loop
    assert _record_count(record_store) == 1


def test_dynamo_record_leg_failure_writes_nothing(dynamo_pair):
    grant_store, record_store = dynamo_pair
    record_store.put_record(make_record(), boto3.Session())

    with pytest.raises(RecordAlreadyExistsError):
        grant_store.write_record_and_grant(
            make_record(), make_grant(), record_store, boto3.Session()
        )

    # the grant leg was canceled with it — the real atomicity proof
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None


def test_dynamo_create_collision_writes_nothing(dynamo_pair):
    grant_store, record_store = dynamo_pair
    grant_store.put_grant(make_grant(), boto3.Session())

    with pytest.raises(GrantAlreadyExistsError):
        grant_store.write_record_and_grant(
            make_record(), make_grant(ownerId="bob"), record_store, boto3.Session(),
            expected=None,
        )

    assert _record_count(record_store) == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "alice"


def test_dynamo_stale_update_baseline_writes_nothing(dynamo_pair):
    grant_store, record_store = dynamo_pair
    grant_store.put_grant(make_grant(), boto3.Session())
    current = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)

    grant_store.put_grant(make_grant(ownerId="mallory"), boto3.Session())

    with pytest.raises(GrantUpdateConflictError):
        grant_store.write_record_and_grant(
            make_record(), make_grant(level=AutonomyLevel.on_loop), record_store,
            boto3.Session(), expected=current,
        )

    assert _record_count(record_store) == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "mallory"


def test_dynamo_mismatched_backend_pairing_refused(dynamo_pair):
    grant_store, _ = dynamo_pair

    with pytest.raises(TypeError, match="DynamoDBPromotionRecordStore"):
        grant_store.write_record_and_grant(
            make_record(), make_grant(), InMemoryPromotionRecordStore(), boto3.Session()
        )
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None


def test_dynamo_table_mismatch_refused(dynamo_pair):
    grant_store, _ = dynamo_pair
    other = DynamoDBPromotionRecordStore(table_name="some-other-table")

    with pytest.raises(ValueError, match="SAME table"):
        grant_store.write_record_and_grant(
            make_record(), make_grant(), other, boto3.Session()
        )
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
