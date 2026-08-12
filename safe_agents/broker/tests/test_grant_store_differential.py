"""Differential grant-store suite: ONE contract, THREE backends (product-wrapper Phase 1).

Every grant-store + PromotionRecord-ledger conformance behavior, parametrized
across InMemoryGrantStore / SqliteGrantStore / DynamoDBGrantStore (moto) and
their record-store siblings — including the ``write_record_and_grant``
failure-injection set from test_grants_transact.py. If sqlite wants a Protocol
change memory doesn't need, the Protocol is wrong, not the impl; this suite is
where that shows up.

Each backend harness exposes OUT-OF-BAND tamper/raw-read helpers (poking the
dict / raw SQL on a REAL second connection / raw DynamoDB item) — tamper must
bypass the store API by definition, and nothing-was-written assertions must
not trust the API under test. The moto backend importorskips per-param, so
the memory/sqlite rows run AWS-free. Factories mirror test_grants_transact.py
(defined locally: that module's own top-level ``importorskip("moto")`` makes
it unimportable on an AWS-free box).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.sqlite_store import (
    SqliteGrantStore,
    SqlitePromotionRecordStore,
)
from safe_agents.broker.grants.store import (
    GrantAlreadyExistsError,
    GrantUpdateConflictError,
    InMemoryGrantStore,
    RecordAlreadyExistsError,
    RecordTimestampFormatError,
    _principal_key,
    canonical_grant_payload,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal

PRINCIPAL = Principal(agentId="agent-diff", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
HMAC_KEY = b"test-hmac-key-differential"
TS = "2026-07-25T12:00:00+00:00"
TS2 = "2026-07-25T13:00:00+00:00"
TS_NEXT_DAY = "2026-07-26T09:00:00+00:00"
SIGNATURE = {"payloadType": "application/vnd.test+json", "payload": "e30=", "signatures": []}
EVIDENCE = "evidence-ref-001"


def make_grant(**overrides) -> Grant:
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256:env-001",
        promotedBy="alice",
        evidence=EVIDENCE,
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


def make_promotion_record(**overrides) -> PromotionRecord:
    return make_record(
        recordType="promotion",
        fromLevel=AutonomyLevel.in_loop,
        toLevel=AutonomyLevel.on_loop,
        predicate="passed",
        ratifiedBy="checker-bob",
        **overrides,
    )


GRANT_PK = f"GRANT#{_principal_key(PRINCIPAL)}"
GRANT_SK = f"CLASS#{ACTION_CLASS}"
RECORD_PK = f"RECORD#{_principal_key(PRINCIPAL)}#{ACTION_CLASS}"


# ===========================================================================
# Backend harnesses — the store pair under test + out-of-band tamper/raw reads
# ===========================================================================


class MemoryBackend:
    name = "memory"
    supports_record_signature = True
    pairing_error_match = "InMemoryPromotionRecordStore"

    def __init__(self) -> None:
        self.grants = InMemoryGrantStore(hmac_key=HMAC_KEY)
        self.records = InMemoryPromotionRecordStore()

    def mismatched_record_store(self):
        class _NotARecordStore:
            pass

        return _NotARecordStore()

    def tamper_grant_data(self) -> None:
        # #246: items are {"data": str, "grantHash": str}; tamper the stored
        # data STRING, like the other backends.
        item = self.grants._store[(_principal_key(PRINCIPAL), ACTION_CLASS)]
        item["data"] = item["data"].replace(EVIDENCE, "tampered-evidence")

    def tamper_grant_hash(self) -> None:
        item = self.grants._store[(_principal_key(PRINCIPAL), ACTION_CLASS)]
        item["grantHash"] = "0" * 64

    def raw_grant_data(self) -> str | None:
        item = self.grants._store.get((_principal_key(PRINCIPAL), ACTION_CLASS))
        return item["data"] if item is not None else None

    def raw_record_exists(self, record: PromotionRecord) -> bool:
        return InMemoryPromotionRecordStore._key(record) in self.records._records

    def record_signature(self, record: PromotionRecord) -> dict | None:
        return self.records.signature_for(record)


class SqliteBackend:
    name = "sqlite"
    supports_record_signature = True
    pairing_error_match = "SqlitePromotionRecordStore"

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.grants = SqliteGrantStore(HMAC_KEY, db_path)
        self.records = SqlitePromotionRecordStore(db_path)

    def mismatched_record_store(self):
        return InMemoryPromotionRecordStore()

    def _raw_conn(self):
        # A REAL second connection, deliberately: out-of-band tamper and raw
        # reads must not ride the store's own handle, or a single-connection
        # implementation could hide visibility bugs.
        import sqlite3

        return sqlite3.connect(str(self.db_path))

    def _raw_fetchone(self, sql: str, params: tuple):
        """Raw read that tolerates an ABSENT schema as "no rows".

        The sqlite stores open their connection lazily (the shipped
        _SqliteStoreBase idiom), so a refusal that fires BEFORE any store
        touch — a non-canonical record ts, a pairing TypeError — leaves the db
        file with no `items` table at all. That is the strongest form of
        nothing-was-written, so it must read as absence here, not as a harness
        error. Any OTHER OperationalError still propagates.
        """
        import sqlite3

        with self._raw_conn() as conn:
            try:
                return conn.execute(sql, params).fetchone()
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc):
                    return None
                raise

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

    def tamper_grant_data(self) -> None:
        def mutate(attrs):
            attrs["data"] = attrs["data"].replace(EVIDENCE, "tampered-evidence")

        self._rewrite_item(GRANT_PK, GRANT_SK, mutate)

    def tamper_grant_hash(self) -> None:
        def mutate(attrs):
            attrs["grantHash"] = "0" * 64

        self._rewrite_item(GRANT_PK, GRANT_SK, mutate)

    def raw_grant_data(self) -> str | None:
        row = self._raw_fetchone(
            "SELECT item FROM items WHERE pk = ? AND sk = ?", (GRANT_PK, GRANT_SK)
        )
        return json.loads(row[0])["data"] if row is not None else None

    def raw_record_exists(self, record: PromotionRecord) -> bool:
        return (
            self._raw_fetchone(
                "SELECT 1 FROM items WHERE pk = ? AND sk = ?",
                (RECORD_PK, f"{record.ts}#{record.recordType}"),
            )
            is not None
        )

    def record_signature(self, record: PromotionRecord) -> dict | None:
        return self.records.signature_for(record)


class DynamoBackend:
    name = "dynamo"
    supports_record_signature = False  # DynamoDBPromotionRecordStore has no read seam (#245)
    pairing_error_match = "DynamoDBPromotionRecordStore"

    REGION = "us-east-1"
    TABLE = "safe-agents-grants-differential"

    def __init__(self, boto3_module, grants, records) -> None:
        self._boto3 = boto3_module
        self.grants = grants
        self.records = records

    def mismatched_record_store(self):
        return InMemoryPromotionRecordStore()

    def _table(self):
        return self._boto3.resource("dynamodb", region_name=self.REGION).Table(self.TABLE)

    def _set_attr(self, attr: str, value: str) -> None:
        self._table().update_item(
            Key={"pk": GRANT_PK, "sk": GRANT_SK},
            UpdateExpression="SET #a = :v",
            ExpressionAttributeNames={"#a": attr},
            ExpressionAttributeValues={":v": value},
        )

    def tamper_grant_data(self) -> None:
        item = self._table().get_item(Key={"pk": GRANT_PK, "sk": GRANT_SK})["Item"]
        self._set_attr("data", item["data"].replace(EVIDENCE, "tampered-evidence"))

    def tamper_grant_hash(self) -> None:
        self._set_attr("grantHash", "0" * 64)

    def raw_grant_data(self) -> str | None:
        response = self._table().get_item(Key={"pk": GRANT_PK, "sk": GRANT_SK})
        return response["Item"]["data"] if "Item" in response else None

    def raw_record_exists(self, record: PromotionRecord) -> bool:
        key = {"pk": RECORD_PK, "sk": f"{record.ts}#{record.recordType}"}
        return "Item" in self._table().get_item(Key=key)

    def record_signature(self, record: PromotionRecord) -> dict | None:  # pragma: no cover
        raise NotImplementedError


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

    from safe_agents.broker.grants.store import (
        DynamoDBGrantStore,
        DynamoDBPromotionRecordStore,
    )

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
            DynamoDBGrantStore(hmac_key=HMAC_KEY, table_name=DynamoBackend.TABLE),
            # Both stores on the SAME table — write_record_and_grant's pairing
            # check requires it (the two item kinds co-locate).
            DynamoDBPromotionRecordStore(table_name=DynamoBackend.TABLE),
        )


# ===========================================================================
# Grant-store conformance — every backend
# ===========================================================================


class TestGrantConformance:
    def test_get_absent_is_none_not_quarantined(self, backend):
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.grant is None and not read.quarantined

    def test_put_get_round_trip(self, backend):
        grant = make_grant()
        backend.grants.put_grant(grant, None)
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.grant == grant and not read.quarantined
        # the read carries the stored bytes + item hash (the update baseline)
        assert read.raw_data == canonical_grant_payload(grant)
        assert read.stored_hash

    def test_create_then_duplicate_refused(self, backend):
        backend.grants.create_grant(make_grant(), None)
        with pytest.raises(GrantAlreadyExistsError):
            backend.grants.create_grant(make_grant(ownerId="bob"), None)
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "alice"

    def test_update_happy_path(self, backend):
        backend.grants.put_grant(make_grant(), None)
        current = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        backend.grants.update_grant(
            make_grant(level=AutonomyLevel.on_loop),
            current.stored_hash,
            None,
            current.raw_data,
        )
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.grant.level is AutonomyLevel.on_loop and not read.quarantined

    def test_update_wrong_expected_hash_refused(self, backend):
        backend.grants.put_grant(make_grant(), None)
        current = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.update_grant(
                make_grant(level=AutonomyLevel.on_loop), "0" * 64, None, current.raw_data
            )
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop

    def test_update_stale_prev_raw_data_refused(self, backend):
        # correct hash, wrong bytes — the data half of the condition alone
        backend.grants.put_grant(make_grant(), None)
        current = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.update_grant(
                make_grant(level=AutonomyLevel.on_loop),
                current.stored_hash,
                None,
                current.raw_data + " ",
            )

    def test_update_stale_baseline_after_concurrent_write_refused(self, backend):
        backend.grants.put_grant(make_grant(), None)
        stale = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        backend.grants.put_grant(make_grant(ownerId="mallory"), None)
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.update_grant(
                make_grant(level=AutonomyLevel.on_loop),
                stale.stored_hash,
                None,
                stale.raw_data,
            )
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant.ownerId == "mallory"

    def test_update_requires_prev_raw_data(self, backend):
        backend.grants.put_grant(make_grant(), None)
        current = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        with pytest.raises(ValueError, match="prev_raw_data"):
            backend.grants.update_grant(make_grant(), current.stored_hash, None, None)

    def test_update_absent_grant_refused(self, backend):
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.update_grant(make_grant(), "0" * 64, None, "{}")


class TestGrantTamper:
    def test_tampered_data_quarantines_with_evidence(self, backend):
        backend.grants.put_grant(make_grant(), None)
        backend.tamper_grant_data()
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.quarantined and read.grant is None
        assert "hash mismatch" in read.quarantine_reason
        # the tampered bytes ride the result as evidence, never parsed
        assert "tampered-evidence" in read.raw_data

    def test_tampered_hash_quarantines(self, backend):
        grant = make_grant()
        backend.grants.put_grant(grant, None)
        backend.tamper_grant_hash()
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.quarantined and read.grant is None
        assert read.raw_data == canonical_grant_payload(grant)


# ===========================================================================
# PromotionRecord ledger conformance — every backend
# ===========================================================================


class TestRecordConformance:
    def test_put_list_round_trip_chronological(self, backend):
        backend.records.put_record(make_record(ts=TS2), None)
        backend.records.put_record(make_record(ts=TS), None)
        records = backend.records.list_records(PRINCIPAL, ACTION_CLASS, None)
        assert [r.ts for r in records] == [TS, TS2]

    def test_ts_prefix_filters_lexically(self, backend):
        backend.records.put_record(make_record(ts=TS), None)
        backend.records.put_record(make_record(ts=TS_NEXT_DAY), None)
        day_one = backend.records.list_records(
            PRINCIPAL, ACTION_CLASS, None, ts_prefix="2026-07-25"
        )
        assert [r.ts for r in day_one] == [TS]

    def test_duplicate_record_refused(self, backend):
        backend.records.put_record(make_record(), None)
        with pytest.raises(RecordAlreadyExistsError):
            backend.records.put_record(make_record(), None)

    @pytest.mark.parametrize("bad_ts", ["2026-07-25T12:00:00Z", "2026-07-25T12:00:00"])
    def test_non_canonical_ts_refused(self, backend, bad_ts):
        with pytest.raises(RecordTimestampFormatError):
            backend.records.put_record(make_record(ts=bad_ts), None)
        assert not backend.raw_record_exists(make_record(ts=bad_ts))

    def test_record_signature_round_trip(self, backend):
        if not backend.supports_record_signature:
            pytest.skip(f"{backend.name} record store does not expose a signature read seam")
        backend.records.put_record(make_record(), None, signature=SIGNATURE)
        assert backend.record_signature(make_record()) == SIGNATURE
        backend.records.put_record(make_record(ts=TS2), None)
        assert backend.record_signature(make_record(ts=TS2)) is None


# ===========================================================================
# write_record_and_grant (#244) — the failure-injection set, every backend
# ===========================================================================


class TestAtomicWriteDifferential:
    def test_create_happy_path_writes_both(self, backend):
        backend.grants.write_record_and_grant(
            make_record(), make_grant(), backend.records, None, signature=SIGNATURE
        )
        read = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.grant is not None and not read.quarantined
        records = backend.records.list_records(PRINCIPAL, ACTION_CLASS, None)
        assert [r.recordType for r in records] == ["bootstrap"]
        if backend.supports_record_signature:
            assert backend.record_signature(make_record()) == SIGNATURE

    def test_update_happy_path_writes_both(self, backend):
        backend.grants.put_grant(make_grant(), None)
        current = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        backend.grants.write_record_and_grant(
            make_promotion_record(),
            make_grant(level=AutonomyLevel.on_loop),
            backend.records,
            None,
            expected=current,
        )
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.on_loop
        assert len(backend.records.list_records(PRINCIPAL, ACTION_CLASS, None)) == 1

    def test_record_leg_failure_leaves_grant_unwritten(self, backend):
        backend.records.put_record(make_record(), None)  # occupy the record key
        with pytest.raises(RecordAlreadyExistsError):
            backend.grants.write_record_and_grant(
                make_record(), make_grant(), backend.records, None
            )
        # raw read, not the API under test
        assert backend.raw_grant_data() is None

    def test_stale_expected_leaves_record_unwritten(self, backend):
        backend.grants.put_grant(make_grant(), None)
        stale = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        backend.grants.put_grant(make_grant(ownerId="mallory"), None)
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.write_record_and_grant(
                make_promotion_record(),
                make_grant(level=AutonomyLevel.on_loop),
                backend.records,
                None,
                expected=stale,
            )
        assert not backend.raw_record_exists(make_promotion_record())
        assert backend.raw_grant_data() == canonical_grant_payload(make_grant(ownerId="mallory"))

    def test_create_collision_leaves_record_unwritten(self, backend):
        backend.grants.put_grant(make_grant(), None)
        with pytest.raises(GrantAlreadyExistsError):
            backend.grants.write_record_and_grant(
                make_record(), make_grant(ownerId="bob"), backend.records, None, expected=None
            )
        assert not backend.raw_record_exists(make_record())
        assert backend.raw_grant_data() == canonical_grant_payload(make_grant())

    def test_both_legs_fail_maps_to_grant_conflict(self, backend):
        # Grant-conflict precedence: with the record key occupied AND a stale
        # grant baseline, the grant error surfaces (memory/sqlite check the
        # grant leg first; Dynamo maps CancellationReasons[1] first).
        backend.grants.put_grant(make_grant(), None)
        stale = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        backend.grants.put_grant(make_grant(ownerId="mallory"), None)
        backend.records.put_record(make_promotion_record(), None)
        with pytest.raises(GrantUpdateConflictError):
            backend.grants.write_record_and_grant(
                make_promotion_record(),
                make_grant(level=AutonomyLevel.on_loop),
                backend.records,
                None,
                expected=stale,
            )

    def test_pairing_mismatch_refused_before_any_write(self, backend):
        with pytest.raises(TypeError, match=backend.pairing_error_match):
            backend.grants.write_record_and_grant(
                make_record(), make_grant(), backend.mismatched_record_store(), None
            )
        assert backend.raw_grant_data() is None
        assert not backend.raw_record_exists(make_record())

    def test_non_canonical_ts_refused_before_any_write(self, backend):
        bad = make_record(ts="2026-07-25T12:00:00Z")
        with pytest.raises(RecordTimestampFormatError):
            backend.grants.write_record_and_grant(bad, make_grant(), backend.records, None)
        assert backend.raw_grant_data() is None
        assert not backend.raw_record_exists(bad)


# ===========================================================================
# SQLite-only proofs: pairing on the resolved path + durability across a real
# process-restart shape (close, fresh second connection)
# ===========================================================================


class TestSqliteOnly:
    def test_different_db_path_pairing_refused(self, tmp_path):
        grants = SqliteGrantStore(HMAC_KEY, tmp_path / "broker.db")
        other_records = SqlitePromotionRecordStore(tmp_path / "other.db")
        with pytest.raises(ValueError, match="SAME database"):
            grants.write_record_and_grant(make_record(), make_grant(), other_records, None)
        assert grants.get_grant(PRINCIPAL, ACTION_CLASS).grant is None

    def test_grants_and_records_survive_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first_grants = SqliteGrantStore(HMAC_KEY, db)
        first_records = SqlitePromotionRecordStore(db)
        first_grants.write_record_and_grant(
            make_record(), make_grant(), first_records, None, signature=SIGNATURE
        )
        first_grants.close()
        first_records.close()

        fresh_grants = SqliteGrantStore(HMAC_KEY, db)
        fresh_records = SqlitePromotionRecordStore(db)
        read = fresh_grants.get_grant(PRINCIPAL, ACTION_CLASS)
        assert read.grant == make_grant() and not read.quarantined
        assert [r.ts for r in fresh_records.list_records(PRINCIPAL, ACTION_CLASS)] == [TS]
        assert fresh_records.signature_for(make_record()) == SIGNATURE

    def test_rolled_back_atomic_write_survives_as_nothing(self, tmp_path):
        db = tmp_path / "broker.db"
        first_grants = SqliteGrantStore(HMAC_KEY, db)
        first_records = SqlitePromotionRecordStore(db)
        first_records.put_record(make_record())  # occupy the record key → atomic op cancels
        with pytest.raises(RecordAlreadyExistsError):
            first_grants.write_record_and_grant(
                make_record(), make_grant(), first_records, None
            )
        first_grants.close()
        first_records.close()

        fresh_grants = SqliteGrantStore(HMAC_KEY, db)
        fresh_records = SqlitePromotionRecordStore(db)
        assert fresh_grants.get_grant(PRINCIPAL, ACTION_CLASS).grant is None
        assert len(fresh_records.list_records(PRINCIPAL, ACTION_CLASS)) == 1  # only the pre-existing
