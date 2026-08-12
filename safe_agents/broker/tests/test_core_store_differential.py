"""Differential core-store suite: ONE contract, THREE backends (product-wrapper Phase 1, grants-sqlite slice).

The enforcement (counters/idempotency/ledger), approval (intents), and
envelope store contracts, each parametrized across the in-memory fake, the new
sqlite implementation, and the DynamoDB implementation under moto — the same
shape as test_mcp_store_differential.py. If sqlite wants a Protocol change
memory doesn't need, the Protocol is wrong, not the impl; this suite is where
that shows up.

Raw-read assertions bypass the store API by definition (a nothing-was-written
or column-moved claim must not trust the API under test): the sqlite harness
opens REAL second connections, the dynamo harness reads raw items, the memory
harness pokes the dicts. The moto backend importorskips per-param, so the
memory/sqlite rows run AWS-free.

One documented backend divergence (not papered over): a ledger status
transition on a MISSING entry raises KeyError on memory (dict access,
store.py::InMemoryStore.commit_ledger) and sqlite (deliberate match), but
DynamoStore's update_item carries no ConditionExpression
(store.py::DynamoStore.commit_ledger), and DynamoDB UpdateItem on an absent
key silently UPSERTS a partial item — an accident of UpdateItem the dynamo
rows assert as-is rather than hide.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from safe_agents.broker.approval.sqlite_store import SqliteIntentStore
from safe_agents.broker.approval.store import (
    EXECUTED_INTENT_RETENTION_DAYS,
    InMemoryIntentStore,
    QuarantinedIntentError,
    canonical_intent_payload,
)
from safe_agents.broker.enforcement.sqlite_store import SqliteEnforcementStore
from safe_agents.broker.enforcement.store import InMemoryStore
from safe_agents.broker.enforcement.types import IdempotencyRecord, LedgerEntry
from safe_agents.broker.envelope.sqlite_store import SqliteEnvelopeStore
from safe_agents.broker.envelope.store import InMemoryEnvelopeStore
from safe_agents.broker.schemas import BrokeredCall, Envelope, Intent
from safe_agents.broker.schemas.common import Principal

REGION = "us-east-1"
TS = "2026-07-25T12:00:00+00:00"
TS2 = "2026-07-25T13:00:00+00:00"
# 'Z'-suffixed on purpose: the sqlite expiry paths must normalize via datetime
# parsing (Dynamo's put path does .replace("Z", "+00:00")), never compare strings.
EXPIRY = "2027-01-01T00:00:00Z"
EXECUTED_AT = "2026-07-25T12:34:56Z"
PRINCIPAL = Principal(agentId="differential-agent", skill="core", user="maintainer", tier="B")
# The broker-held key the intent stores HMAC their stored frozen bytes with (#349).
INTENT_HMAC_KEY = b"test-hmac-key"


# ===========================================================================
# Builders — mirror the shapes in test_approval.py / test_envelope_store.py
# ===========================================================================


def make_call() -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": {
                "agentId": "differential-agent",
                "skill": "core",
                "user": "maintainer",
                "tier": "B",
            },
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 100, "to": "acct-xyz"},
            "manifest": {
                "tool": "payments",
                "op": "transfer",
                "effect": "write",
                "external": True,
                "reversible": False,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-1", "ingestedSources": []},
            "ts": TS,
        }
    )


def make_intent(
    intent_id: str = "intent-1",
    status: str = "pending",
    expiry: str = EXPIRY,
    approved_by: str | None = None,
) -> Intent:
    return Intent(
        id=intent_id,
        materializedRequest=make_call(),
        renderedForHuman="transfer 100 to acct-xyz",
        status=status,
        expiry=expiry,
        approvedBy=approved_by,
        ts=TS,
    )


def make_ledger_entry(
    entry_id: str = "entry-1", idempotency_key: str | None = None
) -> LedgerEntry:
    return LedgerEntry(
        entry_id=entry_id,
        idempotency_key=idempotency_key,
        call_json=make_call().model_dump_json(),
        decision_kind="allow",
        status="uncommitted",
        ts_created=TS,
    )


def make_idem(key: str = "idem-1", result_json: str | None = None) -> IdempotencyRecord:
    # decision_json is opaque to every store (never parsed) — a stand-in string.
    return IdempotencyRecord(
        key=key, decision_json='{"kind": "allow"}', ts=TS, result_json=result_json
    )


def make_envelope(polarity: str = "abstain") -> Envelope:
    return Envelope.model_validate(
        {
            "polarity": polarity,
            "caps": {"actions_per_run": 1},
            "allowlists": {"tools": ["snapshot.read"]},
            "high_stakes": False,
        }
    )


# ===========================================================================
# Moto scaffolding — one pk/sk table per fixture, created inside mock_aws
# ===========================================================================


@contextlib.contextmanager
def _moto_table(table_name: str):
    pytest.importorskip("moto", reason="moto is required for the dynamo differential row")
    boto3 = pytest.importorskip(
        "boto3", reason="boto3 is required for the dynamo differential row"
    )
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    ):
        os.environ.setdefault(var, "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=table_name,
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
        ddb.Table(table_name).wait_until_exists()
        yield boto3


def _raw_sqlite_item(db_path: Path, pk: str, sk: str) -> dict | None:
    """Non-key attrs at (pk, sk) via a REAL second connection, or None."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT item FROM items WHERE pk = ? AND sk = ?", (pk, sk)
        ).fetchone()
    return None if row is None else json.loads(row[0])


# ===========================================================================
# Backend harnesses — the store under test + out-of-band raw reads
# ===========================================================================


class EnforcementBackend:
    def __init__(self, name: str, store, raw_ledger_item) -> None:
        self.name = name
        self.store = store
        # raw_ledger_item(entry_id) -> non-key attr dict | None, out-of-band.
        self.raw_ledger_item = raw_ledger_item


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def enforcement_backend(request, tmp_path):
    if request.param == "memory":
        store = InMemoryStore()

        def raw(entry_id: str) -> dict | None:
            entry = store.get_ledger_entry(entry_id)
            if entry is None:
                return None
            attrs = {
                "call_json": entry.call_json,
                "decision_kind": entry.decision_kind,
                "status": entry.status,
                "ts_created": entry.ts_created,
            }
            for name in ("idempotency_key", "ts_committed", "error"):
                if getattr(entry, name) is not None:
                    attrs[name] = getattr(entry, name)
            return attrs

        yield EnforcementBackend("memory", store, raw)
        return
    if request.param == "sqlite":
        db = tmp_path / "broker.db"
        yield EnforcementBackend(
            "sqlite",
            SqliteEnforcementStore(db),
            lambda entry_id: _raw_sqlite_item(db, f"LEDGER#{entry_id}", "v0"),
        )
        return
    table_name = "safe-agents-enforcement-differential"
    with _moto_table(table_name) as boto3:
        from safe_agents.broker.enforcement.store import DynamoStore

        table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)

        def raw(entry_id: str) -> dict | None:
            item = table.get_item(Key={"pk": f"LEDGER#{entry_id}", "sk": "v0"}).get("Item")
            if item is None:
                return None
            return {k: v for k, v in item.items() if k not in ("pk", "sk")}

        yield EnforcementBackend("dynamo", DynamoStore(table_name), raw)


class IntentBackend:
    def __init__(
        self, name: str, store, db_path: Path | None = None, tamper_item=None
    ) -> None:
        self.name = name
        self.store = store
        self.db_path = db_path
        # tamper_item(intent_id, mutate) rewrites the stored item attrs
        # OUT-OF-BAND (bypassing the store API) — the #349 A4 attacker.
        self.tamper_item = tamper_item

    def raw_expires_at(self, intent_id: str) -> str | None:
        """The substrate expires_at COLUMN (sqlite only), via a second connection."""
        assert self.db_path is not None, "expires_at column exists only on sqlite"
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT expires_at FROM items WHERE pk = ? AND sk = ?",
                (f"INTENT#{intent_id}", "v0"),
            ).fetchone()
        return None if row is None else row[0]


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def intent_backend(request, tmp_path):
    if request.param == "memory":
        store = InMemoryIntentStore(hmac_key=INTENT_HMAC_KEY)

        def tamper_memory(intent_id: str, mutate) -> None:
            store._items[intent_id] = mutate(dict(store._items[intent_id]))

        yield IntentBackend("memory", store, tamper_item=tamper_memory)
        return
    if request.param == "sqlite":
        db = tmp_path / "broker.db"

        def tamper_sqlite(intent_id: str, mutate) -> None:
            with sqlite3.connect(str(db)) as conn:
                row = conn.execute(
                    "SELECT item FROM items WHERE pk = ? AND sk = ?",
                    (f"INTENT#{intent_id}", "v0"),
                ).fetchone()
                conn.execute(
                    "UPDATE items SET item = ? WHERE pk = ? AND sk = ?",
                    (json.dumps(mutate(json.loads(row[0]))), f"INTENT#{intent_id}", "v0"),
                )

        yield IntentBackend(
            "sqlite",
            SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY),
            db,
            tamper_item=tamper_sqlite,
        )
        return
    table_name = "safe-agents-intents-differential"
    with _moto_table(table_name) as boto3:
        from safe_agents.broker.approval.store import DynamoIntentStore

        def tamper_dynamo(intent_id: str, mutate) -> None:
            table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
            item = table.get_item(
                Key={"pk": f"INTENT#{intent_id}", "sk": "v0"}
            )["Item"]
            key = {"pk": item.pop("pk"), "sk": item.pop("sk")}
            table.put_item(Item={**key, **mutate(item)})

        yield IntentBackend(
            "dynamo",
            DynamoIntentStore(table_name, hmac_key=INTENT_HMAC_KEY),
            tamper_item=tamper_dynamo,
        )


class EnvelopeBackend:
    def __init__(self, name: str, store) -> None:
        self.name = name
        self.store = store


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def envelope_backend(request, tmp_path):
    if request.param == "memory":
        yield EnvelopeBackend("memory", InMemoryEnvelopeStore())
        return
    if request.param == "sqlite":
        yield EnvelopeBackend("sqlite", SqliteEnvelopeStore(tmp_path / "broker.db"))
        return
    table_name = "safe-agents-envelope-differential"
    with _moto_table(table_name):
        from safe_agents.broker.envelope.store import DynamoDBEnvelopeStore

        yield EnvelopeBackend("dynamo", DynamoDBEnvelopeStore(table_name=table_name))


# ===========================================================================
# Counter conformance — every backend
# ===========================================================================


class TestCounterConformance:
    def test_increment_under_cap(self, enforcement_backend):
        store = enforcement_backend.store
        assert store.try_increment_counter("k", 1.0, 5.0) is True
        assert store.read_counter("k") == 1.0

    def test_accumulates_then_refuses_over_cap(self, enforcement_backend):
        store = enforcement_backend.store
        for _ in range(3):
            assert store.try_increment_counter("k", 1.0, 3.0) is True
        assert store.try_increment_counter("k", 1.0, 3.0) is False
        assert store.read_counter("k") == 3.0  # the refused increment wrote nothing

    def test_single_action_larger_than_cap_refused(self, enforcement_backend):
        store = enforcement_backend.store
        assert store.try_increment_counter("k", 10.0, 5.0) is False
        assert store.read_counter("k") == 0.0

    def test_read_counter_defaults_zero(self, enforcement_backend):
        assert enforcement_backend.store.read_counter("never-touched") == 0.0

    def test_fractional_deltas(self, enforcement_backend):
        store = enforcement_backend.store
        for _ in range(3):
            assert store.try_increment_counter("frac", 0.25, 1.0) is True
        assert store.read_counter("frac") == 0.75
        assert store.try_increment_counter("frac", 0.5, 1.0) is False
        assert store.try_increment_counter("frac", 0.25, 1.0) is True  # exactly at cap
        assert store.read_counter("frac") == 1.0


# ===========================================================================
# Idempotency conformance — every backend
# ===========================================================================


class TestIdempotencyConformance:
    def test_first_put_wins_second_refused(self, enforcement_backend):
        store = enforcement_backend.store
        assert store.put_idempotency_if_absent(make_idem()) is True
        assert store.put_idempotency_if_absent(make_idem()) is False

    def test_get_absent_returns_none(self, enforcement_backend):
        assert enforcement_backend.store.get_idempotency("nope") is None

    def test_round_trip_with_result(self, enforcement_backend):
        store = enforcement_backend.store
        store.put_idempotency_if_absent(make_idem(result_json='{"ok": true}'))
        got = store.get_idempotency("idem-1")
        assert got is not None
        assert got.decision_json == '{"kind": "allow"}'
        assert got.ts == TS
        assert got.result_json == '{"ok": true}'

    def test_round_trip_result_none_tolerated(self, enforcement_backend):
        store = enforcement_backend.store
        store.put_idempotency_if_absent(make_idem(result_json=None))
        got = store.get_idempotency("idem-1")
        assert got is not None and got.result_json is None

    def test_delete_then_reput_wins(self, enforcement_backend):
        store = enforcement_backend.store
        store.put_idempotency_if_absent(make_idem())
        store.delete_idempotency("idem-1")
        assert store.get_idempotency("idem-1") is None
        assert store.put_idempotency_if_absent(make_idem()) is True

    def test_delete_absent_is_noop(self, enforcement_backend):
        enforcement_backend.store.delete_idempotency("never-existed")  # must not raise


# ===========================================================================
# Ledger conformance — every backend
# ===========================================================================


class TestLedgerConformance:
    def test_write_then_uncommitted_contains(self, enforcement_backend):
        store = enforcement_backend.store
        store.write_ledger(make_ledger_entry())
        entries = store.get_uncommitted_entries()
        assert [e.entry_id for e in entries] == ["entry-1"]
        assert entries[0].call_json == make_call().model_dump_json()
        assert entries[0].status == "uncommitted"

    def test_commit_reflected(self, enforcement_backend):
        store = enforcement_backend.store
        store.write_ledger(make_ledger_entry())
        store.commit_ledger("entry-1", TS2)
        assert store.get_uncommitted_entries() == []
        raw = enforcement_backend.raw_ledger_item("entry-1")
        assert raw["status"] == "committed" and raw["ts_committed"] == TS2

    def test_compensate_reflected(self, enforcement_backend):
        store = enforcement_backend.store
        store.write_ledger(make_ledger_entry())
        store.compensate_ledger("entry-1", "connector timed out")
        assert store.get_uncommitted_entries() == []
        raw = enforcement_backend.raw_ledger_item("entry-1")
        assert raw["status"] == "compensated" and raw["error"] == "connector timed out"

    def test_escalate_reflected(self, enforcement_backend):
        store = enforcement_backend.store
        store.write_ledger(make_ledger_entry())
        store.escalate_ledger("entry-1", "compensation failed")
        assert store.get_uncommitted_entries() == []
        raw = enforcement_backend.raw_ledger_item("entry-1")
        assert raw["status"] == "escalated" and raw["error"] == "compensation failed"

    def test_write_ledger_is_blind_put(self, enforcement_backend):
        store = enforcement_backend.store
        store.write_ledger(make_ledger_entry())
        replacement = make_ledger_entry(idempotency_key="idem-9")
        store.write_ledger(replacement)
        raw = enforcement_backend.raw_ledger_item("entry-1")
        assert raw["idempotency_key"] == "idem-9"

    def test_transition_on_missing_entry(self, enforcement_backend):
        store = enforcement_backend.store
        if enforcement_backend.name == "dynamo":
            # Documented divergence (see module docstring): DynamoStore's
            # update_item has no ConditionExpression, and DynamoDB UpdateItem
            # on an absent key silently UPSERTS a partial item.
            store.commit_ledger("ghost", TS2)
            raw = enforcement_backend.raw_ledger_item("ghost")
            assert raw is not None and raw["status"] == "committed"
        else:
            # memory (dict access) and sqlite (deliberate match) are loud.
            with pytest.raises(KeyError):
                store.commit_ledger("ghost", TS2)
            assert enforcement_backend.raw_ledger_item("ghost") is None


# ===========================================================================
# Intent conformance — every backend
# ===========================================================================


class TestIntentConformance:
    def test_put_get_round_trip(self, intent_backend):
        store = intent_backend.store
        store.put_intent(make_intent())
        got = store.get_intent("intent-1")
        assert got is not None
        assert got.status == "pending"
        assert got.expiry == EXPIRY
        assert got.approvedBy is None
        assert got.executedAt is None
        assert got.materializedRequest == make_call()

    def test_get_absent_returns_none(self, intent_backend):
        assert intent_backend.store.get_intent("nope") is None

    def test_transition_pending_to_approved(self, intent_backend):
        store = intent_backend.store
        store.put_intent(make_intent())
        assert store.transition_status("intent-1", "pending", "approved", "maintainer") is True
        got = store.get_intent("intent-1")
        assert got.status == "approved" and got.approvedBy == "maintainer"

    def test_transition_wrong_expected_refused(self, intent_backend):
        store = intent_backend.store
        store.put_intent(make_intent())
        assert store.transition_status("intent-1", "approved", "executed") is False
        assert store.get_intent("intent-1").status == "pending"

    def test_transition_absent_refused(self, intent_backend):
        assert intent_backend.store.transition_status("nope", "pending", "approved") is False

    def test_double_transition_exactly_one_true(self, intent_backend):
        store = intent_backend.store
        store.put_intent(make_intent())
        results = [
            store.transition_status("intent-1", "pending", "approved", "maintainer")
            for _ in range(2)
        ]
        assert results == [True, False]

    def test_executed_transition_stamps_executed_at(self, intent_backend):
        store = intent_backend.store
        store.put_intent(make_intent())
        assert store.transition_status("intent-1", "pending", "approved", "maintainer") is True
        assert (
            store.transition_status(
                "intent-1", "approved", "executed", executed_at=EXECUTED_AT
            )
            is True
        )
        got = store.get_intent("intent-1")
        assert got.status == "executed" and got.executedAt == EXECUTED_AT
        if intent_backend.name == "sqlite":
            # The expires_at COLUMN must move to executedAt + retention — the
            # sqlite mirror of Dynamo's TTL extension, anchored on executed_at
            # itself (sa#213 pin). Raw SQL, not the store API.
            executed_dt = datetime.fromisoformat(EXECUTED_AT.replace("Z", "+00:00"))
            expected = (
                executed_dt + timedelta(days=EXECUTED_INTENT_RETENTION_DAYS)
            ).isoformat()
            assert intent_backend.raw_expires_at("intent-1") == expected

    def test_non_executed_transition_preserves_expiry_column(self, intent_backend):
        if intent_backend.name != "sqlite":
            pytest.skip("the expires_at column exists only on sqlite")
        store = intent_backend.store
        store.put_intent(make_intent())
        before = intent_backend.raw_expires_at("intent-1")
        assert before is not None
        assert store.transition_status("intent-1", "pending", "approved", "maintainer") is True
        assert intent_backend.raw_expires_at("intent-1") == before


def _evil_payload(intent_id: str = "intent-1") -> str:
    """The A4 attacker's best rewrite (#349): the frozen call's args replaced,
    the payload re-serialized in the EXACT canonical form the store uses — every
    unkeyed field recomputed consistently. Only the broker-held HMAC key is out
    of reach, which is precisely why an unkeyed stored digest (issue #349
    option 2) would not have refused this row."""
    evil_call = make_call().model_copy(
        update={"args": {"amount": 999999, "to": "acct-attacker"}}
    )
    return canonical_intent_payload(
        Intent(
            id=intent_id,
            materializedRequest=evil_call,
            renderedForHuman="transfer 100 to acct-xyz",
            status="pending",
            expiry=EXPIRY,
            ts=TS,
        )
    )


class TestIntentTamperEvidence:
    """#349 — every backend HMACs the stored frozen bytes and verify-then-parses.

    Data-driven over the tamper shapes; parametrized over all three backends by
    the fixture, mirroring how the grants backends share _read_result_from_item.
    """

    TAMPERS = {
        "frozen-call-rewrite": (
            lambda attrs: {**attrs, "data": _evil_payload()},
            "HMAC mismatch",
        ),
        "hash-stripped": (
            lambda attrs: {k: v for k, v in attrs.items() if k != "intentHash"},
            "missing its data or intentHash",
        ),
    }

    @pytest.mark.parametrize("tamper_name", sorted(TAMPERS))
    def test_tampered_row_quarantines_on_read(self, intent_backend, tamper_name):
        mutate, expected_reason = self.TAMPERS[tamper_name]
        store = intent_backend.store
        store.put_intent(make_intent())
        intent_backend.tamper_item("intent-1", mutate)
        with pytest.raises(QuarantinedIntentError, match=expected_reason):
            store.get_intent("intent-1")

    def test_untampered_row_reads_clean_after_transitions(self, intent_backend):
        """Control: lifecycle transitions never disturb the integrity basis."""
        store = intent_backend.store
        store.put_intent(make_intent())
        assert store.transition_status("intent-1", "pending", "approved", "maintainer") is True
        got = store.get_intent("intent-1")
        assert got.status == "approved"
        assert got.materializedRequest == make_call()


# ===========================================================================
# Envelope conformance — every backend
# ===========================================================================


class TestEnvelopeConformance:
    def test_put_get_round_trip(self, envelope_backend):
        store = envelope_backend.store
        store.put_envelope(PRINCIPAL, make_envelope())
        got = store.get_envelope(PRINCIPAL)
        assert got is not None
        assert got.polarity == "abstain"
        assert got.allowlists.tools == ["snapshot.read"]
        assert got.high_stakes is False

    def test_get_absent_returns_none(self, envelope_backend):
        assert envelope_backend.store.get_envelope(PRINCIPAL) is None

    def test_put_overwrite_reflects_newer(self, envelope_backend):
        store = envelope_backend.store
        store.put_envelope(PRINCIPAL, make_envelope())
        store.put_envelope(PRINCIPAL, make_envelope(polarity="act"))
        assert store.get_envelope(PRINCIPAL).polarity == "act"


# ===========================================================================
# SQLite-only proofs: durability across close+reopen, and the boot sweep
# ===========================================================================


class TestSqliteDurability:
    def test_enforcement_state_survives_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteEnforcementStore(db)
        first.try_increment_counter("k", 2.0, 5.0)
        first.put_idempotency_if_absent(make_idem(result_json='{"ok": true}'))
        first.write_ledger(make_ledger_entry())
        first.close()

        fresh = SqliteEnforcementStore(db)
        assert fresh.read_counter("k") == 2.0
        got = fresh.get_idempotency("idem-1")
        assert got is not None and got.result_json == '{"ok": true}'
        assert [e.entry_id for e in fresh.get_uncommitted_entries()] == ["entry-1"]

    def test_intents_survive_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY)
        first.put_intent(make_intent())
        first.transition_status("intent-1", "pending", "approved", "maintainer")
        first.close()

        fresh = SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY)
        got = fresh.get_intent("intent-1")
        assert got is not None
        assert got.status == "approved" and got.approvedBy == "maintainer"

    def test_envelope_survives_reopen(self, tmp_path):
        db = tmp_path / "broker.db"
        first = SqliteEnvelopeStore(db)
        first.put_envelope(PRINCIPAL, make_envelope())
        first.close()

        fresh = SqliteEnvelopeStore(db)
        assert fresh.get_envelope(PRINCIPAL).polarity == "abstain"


class TestSqliteSweep:
    def _plant_counter_with_expiry(self, db: Path) -> None:
        """A non-INTENT row carrying an expires_at, planted via raw SQL — the
        sweep must NOT touch it (other item families own their lifecycles)."""
        with sqlite3.connect(str(db)) as conn:
            conn.execute(
                "INSERT INTO items (pk, sk, item, expires_at) VALUES (?, ?, ?, ?)",
                ("COUNTER#planted", "v0", '{"spent": 1.0}', "2020-01-01T00:00:00+00:00"),
            )

    def test_sweep_deletes_expired_intent_only(self, tmp_path):
        db = tmp_path / "broker.db"
        store = SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY)
        store.put_intent(make_intent("expired", expiry="2020-01-01T00:00:00Z"))
        store.put_intent(make_intent("alive", expiry=EXPIRY))
        self._plant_counter_with_expiry(db)

        assert store.sweep_expired() == 1
        assert store.get_intent("expired") is None
        assert store.get_intent("alive") is not None
        # The planted COUNTER row is untouched despite its stale expires_at.
        assert _raw_sqlite_item(db, "COUNTER#planted", "v0") == {"spent": 1.0}

    def test_sweep_with_explicit_now_is_a_pure_predicate(self, tmp_path):
        db = tmp_path / "broker.db"
        store = SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY)
        store.put_intent(make_intent("edge", expiry="2026-07-25T12:00:00Z"))
        boundary = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)

        assert store.sweep_expired(now=boundary - timedelta(seconds=1)) == 0
        assert store.get_intent("edge") is not None
        assert store.sweep_expired(now=boundary + timedelta(seconds=1)) == 1
        assert store.get_intent("edge") is None

    def test_sweep_result_visible_to_second_connection(self, tmp_path):
        db = tmp_path / "broker.db"
        store = SqliteIntentStore(db, hmac_key=INTENT_HMAC_KEY)
        store.put_intent(make_intent("expired", expiry="2020-01-01T00:00:00Z"))
        store.sweep_expired()
        assert _raw_sqlite_item(db, "INTENT#expired", "v0") is None
