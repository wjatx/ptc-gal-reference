"""Real-DynamoDB tests for the three broker stores (sa#101).

Why this file exists
--------------------
The production stores — ``DynamoStore`` (enforcement), ``DynamoIntentStore``
(approval) and ``DynamoDBGrantStore`` (grants) — were previously exercised in CI
only through their ``InMemory*`` fakes. The real DynamoDB Condition/Update
expressions never ran, so two invalid-expression bugs shipped and were caught
only when the local arm ran against DynamoDB Local:

  1. arithmetic in a ConditionExpression (``spent + :delta <= :cap``), and
  2. ``if_not_exists()`` in a ConditionExpression.

DynamoDB forbids both — a ConditionExpression may use only comparisons and
``attribute_(not_)exists`` — but nothing in CI evaluated the expression, so the
regressions were invisible.

These tests run the *real* store methods against **moto** (``mock_aws``), whose
DynamoDB expression evaluator parses and rejects invalid Condition/Update
expressions exactly as DynamoDB does. A regression to arithmetic or
``if_not_exists`` inside a ConditionExpression makes moto raise (see
``test_moto_rejects_arithmetic_condition_expression``), which propagates out of
the store method and fails the corresponding round-trip test. No container and
no live AWS are required.

moto is guarded with ``importorskip`` so the rest of the suite still imports
when moto is absent; it is declared in broker's ``[dev]`` extra so CI installs
it.
"""

from __future__ import annotations

import os

import pytest

# moto needs credentials + a region present in the environment even though it
# never talks to AWS. Set dummy values before boto3 resolves a default session.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

# Skip the whole module (not error) if moto is not installed, so a suite run
# without the [dev] extra still imports cleanly.
pytest.importorskip("moto", reason="moto is required for real-DynamoDB store tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for real-DynamoDB store tests")

from moto import mock_aws  # noqa: E402

from safe_agents.broker.approval.store import DynamoIntentStore  # noqa: E402
from safe_agents.broker.enforcement.store import DynamoStore  # noqa: E402
from safe_agents.broker.enforcement.types import (  # noqa: E402
    IdempotencyRecord,
    LedgerEntry,
    decision_to_json,
)
from safe_agents.broker.envelope.store import DynamoDBEnvelopeStore  # noqa: E402
from safe_agents.broker.grants.store import (  # noqa: E402
    DynamoDBGrantStore,
    DynamoDBPromotionRecordStore,
    compute_grant_hash,
)
from safe_agents.broker.schemas import (  # noqa: E402
    Allow,
    BrokeredCall,
    Envelope,
    Grant,
    Intent,
    PromotionRecord,
)
from safe_agents.broker.schemas.common import Principal  # noqa: E402

REGION = "us-east-1"
TABLE = "safe-agents-store-test"


# ---------------------------------------------------------------------------
# Table fixture — one single-table (pk HASH / sk RANGE) DynamoDB table.
#
# The real infra uses a table per store, but every store keys on the same
# pk/sk shape, so a single moto table serves all three here.
# ---------------------------------------------------------------------------


@pytest.fixture
def table_name():
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
        yield TABLE


def _raw_item(pk: str, sk: str = "v0") -> dict | None:
    """Read an item straight from DynamoDB, bypassing the store — for asserting
    on attributes the store does not surface (e.g. the TTL field)."""
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    return table.get_item(Key={"pk": pk, "sk": sk}).get("Item")


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------

_PRINCIPAL_DICT = {"agentId": "agent-1", "skill": "email", "user": "alice", "tier": "B"}
_TS = "2026-06-28T00:00:00Z"


def _call() -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL_DICT,
            "tool": "email",
            "op": "send",
            "args": {"to": "bob@example.com"},
            "manifest": {
                "tool": "email",
                "op": "send",
                "effect": "write",
                "external": True,
                "reversible": False,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-1", "ingestedSources": []},
            "ts": _TS,
        }
    )


def _ledger_entry(entry_id: str, status: str = "uncommitted") -> LedgerEntry:
    return LedgerEntry(
        entry_id=entry_id,
        idempotency_key=f"idem-{entry_id}",
        call_json=_call().model_dump_json(),
        decision_kind="allow",
        status=status,  # type: ignore[arg-type]
        ts_created=_TS,
    )


# ===========================================================================
# Meta-test — evidence that moto actually catches the invalid-expression bug
# class. This is the guard the round-trip tests below rely on.
# ===========================================================================


def test_moto_rejects_arithmetic_condition_expression(table_name):
    """moto must reject arithmetic inside a ConditionExpression — the exact bug
    (`spent + :delta <= :cap`) that shipped. If moto silently accepted it, none
    of the try_increment_counter regressions would be caught, so pin the
    behavior explicitly here."""
    from decimal import Decimal

    table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
    table.put_item(Item={"pk": "COUNTER#x", "sk": "v0", "spent": Decimal("50")})

    with pytest.raises(Exception) as exc_info:  # moto raises ValueError; DynamoDB a ClientError
        table.update_item(
            Key={"pk": "COUNTER#x", "sk": "v0"},
            UpdateExpression="SET spent = spent + :delta",
            ConditionExpression="spent + :delta <= :cap",
            ExpressionAttributeValues={":delta": Decimal("10"), ":cap": Decimal("100")},
        )
    # Not a ConditionalCheckFailed (which would be a legitimate cap rejection) —
    # a genuine parse failure of the invalid expression.
    assert "ConditionalCheckFailed" not in type(exc_info.value).__name__


def test_moto_rejects_if_not_exists_in_condition_expression(table_name):
    """moto must also reject if_not_exists() inside a ConditionExpression — the
    second shipped bug."""
    from decimal import Decimal

    table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
    table.put_item(Item={"pk": "COUNTER#x", "sk": "v0", "spent": Decimal("50")})

    with pytest.raises(Exception) as exc_info:
        table.update_item(
            Key={"pk": "COUNTER#x", "sk": "v0"},
            UpdateExpression="SET spent = spent + :delta",
            ConditionExpression="if_not_exists(spent, :zero) <= :headroom",
            ExpressionAttributeValues={
                ":delta": Decimal("10"),
                ":zero": Decimal("0"),
                ":headroom": Decimal("90"),
            },
        )
    assert "ConditionalCheckFailed" not in type(exc_info.value).__name__


# ===========================================================================
# DynamoStore (enforcement) — counters, idempotency, ledger.
# These run the REAL ConditionExpressions: a regression to `+`/`if_not_exists`
# in a condition raises here rather than reaching the local arm.
# ===========================================================================


class TestDynamoStoreCounter:
    CAP = 100.0

    def test_increment_below_cap_succeeds(self, table_name):
        store = DynamoStore(table_name)
        assert store.try_increment_counter("c", 40.0, self.CAP) is True
        assert store.read_counter("c") == 40.0

    def test_increment_exactly_to_cap_succeeds(self, table_name):
        store = DynamoStore(table_name)
        assert store.try_increment_counter("c", 90.0, self.CAP) is True
        # 90 <= headroom(90) → the final unit exactly reaching the cap fits.
        assert store.try_increment_counter("c", 10.0, self.CAP) is True
        assert store.read_counter("c") == 100.0

    def test_increment_that_would_exceed_cap_returns_false(self, table_name):
        store = DynamoStore(table_name)
        assert store.try_increment_counter("c", 90.0, self.CAP) is True
        # 90 + 20 = 110 > 100 → rejected, counter unchanged.
        assert store.try_increment_counter("c", 20.0, self.CAP) is False
        assert store.read_counter("c") == 90.0

    def test_single_delta_larger_than_cap_returns_false(self, table_name):
        store = DynamoStore(table_name)
        # A single action larger than the whole cap can never fit.
        assert store.try_increment_counter("c", 150.0, self.CAP) is False
        assert store.read_counter("c") == 0.0

    def test_sequential_increments_respect_cap(self, table_name):
        """Fill the counter one unit at a time; the increment that would cross
        the cap is the one that fails — the CAS condition holds across writes."""
        store = DynamoStore(table_name)
        succeeded = 0
        for _ in range(120):
            if store.try_increment_counter("c", 1.0, self.CAP):
                succeeded += 1
        assert succeeded == 100
        assert store.read_counter("c") == 100.0

    def test_read_counter_absent_is_zero(self, table_name):
        store = DynamoStore(table_name)
        assert store.read_counter("never-touched") == 0.0


class TestDynamoStoreIdempotency:
    def _record(self, key: str) -> IdempotencyRecord:
        return IdempotencyRecord(
            key=key,
            decision_json=decision_to_json(Allow(kind="allow")),
            ts=_TS,
        )

    def test_first_writer_wins(self, table_name):
        store = DynamoStore(table_name)
        assert store.put_idempotency_if_absent(self._record("k1")) is True
        # Second put with the same key loses the race — the ConditionExpression
        # (attribute_not_exists(pk)) rejects it.
        assert store.put_idempotency_if_absent(self._record("k1")) is False

    def test_get_returns_stored_record(self, table_name):
        store = DynamoStore(table_name)
        store.put_idempotency_if_absent(self._record("k2"))
        got = store.get_idempotency("k2")
        assert got is not None
        assert got.key == "k2"
        assert got.decision().kind == "allow"

    def test_get_absent_returns_none(self, table_name):
        store = DynamoStore(table_name)
        assert store.get_idempotency("missing") is None

    def test_result_json_round_trips(self, table_name):
        """sa#108: the cached connector result survives the DynamoDB round-trip."""
        store = DynamoStore(table_name)
        record = IdempotencyRecord(
            key="k-result",
            decision_json=decision_to_json(Allow(kind="allow")),
            ts=_TS,
            result_json='{"event_id": "evt-99"}',
        )
        assert store.put_idempotency_if_absent(record) is True

        got = store.get_idempotency("k-result")
        assert got is not None
        assert got.result_json == '{"event_id": "evt-99"}'
        assert got.result() == {"event_id": "evt-99"}

    def test_record_without_result_json_reads_back_none(self, table_name):
        """Back-compat: a record written without result_json (pre-sa#108, or any
        non-executing decision) stores no attribute and reads back result None."""
        store = DynamoStore(table_name)
        store.put_idempotency_if_absent(self._record("k-no-result"))

        raw = _raw_item("IDEM#k-no-result")
        assert raw is not None
        assert "result_json" not in raw  # non-executing record writes no attribute

        got = store.get_idempotency("k-no-result")
        assert got is not None
        assert got.result_json is None
        assert got.result() is None


class TestDynamoStoreLedger:
    def test_write_then_get_uncommitted_round_trip(self, table_name):
        store = DynamoStore(table_name)
        store.write_ledger(_ledger_entry("e1"))
        store.write_ledger(_ledger_entry("e2"))

        uncommitted = store.get_uncommitted_entries()
        ids = {e.entry_id for e in uncommitted}
        assert ids == {"e1", "e2"}
        # Field fidelity survived the DynamoDB round-trip.
        e1 = next(e for e in uncommitted if e.entry_id == "e1")
        assert e1.idempotency_key == "idem-e1"
        assert e1.decision_kind == "allow"
        assert e1.status == "uncommitted"

    def test_commit_removes_from_uncommitted(self, table_name):
        store = DynamoStore(table_name)
        store.write_ledger(_ledger_entry("e1"))
        store.write_ledger(_ledger_entry("e2"))

        store.commit_ledger("e1", ts_committed="2026-06-28T01:00:00Z")

        uncommitted = store.get_uncommitted_entries()
        assert {e.entry_id for e in uncommitted} == {"e2"}


# ===========================================================================
# DynamoIntentStore (approval) — put/get + the status-transition conditional.
# ===========================================================================


# The broker-held key the intent store HMACs its stored frozen bytes with (#349).
_INTENT_KEY = b"intent-hmac-key"


def _intent(intent_id: str, status: str = "pending") -> Intent:
    return Intent(
        id=intent_id,
        materializedRequest=_call(),
        renderedForHuman="Send email to bob@example.com",
        status=status,  # type: ignore[arg-type]
        expiry="2026-06-28T00:15:00Z",
        ts=_TS,
    )


class TestDynamoIntentStore:
    def test_put_then_get_round_trip(self, table_name):
        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i1"))

        got = store.get_intent("i1")
        assert got is not None
        assert got.id == "i1"
        assert got.status == "pending"
        assert got.renderedForHuman == "Send email to bob@example.com"
        # The frozen materializedRequest survives the JSON round-trip.
        assert got.materializedRequest.tool == "email"
        assert got.materializedRequest.op == "send"

    def test_get_absent_returns_none(self, table_name):
        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        assert store.get_intent("nope") is None

    def test_ttl_attribute_is_set(self, table_name):
        """put_intent must set the numeric `ttl` attribute (epoch seconds) that
        DynamoDB TTL auto-expiry relies on."""
        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i-ttl"))

        raw = _raw_item("INTENT#i-ttl")
        assert raw is not None
        assert "ttl" in raw
        # 2026-06-28T00:15:00Z in epoch seconds.
        assert int(raw["ttl"]) == 1782605700

    def test_transition_from_expected_status_succeeds(self, table_name):
        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i2"))

        ok = store.transition_status(
            "i2", expected_status="pending", new_status="approved", approved_by="alice"
        )
        assert ok is True
        got = store.get_intent("i2")
        assert got is not None
        assert got.status == "approved"
        assert got.approvedBy == "alice"

    def test_transition_from_wrong_status_fails(self, table_name):
        """The `#status = :expected_status` ConditionExpression must reject a
        transition whose expected status does not match — two concurrent
        approvals cannot both win."""
        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i3"))

        # First approval wins.
        assert store.transition_status("i3", "pending", "approved", "alice") is True
        # Second caller still expects "pending" → conditional check fails → False.
        assert store.transition_status("i3", "pending", "approved", "bob") is False
        got = store.get_intent("i3")
        assert got is not None
        assert got.approvedBy == "alice"  # unchanged

    def test_executed_transition_stamps_executed_at_and_extends_ttl(self, table_name):
        """The approved→executed transition stamps executedAt and extends the item TTL
        past the short approval window so the executed intent stays flaggable (#193)."""
        from datetime import datetime, timezone

        from safe_agents.broker.approval.store import EXECUTED_INTENT_RETENTION_DAYS

        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i-exec"))
        # The approval-window TTL from _intent's expiry (2026-06-28) is long past.
        approval_ttl = int(_raw_item("INTENT#i-exec")["ttl"])

        assert store.transition_status("i-exec", "pending", "approved", "alice") is True
        executed_at = "2026-07-14T12:00:00+00:00"
        assert (
            store.transition_status(
                "i-exec", "approved", "executed", executed_at=executed_at
            )
            is True
        )

        got = store.get_intent("i-exec")
        assert got is not None
        assert got.status == "executed"
        assert got.executedAt == executed_at
        raw = _raw_item("INTENT#i-exec")
        new_ttl = int(raw["ttl"])
        # Extended to executedAt + retention days, beyond the original approval-window TTL.
        assert new_ttl > approval_ttl
        executed_epoch = int(
            datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        )
        assert new_ttl == executed_epoch + EXECUTED_INTENT_RETENTION_DAYS * 86400

    def test_retention_ttl_is_exactly_executed_at_plus_seven_days(self, table_name):
        """Class-D pin (sa#213): ttl == executedAt + exactly 7 days, epoch arithmetic,
        anchored to the EXECUTION timestamp — the same anchor the /flag false_action
        back-write keys off. Fixed inputs reproduce the 2026-07-16 live dev-table scan
        (executedAt 2026-07-14T18:21:52Z → ttl 2026-07-21T18:21:52Z, exact); before
        the sa#213 fix the ttl derived from the store's OWN clock, so the observed
        equality was a same-second race, not an invariant."""
        from datetime import datetime, timezone

        from safe_agents.broker.approval.store import EXECUTED_INTENT_RETENTION_DAYS

        store = DynamoIntentStore(table_name, hmac_key=_INTENT_KEY)
        store.put_intent(_intent("i-pin"))
        assert store.transition_status("i-pin", "pending", "approved", "alice") is True

        executed_at = "2026-07-14T18:21:52Z"  # the live scan's observed stamp
        assert (
            store.transition_status("i-pin", "approved", "executed", executed_at=executed_at)
            is True
        )

        expected = int(datetime(2026, 7, 21, 18, 21, 52, tzinfo=timezone.utc).timestamp())
        assert int(_raw_item("INTENT#i-pin")["ttl"]) == expected
        # 7 days is exactly 604800 seconds — a timedelta carry, never calendar math.
        assert expected - int(
            datetime(2026, 7, 14, 18, 21, 52, tzinfo=timezone.utc).timestamp()
        ) == EXECUTED_INTENT_RETENTION_DAYS * 86400


# ===========================================================================
# DynamoDBGrantStore (grants) — HMAC round-trip + quarantine on key mismatch.
# ===========================================================================

_GRANT_PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")

_GRANT_BASE = dict(
    principal=_GRANT_PRINCIPAL,
    actionClass="email.send",
    level="in-loop",
    envelopeHash="sha256:abc",
    promotedBy="alice",
    evidence="evidence-ref-001",
    ts=_TS,
    lastSafeLevel="in-loop",
    demotionTriggers=["stale_confidence"],
    demotionReason=None,
    labelLatency="P1D",
    ownerId="alice",
)

_KEY_A = b"hmac-key-a"
_KEY_B = b"hmac-key-b"


class TestDynamoDBGrantStore:
    def test_put_then_get_same_key_not_quarantined(self, table_name):
        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        result = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert result.grant is not None
        assert result.quarantined is False
        assert result.grant.ownerId == "alice"
        assert result.grant.actionClass == "email.send"
        # The item-level hash is the HMAC over the stored bytes (#246).
        assert result.stored_hash == compute_grant_hash(result.grant, _KEY_A)

    def test_get_absent_returns_none(self, table_name):
        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        result = store.get_grant(_GRANT_PRINCIPAL, "nonexistent.class")
        assert result.grant is None
        assert result.quarantined is False

    def test_different_hmac_key_reads_back_quarantined(self, table_name):
        """A reader with a different HMAC key recomputes a different hash than
        the one stored, so the record is quarantined (returned for audit, never
        authoritative)."""
        writer = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        writer.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        reader = DynamoDBGrantStore(hmac_key=_KEY_B, table_name=table_name)
        result = reader.get_grant(_GRANT_PRINCIPAL, "email.send")

        assert result.grant is None  # unverified bytes are never parsed (#246)
        assert result.raw_data is not None  # the bytes ride for audit
        assert result.quarantined is True
        assert result.quarantine_reason is not None

    # -- update_grant: the real ConditionExpression against real DynamoDB ----

    def test_update_grant_succeeds_when_hash_matches(self, table_name):
        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())
        current = store.get_grant(_GRANT_PRINCIPAL, "email.send")

        updated = current.grant.model_copy(update={"ownerId": "bob"})
        store.update_grant(
            updated, current.stored_hash, boto3.Session(), prev_raw_data=current.raw_data
        )

        after = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert not after.quarantined  # hash recomputed on write
        assert after.grant.ownerId == "bob"

    def test_update_grant_conflict_on_stale_hash(self, table_name):
        from safe_agents.broker.grants.store import GrantUpdateConflictError

        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())
        current = store.get_grant(_GRANT_PRINCIPAL, "email.send")

        # Concurrent modification lands between read and write
        store.put_grant(
            Grant(**{**_GRANT_BASE, "ownerId": "mallory"}), session=boto3.Session()
        )

        updated = current.grant.model_copy(update={"ownerId": "bob"})
        with pytest.raises(GrantUpdateConflictError):
            store.update_grant(
                updated, current.stored_hash, boto3.Session(), prev_raw_data=current.raw_data
            )

        # The conditional write must not have landed
        after = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert after.grant.ownerId == "mallory"

    def test_update_grant_never_creates_item(self, table_name):
        from safe_agents.broker.grants.store import GrantUpdateConflictError

        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        with pytest.raises(GrantUpdateConflictError):
            store.update_grant(
                Grant(**_GRANT_BASE), "any-hash", boto3.Session(), prev_raw_data="{}"
            )
        assert store.get_grant(_GRANT_PRINCIPAL, "email.send").grant is None

    def test_item_without_granthash_reads_quarantined(self, table_name):
        """The pre-#246 legacy fallback is RETIRED: an item missing its
        grantHash attribute cannot be verified, reads back quarantined
        (grant=None), and is not updatable — the remedy is the re-seed
        ceremony, failing toward less authority."""
        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        # Strip grantHash to reproduce the unverifiable item shape
        table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
        table.update_item(
            Key={"pk": "GRANT#agent-1#email#alice#B", "sk": "CLASS#email.send"},
            UpdateExpression="REMOVE grantHash",
        )

        current = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert current.quarantined is True
        assert current.grant is None
        assert current.raw_data is not None  # bytes ride for audit

    def test_update_grant_refuses_data_tamper_with_intact_granthash(self, table_name):
        """The quarantine race: a tamper of the 'data' payload alone (the
        grantHash attribute untouched) landing between a guarded re-read and
        the write must FAIL the conditional write — a hash-only condition
        would pass and silently overwrite the tamper evidence."""
        from safe_agents.broker.grants.store import GrantUpdateConflictError

        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())
        current = store.get_grant(_GRANT_PRINCIPAL, "email.send")

        # Tamper the data payload directly, leaving grantHash as-is.
        table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
        table.update_item(
            Key={"pk": "GRANT#agent-1#email#alice#B", "sk": "CLASS#email.send"},
            UpdateExpression="SET #data = :tampered",
            ExpressionAttributeNames={"#data": "data"},
            ExpressionAttributeValues={
                ":tampered": current.raw_data.replace('"alice"', '"mallory"')
            },
        )

        updated = current.grant.model_copy(update={"ownerId": "bob"})
        with pytest.raises(GrantUpdateConflictError):
            store.update_grant(
                updated, current.stored_hash, boto3.Session(), prev_raw_data=current.raw_data
            )
        # The tampered item stands for audit (and reads back quarantined).
        after = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert after.quarantined

    # -- create_grant: the real attribute_not_exists condition (#190) --------

    def test_create_grant_creates_and_reads_back(self, table_name):
        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.create_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        result = store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert result.grant is not None
        assert not result.quarantined

    def test_create_grant_never_overwrites(self, table_name):
        from safe_agents.broker.grants.store import GrantAlreadyExistsError

        store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        store.create_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        with pytest.raises(GrantAlreadyExistsError):
            store.create_grant(
                Grant(**{**_GRANT_BASE, "ownerId": "mallory"}), session=boto3.Session()
            )
        # The original stands untouched.
        assert store.get_grant(_GRANT_PRINCIPAL, "email.send").grant.ownerId == "alice"


# ===========================================================================
# DynamoDBPromotionRecordStore — the append-only ceremony ledger, co-located
# in the grants table as RECORD# items. Proves the real attribute_not_exists
# condition (append-only), chronological Query, and coexistence with GRANT#.
# ===========================================================================


# Record ts must be canonical (+00:00, never 'Z') — put_record rejects
# non-canonical ts (#191), unlike grant/other fixtures that keep using _TS.
_RECORD_TS = "2026-06-28T00:00:00+00:00"


def _record(ts: str = _RECORD_TS, record_type: str = "bootstrap") -> PromotionRecord:
    return PromotionRecord.model_validate(
        {
            "recordType": record_type,
            "actionClass": "email.send",
            "principal": _PRINCIPAL_DICT,
            "fromLevel": None if record_type == "bootstrap" else "on-loop",
            "toLevel": "in-loop",
            "evidence": "evidence-ref-001",
            "proposedBy": "alice",
            "ratifiedBy": "alice",
            "envelopeHash": "sha256:abc",
            "ts": ts,
        }
    )


class TestDynamoDBPromotionRecordStore:
    def test_put_then_list_round_trip(self, table_name):
        store = DynamoDBPromotionRecordStore(table_name=table_name)
        record = _record()
        store.put_record(record, session=boto3.Session())

        records = store.list_records(_GRANT_PRINCIPAL, "email.send")
        assert records == [record]

    def test_list_is_chronological(self, table_name):
        store = DynamoDBPromotionRecordStore(table_name=table_name)
        later = _record(ts="2026-06-29T00:00:00+00:00", record_type="tightening")
        earlier = _record(ts="2026-06-28T00:00:00+00:00")
        store.put_record(later, session=boto3.Session())  # inserted out of order
        store.put_record(earlier, session=boto3.Session())

        records = store.list_records(_GRANT_PRINCIPAL, "email.send")
        assert [r.ts for r in records] == [
            "2026-06-28T00:00:00+00:00",
            "2026-06-29T00:00:00+00:00",
        ]

    def test_list_ts_prefix_returns_only_matching_day(self, table_name):
        """The runner's same-day dedupe read: begins_with(sk, :prefix) against
        the real Query evaluator returns only records whose ts starts with the
        UTC-day prefix."""
        store = DynamoDBPromotionRecordStore(table_name=table_name)
        store.put_record(_record(ts="2026-06-28T01:00:00+00:00"), session=boto3.Session())
        store.put_record(
            _record(ts="2026-06-29T01:00:00+00:00", record_type="tightening"),
            session=boto3.Session(),
        )

        same_day = store.list_records(
            _GRANT_PRINCIPAL, "email.send", boto3.Session(), ts_prefix="2026-06-28"
        )
        assert [r.ts for r in same_day] == ["2026-06-28T01:00:00+00:00"]

    def test_append_only_never_overwrites(self, table_name):
        from safe_agents.broker.grants.store import RecordAlreadyExistsError

        store = DynamoDBPromotionRecordStore(table_name=table_name)
        store.put_record(_record(), session=boto3.Session())

        with pytest.raises(RecordAlreadyExistsError):
            store.put_record(_record(), session=boto3.Session())
        assert len(store.list_records(_GRANT_PRINCIPAL, "email.send")) == 1

    def test_list_absent_returns_empty(self, table_name):
        store = DynamoDBPromotionRecordStore(table_name=table_name)
        assert store.list_records(_GRANT_PRINCIPAL, "nonexistent.class") == []

    def test_put_record_signature_attribute_round_trip(self, table_name):
        """The optional DSSE envelope is stored as a `signature` attribute JSON
        string on the SAME ledger item — beside the record blob, never a field
        on the PromotionRecord schema — and its presence changes nothing about
        what list_records returns."""
        import json

        store = DynamoDBPromotionRecordStore(table_name=table_name)
        record = _record()
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": "eyJfdHlwZSI6ICJ0ZXN0In0=",
            "signatures": [{"keyid": "issuer-key-1", "sig": "c2ln"}],
        }
        store.put_record(record, session=boto3.Session(), signature=envelope)

        raw = _raw_item(
            "RECORD#agent-1#email#alice#B#email.send", f"{record.ts}#{record.recordType}"
        )
        assert raw is not None
        assert json.loads(raw["signature"]) == envelope
        assert store.list_records(_GRANT_PRINCIPAL, "email.send") == [record]

    def test_put_record_without_signature_writes_no_attribute(self, table_name):
        """The unsigned append stays byte-for-byte the pre-signing item shape."""
        store = DynamoDBPromotionRecordStore(table_name=table_name)
        record = _record()
        store.put_record(record, session=boto3.Session())

        raw = _raw_item(
            "RECORD#agent-1#email#alice#B#email.send", f"{record.ts}#{record.recordType}"
        )
        assert raw is not None
        assert "signature" not in raw

    def test_coexists_with_grant_items(self, table_name):
        """RECORD# and GRANT# items for the same principal share one table
        without collision — the item-type prefix keeps them apart."""
        grant_store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        grant_store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        record_store = DynamoDBPromotionRecordStore(table_name=table_name)
        record_store.put_record(_record(), session=boto3.Session())

        grant_result = grant_store.get_grant(_GRANT_PRINCIPAL, "email.send")
        assert grant_result.grant is not None
        assert not grant_result.quarantined
        assert len(record_store.list_records(_GRANT_PRINCIPAL, "email.send")) == 1


# ===========================================================================
# DynamoDBProposalStore (#123) — durable promotion proposals, co-located in
# the grants table as PROPOSAL# items. Proves the real put condition
# (append-only content) and the real consume condition (single-shot status
# flip — the double-ratify race) against moto's expression evaluator.
# ===========================================================================


def _proposal(proposal_id: str = "prop-001"):
    from safe_agents.broker.grants.ceremony import PromotionCeremony
    from safe_agents.broker.grants.predicate import ActionClassMetrics
    from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger
    from safe_agents.broker.schemas.evidence import (
        ConfidenceArtifact,
        SelfConsistencyEvidence,
    )

    return PromotionCeremony.propose_promotion(
        _GRANT_PRINCIPAL,
        "email.send",
        AutonomyLevel.on_loop,
        "evidence-ref-001",
        "human-proposer",
        proposal_id=proposal_id,
        expires_at="2026-08-01T00:00:00+00:00",
        owner_id="alice",
        from_level=AutonomyLevel.in_loop,
        envelope_hash="sha256:abc",
        label_latency="P1D",
        demotion_triggers=[DemotionTrigger.stale_confidence],
        last_safe_level=AutonomyLevel.in_loop,
        metrics=ActionClassMetrics(
            false_action_count=0, human_override_count=0, observation_count=50
        ),
        window_n=100,
        min_observations=10,
        threshold=0.05,
        artifact=ConfidenceArtifact(
            confidence=0.9,
            error_prob=0.1,
            evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
            computed_at="2026-07-12T00:00:00+00:00",
        ),
        covered=True,
        provenance_maturity="signed-lineage",
        blast_class="low",
        error_budget=None,
    )


class TestDynamoDBProposalStore:
    def _store(self, table_name):
        from safe_agents.broker.grants.proposals import DynamoDBProposalStore

        return DynamoDBProposalStore(hmac_key=_KEY_A, table_name=table_name)

    def test_put_then_get_round_trip(self, table_name):
        store = self._store(table_name)
        proposal = _proposal()
        store.put_proposal(proposal, session=boto3.Session())

        result = store.get_proposal(_GRANT_PRINCIPAL, "email.send", "prop-001")
        assert result is not None
        restored, status = result
        assert restored == proposal
        assert status == "pending"

    def test_put_never_overwrites(self, table_name):
        from safe_agents.broker.grants.proposals import ProposalAlreadyExistsError

        store = self._store(table_name)
        store.put_proposal(_proposal(), session=boto3.Session())
        with pytest.raises(ProposalAlreadyExistsError):
            store.put_proposal(_proposal(), session=boto3.Session())

    def test_consume_is_single_shot(self, table_name):
        """The real pending-only ConditionExpression kills the double-ratify race."""
        from safe_agents.broker.grants.proposals import ProposalConsumedError

        store = self._store(table_name)
        store.put_proposal(_proposal(), session=boto3.Session())

        store.consume_proposal(
            _GRANT_PRINCIPAL, "email.send", "prop-001", "ratified", session=boto3.Session()
        )
        _, status = store.get_proposal(_GRANT_PRINCIPAL, "email.send", "prop-001")
        assert status == "ratified"

        with pytest.raises(ProposalConsumedError):
            store.consume_proposal(
                _GRANT_PRINCIPAL, "email.send", "prop-001", "rejected", session=boto3.Session()
            )

    def test_consume_absent_raises(self, table_name):
        from safe_agents.broker.grants.proposals import ProposalConsumedError

        store = self._store(table_name)
        with pytest.raises(ProposalConsumedError):
            store.consume_proposal(
                _GRANT_PRINCIPAL, "email.send", "prop-ghost", "ratified", session=boto3.Session()
            )

    def test_list_pending_filters_consumed(self, table_name):
        store = self._store(table_name)
        store.put_proposal(_proposal("prop-a"), session=boto3.Session())
        store.put_proposal(_proposal("prop-b"), session=boto3.Session())
        store.consume_proposal(
            _GRANT_PRINCIPAL, "email.send", "prop-b", "rejected", session=boto3.Session()
        )

        pending = store.list_pending(_GRANT_PRINCIPAL, "email.send")
        assert [p.proposal_id for p in pending] == ["prop-a"]

    def test_get_refuses_tampered_data(self, table_name):
        """A PROPOSAL# item's data edited in the table (its hash attribute
        untouched) is refused loudly on read — the real item, real tamper."""
        from safe_agents.broker.grants.proposals import ProposalIntegrityError

        store = self._store(table_name)
        store.put_proposal(_proposal(), session=boto3.Session())

        table = boto3.resource("dynamodb", region_name=REGION).Table(table_name)
        item = table.get_item(
            Key={"pk": "PROPOSAL#agent-1#email#alice#B#email.send", "sk": "prop-001"}
        )["Item"]
        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #data = :tampered",
            ExpressionAttributeNames={"#data": "data"},
            ExpressionAttributeValues={
                ":tampered": item["data"].replace('"on-loop"', '"out-of-loop"')
            },
        )

        with pytest.raises(ProposalIntegrityError, match="hash mismatch"):
            store.get_proposal(_GRANT_PRINCIPAL, "email.send", "prop-001")


# ===========================================================================
# DynamoDBEnvelopeStore (sa#136 Phase 3 Slice A) — co-located in the SAME
# table as grants, as a distinct "ENVELOPE#" item type. Proves the two item
# types coexist in one real (moto-backed) table without collision, and that
# a Grant's real GRANT# item is untouched by an ENVELOPE# write for the same
# principal.
# ===========================================================================


class TestDynamoDBEnvelopeStore:
    def test_put_then_get_round_trip(self, table_name):
        store = DynamoDBEnvelopeStore(table_name=table_name)
        envelope = Envelope.model_validate(
            {
                "polarity": "abstain",
                "caps": {"actions_per_run": 1},
                "allowlists": {"tools": ["snapshot.read"]},
                "high_stakes": False,
            }
        )
        store.put_envelope(_GRANT_PRINCIPAL, envelope, session=boto3.Session())

        got = store.get_envelope(_GRANT_PRINCIPAL)
        assert got is not None
        assert got.polarity == "abstain"
        assert got.caps.actions_per_utc_day == 1
        assert got.allowlists.tools == ["snapshot.read"]

    def test_get_absent_returns_none(self, table_name):
        store = DynamoDBEnvelopeStore(table_name=table_name)
        assert store.get_envelope(_GRANT_PRINCIPAL) is None

    def test_coexists_with_grant_for_same_principal(self, table_name):
        """A GRANT# item and an ENVELOPE# item for the SAME principal, in the
        SAME table, must not collide — proving the item-type prefix is what
        keeps them apart, not accidental key separation."""
        grant_store = DynamoDBGrantStore(hmac_key=_KEY_A, table_name=table_name)
        grant_store.put_grant(Grant(**_GRANT_BASE), session=boto3.Session())

        envelope_store = DynamoDBEnvelopeStore(table_name=table_name)
        envelope = Envelope.model_validate({"polarity": "act", "high_stakes": True})
        envelope_store.put_envelope(_GRANT_PRINCIPAL, envelope, session=boto3.Session())

        grant_result = grant_store.get_grant(_GRANT_PRINCIPAL, "email.send")
        envelope_result = envelope_store.get_envelope(_GRANT_PRINCIPAL)

        assert grant_result.grant is not None
        assert not grant_result.quarantined
        assert envelope_result is not None
        assert envelope_result.polarity == "act"
        assert envelope_result.high_stakes is True
