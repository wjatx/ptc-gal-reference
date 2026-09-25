"""Two held calls in one clock tick must get two intent ids (#38).

Every hold is written under its intent id with a blind put, in all three intent
store backends. When two holds from one turn shared an id, the second silently
replaced the first pending intent: both callers were told the same id, and
approving it released only the call written last. Windows CI hit this because its
wall clock advances about every 15.6 ms.

These tests freeze the PEP's clock so every call lands in one tick, which is the
worst case on any platform, and run against each intent store backend.
"""

from __future__ import annotations

import datetime as dt
import types
from collections.abc import Iterator

import pytest

import safe_agents.broker.runtime.pep as pep_module
from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.sqlite_store import SqliteIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.schemas import ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.envelope import ApprovalQueue
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
)

_FROZEN_NOW = dt.datetime(2026, 9, 24, 12, 0, 0, tzinfo=dt.UTC)
_HMAC_KEY = b"intent-collision-test-key"
_DYNAMO_TABLE = "intent-collision"
_DYNAMO_REGION = "us-east-1"

_ARGS_A = {"amount": 100, "to": "acct-a"}
_ARGS_B = {"amount": 999, "to": "acct-b"}


class _FrozenDatetime(dt.datetime):
    """A datetime whose now() never advances: every call lands in one tick."""

    @classmethod
    def now(cls, tz=None):  # noqa: ARG003 (signature mirrors datetime.now)
        return _FROZEN_NOW


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze only the PEP's view of the clock, the source of BrokeredCall.ts."""
    monkeypatch.setattr(
        pep_module,
        "datetime",
        types.SimpleNamespace(
            datetime=_FrozenDatetime,
            UTC=dt.UTC,
            timedelta=dt.timedelta,
            timezone=dt.timezone,
        ),
    )


def _dynamo_store(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    pytest.importorskip("moto", reason="moto is required for the DynamoDB backend")
    boto3 = pytest.importorskip("boto3", reason="boto3 is required for the DynamoDB backend")
    from moto import mock_aws  # noqa: PLC0415 (optional dev dependency)

    from safe_agents.broker.approval.store import DynamoIntentStore  # noqa: PLC0415

    for name, value in {
        "AWS_DEFAULT_REGION": _DYNAMO_REGION,
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
    }.items():
        monkeypatch.setenv(name, value)
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=_DYNAMO_REGION)
        ddb.create_table(
            TableName=_DYNAMO_TABLE,
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
        yield DynamoIntentStore(_DYNAMO_TABLE, hmac_key=_HMAC_KEY)


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def intent_store(request, tmp_path, monkeypatch) -> Iterator[object]:
    if request.param == "memory":
        yield InMemoryIntentStore(hmac_key=_HMAC_KEY)
    elif request.param == "sqlite":
        yield SqliteIntentStore(tmp_path / "intents.db", hmac_key=_HMAC_KEY)
    else:
        yield from _dynamo_store(monkeypatch)


def _runtime(intent_store, approval_queue: ApprovalQueue | None = None):
    """A runtime whose payments.transfer is external + irreversible, so every call holds."""
    connector = StubConnector()
    runtime = BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("payments.transfer", level=AutonomyLevel.on_loop)],
        optable=ToolOpTable(
            [ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False)]
        ),
        doer=Doer(
            connectors={"payments": connector},
            secrets=FakeSecretsProvider({"payments": "cred-payments"}),
        ),
        pip=make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        enforcement_store=InMemoryStore(),
        intent_store=intent_store,
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        approval_queue=approval_queue,
    )
    return runtime, connector


def _hold(runtime, args: dict, idempotency_key: str):
    response = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args=args, idempotency_key=idempotency_key)
    )
    assert response.decision_kind == "require_approval"
    return response


@pytest.mark.usefixtures("frozen_clock")
@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param((_ARGS_A, "k1"), (_ARGS_B, "k2"), id="different_args"),
        pytest.param((_ARGS_A, "k1"), (_ARGS_A, "k2"), id="identical_args"),
        # A retry under the same key re-holds: enforce() releases the claim on a
        # hold (#148), so the replay is a fresh hold, never an idempotent replay.
        pytest.param((_ARGS_A, "k1"), (_ARGS_A, "k1"), id="same_key_retry"),
    ],
)
def test_holds_in_one_tick_get_distinct_ids_and_each_releases_its_own_call(
    intent_store, first, second
) -> None:
    runtime, connector = _runtime(intent_store)
    r1 = _hold(runtime, *first)
    r2 = _hold(runtime, *second)

    assert r1.intent_id != r2.intent_id
    assert not r2.idempotent
    for response, (args, _) in ((r1, first), (r2, second)):
        stored = intent_store.get_intent(response.intent_id)
        assert stored.status == "pending"
        assert stored.materializedRequest.args == args

    # Each approval releases exactly the call it was issued for, in either order.
    for response, (args, _) in ((r2, second), (r1, first)):
        result = runtime.approve_intent(response.intent_id, approved_by="owner@example")
        assert result.executed, result.rejection_reason
        assert connector.calls[-1].args == args
    assert len(connector.calls) == 2


@pytest.mark.usefixtures("frozen_clock")
def test_dedup_on_still_coalesces_identical_calls_in_one_tick(intent_store) -> None:
    """The dedup knob maps identical calls onto one id, and #38 must not undo that."""
    runtime, _ = _runtime(intent_store, ApprovalQueue(dedup=True))
    r1 = _hold(runtime, _ARGS_A, "k1")
    r2 = _hold(runtime, _ARGS_A, "k2")
    r3 = _hold(runtime, _ARGS_B, "k3")
    assert r1.intent_id == r2.intent_id
    assert r3.intent_id != r1.intent_id


@pytest.mark.usefixtures("frozen_clock")
def test_call_ts_is_strictly_increasing_when_the_clock_stands_still() -> None:
    runtime, _ = _runtime(InMemoryIntentStore(hmac_key=_HMAC_KEY))
    stamps = [dt.datetime.fromisoformat(runtime._stamp_call_ts()) for _ in range(3)]
    assert stamps[0] == _FROZEN_NOW
    assert stamps == sorted(set(stamps))
    assert stamps[-1] - stamps[0] == dt.timedelta(microseconds=2)
