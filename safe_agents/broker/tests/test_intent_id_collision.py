"""Two held calls in one clock tick must get two intent ids (#38).

Every hold used to be written under its intent id with a blind put, in all
three intent store backends. When two holds from one turn shared an id, the
second silently replaced the first pending intent: both callers were told the same id, and
approving it released only the call written last. Windows CI hit this because its
wall clock advances about every 15.6 ms.

These tests freeze the PEP's clock so every call lands in one tick, which is the
worst case on any platform, and run against each intent store backend.

The last group is defence in depth (#39): with the #38 stamp defeated, so two
holds DO share an id, the store refuses to overwrite the pending intent and the
PEP denies the second call on the tape instead of holding it.
"""

from __future__ import annotations

import datetime as dt
import types
from collections.abc import Iterator

import pytest

import safe_agents.broker.runtime.pep as pep_module
from safe_agents.broker.approval import (
    InMemoryIntentStore,
    IntentAlreadyPendingError,
    materialize,
)
from safe_agents.broker.approval.queue_guard import dedup_intent_id
from safe_agents.broker.approval.sqlite_store import SqliteIntentStore
from safe_agents.broker.audit import InMemorySink, hash_args
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
from safe_agents.broker.schemas.decision import RenderedIntent, RequireApproval
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


# ---------------------------------------------------------------------------
# #39: the store refuses to overwrite a pending intent when ids DO collide
# ---------------------------------------------------------------------------


@pytest.fixture
def colliding_runtime(intent_store, monkeypatch):
    """A runtime whose #38 stamp is defeated: every call gets one ts, so one id."""
    runtime, connector = _runtime(intent_store)
    fixed_ts = _FROZEN_NOW.isoformat()
    monkeypatch.setattr(runtime, "_stamp_call_ts", lambda: fixed_ts)
    return runtime, connector


def test_colliding_hold_is_denied_on_the_tape_and_first_hold_survives(
    intent_store, colliding_runtime
) -> None:
    runtime, connector = colliding_runtime
    r1 = _hold(runtime, _ARGS_A, "k1")
    r2 = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args=_ARGS_B, idempotency_key="k2")
    )

    # The second call is not held: it is denied, naming the id it collided on.
    assert r2.decision_kind == "deny"
    assert r2.intent_id is None
    assert r2.reason == f"{pep_module.INTENT_ID_COLLISION_REASON}: {r1.intent_id}"
    last = runtime._audit_sink.records()[-1]
    assert (last.decision, last.outcome) == ("deny", "denied")
    assert last.intentId == r1.intent_id
    assert last.reason == r2.reason

    # The first hold is intact and releases exactly its own call.
    stored = intent_store.get_intent(r1.intent_id)
    assert stored.status == "pending"
    assert stored.materializedRequest.args == _ARGS_A
    result = runtime.approve_intent(r1.intent_id, approved_by="owner@example")
    assert result.executed, result.rejection_reason
    assert [c.args for c in connector.calls] == [_ARGS_A]


def test_colliding_hold_after_first_resolves_is_held(intent_store, colliding_runtime) -> None:
    """Only a PENDING intent blocks the id; once it resolves, the id is reusable."""
    runtime, _ = colliding_runtime
    r1 = _hold(runtime, _ARGS_A, "k1")
    rejected = runtime.reject_intent(r1.intent_id, "owner@example")
    assert rejected.rejection_reason == "rejected by owner"
    r2 = _hold(runtime, _ARGS_B, "k2")
    assert r2.intent_id == r1.intent_id
    assert intent_store.get_intent(r2.intent_id).materializedRequest.args == _ARGS_B


def _require_approval(intent_id: str) -> RequireApproval:
    return RequireApproval(
        kind="require_approval",
        reason="held",
        renderedIntent=RenderedIntent(id=intent_id, renderedForHuman="rendered"),
    )


class _PendingCheckMisses:
    """The dedup race: materialize's pending check reads nothing, as if the
    first hold landed between that read and this put. The put hits the store."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def get_intent(self, intent_id: str):  # noqa: ARG002 (the race: the read misses)
        return None

    def put_intent(self, intent) -> None:
        self._inner.put_intent(intent)


def test_dedup_race_past_the_pending_check_coalesces(intent_store) -> None:
    """Under dedup the id is content-derived, so a refused put is an identical
    hold that won the race: coalesce, never raise, never notify twice."""
    runtime, _ = _runtime(intent_store, ApprovalQueue(dedup=True))
    r1 = _hold(runtime, _ARGS_A, "k1")
    held = intent_store.get_intent(r1.intent_id)
    call = held.materializedRequest
    dedup_id = dedup_intent_id(call.principal, call.tool, call.op, hash_args(call.args))
    assert dedup_id == r1.intent_id

    notified: list = []
    approval = materialize(
        call,
        _require_approval("intent-ts-based"),
        _PendingCheckMisses(intent_store),
        notifier=notified.append,
        dedup_id=dedup_id,
    )
    assert (approval.status, approval.intent_id) == ("coalesced", dedup_id)
    assert notified == []
    assert intent_store.get_intent(dedup_id).ts == held.ts


def test_without_dedup_a_refused_put_propagates_from_materialize(intent_store) -> None:
    """materialize() never reports a hold it did not make, and never notifies for it."""
    runtime, _ = _runtime(intent_store)
    r1 = _hold(runtime, _ARGS_A, "k1")
    other = intent_store.get_intent(r1.intent_id).materializedRequest.model_copy(
        update={"args": _ARGS_B}
    )

    notified: list = []
    with pytest.raises(IntentAlreadyPendingError):
        materialize(
            other, _require_approval(r1.intent_id), intent_store, notifier=notified.append
        )
    assert notified == []
    assert intent_store.get_intent(r1.intent_id).materializedRequest.args == _ARGS_A
