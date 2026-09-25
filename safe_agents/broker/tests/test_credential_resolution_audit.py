"""A credential that fails to resolve is audited like any other execution failure (#35).

The gate allowed the call; the Doer then could not obtain the connector's credential.
Before #35 the resolution ran outside the try that turns connector failures into a
ConnectorExecutionError, so the exception escaped `handle_request` and the allowed
call left no audit record, only a WAL intent.

What these pin:
  * exactly one record, `decision=allow, outcome=failed`, whose `error` names the
    secret leaf, the strategy and the exception TYPE;
  * no credential material and no foreign backend message on the tape, the WAL or
    the reply (a base-authored CredentialStrategyError message is kept: the base
    writes those never to interpolate a token, and they carry the diagnosis);
  * the idempotency behaviour is the connector failure's, not a new one: the key is
    burned and a retry under it is refused, never replayed and never re-attempted;
  * the wiring defects the Doer already raises (no connector registered, a
    non-permitted decision) are NOT converted into audited failures.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    CredentialResolutionError,
    CredentialStrategyError,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.runtime.doer import ConfinementError
from safe_agents.broker.schemas import BrokeredCall, Session, Taint, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.decision import Allow, Deny
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, PRINCIPAL, make_grant, make_pip

_TOOL = "calendar"
_OP = "create_event"
# Present in the secrets store under a DIFFERENT leaf, and embedded in every
# injected failure message, so a leak of either kind would show up on the tape.
_SENTINEL = "cred-sentinel-7f3a9c"
_BACKEND_DETAIL = "/var/run/secrets/broker.json"


class _RaisingSecrets:
    """A secrets backend that fails with a message carrying detail it should not."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def fetch_secret(self, secret_name: str) -> str:  # noqa: ARG002
        raise self._exc


class _RaisingStrategy:
    """A CredentialProvider whose resolve() fails (a mint or assume that broke)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    def resolve(self, *, secrets, secret_name):  # noqa: ANN001, ARG002
        self.calls += 1
        raise self._exc


def _missing_leaf():
    return {"secrets": FakeSecretsProvider({"other-leaf": _SENTINEL})}


def _backend_error():
    return {
        "secrets": _RaisingSecrets(
            RuntimeError(f"backend refused {_SENTINEL} reading {_BACKEND_DETAIL}")
        )
    }


def _strategy_error():
    # A base-authored message (the shape credentials.py raises for a failed
    # token exchange); it is kept verbatim because the base vouches for it.
    return {
        "strategy": _RaisingStrategy(
            CredentialStrategyError(
                "oauth_refresh token exchange with 'https://idp.example/token' "
                "failed: URLError"
            )
        )
    }


def _strategy_foreign_error():
    # A strategy (or injected fetcher) that lets a foreign exception out, with
    # credential material in its message: only the type may survive.
    return {"strategy": _RaisingStrategy(ValueError(f"bad grant {_SENTINEL}"))}


def _build(*, secrets=None, strategy=None, connector=None):
    store = InMemoryStore()
    sink = InMemorySink()
    connector = connector or StubConnector(result={"event_id": "evt-35"})
    doer = Doer(
        connectors={_TOOL: connector},
        secrets=secrets or FakeSecretsProvider({_TOOL: _SENTINEL}),
        credential_strategies={_TOOL: strategy} if strategy is not None else None,
    )
    runtime = BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant(f"{_TOOL}.{_OP}", level=AutonomyLevel.out_of_loop)],
        optable=ToolOpTable(
            [ToolOp(tool=_TOOL, op=_OP, effect="write", external=False, reversible=True)]
        ),
        doer=doer,
        pip=make_pip(grant_level=AutonomyLevel.out_of_loop),
        enforcement_store=store,
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )
    return runtime, sink, store, connector


def _request(key: str | None = None) -> AgentRequest:
    return AgentRequest(
        tool=_TOOL, op=_OP, args={"title": "t35"}, idempotency_key=key
    )


_FAILURES = [
    pytest.param(
        _missing_leaf,
        ("StaticSecret", f"secret leaf {_TOOL!r}", ": KeyError"),
        ("unknown secret",),
        id="missing-secret-leaf",
    ),
    pytest.param(
        _backend_error,
        ("StaticSecret", f"secret leaf {_TOOL!r}", ": RuntimeError"),
        (_BACKEND_DETAIL, "backend refused"),
        id="secrets-backend-error",
    ),
    pytest.param(
        _strategy_error,
        (
            "_RaisingStrategy",
            "CredentialStrategyError: oauth_refresh token exchange",
            "failed: URLError",
        ),
        (),
        id="strategy-error-keeps-base-authored-message",
    ),
    pytest.param(
        _strategy_foreign_error,
        ("_RaisingStrategy", ": ValueError"),
        ("bad grant",),
        id="strategy-foreign-error-keeps-type-only",
    ),
]


@pytest.mark.parametrize(("arrange", "present", "absent"), _FAILURES)
def test_credential_failure_is_one_failed_allow_record(arrange, present, absent) -> None:
    runtime, sink, store, connector = _build(**arrange())

    # The tape is checked BEFORE anything is said about the exception, so the
    # pre-#35 shape fails on the missing record rather than on the escape.
    escaped: Exception | None = None
    try:
        response = runtime.handle_request(_request())
    except Exception as exc:  # noqa: BLE001 — asserted on below
        escaped, response = exc, None

    records = sink.records()
    assert len(records) == 1, (
        f"an allowed call whose credential failed must leave exactly one audit "
        f"record; got {len(records)} (handle_request raised "
        f"{type(escaped).__name__ if escaped else 'nothing'})"
    )
    assert escaped is None, f"handle_request must reply, not raise {escaped!r}"
    record = records[0]
    assert (record.decision, record.outcome) == ("allow", "failed")
    error = record.error or ""
    assert error.startswith(
        f"connector {_TOOL!r} op {_OP!r} failed: credential could not be resolved"
    ), error
    for fragment in present:
        assert fragment in error, (fragment, error)
    for fragment in absent:
        assert fragment not in error, (fragment, error)

    # No credential material anywhere it could travel: the tape, the WAL, the reply.
    assert _SENTINEL not in record.model_dump_json()
    assert _SENTINEL not in repr(list(store._ledger.values()))
    assert _SENTINEL not in repr(response)

    # The reply is the connector-failure shape, so a mouth frames it the same way.
    assert response.decision_kind == "deny"
    assert response.execution_outcome == "failed"
    assert len(connector.calls) == 0, "the connector must not run without a credential"
    [entry] = store._ledger.values()
    assert entry.status == "compensated"  # reversible op: the saga compensated


class _Breaker:
    def execute(self, tool, op, args, credential):  # noqa: ANN001, ARG002
        raise TimeoutError("upstream went away")


@pytest.mark.parametrize(
    "arrange",
    [
        pytest.param(lambda: {"connector": _Breaker()}, id="connector-failure"),
        pytest.param(_missing_leaf, id="credential-failure"),
    ],
)
def test_retry_under_the_same_key_is_refused_like_a_connector_failure(arrange) -> None:
    """Parity with the connector case: the key is burned, a retry is refused.

    Not replayed as `failed`, and not re-attempted: the retry is a gate deny
    naming the uncertain earlier attempt, and never reaches the Doer again.
    """
    runtime, sink, _, _ = _build(**arrange())

    first = runtime.handle_request(_request("k-35"))
    second = runtime.handle_request(_request("k-35"))

    assert first.execution_outcome == "failed"
    assert second.decision_kind == "deny"
    assert second.execution_outcome is None
    assert "already attempted" in (second.reason or "")
    assert _SENTINEL not in (second.reason or "")
    # The refusal is audited as a gate deny; there is no second allow record,
    # which is what a re-attempt would have written.
    assert [(r.decision, r.outcome) for r in sink.records()] == [
        ("allow", "failed"),
        ("deny", "denied"),
    ]


def test_retry_does_not_resolve_the_credential_again() -> None:
    strategy = _RaisingStrategy(CredentialStrategyError("mint failed"))
    runtime, _, _, _ = _build(strategy=strategy)

    runtime.handle_request(_request("k-35b"))
    runtime.handle_request(_request("k-35b"))

    assert strategy.calls == 1


def _call(tool: str = _TOOL) -> BrokeredCall:
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=tool,
        op=_OP,
        args={},
        manifest=ToolOp(tool=tool, op=_OP, effect="write", external=False, reversible=True),
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="test-credential-resolution", ingestedSources=[]),
        ts="2026-09-24T00:00:00Z",
    )


@pytest.mark.parametrize(
    ("tool", "decision", "expected", "match"),
    [
        pytest.param(
            "nope",
            Allow(kind="allow"),
            ValueError,
            "no connector registered",
            id="no-connector-registered",
        ),
        pytest.param(
            _TOOL,
            Deny(kind="deny", reason="x"),
            ConfinementError,
            "non-permitted decision",
            id="non-permitted-decision",
        ),
    ],
)
def test_wiring_defects_are_not_converted(tool, decision, expected, match) -> None:
    """Those are different defects from a credential failure and stay loud.

    The secrets store is empty, so a conversion would have had a failure to wrap.
    """
    doer = Doer(connectors={_TOOL: StubConnector(result={})}, secrets=FakeSecretsProvider({}))
    call = _call(tool)  # built outside raises(): a ValidationError IS a ValueError

    with pytest.raises(expected, match=match) as excinfo:
        doer.execute(call, decision)

    assert not isinstance(excinfo.value, CredentialResolutionError)
