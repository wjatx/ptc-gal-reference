"""The age of fetched inputs at each decision point that reads one (#176).

Companion to ``test_input_age.py``, which pins the rule on the broker's own
decision. This file pins the properties that rule's documents state about WHEN
an instant is read and HOW the check fails, and the two decision points that sit
outside the PEP's own reads:

  BEFORE      a fetch instant is read before the read it stamps, never after;
  FAIL-CLOSED an error while checking ages refuses, and never reads as fresh;
  REVALIDATE  the age is checked again at enforce()'s premise revalidation;
  DELEGATION  the delegation store's read is an input of its own;
  BOUNDED     a declared age is bounded at load, and an age large enough to
              overflow an instant is clamped, never raised mid-decision;
  DRAIN       the drain worker's key carries its cold-start instant;
  MCP         the MCP host's two-key admission snapshot is an input: its as-of
              rides the decision's record, and past a declared age the host
              fetches it again before gating the call.

In-memory fakes throughout; a hand-advanced clock stands in for elapsed time.
"""

from __future__ import annotations

import asyncio
import datetime
from typing import Any

import pydantic
import pytest
import yaml

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.delegation.store import InMemorySubGrantStore
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.mcp.discovery import ToolState
from safe_agents.broker.mcp.factory import SupervisedMcpHost
from safe_agents.broker.mcp.host import McpHost, ToolNotCallableError
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.pdp import Facts
from safe_agents.broker.prototype import boot_config
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.runtime.input_age import DecisionInputs, InputAgePolicy
from safe_agents.broker.schemas import AgentManifest, ToolOp
from safe_agents.broker.schemas.common import MAX_DECLARABLE_AGE_SECONDS, AutonomyLevel
from safe_agents.broker.schemas.decision import Allow
from safe_agents.broker.schemas.mcp_registry import (
    McpServerDecl,
    McpToolDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH
from safe_agents.broker.tests.test_input_age import (
    _PRINCIPAL,
    _PRINCIPAL_DATA,
    _READ,
    SEC,
    T0,
    _call,
    _Clock,
    _grant,
    _manifest,
    _runtime,
    _startup_at,
)
from safe_agents.broker.taint import build_trust_map
from safe_agents.connectors.mcp_connector import McpConnector

# The reason prefixes the contract documents name (broker/SCHEMAS.md). Spelled out
# here, never imported, so a change to the constant cannot pass by changing both.
_DOCUMENTED_PAST_AGE_PREFIX = "input past maximum age: "
_DOCUMENTED_CHECK_FAILED_PREFIX = "input age check failed: "


# ---------------------------------------------------------------------------
# BEFORE — the fetch instant precedes the read it stamps
# ---------------------------------------------------------------------------


def test_before_the_manifest_fetch_instant_is_read_before_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(_manifest().model_dump_json(), encoding="utf-8")
    clock = _Clock(T0)
    real_load = yaml.safe_load

    def _slow_read(text: str) -> Any:
        clock.now = T0 + 3600 * SEC  # the read takes an hour
        return real_load(text)

    monkeypatch.setattr(boot_config.yaml, "safe_load", _slow_read)
    manifest = boot_config.load_agent_manifest(path, clock=clock)
    assert manifest._fetched_at == T0


def test_before_a_timed_read_is_stamped_with_the_instant_it_began() -> None:
    clock = _Clock(T0)
    inputs = DecisionInputs(InputAgePolicy(), clock)

    def _slow_read(arg: Any) -> str:
        clock.now = T0 + 30 * SEC
        return "facts"

    assert inputs.timed(_slow_read, ("grant",))(None) == "facts"
    assert inputs.audit_fields()["inputs_as_of"] == {"grant": T0.isoformat()}


# ---------------------------------------------------------------------------
# FAIL-CLOSED — an error while checking refuses, with the documented reason
# ---------------------------------------------------------------------------


def test_fail_closed_an_error_in_the_age_check_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    inputs = DecisionInputs(InputAgePolicy.from_seconds(_startup_at(T0), {}), _Clock())

    def _broken(now: datetime.datetime) -> list:
        raise RuntimeError("age check broke")

    monkeypatch.setattr(inputs, "stale", _broken)
    decided: list = []

    def _allow(call: Any, facts: Any) -> Allow:
        decided.append(call)
        return Allow(kind="allow")

    decision = inputs.gate(_allow)("call", "facts")
    assert decision.kind == "deny"
    assert decision.reason == f"{_DOCUMENTED_CHECK_FAILED_PREFIX}RuntimeError"
    assert decided == []  # the decider is never consulted on a refusal


def test_fail_closed_the_documented_reason_prefix_names_the_input() -> None:
    clock = _Clock()
    runtime, sink, _, _, _ = _runtime(clock=clock, startup=_startup_at(T0), max_age={"hmac_key": 5})
    clock.now = T0 + 5 * SEC
    response = _call(runtime)
    assert response.reason.startswith(f"{_DOCUMENTED_PAST_AGE_PREFIX}hmac_key (as of ")
    assert sink.records()[-1].reason == response.reason


# ---------------------------------------------------------------------------
# REVALIDATE — enforce()'s premise revalidation is gated too
# ---------------------------------------------------------------------------


def test_revalidate_an_input_that_ages_out_between_decision_and_revalidation_refuses() -> None:
    """The PIP runs for the initial decision and again for revalidation. Time
    passes during the second read, so the envelope crosses its age between the
    initial (gated) decision and the revalidation (which must be gated too)."""
    clock = _Clock(T0 + 59 * SEC)
    reads: list[datetime.datetime] = []

    def _pip(call: Any) -> Facts:
        reads.append(clock.now)
        if len(reads) == 2:
            clock.now = T0 + 60 * SEC  # the revalidation read lands on the horizon
        return Facts(
            grant_present=True,
            grant_level=AutonomyLevel.on_loop,
            error_budget_breached=False,
            cap_budget_breached=False,
            escalation_budget_available=True,
            human_reachable=True,
            transform_op=None,
        )

    connector = _Counting()
    store = InMemoryStore()
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_grant("calendar.list")],
        optable=ToolOpTable([_READ]),
        doer=Doer(
            connectors={"calendar": connector},
            secrets=FakeSecretsProvider({"calendar": "cred"}),
        ),
        pip=_pip,
        enforcement_store=store,
        intent_store=InMemoryIntentStore(),
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        input_ages=InputAgePolicy.from_seconds(_startup_at(T0), {"envelope": 60}),
        clock=clock,
    )
    response = _call(runtime)
    assert len(reads) == 2  # the initial read passed the gate; revalidation ran
    assert response.decision_kind == "deny"
    assert response.reason.startswith(f"{_DOCUMENTED_PAST_AGE_PREFIX}envelope")
    assert connector.count == 0


class _Counting:
    def __init__(self) -> None:
        self.count = 0

    def execute(self, tool, op, args, credential):  # noqa: ANN001, ANN201
        self.count += 1
        return {"ok": True}


# ---------------------------------------------------------------------------
# DELEGATION — the delegation store is an input where delegation is on
# ---------------------------------------------------------------------------


@pytest.fixture
def _memory_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "BROKER_STORE",
        "BROKER_AUDIT_BUCKET",
        "BROKER_AUDIT_PATH",
        "BROKER_SECRETS",
        "BROKER_GRANT_LOAD",
        "BROKER_ENVELOPE_LOAD",
    ):
        monkeypatch.delenv(var, raising=False)


def test_delegation_store_read_is_recorded_and_bounds_the_horizon(_memory_arm: None) -> None:
    clock = _Clock()
    runtime, sink = build_runtime(
        _manifest(input_max_age_seconds={"sub_grants": 30}),
        sub_grant_store=InMemorySubGrantStore(),
        clock=clock,
    )
    clock.now = T0 + 7 * SEC
    _call(runtime)
    record = sink.records()[-1]
    assert record.inputsAsOf["sub_grants"] == (T0 + 7 * SEC).isoformat()
    assert record.horizon == (T0 + 37 * SEC).isoformat()


def test_delegation_off_records_no_delegation_input(_memory_arm: None) -> None:
    runtime, sink = build_runtime(_manifest(), clock=_Clock())
    _call(runtime)
    assert "sub_grants" not in sink.records()[-1].inputsAsOf


# ---------------------------------------------------------------------------
# BOUNDED — the declared age, at load and in the arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "accepted"),
    [(MAX_DECLARABLE_AGE_SECONDS, True), (MAX_DECLARABLE_AGE_SECONDS + 1, False), (10**12, False)],
)
def test_bounded_a_declared_age_above_the_ceiling_is_refused_at_load(seconds, accepted) -> None:
    if accepted:
        assert _manifest(input_max_age_seconds={"envelope": seconds})
    else:
        with pytest.raises(pydantic.ValidationError, match="largest declarable age"):
            _manifest(input_max_age_seconds={"envelope": seconds})


def test_bounded_an_overflowing_end_is_clamped_and_the_decision_is_recorded() -> None:
    """A policy built in code skips the manifest's ceiling. An end past the last
    representable instant is no bound, and the decision is still recorded."""
    clock = _Clock()
    runtime, sink, connector, _, _ = _runtime(
        clock=clock, startup=_startup_at(T0), max_age={"envelope": 10**12}
    )
    response = _call(runtime)
    assert response.decision_kind == "allow"
    assert connector.count == 1
    assert sink.records()[-1].horizon.startswith("9999-12-31T23:59:59")


# ---------------------------------------------------------------------------
# DRAIN — the key's as-of is the cold start's, with or without an ARN
# ---------------------------------------------------------------------------


def test_drain_a_key_from_the_environment_is_stamped_once_at_cold_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from safe_agents.broker.prototype import broker_server
    from safe_agents.channels.drain import handler as h

    monkeypatch.delenv("BROKER_HMAC_KEY_SECRET_ARN", raising=False)
    monkeypatch.setenv("BROKER_HMAC_KEY", "env-key")
    monkeypatch.setattr(h, "_HMAC_KEY_FETCHED_AT", None)

    before = datetime.datetime.now(datetime.UTC)
    h._resolve_hmac_key()
    after = datetime.datetime.now(datetime.UTC)
    stamped = h._HMAC_KEY_FETCHED_AT
    assert stamped is not None and before <= stamped <= after

    seen: list = []
    monkeypatch.setattr(
        broker_server,
        "build_runtime",
        lambda manifest, **kwargs: (seen.append(kwargs["input_as_of"]), (object(), None))[1],
    )
    h._build_runtime(_manifest())
    h._build_runtime(_manifest())
    # Every per-record runtime carries the one cold-start instant, so a declared
    # hmac_key age fires on the drain as it does on the service.
    assert [given["hmac_key"].as_of for given in seen] == [stamped, stamped]


# ---------------------------------------------------------------------------
# MCP — the two-key admission snapshot is a fetched input
# ---------------------------------------------------------------------------

_SERVER = "calc"
_TOOL = "add"
_MCP_OP = ToolOp(tool=_SERVER, op=_TOOL, effect="read", external=True, reversible=True)
_TOOL_DEF = McpToolDef(
    server_id=_SERVER,
    tool_name=_TOOL,
    input_schema={"type": "object"},
    description="Add two integers.",
)


class _FakeClient:
    """An SDK-free stand-in for ``McpClient``: advertises one tool, counts calls."""

    def __init__(self, clock: _Clock, *, advance_on_list: datetime.timedelta | None = None):
        self.server_id = _SERVER
        self.calls = 0
        self.lists = 0
        self.list_fails = False
        self._clock = clock
        self._advance = advance_on_list

    async def list_tool_defs(self) -> list[McpToolDef]:
        self.lists += 1
        if self.list_fails:
            raise ConnectionError("server unreachable")
        if self._advance is not None:
            self._clock.now += self._advance
        return [_TOOL_DEF]

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls += 1
        return {"sum": 5}


def _admitted_registry() -> MemoryToolRegistry:
    registry = MemoryToolRegistry()
    registry.admit_tool(
        RegisteredTool(
            tool_def=_TOOL_DEF,
            def_hash=compute_tool_def_hash(_TOOL_DEF),
            status=RegistryStatus.ACTIVE,
            admitted_by="arn:aws:sts::000000000000:assumed-role/Admitter/test",
            admitted_at="2026-07-17T00:00:00Z",
        )
    )
    return registry


def _withdraw(registry: MemoryToolRegistry) -> None:
    """The registry row is removed after the spawn: key #2 no longer activates."""
    del registry._rows[(_SERVER, _TOOL)]


_DECL = McpServerDecl(tools=[McpToolDecl(tool_name=_TOOL)])


def _mcp_runtime(
    clock: _Clock, host: McpHost, level: AutonomyLevel = AutonomyLevel.on_loop
) -> tuple[BrokerRuntime, InMemorySink, McpConnector]:
    sink = InMemorySink()
    connector = McpConnector(host)
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_grant(f"{_SERVER}.{_TOOL}")],
        optable=ToolOpTable([_MCP_OP]),
        doer=Doer(connectors={_SERVER: connector}, secrets=FakeSecretsProvider({})),
        pip=lambda call: Facts(
            grant_present=True,
            grant_level=level,
            error_budget_breached=False,
            cap_budget_breached=False,
            escalation_budget_available=True,
            human_reachable=True,
            transform_op=None,
        ),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        input_ages=InputAgePolicy.from_seconds(_startup_at(T0), {}),
        clock=clock,
    )
    return runtime, sink, connector


def _mcp_call(runtime: BrokerRuntime):
    return runtime.handle_request(AgentRequest(tool=_SERVER, op=_TOOL, args={"a": 2, "b": 3}))


def test_mcp_the_snapshot_as_of_rides_the_record_across_the_connector_thread() -> None:
    clock = _Clock(T0)
    registry = _admitted_registry()
    client = _FakeClient(clock, advance_on_list=5 * SEC)  # discovery takes 5s
    host = McpHost(_DECL, registry, client, clock=clock)
    asyncio.run(host.refresh())
    assert host.snapshot_fetched_at == T0  # read before the advertised list

    runtime, sink, connector = _mcp_runtime(clock, host)
    try:
        clock.now = T0 + 20 * SEC
        assert _mcp_call(runtime).decision_kind == "allow"
        executed = sink.records()[-1]
        assert executed.outcome == "executed"
        assert executed.inputsAsOf["mcp_admission"] == T0.isoformat()

        _withdraw(registry)  # no age declared: the snapshot lasts the session
        assert _mcp_call(runtime).decision_kind == "allow"
        assert client.calls == 2
    finally:
        connector.close()


def test_mcp_past_its_age_the_snapshot_is_fetched_again_before_the_gate() -> None:
    clock = _Clock(T0)
    registry = _admitted_registry()
    client = _FakeClient(clock)
    host = McpHost(_DECL, registry, client, max_age=60 * SEC, clock=clock)
    asyncio.run(host.refresh())
    runtime, sink, connector = _mcp_runtime(clock, host)
    try:
        _withdraw(registry)
        clock.now = T0 + 59 * SEC
        assert _mcp_call(runtime).decision_kind == "allow"  # within its age
        assert client.lists == 1

        clock.now = T0 + 60 * SEC
        response = _mcp_call(runtime)
        assert response.decision_kind == "deny"
        assert response.execution_outcome == "refused"
        assert client.lists == 2  # discovery ran again
        assert client.calls == 1  # the withdrawn tool was not reached
        refused = sink.records()[-1]
        assert refused.outcome == "refused"
        assert ToolState.DECLARED.value in refused.error
        assert refused.inputsAsOf["mcp_admission"] == (T0 + 60 * SEC).isoformat()
    finally:
        connector.close()


def test_mcp_a_release_records_the_snapshot_its_connector_call_was_gated_on() -> None:
    clock = _Clock(T0)
    host = McpHost(_DECL, _admitted_registry(), _FakeClient(clock), clock=clock)
    asyncio.run(host.refresh())
    runtime, sink, connector = _mcp_runtime(clock, host, AutonomyLevel.in_loop)
    try:
        held = _mcp_call(runtime)
        assert held.decision_kind == "require_approval"
        assert "mcp_admission" not in sink.records()[-1].inputsAsOf  # nothing reached
        clock.now = T0 + 30 * SEC
        assert runtime.approve_intent(held.intent_id, approved_by="owner:x").executed
        release = sink.records()[-1]
        assert release.outcome == "executed"
        assert release.inputsAsOf["mcp_admission"] == T0.isoformat()
    finally:
        connector.close()


def test_mcp_a_refetch_that_fails_makes_no_call() -> None:
    clock = _Clock(T0)
    client = _FakeClient(clock)
    host = McpHost(_DECL, _admitted_registry(), client, max_age=60 * SEC, clock=clock)
    asyncio.run(host.refresh())
    client.list_fails = True
    clock.now = T0 + 60 * SEC
    with pytest.raises(ConnectionError):
        asyncio.run(host.call(_TOOL, {}))
    assert client.calls == 0


def test_mcp_no_snapshot_establishes_nothing_and_refuses() -> None:
    clock = _Clock(T0)
    inputs = DecisionInputs(InputAgePolicy(), clock)
    host = McpHost(_DECL, _admitted_registry(), _FakeClient(clock), clock=clock)
    with inputs.bound(), pytest.raises(ToolNotCallableError):
        asyncio.run(host.call(_TOOL, {}))
    assert inputs.audit_fields()["inputs_as_of"] is None


class _FakeSupervised(SupervisedMcpHost):
    def __init__(self, client: _FakeClient, **kwargs: Any) -> None:
        super().__init__(_SERVER, server_decl=_DECL, registry=_admitted_registry(), **kwargs)
        self._client = client

    def _open_client(self):  # noqa: ANN202
        import contextlib

        @contextlib.asynccontextmanager
        async def _ctx():
            yield self._client

        return _ctx()


def test_mcp_a_supervised_host_hands_the_declared_age_to_every_generation() -> None:
    async def scenario() -> datetime.timedelta | None:
        supervised = _FakeSupervised(_FakeClient(_Clock()), admission_max_age=60 * SEC)
        await supervised.start()
        try:
            return supervised.inner._max_age
        finally:
            await supervised.aclose()

    assert asyncio.run(scenario()) == 60 * SEC


def test_mcp_construction_reads_the_declared_age_from_the_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from safe_agents.broker.prototype import mcp_construction

    monkeypatch.delenv("BROKER_STORE", raising=False)
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "registry-table")
    seen: dict = {}

    def _capture(*args: Any, **kwargs: Any):
        seen.update(kwargs)

        async def factory():
            return None

        return factory

    monkeypatch.setattr(mcp_construction, "stdio_host_factory", _capture)
    manifest = AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
            "principal": _PRINCIPAL_DATA,
            "grant_classes": [f"{_SERVER}.{_TOOL}"],
            "connectors": [_SERVER],
            "tool_ops": [_MCP_OP.model_dump()],
            "mcp_servers": {
                _SERVER: {"command": "calc-server", "tools": [{"tool_name": _TOOL}]}
            },
            "input_max_age_seconds": {"mcp_admission": 90},
        }
    )
    connectors = mcp_construction.build_mcp_connectors(
        manifest, secrets=FakeSecretsProvider({}), credential_strategies={},
        secret_name_for=lambda name: name,
    )
    asyncio.run(connectors[_SERVER]._factory())
    assert seen["admission_max_age"] == 90 * SEC

