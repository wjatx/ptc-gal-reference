"""SDK-free conformance suite for the MCP child lifecycle — M17–M21 (#221 P3).

The lifecycle clauses (MCP-HOST.md §"Child lifecycle") are contract-tier and
none of their logic touches the `mcp` SDK: `SupervisedStdioHost` drives a
transport it reaches through `client.connect_stdio`, so a fake async context
manager standing in for one spawned child exercises every branch — typed death
(M17), reconnect-as-new-discovery (M18), ships-OFF respawn (M19), and
reap-before-loop-close (M20) — with zero child processes. The remote clause
(M21) rides the same shared supervision body: the streamable-HTTP tests fake
`client.connect_streamable_http` the same way and pin that every lifecycle
clause carries over to a remote session unchanged. The real-transport half
(SIGKILL a live child, real reap assertions) lives in `test_mcp_stdio.py`
behind the `stdio` mark.

The fake death exception carries ``__module__ = "anyio"`` deliberately: the
contract's transport-death family is "an anyio stream-closure out of a call"
(a killed child does not wake the parked driver — it just closes the streams),
and this simulates exactly that signal without importing anyio.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest

from safe_agents.broker.mcp import client as _client_mod
from safe_agents.broker.mcp.factory import (
    McpChildDeathError,
    SupervisedStdioHost,
    SupervisedStreamableHttpHost,
    _is_transport_death,
    stdio_host_factory,
)
from safe_agents.broker.mcp.host import ToolNotCallableError
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.prototype.mcp_construction import McpConstructionError
from safe_agents.broker.schemas.mcp_registry import (
    McpRespawnPolicy,
    McpServerDecl,
    McpToolDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)

_SERVER_ID = "faketool"
_DECL = McpServerDecl(
    tools=[McpToolDecl(tool_name="alpha"), McpToolDecl(tool_name="beta")]
)
_TOOL_NAMES = ["alpha", "beta"]


class _FakeTransportDeath(Exception):
    """Stands in for anyio's stream-closure family (see module docstring)."""


_FakeTransportDeath.__module__ = "anyio"


class _FakeChild:
    """One fake spawned child: a client until killed, then a dead pipe."""

    def __init__(self, server_id: str, tool_names: list[str]) -> None:
        self.server_id = server_id
        self._tool_names = tool_names
        self.killed = False
        self.exited = False  # context unwound — the reap marker

    async def list_tool_defs(self) -> list[McpToolDef]:
        if self.killed:
            raise _FakeTransportDeath("stream closed")
        return [
            McpToolDef(
                server_id=self.server_id,
                tool_name=name,
                input_schema={"type": "object"},
                description=f"fake {name}",
            )
            for name in self._tool_names
        ]

    async def call_tool(self, tool_name: str, arguments=None):
        if self.killed:
            raise _FakeTransportDeath("stream closed")
        return {"tool": tool_name, "args": arguments or {}}


class _Spawns:
    """Log of every fake spawn: the children and the env each one received."""

    def __init__(self) -> None:
        self.children: list[_FakeChild] = []
        self.envs: list[dict | None] = []

    @property
    def count(self) -> int:
        return len(self.children)

    @property
    def current(self) -> _FakeChild:
        return self.children[-1]


def _fake_transport(
    monkeypatch,
    *,
    tool_names_for_spawn=lambda i: _TOOL_NAMES,
    fail_spawn=lambda i: False,
) -> _Spawns:
    """Patch `client.connect_stdio` with a controllable fake child transport."""
    spawns = _Spawns()

    @asynccontextmanager
    async def fake_connect(server_id, command, args=None, *, cwd=None, env=None):
        index = spawns.count
        if fail_spawn(index):
            spawns.envs.append(env)
            spawns.children.append(_FakeChild(server_id, []))
            spawns.current.exited = True
            raise OSError(f"fake spawn {index} refused")
        child = _FakeChild(server_id, tool_names_for_spawn(index))
        spawns.children.append(child)
        spawns.envs.append(env)
        try:
            yield child
        finally:
            child.exited = True

    monkeypatch.setattr(_client_mod, "connect_stdio", fake_connect)
    return spawns


def _admit(registry: MemoryToolRegistry, tool_names=_TOOL_NAMES) -> None:
    for name in tool_names:
        tool_def = McpToolDef(
            server_id=_SERVER_ID,
            tool_name=name,
            input_schema={"type": "object"},
            description=f"fake {name}",
        )
        registry.admit_tool(
            RegisteredTool(
                tool_def=tool_def,
                def_hash=compute_tool_def_hash(tool_def),
                status=RegistryStatus.ACTIVE,
                admitted_by="arn:aws:sts::000000000000:assumed-role/Admitter/test",
                admitted_at="2026-07-19T00:00:00Z",
            )
        )


def _supervised(registry: MemoryToolRegistry, **kwargs) -> SupervisedStdioHost:
    return SupervisedStdioHost(
        _SERVER_ID,
        "fake-command",
        [],
        server_decl=_DECL,
        registry=registry,
        **kwargs,
    )


# -- M17: child death is a typed failure --------------------------------------


def test_m17_spawn_failure_is_typed_with_real_cause(monkeypatch):
    """A first spawn that cannot connect raises `McpChildDeathError` with the
    real error on __cause__ — typed, nothing less diagnosable than raw."""
    _fake_transport(monkeypatch, fail_spawn=lambda i: True)

    async def scenario():
        with pytest.raises(McpChildDeathError) as exc:
            await _supervised(MemoryToolRegistry()).start()
        assert exc.value.server_id == _SERVER_ID
        assert isinstance(exc.value.__cause__, OSError)

    asyncio.run(scenario())


def test_m17_mid_call_death_is_typed_with_cause_chained(monkeypatch):
    """A transport-closure exception out of a call wraps as the typed death
    error (the killed-child-never-wakes-the-driver path), cause chained."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(registry).start()
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError) as exc:
            await host.call("alpha", {})
        assert isinstance(exc.value.__cause__, _FakeTransportDeath)

    asyncio.run(scenario())


def test_m17_construction_refusal_is_not_wrapped(monkeypatch):
    """A boot-time wiring refusal (`McpConstructionError` out of the env
    provider) is a refusal, not a child death — it propagates as itself."""
    _fake_transport(monkeypatch)

    async def refusing_env():
        raise McpConstructionError("credential has no field 'KEY'")

    async def scenario():
        supervised = _supervised(MemoryToolRegistry(), env_provider=refusing_env)
        with pytest.raises(McpConstructionError, match="no field 'KEY'"):
            await supervised.start()

    asyncio.run(scenario())


def test_m17_admission_refusal_passes_through_untyped(monkeypatch):
    """`ToolNotCallableError` is an admission verdict, never a death — the
    lifecycle wrapper must not swallow or re-type it."""
    _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()  # nothing admitted → everything uncallable

    async def scenario():
        host = await _supervised(registry).start()
        with pytest.raises(ToolNotCallableError):
            await host.call("alpha", {})

    asyncio.run(scenario())


def test_m17_sdk_connection_closed_error_is_typed_death(monkeypatch):
    """The SDK's `McpError: Connection closed` shape (how a real session
    reports a dead child when its reader saw EOF first — observed live against
    alpaca-mcp-server) wraps typed; any OTHER McpError stays a call error."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    class McpError(Exception):  # name-matched by the contract, faked SDK-free
        pass

    async def scenario():
        host = await _supervised(registry).start()
        client = spawns.current

        async def dead_call(tool_name, arguments=None):
            raise McpError("Connection closed")

        client.call_tool = dead_call  # type: ignore[method-assign]
        with pytest.raises(McpChildDeathError) as exc:
            await host.call("alpha", {})
        assert isinstance(exc.value.__cause__, McpError)

    asyncio.run(scenario())


def test_m17_other_protocol_error_is_not_a_death(monkeypatch):
    """A non-connection McpError is a genuine call error: it propagates as
    itself and the session stays live (no death recorded, no respawn)."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    class McpError(Exception):
        pass

    async def scenario():
        host = await _supervised(registry).start()
        client = spawns.current
        original = client.call_tool

        async def flaky_call(tool_name, arguments=None):
            client.call_tool = original  # one-shot protocol error
            raise McpError("Invalid params")

        client.call_tool = flaky_call  # type: ignore[method-assign]
        with pytest.raises(McpError, match="Invalid params"):
            await host.call("alpha", {})
        # The session survived: the same child answers the next call.
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        assert spawns.count == 1

    asyncio.run(scenario())


# -- M19: respawn is data and ships OFF ---------------------------------------


def test_m19_absent_policy_means_no_respawn_and_sticky_typed(monkeypatch):
    """With no respawn block a death is terminal: every later call is the
    typed failure and NO second spawn ever happens (the OFF path is the
    pre-knob behavior)."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(registry).start()
        await host.call("alpha", {})
        spawns.current.killed = True
        for _ in range(3):
            with pytest.raises(McpChildDeathError):
                await host.call("alpha", {})
        assert spawns.count == 1, "the OFF path must never spawn a second child"

    asyncio.run(scenario())


def test_m19_policy_respawns_and_call_flows_again(monkeypatch):
    """With a policy the death triggers a fresh spawn and the call flows —
    exactly max one extra child for a one-death, first-attempt success."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=2, backoff_seconds=0.0)
        ).start()
        await host.call("alpha", {})
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})  # the in-flight death is still typed
        result = await host.call("alpha", {})  # next dispatch respawns
        assert result["tool"] == "alpha"
        assert spawns.count == 2

    asyncio.run(scenario())


def test_m19_exhausted_policy_degrades_to_sticky_typed(monkeypatch):
    """When every respawn attempt fails, the policy exhausts into exactly the
    OFF behavior: typed failure, sticky, no further attempts ever."""
    spawns = _fake_transport(monkeypatch, fail_spawn=lambda i: i >= 1)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=2, backoff_seconds=0.0)
        ).start()
        await host.call("alpha", {})
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})  # the mid-call death itself
        with pytest.raises(McpChildDeathError, match="exhausted"):
            await host.call("alpha", {})  # burns both attempts, exhausts
        assert spawns.count == 3  # 1 good + 2 failed respawns
        with pytest.raises(McpChildDeathError, match="exhausted"):
            await host.call("alpha", {})  # sticky — no retry storm
        assert spawns.count == 3

    asyncio.run(scenario())


def test_m19_respawn_block_requires_spawn_config():
    """A namespace-only declaration carrying a respawn block is refused at
    manifest load — policy for a child the manifest never spawns is dead
    config at best."""
    with pytest.raises(ValueError, match="respawn"):
        McpServerDecl.model_validate(
            {"tools": [], "respawn": {"max_attempts": 1}}
        )


@pytest.mark.parametrize(
    "policy",
    [
        {"max_attempts": 0},
        {"max_attempts": 4},
        {"max_attempts": 1, "backoff_seconds": -1.0},
        {"max_attempts": 1, "backoff_seconds": 11.0},
        {"max_attempts": 3, "backoff_seconds": 10.0},  # burst > 20s
    ],
)
def test_m19_policy_bounds_are_enforced(policy):
    """The burst must fit inside the connector's call-liveness backstop — an
    unbounded policy would resurrect the bare-TimeoutError failure M17 kills."""
    with pytest.raises(ValueError):
        McpRespawnPolicy.model_validate(policy)


# -- M18: a reconnect is a new discovery --------------------------------------


def test_m18_respawn_rereads_registry_and_reruns_discovery(monkeypatch):
    """A registry change while the child was dead governs the respawned
    session: the row deleted between death and respawn makes that tool
    uncallable after reconnect — fresh reads, no verdict carried across."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0)
        ).start()
        await host.call("beta", {})  # ACTIVE under the first snapshot
        spawns.current.killed = True
        del registry._rows[(_SERVER_ID, "beta")]  # the world changed while dead
        with pytest.raises(McpChildDeathError):
            await host.call("beta", {})
        # After the respawn, the fresh discovery refuses beta (no row now) …
        with pytest.raises(ToolNotCallableError):
            await host.call("beta", {})
        # … while alpha, still admitted, flows on the same fresh snapshot.
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        assert spawns.count == 2

    asyncio.run(scenario())


def test_m18_advertised_drift_across_respawn_is_quarantined(monkeypatch):
    """A respawned child advertising a CHANGED tool set is judged as new: a
    tool it no longer advertises refuses, and a renamed advertisement is
    uncallable (no admitted row) — the old session's verdicts are dead."""
    spawns = _fake_transport(
        monkeypatch,
        tool_names_for_spawn=lambda i: _TOOL_NAMES if i == 0 else ["alpha", "gamma"],
    )
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0)
        ).start()
        await host.call("beta", {})
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError):
            await host.call("beta", {})
        with pytest.raises(ToolNotCallableError):
            await host.call("beta", {})  # withdrawn by the respawned child
        with pytest.raises(ToolNotCallableError):
            await host.call("gamma", {})  # newly advertised, never admitted

    asyncio.run(scenario())


def test_m18_env_provider_reresolves_per_spawn(monkeypatch):
    """The credential half is re-resolved on every spawn — a respawn never
    reuses the previous child's environment."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)
    resolutions = []

    async def env_provider():
        resolutions.append(len(resolutions))
        return {"CRED": f"resolution-{len(resolutions) - 1}"}

    async def scenario():
        host = await _supervised(
            registry,
            env_provider=env_provider,
            respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0),
        ).start()
        await host.call("alpha", {})
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})
        await host.call("alpha", {})
        assert resolutions == [0, 1]
        assert spawns.envs == [{"CRED": "resolution-0"}, {"CRED": "resolution-1"}]

    asyncio.run(scenario())


# -- M20: shutdown reaps children before the loop closes -----------------------


def test_m20_aclose_reaps_child_before_returning(monkeypatch):
    """`aclose()` awaits the driver unwind: when it returns, the child's
    context has exited (the reap is proven, not requested) — and later calls
    refuse typed."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(registry).start()
        await host.call("alpha", {})
        assert spawns.current.exited is False
        await host.aclose()
        assert spawns.current.exited is True
        await host.aclose()  # idempotent
        with pytest.raises(McpChildDeathError, match="closing"):
            await host.call("alpha", {})

    asyncio.run(scenario())


def test_m20_connector_close_drives_aclose_before_loop_teardown(monkeypatch):
    """Through the real connector: `close()` drives the supervised host's
    `aclose()` on the loop FIRST, so the child context exits while the loop is
    still alive, and only then is the loop stopped and closed.

    The spy pins the ORDERING, not just the outcome: the generic cancel-pending
    sweep would also unwind the fake's context, so asserting `exited` alone
    would pass with the aclose seam deleted. The spy proves aclose itself ran
    during close() and that the child was already reaped when it returned."""
    from safe_agents.connectors.mcp_connector import McpConnector

    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)
    inner = stdio_host_factory(
        _SERVER_ID,
        "fake-command",
        [],
        server_decl=_DECL,
        registry=registry,
    )
    events: list[tuple[str, bool]] = []

    async def factory():
        host = await inner()
        real_aclose = host.aclose

        async def spy_aclose():
            await real_aclose()
            events.append(("aclose_done", spawns.current.exited))

        host.aclose = spy_aclose  # type: ignore[method-assign]
        return host

    connector = McpConnector(factory)
    try:
        result = connector.execute(_SERVER_ID, "alpha", {}, credential="")
        assert result["tool"] == "alpha"
        assert spawns.current.exited is False
    finally:
        connector.close()
    assert events == [("aclose_done", True)], (
        "close() must drive aclose (and the child must be reaped by the time "
        "it returns) — the cancel-pending sweep alone is not the M20 ordering"
    )
    assert spawns.current.exited is True
    connector.close()  # idempotent


def test_m17_first_spawn_failure_is_typed_but_not_sticky(monkeypatch):
    """A never-connected server may be re-attempted on a later dispatch (the
    pre-knob connector re-invoked its factory the same way): the first failure
    is typed, and the NEXT call spawns again and succeeds."""
    spawns = _fake_transport(monkeypatch, fail_spawn=lambda i: i == 0)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = _supervised(registry)
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        assert spawns.count == 2

    asyncio.run(scenario())


def test_m19_stale_inflight_call_cannot_kill_respawned_child(monkeypatch):
    """Generation scoping: two calls in flight on the same dying child — the
    first death respawns; the second (stale) observer's death handling must
    NOT retire the fresh child. Exactly one respawn happens and the session
    stays live."""
    spawns = _fake_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0)
        ).start()
        await host.call("alpha", {})
        gen1 = spawns.current
        release_b = asyncio.Event()

        async def dying_call(tool_name, arguments=None):
            if tool_name == "beta":  # B: park until AFTER the respawn
                await release_b.wait()
            raise _FakeTransportDeath("stream closed")

        gen1.call_tool = dying_call  # type: ignore[method-assign]
        task_b = asyncio.ensure_future(host.call("beta", {}))
        await asyncio.sleep(0.01)  # B is in flight on gen-1
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})  # A: dies, retires gen-1
        assert (await host.call("alpha", {}))["tool"] == "alpha"  # respawn: gen-2
        assert spawns.count == 2
        # NOW deliver B's stale death — it must not retire the fresh child.
        release_b.set()
        with pytest.raises(McpChildDeathError):
            await task_b  # B's own call still fails typed
        assert (await host.call("alpha", {}))["tool"] == "alpha", (
            "stale observer killed the respawned child"
        )
        assert spawns.count == 2 and spawns.current.exited is False

    asyncio.run(scenario())


def test_m19_burst_deadline_expiry_degrades_typed_and_sticky(monkeypatch):
    """A respawn burst that cannot finish inside its deadline is cancelled and
    degrades to the exhausted OFF behavior — typed and sticky, never the bare
    timeout M17 kills."""
    from safe_agents.broker.mcp import factory as _factory_mod

    monkeypatch.setattr(_factory_mod, "_BURST_DEADLINE_S", 0.05)
    spawns = _fake_transport(monkeypatch, fail_spawn=lambda i: i >= 1)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised(
            registry, respawn=McpRespawnPolicy(max_attempts=3, backoff_seconds=0.1)
        ).start()
        await host.call("alpha", {})
        spawns.current.killed = True
        with pytest.raises(McpChildDeathError):
            await host.call("alpha", {})  # the death itself
        with pytest.raises(McpChildDeathError, match="deadline"):
            await host.call("alpha", {})  # burst trips the deadline
        with pytest.raises(McpChildDeathError):  # sticky thereafter
            await host.call("alpha", {})

    asyncio.run(scenario())


def test_m20_doer_close_drives_every_closeable_connector_and_isolates_failure():
    """The service half of M20: `Doer.close()` calls `close()` on every
    connector that has one, skips those that don't, and one connector's
    failure never blocks another's reap."""
    from safe_agents.broker.runtime import Doer, FakeSecretsProvider

    closed: list[str] = []

    class _Closeable:
        def __init__(self, name: str, fail: bool = False) -> None:
            self._name, self._fail = name, fail

        def execute(self, tool, op, args, credential):
            return None

        def close(self) -> None:
            if self._fail:
                raise RuntimeError("teardown hiccup")
            closed.append(self._name)

    class _PlainConnector:
        def execute(self, tool, op, args, credential):
            return None

    doer = Doer(
        connectors={
            "a": _Closeable("a"),
            "boom": _Closeable("boom", fail=True),
            "plain": _PlainConnector(),
            "z": _Closeable("z"),
        },
        secrets=FakeSecretsProvider({}),
    )
    doer.close()  # must not raise
    assert closed == ["a", "z"], "the failing connector must not block the rest"


# -- factory argument discipline ----------------------------------------------


def test_factory_refuses_env_and_env_provider_together():
    """A static env cannot also be per-spawn resolved — fail at build."""
    with pytest.raises(ValueError, match="env OR env_provider"):
        stdio_host_factory(
            _SERVER_ID,
            "fake-command",
            [],
            server_decl=_DECL,
            registry=MemoryToolRegistry(),
            env={"A": "B"},
            env_provider=lambda: None,  # type: ignore[arg-type]
        )


# -- M21: the streamable-HTTP transport rides the same lifecycle ---------------


class _FakeHttpxDeath(Exception):
    """Stands in for httpx's connect/read error family — how the SDK's
    streamable-HTTP client surfaces a dead or unreachable remote peer.
    Module-matched by `_is_transport_death`, faked SDK-free."""


_FakeHttpxDeath.__module__ = "httpx"


def _fake_http_transport(
    monkeypatch,
    *,
    tool_names_for_connect=lambda i: _TOOL_NAMES,
    fail_connect=lambda i: False,
) -> _Spawns:
    """Patch `client.connect_streamable_http` with a controllable fake peer.

    Reuses `_FakeChild`/`_Spawns`: one "spawn" is one ENTERED connect context
    (a reconnect re-enters it fresh — M18/M21), and `envs` records the headers
    each connect received (the static plumbing half, the http mirror of the
    stdio env log)."""
    spawns = _Spawns()

    @asynccontextmanager
    async def fake_connect(server_id, url, *, headers=None):
        index = spawns.count
        if fail_connect(index):
            spawns.envs.append(headers)
            spawns.children.append(_FakeChild(server_id, []))
            spawns.current.exited = True
            raise _FakeHttpxDeath(f"fake connect {index} refused")
        child = _FakeChild(server_id, tool_names_for_connect(index))
        spawns.children.append(child)
        spawns.envs.append(headers)
        try:
            yield child
        finally:
            child.exited = True

    monkeypatch.setattr(_client_mod, "connect_streamable_http", fake_connect)
    return spawns


def _supervised_http(registry: MemoryToolRegistry, **kwargs) -> SupervisedStreamableHttpHost:
    return SupervisedStreamableHttpHost(
        _SERVER_ID,
        "http://fake.invalid/mcp",
        server_decl=_DECL,
        registry=registry,
        **kwargs,
    )


def test_m21_http_first_connect_failure_is_typed_with_real_cause(monkeypatch):
    """M17 over http: a first connect that cannot reach the peer raises
    `McpChildDeathError` with the real transport error on __cause__."""
    _fake_http_transport(monkeypatch, fail_connect=lambda i: True)

    async def scenario():
        with pytest.raises(McpChildDeathError) as exc:
            await _supervised_http(MemoryToolRegistry()).start()
        assert exc.value.server_id == _SERVER_ID
        assert isinstance(exc.value.__cause__, _FakeHttpxDeath)

    asyncio.run(scenario())


def test_m21_http_mid_call_death_typed_then_sticky_without_policy(monkeypatch):
    """M17+M19 over http: a mid-call httpx-family error wraps as the typed
    death (cause chained), and with respawn=None the next dispatch is the
    sticky typed failure — no reconnect ever happens (the OFF path)."""
    spawns = _fake_http_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised_http(registry).start()
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        client = spawns.current

        async def dead_call(tool_name, arguments=None):
            raise _FakeHttpxDeath("connection reset by peer")

        client.call_tool = dead_call  # type: ignore[method-assign]
        with pytest.raises(McpChildDeathError) as exc:
            await host.call("alpha", {})
        assert isinstance(exc.value.__cause__, _FakeHttpxDeath)
        with pytest.raises(McpChildDeathError, match="respawn"):
            await host.call("alpha", {})
        assert spawns.count == 1, "the OFF path must never re-enter the connect context"

    asyncio.run(scenario())


def test_m21_http_reconnect_reenters_context_and_reruns_discovery(monkeypatch):
    """M18/M25 over http: with a policy, a death re-ENTERS the connect context
    and re-runs refresh — a registry row deleted while the session was dead is
    refused by the fresh discovery, and the headers_provider is re-invoked so
    the new session carries a FRESHLY resolved credential.

    The differing values are the point, not incidental: an expired access token
    surfaces as a transport death, so re-minting on reconnect is the only
    re-auth path there is. A static header dict would pass a
    "headers were supplied" assertion while leaving that path untested.
    """
    spawns = _fake_http_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)
    minted = iter(["token-1", "token-2", "token-3"])

    async def headers_provider():
        return {"Authorization": f"Bearer {next(minted)}"}

    async def scenario():
        host = await _supervised_http(
            registry,
            headers_provider=headers_provider,
            respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0),
        ).start()
        await host.call("beta", {})  # ACTIVE under the first snapshot
        spawns.current.killed = True
        del registry._rows[(_SERVER_ID, "beta")]  # the world changed while dead
        with pytest.raises(McpChildDeathError):
            await host.call("beta", {})
        # After the reconnect, the fresh discovery refuses beta (no row now) …
        with pytest.raises(ToolNotCallableError):
            await host.call("beta", {})
        # … while alpha, still admitted, flows on the same fresh snapshot.
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        assert spawns.count == 2, "the reconnect must re-enter the connect context"
        assert spawns.children[0].exited is True, "the dead generation was exited"
        assert spawns.envs == [
            {"Authorization": "Bearer token-1"},
            {"Authorization": "Bearer token-2"},
        ], "the reconnect must re-resolve the credential, not replay the dead one"

    asyncio.run(scenario())


def test_m21_http_aclose_exits_connect_context_before_returning(monkeypatch):
    """M20 over http: `aclose()` awaits the driver unwind — when it returns,
    the connect context has exited (the disconnect is proven, not requested)
    and later calls refuse typed."""
    spawns = _fake_http_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised_http(registry).start()
        await host.call("alpha", {})
        assert spawns.current.exited is False
        await host.aclose()
        assert spawns.current.exited is True
        await host.aclose()  # idempotent
        with pytest.raises(McpChildDeathError, match="closing"):
            await host.call("alpha", {})

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "module",
    ["anyio", "anyio.streams.stapled", "httpx", "httpx._exceptions", "httpcore"],
)
def test_transport_death_matches_transport_module_families(module):
    """The transport-death predicate matches on the TOP-LEVEL module of the
    exception type — anyio (both transports' in-process streams) and
    httpx/httpcore (the streamable-HTTP client's connect/read family)."""
    exc_type = type("FakeTransportErr", (Exception,), {"__module__": module})
    assert _is_transport_death(exc_type("stream closed")) is True


def test_transport_death_negative_row_stays_a_call_error():
    """A plain exception from any other module is a genuine call error, never
    a death — the predicate must not widen past the transport families."""
    assert _is_transport_death(ValueError("bad arguments")) is False


def test_transport_death_matches_session_terminated_mcp_error():
    """The stale-session shape on newer SDKs (repro'd on 1.28.1): a restarted
    remote answers an old mcp-session-id POST and the SDK raises
    `McpError("Session terminated")` to the CALLER — a death, matched
    case-insensitively by message like the connection-closed shape."""

    class McpError(Exception):
        pass

    assert _is_transport_death(McpError("Session terminated")) is True
    assert _is_transport_death(McpError("session terminated")) is True


def test_transport_death_session_terminated_code_is_rewording_resilient():
    """The SDK SYNTHESIZES the stale-session error as
    `ErrorData(code=32600, ...)` — the sign-bugged POSITIVE 32600, a value no
    genuine JSON-RPC error uses — so that exact structured code matches even
    if a future SDK rewords the message. The standard -32600
    (INVALID_REQUEST) must NOT match: a live server can legitimately send it
    for a malformed request that is no death."""

    class _ErrorData:
        def __init__(self, code: int) -> None:
            self.code = code

    class McpError(Exception):
        def __init__(self, message: str, code: int) -> None:
            super().__init__(message)
            self.error = _ErrorData(code)

    assert _is_transport_death(McpError("some future wording", 32600)) is True
    assert _is_transport_death(McpError("Invalid Request", -32600)) is False


def test_transport_death_unwraps_exception_groups_to_their_leaves():
    """An ExceptionGroup's own module is `builtins` — the SDK's transports
    re-raise their task group's failure as a group, so the predicate must
    judge the LEAVES: a group with any transport-family leaf (even nested)
    is a death; a group of only non-transport leaves stays a call error."""
    httpx_leaf = _FakeHttpxDeath("connect fail")
    assert _is_transport_death(ExceptionGroup("transport", [httpx_leaf])) is True
    nested = ExceptionGroup(
        "outer", [ExceptionGroup("inner", [_FakeHttpxDeath("read fail")])]
    )
    assert _is_transport_death(nested) is True
    assert (
        _is_transport_death(ExceptionGroup("app", [ValueError("bad arguments")]))
        is False
    )


def test_m17_driver_death_retires_a_parked_call_promptly(monkeypatch):
    """The streamable-http death direction: the SDK delivers a dead peer's
    failure to the DRIVER task (the transport task group cancels the connect
    context's body and re-raises the real cause as an ExceptionGroup) while
    the dispatching caller stays PARKED on its response stream forever. The
    supervised call must race the driver and surface the death typed
    promptly — never ride the connector's 30s backstop (the M17 gap the live
    toy-server suite found). With no respawn policy the next dispatch is the
    sticky typed failure (M19 OFF)."""
    spawns = _Spawns()
    peer_died = asyncio.Event()

    class _DyingConnectContext:
        """Mimics the SDK context: on peer death, cancel the body (the
        driver's park) and replace the cancellation with the real cause,
        grouped, out of __aexit__."""

        def __init__(self, server_id: str) -> None:
            self._server_id = server_id
            self._reaper: asyncio.Task | None = None

        async def __aenter__(self) -> _FakeChild:
            child = _FakeChild(self._server_id, _TOOL_NAMES)
            spawns.children.append(child)
            spawns.envs.append(None)
            body = asyncio.current_task()

            async def _reap_on_death():
                await peer_died.wait()
                body.cancel()

            self._reaper = asyncio.ensure_future(_reap_on_death())
            return child

        async def __aexit__(self, exc_type, exc, tb) -> bool:
            self._reaper.cancel()
            spawns.current.exited = True
            if isinstance(exc, asyncio.CancelledError) and peer_died.is_set():
                raise ExceptionGroup("transport", [_FakeHttpxDeath("connect fail")])
            return False

    monkeypatch.setattr(
        _client_mod,
        "connect_streamable_http",
        lambda server_id, url, *, headers=None: _DyingConnectContext(server_id),
    )
    registry = MemoryToolRegistry()
    _admit(registry)

    async def scenario():
        host = await _supervised_http(registry).start()
        assert (await host.call("alpha", {}))["tool"] == "alpha"

        async def parked_call(tool_name, arguments=None):
            await asyncio.Event().wait()  # the caller never wakes on its own

        spawns.current.call_tool = parked_call  # type: ignore[method-assign]

        async def _peer_dies_shortly():
            await asyncio.sleep(0.05)
            peer_died.set()

        asyncio.ensure_future(_peer_dies_shortly())
        with pytest.raises(McpChildDeathError) as exc:
            # Bounded WELL under the 30s backstop: a hang here is the gap.
            await asyncio.wait_for(host.call("alpha", {}), timeout=5)
        cause = exc.value.__cause__
        assert isinstance(cause, ExceptionGroup)
        assert any(isinstance(leaf, _FakeHttpxDeath) for leaf in cause.exceptions)
        assert spawns.current.exited is True  # the dead generation unwound
        with pytest.raises(McpChildDeathError, match="respawn"):
            await host.call("alpha", {})  # M19 OFF: sticky typed

    asyncio.run(scenario())


def test_m17_session_terminated_death_engages_the_m19_fork(monkeypatch):
    """The 1.28.x stale-session shape end-to-end: the SDK raises
    `McpError("Session terminated")` to the CALLER while the transport task
    group and driver stay HEALTHY. It must classify as a death — typed
    promptly with the cause chained, the healthy driver's generation retired
    — and the respawn policy must engage on the next dispatch. Before the
    predicate row landed, the raw McpError re-raised, `_mark_dead` never ran,
    and every later call repeated the same raw error forever: M19 inert for
    the most common remote death, a server deploy bounce."""
    spawns = _fake_http_transport(monkeypatch)
    registry = MemoryToolRegistry()
    _admit(registry)

    class McpError(Exception):  # name-matched by the contract, faked SDK-free
        pass

    async def scenario():
        host = await _supervised_http(
            registry, respawn=McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0)
        ).start()
        await host.call("alpha", {})
        client = spawns.current

        async def stale_session_call(tool_name, arguments=None):
            raise McpError("Session terminated")

        client.call_tool = stale_session_call  # type: ignore[method-assign]
        with pytest.raises(McpChildDeathError) as exc:
            await host.call("alpha", {})
        assert isinstance(exc.value.__cause__, McpError)
        assert client.exited is True, "the healthy driver's generation was retired"
        # The M19 fork engages: the next dispatch reconnects and flows.
        assert (await host.call("alpha", {}))["tool"] == "alpha"
        assert spawns.count == 2

    asyncio.run(scenario())
