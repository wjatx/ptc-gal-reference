"""Real-streamable-HTTP-transport suite for the MCP host (#221 P4, M21).

The stdio counterpart (`test_mcp_stdio.py`) proves the supervised lifecycle
over a spawned child; this file proves the SAME lifecycle clauses over the
second reference transport: every test spawns
`fixtures/streamable_http_toy_server.py` as an ACTUAL SUBPROCESS serving
FastMCP over streamable-http on loopback (the sanctioned M21 plain-http
carve-out) and drives it through `connect_streamable_http` and
`streamable_http_host_factory` — so killing the server is a real session
death and restarting it is a real reconnect target, with "child" read as
"session" per M21.

Proven properties: discovery → hash → two-key admission → call over real
HTTP; a store row cannot mint an undeclared tool callable (UNLISTED, M3/M4);
a killed server surfaces on the FIRST post-death dispatch as a PROMPT typed
`McpChildDeathError` with the real transport cause chained, sticky with no
respawn policy (M17/M19 OFF); with a policy and the server restarted, a call
reconnects and re-runs discovery fresh (M18/M19 ON); `aclose()` exits the
session context while the loop is alive and further calls refuse typed (M20).

One observed transport delta, codified rather than hidden: over
streamable-http a dead peer is noticed only at the next POST, and the SDK
delivers the failure to the TRANSPORT task group — the driver task dies
promptly with the real cause (an ExceptionGroup wrapping httpx.ConnectError)
while the DISPATCHING caller is left parked on its response stream forever.
`SupervisedMcpHost.call` closes that gap by RACING the in-flight call
against its generation's driver task, so the death legs here assert the
strong form directly: the first post-death dispatch itself returns typed and
prompt — never the bare 30s backstop `TimeoutError` M17 exists to kill.

The stale-session shape (a restarted server answering an old
mcp-session-id) is SDK-version-dependent: on this env's 1.25.0 it rides the
task group as httpx.HTTPStatusError 400 (what the reconnect leg observes);
on 1.28.x the SDK instead raises `McpError("Session terminated")` to the
CALLER with the driver healthy — covered by `_is_transport_death`'s McpError
branch and proven SDK-free in test_mcp_lifecycle.py. These live legs are the
canary for the next message/shape drift in either direction.

The suite needs only the `mcp` extra (FastMCP + its bundled uvicorn ride
inside it) and a spawnable child python — loopback only, no AWS. No custom
pytest marker: pyproject registers only `stdio`, and an unregistered marker
would warn on every run; select this suite by file path.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip(
    "mcp", reason="the streamable-http transport needs the optional `mcp` extra"
)

from safe_agents.broker.mcp.client import connect_streamable_http
from safe_agents.broker.mcp.factory import (
    McpChildDeathError,
    streamable_http_host_factory,
)
from safe_agents.broker.mcp.discovery import ToolState
from safe_agents.broker.mcp.host import ToolNotCallableError
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.schemas.mcp_registry import (
    McpRespawnPolicy,
    McpServerDecl,
    McpToolDecl,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.connectors.mcp_connector import McpConnector

_SERVER_ID = "toyhttp"
_FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "streamable_http_toy_server.py")
# The pgrep -f needle for the server subprocess (matches its argv, not pytest's).
_SERVER_NEEDLE = "streamable_http_toy_server.py"
# `shout` is deliberately NOT declared: the UNLISTED leg's subject.
_DECL = McpServerDecl(
    tools=[McpToolDecl(tool_name="echo"), McpToolDecl(tool_name="add")]
)
# Well under the connector's 30s backstop: proves fail-fast, not timeout-rescue.
_PROMPT_S = 10.0
# Server readiness bound — a cold child pays the mcp+uvicorn import, ~1-2s.
_READY_S = 30.0


def _url(port: int) -> str:
    # The SDK's FastMCP default streamable_http_path is "/mcp".
    return f"http://127.0.0.1:{port}/mcp"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _server_pids() -> list[int]:
    out = subprocess.run(
        ["pgrep", "-f", _SERVER_NEEDLE], capture_output=True, text=True
    )
    return [int(line) for line in out.stdout.split()] if out.returncode == 0 else []


class _ToyServer:
    """One toy-server subprocess on a fixed port, restartable on that port
    (the reconnect leg needs death and rebirth at the SAME url)."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, _FIXTURE, str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + _READY_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"toy server exited at startup (code {self.proc.returncode})"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.05)  # no-op under the suite fixture; deadline bounds
        raise RuntimeError(f"toy server never listened on port {self.port}")

    def kill(self) -> None:
        """SIGKILL and REAP — on return the process is gone and the port dead."""
        assert self.proc is not None
        self.proc.kill()
        self.proc.wait(timeout=_PROMPT_S)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.kill()


@pytest.fixture(autouse=True)
def _no_stray_servers():
    """Fail loudly if a test leaks a toy-server subprocess (the zombie check)."""
    assert _server_pids() == [], "stray toy server before test"
    yield
    deadline = time.monotonic() + _PROMPT_S
    while time.monotonic() < deadline and _server_pids():
        time.sleep(0.05)
    assert _server_pids() == [], f"toy server leaked: pids {_server_pids()}"


@pytest.fixture()
def toy_server():
    server = _ToyServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _admit_all(registry: MemoryToolRegistry, defs) -> None:
    for d in defs:
        registry.admit_tool(
            RegisteredTool(
                tool_def=d,
                def_hash=compute_tool_def_hash(d),
                status=RegistryStatus.ACTIVE,
                admitted_by="arn:aws:sts::000000000000:assumed-role/Admitter/test",
                admitted_at="2026-07-19T00:00:00Z",
            )
        )


def _toy_factory(registry: MemoryToolRegistry, port: int, respawn=None):
    """The reference factory against the toy server, admitting EVERY advertised
    tool between connect and the first refresh — deliberately including the
    undeclared `shout`, so its refusal below is the two-key proof (a registry
    row alone cannot mint a callable)."""
    inner = streamable_http_host_factory(
        _SERVER_ID,
        _url(port),
        server_decl=_DECL,
        registry=registry,
        respawn=respawn,
    )

    async def factory():
        host = await inner()  # a started SupervisedStreamableHttpHost
        _admit_all(registry, await host.inner._client.list_tool_defs())
        await host.refresh()
        return host

    return factory


# -- plain connect_streamable_http lifecycle ---------------------------------


def test_http_discovery_hash_call_repeat_and_context_exit(toy_server):
    """Over a REAL remote peer: discovery materializes all three tools
    (hashable, the admission input), calls run repeatedly and return structured
    content, and exiting the context disconnects cleanly — no hang."""

    async def scenario():
        async with connect_streamable_http(_SERVER_ID, _url(toy_server.port)) as client:
            defs = await client.list_tool_defs()
            assert sorted(d.tool_name for d in defs) == ["add", "echo", "shout"]
            for d in defs:
                assert len(compute_tool_def_hash(d)) == 64
            r1 = await client.call_tool("echo", {"text": "ping"})
            assert r1.isError is False
            # FastMCP's typed return arrives as structured content on the wire.
            assert r1.structuredContent["text"] == "ping"
            r2 = await client.call_tool("add", {"a": 2, "b": 3})
            assert r2.isError is False
            assert r2.structuredContent["total"] == 5

    asyncio.run(scenario())


# -- connector factory lifecycle ---------------------------------------------


def test_http_connector_admitted_call_flows_and_row_cannot_mint_undeclared(toy_server):
    """The full connector path over real HTTP: admitted calls flow with
    structured content, while `shout` — advertised AND holding an admitted
    registry row, but never declared in the manifest — refuses UNLISTED
    (M3/M4: the store can select, never mint). close() is idempotent."""
    connector = McpConnector(_toy_factory(MemoryToolRegistry(), toy_server.port))
    try:
        r1 = connector.execute(_SERVER_ID, "echo", {"text": "hello"}, credential="")
        assert r1.isError is False
        assert r1.structuredContent["text"] == "hello"
        r2 = connector.execute(_SERVER_ID, "add", {"a": 40, "b": 2}, credential="")
        assert r2.isError is False
        assert r2.structuredContent["total"] == 42

        with pytest.raises(ToolNotCallableError) as exc:
            connector.execute(_SERVER_ID, "shout", {"text": "hi"}, credential="")
        assert exc.value.reason is ToolState.UNLISTED
    finally:
        connector.close()
    connector.close()  # idempotent


# -- death + reconnect semantics ---------------------------------------------


def test_http_server_death_retires_driver_promptly_then_sticky_typed(toy_server):
    """SIGKILL the server mid-session: the FIRST post-death dispatch itself
    surfaces the TYPED death error promptly with the real transport cause
    chained — the caller parks on its response stream, so only the call/driver
    race in `SupervisedMcpHost.call` delivers this without the 30s backstop
    (M17/M21) — and every subsequent dispatch stays typed, stable across
    retries with no respawn policy (M19: absent block = no respawn).
    aclose() still tears down cleanly."""

    async def scenario():
        host = await _toy_factory(MemoryToolRegistry(), toy_server.port)()
        warm = await host.call("echo", {"text": "warm"})
        assert warm.isError is False
        toy_server.kill()

        # No manual cancel, no driver poll: the dispatch IS the assertion.
        # wait_for is a backstop only — a TimeoutError here is the M17 gap.
        t0 = time.monotonic()
        with pytest.raises(McpChildDeathError) as first:
            await asyncio.wait_for(
                host.call("echo", {"text": "provoke"}), timeout=_PROMPT_S
            )
        assert time.monotonic() - t0 < _PROMPT_S, "first dispatch was not prompt"
        assert first.value.server_id == _SERVER_ID
        assert first.value.__cause__ is not None
        assert host.inner is None  # the dead generation is retired

        for attempt in range(2):  # the failure is stable across retries
            t0 = time.monotonic()
            with pytest.raises(McpChildDeathError) as exc:
                await host.call("echo", {"text": "x"})
            assert time.monotonic() - t0 < _PROMPT_S, f"attempt {attempt} hung"
            assert exc.value.server_id == _SERVER_ID
            assert exc.value.__cause__ is not None, (
                "the real transport error must ride __cause__ — nothing gets "
                "less diagnosable than the raw exception was"
            )

        t0 = time.monotonic()
        await host.aclose()
        assert time.monotonic() - t0 < _PROMPT_S

    asyncio.run(scenario())


def test_http_respawn_policy_reconnects_and_rechecks_discovery(toy_server):
    """The M19 knob over real HTTP: SIGKILL the server, restart it on the SAME
    port → the dispatch after the death notice reconnects and the call flows
    again. M18 rides along: a registry row deleted while the peer was dead
    governs the reconnected session (that tool refuses on the fresh snapshot),
    proving no verdict crossed the death."""

    async def scenario():
        registry = MemoryToolRegistry()
        host = await _toy_factory(
            registry,
            toy_server.port,
            respawn=McpRespawnPolicy(max_attempts=2, backoff_seconds=0.0),
        )()
        warm = await host.call("echo", {"text": "warm"})
        assert warm.isError is False
        toy_server.kill()
        toy_server.start()  # rebirth at the same url — the reconnect target

        # The world changes while the session is dead: `add` loses its row.
        del registry._rows[(_SERVER_ID, "add")]

        # The provoking POST hits the NEW server with the OLD session id (a
        # 400 — the second observed death shape, httpx.HTTPStatusError); the
        # racing call surfaces it typed and prompt, no manual cancel needed.
        with pytest.raises(McpChildDeathError):
            await asyncio.wait_for(
                host.call("echo", {"text": "provoke"}), timeout=_PROMPT_S
            )

        # Next dispatch takes the M19 fork: reconnect, fresh discovery, flows.
        result = await host.call("echo", {"text": "back"})
        assert result.isError is False
        assert result.structuredContent["text"] == "back"
        assert host.inner is not None  # a live NEW session generation

        # … under a FRESH snapshot: the deleted row now refuses.
        with pytest.raises(ToolNotCallableError):
            await host.call("add", {"a": 1, "b": 1})

        await host.aclose()

    asyncio.run(scenario())


# -- aclose reap (M20) --------------------------------------------------------


def test_http_aclose_exits_session_and_refuses_further_calls(toy_server):
    """`aclose()` exits the connect context while the loop is still alive
    (M20 with "child" read as "session"): it returns promptly, the inner host
    is retired, and a further call refuses with the closing-typed death.
    A second aclose is a no-op."""

    async def scenario():
        registry = MemoryToolRegistry()
        host = await _toy_factory(registry, toy_server.port)()
        r = await host.call("echo", {"text": "hi"})
        assert r.isError is False

        t0 = time.monotonic()
        await host.aclose()
        assert time.monotonic() - t0 < _PROMPT_S
        assert host.inner is None  # the session generation is retired

        with pytest.raises(McpChildDeathError, match="closing"):
            await host.call("echo", {"text": "hi"})
        await host.aclose()  # idempotent

    asyncio.run(scenario())
