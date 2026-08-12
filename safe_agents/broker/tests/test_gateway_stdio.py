"""Conformance for the broker's MCP mouth — the SDK-bound half (#283).

`test_gateway_surface.py` proves the decisions; this proves the WIRING. It drives a
real SDK `Server` — the same object `serve_stdio` runs — through the SDK's
in-memory transport, so a genuine MCP client performs `initialize`, `tools/list`
and `tools/call` against the gateway.

In-memory rather than a spawned stdio child on purpose. The session's bar is a
refusal driven in-process; a child process would prove the same handlers plus
`anyio`'s stdio plumbing, at the cost of a process to reap. The stdio path itself
is four lines in `serve_stdio` and is what the #284 live wrap exercises.

"A seam is proven per transport" is the standing warning against assuming
otherwise, and it is why the marshal these handlers rely on is homed once in
`broker/marshal.py` rather than re-derived here.

Coroutines are driven through `_run` rather than a pytest-async plugin, following
`test_mcp_host.py:87-89` — the house pattern for this suite.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.gateway.server import build_server

pytest.importorskip("mcp", reason="the gateway's SDK binding needs the optional 'mcp' extra")

from mcp.shared.memory import (  # noqa: E402 — after the extra's availability check
    create_connected_server_and_client_session,
)

_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3] / "examples" / "embedded_agent" / "manifest.yaml"
)


def _run(coro):
    """Drive one coroutine to completion without a pytest-async plugin."""
    return asyncio.run(coro)


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch):
    for var in (
        "BROKER_STORE",
        "BROKER_MANIFEST",
        "BROKER_SECRETS",
        "BROKER_SECRETS_DIR",
        "BROKER_SECRETS_FILE",
        "BROKER_AUDIT_PATH",
        "BROKER_AUDIT_BUCKET",
        "BROKER_ENVELOPE_LOAD",
        "BROKER_GRANT_LOAD",
        "BROKER_SQLITE_PATH",
    ):
        monkeypatch.delenv(var, raising=False)

    runtime, sink = build_runtime(load_agent_manifest(_MANIFEST_PATH))
    try:
        yield GatewaySurface(runtime), sink
    finally:
        runtime.close()


def test_client_sees_only_granted_tools(gateway) -> None:
    surface, _ = gateway

    async def _drive():
        async with create_connected_server_and_client_session(build_server(surface)) as client:
            return await client.list_tools()

    names = [tool.name for tool in _run(_drive()).tools]
    assert names == ["search__query"]
    # notify.send is classified in the manifest and NOT granted, so a real MCP
    # client never sees it. Absence, not refusal — the same property
    # served_registry() has always had, now visible over the wire.
    assert "notify__send" not in names


def test_advertised_tool_carries_the_broker_authored_description(gateway) -> None:
    surface, _ = gateway

    async def _drive():
        async with create_connected_server_and_client_session(build_server(surface)) as client:
            return await client.list_tools()

    (tool,) = _run(_drive()).tools
    assert tool.description.startswith("search.query — brokered read, local")


def test_granted_call_executes_over_the_wire(gateway) -> None:
    surface, _ = gateway

    async def _drive():
        async with create_connected_server_and_client_session(build_server(surface)) as client:
            return await client.call_tool("search__query", {"query": "broker"})

    result = _run(_drive())
    assert result.isError is False
    assert "The agent holds no connector credentials" in result.content[0].text


def test_unadmitted_tool_is_refused_over_the_wire_with_its_audit_line(gateway) -> None:
    """The #283 definition of done, in process.

    A real MCP client asks for a tool the gateway never advertised. It comes back
    an error carrying the broker's own reason, and the refusal is on the tape —
    which is the point of routing unknown names to the broker instead of answering
    them at the mouth.
    """
    surface, sink = gateway
    before = len(sink.records())

    async def _drive():
        async with create_connected_server_and_client_session(build_server(surface)) as client:
            return await client.call_tool("notify__send", {"text": "shipping it"})

    result = _run(_drive())
    assert result.isError is True
    assert "tool not granted to this principal" in result.content[0].text

    new_records = sink.records()[before:]
    assert [(r.decision, r.outcome) for r in new_records] == [("deny", "denied")]


def test_the_gateway_does_not_enforce_its_own_placeholder_schema(gateway) -> None:
    """A permissive schema must not become a silent client-side gate.

    The handler is registered with `validate_input=False`. If that regressed, the
    SDK would validate arguments against the invented schema and refuse locally —
    a refusal the broker never saw and the audit tape never recorded, which is
    enforcement in the wrong place by the wrong component.
    """
    surface, sink = gateway
    before = len(sink.records())

    async def _drive():
        async with create_connected_server_and_client_session(build_server(surface)) as client:
            # Deliberately odd shape: a client-side validator is what would object.
            return await client.call_tool(
                "search__query", {"query": "broker", "extra": [1, 2]}
            )

    result = _run(_drive())
    assert result.isError is False
    # The call reached the broker and was recorded — proof it was not stopped short.
    assert len(sink.records()) > before
