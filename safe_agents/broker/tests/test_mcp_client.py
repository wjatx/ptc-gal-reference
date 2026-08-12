"""Tests for the thin reference MCP client (#174) against an in-memory server.

The `mcp` extra is optional, so the whole module skips cleanly when it is absent
(`pytest.importorskip`). The fake MCP server is an in-process FastMCP wired to the
client over the SDK's in-memory transport — no network, no subprocess.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp", reason="the reference MCP client needs the optional `mcp` extra")

import contextlib

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from safe_agents.broker.mcp.client import McpClient, _tool_def_from_sdk
from safe_agents.broker.schemas.mcp_registry import McpToolDef, compute_tool_def_hash

_SERVER_ID = "calc"


def _fake_server() -> FastMCP:
    server = FastMCP("calc")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    @server.tool()  # no docstring -> the SDK advertises description=None
    def echo_no_doc(text: str) -> str:
        return text

    return server


@contextlib.asynccontextmanager
async def _connected_client():
    server = _fake_server()
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        yield McpClient(_SERVER_ID, session)


def _run(coro):
    """Drive one coroutine to completion without depending on a pytest-async plugin."""
    import asyncio

    return asyncio.run(coro)


def test_list_tools_materializes_tool_defs():
    async def scenario():
        async with _connected_client() as client:
            return await client.list_tool_defs()

    defs = _run(scenario())

    by_name = {d.tool_name: d for d in defs}
    assert set(by_name) == {"add", "echo_no_doc"}

    add = by_name["add"]
    assert isinstance(add, McpToolDef)
    assert add.server_id == _SERVER_ID  # OUR config, never the server
    assert add.description == "Add two integers."
    assert add.input_schema.get("type") == "object"
    # The materialized def is hashable by the gate's drift primitive.
    assert len(compute_tool_def_hash(add)) == 64


def test_description_absent_becomes_empty_string():
    async def scenario():
        async with _connected_client() as client:
            return await client.list_tool_defs()

    by_name = {d.tool_name: d for d in _run(scenario())}
    # A tool with no docstring must materialize description="" so the four-field
    # hash is total (never None).
    assert by_name["echo_no_doc"].description == ""


def test_call_tool_round_trip():
    async def scenario():
        async with _connected_client() as client:
            return await client.call_tool("add", {"a": 2, "b": 3})

    result = _run(scenario())

    assert result.isError is False
    assert result.content[0].text == "5"


def test_tool_def_from_sdk_maps_fields_without_sdk_types():
    class _FakeSdkTool:
        name = "lookup"
        description = None
        inputSchema = {"type": "object", "properties": {"q": {"type": "string"}}}

    d = _tool_def_from_sdk(_SERVER_ID, _FakeSdkTool())
    assert d == McpToolDef(
        server_id=_SERVER_ID,
        tool_name="lookup",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        description="",
    )


def test_tool_def_from_sdk_omitted_fields_default_to_none():
    """A tool that advertises none of the 6 extra fields yields None, not {}/''."""

    class _FakeSdkTool:
        name = "lookup"
        description = "Look something up."
        inputSchema = {"type": "object"}

    d = _tool_def_from_sdk(_SERVER_ID, _FakeSdkTool())
    assert d.title is None
    assert d.output_schema is None
    assert d.icons is None
    assert d.annotations is None
    assert d.meta is None
    assert d.execution is None


def test_tool_def_from_sdk_coerces_pydantic_values_and_preserves_vendor_keys():
    """A pydantic-model-shaped SDK value must land as a plain, JSON-able dict,
    with an unknown vendor key (the SDK's `extra="allow"` overflow) intact.
    """

    class _FakeModel:
        """Duck-types pydantic's `model_dump(mode="json", exclude_none=True)`."""

        def __init__(self, data: dict):
            self._data = data

        def model_dump(self, mode="json", exclude_none=False):
            assert mode == "json"
            assert exclude_none is True
            return dict(self._data)

    class _FakeSdkTool:
        name = "lookup"
        description = "Look something up."
        inputSchema = {"type": "object"}
        title = "Lookup"
        outputSchema = {"type": "object", "properties": {"result": {"type": "string"}}}
        icons = [_FakeModel({"src": "https://example.test/icon.png"})]
        annotations = _FakeModel({"readOnlyHint": True, "vendorCustomHint": "keep-me"})
        meta = _FakeModel({"vendor": "acme"})
        execution = _FakeModel({"timeoutMs": 5000})

    d = _tool_def_from_sdk(_SERVER_ID, _FakeSdkTool())

    assert d.title == "Lookup"
    assert d.output_schema == {"type": "object", "properties": {"result": {"type": "string"}}}
    assert d.icons == [{"src": "https://example.test/icon.png"}]
    assert d.annotations == {"readOnlyHint": True, "vendorCustomHint": "keep-me"}
    assert d.meta == {"vendor": "acme"}
    assert d.execution == {"timeoutMs": 5000}
    # every coerced value is plain JSON-able data, not a model instance
    import json

    json.dumps(
        {
            "title": d.title,
            "output_schema": d.output_schema,
            "icons": d.icons,
            "annotations": d.annotations,
            "meta": d.meta,
            "execution": d.execution,
        }
    )
