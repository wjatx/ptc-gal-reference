"""server.py — the stdio binding for the broker's MCP mouth (#283).

The only module in the gateway that touches the `mcp` SDK, and it imports it
lazily inside functions — so `safe_agents.broker.gateway` imports cleanly with the
optional `mcp` extra absent, exactly as `broker/mcp/client.py` does on the client
side. Everything worth testing lives in `surface.py`, which needs no SDK at all.

There is no policy in this file. It translates: SDK request in, `GatewaySurface`
call, SDK result out. If a decision appears here, it is in the wrong place.

## Why the low-level `Server` and not FastMCP

The three MCP servers already in this tree (`examples/restricted_mcp_server`, the
two test fixtures) use FastMCP, which is the right tool for AUTHORING a server with
a fixed set of hand-written tools. This is a proxy: its tool list is whatever the
broker currently serves this principal, computed per request. That is the low-level
`Server`'s handler API, not a decorator over a static function set.
"""

from __future__ import annotations

from typing import Any

from safe_agents.broker.gateway.surface import GatewayResult, GatewaySurface


def build_server(surface: GatewaySurface) -> Any:
    """Wire a `GatewaySurface` to an SDK `Server` with the two tool handlers.

    Returns the SDK object rather than a wrapper: callers that want to drive it
    in-process (the conformance tests, via the SDK's memory transport) need the
    real thing, and hiding it behind a shim would make the in-process proof less
    like the stdio path it stands in for.
    """
    from mcp.server.lowlevel import Server  # noqa: PLC0415 — optional extra
    import mcp.types as types  # noqa: PLC0415

    server = Server(surface.server_name)

    @server.list_tools()
    async def _list_tools() -> list[Any]:
        return [
            types.Tool(
                name=tool.wire_name,
                description=tool.description,
                inputSchema=tool.input_schema,
            )
            for tool in surface.tools()
        ]

    # validate_input=False: the broker is the enforcement point, and a schema the
    # gateway invented (see `surface._PERMISSIVE_SCHEMA`) must never refuse a call
    # locally. A client-side rejection would keep the call off the audit tape,
    # turning an unenforceable placeholder schema into a silent, unrecorded gate.
    @server.call_tool(validate_input=False)
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> Any:
        result = surface.call(name, arguments)
        return _to_call_tool_result(result, types)

    return server


def _to_call_tool_result(result: GatewayResult, types: Any) -> Any:
    """Shape one `GatewayResult` as an SDK `CallToolResult`.

    A refusal is `isError=True`. That is the honest mapping: the client asked for an
    effect and did not get one, and a refused call reported as success would be the
    flattering-direction lie the posture ladder exists to forbid. The broker's own
    reason string is passed through verbatim — it is what the audit record says.
    """
    content = [types.TextContent(type="text", text=result.text)]
    if result.ok:
        return types.CallToolResult(content=content, isError=False)
    return types.CallToolResult(content=content, isError=True)


async def serve_stdio(surface: GatewaySurface) -> None:
    """Run the gateway over stdio until the client disconnects.

    This is the shape a wrapped harness launches: one process, one MCP server on
    stdin/stdout, every tool call routed through the broker.
    """
    from mcp.server.stdio import stdio_server  # noqa: PLC0415

    server = build_server(surface)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
