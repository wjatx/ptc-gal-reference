"""server.py — the SDK bindings for the broker's MCP mouth: stdio and the network.

The only module in the gateway that touches the `mcp` SDK, and it imports it
lazily inside functions — so `safe_agents.broker.gateway` imports cleanly with the
optional `mcp` extra absent, exactly as `broker/mcp/client.py` does on the client
side. Everything worth testing lives in `surface.py`, `authn.py` and `network.py`,
which need no SDK at all.

Both transports serve the SAME SDK `Server`, built once by `build_server`. The
network mouth has no handlers and no result conversion of its own, so there is
one place a `GatewayResult` becomes a wire result and a change to it lands on
both transports (`broker/GATEWAY.md` G9, G11).

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

import logging
import socket
import sys
from typing import Any, Callable, Mapping

from safe_agents.broker.gateway.authn import Authenticator, RefusalLedger
from safe_agents.broker.gateway.network import (
    SERVER_LOGGER,
    ConnectionGuard,
    DiagnosticBudget,
    MouthApp,
    SerializedSurface,
)
from safe_agents.broker.gateway.surface import GatewayResult, GatewaySurface

#: How long a stopping server waits for open connections (a client's standing
#: event stream, for one) before closing them.
_GRACEFUL_SHUTDOWN_S = 5


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


class NetworkMouth:
    """The network MCP mouth: the same surface, over streamable HTTP.

    A sibling to `serve_stdio`. What differs is only what a socket forces:

      - every request is authenticated before the SDK sees it (`ConnectionGuard`
        is the outermost ASGI layer, so no `initialize`, `tools/list` or
        `tools/call` is served to a connection that has not passed);
      - calls into the runtime are serialized on one thread, held by
        `SerializedSurface` and not left to how a handler happens to be written;
      - refused connections are counted and recorded through `record_refusals`,
        the one thing this object can do to the audit tape;
      - what the HTTP server underneath writes to stderr is bounded by
        `DiagnosticBudget`, because some of it is written for requests the
        guard never sees, and request lines are not logged at all.

    BUILD AND SERVE ON THE THREAD THAT BUILT THE RUNTIME. The event loop runs on
    the thread that calls `serve()`, the handlers call the runtime synchronously
    on that loop, and the runtime (and a sqlite store's connections) belong to
    the thread that made them. While a call is inside the runtime the loop is
    blocked and nothing else is served, which is the same serialization `/call`
    gets from a single-threaded server, and is the point.

    `listener` is an already-bound, listening socket (`network.bind_listener`), so
    a bad address has refused before this object exists.
    """

    def __init__(
        self,
        surface: GatewaySurface,
        *,
        authenticator: Authenticator,
        record_refusals: Callable[[Mapping[str, int]], None],
        listener: socket.socket,
    ) -> None:
        self._surface = SerializedSurface(surface)
        self._authenticator = authenticator
        self._ledger = RefusalLedger(record_refusals)
        self._listener = listener
        self._server: Any = None
        self._stop_requested = False

    def build_app(self) -> Any:
        """The ASGI application: guard, then the one route, then the SDK.

        Only the two arguments every SDK release in the supported range accepts
        are passed to the session manager; the rest are the SDK's defaults.
        """
        from mcp.server.streamable_http_manager import (  # noqa: PLC0415 — optional extra
            StreamableHTTPSessionManager,
        )

        manager = StreamableHTTPSessionManager(app=build_server(self._surface))
        return ConnectionGuard(
            MouthApp(manager.handle_request, manager.run),
            self._authenticator,
            self._ledger,
        )

    async def serve(self) -> None:
        """Serve until stopped, then write out any refusals still uncounted on the tape."""
        import uvicorn  # noqa: PLC0415 — arrives with the optional `mcp` extra

        config = uvicorn.Config(
            self.build_app(),
            lifespan="on",
            # No access log: a request line carries the query string, and a
            # credential someone wrongly put there must not be copied to a log.
            access_log=False,
            log_config=None,
            server_header=False,
            timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_S,
        )
        self._server = uvicorn.Server(config)
        # One-way, and never an assignment of the flag's value: `request_stop`
        # may run from a signal handler between any two of these lines, and a
        # stop it has already set on the server must not be written back to False.
        if self._stop_requested:
            self._server.should_exit = True
        # The server logs a line for a request it cannot parse, before the guard
        # is asked anything. Bound it, so a stranger cannot grow a kept stderr.
        budget = DiagnosticBudget()
        server_log = logging.getLogger(SERVER_LOGGER)
        server_log.addFilter(budget)
        try:
            await self._server.serve(sockets=[self._listener])
        finally:
            self._ledger.close()
            server_log.removeFilter(budget)
            suppressed = budget.drain()
            if suppressed:
                print(
                    f"[broker] {suppressed} server diagnostic(s) suppressed before shutdown",
                    file=sys.stderr,
                )

    def request_stop(self) -> None:
        """Ask `serve()` to return, whether it is running or has yet to start.

        A stop requested before `serve()` is remembered: the mouth starts, sees
        it, and shuts down without serving. Safe to call from another thread or
        from a signal handler, and any number of times.
        """
        self._stop_requested = True
        if self._server is not None:
            self._server.should_exit = True
