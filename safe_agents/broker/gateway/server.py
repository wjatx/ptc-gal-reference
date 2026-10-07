"""server.py — the SDK and server bindings for the gateway's mouths.

The only module in the gateway that touches the `mcp` SDK, and it imports it
lazily inside functions — so `safe_agents.broker.gateway` imports cleanly with the
optional `mcp` extra absent, exactly as `broker/mcp/client.py` does on the client
side. Everything worth testing lives in `surface.py`, `authn.py` and `network.py`,
which need no SDK at all.

Both transports serve the SAME SDK `Server`, built once by `build_server`. The
network mouth has no handlers and no result conversion of its own, so there is
one place a `GatewayResult` becomes a wire result and a change to it lands on
both transports (`broker/GATEWAY.md` G9, G11).

Every HTTP mouth runs on one serve loop (`_ServedMouth`), and every mouth the
process opens runs on ONE event loop, on the thread that built the runtime
(`serve_until_any_stops`).

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

import asyncio
import contextlib
import logging
import os
import socket
import sys
import threading
from typing import Any, Callable, Iterator, Mapping, Sequence

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


async def serve_stdio(surface: Any, *, stdin: Any = None) -> None:
    """Run the gateway over stdio until the client disconnects.

    This is the shape a wrapped harness launches: one process, one MCP server on
    stdin/stdout, every tool call routed through the broker. `stdin` is where
    lines are read from (the SDK's own reader when None); `StdioMouth` passes one
    a stop can abandon.
    """
    from mcp.server.stdio import stdio_server  # noqa: PLC0415

    server = build_server(surface)
    async with stdio_server(stdin=stdin) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


class _StdinLines:
    """This process's stdin as an async iterator of text lines, read on a daemon thread.

    Why not the SDK's own reader: it reads each line in a worker thread that a
    cancellation waits for, so a gateway told to stop would sit until its client
    sent another line or closed the pipe. A stop has to stop. This reader's
    thread is a daemon and is never waited for: cancelling the iteration returns
    at once, and the thread, still blocked in its read, ends with the process.

    `os.read` on the descriptor, not `sys.stdin.buffer`: a daemon thread blocked
    inside a buffered read holds that buffer's lock, and the interpreter cannot
    finish shutting down past it. At most `_AHEAD` lines are read ahead of the
    session. Lines are decoded as UTF-8 with replacement, as the SDK's reader does.
    """

    _CHUNK = 65536
    _AHEAD = 16

    def __init__(self, fd: int = 0) -> None:
        self._fd = fd
        self._queue: asyncio.Queue[str | None] | None = None
        self._room = threading.Semaphore(self._AHEAD)

    def __aiter__(self) -> "_StdinLines":
        return self

    async def __anext__(self) -> str:
        if self._queue is None:
            self._queue = asyncio.Queue()
            threading.Thread(
                target=self._pump,
                args=(asyncio.get_running_loop(), self._queue),
                name="gateway-stdin",
                daemon=True,
            ).start()
        line = await self._queue.get()
        self._room.release()
        if line is None:
            raise StopAsyncIteration
        return line

    def _pump(self, loop: asyncio.AbstractEventLoop, lines: "asyncio.Queue[str | None]") -> None:
        def put(item: str | None) -> bool:
            self._room.acquire()
            try:
                loop.call_soon_threadsafe(lines.put_nowait, item)
            except RuntimeError:  # the loop has closed: nobody is reading
                return False
            return True

        pending = b""
        try:
            while chunk := os.read(self._fd, self._CHUNK):
                pending += chunk
                *complete, pending = pending.split(b"\n")
                for line in complete:
                    if not put((line + b"\n").decode("utf-8", "replace")):
                        return
        except OSError:
            pass
        if pending and not put(pending.decode("utf-8", "replace")):
            return
        put(None)


class StdioMouth:
    """`serve_stdio` as a mouth that can be stopped.

    It serves until the client closes stdin, or until `request_stop()`, which
    cancels the session at once rather than waiting for the client's next line.
    Before this existed the stdio gateway had no stop of its own: a `SIGTERM` took
    the default action and ended the process on the spot, before the launcher's
    cleanup (MCP-HOST.md M20).
    """

    def __init__(self, surface: Any) -> None:
        self._surface = surface
        self._stop_requested = False
        self._stopped: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def serve(self) -> None:
        # The event before the loop: `request_stop` reads them in the other order.
        self._stopped = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        if self._stop_requested:
            return
        session = asyncio.ensure_future(serve_stdio(self._surface, stdin=_StdinLines()))
        stop = asyncio.ensure_future(self._stopped.wait())
        try:
            await asyncio.wait({session, stop}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stop.cancel()
            if not session.done():
                session.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session  # a session that failed raises here

    def request_stop(self) -> None:
        """Ask `serve()` to return. Safe from a signal handler, before or during serving."""
        self._stop_requested = True
        loop, stopped = self._loop, self._stopped
        if loop is not None and stopped is not None:
            with contextlib.suppress(RuntimeError):  # the loop has already closed
                loop.call_soon_threadsafe(stopped.set)


_budget_lock = threading.Lock()
_budget: DiagnosticBudget | None = None
_budget_holders = 0


@contextlib.contextmanager
def _server_diagnostics_bounded() -> Iterator[None]:
    """Hold ONE `DiagnosticBudget` on the server's logger while any mouth serves.

    Every HTTP mouth in the process logs through the same server logger, so the
    bound G20 states is per process: two mouths serving at once share one budget
    rather than stacking two. The last mouth to stop removes it and reports what
    it held back.
    """
    global _budget, _budget_holders
    with _budget_lock:
        if _budget_holders == 0:
            _budget = DiagnosticBudget()
            logging.getLogger(SERVER_LOGGER).addFilter(_budget)
        _budget_holders += 1
    try:
        yield
    finally:
        suppressed = 0
        with _budget_lock:
            _budget_holders -= 1
            if _budget_holders == 0 and _budget is not None:
                logging.getLogger(SERVER_LOGGER).removeFilter(_budget)
                suppressed = _budget.drain()
                _budget = None
        if suppressed:
            print(
                f"[broker] {suppressed} server diagnostic(s) suppressed before shutdown",
                file=sys.stderr,
            )


def _server_without_signal_capture(uvicorn: Any) -> type:
    """The HTTP server class, minus its own signal handlers.

    The server would take SIGINT and SIGTERM for itself while it serves. With two
    mouths in one loop, two servers taking them in turn leave a signal reaching
    one server and not the other. So no server takes them: the launcher's one
    handler (`__main__._stop_signals_reach`) stays in place throughout and stops
    every mouth the process opened.
    """

    class _Server(uvicorn.Server):  # type: ignore[misc, name-defined]
        @contextlib.contextmanager
        def capture_signals(self) -> Iterator[None]:
            yield

        def install_signal_handlers(self) -> None:  # releases before capture_signals
            return None

    return _Server


class _ServedMouth:
    """One authenticated HTTP mouth: the guard, an application, a server, a stop.

    What every HTTP mouth shares, written once:

      - every request is authenticated before the application sees it
        (`ConnectionGuard` is the outermost ASGI layer, G12);
      - calls into the runtime are serialized on one thread, held by
        `SerializedSurface` and not left to how a handler happens to be written
        (G18);
      - refused connections are counted and recorded through `record_refusals`,
        the one thing this object can do to the audit tape (G17);
      - what the HTTP server underneath writes to stderr is bounded by
        `DiagnosticBudget`, because some of it is written for requests the
        guard never sees, and request lines are not logged at all (G20).

    BUILD AND SERVE ON THE THREAD THAT BUILT THE RUNTIME. The event loop runs on
    the thread that calls `serve()`, the handlers call the runtime synchronously
    on that loop, and the runtime (and a sqlite store's connections) belong to
    the thread that made them. While a call is inside the runtime the loop is
    blocked and nothing else is served, which is the same serialization `/call`
    gets from a single-threaded server, and is the point.

    `listener` is an already-bound, listening socket (`network.bind_listener`), so
    a bad address has refused before this object exists. `surface` may already be
    a `SerializedSurface`; mouths sharing one runtime must share that one object,
    so that its rules cover all of them together.
    """

    def __init__(
        self,
        surface: Any,
        *,
        authenticator: Authenticator,
        record_refusals: Callable[[Mapping[str, int]], None],
        listener: socket.socket,
    ) -> None:
        self._surface = surface if isinstance(surface, SerializedSurface) else SerializedSurface(surface)
        self._authenticator = authenticator
        self._ledger = RefusalLedger(record_refusals)
        self._listener = listener
        self._server: Any = None
        self._stop_requested = False

    def _application(self) -> Any:
        raise NotImplementedError

    def build_app(self) -> Any:
        """The ASGI application: the guard, then this mouth's application."""
        return ConnectionGuard(self._application(), self._authenticator, self._ledger)

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
        self._server = _server_without_signal_capture(uvicorn)(config)
        # One-way, and never an assignment of the flag's value: `request_stop`
        # may run from a signal handler between any two of these lines, and a
        # stop it has already set on the server must not be written back to False.
        if self._stop_requested:
            self._server.should_exit = True
        # The server logs a line for a request it cannot parse, before the guard
        # is asked anything. Bound it, so a stranger cannot grow a kept stderr.
        with _server_diagnostics_bounded():
            try:
                await self._server.serve(sockets=[self._listener])
            finally:
                self._ledger.close()

    def request_stop(self) -> None:
        """Ask `serve()` to return, whether it is running or has yet to start.

        A stop requested before `serve()` is remembered: the mouth starts, sees
        it, and shuts down without serving. Safe to call from another thread or
        from a signal handler, and any number of times.
        """
        self._stop_requested = True
        if self._server is not None:
            self._server.should_exit = True


class NetworkMouth(_ServedMouth):
    """The network MCP mouth: the same surface, over streamable HTTP (G11 to G20).

    A sibling to `serve_stdio`. What differs is only what a socket forces, and
    that is `_ServedMouth`. The application is the one route in front of the SDK's
    session manager.
    """

    def _application(self) -> Any:
        """The one route, then the SDK.

        Only the two arguments every SDK release in the supported range accepts
        are passed to the session manager; the rest are the SDK's defaults.
        """
        from mcp.server.streamable_http_manager import (  # noqa: PLC0415 — optional extra
            StreamableHTTPSessionManager,
        )

        manager = StreamableHTTPSessionManager(app=build_server(self._surface))
        return MouthApp(manager.handle_request, manager.run)


async def serve_until_any_stops(mouths: Sequence[Any]) -> None:
    """Serve every mouth on this loop until one returns, then stop the others.

    The mouths share this loop, and so the thread that built the runtime (G18).
    When one returns, because it was stopped, because its client went away, or
    because it failed, the rest are asked to stop. Every mouth
    then finishes its own shutdown, ledger tail included, before this returns.
    The first failure is raised once all of them have stopped.
    """
    tasks = [asyncio.ensure_future(mouth.serve()) for mouth in mouths]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for mouth, task in zip(mouths, tasks):
            if not task.done():
                mouth.request_stop()
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result
