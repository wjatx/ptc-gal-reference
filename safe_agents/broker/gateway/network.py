"""network.py — the network MCP mouth, minus the SDK.

The gateway's third module of pure logic, beside `surface.py` (what is advertised
and answered) and `authn.py` (who may speak). This one holds everything about
serving MCP over a socket that does not need the `mcp` SDK to state or to test:

  - `ConnectionGuard` puts the authenticator in front of every request, as plain
    ASGI, so the check runs before the SDK sees a byte.
  - `MouthApp` is the one route and the lifespan, also plain ASGI.
  - `SerializedSurface` holds the runtime's two concurrency rules where a
    transport cannot quietly break them. Every mouth in the process enters
    the runtime through the same one.
  - `DiagnosticBudget` bounds what the HTTP server underneath may write to the
    diagnostic stream, because a caller who has not authenticated can make it
    write.
  - `resolve_transport` / `resolve_network_mouth` read the launch settings from
    the environment, the same place every other broker setting comes from
    (`broker/GATEWAY.md` G10).

"The HTTP mouth" in this repository already names `/call`. This is the NETWORK
MCP MOUTH: the same `GatewaySurface` the stdio mouth serves, reached over
streamable HTTP.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from safe_agents.broker.gateway.authn import (
    ADMITTED,
    Authenticator,
    ConnectionFacts,
    GatewayConfigError,
    RefusalCause,
    RefusalLedger,
    resolve_authenticator,
)

#: The code this mouth's refusal records carry as their `op`
#: (`BrokerRuntime.record_refused_connections`).
MOUTH_CODE = "network-mcp"

#: The one path the mouth serves. Not a setting: a second config surface for a
#: value nobody needs to vary is what G10 forbids.
MCP_PATH = "/mcp"

TRANSPORT_ENV = "BROKER_GATEWAY_TRANSPORT"
HOST_ENV = "BROKER_GATEWAY_HOST"
PORT_ENV = "BROKER_GATEWAY_PORT"

TRANSPORT_STDIO = "stdio"
TRANSPORT_STREAMABLE_HTTP = "streamable-http"
#: The CLOSED set of transports. Unset means stdio, which is what the gateway
#: served before this one existed; anything else must be named exactly.
_TRANSPORTS = (TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP)

#: Loopback unless the launcher names something else.
DEFAULT_HOST = "127.0.0.1"

ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]

_UNAUTHORIZED_BODY = json.dumps({"error": "unauthorized"}).encode()
_NOT_FOUND_BODY = json.dumps({"error": "not found"}).encode()


async def _respond(send: Callable[[dict], Awaitable[None]], status: int, body: bytes,
                   extra_headers: tuple[tuple[bytes, bytes], ...] = ()) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            *extra_headers,
        ],
    })
    await send({"type": "http.response.body", "body": body})


class ConnectionGuard:
    """Authenticate every request before anything behind it runs.

    Plain ASGI and outermost, so the check precedes routing, the session lookup
    and the SDK. It runs on EVERY request and not once per session: a session id
    is something a caller sends, and nothing a caller sends may stand in for the
    credential.

    A refused request gets one fixed `401`. The reply does not say which check
    failed and is not a JSON-RPC frame, because no MCP frame is served to a
    connection that has not authenticated. The cause goes to the ledger, as a
    code from a closed vocabulary.

    `lifespan` is the server's own start and stop, not a caller's frame, and
    passes through. Any other non-HTTP scope is refused.
    """

    def __init__(self, app: ASGIApp, authenticator: Authenticator, ledger: RefusalLedger) -> None:
        self._app = app
        self._authenticator = authenticator
        self._ledger = ledger

    def _verdict(self, scope: dict) -> RefusalCause | None:
        """The cause to refuse for, or None to admit. Fails closed on everything."""
        if scope["type"] != "http":
            return RefusalCause.UNSUPPORTED_SCOPE
        try:
            facts = ConnectionFacts(
                authorization=tuple(
                    value for name, value in scope.get("headers", ())
                    if name.lower() == b"authorization"
                ),
                query_string=scope.get("query_string", b"") or b"",
            )
            verdict = self._authenticator.check(facts)
        except Exception:  # noqa: BLE001 — a check that raises has not admitted
            return RefusalCause.AUTHENTICATOR_ERROR
        if verdict is ADMITTED:
            return None
        if isinstance(verdict, RefusalCause):
            return verdict
        # Neither the admitting value nor a cause: a broken authenticator. Refuse.
        return RefusalCause.AUTHENTICATOR_ERROR

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._app(scope, receive, send)
            return
        cause = self._verdict(scope)
        if cause is None:
            # An authenticated request is also a moment to write out refusals
            # that have been waiting for their window, so a burst followed by
            # ordinary traffic does not sit unrecorded until shutdown.
            self._ledger.flush_if_due()
            await self._app(scope, receive, send)
            return
        self._ledger.refuse(cause)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        await _respond(send, 401, _UNAUTHORIZED_BODY, ((b"www-authenticate", b"Bearer"),))


class MouthApp:
    """The one route and the lifespan, as plain ASGI.

    `handler` serves a request for `MCP_PATH`; `running` is an async context
    manager held open for the server's life (the SDK session manager's `run()`).
    Written by hand, and not as a router with one entry, so the mouth depends on
    no framework's routing behaviour (a mounted path that answers `/mcp` with a
    redirect to `/mcp/`, for one).
    """

    def __init__(
        self,
        handler: ASGIApp,
        running: Callable[[], AbstractAsyncContextManager[Any]],
        *,
        path: str = MCP_PATH,
    ) -> None:
        self._handler = handler
        self._running = running
        self._path = path

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope.get("path") != self._path:
            await _respond(send, 404, _NOT_FOUND_BODY)
            return
        await self._handler(scope, receive, send)

    async def _lifespan(self, receive: Any, send: Any) -> None:
        await receive()  # lifespan.startup
        try:
            running = self._running()
            await running.__aenter__()
        except Exception as exc:  # noqa: BLE001 — report it; the server will not start
            await send({"type": "lifespan.startup.failed", "message": str(exc)})
            return
        try:
            await send({"type": "lifespan.startup.complete"})
            await receive()  # lifespan.shutdown
        finally:
            await running.__aexit__(None, None, None)
        await send({"type": "lifespan.shutdown.complete"})


class RuntimeEntryRefused(RuntimeError):
    """A transport tried to enter the broker runtime in a way it does not allow."""


class SerializedSurface:
    """A `GatewaySurface` that can only be entered one call at a time, on one thread.

    The runtime behind the surface is not thread-safe by design. One runtime
    serves one principal and threads ONE turn through every call, so two calls
    that overlap can drop one's taint or decide before a sibling's read has
    tainted the turn, and both of those fail OPEN (`runtime/pep.py`,
    `_session_turn`; the same reason `/call` is served single-threaded). The
    sqlite store arm adds a second rule: its connections belong to the thread
    that opened them.

    Both rules hold today because the SDK handlers call the surface synchronously
    on the event-loop thread. That is an accident of how two handlers are written,
    and this class turns it into something that fails loudly: a call from any
    thread but the one that built this object, or a call that arrives while
    another is inside, is REFUSED before it reaches the runtime. Moving the call
    onto a worker thread to "stop blocking the loop" then breaks visibly, where
    without this it would break silently and in the fail-open direction.

    Build it on the thread that built the runtime.
    """

    def __init__(self, surface: Any) -> None:
        self._surface = surface
        self._owner = threading.get_ident()
        self._busy = threading.Lock()

    @property
    def server_name(self) -> str:
        return self._surface.server_name

    def _enter(self) -> None:
        if threading.get_ident() != self._owner:
            raise RuntimeEntryRefused(
                "the gateway refused to enter the broker runtime from a thread other "
                "than the one that built it; calls into one runtime are serialized "
                "on one thread"
            )
        if not self._busy.acquire(blocking=False):
            raise RuntimeEntryRefused(
                "the gateway refused to enter the broker runtime while another call "
                "was inside it; calls into one runtime are serialized"
            )

    def tools(self) -> Any:
        self._enter()
        try:
            return self._surface.tools()
        finally:
            self._busy.release()

    def call(self, wire_name: str, arguments: Any = None) -> Any:
        self._enter()
        try:
            return self._surface.call(wire_name, arguments)
        finally:
            self._busy.release()


#: The logger the HTTP server underneath the mouth writes its diagnostics to.
SERVER_LOGGER = "uvicorn.error"
#: The logger it would write request lines to. The mouth turns that log off.
ACCESS_LOGGER = "uvicorn.access"

#: Server diagnostics admitted per window. Enough to read a real fault by, and a
#: fixed ceiling on what a stranger can make the process write.
DIAGNOSTICS_PER_WINDOW = 20
DIAGNOSTICS_WINDOW_S = 60.0


class DiagnosticBudget(logging.Filter):
    """At most `per_window` server diagnostics per window; the rest are counted.

    The HTTP server logs a line for a request it cannot parse and for an upgrade
    it does not serve. Both happen BEFORE the guard is asked anything, so a
    caller with no credential chooses how many of those lines are written. A
    launcher that keeps the gateway's stderr in a file would then be keeping a
    file a stranger can grow without limit, which is the same flood G17 closes
    for the tape, one stream over.

    Attached to the server's logger for as long as the mouth serves. The budget
    is per window and not per message: which line is repeated is the caller's
    choice too. Nothing is dropped silently. Lines over the budget are counted,
    and the count rides the first line of the next window; `drain()` hands back
    whatever is still uncounted at shutdown.
    """

    def __init__(
        self,
        *,
        per_window: int = DIAGNOSTICS_PER_WINDOW,
        window_s: float = DIAGNOSTICS_WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        if per_window <= 0 or window_s <= 0:
            raise ValueError("per_window and window_s must be positive")
        self._per_window = per_window
        self._window_s = window_s
        self._clock = clock
        self._lock = threading.Lock()
        self._opened: float | None = None
        self._admitted = 0
        self._suppressed = 0

    def filter(self, record: logging.LogRecord) -> bool:
        with self._lock:
            now = self._clock()
            if self._opened is None or now - self._opened >= self._window_s:
                self._opened = now
                self._admitted = 0
            if self._admitted >= self._per_window:
                self._suppressed += 1
                return False
            self._admitted += 1
            carried, self._suppressed = self._suppressed, 0
        if carried:
            record.msg = (
                f"{record.getMessage()} "
                f"({carried} earlier server diagnostic(s) suppressed)"
            )
            record.args = None
        return True

    def drain(self) -> int:
        """Diagnostics suppressed and not yet reported. Resets the count."""
        with self._lock:
            suppressed, self._suppressed = self._suppressed, 0
        return suppressed


def resolve_transport(env: Mapping[str, str] | None = None) -> str:
    """Which mouth to launch: `stdio` (unset) or `streamable-http`. A typo refuses."""
    source = os.environ if env is None else env
    value = source.get(TRANSPORT_ENV, "") or TRANSPORT_STDIO
    if value not in _TRANSPORTS:
        raise GatewayConfigError(
            f"{TRANSPORT_ENV}={value!r} is not a recognized gateway transport; "
            "refusing to start: an unrecognized value must not fall back to a mouth "
            f"the launcher did not ask for. Valid values: unset (= {TRANSPORT_STDIO!r}), "
            + ", ".join(repr(t) for t in _TRANSPORTS) + "."
        )
    return value


def is_loopback(host: str) -> bool:
    """True when `host` can only be reached from this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class NetworkMouthSettings:
    """The network MCP mouth's launch settings, resolved and validated."""

    host: str
    port: int
    authenticator: Authenticator


def resolve_network_mouth(env: Mapping[str, str] | None = None) -> NetworkMouthSettings:
    """Resolve host, port and authenticator from the environment, or refuse.

    The authenticator is resolved FIRST, so a mouth nobody told how to
    authenticate refuses before it has looked at where it would listen.
    """
    source = os.environ if env is None else env
    authenticator = resolve_authenticator(source)
    host = source.get(HOST_ENV, "") or DEFAULT_HOST
    raw_port = source.get(PORT_ENV, "")
    if not raw_port:
        raise GatewayConfigError(
            f"{PORT_ENV} is unset; refusing to start the network MCP mouth: the "
            "launcher has to tell the agent where the gateway listens, so it names "
            "the port. 0 asks the operating system for a free one, which is "
            "reported on stderr once bound."
        )
    port = parse_port(raw_port, PORT_ENV)
    return NetworkMouthSettings(host=host, port=port, authenticator=authenticator)


def parse_port(raw: str, env_name: str) -> int:
    """A port number from 0 to 65535, or a refusal naming the setting."""
    try:
        port = int(raw)
    except ValueError:
        port = -1
    if not 0 <= port <= 65535:
        raise GatewayConfigError(f"{env_name}={raw!r} is not a port number (0 to 65535)")
    return port


def bind_listener(
    host: str, port: int, *, host_env: str = HOST_ENV, port_env: str = PORT_ENV
) -> socket.socket:
    """Bind and listen, so a bad address refuses at startup and in words.

    Returns the listening socket; with `port=0` its `getsockname()` says which
    port the operating system chose. Binding here, before the server loop exists,
    is also what lets a launcher learn the address before the first request.
    `host_env` and `port_env` name the settings the refusal tells the launcher to
    change, since more than one mouth binds through here.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        return socket.create_server((host, port), family=family)
    except OSError as exc:
        raise GatewayConfigError(
            f"could not listen on {host}:{port} ({exc}); set {host_env} / {port_env} "
            "to an address this machine can bind"
        ) from exc


def listener_url(listener: socket.socket, path: str = MCP_PATH) -> str:
    """The URL a client reaches the mouth at, from the bound socket."""
    host, port = listener_address(listener)
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port}{path}"


def listener_address(listener: socket.socket) -> tuple[str, int]:
    """The host and port the socket is bound to."""
    host, port = listener.getsockname()[:2]
    return host, port
