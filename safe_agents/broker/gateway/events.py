"""events.py — the tool-event mouth, minus the HTTP server.

A coding harness has tools of its own: a shell, file reads and writes, a web
fetch. Their calls never become MCP calls, so the gateway never sees them. A
harness's hooks can report each one after it ran, and this is where such a
report arrives (`broker/GATEWAY.md` G21 on).

The mouth OBSERVES. It never decides, and nothing it receives is a request for
anything: the call it reports has already happened. A valid report reaches one
runtime method, `BrokerRuntime.record_observed_event`, which writes one record
and, when the tool read something, taints the broker-held session turn. A
forged report can only add taint, so the most it costs is approvals. A report
the harness never sends is the harness's own fail-open, and no mouth fixes it.

Plain ASGI and SDK-free, like `network.py`. `server.py` serves it on a socket
of its own, beside the MCP mouth on either transport, behind the same guard,
the same authenticator and the same launch token (G12 to G14). Its refusals
are recorded under their own mouth code (G17), and it enters the runtime
through the same `SerializedSurface` as every other mouth in the process (G18).
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from safe_agents.broker.gateway.authn import (
    Authenticator,
    GatewayConfigError,
    resolve_authenticator,
)
from safe_agents.broker.gateway.network import DEFAULT_HOST, parse_port
from safe_agents.broker.runtime.observed import validate_observed_event

logger = logging.getLogger(__name__)

#: The code this mouth passes to the runtime: on each observed record, and as
#: the `op` of its refusal records (`BrokerRuntime.record_refused_connections`).
EVENT_MOUTH_CODE = "tool-event"

#: The one path the mouth serves. Not a setting, for the reason `/mcp` is not.
EVENTS_PATH = "/events"

#: Named = the mouth opens. 0 = any free port.
EVENT_PORT_ENV = "BROKER_EVENT_MOUTH_PORT"
#: The bind address. Default loopback.
EVENT_HOST_ENV = "BROKER_EVENT_MOUTH_HOST"
#: Optional: a file the gateway writes `host:port` to once bound, for a launcher
#: that asked for port 0. It holds no secret.
EVENT_ADDR_FILE_ENV = "BROKER_EVENT_MOUTH_ADDR_FILE"

#: The most a report body may be. A valid report is a few hundred bytes; the
#: bound is what stops a caller making the mouth read without limit.
MAX_EVENT_BODY_BYTES = 4096

#: The keys a report may carry. Any other key is refused, so a field the mouth
#: does not understand is never silently dropped.
_REQUIRED_KEYS = frozenset({"harness", "tool_class", "locality", "subject_digest"})
_OPTIONAL_KEYS = frozenset({"result_digest"})

_BAD_REQUEST_BODY = json.dumps({"error": "bad request"}).encode()
_NOT_FOUND_BODY = json.dumps({"error": "not found"}).encode()
_NOT_RECORDED_BODY = json.dumps({"error": "not recorded"}).encode()

Observe = Callable[..., "str | None"]


async def _respond(send: Callable[[dict], Awaitable[None]], status: int, body: bytes) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class _Malformed(Exception):
    """A report the mouth refuses with its one fixed 400."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _Malformed("a key is repeated")
    return dict(pairs)


def parse_report(body: bytes) -> dict[str, Any]:
    """The report's fields, checked against the vocabulary, or `_Malformed`.

    The checks are `observed.validate_observed_event`'s, run here so a malformed
    report is refused before it enters the runtime. The runtime runs them again.
    """
    try:
        report = json.loads(body, object_pairs_hook=_no_duplicate_keys)
    except _Malformed:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise _Malformed("not JSON") from exc
    if not isinstance(report, dict):
        raise _Malformed("not an object")
    keys = set(report)
    if not _REQUIRED_KEYS <= keys or keys - _REQUIRED_KEYS - _OPTIONAL_KEYS:
        raise _Malformed("wrong keys")
    fields = {
        "harness": report["harness"],
        "tool_class": report["tool_class"],
        "locality": report["locality"],
        "subject_digest": report["subject_digest"],
        "result_digest": report.get("result_digest"),
    }
    try:
        validate_observed_event(mouth=EVENT_MOUTH_CODE, **fields)
    except ValueError as exc:
        raise _Malformed(str(exc)) from exc
    return fields


class EventApp:
    """The one route, as plain ASGI. Sits behind `ConnectionGuard`.

    `POST /events` with a JSON report gets 200 and `{"source": <id or null>}`.
    Anything else on that path, a wrong method, a body that is not a report, a
    body over `max_body` bytes, gets one fixed 400 and writes nothing to the
    tape. Any other path gets 404. A report the runtime could not record gets a
    fixed 500; the taint it carried may already have landed, because the runtime
    taints before it writes.

    `observe` is `SerializedSurface.observe` with the mouth code bound. It is the
    only thing this object can do to the runtime.
    """

    def __init__(
        self,
        observe: Observe,
        *,
        path: str = EVENTS_PATH,
        max_body: int = MAX_EVENT_BODY_BYTES,
    ) -> None:
        self._observe = observe
        self._path = path
        self._max_body = max_body

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        if scope.get("path") != self._path:
            await _respond(send, 404, _NOT_FOUND_BODY)
            return
        try:
            if scope.get("method") != "POST":
                raise _Malformed("wrong method")
            fields = parse_report(await self._read_body(scope, receive))
        except _Malformed:
            await _respond(send, 400, _BAD_REQUEST_BODY)
            return
        try:
            source = self._observe(**fields)
        except ValueError:
            await _respond(send, 400, _BAD_REQUEST_BODY)
            return
        except Exception as exc:  # noqa: BLE001 — answer the hook; the detail goes to stderr
            logger.error(
                "a tool-event report was not recorded: %s: %s",
                type(exc).__name__, exc, exc_info=True,
            )
            await _respond(send, 500, _NOT_RECORDED_BODY)
            return
        await _respond(send, 200, json.dumps({"source": source}).encode())

    async def _read_body(self, scope: dict, receive: Any) -> bytes:
        """Read at most `max_body` bytes, refusing before reading past it."""
        for name, value in scope.get("headers", ()):
            if name.lower() == b"content-length":
                try:
                    declared = int(value)
                except ValueError as exc:
                    raise _Malformed("bad content-length") from exc
                if declared > self._max_body:
                    raise _Malformed("too large")
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                raise _Malformed("the request ended before its body")
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self._max_body:
                raise _Malformed("too large")
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)

    @staticmethod
    async def _lifespan(receive: Any, send: Any) -> None:
        await receive()  # lifespan.startup
        await send({"type": "lifespan.startup.complete"})
        await receive()  # lifespan.shutdown
        await send({"type": "lifespan.shutdown.complete"})


@dataclass(frozen=True)
class EventMouthSettings:
    """The tool-event mouth's launch settings, resolved and validated."""

    host: str
    port: int
    authenticator: Authenticator
    addr_file: str | None = None


def resolve_event_mouth(env: Mapping[str, str] | None = None) -> EventMouthSettings | None:
    """The tool-event mouth's settings, None when it is not asked for, or a refusal.

    The port is what opens it: unset, the mouth stays shut and nothing else is
    read. A host or an address file named without a port refuses, because a
    launcher that named either expected a mouth. The authenticator is the network
    MCP mouth's (G13, G14): unnamed refuses to start, on loopback as anywhere.
    """
    source = os.environ if env is None else env
    raw_port = source.get(EVENT_PORT_ENV, "")
    if not raw_port:
        stray = [name for name in (EVENT_HOST_ENV, EVENT_ADDR_FILE_ENV) if source.get(name)]
        if stray:
            raise GatewayConfigError(
                f"{' and '.join(stray)} named but {EVENT_PORT_ENV} is unset; refusing "
                "to start: the tool-event mouth opens when its port is named, and "
                "a launcher that named its address expected it open."
            )
        return None
    authenticator = resolve_authenticator(source)
    port = parse_port(raw_port, EVENT_PORT_ENV)
    host = source.get(EVENT_HOST_ENV, "") or DEFAULT_HOST
    return EventMouthSettings(
        host=host,
        port=port,
        authenticator=authenticator,
        addr_file=source.get(EVENT_ADDR_FILE_ENV, "") or None,
    )


def write_address_file(path: str, host: str, port: int) -> None:
    """Write `host:port` and a newline to `path`, owner-only (an IPv6 host bracketed).

    Created or truncated. Not followed through a symbolic link where the platform
    can refuse one. The file holds no secret, and is owner-only anyway: what
    listens where is the launcher's business. Refuses, in words, when it cannot.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            if sys.platform != "win32":
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            shown = f"[{host}]" if ":" in host else host
            os.write(fd, f"{shown}:{port}\n".encode("ascii"))
        finally:
            os.close(fd)
    except OSError as exc:
        raise GatewayConfigError(
            f"{EVENT_ADDR_FILE_ENV}={path} could not be written ({exc})"
        ) from exc
