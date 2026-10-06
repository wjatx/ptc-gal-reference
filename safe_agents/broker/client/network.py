"""A minimal MCP client for the gateway's network MCP mouth (streamable HTTP).

    with NetworkGatewayClient("http://127.0.0.1:8765/mcp", token=token) as gateway:
        gateway.initialize()
        tools = gateway.list_tools()
        result = gateway.call_tool("payments__transfer", {"amount": "1000"})

The sibling of the stdio `GatewayClient`, for a consumer that cannot be the
gateway's parent process: an agent inside a sandbox, with the gateway outside it.
The frames, the three calls, the error and `result_text` are the stdio client's
(`_frames.py`); only the carrying differs.

Standard library only, and raw JSON-RPC over `http.client` rather than the `mcp`
SDK's client, for the same two reasons as the stdio client: the frames on the wire
are the ones any MCP client sends, and a consumer needs nothing installed to ask.

## What the transport requires, and what this does about it

  - Every message is a `POST` of one JSON-RPC frame to the one MCP endpoint, with
    `Content-Type: application/json` and an `Accept` naming BOTH `application/json`
    and `text/event-stream`. A server may answer a request with either, so both
    are read: a JSON body, or an event stream that is read until the event
    carrying this request's reply.
  - A notification is answered `202 Accepted` with no body.
  - The reply to `initialize` may carry an `Mcp-Session-Id` header. It is sent
    back on every later request, with the negotiated revision as
    `MCP-Protocol-Version`. `close()` ends the session with a `DELETE`.
  - The launch token goes in `Authorization: Bearer <token>` on EVERY request,
    which is what the mouth checks on every request. It is never put in the URL.

## Every wait is bounded

One deadline covers a whole exchange: connecting, sending, and reading the reply
to its last byte. A socket timeout alone bounds each read and not the sum of
them, so a peer that sends one byte at a time could hold a caller for as long as
it liked. A timer therefore shuts the socket at the deadline, which ends
whichever read is waiting. Resolving a host NAME is the one step the standard
library cannot bound; an address literal, which is what a launcher reports,
involves none.

**A timeout or a dropped connection does not mean the call was not made.** The
frame may have reached the broker, been decided and taken effect before the
reply was lost. This client reports that no reply came and does not retry: a
retry would be a second call, and whether to make one is not a client's decision.

## What this does not do

It does not follow redirects (the token would follow them to wherever they
point), does not speak TLS (the mouth it is written for serves plain HTTP, and a
URL with any other scheme is refused), does not open the standing `GET` stream
for messages a server starts on its own, does not resume a broken event stream,
and does not answer a request a server sends to it. The gateway does none of
those things to a client.

This module decides nothing. It carries frames and reports what came back.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import threading
from typing import Any
from urllib.parse import urlsplit

from safe_agents.broker.client._frames import (
    DEFAULT_TIMEOUT_SECONDS,
    GatewayClientError,
    McpCalls,
    notification_frame,
    request_frame,
    result_of,
)

SESSION_ID_HEADER = "Mcp-Session-Id"
PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_EVENT_STREAM = "text/event-stream"

_SCHEME = "http"
_INITIALIZE = "initialize"
_ACCEPT = f"{CONTENT_TYPE_JSON}, {CONTENT_TYPE_EVENT_STREAM}"

# Ending a session is a courtesy to the server, so it gets a shorter wait than a
# call does: a gateway that has gone must not hold up the caller's exit.
_CLOSE_TIMEOUT_SECONDS = 5.0

# How much of an error body is quoted in a message.
_DETAIL_CHARS = 500

# What may appear in a header value this client sends: visible ASCII, no spaces.
# Narrower than HTTP allows and wide enough for any bearer token or session id.
_HEADER_SAFE = re.compile(r"[\x21-\x7e]+")

_UNSET = object()


class NetworkGatewayClient(McpCalls):
    """One MCP session with a gateway's network MCP mouth, authenticated by launch token."""

    client_name = "safe-agents-network-client"

    def __init__(self, url: str, *, token: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise GatewayClientError(f"{url!r} is not a URL this client can read") from None
        if parts.scheme != _SCHEME:
            raise GatewayClientError(
                f"the gateway URL must start with {_SCHEME}:// (got scheme {parts.scheme!r}); "
                "the network MCP mouth serves plain HTTP and this client speaks nothing else"
            )
        if not parts.hostname:
            raise GatewayClientError("the gateway URL names no host")
        if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
            raise GatewayClientError(
                "the gateway URL must be only where the gateway listens: no user, "
                "password, query string or fragment. The token is passed as `token` "
                "and travels in a header, never in the URL"
            )
        # Never echo the value: this message may be logged.
        if not isinstance(token, str) or not _HEADER_SAFE.fullmatch(token):
            raise GatewayClientError(
                "the launch token is empty or contains characters that cannot be "
                "sent in a header (whitespace, control or non-ASCII characters); "
                "pass it exactly as the launcher supplied it, with no trailing newline"
            )
        if not timeout > 0:
            raise GatewayClientError("timeout must be a positive number of seconds")
        self.url = url
        self.timeout = timeout
        self._host = parts.hostname
        self._port = port
        self._path = parts.path or "/"
        self._authorization = f"Bearer {token}"
        self._session_id: str | None = None
        self._protocol_version: str | None = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.url!r})"

    # -- context manager ---------------------------------------------------------

    def __enter__(self) -> NetworkGatewayClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def session_id(self) -> str | None:
        """The session the server opened at `initialize`, if it opened one."""
        return self._session_id

    # -- plumbing ----------------------------------------------------------------

    def _headers(self, *, with_body: bool) -> dict[str, str]:
        headers = {
            "Authorization": self._authorization,
            "Accept": _ACCEPT,
            # One connection per exchange. A session is carried by its header and
            # not by a connection, and a fresh connection cannot have gone stale
            # since the last call.
            "Connection": "close",
        }
        if with_body:
            headers["Content-Type"] = CONTENT_TYPE_JSON
        if self._session_id is not None:
            headers[SESSION_ID_HEADER] = self._session_id
        if self._protocol_version is not None:
            headers[PROTOCOL_VERSION_HEADER] = self._protocol_version
        return headers

    def _exchange(
        self,
        http_method: str,
        frame: dict[str, Any] | None,
        *,
        what: str,
        reply_to: Any = _UNSET,
        timeout: float | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """One HTTP exchange under one deadline.

        `what` names the exchange in messages. Returns the JSON-RPC frame
        answering `reply_to` (None when no reply was asked for, once the server
        has accepted the message) and the session id header of the response.
        """
        limit = self.timeout if timeout is None else timeout
        connection = http.client.HTTPConnection(self._host, self._port, timeout=limit)
        expired = threading.Event()
        # The socket is held here and not read off the connection at the deadline:
        # once a response that ends with the connection has its headers, the
        # connection object lets go of its socket while the response reads on.
        held: list[socket.socket] = []

        def shut_at_deadline() -> None:
            expired.set()
            for sock in held:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        deadline = threading.Timer(limit, shut_at_deadline)
        deadline.daemon = True
        deadline.start()
        try:
            connection.connect()
            held.append(connection.sock)
            if expired.is_set():
                raise TimeoutError
            body = None if frame is None else json.dumps(frame).encode("utf-8")
            connection.request(http_method, self._path, body=body, headers=self._headers(with_body=body is not None))
            response = connection.getresponse()
            return self._read(response, what=what, reply_to=reply_to)
        except GatewayClientError:
            if expired.is_set():
                raise self._no_reply(what, limit) from None
            raise
        except (OSError, http.client.HTTPException) as exc:
            if expired.is_set() or isinstance(exc, TimeoutError):
                raise self._no_reply(what, limit) from None
            raise GatewayClientError(
                f"the gateway at {self.url} could not be reached, or closed the connection "
                f"before replying to {what} ({type(exc).__name__}: {exc}). If a call was "
                "in flight, this does not say whether it was made"
            ) from None
        finally:
            deadline.cancel()
            connection.close()

    @staticmethod
    def _no_reply(what: str, limit: float) -> GatewayClientError:
        return GatewayClientError(
            f"no reply to {what} within {limit:g}s. If a call was in flight, this does "
            "not say whether it was made"
        )

    def _read(
        self, response: http.client.HTTPResponse, *, what: str, reply_to: Any
    ) -> tuple[dict[str, Any] | None, str | None]:
        status = response.status
        content_type = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
        if status == http.client.UNAUTHORIZED:
            raise GatewayClientError(
                f"the gateway refused {what} (HTTP 401): it did not accept the launch "
                "token. Nothing was served and no call was made"
            )
        if not 200 <= status < 300:
            detail = _error_detail(response.read(), content_type)
            if status == http.client.NOT_FOUND and self._session_id is not None:
                raise GatewayClientError(
                    f"the gateway no longer knows this session (HTTP 404 for {what}: {detail}); "
                    "it has ended the session or restarted. Start a new client"
                )
            raise GatewayClientError(f"the gateway answered {what} with HTTP {status}: {detail}")
        if reply_to is _UNSET:
            response.read()
            return None, None
        if content_type == CONTENT_TYPE_JSON:
            frame = _matching_frame(_decode_json(response.read(), what), reply_to)
        elif content_type == CONTENT_TYPE_EVENT_STREAM:
            frame = _reply_from_event_stream(response, reply_to, what)
        else:
            raise GatewayClientError(
                f"the gateway answered {what} with content type {content_type!r}; a "
                f"request is answered with {CONTENT_TYPE_JSON} or {CONTENT_TYPE_EVENT_STREAM}"
            )
        if frame is None:
            raise GatewayClientError(
                f"the gateway's answer to {what} ended without a reply to it. If a call "
                "was in flight, this does not say whether it was made"
            )
        return frame, response.getheader(SESSION_ID_HEADER)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no reply)."""
        self._exchange("POST", notification_frame(method, params), what=repr(method))

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a request and return its `result`.

        Raises GatewayClientError on a JSON-RPC error, a refused connection (wrong
        token), any other HTTP error, an answer that is not MCP, the server going
        away, or the deadline passing.
        """
        request_id = self._take_id()
        frame, session_id = self._exchange(
            "POST", request_frame(request_id, method, params), what=repr(method), reply_to=request_id
        )
        assert frame is not None
        result = result_of(frame, method)
        if method == _INITIALIZE:
            self._adopt_session(session_id, result)
        return result

    def _adopt_session(self, session_id: str | None, result: dict[str, Any]) -> None:
        """Remember what the handshake fixed: the session and the revision spoken.

        Both come back to the server as header values, so a value that could not
        be sent as one is refused here and not at the next call.
        """
        version = result.get("protocolVersion")
        for value in (session_id, version):
            if value is not None and not (isinstance(value, str) and _HEADER_SAFE.fullmatch(value)):
                raise GatewayClientError(
                    "the gateway's reply to 'initialize' carried a session id or protocol "
                    "version that cannot be sent back in a header"
                )
        self._session_id = session_id
        self._protocol_version = version

    # -- shutdown ------------------------------------------------------------------

    def close(self) -> None:
        """End the session, if the server opened one. Never raises; safe to repeat.

        A server that has gone, or that does not let a client end a session, is
        not an error at the point of leaving.
        """
        if self._session_id is None:
            return
        try:
            self._exchange(
                "DELETE", None, what="the end of the session",
                timeout=min(self.timeout, _CLOSE_TIMEOUT_SECONDS),
            )
        except GatewayClientError:
            pass
        finally:
            self._session_id = None


def _decode_json(raw: bytes, what: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise GatewayClientError(
            f"the gateway's answer to {what} was not JSON: {raw[:_DETAIL_CHARS]!r}"
        ) from None


def _matching_frame(payload: Any, reply_to: Any) -> dict[str, Any] | None:
    """The reply to `reply_to` in `payload`: one frame, or a batch of them.

    Anything else a server interleaves (a notification, a request of its own, a
    reply to another id) is skipped, as the stdio client skips it.
    """
    for frame in payload if isinstance(payload, list) else [payload]:
        if (
            isinstance(frame, dict)
            and frame.get("id") == reply_to
            and ("result" in frame or "error" in frame)
        ):
            return frame
    return None


def _reply_from_event_stream(response: http.client.HTTPResponse, reply_to: Any, what: str) -> dict[str, Any] | None:
    """Read server-sent events until the one carrying the reply to `reply_to`.

    Only `data` is used. An event with no data (a comment the server sends to keep
    the stream open, or the empty event newer revisions open a stream with) is
    skipped. Returns None if the stream ends first.
    """
    data: list[str] = []
    while True:
        raw = response.readline()
        if not raw:
            return None
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line:
            name, _, value = line.partition(":")
            if name == "data":
                data.append(value[1:] if value.startswith(" ") else value)
            continue
        # A blank line ends one event.
        text, data = "\n".join(data), []
        if not text:
            continue
        frame = _matching_frame(_decode_json(text.encode("utf-8"), what), reply_to)
        if frame is not None:
            return frame


def _error_detail(raw: bytes, content_type: str) -> str:
    """What an error body says, shortened: the JSON-RPC message when there is one."""
    text = raw.decode("utf-8", "replace")
    if content_type == CONTENT_TYPE_JSON:
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            text = str(payload["error"].get("message", text))
    text = text.strip()
    return text[:_DETAIL_CHARS] or "(no body)"
