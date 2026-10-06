"""The network gateway client on the wire, against a scripted HTTP server.

`test_client_network_e2e.py` asks the real network MCP mouth. This file asks a
server that answers exactly what a test tells it to, which is the only way to
see the things the real mouth never does: a JSON answer where it would stream,
frames interleaved before the reply, a stream that stops early, a redirect, a
peer that sends one byte at a time and never finishes.

Standard library on both ends, so this runs with the optional `mcp` extra absent.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

import pytest

from safe_agents.broker.client import GatewayClientError, NetworkGatewayClient, result_text

TOKEN = "t0ken-" + "a" * 40
SESSION = "session-1"
REVISION = "2025-03-26"
_JSON = "application/json"
_SSE = "text/event-stream"
# Long enough that a slow machine does not trip it, short enough to wait out.
_SHORT_S = 1.0
# How far past its deadline a bounded wait may run before the test calls it unbounded.
_SLACK_S = 4.0


def _reply(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _sse(*events: str) -> bytes:
    return "".join(events).encode("utf-8")


def _event(payload: Any, newline: str = "\n") -> str:
    return f"event: message{newline}data: {json.dumps(payload)}{newline}{newline}"


class _Scripted:
    """An HTTP server that records every request and answers from `script`.

    `script(server, request)` returns `(status, headers, body)` or writes to
    `request["handler"]` itself and returns None.
    """

    def __init__(self, script: Callable[[_Scripted, dict[str, Any]], Any]) -> None:
        self.requests: list[dict[str, Any]] = []
        self.release = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                request = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": json.loads(raw) if raw else None,
                    "handler": self,
                }
                outer.requests.append(request)
                answer = script(outer, request)
                if answer is None:
                    return
                status, headers, body = answer
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_DELETE = do_GET = _serve

            def log_message(self, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/mcp"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.release.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(10)

    def methods(self) -> list[str]:
        return [
            r["body"]["method"] if r["body"] else r["method"] for r in self.requests
        ]


@pytest.fixture
def serve():
    servers: list[_Scripted] = []

    def start(script) -> _Scripted:
        servers.append(_Scripted(script))
        return servers[-1]

    yield start
    for server in servers:
        server.close()


def _well_behaved(answer_request) -> Callable[[_Scripted, dict[str, Any]], Any]:
    """A server that does the handshake properly and answers requests with `answer_request`."""

    def script(server: _Scripted, request: dict[str, Any]):
        body = request["body"]
        if request["method"] == "DELETE":
            return 200, {}, b""
        if "id" not in body:
            return 202, {}, b""
        if body["method"] == "initialize":
            frame = _reply(body["id"], {"protocolVersion": REVISION, "capabilities": {}, "serverInfo": {"name": "s"}})
            return 200, {"Content-Type": _JSON, "Mcp-Session-Id": SESSION}, json.dumps(frame).encode()
        return answer_request(server, request)

    return script


def _json_tools(server: _Scripted, request: dict[str, Any]):
    frame = _reply(request["body"]["id"], {"tools": [{"name": "search__query"}]})
    return 200, {"Content-Type": _JSON}, json.dumps(frame).encode()


class TestWhatTheClientSends:
    def test_the_handshake_then_every_request_carries_what_the_transport_requires(self, serve) -> None:
        server = serve(_well_behaved(_json_tools))
        with NetworkGatewayClient(server.url, token=TOKEN) as gateway:
            gateway.initialize()
            assert gateway.list_tools() == [{"name": "search__query"}]
            assert gateway.session_id == SESSION
        assert server.methods() == ["initialize", "notifications/initialized", "tools/list", "DELETE"]

        for request in server.requests:
            headers = request["headers"]
            # The token is on EVERY request, the session teardown included.
            assert headers["authorization"] == f"Bearer {TOKEN}"
            assert headers["accept"] == "application/json, text/event-stream"
            assert request["path"] == "/mcp"
        for request in server.requests[:3]:
            assert request["headers"]["content-type"] == "application/json"
            assert request["body"]["jsonrpc"] == "2.0"

        first, *later = server.requests
        assert "mcp-session-id" not in first["headers"]
        assert "mcp-protocol-version" not in first["headers"]
        assert first["body"]["params"]["protocolVersion"] == "2025-06-18"
        for request in later:
            assert request["headers"]["mcp-session-id"] == SESSION
            # The revision the SERVER chose, not the one this client offered.
            assert request["headers"]["mcp-protocol-version"] == REVISION
        assert "id" not in server.requests[1]["body"]
        assert [r["body"]["id"] for r in (server.requests[0], server.requests[2])] == [1, 2]

    def test_close_ends_the_session_once_and_only_if_there_was_one(self, serve) -> None:
        server = serve(_well_behaved(_json_tools))
        never_opened = NetworkGatewayClient(server.url, token=TOKEN)
        never_opened.close()
        assert server.requests == []

        gateway = NetworkGatewayClient(server.url, token=TOKEN)
        gateway.initialize()
        gateway.close()
        gateway.close()
        assert server.methods().count("DELETE") == 1
        assert gateway.session_id is None

    def test_a_server_that_opens_no_session_is_sent_no_session(self, serve) -> None:
        def script(server, request):
            body = request["body"]
            if "id" not in body:
                return 202, {}, b""
            result = {"protocolVersion": REVISION} if body["method"] == "initialize" else {"tools": []}
            return 200, {"Content-Type": _JSON}, json.dumps(_reply(body["id"], result)).encode()

        server = serve(script)
        with NetworkGatewayClient(server.url, token=TOKEN) as gateway:
            gateway.initialize()
            assert gateway.list_tools() == []
        assert all("mcp-session-id" not in r["headers"] for r in server.requests)
        assert "DELETE" not in server.methods()


_CALL = {"content": [{"type": "text", "text": "held"}], "isError": True}


def _answers() -> list[Any]:
    def other(request_id):
        return [
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "x"}},
            {"jsonrpc": "2.0", "id": 99, "method": "ping"},
            # A request the SERVER makes may reuse this request's id: each side
            # numbers its own. It is a request, and must not be read as the reply.
            {"jsonrpc": "2.0", "id": request_id, "method": "ping"},
            _reply(request_id + 1000, {"content": [], "isError": False}),
        ]

    return [
        pytest.param(lambda i: (_JSON, json.dumps(_reply(i, _CALL)).encode()), id="json"),
        pytest.param(lambda i: (_JSON + "; charset=utf-8", json.dumps(_reply(i, _CALL)).encode()),
                     id="json with a charset"),
        pytest.param(lambda i: (_JSON, json.dumps([*other(i), _reply(i, _CALL)]).encode()), id="json batch"),
        pytest.param(lambda i: (_SSE, _sse(_event(_reply(i, _CALL)))), id="event stream"),
        pytest.param(lambda i: (_SSE, _sse(_event(_reply(i, _CALL), "\r\n"))), id="event stream, CRLF"),
        pytest.param(
            lambda i: (_SSE, _sse(
                "id: 1\ndata: \n\n",          # the empty event newer revisions open a stream with
                ": ping - keep-alive\n\n",    # a comment
                *[_event(frame) for frame in other(i)],
                _event(_reply(i, _CALL)),
                _event(_reply(i, {"content": [], "isError": False})),  # never read
            )),
            id="event stream with frames before the reply",
        ),
        pytest.param(
            lambda i: (_SSE, _sse(
                "data: " + json.dumps(_reply(i, _CALL), indent=1).replace("\n", "\ndata: ") + "\n\n"
            )),
            id="event stream, data over several lines",
        ),
        pytest.param(
            lambda i: (_SSE, _sse("data:" + json.dumps(_reply(i, _CALL)) + "\n\n")),
            id="event stream, no space after the colon",
        ),
    ]


class TestBothAnswerShapesAreRead:
    @pytest.mark.parametrize("answer", _answers())
    def test_the_reply_is_found_whichever_way_the_server_sends_it(self, serve, answer) -> None:
        def call(server, request):
            content_type, body = answer(request["body"]["id"])
            return 200, {"Content-Type": content_type}, body

        server = serve(_well_behaved(call))
        with NetworkGatewayClient(server.url, token=TOKEN) as gateway:
            gateway.initialize()
            result = gateway.call_tool("notify__send", {"text": "x"})
        assert result == _CALL
        assert result_text(result) == "held"
        sent = server.requests[2]["body"]
        assert sent["method"] == "tools/call"
        assert sent["params"] == {"name": "notify__send", "arguments": {"text": "x"}}


def _one_answer(status: int, headers: dict[str, str], body: bytes):
    return _well_behaved(lambda server, request: (status, headers, body))


class TestAnswersThatAreNotAReply:
    @pytest.mark.parametrize(
        ("status", "headers", "body", "words"),
        [
            pytest.param(200, {"Content-Type": _SSE}, _sse(_event(_reply(999, {}))),
                         "ended without a reply", id="the stream ends first"),
            pytest.param(200, {"Content-Type": _JSON}, json.dumps(_reply(999, {})).encode(),
                         "ended without a reply", id="a reply to another id"),
            pytest.param(200, {"Content-Type": "text/html"}, b"<html>", "content type 'text/html'",
                         id="not an MCP content type"),
            pytest.param(200, {"Content-Type": _JSON}, b"{not json", "was not JSON", id="not JSON"),
            pytest.param(200, {"Content-Type": _SSE}, b"data: {not json\n\n", "was not JSON",
                         id="an event that is not JSON"),
            pytest.param(500, {"Content-Type": "text/plain"}, b"boom", "HTTP 500: boom", id="a server error"),
            pytest.param(
                400, {"Content-Type": _JSON},
                json.dumps({"jsonrpc": "2.0", "id": "server-error",
                            "error": {"code": -32600, "message": "Bad Request: Unsupported protocol version"}}).encode(),
                "HTTP 400: Bad Request: Unsupported protocol version", id="the server's own error message",
            ),
            pytest.param(404, {"Content-Type": _JSON}, b"{}", "no longer knows this session",
                         id="the session is gone"),
        ],
    )
    def test_it_is_an_error_in_words(self, serve, status, headers, body, words) -> None:
        server = serve(_one_answer(status, headers, body))
        gateway = NetworkGatewayClient(server.url, token=TOKEN)
        gateway.initialize()
        with pytest.raises(GatewayClientError) as raised:
            gateway.list_tools()
        assert words in str(raised.value)

    def test_a_json_rpc_error_is_raised_as_the_stdio_client_raises_it(self, serve) -> None:
        def answer(server, request):
            frame = {"jsonrpc": "2.0", "id": request["body"]["id"], "error": {"code": -32601, "message": "nope"}}
            return 200, {"Content-Type": _SSE}, _sse(_event(frame))

        server = serve(_well_behaved(answer))
        gateway = NetworkGatewayClient(server.url, token=TOKEN)
        gateway.initialize()
        with pytest.raises(GatewayClientError, match="'tools/list' returned a JSON-RPC error: .*nope"):
            gateway.list_tools()

    def test_a_refused_token_says_so_and_does_not_repeat_the_token(self, serve) -> None:
        server = serve(lambda s, r: (401, {"Content-Type": _JSON, "WWW-Authenticate": "Bearer"},
                                     b'{"error": "unauthorized"}'))
        gateway = NetworkGatewayClient(server.url, token=TOKEN)
        with pytest.raises(GatewayClientError) as raised:
            gateway.initialize()
        assert "HTTP 401" in str(raised.value) and "launch token" in str(raised.value)
        assert TOKEN not in str(raised.value)
        # One request, no retry, and nothing sent after the refusal.
        assert server.methods() == ["initialize"]
        assert gateway.session_id is None

    def test_a_redirect_is_not_followed(self, serve) -> None:
        """The token would follow a redirect to wherever it points."""
        elsewhere = serve(lambda s, r: (200, {"Content-Type": _JSON}, b"{}"))
        server = serve(lambda s, r: (307, {"Location": elsewhere.url}, b""))
        with pytest.raises(GatewayClientError, match="HTTP 307"):
            NetworkGatewayClient(server.url, token=TOKEN).initialize()
        assert elsewhere.requests == []
        assert len(server.requests) == 1

    @pytest.mark.parametrize("value", ["bad\x00id", "two words", "café"])
    def test_a_session_id_that_cannot_be_sent_back_is_refused_at_the_handshake(self, serve, value) -> None:
        def script(server, request):
            frame = _reply(request["body"]["id"], {"protocolVersion": REVISION})
            handler = request["handler"]
            body = json.dumps(frame).encode()
            handler.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: "
                + value.encode("latin-1") + b"\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body
            )

        server = serve(script)
        gateway = NetworkGatewayClient(server.url, token=TOKEN)
        with pytest.raises(GatewayClientError, match="cannot be sent back in a header"):
            gateway.initialize()
        assert gateway.session_id is None


def _elapsed(action) -> tuple[float, GatewayClientError]:
    started = time.monotonic()
    with pytest.raises(GatewayClientError) as raised:
        action()
    return time.monotonic() - started, raised.value


class TestEveryWaitIsBounded:
    def test_a_server_that_never_answers(self, serve) -> None:
        def hang(server, request):
            server.release.wait(30)

        server = serve(_well_behaved(hang))
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=_SHORT_S)
        gateway.initialize()
        elapsed, error = _elapsed(lambda: gateway.call_tool("search__query", {"query": "x"}))
        assert _SHORT_S * 0.8 <= elapsed < _SHORT_S + _SLACK_S
        assert "no reply to 'tools/call' within 1s" in str(error)
        assert "does not say whether it was made" in str(error)
        # No retry: the call was sent exactly once.
        assert server.methods().count("tools/call") == 1

    def test_a_server_that_sends_one_byte_at_a_time_forever(self, serve) -> None:
        """A socket timeout bounds each read and not their sum. Every byte here
        arrives well inside the timeout, so only an overall deadline ends it."""
        def trickle(server, request):
            handler = request["handler"]
            handler.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            try:
                while not server.release.is_set():
                    handler.wfile.write(b":")
                    handler.wfile.flush()
                    time.sleep(0.02)
            except OSError:
                pass

        server = serve(_well_behaved(trickle))
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=_SHORT_S)
        gateway.initialize()
        elapsed, error = _elapsed(gateway.list_tools)
        assert _SHORT_S * 0.8 <= elapsed < _SHORT_S + _SLACK_S
        assert "no reply to 'tools/list' within 1s" in str(error)

    def test_a_server_that_goes_away_mid_reply_is_reported_at_once(self, serve) -> None:
        def vanish(server, request):
            handler = request["handler"]
            handler.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: message\r\ndata: {\"jsonrpc\""
            )
            handler.wfile.flush()
            handler.connection.shutdown(socket.SHUT_RDWR)

        server = serve(_well_behaved(vanish))
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=30)
        gateway.initialize()
        elapsed, error = _elapsed(lambda: gateway.call_tool("search__query", {"query": "x"}))
        assert elapsed < _SLACK_S
        assert "does not say whether it was made" in str(error)
        assert "within" not in str(error), "a dropped connection is not a timeout"

    def test_a_server_that_drops_the_connection_before_answering(self, serve) -> None:
        def drop(server, request):
            request["handler"].connection.shutdown(socket.SHUT_RDWR)

        server = serve(_well_behaved(drop))
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=30)
        gateway.initialize()
        elapsed, error = _elapsed(gateway.list_tools)
        assert elapsed < _SLACK_S
        assert "closed the connection before replying to 'tools/list'" in str(error)

    def test_nothing_is_listening(self) -> None:
        with socket.create_server(("127.0.0.1", 0)) as placeholder:
            port = placeholder.getsockname()[1]
        gateway = NetworkGatewayClient(f"http://127.0.0.1:{port}/mcp", token=TOKEN, timeout=30)
        elapsed, error = _elapsed(gateway.initialize)
        assert elapsed < _SLACK_S
        assert "could not be reached" in str(error)

    def test_leaving_never_raises_and_never_waits_long_when_the_server_has_gone(self, serve) -> None:
        server = serve(_well_behaved(_json_tools))
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=30)
        gateway.initialize()
        server.close()
        started = time.monotonic()
        gateway.close()
        assert time.monotonic() - started < _SLACK_S
        assert gateway.session_id is None


    def test_leaving_does_not_wait_out_a_call_length_timeout(self, serve) -> None:
        """Ending the session is a courtesy. A gateway that accepts the request
        and never answers it must not hold the caller's exit for as long as a
        call would be allowed to take."""
        def script(server, request):
            if request["method"] == "DELETE":
                server.release.wait(30)
                return None
            return _well_behaved(_json_tools)(server, request)

        server = serve(script)
        gateway = NetworkGatewayClient(server.url, token=TOKEN, timeout=30)
        gateway.initialize()
        started = time.monotonic()
        gateway.close()
        assert time.monotonic() - started < 5.0 + _SLACK_S
        assert gateway.session_id is None


class TestWhatTheClientRefusesToBeBuiltWith:
    @pytest.mark.parametrize(
        ("url", "words"),
        [
            pytest.param("https://127.0.0.1:1/mcp", "must start with http://", id="another scheme"),
            pytest.param("127.0.0.1:8765/mcp", "must start with http://", id="no scheme"),
            pytest.param("http:///mcp", "names no host", id="no host"),
            pytest.param(f"http://127.0.0.1:1/mcp?access_token={TOKEN}", "never in the URL", id="a query string"),
            pytest.param(f"http://agent:{TOKEN}@127.0.0.1:1/mcp", "never in the URL", id="a password"),
            pytest.param("http://127.0.0.1:1/mcp#x", "never in the URL", id="a fragment"),
            pytest.param("http://127.0.0.1:port/mcp", "not a URL this client can read", id="a port that is not one"),
        ],
    )
    def test_a_url_that_is_more_or_less_than_where_the_gateway_listens(self, url, words) -> None:
        with pytest.raises(GatewayClientError) as raised:
            NetworkGatewayClient(url, token=TOKEN)
        assert words in str(raised.value)

    @pytest.mark.parametrize(
        "token",
        ["", TOKEN + "\n", "two words" + "a" * 30, TOKEN + "\r\nX-Injected: 1", "café" + "a" * 30, None],
        ids=["empty", "trailing newline", "a space", "a header injection", "non-ASCII", "not a string"],
    )
    def test_a_token_that_cannot_travel_in_a_header(self, token) -> None:
        with pytest.raises(GatewayClientError) as raised:
            NetworkGatewayClient("http://127.0.0.1:1/mcp", token=token)
        assert "launch token" in str(raised.value)
        if token:
            assert token.strip() not in str(raised.value)

    @pytest.mark.parametrize("timeout", [0, -1, float("nan")])
    def test_a_wait_that_is_not_a_wait(self, timeout) -> None:
        with pytest.raises(GatewayClientError, match="positive number of seconds"):
            NetworkGatewayClient("http://127.0.0.1:1/mcp", token=TOKEN, timeout=timeout)

    def test_the_client_does_not_show_the_token(self) -> None:
        gateway = NetworkGatewayClient("http://127.0.0.1:1/mcp", token=TOKEN)
        assert TOKEN not in repr(gateway)
        assert TOKEN not in str(vars(gateway).keys())
