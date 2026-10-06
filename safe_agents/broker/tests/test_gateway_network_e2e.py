"""The network MCP mouth, end to end: a real server on a real loopback socket.

`test_gateway_network.py` proves the guard with three dicts and no SDK. This is
the other half of "a seam is proven per transport": the same questions asked of
the object `python -m safe_agents.broker.gateway` actually serves, bound to an
ephemeral port (port 0) and driven by the `mcp` SDK's own streamable HTTP client.

The server runs on a thread of its own and BUILDS ITS RUNTIME THERE, because that
is the rule the mouth lives by: the thread that builds the runtime is the thread
that calls it. The client runs on the test's thread.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.gateway.authn import LaunchToken
from safe_agents.broker.gateway.network import (
    ACCESS_LOGGER,
    DIAGNOSTICS_PER_WINDOW,
    MOUTH_CODE,
    SERVER_LOGGER,
    bind_listener,
    listener_url,
)
from safe_agents.broker.client.stdio import env_without_broker_config
from safe_agents.broker.runtime.pep import MOUTH_REFUSAL_TOOL
from safe_agents.broker.tests.test_gateway_authn import OTHER, TOKEN, write_token
from safe_agents.broker.tests.test_gateway_network import _BROKER_ENV, _frame

pytest.importorskip("mcp", reason="the network MCP mouth needs the optional 'mcp' extra")

import httpx  # noqa: E402 — arrives with the extra
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import (  # noqa: E402
    create_mcp_http_client,
    streamable_http_client,
)

from safe_agents.broker.gateway.server import NetworkMouth  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
_MANIFEST_PATH = REPO_ROOT / "examples" / "embedded_agent" / "manifest.yaml"
_MCP_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
_JOIN_S = 20
#: How long a launched gateway gets to say where it listens, and to leave.
_LAUNCH_S = 60
_EXIT_S = 30


class _Served:
    """One running network mouth, and what the test may look at afterwards."""

    def __init__(self, make_surface, *, build_on_callers_thread: bool = False) -> None:
        """`build_on_callers_thread` breaks the mouth's one rule on purpose: the
        mouth is built here and served on another thread."""
        self.listener = bind_listener("127.0.0.1", 0)
        self.url = listener_url(self.listener)
        self.runtime = None
        self.sink = None
        self.requests: list = []
        self.listings = 0
        self.thread_id: int | None = None
        self.error: BaseException | None = None
        self._mouth: NetworkMouth | None = None
        self._built = threading.Event()
        if build_on_callers_thread:
            self._build(make_surface)
        self._thread = threading.Thread(target=self._run, args=(make_surface,), daemon=True)
        self._thread.start()
        assert self._built.wait(_JOIN_S), "the mouth was never built"
        if self.error is not None:
            raise self.error

    def _build(self, make_surface) -> None:
        self._mouth = NetworkMouth(
            make_surface(self),
            authenticator=LaunchToken(TOKEN),
            record_refusals=self._record,
            listener=self.listener,
        )

    def _run(self, make_surface) -> None:
        try:
            self.thread_id = threading.get_ident()
            if self._mouth is None:
                self._build(make_surface)
        except BaseException as exc:  # noqa: BLE001 — hand it to the test thread
            self.error = exc
            self._built.set()
            return
        self._built.set()
        try:
            asyncio.run(self._mouth.serve())
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
        finally:
            if self.runtime is not None:
                self.runtime.close()

    def _record(self, causes) -> None:
        if self.runtime is not None:
            self.runtime.record_refused_connections(mouth=MOUTH_CODE, causes=causes)

    def stop(self) -> None:
        assert self._mouth is not None
        self._mouth.request_stop()
        self._thread.join(_JOIN_S)
        assert not self._thread.is_alive(), "the mouth did not stop"
        if self.error is not None:
            raise self.error


def _real_surface(served: _Served) -> GatewaySurface:
    """The embedded example's runtime, with spies on the two ways into it."""
    runtime, sink = build_runtime(load_agent_manifest(_MANIFEST_PATH))
    served.runtime, served.sink = runtime, sink
    real_handle, real_registry = runtime.handle_request, runtime.served_registry

    def handle_request(request, **kwargs):
        served.requests.append(request)
        return real_handle(request, **kwargs)

    def served_registry():
        served.listings += 1
        return real_registry()

    runtime.handle_request = handle_request
    runtime.served_registry = served_registry
    return GatewaySurface(runtime)


@pytest.fixture
def mouth(monkeypatch: pytest.MonkeyPatch):
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    served = _Served(_real_surface)
    try:
        yield served
    finally:
        served.stop()


def _run(coro):
    return asyncio.run(coro)


async def _session(url: str, token: str | None, drive, extra_headers: dict[str, str] | None = None):
    headers = dict(extra_headers or {})
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with create_mcp_http_client(headers=headers) as http_client:
        async with streamable_http_client(url, http_client=http_client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await drive(session)


def _mouth_records(served: _Served) -> list:
    return [r for r in served.sink.records() if r.tool == MOUTH_REFUSAL_TOOL]


class TestServedOverARealSocket:
    def test_an_authenticated_client_lists_and_calls(self, mouth) -> None:
        async def drive(session):
            return await session.list_tools(), await session.call_tool("search__query", {"query": "broker"})

        tools, result = _run(_session(mouth.url, TOKEN, drive))
        assert [tool.name for tool in tools.tools] == ["search__query"]
        assert result.isError is False
        assert "The agent holds no connector credentials" in result.content[0].text

    def test_a_stop_requested_before_serving_is_honoured(self) -> None:
        """A stop can arrive before the server underneath exists (a signal in
        the moment between the address being announced and the server taking
        signals for itself). The mouth must start, see it, and return."""
        slow = _SlowSurface()
        done = threading.Event()
        failed: list[BaseException] = []
        made: list[NetworkMouth] = []

        def run() -> None:
            try:
                mouth = NetworkMouth(
                    slow, authenticator=LaunchToken(TOKEN),
                    record_refusals=lambda causes: None, listener=bind_listener("127.0.0.1", 0),
                )
                made.append(mouth)
                mouth.request_stop()
                asyncio.run(mouth.serve())
            except BaseException as exc:  # noqa: BLE001 — hand it to the test thread
                failed.append(exc)
            finally:
                done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        returned = done.wait(_JOIN_S)
        if not returned:
            made[0].request_stop()  # do not leave it serving behind the failure
            thread.join(_JOIN_S)
        assert returned, "a stop requested before serve() was forgotten: the mouth kept serving"
        assert failed == []
        assert slow.calls == 0

    def test_a_refusal_is_the_brokers_and_is_on_the_tape(self, mouth) -> None:
        """Parity with the stdio mouth (G3, G4): an unadvertised name is routed to
        the broker, comes back an error carrying its reason, and is recorded."""
        async def drive(session):
            return await session.call_tool("notify__send", {"text": "shipping it"})

        result = _run(_session(mouth.url, TOKEN, drive))
        assert result.isError is True
        assert "tool not granted to this principal" in result.content[0].text
        last = mouth.sink.records()[-1]
        assert (last.tool, last.op, last.decision, last.outcome) == ("notify", "send", "deny", "denied")

    def test_calls_enter_the_runtime_on_the_thread_that_built_it(self, mouth) -> None:
        threads: list[int] = []
        real = mouth.runtime.handle_request

        def spy(request, **kwargs):
            threads.append(threading.get_ident())
            return real(request, **kwargs)

        mouth.runtime.handle_request = spy

        async def drive(session):
            return await session.call_tool("search__query", {"query": "broker"})

        _run(_session(mouth.url, TOKEN, drive))
        assert threads == [mouth.thread_id]


_UNAUTHENTICATED = [
    pytest.param({}, "", "missing_credential", id="missing token"),
    pytest.param({"Authorization": f"Bearer {OTHER}"}, "", "wrong_token", id="wrong token"),
    pytest.param({"Authorization": f"Basic {TOKEN}"}, "", "wrong_scheme", id="wrong scheme"),
    pytest.param({}, f"?access_token={TOKEN}", "credential_in_query", id="token in the query string"),
    pytest.param(
        {"Authorization": f"Bearer {TOKEN}"}, f"?access_token={TOKEN}",
        "credential_in_query", id="right header AND a token in the query string",
    ),
]

_FRAMES = [
    pytest.param("POST", _frame("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                               "clientInfo": {"name": "x", "version": "0"}}), id="initialize"),
    pytest.param("POST", _frame("tools/list"), id="tools/list"),
    pytest.param("POST", _frame("tools/call", {"name": "search__query", "arguments": {"query": "x"}}),
                 id="tools/call"),
    pytest.param("GET", b"", id="GET event stream"),
    pytest.param("DELETE", b"", id="DELETE session"),
    # Methods no MCP client sends. An OPTIONS let past the guard is answered by
    # the SDK with a JSON-RPC frame and a fresh session id, so "every request"
    # has to mean every method (G12), a CORS preflight and a health probe included.
    pytest.param("OPTIONS", b"", id="OPTIONS preflight"),
    pytest.param("HEAD", b"", id="HEAD"),
    pytest.param("PUT", _frame("tools/list"), id="PUT"),
    pytest.param("PATCH", _frame("tools/list"), id="PATCH"),
]


class TestNothingIsServedBeforeAuthentication:
    @pytest.mark.parametrize(("method", "body"), _FRAMES)
    @pytest.mark.parametrize(("headers", "query", "cause"), _UNAUTHENTICATED)
    def test_every_frame_is_refused_and_the_runtime_is_never_reached(
        self, mouth, method, body, headers, query, cause
    ) -> None:
        response = httpx.request(
            method, mouth.url + query, headers={**_MCP_HEADERS, **headers}, content=body, timeout=10
        )
        assert response.status_code == 401
        if method == "HEAD":
            assert response.content == b""  # HTTP carries no body on a HEAD reply
        else:
            assert response.json() == {"error": "unauthorized"}
        assert response.headers["www-authenticate"] == "Bearer"
        assert "mcp-session-id" not in response.headers
        assert "jsonrpc" not in response.text

        assert mouth.requests == [], "handle_request was reached without authentication"
        assert mouth.listings == 0, "the served registry was read without authentication"
        (record,) = _mouth_records(mouth)
        assert record.reason == f"1 connection(s) refused before any frame was served: {cause}=1"

    def test_a_live_session_id_does_not_stand_in_for_the_token(self, mouth) -> None:
        """Open a real session with the token, then reuse its id without one."""
        with httpx.Client(timeout=10) as client:
            opened = client.post(
                mouth.url,
                headers={**_MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"},
                content=_frame("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": "x", "version": "0"}}),
            )
            assert opened.status_code == 200
            session_id = opened.headers["mcp-session-id"]
            session = {**_MCP_HEADERS, "mcp-session-id": session_id}
            # Use the session WITH the token first, so the mouth has seen this id
            # admitted. A guard that remembered admitted sessions fails below.
            used = client.post(
                mouth.url,
                headers={**session, "Authorization": f"Bearer {TOKEN}"},
                content=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
            )
            assert used.status_code == 202
            call = _frame("tools/call", {"name": "search__query", "arguments": {"query": "x"}})
            stolen = {
                "POST": client.post(mouth.url, headers=session, content=call),
                "POST, wrong token": client.post(
                    mouth.url, headers={**session, "Authorization": f"Bearer {OTHER}"}, content=call
                ),
                "DELETE": client.delete(mouth.url, headers=session),
            }
            assert {how: r.status_code for how, r in stolen.items()} == dict.fromkeys(stolen, 401)
            assert mouth.requests == [], "a session id alone reached the runtime"
            # The session is still there for its owner: the refused DELETE ended nothing.
            kept = client.post(mouth.url, headers={**session, "Authorization": f"Bearer {TOKEN}"}, content=call)
            assert kept.status_code == 200
        assert len(mouth.requests) == 1

    @pytest.mark.parametrize("path", ["/", "/registry", "/call", "/mcp/", "/MCP"])
    def test_the_served_mouth_authenticates_before_it_routes(self, mouth, path) -> None:
        """G12 on the object that is served, not on a guard built for the test:
        a stranger gets the same 401 on every path, cannot tell which paths
        exist, and is counted. Only with the token does a wrong path say so."""
        elsewhere = mouth.url.removesuffix("/mcp") + path
        refused = httpx.get(elsewhere, timeout=10)
        on_the_route = httpx.get(mouth.url, timeout=10)
        assert refused.status_code == 401, "an unauthenticated request was routed before it was authenticated"
        assert (refused.content, refused.headers["www-authenticate"]) == (
            on_the_route.content, on_the_route.headers["www-authenticate"],
        )
        mouth.stop()
        counted = [record.reason for record in _mouth_records(mouth)]
        assert counted == [
            "1 connection(s) refused before any frame was served: missing_credential=1",
            "1 connection(s) refused before any frame was served: missing_credential=1",
        ], "a refusal on a path the mouth does not serve went uncounted"
        assert mouth.requests == [] and mouth.listings == 0

    def test_a_wrong_path_is_only_named_to_an_authenticated_caller(self, mouth) -> None:
        elsewhere = mouth.url.removesuffix("/mcp") + "/registry"
        response = httpx.get(elsewhere, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=10)
        assert response.status_code == 404
        assert _mouth_records(mouth) == []

    def test_the_sdk_client_cannot_initialize_without_the_token(self, mouth) -> None:
        async def drive(session):  # pragma: no cover — never reached
            return await session.list_tools()

        with pytest.raises(BaseException) as failure:  # noqa: PT011 — the SDK raises a group
            _run(_session(mouth.url, None, drive))
        assert not isinstance(failure.value, (KeyboardInterrupt, SystemExit))
        assert mouth.requests == [] and mouth.listings == 0

    def test_a_flood_of_refusals_leaves_one_record_until_the_window_turns(self, mouth) -> None:
        with httpx.Client(timeout=10) as client:
            for _ in range(40):
                assert client.post(mouth.url, headers=_MCP_HEADERS, content=_frame("tools/list")).status_code == 401
        (record,) = _mouth_records(mouth)
        assert record.reason.endswith("missing_credential=1")
        mouth.stop()  # shutdown writes the tail: every refusal is counted
        first, tail = _mouth_records(mouth)
        assert tail.reason == "39 connection(s) refused before any frame was served: missing_credential=39"


class TestTheCallerNeverNamesThePrincipal:
    _CLAIMS = {
        "X-Principal": "root-agent",
        "X-Agent-Id": "root-agent",
        "X-Forwarded-User": "root-agent",
        "X-Broker-Principal": '{"agentId":"root-agent","skill":"admin","user":"root","tier":"A"}',
        "From": "root-agent@example.invalid",
    }
    _ARGUMENTS = {
        "query": "broker",
        "principal": {"agentId": "root-agent", "skill": "admin", "user": "root", "tier": "A"},
        "agentId": "root-agent",
        "_meta": {"principal": "root-agent"},
        "idempotency_key": "replay-me",
        "turn_id": "turn:fresh",
    }

    def test_no_header_or_body_field_changes_who_the_call_is_made_as(self, mouth) -> None:
        before = mouth.runtime._principal.model_dump()

        async def drive(session):
            return (
                await session.call_tool("search__query", dict(self._ARGUMENTS)),
                await session.call_tool("notify__send", dict(self._ARGUMENTS)),
            )

        _run(_session(mouth.url, TOKEN, drive, extra_headers=self._CLAIMS))

        assert mouth.runtime._principal.model_dump() == before
        assert before["agentId"] == "embedded-assistant"
        for request in mouth.requests:
            # The mouth hands the broker a coordinate and the arguments, as sent.
            # It lifts nothing out of them into a field the broker would trust.
            assert request.args == self._ARGUMENTS
            assert request.idempotency_key is None
            assert request.confidence is None
            assert set(vars(request)) == {"tool", "op", "args", "confidence", "idempotency_key"}
        assert [(r.tool, r.op) for r in mouth.requests] == [("search", "query"), ("notify", "send")]
        for record in mouth.sink.records():
            assert record.principal.model_dump() == before


class _SlowSurface:
    """A surface whose calls take long enough to overlap if anything lets them."""

    server_name = "slow"

    def __init__(self) -> None:
        self.in_flight = 0
        self.max_in_flight = 0
        self.threads: set[int] = set()
        self.calls = 0
        self._lock = threading.Lock()

    def tools(self):
        return []

    def call(self, wire_name, arguments=None):
        from safe_agents.broker.gateway.surface import GatewayResult

        with self._lock:
            self.in_flight += 1
            self.calls += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            self.threads.add(threading.get_ident())
        time.sleep(0.05)
        with self._lock:
            self.in_flight -= 1
        return GatewayResult(ok=True, text=wire_name, decision_kind="allow")


def test_calls_into_the_runtime_never_overlap() -> None:
    """Three clients, four calls each, all sent at once.

    Fails if two calls are ever inside the surface together, if any call enters
    it from a thread other than the one that built it, or if serialization is
    kept by refusing calls: every one of the twelve must come back served.
    """
    slow = _SlowSurface()
    served = _Served(lambda _served: slow)
    try:
        async def one_client(index: int):
            async def drive(session):
                return await asyncio.gather(
                    *(session.call_tool(f"c{index}__n{n}", {}) for n in range(4))
                )
            return await _session(served.url, TOKEN, drive)

        async def all_clients():
            return await asyncio.gather(*(one_client(i) for i in range(3)))

        results = [result for batch in _run(all_clients()) for result in batch]
    finally:
        served.stop()

    assert [r.isError for r in results] == [False] * 12, [r.content[0].text for r in results if r.isError]
    assert slow.calls == 12
    assert slow.max_in_flight == 1
    assert slow.threads == {served.thread_id}


def test_the_served_mouth_refuses_a_call_from_a_thread_that_did_not_build_it() -> None:
    """G18 on the object that is served: `NetworkMouth` reaches the surface only
    through `SerializedSurface`.

    The mouth is built on this thread and served on another, which is the
    mistake the wrapper exists to catch. Every call must come back refused in
    the wrapper's words, and the surface behind it must never run. A mouth that
    held the bare surface would serve all of this without complaint.
    """
    slow = _SlowSurface()
    served = _Served(lambda _served: slow, build_on_callers_thread=True)
    try:
        assert served.thread_id != threading.get_ident()

        async def drive(session):
            return await session.call_tool("search__query", {"query": "x"})

        result = _run(_session(served.url, TOKEN, drive))
    finally:
        served.stop()

    assert result.isError is True, "the served mouth entered the surface without SerializedSurface in front of it"
    assert "refused to enter the broker runtime from a thread other than the one that built it" in (
        result.content[0].text
    )
    assert slow.calls == 0, "the surface was entered from a thread that did not build it"


@contextlib.contextmanager
def _listening(name: str, level: int):
    """Hear everything logger `name` would hand to a configured application.

    Restores the logger afterwards: the server sets process-wide logging state
    when it is configured, and one test must not decide what the next one hears.
    """
    records: list[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.name == name:
                records.append(record)

    log, root, keep = logging.getLogger(name), logging.getLogger(), _Keep(level=logging.DEBUG)
    before = (log.level, log.propagate, list(log.handlers))
    log.setLevel(level)
    log.propagate = True
    root.addHandler(keep)
    try:
        yield records
    finally:
        root.removeHandler(keep)
        log.level, log.propagate, log.handlers = before[0], before[1], before[2]


def _raw(served: _Served, payload: bytes) -> bytes:
    """Send bytes no HTTP client would. Returns the status code of the reply."""
    reply = b""
    with socket.create_connection(served.listener.getsockname()[:2], timeout=10) as conn:
        conn.sendall(payload)
        while b"\r\n" not in reply:
            chunk = conn.recv(65536)
            if not chunk:
                break
            reply += chunk
    return reply.split(b" ")[1] if reply.count(b" ") else reply


class TestWhatTheServerUnderneathMayLog:
    def test_no_request_line_reaches_a_log(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The application has logging configured, at INFO, before the mouth
        starts: the case where an access log would be written if it were on.
        A request line carries the query string, so a token someone put there
        would be copied out with it."""
        for var in _BROKER_ENV:
            monkeypatch.delenv(var, raising=False)
        with _listening(ACCESS_LOGGER, logging.INFO) as access, _listening(SERVER_LOGGER, logging.INFO) as server:
            served = _Served(_real_surface)
            try:
                in_query = httpx.post(f"{served.url}?access_token={TOKEN}", headers=_MCP_HEADERS,
                                      content=_frame("tools/list"), timeout=10)
                with_header = httpx.post(f"{served.url}?access_token={TOKEN}",
                                         headers={**_MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"},
                                         content=_frame("tools/list"), timeout=10)
                served_one = httpx.post(f"{served.url}?page=2",
                                        headers={**_MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"},
                                        content=_frame("ping"), timeout=10)
            finally:
                served.stop()
        assert (in_query.status_code, with_header.status_code) == (401, 401)
        assert served_one.status_code != 401
        assert server, "the listener heard nothing at all, so its silence about requests proves nothing"
        logged = [record.getMessage() for record in access + server]
        assert [line for line in logged if "/mcp" in line or "access_token" in line] == [], (
            "a request line was logged"
        )
        assert access == []
        assert TOKEN not in "\n".join(logged)

    def test_a_stranger_cannot_make_the_server_log_without_bound(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bytes that are not HTTP, and an upgrade the mouth does not serve, each
        make the server underneath log, and neither needs a credential."""
        for var in _BROKER_ENV:
            monkeypatch.delenv(var, raising=False)
        attempts = DIAGNOSTICS_PER_WINDOW * 3
        upgrade = (b"GET /mcp HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                   b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n")
        with _listening(SERVER_LOGGER, logging.WARNING) as server:
            served = _Served(_real_surface)
            try:
                for _ in range(attempts):
                    assert _raw(served, b"\x00\x01 not http at all\r\n\r\n") == b"400"
                    # 401 from the guard; 403 where a websocket library is
                    # installed and the guard closes the handshake instead.
                    assert _raw(served, upgrade) in (b"401", b"403")
            finally:
                served.stop()
            assert logging.getLogger(SERVER_LOGGER).filters == [], "the mouth left its filter behind"
        warnings = [record for record in server if record.levelno >= logging.WARNING]
        assert warnings, "the server logged nothing for these requests, so the bound was not exercised"
        assert len(warnings) <= DIAGNOSTICS_PER_WINDOW, (
            f"{attempts * 2} unauthenticated requests wrote {len(warnings)} diagnostic lines"
        )
        assert served.requests == [] and served.listings == 0


def _launch(env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "safe_agents.broker.gateway"],
        cwd=REPO_ROOT,
        env={**env_without_broker_config(), **env},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def _refused(env: dict[str, str]) -> tuple[int, str, str]:
    """Launch a gateway that must refuse to start. Returns (returncode, stdout, stderr).

    A gateway that STARTS is the failure this exists to catch, so it is never
    left running behind the assertion that catches it.
    """
    child = _launch(env)
    try:
        stdout, stderr = child.communicate(timeout=_LAUNCH_S)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        pytest.fail("the gateway did not refuse to start: it was still running, and has been killed")
    return child.returncode, stdout, stderr


class _Launched:
    """A launched gateway whose stderr is read on a thread, so no wait on it is unbounded."""

    _LISTENING = re.compile(r"network MCP mouth on (http://127\.0\.0\.1:\d+/mcp) \(authenticator: launch_token\)")

    def __init__(self, env: dict[str, str]) -> None:
        self.child = _launch(env)
        self.lines: list[str] = []
        self._found: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        for line in self.child.stderr:
            self.lines.append(line)
            found = self._LISTENING.search(line)
            if found:
                self._found.put(found.group(1))
        self._found.put(None)  # stderr closed: the process is gone or going

    def url(self) -> str:
        try:
            url = self._found.get(timeout=_LAUNCH_S)
        except queue.Empty:
            url = None
        if url is None:
            self.kill()
            pytest.fail("the gateway never said where it listens:\n" + "".join(self.lines))
        return url

    def kill(self) -> None:
        self.child.kill()
        self.child.wait()
        self._reader.join(_JOIN_S)

    def stop(self) -> dict:
        """Send ONE stop signal and wait. A gateway that needs a second one fails."""
        if os.name == "nt":
            self.child.terminate()
        else:
            self.child.send_signal(signal.SIGTERM)
        try:
            self.child.wait(timeout=_EXIT_S)
        except subprocess.TimeoutExpired:
            self.kill()
            pytest.fail(
                f"the gateway was still running {_EXIT_S}s after one stop signal, and has "
                "been killed:\n" + "".join(self.lines)
            )
        self._reader.join(_JOIN_S)
        return {
            "returncode": self.child.returncode,
            "stdout": self.child.stdout.read(),
            "stderr": "".join(self.lines),
        }


_NETWORK = {"BROKER_GATEWAY_TRANSPORT": "streamable-http", "BROKER_GATEWAY_PORT": "0",
            "BROKER_GATEWAY_HOST": "127.0.0.1"}


class TestTheLauncher:
    @pytest.mark.parametrize(
        ("env", "words"),
        [
            pytest.param({"BROKER_GATEWAY_TRANSPORT": "http"}, "not a recognized gateway transport", id="typo'd transport"),
            pytest.param({}, "BROKER_GATEWAY_AUTH is unset", id="unnamed authenticator"),
            pytest.param({"BROKER_GATEWAY_AUTH": "oauth_bearer"}, "NOT YET IMPLEMENTED", id="reserved oauth"),
            pytest.param({"BROKER_GATEWAY_AUTH": "mtls_workload_identity"}, "NOT YET IMPLEMENTED", id="reserved mtls"),
            pytest.param({"BROKER_GATEWAY_AUTH": "launch_token"}, "BROKER_GATEWAY_TOKEN_FILE is unset", id="no token file"),
            pytest.param({"BROKER_GATEWAY_AUTH": "launch_token", "BROKER_GATEWAY_TOKEN_FILE": "EMPTY"}, "is empty", id="empty token"),
        ],
    )
    def test_startup_refuses_in_words_before_the_runtime_is_built(self, tmp_path: Path, env, words) -> None:
        env = {**_NETWORK, **env}
        if env.get("BROKER_GATEWAY_TOKEN_FILE") == "EMPTY":
            env["BROKER_GATEWAY_TOKEN_FILE"] = str(write_token(tmp_path / "token", b""))
        returncode, stdout, stderr = _refused(env)
        assert returncode == 1
        assert stdout == ""
        assert "[broker] refusing to start the MCP gateway:" in stderr
        assert words in stderr
        assert "Traceback" not in stderr
        # A launcher reads this line as bytes in whatever encoding it expects, and a
        # child's stderr is written in the platform's own. Plain ASCII is the one
        # spelling both agree on: a dash outside it reached a Windows launcher as a
        # byte that is not UTF-8, and the refusal could not be read at all.
        assert stderr.isascii(), stderr
        assert "store backend" not in stderr, "the runtime was built before the refusal"

    @pytest.mark.parametrize("taken", ["a port already in use", "an address this machine does not have"])
    def test_an_address_it_cannot_bind_refuses_before_the_runtime_is_built(self, tmp_path: Path, taken) -> None:
        """G19: the bind is a launch setting like the rest. Everything else here
        is valid, so the only thing left to refuse is the address, and the
        refusal must come before a store is opened."""
        env = {**_NETWORK, "BROKER_GATEWAY_AUTH": "launch_token",
               "BROKER_GATEWAY_TOKEN_FILE": str(write_token(tmp_path / "token"))}
        with contextlib.ExitStack() as held:
            if taken == "a port already in use":
                holder = bind_listener("127.0.0.1", 0)
                held.callback(holder.close)
                env["BROKER_GATEWAY_PORT"] = str(holder.getsockname()[1])
            else:
                env["BROKER_GATEWAY_HOST"] = "203.0.113.1"  # TEST-NET-3
            returncode, stdout, stderr = _refused(env)
        assert returncode == 1
        assert stdout == ""
        assert "[broker] refusing to start the MCP gateway: could not listen on" in stderr
        assert "Traceback" not in stderr
        assert "store backend" not in stderr, "the runtime was built before the address was bound"
        assert "MCP gateway ready" not in stderr
        assert TOKEN not in stderr

    @contextlib.contextmanager
    def _serving(self, tmp_path: Path):
        """Launch the module on the network mouth. Yields its URL and, once the
        block has left and the process has been sent ONE stop signal, what it left."""
        launched = _Launched({
            "BROKER_GATEWAY_TRANSPORT": "streamable-http",
            "BROKER_GATEWAY_AUTH": "launch_token",
            "BROKER_GATEWAY_TOKEN_FILE": str(write_token(tmp_path / "token")),
            "BROKER_GATEWAY_PORT": "0",
            "BROKER_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        })
        url = launched.url()
        left: dict = {}
        try:
            assert TOKEN not in "".join(launched.lines)
            yield url, left
        except BaseException:
            launched.kill()
            raise
        left.update(launched.stop())
        tape = tmp_path / "audit.jsonl"
        left["tape"] = (
            [json.loads(line) for line in tape.read_text(encoding="utf-8").splitlines()]
            if tape.exists() else []
        )

    def test_the_module_serves_the_network_mouth_from_the_environment(self, tmp_path: Path) -> None:
        async def drive(session):
            return await session.list_tools()

        with self._serving(tmp_path) as (url, left):
            tools = _run(_session(url, TOKEN, drive))
        # The checked-in example manifest, which is what an unnamed manifest
        # resolves to on the memory arm.
        assert "search__query" in [tool.name for tool in tools.tools]
        assert left["stdout"] == "", "the network mouth wrote to stdout"
        assert TOKEN not in left["stderr"]
        if os.name != "nt":
            # A stop signal ends the process by RETURNING, so the shutdown work runs.
            assert left["returncode"] == 0

    @pytest.mark.skipif(os.name == "nt", reason="a graceful stop needs a signal the child can catch")
    @pytest.mark.parametrize("attempt", range(3))
    def test_one_stop_signal_sent_the_moment_the_address_is_known_stops_it(self, tmp_path: Path, attempt) -> None:
        """A launcher reads the listening line and stops the gateway at once.

        That signal lands before the server underneath has taken signals for
        itself. It must still stop the gateway, by returning, with the one
        signal. Run three times because what it guards is a window.
        """
        with self._serving(tmp_path) as (_url, left):
            pass
        assert left["returncode"] == 0, left["stderr"]
        assert left["stdout"] == ""
        assert "Traceback" not in left["stderr"]

    @pytest.mark.skipif(os.name == "nt", reason="a graceful stop needs a signal the child can catch")
    def test_connections_the_launched_mouth_refuses_reach_the_audit_tape(self, tmp_path: Path) -> None:
        """G17 through the real launcher: the callback `__main__` hands the mouth
        writes to the runtime's tape. One record at once, and the two refusals
        still waiting for their window at shutdown, behind it."""
        with self._serving(tmp_path) as (url, left):
            for _ in range(3):
                assert httpx.post(url, headers=_MCP_HEADERS, content=_frame("tools/list"), timeout=10).status_code == 401
        assert left["returncode"] == 0
        reasons = [r["reason"] for r in left["tape"] if r["tool"] == MOUTH_REFUSAL_TOOL]
        assert reasons == [
            "1 connection(s) refused before any frame was served: missing_credential=1",
            "2 connection(s) refused before any frame was served: missing_credential=2",
        ], "connections the launched mouth refused did not reach the audit tape"
        assert left["stdout"] == ""
