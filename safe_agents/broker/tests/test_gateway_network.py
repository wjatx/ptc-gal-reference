"""The network MCP mouth's guard, route, serialization and launch settings — SDK-free.

Everything here runs with no `mcp` SDK and no socket. `ConnectionGuard` and
`MouthApp` are plain ASGI, so a request is three dicts and two coroutines, and the
question "did anything behind the guard run?" is answered by an inner app that
records whether it was called. `test_gateway_network_e2e.py` asks the same
questions of a real server on a real socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.gateway.authn import (
    ADMITTED,
    AUTH_ENV,
    TOKEN_FILE_ENV,
    GatewayConfigError,
    LaunchToken,
    MouthAuthenticator,
    RefusalCause,
    RefusalLedger,
)
from safe_agents.broker.gateway import __main__ as launcher
from safe_agents.broker.gateway.network import (
    HOST_ENV,
    MCP_PATH,
    MOUTH_CODE,
    PORT_ENV,
    TRANSPORT_ENV,
    ConnectionGuard,
    DiagnosticBudget,
    MouthApp,
    RuntimeEntryRefused,
    SerializedSurface,
    bind_listener,
    is_loopback,
    listener_url,
    resolve_network_mouth,
    resolve_transport,
)
from safe_agents.broker.runtime.pep import MOUTH_REFUSAL_TOOL
from safe_agents.broker.tests.test_gateway_authn import OTHER, TOKEN, write_token

REPO_ROOT = Path(__file__).resolve().parents[3]
_MANIFEST_PATH = REPO_ROOT / "examples" / "embedded_agent" / "manifest.yaml"

_BROKER_ENV = (
    "BROKER_STORE", "BROKER_MANIFEST", "BROKER_SECRETS", "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE", "BROKER_AUDIT_PATH", "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD", "BROKER_SQLITE_PATH",
    TRANSPORT_ENV, AUTH_ENV, TOKEN_FILE_ENV, HOST_ENV, PORT_ENV,
    "BROKER_EVENT_MOUTH_PORT", "BROKER_EVENT_MOUTH_HOST", "BROKER_EVENT_MOUTH_ADDR_FILE",
)


def _frame(method: str, params: dict | None = None) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()


#: Every kind of request an MCP client sends this transport, and then the
#: methods it never sends. The three frames the invariant names come first. The
#: guard authenticates a REQUEST, whatever its method: OPTIONS and HEAD are the
#: two a server is most often taught to answer without a credential (a CORS
#: preflight, a health probe), and an OPTIONS let past this guard is answered by
#: the SDK with a JSON-RPC frame and a freshly minted session id.
FRAMES = [
    pytest.param("POST", _frame("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                               "clientInfo": {"name": "x", "version": "0"}}), id="initialize"),
    pytest.param("POST", _frame("tools/list"), id="tools/list"),
    pytest.param("POST", _frame("tools/call", {"name": "search__query", "arguments": {"query": "x"}}),
                 id="tools/call"),
    pytest.param("POST", _frame("ping"), id="ping"),
    pytest.param("POST", json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
                 id="notification"),
    pytest.param("GET", b"", id="GET event stream"),
    pytest.param("DELETE", b"", id="DELETE session"),
    pytest.param("OPTIONS", b"", id="OPTIONS preflight"),
    pytest.param("HEAD", b"", id="HEAD"),
    pytest.param("PUT", _frame("tools/list"), id="PUT"),
    pytest.param("PATCH", _frame("tools/list"), id="PATCH"),
    pytest.param("TRACE", b"", id="TRACE"),
    pytest.param("BREW", _frame("tools/list"), id="a method nobody defined"),
]

#: Ways to present no valid credential. `headers` are extra to the request.
UNAUTHENTICATED = [
    pytest.param([], b"", RefusalCause.MISSING_CREDENTIAL, id="missing token"),
    pytest.param([(b"authorization", f"Bearer {OTHER}".encode())], b"",
                 RefusalCause.WRONG_TOKEN, id="wrong token"),
    pytest.param([(b"authorization", f"Basic {TOKEN}".encode())], b"",
                 RefusalCause.WRONG_SCHEME, id="wrong scheme"),
    pytest.param([], f"access_token={TOKEN}".encode(),
                 RefusalCause.CREDENTIAL_IN_QUERY, id="token in the query string"),
    pytest.param([(b"mcp-session-id", b"0" * 32)], b"",
                 RefusalCause.MISSING_CREDENTIAL, id="a session id is not a credential"),
    pytest.param([(b"x-api-key", TOKEN.encode()), (b"cookie", f"token={TOKEN}".encode())], b"",
                 RefusalCause.MISSING_CREDENTIAL, id="the token in some other header"),
]


class _Inner:
    """Stands where the route and the SDK stand. Records whether it ran."""

    def __init__(self) -> None:
        self.scopes: list[dict] = []

    async def __call__(self, scope, receive, send) -> None:
        self.scopes.append(scope)
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"served"})


def _scope(method: str = "POST", headers=(), query: bytes = b"", path: str = MCP_PATH) -> dict:
    return {"type": "http", "method": method, "path": path, "query_string": query,
            "headers": [(b"content-type", b"application/json"), *headers]}


def _drive(app, scope: dict, body: bytes = b"") -> tuple[list[dict], int]:
    """Run one request. Returns what was sent and how many body reads happened."""
    sent: list[dict] = []
    reads = 0

    async def receive() -> dict:
        nonlocal reads
        reads += 1
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent, reads


@pytest.fixture
def guarded():
    inner = _Inner()
    recorded: list[dict[str, int]] = []
    ledger = RefusalLedger(lambda counts: recorded.append(dict(counts)), window_s=1e9)
    return ConnectionGuard(inner, LaunchToken(TOKEN), ledger), inner, ledger, recorded


class TestGuardRefusesBeforeAnythingRuns:
    @pytest.mark.parametrize(("method", "body"), FRAMES)
    @pytest.mark.parametrize(("headers", "query", "cause"), UNAUTHENTICATED)
    def test_no_frame_is_served_without_authentication(
        self, guarded, method, body, headers, query, cause
    ) -> None:
        guard, inner, ledger, recorded = guarded
        sent, reads = _drive(guard, _scope(method, headers, query), body)

        assert inner.scopes == [], "the request reached what is behind the guard"
        assert reads == 0, "the guard read the body of a request it had not admitted"
        assert sent[0]["status"] == 401
        assert (b"www-authenticate", b"Bearer") in sent[0]["headers"]
        assert json.loads(sent[1]["body"]) == {"error": "unauthorized"}
        assert recorded == [{cause.value: 1}]

    @pytest.mark.parametrize(("headers", "query", "cause"), UNAUTHENTICATED)
    def test_the_refusal_does_not_say_which_check_failed(
        self, guarded, headers, query, cause
    ) -> None:
        guard, _, _, _ = guarded
        sent, _ = _drive(guard, _scope("POST", headers, query))
        baseline, _ = _drive(guard, _scope("POST"))
        assert sent == baseline

    @pytest.mark.parametrize(("method", "body"), FRAMES)
    def test_every_frame_is_served_with_the_token(self, guarded, method, body) -> None:
        guard, inner, _, recorded = guarded
        scope = _scope(method, [(b"authorization", f"Bearer {TOKEN}".encode())])
        sent, _ = _drive(guard, scope, body)
        assert inner.scopes == [scope]
        assert sent[0]["status"] == 200
        assert recorded == []

    def test_authentication_is_per_request_not_per_session(self, guarded) -> None:
        """A session id the guard has ALREADY seen beside the token buys nothing
        when it comes back alone. The id is sent with the token first, twice, so
        a guard that remembered admitted sessions would have it to remember."""
        guard, inner, _, recorded = guarded
        session = (b"mcp-session-id", b"0" * 32)
        authorized = (b"authorization", f"Bearer {TOKEN}".encode())
        for _ in range(2):
            sent, _ = _drive(guard, _scope("POST", [authorized, session]))
            assert sent[0]["status"] == 200
        for method in ("POST", "GET", "DELETE", "OPTIONS", "HEAD"):
            sent, _ = _drive(guard, _scope(method, [session]))
            assert sent[0]["status"] == 401, f"{method} was admitted on a session id alone"
        sent, _ = _drive(guard, _scope("POST", [(b"authorization", f"Bearer {OTHER}".encode()), session]))
        assert sent[0]["status"] == 401, "a known session id carried a wrong token past the guard"
        assert len(inner.scopes) == 2
        assert recorded == [{"missing_credential": 1}]

    def test_an_unknown_path_is_refused_before_it_is_routed(self, guarded) -> None:
        """Unauthenticated, every path answers the same 401: the mouth does not
        tell a stranger which paths exist."""
        guard, inner, _, _ = guarded
        sent, _ = _drive(guard, _scope("GET", path="/registry"))
        assert sent[0]["status"] == 401
        assert inner.scopes == []

    def test_a_websocket_is_refused_and_counted(self, guarded) -> None:
        guard, inner, _, recorded = guarded
        scope = {"type": "websocket", "path": MCP_PATH,
                 "headers": [(b"authorization", f"Bearer {TOKEN}".encode())]}
        sent, _ = _drive(guard, scope)
        assert inner.scopes == []
        assert sent == [{"type": "websocket.close", "code": 1008}]
        assert recorded == [{"unsupported_scope": 1}]

    def test_lifespan_passes_through(self, guarded) -> None:
        guard, inner, _, recorded = guarded
        _drive(guard, {"type": "lifespan"})
        assert [scope["type"] for scope in inner.scopes] == ["lifespan"]
        assert recorded == []


class _Says:
    name = MouthAuthenticator.LAUNCH_TOKEN

    def __init__(self, verdict) -> None:
        self._verdict = verdict

    def check(self, facts):
        if isinstance(self._verdict, Exception):
            raise self._verdict
        return self._verdict


class TestGuardFailsClosed:
    @pytest.mark.parametrize(
        "verdict",
        [None, True, 1, "ADMITTED", object(), RuntimeError("boom")],
        ids=["None", "True", "1", "the word", "an object", "raises"],
    )
    def test_only_the_admitting_value_admits(self, verdict) -> None:
        """A check that falls off the end, returns something truthy, or raises
        has not admitted anybody."""
        inner = _Inner()
        recorded: list[dict[str, int]] = []
        ledger = RefusalLedger(lambda counts: recorded.append(dict(counts)))
        sent, _ = _drive(ConnectionGuard(inner, _Says(verdict), ledger), _scope())
        assert inner.scopes == []
        assert sent[0]["status"] == 401
        assert recorded == [{"authenticator_error": 1}]

    def test_the_admitting_value_admits(self) -> None:
        inner = _Inner()
        guard = ConnectionGuard(inner, _Says(ADMITTED), RefusalLedger(lambda counts: None))
        sent, _ = _drive(guard, _scope())
        assert len(inner.scopes) == 1 and sent[0]["status"] == 200

    def test_a_failed_recording_still_refuses(self) -> None:
        def broken(counts) -> None:
            raise OSError("tape unavailable")

        inner = _Inner()
        guard = ConnectionGuard(inner, LaunchToken(TOKEN), RefusalLedger(broken))
        sent, _ = _drive(guard, _scope())
        assert inner.scopes == []
        assert sent[0]["status"] == 401


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestGuardWritesOutWaitingRefusals:
    """G17: the first refusal of a window is recorded at once and the rest wait
    for the window to turn. Something has to notice that it has turned, and when
    the only traffic left is authenticated, that something is the guard."""

    def _guarded(self):
        clock, inner, recorded = _Clock(), _Inner(), []
        ledger = RefusalLedger(lambda counts: recorded.append(dict(counts)), window_s=60, clock=clock)
        return ConnectionGuard(inner, LaunchToken(TOKEN), ledger), clock, inner, recorded

    def test_an_admitted_request_records_refusals_whose_window_has_turned(self) -> None:
        guard, clock, inner, recorded = self._guarded()
        admitted = _scope("POST", [(b"authorization", f"Bearer {TOKEN}".encode())])
        for _ in range(3):
            _drive(guard, _scope())
        assert recorded == [{"missing_credential": 1}], "the first refusal was not recorded at once"

        clock.now = 59.9
        sent, _ = _drive(guard, admitted)
        assert sent[0]["status"] == 200
        assert recorded == [{"missing_credential": 1}], "a record was written inside the window"

        clock.now = 60.0
        sent, _ = _drive(guard, admitted)
        assert sent[0]["status"] == 200
        assert recorded == [{"missing_credential": 1}, {"missing_credential": 2}], (
            "refusals waiting for their window were not written out when an "
            "authenticated request arrived after it had turned"
        )
        assert len(inner.scopes) == 2

    def test_an_admitted_request_with_nothing_waiting_records_nothing(self) -> None:
        guard, clock, _, recorded = self._guarded()
        clock.now = 600.0
        _drive(guard, _scope("POST", [(b"authorization", f"Bearer {TOKEN}".encode())]))
        assert recorded == []


class TestDiagnosticBudget:
    """The server underneath logs for requests the guard never sees, so how many
    lines it writes is a stranger's choice until something bounds it."""

    def _logger(self, budget: DiagnosticBudget) -> tuple[logging.Logger, list[str]]:
        lines: list[str] = []

        class _Keep(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                lines.append(record.getMessage())

        log = logging.Logger("budgeted")  # detached: nothing else hears it
        log.addFilter(budget)
        log.addHandler(_Keep())
        return log, lines

    def test_a_flood_writes_only_the_budget(self) -> None:
        clock = _Clock()
        budget = DiagnosticBudget(per_window=3, window_s=60, clock=clock)
        log, lines = self._logger(budget)
        for n in range(500):
            log.warning("Invalid HTTP request received. %d", n)
        assert lines == [f"Invalid HTTP request received. {n}" for n in range(3)]

    def test_a_different_message_does_not_get_a_budget_of_its_own(self) -> None:
        budget = DiagnosticBudget(per_window=2, window_s=60, clock=_Clock())
        log, lines = self._logger(budget)
        for n in range(50):
            log.warning("message %d", n)
            log.error("another %d", n)
        assert lines == ["message 0", "another 0"]

    def test_the_next_window_admits_again_and_says_what_was_held_back(self) -> None:
        clock = _Clock()
        budget = DiagnosticBudget(per_window=2, window_s=60, clock=clock)
        log, lines = self._logger(budget)
        for _ in range(10):
            log.warning("noise")
        clock.now = 59.9
        log.warning("still inside the window")
        clock.now = 60.0
        log.warning("a real fault: %s", "disk")
        log.warning("and another")
        log.warning("over again")
        assert lines == [
            "noise",
            "noise",
            "a real fault: disk (9 earlier server diagnostic(s) suppressed)",
            "and another",
        ]
        assert budget.drain() == 1
        assert budget.drain() == 0

    @pytest.mark.parametrize("kwargs", [{"per_window": 0}, {"window_s": 0}])
    def test_a_budget_that_bounds_nothing_or_admits_nothing_is_refused(self, kwargs) -> None:
        with pytest.raises(ValueError):
            DiagnosticBudget(**kwargs)


class TestMouthApp:
    def _app(self):
        inner = _Inner()
        events: list[str] = []

        @contextlib.asynccontextmanager
        async def running():
            events.append("up")
            try:
                yield
            finally:
                events.append("down")

        return MouthApp(inner, running), inner, events

    def test_the_one_path_is_served(self) -> None:
        app, inner, _ = self._app()
        sent, _ = _drive(app, _scope())
        assert sent[0]["status"] == 200 and len(inner.scopes) == 1

    @pytest.mark.parametrize("path", ["/", "/mcp/", "/call", "/registry", "/mcp/extra"])
    def test_any_other_path_is_not_found(self, path: str) -> None:
        app, inner, _ = self._app()
        sent, _ = _drive(app, _scope(path=path))
        assert sent[0]["status"] == 404 and inner.scopes == []

    def test_lifespan_holds_the_manager_open_between_startup_and_shutdown(self) -> None:
        app, _, events = self._app()
        inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent: list[str] = []

        async def receive():
            sent.append(f"read:{events[-1] if events else '-'}")
            return inbox.pop(0)

        async def send(message):
            sent.append(message["type"])

        asyncio.run(app({"type": "lifespan"}, receive, send))
        assert sent == ["read:-", "lifespan.startup.complete", "read:up", "lifespan.shutdown.complete"]
        assert events == ["up", "down"]


class _RecordingSurface:
    server_name = "stub"

    def __init__(self) -> None:
        self.entered = 0
        self.inside = None

    def tools(self):
        self.entered += 1
        return []

    def call(self, wire_name, arguments=None):
        self.entered += 1
        if self.inside is not None:
            return self.inside()
        return (wire_name, arguments)


class TestSerializedSurface:
    def test_it_passes_calls_through_on_the_owning_thread(self) -> None:
        inner = _RecordingSurface()
        surface = SerializedSurface(inner)
        assert surface.server_name == "stub"
        assert surface.tools() == []
        assert surface.call("a__b", {"k": 1}) == ("a__b", {"k": 1})
        assert surface.call("a__b") == ("a__b", None)

    @pytest.mark.parametrize("method", ["tools", "call"])
    def test_another_thread_is_refused_before_the_runtime(self, method: str) -> None:
        inner = _RecordingSurface()
        surface = SerializedSurface(inner)
        caught: list[BaseException] = []

        def off_thread() -> None:
            try:
                surface.tools() if method == "tools" else surface.call("a__b")
            except BaseException as exc:  # noqa: BLE001
                caught.append(exc)

        worker = threading.Thread(target=off_thread)
        worker.start()
        worker.join()
        assert len(caught) == 1 and isinstance(caught[0], RuntimeEntryRefused)
        assert "thread" in str(caught[0])
        assert inner.entered == 0

    def test_an_overlapping_call_is_refused_before_the_runtime(self) -> None:
        inner = _RecordingSurface()
        surface = SerializedSurface(inner)
        inner.inside = lambda: surface.call("second__call")
        with pytest.raises(RuntimeEntryRefused, match="another call"):
            surface.call("first__call")
        assert inner.entered == 1, "the second call reached the surface"

    def test_a_raising_call_does_not_wedge_the_next_one(self) -> None:
        inner = _RecordingSurface()
        surface = SerializedSurface(inner)

        def boom():
            raise KeyError("x")

        inner.inside = boom
        with pytest.raises(KeyError):
            surface.call("a__b")
        inner.inside = None
        assert surface.call("a__b") == ("a__b", None)


class TestLaunchSettings:
    @pytest.mark.parametrize(
        ("env", "expected"),
        [({}, "stdio"), ({TRANSPORT_ENV: ""}, "stdio"), ({TRANSPORT_ENV: "stdio"}, "stdio"),
         ({TRANSPORT_ENV: "streamable-http"}, "streamable-http")],
    )
    def test_transport(self, env, expected) -> None:
        assert resolve_transport(env) == expected

    @pytest.mark.parametrize("value", ["http", "sse", "streamable_http", "STDIO", "network"])
    def test_an_unrecognized_transport_refuses(self, value: str) -> None:
        with pytest.raises(GatewayConfigError, match="not a recognized gateway transport"):
            resolve_transport({TRANSPORT_ENV: value})

    def _named(self, tmp_path: Path, **extra: str) -> dict[str, str]:
        token_file = write_token(tmp_path / "token")
        return {AUTH_ENV: "launch_token", TOKEN_FILE_ENV: str(token_file), PORT_ENV: "0", **extra}

    def test_the_default_bind_is_loopback(self, tmp_path: Path) -> None:
        settings = resolve_network_mouth(self._named(tmp_path))
        assert (settings.host, settings.port) == ("127.0.0.1", 0)
        assert is_loopback(settings.host)

    def test_the_bind_address_is_a_named_setting(self, tmp_path: Path) -> None:
        settings = resolve_network_mouth(self._named(tmp_path, **{HOST_ENV: "0.0.0.0", PORT_ENV: "8443"}))
        assert (settings.host, settings.port) == ("0.0.0.0", 8443)
        assert not is_loopback(settings.host)

    @pytest.mark.parametrize(
        ("change", "words"),
        [
            pytest.param({PORT_ENV: ""}, f"{PORT_ENV} is unset", id="no port"),
            pytest.param({PORT_ENV: "http"}, "not a port number", id="port is a word"),
            pytest.param({PORT_ENV: "-1"}, "not a port number", id="negative port"),
            pytest.param({PORT_ENV: "65536"}, "not a port number", id="port too large"),
            pytest.param({AUTH_ENV: ""}, f"{AUTH_ENV} is unset", id="no authenticator"),
            pytest.param({AUTH_ENV: "oauth_bearer"}, "NOT YET IMPLEMENTED", id="reserved oauth"),
            pytest.param({AUTH_ENV: "mtls_workload_identity"}, "NOT YET IMPLEMENTED", id="reserved mtls"),
            pytest.param({TOKEN_FILE_ENV: ""}, f"{TOKEN_FILE_ENV} is unset", id="no token file"),
        ],
    )
    def test_startup_refuses_in_words(self, tmp_path: Path, change, words) -> None:
        with pytest.raises(GatewayConfigError) as refusal:
            resolve_network_mouth({**self._named(tmp_path), **change})
        assert words in str(refusal.value)

    def test_loopback_is_not_exempt_from_naming_an_authenticator(self) -> None:
        with pytest.raises(GatewayConfigError, match="on loopback or anywhere else"):
            resolve_network_mouth({HOST_ENV: "127.0.0.1", PORT_ENV: "0"})

    @pytest.mark.parametrize(
        ("host", "loopback"),
        [("127.0.0.1", True), ("127.8.8.8", True), ("::1", True), ("localhost", True),
         ("0.0.0.0", False), ("::", False), ("192.168.1.4", False), ("example.internal", False)],
    )
    def test_is_loopback(self, host: str, loopback: bool) -> None:
        assert is_loopback(host) is loopback

    def test_port_zero_binds_a_real_port_and_reports_it(self) -> None:
        listener = bind_listener("127.0.0.1", 0)
        try:
            port = listener.getsockname()[1]
            assert port > 0
            assert listener_url(listener) == f"http://127.0.0.1:{port}{MCP_PATH}"
        finally:
            listener.close()

    def test_an_address_that_cannot_be_bound_refuses_in_words(self) -> None:
        with pytest.raises(GatewayConfigError, match="could not listen on"):
            bind_listener("203.0.113.1", 0)  # TEST-NET-3: not an address of this machine


@pytest.fixture
def runtime_and_sink(monkeypatch: pytest.MonkeyPatch):
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    runtime, sink = build_runtime(load_agent_manifest(_MANIFEST_PATH))
    try:
        yield runtime, sink
    finally:
        runtime.close()


class TestRecordingSeam:
    """`BrokerRuntime.record_refused_connections` — what a mouth records through."""

    def test_one_record_in_a_fixed_shape_under_the_runtimes_own_principal(self, runtime_and_sink) -> None:
        runtime, sink = runtime_and_sink
        before = len(sink.records())
        runtime.record_refused_connections(mouth=MOUTH_CODE, causes={"wrong_token": 7, "missing_credential": 2})
        (record,) = sink.records()[before:]
        assert (record.tool, record.op) == (MOUTH_REFUSAL_TOOL, "network-mcp")
        assert (record.decision, record.outcome) == ("deny", "denied")
        assert record.principal.agentId == "embedded-assistant"
        assert record.reason == (
            "9 connection(s) refused before any frame was served: "
            "missing_credential=2, wrong_token=7"
        )

    @pytest.mark.parametrize(
        ("mouth", "causes"),
        [
            pytest.param(MOUTH_CODE, {}, id="nothing to record"),
            pytest.param(MOUTH_CODE, {"wrong_token": 0}, id="zero count"),
            pytest.param(MOUTH_CODE, {"wrong_token": -1}, id="negative count"),
            pytest.param(MOUTH_CODE, {"wrong_token": True}, id="bool count"),
            pytest.param(MOUTH_CODE, {"wrong_token": "3"}, id="string count"),
            pytest.param(MOUTH_CODE, {"Bearer abc123": 1}, id="a header as a cause"),
            pytest.param(MOUTH_CODE, {"wrong_token\nseq=1": 1}, id="a newline in a cause"),
            pytest.param(MOUTH_CODE, {"x" * 41: 1}, id="an overlong cause"),
            pytest.param("GET /mcp?access_token=abc", {"wrong_token": 1}, id="a request line as the mouth"),
            pytest.param("", {"wrong_token": 1}, id="no mouth"),
        ],
    )
    def test_anything_but_short_codes_and_positive_counts_is_refused_unwritten(
        self, runtime_and_sink, mouth, causes
    ) -> None:
        runtime, sink = runtime_and_sink
        before = len(sink.records())
        with pytest.raises(ValueError):
            runtime.record_refused_connections(mouth=mouth, causes=causes)
        assert len(sink.records()) == before

    def test_every_cause_the_mouth_can_name_is_recordable(self, runtime_and_sink) -> None:
        runtime, sink = runtime_and_sink
        before = len(sink.records())
        runtime.record_refused_connections(mouth=MOUTH_CODE, causes={cause.value: 1 for cause in RefusalCause})
        assert len(sink.records()) == before + 1


class _FakeMouth:
    """Stands where `NetworkMouth` stands in the launcher. Serves nothing."""

    made: list["_FakeMouth"] = []
    signal_while_serving = False

    def __init__(self, surface, *, authenticator, record_refusals, listener) -> None:
        self.listener = listener
        self.stops = 0
        self.stops_when_serving_began: int | None = None
        type(self).made.append(self)

    def request_stop(self) -> None:
        self.stops += 1

    async def serve(self) -> None:
        self.stops_when_serving_began = self.stops
        if self.signal_while_serving:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0)


class TestTheLauncherInProcess:
    """`__main__.main()` with the mouth replaced by a stand-in and the bind
    pinned to loopback, so what the launcher itself does around the mouth can be
    read without a second process and without listening on a real network."""

    @pytest.fixture
    def launch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        for var in _BROKER_ENV:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv(TRANSPORT_ENV, "streamable-http")
        monkeypatch.setenv(AUTH_ENV, "launch_token")
        monkeypatch.setenv(TOKEN_FILE_ENV, str(write_token(tmp_path / "token")))
        monkeypatch.setenv(PORT_ENV, "0")
        asked: list[tuple[str, int]] = []

        def loopback_whatever_is_asked(host: str, port: int):
            asked.append((host, port))
            return bind_listener("127.0.0.1", 0)

        _FakeMouth.made = []
        monkeypatch.setattr(launcher, "bind_listener", loopback_whatever_is_asked)
        monkeypatch.setattr(launcher, "NetworkMouth", _FakeMouth)
        return asked

    @pytest.mark.parametrize(
        ("host", "warned"),
        [("192.0.2.7", True), ("0.0.0.0", True), ("::", True),
         ("127.0.0.1", False), ("::1", False), ("localhost", False), (None, False)],
    )
    def test_a_bind_beyond_loopback_is_announced_as_carrying_the_token_in_the_clear(
        self, launch, monkeypatch: pytest.MonkeyPatch, capsys, host, warned
    ) -> None:
        """G19. The address asked for is never bound here: the test's bind is
        always loopback, and the announcement is about what was ASKED."""
        if host is not None:
            monkeypatch.setenv(HOST_ENV, host)
        launcher.main()
        out = capsys.readouterr()
        assert launch == [(host or "127.0.0.1", 0)]
        assert out.out == ""
        assert "network MCP mouth on http://" in out.err
        assert "(authenticator: launch_token)" in out.err
        warning = f"WARNING: bound to {host}, which is not loopback"
        if warned:
            assert warning in out.err
            assert "the bearer token crosses that network in the clear" in out.err
            assert out.err.index("network MCP mouth on") < out.err.index(warning)
        else:
            assert "WARNING" not in out.err
        assert TOKEN not in out.err

    def test_the_address_is_bound_before_the_runtime_is_built(
        self, launch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        order: list[str] = []
        real_bind, real_build = launcher.bind_listener, launcher.build_runtime
        monkeypatch.setattr(launcher, "bind_listener", lambda h, p: (order.append("bind"), real_bind(h, p))[1])
        monkeypatch.setattr(launcher, "build_runtime", lambda m: (order.append("build"), real_build(m))[1])
        launcher.main()
        assert order == ["bind", "build"]

    def test_an_address_that_cannot_be_bound_refuses_without_building_the_runtime(
        self, launch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def cannot(host: str, port: int):
            raise GatewayConfigError(f"could not listen on {host}:{port}")

        built: list[object] = []
        monkeypatch.setattr(launcher, "bind_listener", cannot)
        monkeypatch.setattr(launcher, "build_runtime", lambda manifest: built.append(manifest))
        with pytest.raises(SystemExit) as refusal:
            launcher.main()
        assert "refusing to start the MCP gateway: could not listen on" in str(refusal.value.code)
        assert built == [] and _FakeMouth.made == []

    def test_the_listener_is_closed_when_the_launcher_leaves(self, launch) -> None:
        launcher.main()
        (mouth,) = _FakeMouth.made
        assert mouth.listener.fileno() == -1

    @pytest.mark.skipif(os.name == "nt", reason="needs a signal a process can send itself and catch")
    @pytest.mark.parametrize("when", ["as the address is announced", "while serving"])
    def test_a_stop_signal_reaches_the_mouth_and_is_never_swallowed(
        self, launch, monkeypatch: pytest.MonkeyPatch, when
    ) -> None:
        """From the moment a launcher can know the address, SIGTERM stops the
        mouth. A handler that only absorbed the signal leaves a gateway serving
        after its launcher has stopped it.

        The test puts its own handler under the launcher's first, so a launcher
        that installs none fails here and does not end the test run.
        """
        leaked: list[int] = []

        def ours(signum, _frame) -> None:
            leaked.append(signum)

        before = signal.signal(signal.SIGTERM, ours)
        try:
            if when == "while serving":
                monkeypatch.setattr(_FakeMouth, "signal_while_serving", True)
            else:
                real_announce = launcher._announce

                def announce_then_stop(settings, url) -> None:
                    real_announce(settings, url)
                    os.kill(os.getpid(), signal.SIGTERM)

                monkeypatch.setattr(launcher, "_announce", announce_then_stop)
            launcher.main()
            restored = signal.getsignal(signal.SIGTERM)
        finally:
            signal.signal(signal.SIGTERM, before)

        (mouth,) = _FakeMouth.made
        assert leaked == [], "the launcher had no handler of its own in place for the stop signal"
        assert mouth.stops == 1, "the stop signal did not reach the mouth"
        if when == "as the address is announced":
            assert mouth.stops_when_serving_began == 1, (
                "a stop sent before the mouth began serving was not waiting for it"
            )
        assert restored is ours, "the launcher did not put the earlier handler back"


_IMPORT_WITHOUT_SDK = """
import sys
for name in ("mcp", "uvicorn", "starlette", "anyio"):
    sys.modules[name] = None  # any import of these now raises ImportError
import safe_agents.broker.gateway
import safe_agents.broker.gateway.authn
import safe_agents.broker.gateway.network
import safe_agents.broker.gateway.events
import safe_agents.broker.runtime.observed
import safe_agents.broker.gateway.server
import safe_agents.broker.gateway.__main__
print("imported")
"""


def test_the_gateway_still_imports_with_the_sdk_absent() -> None:
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT_WITHOUT_SDK], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "imported"


def test_importing_the_gateway_does_not_import_the_sdk() -> None:
    probe = "import sys, safe_agents.broker.gateway.server; print(sorted(n for n in ('mcp','uvicorn') if n in sys.modules))"
    done = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"
