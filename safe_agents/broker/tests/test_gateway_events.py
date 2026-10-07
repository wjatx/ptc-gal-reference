"""The tool-event mouth's route, guard, settings and launcher — SDK-free.

`EventApp` and `ConnectionGuard` are plain ASGI, so a report is three dicts and
two coroutines, driven against a real runtime built from the test manifest
(`test_runtime_observed.py`). `test_gateway_events_e2e.py` asks the same
questions of a launched gateway on a real socket.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
import threading
from functools import partial
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.gateway import __main__ as launcher
from safe_agents.broker.gateway.authn import (
    AUTH_ENV,
    TOKEN_FILE_ENV,
    GatewayAuthConfigError,
    GatewayConfigError,
    LaunchToken,
    RefusalLedger,
)
from safe_agents.broker.gateway.events import (
    EVENT_ADDR_FILE_ENV,
    EVENT_HOST_ENV,
    EVENT_MOUTH_CODE,
    EVENT_PORT_ENV,
    EVENTS_PATH,
    MAX_EVENT_BODY_BYTES,
    EventApp,
    resolve_event_mouth,
    write_address_file,
)
from safe_agents.broker.gateway.network import (
    PORT_ENV,
    TRANSPORT_ENV,
    ConnectionGuard,
    RuntimeEntryRefused,
    SerializedSurface,
    bind_listener,
)
from safe_agents.broker.gateway.server import serve_until_any_stops
from safe_agents.broker.runtime.pep import MOUTH_REFUSAL_TOOL, OBSERVED_TOOL
from safe_agents.broker.tests.test_gateway_authn import OTHER, TOKEN, write_token
from safe_agents.broker.tests.test_gateway_network import _BROKER_ENV, _drive, _scope
from safe_agents.broker.tests.test_runtime_observed import RESULT, SUBJECT, WRITE, write_manifest

REPORT = {
    "harness": "example-harness",
    "tool_class": "file-read",
    "locality": "outside",
    "subject_digest": SUBJECT,
    "result_digest": RESULT,
}
AUTH = (b"authorization", f"Bearer {TOKEN}".encode())


def _body(**changes) -> bytes:
    report = {**REPORT, **changes}
    return json.dumps({k: v for k, v in report.items() if v is not ...}).encode()


def _status(sent: list[dict]) -> int:
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def _payload(sent: list[dict]) -> dict:
    return json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


@pytest.fixture
def mouth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A guarded `EventApp` over a real runtime, refusals recorded the way the
    launcher records them. Yields (app, runtime, sink, ledger)."""
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    runtime, sink = build_runtime(load_agent_manifest(write_manifest(tmp_path / "m.yaml")))
    surface = SerializedSurface(GatewaySurface(runtime))
    # Recorded through the launcher's own callback, so the wiring is under test too.
    ledger = RefusalLedger(partial(launcher._record_refusals, runtime, EVENT_MOUTH_CODE), window_s=1e9)
    app = ConnectionGuard(
        EventApp(partial(surface.observe, mouth=EVENT_MOUTH_CODE)), LaunchToken(TOKEN), ledger
    )
    try:
        yield app, runtime, sink, ledger
    finally:
        runtime.close()


class TestNoReportBeforeAuthentication:
    """G12 to G14 hold on this mouth too, with refusals under its own code (G17)."""

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param([], id="missing token"),
            pytest.param([(b"authorization", f"Bearer {OTHER}".encode())], id="wrong token"),
        ],
    )
    @pytest.mark.parametrize("path", [EVENTS_PATH, "/mcp", "/"])
    def test_an_unauthenticated_report_is_refused_before_anything_runs(self, mouth, headers, path) -> None:
        app, runtime, sink, ledger = mouth
        sent, reads = _drive(app, _scope("POST", headers=headers, path=path), _body())
        assert _status(sent) == 401
        assert reads == 0, "the guard let the body be read before authenticating"
        assert runtime.session_turn().tainted is False
        (record,) = sink.records()
        assert (record.tool, record.op) == (MOUTH_REFUSAL_TOOL, EVENT_MOUTH_CODE)
        assert (record.decision, record.outcome) == ("deny", "denied")

    def test_the_token_in_the_query_string_is_refused_beside_a_valid_header(self, mouth) -> None:
        app, _, sink, _ = mouth
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], query=f"token={TOKEN}".encode(),
                                     path=EVENTS_PATH), _body())
        assert _status(sent) == 401
        assert [r.tool for r in sink.records()] == [MOUTH_REFUSAL_TOOL]


#: Everything on the path that is not a report gets the one fixed 400.
NOT_A_REPORT = [
    pytest.param("GET", b"", id="GET"),
    pytest.param("PUT", _body(), id="PUT"),
    pytest.param("DELETE", b"", id="DELETE"),
    pytest.param("POST", b"", id="empty body"),
    pytest.param("POST", b"{not json", id="not JSON"),
    pytest.param("POST", b"\xff\xfe\xfd", id="not text"),
    pytest.param("POST", json.dumps([REPORT]).encode(), id="an array"),
    pytest.param("POST", json.dumps("file-read").encode(), id="a string"),
    pytest.param("POST", _body(extra="x"), id="an unknown key"),
    pytest.param("POST", _body(mouth="network-mcp"), id="a report naming its own mouth"),
    pytest.param("POST", _body(subject_digest=...), id="no subject"),
    pytest.param("POST", _body(harness=...), id="no harness"),
    pytest.param("POST", _body(subject_digest="/etc/passwd"), id="a raw path"),
    pytest.param("POST", _body(tool_class="read"), id="an unknown class"),
    pytest.param("POST", _body(locality="Outside"), id="an unknown locality"),
    pytest.param("POST", _body(harness=3), id="a number as the harness"),
    pytest.param(
        "POST",
        ('{"harness":"a","harness":"b","tool_class":"file-read","locality":"outside",'
         f'"subject_digest":"{SUBJECT}"}}').encode(),
        id="a repeated key",
    ),
]


class TestTheRoute:
    @pytest.mark.parametrize(("method", "body"), NOT_A_REPORT)
    def test_anything_but_a_report_gets_one_fixed_400_and_no_record(self, mouth, method, body) -> None:
        app, runtime, sink, _ = mouth
        sent, _ = _drive(app, _scope(method, headers=[AUTH], path=EVENTS_PATH), body)
        assert _status(sent) == 400
        assert _payload(sent) == {"error": "bad request"}
        assert sink.records() == []
        assert runtime.session_turn().tainted is False

    def test_a_valid_report_is_recorded_and_taints_the_turn(self, mouth) -> None:
        app, runtime, sink, _ = mouth
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], path=EVENTS_PATH), _body())
        assert _status(sent) == 200
        assert _payload(sent) == {"source": "harness:example-harness/file-read/outside"}
        (record,) = sink.records()
        assert (record.tool, record.op, record.outcome) == (OBSERVED_TOOL, "file-read", "observed")
        assert record.reason.endswith("reported by mouth tool-event")
        assert runtime.handle_request(WRITE).decision_kind == "require_approval"

    def test_a_report_that_does_not_taint_answers_null(self, mouth) -> None:
        app, runtime, sink, _ = mouth
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], path=EVENTS_PATH),
                         _body(tool_class="shell", result_digest=...))
        assert (_status(sent), _payload(sent)) == (200, {"source": None})
        assert [r.op for r in sink.records()] == ["shell"]
        assert runtime.session_turn().tainted is False

    def test_another_path_is_not_found_to_an_authenticated_caller(self, mouth) -> None:
        app, _, sink, _ = mouth
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], path="/events/"), _body())
        assert _status(sent) == 404
        assert sink.records() == []

    def test_a_body_declared_too_large_is_refused_unread(self, mouth) -> None:
        app, _, sink, _ = mouth
        scope = _scope("POST", headers=[AUTH, (b"content-length", str(MAX_EVENT_BODY_BYTES + 1).encode())],
                       path=EVENTS_PATH)
        sent, reads = _drive(app, scope, _body())
        assert _status(sent) == 400
        assert reads == 0
        assert sink.records() == []

    def test_a_body_that_grows_past_the_bound_is_refused_without_reading_on(self, mouth) -> None:
        """No content-length, a body streamed in chunks: the mouth stops reading
        at the first chunk past the bound, whatever the caller still has to send."""
        app, _, sink, _ = mouth
        reads = 0

        async def receive() -> dict:
            nonlocal reads
            reads += 1
            return {"type": "http.request", "body": b" " * 1024, "more_body": True}

        sent: list[dict] = []

        async def send(message: dict) -> None:
            sent.append(message)

        asyncio.run(app(_scope("POST", headers=[AUTH], path=EVENTS_PATH), receive, send))
        assert _status(sent) == 400
        assert reads == MAX_EVENT_BODY_BYTES // 1024 + 1
        assert sink.records() == []

    def test_a_report_the_runtime_could_not_record_is_a_fixed_500(self, mouth, monkeypatch) -> None:
        """The taint it carried has landed anyway: the runtime taints first."""
        app, runtime, sink, _ = mouth

        def broken(_record) -> None:
            raise OSError("the tape is unwritable")

        monkeypatch.setattr(sink, "append", broken)
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], path=EVENTS_PATH), _body())
        assert (_status(sent), _payload(sent)) == (500, {"error": "not recorded"})
        assert runtime.session_turn().tainted is True


class TestOneSerializedEntry:
    """G18: the event mouth enters the runtime through the same rules as a call."""

    class _Recording:
        def __init__(self) -> None:
            self.reports: list[dict] = []
            self.server_name = "x"

        def observe(self, **report):
            self.reports.append(report)
            return None

    def test_a_report_from_another_thread_is_refused_before_the_runtime(self) -> None:
        inner = self._Recording()
        serialized = SerializedSurface(inner)
        errors: list[BaseException] = []

        def other() -> None:
            try:
                serialized.observe(mouth=EVENT_MOUTH_CODE, **REPORT)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        thread = threading.Thread(target=other)
        thread.start()
        thread.join()
        assert len(errors) == 1 and isinstance(errors[0], RuntimeEntryRefused)
        assert inner.reports == []

    def test_a_report_while_a_call_is_inside_is_refused_before_the_runtime(self) -> None:
        inner = self._Recording()
        serialized = SerializedSurface(inner)
        inner.call = lambda *_a, **_k: serialized.observe(mouth=EVENT_MOUTH_CODE, **REPORT)
        with pytest.raises(RuntimeEntryRefused):
            serialized.call("crm__post", {})
        assert inner.reports == []


class TestLaunchSettings:
    def _env(self, tmp_path: Path, **extra: str) -> dict[str, str]:
        return {AUTH_ENV: "launch_token", TOKEN_FILE_ENV: str(write_token(tmp_path / "token")), **extra}

    def test_unset_port_means_the_mouth_stays_shut(self, tmp_path: Path) -> None:
        assert resolve_event_mouth(self._env(tmp_path)) is None
        assert resolve_event_mouth({}) is None

    def test_a_named_port_opens_it_on_loopback_by_default(self, tmp_path: Path) -> None:
        settings = resolve_event_mouth(self._env(tmp_path, **{EVENT_PORT_ENV: "0"}))
        assert settings is not None
        assert (settings.host, settings.port, settings.addr_file) == ("127.0.0.1", 0, None)
        assert settings.authenticator.name.value == "launch_token"

    def test_host_and_address_file_are_named_settings(self, tmp_path: Path) -> None:
        settings = resolve_event_mouth(self._env(
            tmp_path, **{EVENT_PORT_ENV: "8123", EVENT_HOST_ENV: "::1", EVENT_ADDR_FILE_ENV: "/x/addr"}
        ))
        assert (settings.host, settings.port, settings.addr_file) == ("::1", 8123, "/x/addr")

    def test_an_unnamed_authenticator_refuses_to_start(self) -> None:
        """G13: no unauthenticated default, on loopback or anywhere else."""
        with pytest.raises(GatewayAuthConfigError, match="BROKER_GATEWAY_AUTH is unset"):
            resolve_event_mouth({EVENT_PORT_ENV: "0"})

    @pytest.mark.parametrize("raw", ["x", "-1", "65536", "80.5"])
    def test_a_port_that_is_not_one_refuses(self, tmp_path: Path, raw: str) -> None:
        with pytest.raises(GatewayConfigError, match=f"{EVENT_PORT_ENV}="):
            resolve_event_mouth(self._env(tmp_path, **{EVENT_PORT_ENV: raw}))

    @pytest.mark.parametrize("name", [EVENT_HOST_ENV, EVENT_ADDR_FILE_ENV])
    def test_an_address_named_without_a_port_refuses(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(GatewayConfigError, match=f"{EVENT_PORT_ENV} is unset"):
            resolve_event_mouth(self._env(tmp_path, **{name: "x"}))


class TestTheAddressFile:
    def test_it_holds_host_and_port_and_is_owner_only(self, tmp_path: Path) -> None:
        path = tmp_path / "addr"
        path.write_text("stale contents that are longer than the address\n", encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o644)
        write_address_file(str(path), "127.0.0.1", 40123)
        assert path.read_text(encoding="utf-8") == "127.0.0.1:40123\n"
        if sys.platform != "win32":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_an_ipv6_host_is_bracketed(self, tmp_path: Path) -> None:
        path = tmp_path / "addr"
        write_address_file(str(path), "::1", 40123)
        assert path.read_text(encoding="utf-8") == "[::1]:40123\n"

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="the platform cannot refuse a link")
    def test_it_is_not_written_through_a_symbolic_link(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        target.write_text("untouched\n", encoding="utf-8")
        (tmp_path / "addr").symlink_to(target)
        with pytest.raises(GatewayConfigError, match="could not be written"):
            write_address_file(str(tmp_path / "addr"), "127.0.0.1", 1)
        assert target.read_text(encoding="utf-8") == "untouched\n"


class _FakeMouth:
    """Stands where a mouth stands in the launcher. Serves until stopped."""

    made: list["_FakeMouth"] = []
    signal_while_serving = False

    def __init__(self, surface, **kwargs) -> None:
        self.surface = surface
        self.listener = kwargs.get("listener")
        self.stops = 0
        type(self).made.append(self)

    def request_stop(self) -> None:
        self.stops += 1

    async def serve(self) -> None:
        if self.signal_while_serving and self is type(self).made[0]:
            os.kill(os.getpid(), signal.SIGTERM)
        while not self.stops:
            await asyncio.sleep(0.01)


class TestTheLauncherInProcess:
    """`__main__.main()` with every mouth replaced by a stand-in."""

    @pytest.fixture
    def launch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        for var in _BROKER_ENV:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("BROKER_MANIFEST", str(write_manifest(tmp_path / "m.yaml")))
        monkeypatch.setenv(EVENT_PORT_ENV, "0")
        monkeypatch.setenv(AUTH_ENV, "launch_token")
        monkeypatch.setenv(TOKEN_FILE_ENV, str(write_token(tmp_path / "token")))
        _FakeMouth.made = []
        for name in ("StdioMouth", "EventMouth", "NetworkMouth"):
            monkeypatch.setattr(launcher, name, _FakeMouth)
        return tmp_path

    def test_an_unnamed_authenticator_refuses_before_the_runtime_is_built(self, launch, monkeypatch) -> None:
        monkeypatch.delenv(AUTH_ENV)
        built: list[object] = []
        monkeypatch.setattr(launcher, "build_runtime", lambda manifest: built.append(manifest))
        with pytest.raises(SystemExit) as refusal:
            launcher.main()
        assert "refusing to start the MCP gateway: BROKER_GATEWAY_AUTH is unset" in str(refusal.value.code)
        assert built == [] and _FakeMouth.made == []

    def test_the_event_address_is_bound_before_the_runtime_is_built(self, launch, monkeypatch) -> None:
        order: list[str] = []
        real_bind, real_build = launcher.bind_listener, launcher.build_runtime

        def bind(host, port, **kwargs):
            order.append("bind")
            return real_bind(host, port, **kwargs)

        monkeypatch.setattr(launcher, "bind_listener", bind)
        monkeypatch.setattr(launcher, "build_runtime", lambda m: (order.append("build"), real_build(m))[1])
        monkeypatch.setattr(_FakeMouth, "serve", _returns)
        launcher.main()
        assert order == ["bind", "build"]

    @pytest.mark.skipif(os.name == "nt", reason="needs a signal a process can send itself and catch")
    @pytest.mark.parametrize("transport", ["stdio", "streamable-http"])
    def test_one_stop_signal_reaches_every_mouth_sharing_the_loop(
        self, launch, monkeypatch, capsys, transport
    ) -> None:
        """Both mouths, one surface, one signal. The test's own handler sits
        under the launcher's, so a launcher with none fails here, not the run."""
        if transport != "stdio":
            monkeypatch.setenv(TRANSPORT_ENV, transport)
            monkeypatch.setenv(PORT_ENV, "0")
        addr = launch / "addr"
        monkeypatch.setenv(EVENT_ADDR_FILE_ENV, str(addr))
        monkeypatch.setattr(_FakeMouth, "signal_while_serving", True)
        leaked: list[int] = []

        def ours(signum, _frame) -> None:
            leaked.append(signum)

        before = signal.signal(signal.SIGTERM, ours)
        try:
            launcher.main()
            restored = signal.getsignal(signal.SIGTERM)
        finally:
            signal.signal(signal.SIGTERM, before)
        assert leaked == [], "the launcher had no handler of its own in place for the stop signal"
        assert len(_FakeMouth.made) == 2
        assert [m.stops for m in _FakeMouth.made] == [1, 1], "the stop did not reach every mouth"
        assert _FakeMouth.made[0].surface is _FakeMouth.made[1].surface, (
            "two mouths over one runtime must share one serialized surface"
        )
        assert isinstance(_FakeMouth.made[0].surface, SerializedSurface)
        assert restored is ours, "the launcher did not put the earlier handler back"
        err = capsys.readouterr().err
        written = addr.read_text(encoding="utf-8")
        assert written.startswith("127.0.0.1:") and written.endswith("\n")
        assert (
            f"[broker] tool-event mouth on http://{written.strip()}/events "
            "(authenticator: launch_token)"
        ) in err
        assert "WARNING" not in err
        assert TOKEN not in err
        assert all(m.listener is None or m.listener.fileno() == -1 for m in _FakeMouth.made)

    def test_a_bind_beyond_loopback_is_announced_as_carrying_the_token_in_the_clear(
        self, launch, monkeypatch, capsys
    ) -> None:
        monkeypatch.setenv(EVENT_HOST_ENV, "192.0.2.7")
        monkeypatch.setattr(launcher, "bind_listener", lambda host, port, **kw: bind_listener("127.0.0.1", 0))
        monkeypatch.setattr(_FakeMouth, "serve", _returns)
        launcher.main()
        err = capsys.readouterr().err
        assert "WARNING: bound to 192.0.2.7, which is not loopback" in err
        assert err.index("tool-event mouth on") < err.index("WARNING")


async def _returns(self) -> None:
    return None


class _Stub:
    def __init__(self, *, returns_after: float | None = None, fails: bool = False) -> None:
        self.returns_after = returns_after
        self.fails = fails
        self.stops = 0
        self.finished = False

    def request_stop(self) -> None:
        self.stops += 1

    async def serve(self) -> None:
        try:
            if self.returns_after is not None:
                await asyncio.sleep(self.returns_after)
                if self.fails:
                    raise RuntimeError("this mouth broke")
                return
            while not self.stops:
                await asyncio.sleep(0.01)
        finally:
            self.finished = True


class TestServeUntilAnyStops:
    def test_when_one_mouth_returns_the_others_are_stopped_and_finish(self) -> None:
        """A stdio client that closes its pipe ends the gateway, event mouth too."""
        first, second = _Stub(returns_after=0.0), _Stub()
        asyncio.run(serve_until_any_stops([first, second]))
        assert (first.stops, second.stops) == (0, 1)
        assert first.finished and second.finished

    def test_a_failing_mouth_stops_the_rest_then_raises(self) -> None:
        broken, other = _Stub(returns_after=0.0, fails=True), _Stub()
        with pytest.raises(RuntimeError, match="this mouth broke"):
            asyncio.run(serve_until_any_stops([broken, other]))
        assert other.stops == 1 and other.finished
