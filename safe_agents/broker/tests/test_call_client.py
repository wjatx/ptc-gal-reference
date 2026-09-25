"""Tests for call_client — the deterministic client the Compute client task runs (#42).

The load-bearing test drives a REAL broker over HTTP: broker_server's own request
handler, bound to an ephemeral port, in front of a runtime built from the
embedded_agent manifest. That is the same allow/refuse pair the AWS walkthrough
shows, so if the wire shape and the client ever drift apart it fails here rather
than in someone's CloudWatch log.

The remaining tests pin the exit-code contract, because the contract is what a
runbook keys on: a deny is a SUCCESS (the broker decided), while an unreachable
broker or an HTTP error is a failure that stops before any later call.
"""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.prototype import broker_server, call_client

_EMBEDDED_MANIFEST = (
    Path(__file__).resolve().parents[3] / "examples" / "embedded_agent" / "manifest.yaml"
)

# The arm-selecting variables, cleared so the runtime below is provably the
# in-memory arm rather than whatever the ambient shell selects.
_ARM_VARS = (
    "BROKER_STORE",
    "BROKER_MANIFEST",
    "BROKER_SECRETS",
    "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE",
    "BROKER_AUDIT_PATH",
    "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD",
    "BROKER_GRANT_LOAD",
    "BROKER_SQLITE_PATH",
)


def _serve(monkeypatch: pytest.MonkeyPatch, runtime, sink) -> str:
    """Bind broker_server's handler to an ephemeral port over ``runtime``; return its URL."""
    monkeypatch.setattr(broker_server, "_RUNTIME", runtime)
    monkeypatch.setattr(broker_server, "_SINK", sink)
    # The handler logs each request to stdout, which capsys would interleave with
    # the client's JSON lines.
    monkeypatch.setattr(broker_server._Handler, "log_message", lambda *a, **k: None)
    server = HTTPServer(("127.0.0.1", 0), broker_server._Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _SERVERS.append(server)
    return f"http://127.0.0.1:{server.server_address[1]}"


_SERVERS: list[HTTPServer] = []


@pytest.fixture(autouse=True)
def _shutdown_servers():
    yield
    while _SERVERS:
        server = _SERVERS.pop()
        server.shutdown()
        server.server_close()


@pytest.fixture
def embedded_broker(monkeypatch: pytest.MonkeyPatch):
    """A real broker for the embedded_agent manifest; yields (url, audit sink)."""
    for var in _ARM_VARS:
        monkeypatch.delenv(var, raising=False)
    runtime, sink = build_runtime(load_agent_manifest(_EMBEDDED_MANIFEST))
    url = _serve(monkeypatch, runtime, sink)
    monkeypatch.setenv("BROKER_URL", url)
    return url, sink


def _lines(out: str) -> list[dict]:
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_allow_and_refusal_round_trip_through_a_real_broker(embedded_broker, capsys):
    url, sink = embedded_broker

    code = call_client.main([
        "--call", "search.query", '{"query": "broker"}',
        "--call", "notify.send", '{"to": "ops"}',
    ])

    assert code == call_client.EXIT_OK
    header, allowed, refused = _lines(capsys.readouterr().out)

    # The registry is what the principal may SEE: granted, not merely classified.
    assert header == {"broker_url": url, "registry": [{"tool": "search", "op": "query"}]}

    assert allowed["call"] == "search.query"
    assert allowed["decision_kind"] == "allow"
    assert [hit["topic"] for hit in allowed["result"]["hits"]] == ["broker"]

    # A policy refusal, not a missing classification (see the example's README).
    assert refused["call"] == "notify.send"
    assert refused["decision_kind"] == "deny"
    assert refused["reason"] == "tool not granted to this principal"
    assert refused["result"] is None

    # Both decisions are on the tape, in order.
    assert [(r.decision, r.outcome) for r in sink.records()] == [
        ("allow", "executed"),
        ("deny", "denied"),
    ]


def test_no_calls_prints_only_the_registry(embedded_broker, capsys):
    assert call_client.main([]) == call_client.EXIT_OK
    (header,) = _lines(capsys.readouterr().out)
    assert header["registry"] == [{"tool": "search", "op": "query"}]


def test_an_unreachable_broker_fails_with_the_url_named(monkeypatch, capsys):
    # Bind then close, so the port is known to be free of a listener.
    server = HTTPServer(("127.0.0.1", 0), broker_server._Handler)
    port = server.server_address[1]
    server.server_close()
    monkeypatch.setenv("BROKER_URL", f"http://127.0.0.1:{port}")

    code = call_client.main(["--call", "search.query", "{}", "--timeout", "2"])

    captured = capsys.readouterr()
    assert code == call_client.EXIT_BROKER_FAILURE
    assert captured.out == ""
    assert "BROKER UNAVAILABLE" in captured.err
    assert f"127.0.0.1:{port}/registry" in captured.err


class _ExplodingRuntime:
    """Serves a registry, then faults on every call — the broker's generic 500 path."""

    def served_registry(self):
        return []

    def handle_request(self, request):
        raise RuntimeError("store outage")


def test_an_http_error_stops_before_later_calls(monkeypatch, capsys):
    monkeypatch.setenv("BROKER_URL", _serve(monkeypatch, _ExplodingRuntime(), None))

    code = call_client.main([
        "--call", "search.query", "{}",
        "--call", "notify.send", "{}",
    ])

    captured = capsys.readouterr()
    assert code == call_client.EXIT_BROKER_FAILURE
    # Only the registry line: the second call is never sent after the first failed.
    assert len(_lines(captured.out)) == 1
    # The server shares this process and logs the fault to stderr, so read the
    # client's own line rather than the whole stream.
    (client_err,) = [ln for ln in captured.err.splitlines() if ln.startswith("BROKER UNAVAILABLE")]
    assert "HTTP 500" in client_err
    assert "internal broker error" in client_err
    # The broker's internal detail stays server-side.
    assert "store outage" not in client_err


@pytest.mark.parametrize(
    ("coordinate", "raw_args", "message"),
    [
        ("searchquery", "{}", "is not TOOL.OP"),
        (".query", "{}", "is not TOOL.OP"),
        ("search.", "{}", "is not TOOL.OP"),
        ("search.query", "{not json", "not valid JSON"),
        ("search.query", '["a"]', "must be a JSON object, got list"),
    ],
)
def test_malformed_calls_are_usage_errors(coordinate, raw_args, message, capsys):
    with pytest.raises(SystemExit) as exc:
        call_client.main(["--call", coordinate, raw_args])
    assert exc.value.code == 2
    assert message in capsys.readouterr().err
