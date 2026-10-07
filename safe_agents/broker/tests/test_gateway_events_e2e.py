"""The tool-event mouth, end to end: a launched gateway, a real socket, a real tape.

`test_gateway_events.py` proves the route and the guard with three dicts. This
launches `python -m safe_agents.broker.gateway` the way a harness does, opens the
tool-event mouth beside it on port 0, finds it through the address file, and
reports to it the way a harness's hook would. The decisive case is the first:
a read the harness made with its own tool, reported to the mouth, holds the next
external write the agent asks for over stdio, and the tape says why, in order.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from safe_agents.broker.audit import verify_chain
from safe_agents.broker.client import GatewayClient, result_text
from safe_agents.broker.client.stdio import env_without_broker_config
from safe_agents.broker.gateway.events import (
    EVENT_ADDR_FILE_ENV,
    EVENT_MOUTH_CODE,
    EVENT_PORT_ENV,
    EVENTS_PATH,
)
from safe_agents.broker.gateway.network import MOUTH_CODE
from safe_agents.broker.runtime.pep import MOUTH_REFUSAL_TOOL, OBSERVED_TOOL
from safe_agents.broker.schemas.audit_record import AuditRecord
from safe_agents.broker.tests.test_gateway_authn import TOKEN, write_token
from safe_agents.broker.tests.test_gateway_events import REPORT
from safe_agents.broker.tests.test_runtime_observed import write_manifest

pytest.importorskip("mcp", reason="the gateway's servers need the optional 'mcp' extra")

from safe_agents.broker.tests.test_gateway_network_e2e import (  # noqa: E402 — needs the extra
    _Launched,
    _refused,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCH_S = 60
_EXIT_S = 30

_SIGNALS = pytest.mark.skipif(os.name == "nt", reason="a graceful stop needs a signal the child can catch")


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """A stdio gateway on the test manifest, with the tool-event mouth open on port 0."""
    return {
        "BROKER_MANIFEST": str(write_manifest(tmp_path / "manifest.yaml")),
        "BROKER_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "BROKER_GATEWAY_AUTH": "launch_token",
        "BROKER_GATEWAY_TOKEN_FILE": str(write_token(tmp_path / "token")),
        EVENT_PORT_ENV: "0",
        EVENT_ADDR_FILE_ENV: str(tmp_path / "events.addr"),
        **extra,
    }


def _events_url(tmp_path: Path, child: subprocess.Popen, stderr) -> str:
    """Wait for the address file, as a launcher that asked for port 0 does."""
    path = tmp_path / "events.addr"
    deadline = time.monotonic() + _LAUNCH_S
    while time.monotonic() < deadline:
        written = path.read_text(encoding="utf-8") if path.exists() else ""
        if written.endswith("\n"):
            return f"http://{written.strip()}{EVENTS_PATH}"
        if child.poll() is not None:
            break
        time.sleep(0.05)
    pytest.fail("the gateway never wrote the tool-event mouth's address:\n" + stderr())


def _post(url: str, body: bytes, token: str | None = TOKEN) -> tuple[int, dict]:
    headers = {"content-type": "application/json"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 — loopback, test
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _tape(tmp_path: Path) -> list[AuditRecord]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    records = [AuditRecord.model_validate_json(line) for line in path.read_text(encoding="utf-8").splitlines()]
    verify_chain(records)
    return records


@pytest.fixture
def gateway(tmp_path: Path):
    """A stdio gateway with the tool-event mouth open. Yields (client, events URL)."""
    client = GatewayClient(env={**env_without_broker_config(), **_env(tmp_path)}, cwd=REPO_ROOT)
    try:
        url = _events_url(tmp_path, client.proc, lambda: client.stderr_text)
        yield client, url
    finally:
        client.close()


@pytest.mark.parametrize("reported", [True, False], ids=["read reported", "control: nothing reported"])
def test_a_reported_read_holds_the_next_external_write_over_stdio(tmp_path: Path, gateway, reported) -> None:
    """The harness read a file outside the project with its own tool, and its hook
    said so. The agent's next external write through the gateway is held, where
    without the report the same write executes. The tape, verified, holds the
    observed record before the held one."""
    client, url = gateway
    client.initialize("event-mouth-e2e")
    assert "crm__post" in [tool["name"] for tool in client.list_tools()]
    if reported:
        status, answer = _post(url, json.dumps(REPORT).encode())
        assert (status, answer) == (200, {"source": "harness:example-harness/file-read/outside"})

    result = client.call_tool("crm__post", {"note": "hello"})
    client.close()

    tape = _tape(tmp_path)
    if not reported:
        assert result["isError"] is False, result_text(result)
        assert [r.outcome for r in tape] == ["executed"]
        return
    assert result["isError"] is True
    assert "crm.post is held for approval" in result_text(result)
    assert "it has NOT executed" in result_text(result)
    assert [(r.tool, r.outcome) for r in tape] == [(OBSERVED_TOOL, "observed"), ("crm", "held")]
    observed, held = tape
    assert (observed.decision, observed.op) == ("abstain", "file-read")
    assert held.reason == "tainted external write"
    assert client.proc.returncode == 0, client.stderr_text
    assert "[broker] tool-event mouth on http://127.0.0.1:" in client.stderr_text


@_SIGNALS
def test_no_report_is_taken_unauthenticated_and_one_sigterm_writes_the_tail(tmp_path: Path, gateway) -> None:
    """G12 and G17 on this mouth, through the launcher: three refused reports are
    one record at once and two at shutdown, under the mouth's own code. A
    malformed report from an authenticated caller writes nothing. One SIGTERM,
    with the stdio session still open, stops both servers, and the process
    leaves by returning."""
    client, url = gateway
    client.initialize("event-mouth-e2e")
    for token in (None, None, "x" * 43):
        assert _post(url, json.dumps(REPORT).encode(), token=token)[0] == 401
    assert _post(url, b'{"harness": "example-harness"}') == (400, {"error": "bad request"})

    client.proc.send_signal(signal.SIGTERM)
    try:
        client.proc.wait(timeout=_EXIT_S)
    except subprocess.TimeoutExpired:
        pytest.fail(f"the gateway was still running {_EXIT_S}s after one SIGTERM:\n{client.stderr_text}")
    client.close()

    assert client.proc.returncode == 0, client.stderr_text
    assert "Traceback" not in client.stderr_text
    tape = _tape(tmp_path)
    assert [(r.tool, r.op, r.reason) for r in tape] == [
        (MOUTH_REFUSAL_TOOL, EVENT_MOUTH_CODE,
         "1 connection(s) refused before any frame was served: missing_credential=1"),
        (MOUTH_REFUSAL_TOOL, EVENT_MOUTH_CODE,
         "2 connection(s) refused before any frame was served: missing_credential=1, wrong_token=1"),
    ]
    for line in client.stdout_lines:
        json.loads(line.decode("utf-8"))


@_SIGNALS
def test_one_sigterm_stops_both_http_mouths_and_writes_both_tails(tmp_path: Path) -> None:
    """With the network MCP mouth and the tool-event mouth sharing one loop, one
    signal stops both, and each writes its own refusal tail."""
    launched = _Launched(_env(tmp_path, BROKER_GATEWAY_TRANSPORT="streamable-http", BROKER_GATEWAY_PORT="0"))
    mcp_url = launched.url()
    events_url = _events_url(tmp_path, launched.child, lambda: "".join(launched.lines))
    try:
        for _ in range(3):
            assert _post(mcp_url, b"{}", token=None)[0] == 401
            assert _post(events_url, json.dumps(REPORT).encode(), token=None)[0] == 401
    except BaseException:
        launched.kill()
        raise
    left = launched.stop()
    assert left["returncode"] == 0, left["stderr"]
    by_mouth = {
        code: [r.reason for r in _tape(tmp_path) if r.tool == MOUTH_REFUSAL_TOOL and r.op == code]
        for code in (MOUTH_CODE, EVENT_MOUTH_CODE)
    }
    expected = [
        "1 connection(s) refused before any frame was served: missing_credential=1",
        "2 connection(s) refused before any frame was served: missing_credential=2",
    ]
    assert by_mouth == {MOUTH_CODE: expected, EVENT_MOUTH_CODE: expected}
    assert left["stdout"] == ""


@pytest.mark.parametrize(
    ("drop", "words"),
    [
        pytest.param("BROKER_GATEWAY_AUTH", "BROKER_GATEWAY_AUTH is unset", id="unnamed authenticator"),
        pytest.param("BROKER_GATEWAY_TOKEN_FILE", "BROKER_GATEWAY_TOKEN_FILE is unset", id="no token file"),
    ],
)
def test_a_stdio_gateway_asked_for_the_event_mouth_refuses_to_start_unauthenticated(
    tmp_path: Path, drop: str, words: str
) -> None:
    """G13 holds for the event mouth on stdio too: no unauthenticated default."""
    env = _env(tmp_path)
    del env[drop]
    returncode, stdout, stderr = _refused(env)
    assert returncode == 1
    assert stdout == ""
    assert "[broker] refusing to start the MCP gateway:" in stderr
    assert words in stderr
    assert "store backend" not in stderr, "the runtime was built before the refusal"
    assert not (tmp_path / "events.addr").exists()
