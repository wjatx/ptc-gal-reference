"""The gateway as a tester launches it: `python -m safe_agents.broker.gateway`, a real
child process speaking MCP over its own stdin and stdout.

`test_gateway_stdio.py` proves the handlers through the SDK's in-memory transport and
says why it stops there. This covers the part it leaves out, which is the part a
laptop exercises first: the module entry point, the environment-only configuration,
the banner kept off stdout, and the stdio plumbing on whatever operating system the
suite runs on. Windows is the reason it exists. Its pipes, its event loop and its
default text encoding all differ from the platforms this code is written on, and
this is the check that runs there.

Raw JSON-RPC lines rather than an SDK client, so the frames on the wire are the
ones README.md tells a reader to send by hand.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the gateway's stdio server needs the optional 'mcp' extra")

REPO_ROOT = Path(__file__).resolve().parents[3]

# A cold interpreter importing pydantic, the SDK and the broker takes a few seconds
# on a slow CI runner. Generous, because a timeout here reads as a hang, not a bug.
_RESPONSE_TIMEOUT_SECONDS = 60.0

_UNDECLARED_TOOL = "payments__transfer"
_REFUSAL = "payments.transfer refused by the broker: no manifest entry for payments.transfer"

_BROKER_ENV_VARS = (
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


class _Gateway:
    """One gateway child, with a reader thread so every wait is bounded.

    A blocking readline() on a pipe cannot time out portably (select() does not
    work on pipes on Windows), so stdout is drained by a thread into a queue.
    """

    def __init__(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in _BROKER_ENV_VARS}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "safe_agents.broker.gateway"],
            cwd=REPO_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._lines: queue.Queue[bytes] = queue.Queue()
        self.stdout_lines: list[bytes] = []
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        for line in self.proc.stdout:
            self.stdout_lines.append(line)
            self._lines.put(line)

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def response(self, request_id: int) -> dict:
        """The response to `request_id`, skipping notifications and other ids."""
        while True:
            try:
                line = self._lines.get(timeout=_RESPONSE_TIMEOUT_SECONDS)
            except queue.Empty:
                pytest.fail(
                    f"no response to request {request_id} within "
                    f"{_RESPONSE_TIMEOUT_SECONDS}s; gateway stderr:\n{self._stderr()}"
                )
            try:
                frame = json.loads(line.decode("utf-8"))
            except ValueError:
                pytest.fail(f"non-JSON line on the protocol's stdout: {line!r}")
            if frame.get("id") == request_id:
                return frame

    def _stderr(self) -> str:
        self.close()
        return self.proc.stderr.read().decode("utf-8", "replace")

    def close(self) -> None:
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=_RESPONSE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self._reader.join(timeout=_RESPONSE_TIMEOUT_SECONDS)


@pytest.fixture
def gateway():
    gw = _Gateway()
    try:
        yield gw
    finally:
        gw.close()
        gw.proc.stdout.close()
        gw.proc.stderr.close()


def _initialize(gw: _Gateway) -> dict:
    gw.send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "laptop-smoke", "version": "0"},
        },
    })
    result = gw.response(1)
    gw.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return result


def test_undeclared_tool_is_refused_by_the_broker_over_real_stdio(gateway) -> None:
    """README's by-hand check, automated: list the tools, then ask for one the
    manifest never declared, and get the broker's refusal rather than an effect."""
    init = _initialize(gateway)
    assert init["result"]["serverInfo"]["name"] == "safe-agents-broker"

    gateway.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [tool["name"] for tool in gateway.response(2)["result"]["tools"]]
    assert names, "the gateway advertised no tools at all"
    assert _UNDECLARED_TOOL not in names

    gateway.send({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": _UNDECLARED_TOOL, "arguments": {"amount": "1000"}},
    })
    result = gateway.response(3)["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"] == _REFUSAL


def test_banner_goes_to_stderr_and_stdout_carries_only_protocol(gateway) -> None:
    """Every line the process ever wrote to stdout must parse as JSON-RPC, checked
    after exit so that output still sitting in a buffer when the handshake ended is
    counted too. The banner belongs on stderr."""
    _initialize(gateway)
    gateway.close()
    stray = []
    for line in gateway.stdout_lines:
        try:
            json.loads(line.decode("utf-8"))
        except ValueError:
            stray.append(line)
    assert stray == [], f"non-protocol output on stdout: {stray!r}"
    stderr = gateway.proc.stderr.read().decode("utf-8", "replace")
    assert "[broker] MCP gateway ready" in stderr
