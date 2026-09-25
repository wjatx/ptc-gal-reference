"""The gateway as a tester launches it: `python -m safe_agents.broker.gateway`, a real
child process speaking MCP over its own stdin and stdout.

`test_gateway_stdio.py` proves the handlers through the SDK's in-memory transport and
says why it stops there. This covers the part it leaves out, which is the part a
laptop exercises first: the module entry point, the environment-only configuration,
the banner kept off stdout, and the stdio plumbing on whatever operating system the
suite runs on. Windows is the reason it exists. Its pipes, its event loop and its
default text encoding all differ from the platforms this code is written on, and
this is the check that runs there.

The client is `gateway/stdio_client.py`, raw JSON-RPC lines rather than an SDK
client, and the same one the laptop demo drives, so the frames checked here are the
frames a tester's run sends.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safe_agents.broker.gateway.stdio_client import (
    GatewayClient,
    env_without_broker_config,
    result_text,
)

pytest.importorskip("mcp", reason="the gateway's stdio server needs the optional 'mcp' extra")

REPO_ROOT = Path(__file__).resolve().parents[3]

_UNDECLARED_TOOL = "payments__transfer"
_REFUSAL = "payments.transfer refused by the broker: no manifest entry for payments.transfer"


@pytest.fixture
def gateway():
    client = GatewayClient(env=env_without_broker_config(), cwd=REPO_ROOT)
    try:
        yield client
    finally:
        client.close()


def test_undeclared_tool_is_refused_by_the_broker_over_real_stdio(gateway) -> None:
    """README's first check, automated: list the tools, then ask for one the
    manifest never declared, and get the broker's refusal rather than an effect."""
    init = gateway.initialize("laptop-smoke")
    assert init["serverInfo"]["name"] == "safe-agents-broker"

    names = [tool["name"] for tool in gateway.list_tools()]
    assert names, "the gateway advertised no tools at all"
    assert _UNDECLARED_TOOL not in names

    result = gateway.call_tool(_UNDECLARED_TOOL, {"amount": "1000"})
    assert result["isError"] is True
    assert result_text(result) == _REFUSAL


def test_banner_goes_to_stderr_and_stdout_carries_only_protocol(gateway) -> None:
    """Every line the process ever wrote to stdout must parse as JSON-RPC, checked
    after exit so that output still sitting in a buffer when the handshake ended is
    counted too. The banner belongs on stderr."""
    gateway.initialize("laptop-smoke")
    gateway.close()
    stray = []
    for line in gateway.stdout_lines:
        try:
            json.loads(line.decode("utf-8"))
        except ValueError:
            stray.append(line)
    assert stray == [], f"non-protocol output on stdout: {stray!r}"
    assert "[broker] MCP gateway ready" in gateway.stderr_text
