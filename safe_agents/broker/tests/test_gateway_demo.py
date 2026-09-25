"""The laptop demo (`python -m safe_agents.broker.gateway.demo`).

Two halves. The script itself is driven in-process against a real runtime built from
the checked-in example manifest, with Tavily's HTTP endpoint faked, so the tests can
show both outcomes a tester sees: the placeholder key failing at the connector, and a
real key succeeding and tainting the turn so the following write is held for
approval. No network is touched. The subprocess half checks the entry point's
failure path: a gateway that refuses to boot gives a clear message and a non-zero
exit, never a hang.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import urllib.error
from typing import Any

import pytest

from safe_agents.broker.api import build_runtime
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.gateway import demo
from safe_agents.broker.gateway.stdio_client import BROKER_ENV_VARS
from safe_agents.broker.prototype.boot_config import load_named_manifest

_REFUSAL = "payments.transfer refused by the broker: no manifest entry for payments.transfer"


class _InProcessClient:
    """The demo's client protocol over a `GatewaySurface`, shaped like MCP results."""

    def __init__(self, surface: GatewaySurface) -> None:
        self._surface = surface

    def initialize(self, client_name: str = "test") -> dict[str, Any]:
        return {"serverInfo": {"name": self._surface.server_name}}

    def list_tools(self) -> list[dict[str, Any]]:
        return [{"name": tool.wire_name} for tool in self._surface.tools()]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self._surface.call(name, arguments)
        return {"content": [{"type": "text", "text": result.text}], "isError": not result.ok}


class _TavilyReply(io.BytesIO):
    def __enter__(self) -> _TavilyReply:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@pytest.fixture
def surface(monkeypatch: pytest.MonkeyPatch):
    for var in BROKER_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    with contextlib.redirect_stdout(io.StringIO()):
        runtime, _sink = build_runtime(load_named_manifest())
    try:
        yield GatewaySurface(runtime)
    finally:
        runtime.close()


def _run(surface: GatewaySurface) -> list[str]:
    out = io.StringIO()
    demo.run(_InProcessClient(surface), out)
    return out.getvalue().splitlines()


def test_placeholder_key_refuses_undeclared_and_fails_search_at_the_connector(
    surface, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rejected(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", rejected)
    lines = _run(surface)

    assert lines[0] == (
        "Connected to safe-agents-broker. It advertises 2 tool(s): notify__send, search__query"
    )
    assert f"   reply  {_REFUSAL}" in lines
    assert (
        "   reply  search.query was allowed by the broker but failed at the connector; "
        "the detail is on the broker's audit record"
    ) in lines
    # A failed read taints nothing, so the write is not held. Whatever its connector
    # then does, it is not an approval hold.
    notify_reply = next(line for line in lines if line.startswith("   reply  notify.send"))
    assert "held for approval" not in notify_reply


def test_a_successful_search_taints_the_turn_and_the_write_is_held(
    surface, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What README.md tells a tester with their own Tavily key to expect."""
    payload = {"results": [{"title": "t", "url": "https://example.org", "content": "c", "score": 0.5}]}
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _TavilyReply(json.dumps(payload).encode()),
    )
    lines = _run(surface)

    assert f"   reply  {_REFUSAL}" in lines
    search_at = lines.index("2. A declared read of external content")
    assert lines[search_at + 2] == "   reply  {"
    notify_reply = next(line for line in lines if line.startswith("   reply  notify.send"))
    assert notify_reply.startswith("   reply  notify.send is held for approval (intent ")
    assert notify_reply.endswith("); it has NOT executed")


def test_long_replies_are_truncated_with_a_count() -> None:
    text = "\n".join(str(n) for n in range(30))
    shown = demo._indent_reply(text).splitlines()
    assert shown[0] == "   reply  0"
    assert shown[-1] == "          ... (18 more lines)"
    assert len(shown) == 13


def test_a_gateway_that_refuses_to_boot_exits_nonzero_with_its_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("mcp", reason="the gateway's stdio server needs the optional 'mcp' extra")
    monkeypatch.setenv("BROKER_SECRETS", "not-an-arm")
    monkeypatch.setattr(sys, "argv", ["demo"])

    assert demo.main([]) == 1
    err = capsys.readouterr().err
    assert err.startswith("demo: ")
    assert "BROKER_SECRETS='not-an-arm' is not a recognized secrets arm" in err
