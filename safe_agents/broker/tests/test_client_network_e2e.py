"""The network gateway client against the real network MCP mouth.

`test_client_network.py` checks the client against a scripted server. This is
the other half: the published client, the launch token, and the object
`python -m safe_agents.broker.gateway` serves, bound to an ephemeral loopback
port. What is asserted is what a consumer sees, an allowed call, a refused one
and a held one, and that each is the BROKER's answer carried through unchanged.

The server is `test_gateway_network_e2e.py`'s: it runs on a thread of its own and
builds its runtime there. Both ends are the same operating-system user on one
machine. No boundary sits between them, so nothing here says anything about a
sandbox.
"""

from __future__ import annotations

import contextlib
import io
import json
import threading
import time

import pytest

from safe_agents.broker.client import GatewayClientError, NetworkGatewayClient, result_text
from safe_agents.broker.tests.test_gateway_authn import OTHER, TOKEN
from safe_agents.broker.tests.test_gateway_network import _BROKER_ENV
from safe_agents.broker.tests.test_gateway_network_e2e import (  # skips without the `mcp` extra
    _mouth_records,
    _real_surface,
    _Served,
)

from safe_agents.broker.api import build_runtime  # noqa: E402
from safe_agents.broker.gateway import GatewaySurface  # noqa: E402
from safe_agents.broker.gateway import demo  # noqa: E402
from safe_agents.broker.prototype.boot_config import load_named_manifest  # noqa: E402

_UNDECLARED_REFUSAL = "payments.transfer refused by the broker: no manifest entry for payments.transfer"


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def mouth(clean_env):
    """The embedded example: `search.query` granted, `notify.send` declared and not granted."""
    served = _Served(_real_surface)
    try:
        yield served
    finally:
        served.stop()


def _named_surface(served: _Served) -> GatewaySurface:
    """The checked-in default manifest, the one the laptop demo runs against."""
    with contextlib.redirect_stdout(io.StringIO()):
        runtime, sink = build_runtime(load_named_manifest())
    served.runtime, served.sink = runtime, sink
    return GatewaySurface(runtime)


class _SearchReply(io.BytesIO):
    def __enter__(self) -> _SearchReply:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@pytest.fixture
def demo_mouth(clean_env, monkeypatch: pytest.MonkeyPatch):
    """The default manifest, with the search provider answering.

    Only the broker's own outbound search is replaced. The client under test
    does not go through `urllib.request`, so its requests are untouched.
    """
    payload = {"results": [{"title": "t", "url": "https://example.org", "content": "c", "score": 0.5}]}
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _SearchReply(json.dumps(payload).encode()),
    )
    served = _Served(_named_surface)
    try:
        yield served
    finally:
        served.stop()


class TestAskingTheRealMouth:
    def test_the_handshake_the_listing_and_an_allowed_call(self, mouth) -> None:
        with NetworkGatewayClient(mouth.url, token=TOKEN, timeout=30) as gateway:
            hello = gateway.initialize()
            assert hello["serverInfo"]["name"] == "safe-agents-broker"
            assert gateway.session_id
            assert [tool["name"] for tool in gateway.list_tools()] == ["search__query"]
            result = gateway.call_tool("search__query", {"query": "broker"})
        assert result["isError"] is False
        assert "The agent holds no connector credentials" in result_text(result)
        # The call reached the runtime once, as the runtime's own principal.
        (request,) = mouth.requests
        assert (request.tool, request.op) == ("search", "query")
        last = mouth.sink.records()[-1]
        assert (last.tool, last.op, last.decision) == ("search", "query", "allow")

    def test_a_refused_call_carries_the_brokers_reason(self, mouth) -> None:
        with NetworkGatewayClient(mouth.url, token=TOKEN, timeout=30) as gateway:
            gateway.initialize()
            not_granted = gateway.call_tool("notify__send", {"text": "shipping it"})
            undeclared = gateway.call_tool("payments__transfer", {"amount": "1000"})
        # A refusal is a result, not an exception, and its text is the broker's.
        assert not_granted["isError"] is True
        assert "tool not granted to this principal" in result_text(not_granted)
        assert undeclared["isError"] is True
        assert result_text(undeclared) == _UNDECLARED_REFUSAL
        denied = [(r.tool, r.op, r.decision, r.outcome) for r in mouth.sink.records()[-2:]]
        assert denied == [("notify", "send", "deny", "denied"), ("payments", "transfer", "deny", "denied")]

    def test_a_held_call_comes_back_held_and_not_executed(self, demo_mouth) -> None:
        """A successful external read taints the turn, so the write that follows
        is held for approval. The turn is the runtime's, so it holds across two
        separate HTTP exchanges from this client."""
        with NetworkGatewayClient(demo_mouth.url, token=TOKEN, timeout=30) as gateway:
            gateway.initialize()
            assert gateway.call_tool("search__query", {"query": "broker"})["isError"] is False
            held = gateway.call_tool("notify__send", {"text": "what I found"})
        assert held["isError"] is True
        text = result_text(held)
        assert text.startswith("notify.send is held for approval (intent ")
        assert text.endswith("); it has NOT executed")
        last = demo_mouth.sink.records()[-1]
        assert (last.tool, last.op, last.decision) == ("notify", "send", "require_approval")

    @pytest.mark.parametrize(
        "write_arguments",
        [
            pytest.param({"text": "what I found"}, id="a new session"),
            pytest.param(
                {"text": "what I found", "turn_id": "fresh", "new_turn": True},
                id="a new session that also asks for a new turn",
            ),
        ],
    )
    def test_taint_from_one_session_holds_a_write_on_the_next(
        self, demo_mouth, write_arguments
    ) -> None:
        """The turn is the runtime's and not a session's (`docs/turn-identity.md`).

        One client reads external content and closes. A second client, with a
        session id of its own, asks for the write. It is held exactly as it is
        within one session. A mouth that started a turn per session, or let an
        argument name one, would let an agent shed taint by reconnecting, and
        that fails open. Both clients hold the same token: there is one agent.
        """
        with NetworkGatewayClient(demo_mouth.url, token=TOKEN, timeout=30) as reader:
            reader.initialize()
            assert reader.call_tool("search__query", {"query": "broker"})["isError"] is False
            first_session = reader.session_id
        with NetworkGatewayClient(demo_mouth.url, token=TOKEN, timeout=30) as writer:
            writer.initialize()
            assert writer.session_id and writer.session_id != first_session
            held = writer.call_tool("notify__send", write_arguments)
        assert held["isError"] is True
        assert result_text(held).startswith("notify.send is held for approval (intent ")
        last = demo_mouth.sink.records()[-1]
        assert (last.tool, last.op, last.decision) == ("notify", "send", "require_approval")

    def test_the_laptop_demo_runs_over_the_network_as_it_does_over_stdio(self, demo_mouth) -> None:
        """One script, either client: the two are interchangeable to a caller."""
        out = io.StringIO()
        with NetworkGatewayClient(demo_mouth.url, token=TOKEN, timeout=30) as gateway:
            demo.run(gateway, out)
        lines = out.getvalue().splitlines()
        assert lines[0] == (
            "Connected to safe-agents-broker. It advertises 2 tool(s): notify__send, search__query"
        )
        assert f"   reply  {_UNDECLARED_REFUSAL}" in lines
        held = next(line for line in lines if line.startswith("   reply  notify.send"))
        assert held.startswith("   reply  notify.send is held for approval (intent ")


class TestTheWrongToken:
    def test_nothing_is_served_and_the_runtime_is_never_reached(self, mouth) -> None:
        gateway = NetworkGatewayClient(mouth.url, token=OTHER, timeout=30)
        with pytest.raises(GatewayClientError) as raised:
            gateway.initialize()
        assert "HTTP 401" in str(raised.value)
        assert OTHER not in str(raised.value)
        assert gateway.session_id is None
        for call in (gateway.list_tools, lambda: gateway.call_tool("search__query", {"query": "x"})):
            with pytest.raises(GatewayClientError, match="HTTP 401"):
                call()
        assert mouth.requests == [] and mouth.listings == 0
        # The mouth recorded that it refused; the client put nothing else on the tape.
        (record,) = _mouth_records(mouth)
        assert "wrong_token" in record.reason
        assert [r.tool for r in mouth.sink.records()] == [record.tool]

    def test_a_session_opened_with_the_token_is_no_use_without_it(self, mouth) -> None:
        """The client sends the token on every request because the mouth checks
        it on every request: a session id is not a credential."""
        with NetworkGatewayClient(mouth.url, token=TOKEN, timeout=30) as gateway:
            gateway.initialize()
            thief = NetworkGatewayClient(mouth.url, token=OTHER, timeout=30)
            thief._session_id = gateway.session_id
            thief._protocol_version = gateway._protocol_version
            with pytest.raises(GatewayClientError, match="HTTP 401"):
                thief.call_tool("search__query", {"query": "x"})
        assert mouth.requests == []


class _BlockingSurface:
    """A surface whose calls wait until released, so a call can be caught in flight."""

    server_name = "blocking"

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def tools(self):
        return []

    def call(self, wire_name, arguments=None):
        from safe_agents.broker.gateway.surface import GatewayResult  # noqa: PLC0415

        self.calls += 1
        self.entered.set()
        self.release.wait(30)
        return GatewayResult(ok=True, text="late", decision_kind="allow")


class TestTheServerGoesQuietOrGoesAway:
    def test_a_call_the_mouth_does_not_answer_is_given_up_on_at_the_deadline(self, clean_env) -> None:
        surface = _BlockingSurface()
        served = _Served(lambda _served: surface)
        try:
            gateway = NetworkGatewayClient(served.url, token=TOKEN, timeout=1.5)
            gateway.initialize()
            started = time.monotonic()
            with pytest.raises(GatewayClientError) as raised:
                gateway.call_tool("search__query", {"query": "x"})
            elapsed = time.monotonic() - started
            assert 1.2 <= elapsed < 6
            assert "no reply to 'tools/call' within 1.5s" in str(raised.value)
            # The honest half of a timeout: the call DID reach the surface. The
            # client gave up waiting, and says it cannot tell.
            assert surface.entered.is_set()
            assert "does not say whether it was made" in str(raised.value)
            assert surface.calls == 1, "a timed-out call must not be retried"
        finally:
            surface.release.set()
            served.stop()

    def test_a_mouth_that_has_stopped_is_reported_and_not_waited_for(self, clean_env) -> None:
        served = _Served(_real_surface)
        gateway = NetworkGatewayClient(served.url, token=TOKEN, timeout=30)
        gateway.initialize()
        served.stop()
        started = time.monotonic()
        with pytest.raises(GatewayClientError, match="could not be reached"):
            gateway.call_tool("search__query", {"query": "x"})
        gateway.close()
        assert time.monotonic() - started < 6
