"""sa#134 exit predicate — broker-side taint self-ingestion.

The PEP's ``_executor`` closure (safe_agents/broker/runtime/pep.py) ingests a
synthetic ``connector:<tool>.<op>`` source into the shared TurnContext
immediately after a successful EXTERNAL READ executes. Because ``connector:``
is never an ``internal:``-prefixed source, the base trust map always treats it
as untrusted, so the ingest taints the turn.

This test proves the hook works end-to-end with ZERO harness-supplied taint
hints (no ``ingested_sources``): a real ``search.query`` executes against a
monkeypatched connector, then a ``notify.send`` in the SAME threaded turn is
escalated to ``require_approval`` by PDP rule 7 (tainted_external_write) —
purely because the broker self-tainted the turn after the read, not because
anything external told it to.
"""

from __future__ import annotations

import io
import json

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
    run_threaded_turn,
)
from safe_agents.connectors import SearchConnector

CREDENTIAL = json.dumps({"provider": "tavily", "api_key": "test-key"})


class _FakeHTTPResponse:
    """Context-manager + read() — enough for ``json.load(response)``."""

    def __init__(self, payload: dict) -> None:
        self._body = io.BytesIO(json.dumps(payload).encode())

    def read(self, *args):
        return self._body.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeUrlopen:
    """Stands in for urllib.request.urlopen; records every Request it is handed."""

    def __init__(self) -> None:
        self.requests: list = []
        self.payload: dict = {"results": []}

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeHTTPResponse(self.payload)


@pytest.fixture
def fake_urlopen(monkeypatch) -> _FakeUrlopen:
    fake = _FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


class _FakeNotifyConnector:
    """Minimal stand-in for a notify connector — no real notify connector exists
    yet in this repo. In the escalated (require_approval) test this is never
    called (rule 7 fires pre-execution); the control test's untainted
    notify.send does reach allow, so the Doer needs a registered connector to
    execute against."""

    def execute(self, tool: str, op: str, args, credential: str):
        return {"tool": tool, "op": op, "sent": True}


def _make_runtime(sink: InMemorySink):
    doer = Doer(
        connectors={"search": SearchConnector(), "notify": _FakeNotifyConnector()},
        secrets=FakeSecretsProvider({"search": CREDENTIAL, "notify": "test-notify-credential"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("search.query"), make_grant("notify.send")],
        optable=CATALOG_TABLE,
        doer=doer,
        pip=make_pip(grant_present=True),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


def test_external_read_self_taints_turn_and_escalates_next_write(fake_urlopen):
    """Exit predicate: search.query (read) then notify.send (write) in one
    threaded turn, with ZERO ingested_sources — the broker's own self-ingest
    hook, not any harness-supplied taint hint, flips the write to
    require_approval."""
    fake_urlopen.payload = {
        "results": [
            {"title": "One", "url": "https://example.com/1", "content": "first", "score": 0.9},
        ],
    }
    sink = InMemorySink()
    runtime = _make_runtime(sink)

    response_1, response_2, ctx = run_threaded_turn(
        runtime,
        AgentRequest(tool="search", op="query", args={"query": "nvidia stock"}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
        ingested_sources_1=None,  # no harness taint hints — the hook is the only source
    )

    # The read executed normally.
    assert response_1.decision_kind == "allow"
    # The write was escalated purely because the read self-tainted the turn.
    assert response_2.decision_kind == "require_approval"

    assert ctx.tainted is True
    assert "connector:search.query" in ctx.to_taint().sources


def test_control_lone_notify_send_on_untainted_turn_is_allowed(fake_urlopen):
    """Control: with no prior external read, the identical notify.send on a
    fresh untainted turn is NOT escalated — isolating taint (not the grant,
    facts, or manifest) as what flips the decision above."""
    sink = InMemorySink()
    runtime = _make_runtime(sink)

    response = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    )

    assert response.decision_kind == "allow"
