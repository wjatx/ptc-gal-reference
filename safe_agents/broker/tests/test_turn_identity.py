"""sa#136 exit predicate — broker-owned turn identity across /call.

sa#134 landed broker-side taint self-ingestion, but it was inert across separate
``POST /call`` requests: each call minted a fresh TurnContext keyed to the
agent-supplied idempotency_key, so a read in call 1 never tainted a write in
call 2, and an agent could mint a fresh turn to launder taint (memory/TAINT.md
Rule 2). sa#136 makes the runtime hold ONE broker-minted TurnContext per
principal across all /call requests; the turn rolls over only via the
broker/harness-owned ``new_turn()``, never on anything the agent supplies.

The cross-/call acceptance predicates:
  1. read (call 1) then tainted write (call 2), with NO threaded turn_context —
     the write escalates to require_approval purely because the broker held the
     turn across the two calls.
  2. the agent cannot launder: distinct idempotency_keys on the two calls still
     escalate — turn identity is decoupled from idempotency_key entirely.
  3. rollover is broker-owned: new_turn() DOES clear taint (a later identical
     write is allowed again) — proving taint is not permanently stuck, but that
     only a broker-side signal, never the agent, can clear it.

Fixtures mirror test_taint_self_ingest.py (the in-turn sa#134 predicate); the
difference is these drive the taint across SEPARATE handle_request calls with no
shared context threaded by the caller.
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
    run_across_calls,
)
from safe_agents.connectors import SearchConnector

CREDENTIAL = json.dumps({"provider": "tavily", "api_key": "test-key"})
_READ_PAYLOAD = {
    "results": [
        {"title": "One", "url": "https://example.com/1", "content": "first", "score": 0.9},
    ],
}


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
    """Stands in for urllib.request.urlopen; returns a fixed search payload."""

    def __init__(self) -> None:
        self.requests: list = []
        self.payload: dict = {"results": []}

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeHTTPResponse(self.payload)


@pytest.fixture
def fake_urlopen(monkeypatch) -> _FakeUrlopen:
    fake = _FakeUrlopen()
    fake.payload = _READ_PAYLOAD
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


class _FakeNotifyConnector:
    """Minimal stand-in for a notify connector — no real one exists yet. On the
    escalated (require_approval) path it is never called (rule 7 fires
    pre-execution); on the untainted control path notify.send reaches allow, so
    the Doer needs a registered connector to execute against."""

    def execute(self, tool: str, op: str, args, credential: str):
        return {"tool": tool, "op": op, "sent": True}


def _make_runtime() -> BrokerRuntime:
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
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


def test_external_read_taints_a_later_call_write(fake_urlopen):
    """Predicate 1: search.query (read) in call 1, then notify.send (write) in
    call 2, with NO threaded turn_context — the broker holds the turn across the
    two /call requests, so the write escalates to require_approval."""
    runtime = _make_runtime()

    response_1, response_2 = run_across_calls(
        runtime,
        AgentRequest(tool="search", op="query", args={"query": "nvidia stock"}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    )

    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "require_approval"


def test_distinct_idempotency_keys_do_not_launder_taint(fake_urlopen):
    """Predicate 2: the agent's only turn-ish lever is idempotency_key. Varying it
    between the read and the write must NOT start a fresh turn — the broker owns
    the turn, so the write still escalates."""
    runtime = _make_runtime()

    response_1 = runtime.handle_request(
        AgentRequest(tool="search", op="query", args={"query": "q"}, idempotency_key="turn-A"),
    )
    response_2 = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "alert"}, idempotency_key="turn-B"),
    )

    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "require_approval"


def test_new_turn_clears_taint_and_only_the_broker_can_roll_it(fake_urlopen):
    """Predicate 3: taint is not permanently stuck — the broker/harness-owned
    new_turn() clears it, so an identical write is allowed after a roll. The agent
    has no HTTP route to new_turn, so only the trusted runtime owner can trigger
    this."""
    runtime = _make_runtime()

    # Read taints the broker-held turn; the next write escalates.
    assert runtime.handle_request(
        AgentRequest(tool="search", op="query", args={"query": "q"}),
    ).decision_kind == "allow"
    assert runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    ).decision_kind == "require_approval"

    # Broker/harness rolls the turn → accumulated taint is discarded.
    runtime.new_turn()

    # The identical write on the fresh turn is allowed again — rollover is real,
    # and it was a broker-side call (not anything the agent supplied) that did it.
    assert runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    ).decision_kind == "allow"


def test_multiple_reads_then_write_matches_automated_run(fake_urlopen):
    """Predicate 5 (realistic automated path): an unattended run that issues
    SEVERAL brokered external reads across separate /calls before a notify.send —
    a consumer agent's daily brief shape (clock/bars/quotes/news → notify). Every
    read self-taints the one broker-held turn, so the write still escalates; taint
    is monotone across N reads, not just the first. This is the cross-/call analog
    of the ~4-reads-then-write production path, and (with human_reachable) it
    escalates rather than silently allowing.
    """
    runtime = _make_runtime()

    # Four brokered external reads, each its own /call (no threaded context).
    for _ in range(4):
        r = runtime.handle_request(AgentRequest(tool="search", op="query", args={"query": "q"}))
        assert r.decision_kind == "allow"

    # The downstream external write on the same broker-held (now tainted) turn.
    write = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "daily brief"}),
    )
    assert write.decision_kind == "require_approval"


def test_control_untainted_cross_call_write_is_allowed(fake_urlopen):
    """Control: two writes across separate calls with NO prior external read stay
    on an untainted broker-held turn — isolating taint (not the shared turn
    itself) as what flips the decision in predicate 1."""
    runtime = _make_runtime()

    response_1 = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "one"}),
    )
    response_2 = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "two"}),
    )

    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "allow"
