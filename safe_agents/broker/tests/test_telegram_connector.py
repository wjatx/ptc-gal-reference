"""Broker integration test for TelegramConnector — a consumer agent's notify.send grant (A3).

Two round-trips against the REAL Telegram Bot API:

  1. Untainted: agent request -> registry -> taint(clean) -> decide(allow) -> enforce
     -> doer executes TelegramConnector with a broker-injected credential -> a REAL
     message lands in the owner's chat -> AuditRecord emitted.
  2. Tainted: the same call, but the turn ingested an untrusted source first (e.g. web
     research shaped the message) -> decide(require_approval) -> the connector is
     NEVER called -> no message sent, Intent materialized instead.

Requires NOTIFY_TELEGRAM_BOT_TOKEN / NOTIFY_TELEGRAM_CHAT_ID in the environment
(the consumer agent's .env); skipped when absent so CI stays green without cross-repo
credentials. Run locally with:

    set -a && source ~/Code/example-agent/.env && set +a
    broker/.venv/bin/pytest broker/tests/test_telegram_connector.py -v
"""

from __future__ import annotations

import json
import os

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink, verify_chain
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.connectors import TelegramConnector
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, PRINCIPAL, make_grant, make_pip

pytestmark = pytest.mark.skipif(
    not (os.environ.get("NOTIFY_TELEGRAM_BOT_TOKEN") and os.environ.get("NOTIFY_TELEGRAM_CHAT_ID")),
    reason="NOTIFY_TELEGRAM_BOT_TOKEN/NOTIFY_TELEGRAM_CHAT_ID not set — source example-agent/.env to run live",
)


def _make_runtime(sink: InMemorySink, connector: TelegramConnector) -> BrokerRuntime:
    credential = json.dumps({
        "bot_token": os.environ["NOTIFY_TELEGRAM_BOT_TOKEN"],
        "chat_id": os.environ["NOTIFY_TELEGRAM_CHAT_ID"],
    })
    doer = Doer(connectors={"notify": connector}, secrets=FakeSecretsProvider({"notify": credential}))
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("notify.send", ts="2026-06-28T00:00:00Z")],
        optable=CATALOG_TABLE,
        doer=doer,
        pip=make_pip(),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


def test_notify_send_round_trip():
    """Full integration: untainted registry -> decide(allow) -> doer sends a REAL
    Telegram message via the live Bot API -> audit."""
    sink = InMemorySink()
    connector = TelegramConnector()
    runtime = _make_runtime(sink, connector)

    registry = runtime.served_registry()
    assert len(registry) == 1
    assert registry[0].tool == "notify"
    assert registry[0].op == "send"

    request = AgentRequest(
        tool="notify",
        op="send",
        args={"text": "safe-agents A3: broker integration test — ignore this message."},
        idempotency_key="test:notify-send-1",
    )
    response = runtime.handle_request(request)

    assert response.decision_kind == "allow"
    assert response.intent_id is None
    assert response.reason is None
    assert "message_id" in response.result

    records = sink.records()
    assert len(records) == 1
    assert records[0].tool == "notify"
    assert records[0].op == "send"
    assert records[0].decision == "allow"
    assert records[0].outcome == "executed"
    verify_chain(records)


def test_notify_send_tainted_requires_approval():
    """A turn that ingested an untrusted source (e.g. web research) cannot autonomously
    send — rule 7 (tainted_external_write) freezes an Intent; the connector is NEVER
    called, so no message is sent."""
    sink = InMemorySink()
    connector = TelegramConnector()
    runtime = _make_runtime(sink, connector)

    request = AgentRequest(
        tool="notify",
        op="send",
        args={"text": "a message shaped by untrusted web content"},
        idempotency_key="test:notify-send-tainted-1",
    )
    response = runtime.handle_request(request, ingested_sources=["web_research:some-query"])

    assert response.decision_kind == "require_approval"
    assert response.intent_id is not None
    assert response.result is None

    records = sink.records()
    assert len(records) == 1
    assert records[0].decision == "require_approval"
    assert records[0].outcome == "held"
    verify_chain(records)


def test_telegram_connector_rejects_non_send_op():
    """Structural guard: the connector itself has no path but 'send'."""
    credential = json.dumps({
        "bot_token": os.environ["NOTIFY_TELEGRAM_BOT_TOKEN"],
        "chat_id": os.environ["NOTIFY_TELEGRAM_CHAT_ID"],
    })
    with pytest.raises(ValueError, match="'send'"):
        TelegramConnector().execute("notify", "broadcast", {"text": "x"}, credential)


def test_telegram_connector_parse_mode_none_sends_plain_text():
    """parse_mode='none' — a caller-supplied arg, safe because it only affects
    rendering, never the destination — sends real unbalanced-Markdown text that
    would otherwise be rejected by Telegram with a 400."""
    credential = json.dumps({
        "bot_token": os.environ["NOTIFY_TELEGRAM_BOT_TOKEN"],
        "chat_id": os.environ["NOTIFY_TELEGRAM_CHAT_ID"],
    })
    result = TelegramConnector().execute(
        "notify", "send",
        {"text": "safe-agents A4 test: unbalanced *markdown [ignore this", "parse_mode": "none"},
        credential,
    )
    assert "message_id" in result
