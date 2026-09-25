"""Tests for approval-queue de-amplification (sa#160 sub-item).

Four concerns:
  1. The `ApprovalQueue` Envelope knob validates/rejects and is hash-bound.
  2. The pure guard (`dedup_intent_id`, `is_flood`) is deterministic — same
     inputs -> same id, distinct content -> distinct id, no polarity anywhere.
  3. `materialize(dedup_id=...)` coalesces an identical PENDING intent (no second
     hold/notify) but does NOT coalesce onto a resolved one.
  4. End-to-end at the PEP require_approval chokepoint: dedup coalesces identical
     re-submissions (one page, not N); the flood cap raises an alarm but NEVER
     sheds (the intent is still held); and the OFF default is byte-identical.
"""
from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError

from safe_agents.broker.approval import InMemoryIntentStore, materialize
from safe_agents.broker.approval.queue_guard import dedup_intent_id, is_flood
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.schemas import BrokeredCall, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.decision import RenderedIntent, RequireApproval
from safe_agents.broker.schemas.envelope import (
    ApprovalQueue,
    Envelope,
    compute_envelope_hash,
)
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    PRINCIPAL_DATA,
    make_grant,
    make_pip,
)

_OTHER_PRINCIPAL = Principal(agentId="a2", skill="s", user="u", tier="A")


# ---------------------------------------------------------------------------
# 1. The ApprovalQueue knob
# ---------------------------------------------------------------------------

def test_approval_queue_validates() -> None:
    aq = ApprovalQueue.model_validate({"dedup": True, "max_pending_per_op_day": 5})
    assert aq.dedup is True
    assert aq.max_pending_per_op_day == 5


def test_approval_queue_defaults_are_off() -> None:
    aq = ApprovalQueue()
    assert aq.dedup is False
    assert aq.max_pending_per_op_day is None


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"max_pending_per_op_day": 0}, id="zero_cap"),
        pytest.param({"max_pending_per_op_day": -1}, id="negative_cap"),
        pytest.param({"unknown": 1}, id="extra_forbidden"),
    ],
)
def test_approval_queue_rejects_invalid(bad: dict) -> None:
    with pytest.raises(ValidationError):
        ApprovalQueue.model_validate(bad)


def test_envelope_approval_queue_unset_is_off() -> None:
    for polarity in ("act", "abstain"):
        env = Envelope.model_validate({"polarity": polarity})
        assert env.approval_queue is None


def test_approval_queue_is_hash_bound() -> None:
    base = Envelope.model_validate({"polarity": "act"})
    tuned = Envelope.model_validate(
        {"polarity": "act", "approval_queue": {"dedup": True, "max_pending_per_op_day": 3}}
    )
    assert compute_envelope_hash(base) != compute_envelope_hash(tuned)


# ---------------------------------------------------------------------------
# 2. The pure guard
# ---------------------------------------------------------------------------

def test_dedup_id_is_deterministic() -> None:
    a = dedup_intent_id(PRINCIPAL, "notify", "send", "digest-1")
    b = dedup_intent_id(PRINCIPAL, "notify", "send", "digest-1")
    assert a == b
    assert a.startswith("intent-dedup-")


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(("notify", "send", "digest-2"), id="different_args"),
        pytest.param(("notify", "publish", "digest-1"), id="different_op"),
        pytest.param(("search", "send", "digest-1"), id="different_tool"),
    ],
)
def test_dedup_id_distinguishes_content(mutate) -> None:
    base = dedup_intent_id(PRINCIPAL, "notify", "send", "digest-1")
    assert dedup_intent_id(PRINCIPAL, *mutate) != base


def test_dedup_id_is_per_principal() -> None:
    a = dedup_intent_id(PRINCIPAL, "notify", "send", "d")
    b = dedup_intent_id(_OTHER_PRINCIPAL, "notify", "send", "d")
    assert a != b


def test_is_flood_is_negation_of_within_cap() -> None:
    assert is_flood(within_cap=False) is True
    assert is_flood(within_cap=True) is False


# ---------------------------------------------------------------------------
# 3. materialize() coalescing (unit)
# ---------------------------------------------------------------------------

def _brokered_call() -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": PRINCIPAL_DATA,
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 100, "to": "acct-xyz"},
            "manifest": {
                "tool": "payments",
                "op": "transfer",
                "effect": "write",
                "external": True,
                "reversible": False,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-1", "ingestedSources": []},
            "ts": "2026-07-09T00:00:00Z",
        }
    )


def _decision() -> RequireApproval:
    return RequireApproval(
        kind="require_approval",
        renderedIntent=RenderedIntent(id="intent-ts-based", renderedForHuman="transfer 100"),
    )


def test_materialize_coalesces_identical_pending() -> None:
    store = InMemoryIntentStore()
    ddid = "intent-dedup-abc"

    first = materialize(_brokered_call(), _decision(), store, dedup_id=ddid)
    assert first.status == "pending"
    assert first.intent_id == ddid

    notified: list = []
    second = materialize(
        _brokered_call(), _decision(), store, notifier=notified.append, dedup_id=ddid
    )
    assert second.status == "coalesced"
    assert second.intent_id == ddid
    assert notified == []  # de-amplified: no second notification fired


def test_materialize_does_not_coalesce_onto_resolved() -> None:
    store = InMemoryIntentStore()
    ddid = "intent-dedup-def"
    materialize(_brokered_call(), _decision(), store, dedup_id=ddid)
    store.transition_status(ddid, "pending", "approved", approved_by="human")

    again = materialize(_brokered_call(), _decision(), store, dedup_id=ddid)
    assert again.status == "pending"  # a resolved duplicate does not block a fresh hold


def test_materialize_without_dedup_id_is_unchanged() -> None:
    store = InMemoryIntentStore()
    res = materialize(_brokered_call(), _decision(), store)
    assert res.status == "pending"
    assert res.intent_id == "intent-ts-based"  # the PDP ts-based id, as before


# ---------------------------------------------------------------------------
# 4. End-to-end at the PEP chokepoint
# ---------------------------------------------------------------------------

def _runtime(approval_queue: ApprovalQueue | None):
    """A runtime granted payments.transfer (external + irreversible -> always
    require_approval), so every /call exercises the hold path."""
    grants = [make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    intent_store = InMemoryIntentStore()
    doer = Doer(
        connectors={"payments": StubConnector()},
        secrets=FakeSecretsProvider({"payments": "cred-payments"}),
    )
    runtime = BrokerRuntime(
        principal=PRINCIPAL,
        grants=grants,
        optable=ToolOpTable(
            [ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False)]
        ),
        doer=doer,
        pip=make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        enforcement_store=InMemoryStore(),
        intent_store=intent_store,
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        approval_queue=approval_queue,
    )
    return runtime, intent_store


def _req(idem: str, to: str) -> AgentRequest:
    return AgentRequest(
        tool="payments",
        op="transfer",
        args={"amount": 100, "to": to},
        idempotency_key=idem,
    )


def test_pep_dedup_coalesces_identical_resubmissions() -> None:
    runtime, intent_store = _runtime(ApprovalQueue(dedup=True))
    # Identical args, distinct idempotency keys (so the idempotency layer does not
    # short-circuit first) — content dedup must still collapse them onto one page.
    r1 = runtime.handle_request(_req("k1", "acct-same"))
    r2 = runtime.handle_request(_req("k2", "acct-same"))
    assert r1.decision_kind == "require_approval"
    assert r1.intent_id == r2.intent_id
    assert intent_store.get_intent(r1.intent_id) is not None


def test_pep_dedup_keeps_distinct_intents_separate() -> None:
    runtime, _ = _runtime(ApprovalQueue(dedup=True))
    r1 = runtime.handle_request(_req("k1", "acct-a"))
    r2 = runtime.handle_request(_req("k2", "acct-b"))
    assert r1.intent_id != r2.intent_id  # distinct content -> distinct page


def test_pep_flood_alarms_but_never_sheds(caplog) -> None:
    runtime, intent_store = _runtime(ApprovalQueue(max_pending_per_op_day=1))
    with caplog.at_level(logging.ERROR):
        r1 = runtime.handle_request(_req("k1", "acct-a"))
        r2 = runtime.handle_request(_req("k2", "acct-b"))  # exceeds cap of 1
    # Both STILL held — the flood cap never denies/sheds.
    assert r1.decision_kind == "require_approval"
    assert r2.decision_kind == "require_approval"
    assert intent_store.get_intent(r1.intent_id) is not None
    assert intent_store.get_intent(r2.intent_id) is not None
    events = [
        json.loads(rec.message).get("event")
        for rec in caplog.records
        if rec.message.startswith("{")
    ]
    assert events.count("approval_queue_flood") == 1


def test_pep_off_default_holds_without_alarm(caplog) -> None:
    runtime, _ = _runtime(None)  # knob unset = OFF
    with caplog.at_level(logging.ERROR):
        r1 = runtime.handle_request(_req("k1", "acct-a"))
        r2 = runtime.handle_request(_req("k2", "acct-a"))  # identical args
    # Unset dedup: identical calls produce DISTINCT ts-based intents (old behavior).
    assert r1.intent_id != r2.intent_id
    assert not any("approval_queue_flood" in rec.message for rec in caplog.records)
