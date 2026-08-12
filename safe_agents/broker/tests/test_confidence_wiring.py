"""Wiring tests for the #184 calibrated-uncertainty slice (W1–W10).

The evidence CONTRACT (the artifact, meets_bar, the blast derivation, the error draw,
the demotion signal) is unit-tested in test_evidence_contract.py (E1–E10). THIS suite
proves the WIRING: a constructed-confidence artifact riding a real BrokeredCall through
the live PEP → PIP → PDP → enforce round-trip actually gates, meters, and signals —
and, load-bearing, that an unset knob is a byte-identical no-op (W1).

Harness style follows test_runtime.py (build a BrokerRuntime with fakes), but the PIP
is the REAL broker_server._make_pip so the below-bar fact (via meets_bar) and the
cumulative error-budget-breach fact (read from the metered counter) are the production
wiring, not a stand-in.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.schemas import (
    BrokeredCall,
    ConfidenceArtifact,
    Confidence,
    DemotionSignal,
    DemotionTrigger,
    Grant,
    ToolOp,
)
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map

# The grant's envelopeHash and the PIP's in_force_hash are compared for equality; a
# single shared constant keeps every seeded grant in-force (no quarantine noise).
_ENVELOPE_HASH = "conf-wiring-test-envelope-hash"
_HMAC_KEY = b"conf-wiring-test-hmac-key"

_PRINCIPAL_DATA = {"agentId": "agent-conf", "skill": "general", "user": "alice", "tier": "B"}
_PRINCIPAL = Principal(**_PRINCIPAL_DATA)

# Ops used across the suite. The internal write is a MEDIUM-blast decision (not a read,
# not an external-irreversible write), so its error draw is error_prob × weights["medium"].
_WRITE = ToolOp(tool="ledger", op="post", effect="write", external=False, reversible=True)
_READ = ToolOp(tool="ledger", op="fetch", effect="read", external=False)


def _artifact(
    *, confidence: float = 0.9, error_prob: float = 0.1, stale: bool = False
) -> ConfidenceArtifact:
    """A valid self-consistency artifact for the wired path."""
    return ConfidenceArtifact(
        confidence=confidence,
        error_prob=error_prob,
        evidence={"method": "self-consistency", "samples": 5, "agreement": confidence},
        stale=stale,
        computed_at="2026-07-12T00:00:00Z",
    )


def _make_grant(action_class: str, level: AutonomyLevel) -> Grant:
    return Grant.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": level,
            "envelopeHash": _ENVELOPE_HASH,
            "promotedBy": "human-reviewer",
            "evidence": "test-evidence-ref",
            "ts": "2026-06-28T00:00:00Z",
            "lastSafeLevel": "in-loop",
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "test-owner",
        }
    )


def _build(
    *,
    knob: Confidence | None,
    ops: list[ToolOp],
    granted: list[str],
    level: AutonomyLevel = AutonomyLevel.on_loop,
    on_demotion_signal=None,
    connectors: dict[str, StubConnector] | None = None,
) -> tuple[BrokerRuntime, InMemorySink, InMemoryStore, dict[str, StubConnector]]:
    """Build a runtime wired with the REAL broker_server PIP + fakes."""
    grant_store = InMemoryGrantStore(hmac_key=_HMAC_KEY)
    grants: list[Grant] = []
    for action_class in granted:
        grant_store.put_grant(_make_grant(action_class, level))
        grants.append(grant_store.get_grant(_PRINCIPAL, action_class).grant)

    store = InMemoryStore()
    sink = InMemorySink()
    connectors = connectors or {"ledger": StubConnector(result={"ok": True})}
    doer = Doer(
        connectors=connectors, secrets=FakeSecretsProvider({"ledger": "cred-ledger"})
    )
    pip = broker_server._make_pip(
        grant_store, store, 100.0, _ENVELOPE_HASH, confidence_knob=knob
    )
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=grants,
        optable=ToolOpTable(ops),
        doer=doer,
        pip=pip,
        enforcement_store=store,
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=_ENVELOPE_HASH,
        counter_cap=100.0,
        confidence_knob=knob,
        on_demotion_signal=on_demotion_signal,
    )
    return runtime, sink, store, connectors


def _error_budget_key(tool: str, op: str) -> str:
    return scoped_counter_key(_PRINCIPAL, tool, op, "error_budget")


# ---------------------------------------------------------------------------
# W1 — knob OFF is a byte-identical no-op: artifact accepted-but-ignored, a write
# executes exactly as before, and no "error_budget" counter is ever written.
# ---------------------------------------------------------------------------


def test_w1_knob_off_invariance():
    runtime, sink, store, connectors = _build(
        knob=None, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(
        AgentRequest(
            tool="ledger",
            op="post",
            args={"x": 1},
            confidence=_artifact(confidence=0.01),  # would be below any bar — ignored
        )
    )
    assert resp.decision_kind == "allow"
    assert resp.result == {"ok": True}
    assert len(connectors["ledger"].calls) == 1
    # No error_budget counter key exists anywhere (the OFF-invariance grep-proof).
    assert not any(k.endswith(":error_budget") for k in store._counters)
    assert sink.records()[-1].decision == "allow"


# ---------------------------------------------------------------------------
# W2 — below-bar → abstain; the artifact rides the audit tape; executor not called.
# ---------------------------------------------------------------------------


def test_w2_below_bar_abstains_and_audits_artifact():
    knob = Confidence(min_confidence=0.7)
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(
        AgentRequest(
            tool="ledger", op="post", args={"x": 1}, confidence=_artifact(confidence=0.4)
        )
    )
    assert resp.decision_kind == "abstain"
    # Executor never ran.
    assert len(connectors["ledger"].calls) == 0
    # The last audit record is the abstain, and its reason carries the artifact.
    last = sink.records()[-1]
    assert last.decision == "abstain"
    assert "confidence artifact: method=" in last.reason
    assert "method=self-consistency" in last.reason


# ---------------------------------------------------------------------------
# W3 — below-bar + escalation exhausted → deny. A decide()-level truth table over
# the rule pair (write-scoped): escalate available → abstain, exhausted → deny, and
# a READ with the same fact is never gated by the pair.
# ---------------------------------------------------------------------------


def _call(op: ToolOp) -> BrokeredCall:
    return BrokeredCall(
        principal=_PRINCIPAL,
        tool=op.tool,
        op=op.op,
        args={},
        manifest=op,
        taint={"tainted": False, "sources": []},
        session={"turnId": "turn-w3", "ingestedSources": []},
        ts="2026-07-12T00:00:00Z",
    )


def _facts(*, escalation: bool, below_bar: bool, effect_read: bool = False) -> Facts:
    return Facts(
        grant_present=True,
        grant_level=AutonomyLevel.on_loop,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=escalation,
        human_reachable=True,
        confidence_below_bar=below_bar,
    )


def test_w3_below_bar_rule_pair_truth_table():
    # Write, below-bar, escalation available → abstain (rule 4).
    d = decide(_call(_WRITE), _facts(escalation=True, below_bar=True))
    assert d.kind == "abstain"
    assert d.escalate is True
    assert "below bar" in d.reason

    # Write, below-bar, escalation exhausted → deny (rule 5).
    d = decide(_call(_WRITE), _facts(escalation=False, below_bar=True))
    assert d.kind == "deny"
    assert "escalation budget exhausted" in d.reason

    # A READ carrying confidence_below_bar is NOT gated by the write-scoped pair.
    d = decide(_call(_READ), _facts(escalation=False, below_bar=True))
    assert d.kind == "allow"


# ---------------------------------------------------------------------------
# W4 — a missing artifact: below-bar when a bar is set (abstain); when NO bar but a
# budget is set, the write executes AND draws error_prob=1.0 × weight.
# ---------------------------------------------------------------------------


def test_w4_missing_artifact_below_bar_when_bar_set():
    knob = Confidence(min_confidence=0.7)
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 1}))
    assert resp.decision_kind == "abstain"
    assert len(connectors["ledger"].calls) == 0


def test_w4_missing_artifact_draws_worst_case_with_budget_no_bar():
    knob = Confidence(
        error_budget_tolerance=10.0,
        blast_weights={"low": 1.0, "medium": 2.0, "high": 4.0},
    )
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 1}))
    assert resp.decision_kind == "allow"
    # Missing artifact ⇒ error_prob 1.0 × medium weight 2.0 = 2.0 drawn.
    assert store.read_counter(_error_budget_key("ledger", "post")) == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# W5 — at/above bar → executes; the draw is exactly error_prob × blast_weight.
# ---------------------------------------------------------------------------


def test_w5_above_bar_executes_and_draws_exact():
    knob = Confidence(
        min_confidence=0.5,
        error_budget_tolerance=10.0,
        blast_weights={"low": 1.0, "medium": 2.0, "high": 4.0},
    )
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(
        AgentRequest(
            tool="ledger",
            op="post",
            args={"x": 1},
            confidence=_artifact(confidence=0.9, error_prob=0.1),
        )
    )
    assert resp.decision_kind == "allow"
    assert len(connectors["ledger"].calls) == 1
    # error_prob 0.1 × medium weight 2.0 = 0.2.
    assert store.read_counter(_error_budget_key("ledger", "post")) == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# W6 — crossing the tolerance emits the signal (log + injected callback), and the
# NEXT write is gated by the now-real error-budget rule (PIP reads the counter).
# ---------------------------------------------------------------------------


def test_w6_crossing_tolerance_emits_signal_and_gates_next(caplog):
    received: list[DemotionSignal] = []
    knob = Confidence(
        error_budget_tolerance=0.3,
        blast_weights={"low": 0.2, "medium": 0.2, "high": 0.2},
    )
    runtime, sink, store, connectors = _build(
        knob=knob,
        ops=[_WRITE],
        granted=["ledger.post"],
        on_demotion_signal=received.append,
    )

    # Each write draws 1.0 (missing artifact) × 0.2 = 0.2.
    with caplog.at_level("ERROR"):
        first = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 1}))
        second = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 2}))

    assert first.decision_kind == "allow"  # spent 0.2, under tolerance
    assert second.decision_kind == "allow"  # spent 0.4 — the crossing draw

    # Exactly one signal, on the crossing (second) draw.
    assert len(received) == 1
    sig = received[0]
    assert sig.trigger == DemotionTrigger.budget_breach
    assert sig.action_class == "ledger.post"
    assert sig.period == datetime.datetime.now(datetime.UTC).strftime("%Y%m%d")
    # The structured PII-safe log-metric line fired.
    assert any("demotion_signal" in rec.message for rec in caplog.records)

    # The NEXT write: the PIP reads spent 0.4 >= 0.3 → error_budget_breached → the PDP
    # escalates (rule 2, now real). Executor not called.
    third = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 3}))
    assert third.decision_kind == "abstain"


# ---------------------------------------------------------------------------
# W7 — an invalid artifact dict is a loud deny, not a silent "no artifact".
# ---------------------------------------------------------------------------


def test_w7_invalid_artifact_denies():
    knob = Confidence(min_confidence=0.7)
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(
        AgentRequest(tool="ledger", op="post", args={"x": 1}, confidence={"garbage": True})
    )
    assert resp.decision_kind == "deny"
    assert resp.reason == "invalid confidence artifact"
    assert len(connectors["ledger"].calls) == 0


# ---------------------------------------------------------------------------
# W8 — reads: below-bar never gates a read, and a read draws no error budget.
# ---------------------------------------------------------------------------


def test_w8_reads_not_gated_and_draw_no_budget():
    knob = Confidence(
        min_confidence=0.7,
        error_budget_tolerance=10.0,
        blast_weights={"low": 1.0, "medium": 2.0, "high": 4.0},
    )
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_READ], granted=["ledger.fetch"]
    )
    resp = runtime.handle_request(
        AgentRequest(
            tool="ledger", op="fetch", args={}, confidence=_artifact(confidence=0.1)
        )
    )
    assert resp.decision_kind == "allow"  # below-bar, but a read is not gated by 4/5
    assert store.read_counter(_error_budget_key("ledger", "fetch")) == 0.0


# ---------------------------------------------------------------------------
# W9 — a raising on_demotion_signal subscriber does not fail the request.
# ---------------------------------------------------------------------------


def test_w9_seam_failure_isolated():
    def _boom(_sig: DemotionSignal) -> None:
        raise RuntimeError("subscriber blew up")

    knob = Confidence(
        error_budget_tolerance=0.1,
        blast_weights={"low": 0.2, "medium": 0.2, "high": 0.2},
    )
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"], on_demotion_signal=_boom
    )
    # First write draws 0.2 >= tolerance 0.1 → crossing → the seam raises; the write
    # still succeeds.
    resp = runtime.handle_request(AgentRequest(tool="ledger", op="post", args={"x": 1}))
    assert resp.decision_kind == "allow"
    assert len(connectors["ledger"].calls) == 1


# ---------------------------------------------------------------------------
# W10 — a stale artifact above the bar is still below-bar → abstain (the wired path).
# ---------------------------------------------------------------------------


def test_w10_stale_artifact_above_bar_abstains():
    knob = Confidence(min_confidence=0.5)
    runtime, sink, store, connectors = _build(
        knob=knob, ops=[_WRITE], granted=["ledger.post"]
    )
    resp = runtime.handle_request(
        AgentRequest(
            tool="ledger",
            op="post",
            args={"x": 1},
            confidence=_artifact(confidence=0.99, stale=True),  # above bar but stale
        )
    )
    assert resp.decision_kind == "abstain"
    assert len(connectors["ledger"].calls) == 0


# ---------------------------------------------------------------------------
# W11 — the duck-typed consumer request (channels/DRAIN.md receivers) carries only
# tool/op/args/idempotency_key. #184's confidence read must tolerate the absent
# attribute (absent == None, the same "no artifact" declaration) — regression for
# the 2026-07-13 live drain AttributeError.
# ---------------------------------------------------------------------------


def test_w11_duck_typed_request_without_confidence_attribute():
    from dataclasses import dataclass
    from typing import Any

    @dataclass(frozen=True)
    class _DrainShapedRequest:
        tool: str
        op: str
        args: Any
        idempotency_key: str | None

    runtime, sink, store, connectors = _build(knob=None, ops=[_WRITE], granted=["ledger.post"])
    resp = runtime.handle_request(
        _DrainShapedRequest(tool="ledger", op="post", args={"x": 1}, idempotency_key="w11-1")
    )
    # No bar and no budget configured: the absent artifact is simply "no artifact" —
    # the request decides normally instead of crashing on the missing attribute.
    assert resp.decision_kind == "allow"
    assert len(connectors["ledger"].calls) == 1
