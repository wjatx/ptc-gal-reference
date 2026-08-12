"""Integration tests for broker.runtime — the capability-confined doer and broker runtime.

Acceptance criteria from #56:
  1. Full round-trip (allow):
       agent call → registry → taint → decide(allow) → enforce → doer executes stub
       connector with an injected credential → AuditRecord emitted with a valid chain
       → result returned to agent.

  2. require_approval round-trip:
       agent call → decide(require_approval) → enforce (no connector execution) →
       materialize Intent → turn ends with pending Intent; NO connector execution.

  3. Confinement:
       - The agent-facing surface (BrokerResponse) contains no credential field.
       - BrokerRuntime's public API exposes no Connector, no Doer, no SecretsProvider.
       - Doer.execute() raises ConfinementError for non-allow/transform decisions.

  4. Idempotent-replay:
       A second request with the same idempotency_key returns the prior outcome without
       re-executing the connector.

All tests use stubs — no real AWS, no network.
"""

from __future__ import annotations

import dataclasses

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink, verify_chain
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.pdp import Facts
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerResponse,
    BrokerRuntime,
    ConfinementError,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.schemas import BrokeredCall, Deny, Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------

_PRINCIPAL_DATA = {
    "agentId": "agent-runtime-test",
    "skill": "general",
    "user": "alice",
    "tier": "B",
}
_PRINCIPAL = Principal(**_PRINCIPAL_DATA)


def _make_grant(action_class: str, level: AutonomyLevel = AutonomyLevel.on_loop) -> Grant:
    """Build a minimal valid Grant for tests."""
    return Grant.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": level,
            "envelopeHash": "test-envelope-hash",
            "promotedBy": "human-reviewer",
            "evidence": "test-evidence-ref",
            "ts": "2026-06-28T00:00:00Z",
            "lastSafeLevel": "in-loop",   # validated: never out-of-loop
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "test-owner",
        }
    )


def _make_pip(
    grant_present: bool = True,
    grant_level: AutonomyLevel = AutonomyLevel.on_loop,
    human_reachable: bool = True,
):
    """Build a PIP callable returning fixed Facts."""

    def pip(call: BrokeredCall) -> Facts:
        return Facts(
            grant_present=grant_present,
            grant_level=grant_level,
            error_budget_breached=False,
            cap_budget_breached=False,
            escalation_budget_available=True,
            human_reachable=human_reachable,
            transform_op=None,
        )

    return pip


def _make_runtime(
    grants: list[Grant],
    connectors: dict[str, StubConnector] | None = None,
    pip=None,
    audit_sink: InMemorySink | None = None,
    enforcement_store: InMemoryStore | None = None,
    intent_store: InMemoryIntentStore | None = None,
    secret_map: dict[str, str] | None = None,
    approval_queue=None,
    counter_period: str = "utc-day",
) -> tuple[BrokerRuntime, InMemorySink, dict[str, StubConnector]]:
    """Build a BrokerRuntime with all fakes wired up."""
    connectors = connectors or {
        "calendar": StubConnector(result={"event_id": "evt-1"}),
        "payments": StubConnector(result={"tx_id": "tx-1"}),
        "crm": StubConnector(result={"deals": []}),
        "email": StubConnector(result={"message_id": "msg-1"}),
    }
    sink = audit_sink or InMemorySink()
    secrets = FakeSecretsProvider(
        secret_map or {
            "calendar": "cred-calendar",
            "payments": "cred-payments",
            "crm": "cred-crm",
            "email": "cred-email",
        }
    )
    doer = Doer(connectors=connectors, secrets=secrets)
    optable = ToolOpTable(
        [
            ToolOp(tool="calendar", op="create_event", effect="write", external=False, reversible=True),
            ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False),
            ToolOp(tool="crm", op="list_deals", effect="read", external=False),
            ToolOp(tool="email", op="send", effect="write", external=True, reversible=False),
        ]
    )
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=grants,
        optable=optable,
        doer=doer,
        pip=pip or _make_pip(grant_level=AutonomyLevel.on_loop),
        enforcement_store=enforcement_store or InMemoryStore(),
        intent_store=intent_store or InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
        approval_queue=approval_queue,
        counter_period=counter_period,  # type: ignore[arg-type]
    )
    return runtime, sink, connectors


# ---------------------------------------------------------------------------
# Test 1 — Full allow round-trip
# ---------------------------------------------------------------------------


def test_allow_round_trip():
    """Full integration: registry → taint → decide(allow) → doer executes → audit."""
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    connectors = {"calendar": StubConnector(result={"event_id": "evt-42"})}
    runtime, sink, stub_connectors = _make_runtime(grants, connectors=connectors)

    # Registry is capability-scoped — agent may only see granted ops.
    registry = runtime.served_registry()
    assert len(registry) == 1
    assert registry[0].tool == "calendar"
    assert registry[0].op == "create_event"

    # Submit a request for the granted op (untainted turn).
    request = AgentRequest(
        tool="calendar",
        op="create_event",
        args={"title": "Team standup", "start": "2026-07-01T09:00:00Z"},
        idempotency_key="turn-1:create-standup",
    )
    response = runtime.handle_request(request)

    # Allow: connector executed, result returned.
    assert response.decision_kind == "allow"
    assert response.result == {"event_id": "evt-42"}
    assert response.idempotent is False
    assert response.intent_id is None
    assert response.reason is None

    # Connector received exactly one call with the broker-injected credential.
    calls = stub_connectors["calendar"].calls
    assert len(calls) == 1
    assert calls[0].credential == "cred-calendar"
    assert calls[0].op == "create_event"

    # One AuditRecord was emitted; chain is intact.
    records = sink.records()
    assert len(records) == 1
    assert records[0].decision == "allow"
    assert records[0].outcome == "executed"
    assert records[0].seq == 0
    verify_chain(records)


# ---------------------------------------------------------------------------
# Test 2 — require_approval round-trip: Intent materialized, no connector call
# ---------------------------------------------------------------------------


def test_require_approval_round_trip():
    """require_approval: Intent materialized, turn ends, NO connector execution."""
    # payments.transfer: external=True, reversible=False → require_approval always
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    connectors = {"payments": StubConnector()}
    intent_store = InMemoryIntentStore()
    runtime, sink, stub_connectors = _make_runtime(
        grants,
        connectors=connectors,
        intent_store=intent_store,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
    )

    request = AgentRequest(
        tool="payments",
        op="transfer",
        args={"amount": 500, "to": "acct-xyz"},
        idempotency_key="turn-2:transfer",
    )
    response = runtime.handle_request(request)

    # Decision is require_approval; turn ends here.
    assert response.decision_kind == "require_approval"
    assert response.intent_id is not None
    assert response.result is None

    # Connector was NOT called.
    assert len(stub_connectors["payments"].calls) == 0

    # Intent was persisted.
    intent = intent_store.get_intent(response.intent_id)
    assert intent is not None
    assert intent.status == "pending"
    # WYSIWYE: the stored materializedRequest is the exact BrokeredCall we sent.
    assert intent.materializedRequest.tool == "payments"
    assert intent.materializedRequest.op == "transfer"

    # Audit record emitted with outcome=held.
    records = sink.records()
    assert len(records) == 1
    assert records[0].decision == "require_approval"
    assert records[0].outcome == "held"
    verify_chain(records)


# ---------------------------------------------------------------------------
# Test 3 — Confinement
# ---------------------------------------------------------------------------


def test_confinement_broker_response_has_no_credential():
    """BrokerResponse contains no credential field — structural confinement assertion."""
    field_names = {f.name for f in dataclasses.fields(BrokerResponse)}
    credential_like = {
        name for name in field_names
        if any(kw in name.lower() for kw in ("credential", "secret", "password", "token", "key"))
    }
    assert credential_like == set(), (
        f"BrokerResponse must not expose credential fields; found: {credential_like}"
    )


def test_confinement_runtime_public_api_has_no_connector_or_doer():
    """BrokerRuntime's public methods expose no connector, Doer, or SecretsProvider."""

    grants = [_make_grant("calendar.create_event")]
    runtime, _, _ = _make_runtime(grants)

    # Enumerate only the public method names.
    public_methods = [
        name for name in dir(runtime)
        if not name.startswith("_") and callable(getattr(runtime, name))
    ]
    # Expected agent-facing API: served_registry + handle_request. new_turn (sa#136)
    # and session_turn (sa#155, the channels drain's ingest seam) are broker/
    # harness-owned turn controls, NOT agent-facing: they are wired to no HTTP route
    # (broker_server.py serves only /registry and /call), so the agent — which
    # reaches the runtime only across that surface — cannot call them, and neither
    # exposes a connector/Doer/secret (session_turn returns a TurnContext, whose
    # taint is add-only). approve_intent / reject_intent (sa#176) are the out-of-band
    # approval seam the channels drain worker calls for an authenticated owner; they
    # use the Doer/intent-store INTERNALLY and return only an ExecutionResult — no
    # Doer, connector, secret, or store reference crosses the surface — and are
    # likewise wired to no agent-facing HTTP route. flag_intent (#193 Phase 6c) is the
    # same shape: an out-of-band owner seam that writes only the false_action evidence
    # counter and returns an ExecutionResult — no execution, no reference crosses out.
    # close (#221 P3, MCP-HOST.md M20) is the service-shutdown seam: the process's
    # SIGTERM handler drives it after the request loop drains so connector-held
    # children are reaped in order; it takes nothing, returns None, and is wired to
    # no agent-facing HTTP route — no connector, Doer, or secret crosses out.
    # describe_intent (#301) is the READ half of the same out-of-band owner seam:
    # an approver must see the stored call before releasing it. It returns a frozen
    # IntentView of data — no store, no Intent model, no raw args — executes nothing,
    # transitions nothing, answers None for another principal's intent so it cannot
    # enumerate, and is wired to no agent-facing HTTP route.
    assert set(public_methods) == {
        "served_registry", "handle_request", "new_turn", "session_turn",
        "approve_intent", "reject_intent", "flag_intent", "describe_intent", "close",
    }, (
        "BrokerRuntime must expose only served_registry/handle_request/new_turn/"
        "session_turn/approve_intent/reject_intent/flag_intent/describe_intent/close; "
        f"found: {public_methods}"
    )


def test_confinement_doer_raises_on_non_allow_decision():
    """Doer.execute() raises ConfinementError for any non-allow/transform decision."""
    connector = StubConnector()
    secrets = FakeSecretsProvider({"calendar": "cred-calendar"})
    doer = Doer(connectors={"calendar": connector}, secrets=secrets)

    call = BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "tool": "calendar",
            "op": "create_event",
            "args": {},
            "manifest": {
                "tool": "calendar",
                "op": "create_event",
                "effect": "write",
                "external": False,
                "reversible": True,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-confinement", "ingestedSources": []},
            "ts": "2026-06-28T00:00:00Z",
        }
    )

    # deny is not a permitted execution decision.
    deny = Deny(kind="deny", reason="test")
    with pytest.raises(ConfinementError):
        doer.execute(call, deny)

    # Connector was never called — confinement was enforced before the connector.
    assert len(connector.calls) == 0


def test_confinement_agent_cannot_obtain_credential_from_response():
    """The connector credential is not reachable from BrokerResponse in any field."""
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    connectors = {"calendar": StubConnector(result={"event_id": "evt-1"})}
    runtime, _, _ = _make_runtime(grants, connectors=connectors)

    response = runtime.handle_request(
        AgentRequest(
            tool="calendar",
            op="create_event",
            args={"title": "test"},
            idempotency_key="turn-cred-test",
        )
    )

    # Serialize the response fully and confirm no credential value appears.
    response_str = str(dataclasses.asdict(response))
    assert "cred-calendar" not in response_str, (
        "Credential value must never appear in BrokerResponse"
    )


# ---------------------------------------------------------------------------
# Test 4 — Idempotent replay
# ---------------------------------------------------------------------------


def test_idempotent_replay():
    """Second call with same idempotency_key returns prior outcome; connector not re-called."""
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    connector = StubConnector(result={"event_id": "evt-idem"})
    enforcement_store = InMemoryStore()
    runtime, sink, _ = _make_runtime(
        grants,
        connectors={"calendar": connector},
        enforcement_store=enforcement_store,
    )

    request = AgentRequest(
        tool="calendar",
        op="create_event",
        args={"title": "idempotent meeting"},
        idempotency_key="turn-idem:meeting",
    )

    # First call — connector executes and returns its result.
    first = runtime.handle_request(request)
    assert first.decision_kind == "allow"
    assert first.idempotent is False
    assert first.result == {"event_id": "evt-idem"}
    assert len(connector.calls) == 1

    # Second call with the same key — idempotent replay; connector NOT called again,
    # but the caller still gets the cached result back (sa#108), not None.
    second = runtime.handle_request(request)
    assert second.decision_kind == "allow"
    assert second.idempotent is True
    assert second.result == {"event_id": "evt-idem"}, "replay must return the cached result, not None"
    assert len(connector.calls) == 1  # still 1, not 2

    # Audit was emitted only once (for the first call).
    records = sink.records()
    assert len(records) == 1
    verify_chain(records)


# ---------------------------------------------------------------------------
# Test 5 — Connector failure: clean deny + outcome=failed + credential never leaks
# ---------------------------------------------------------------------------


class _RaisingConnector:
    """Connector that always fails — models the real GitHubConnector 401/timeout.

    ``leak_credential`` reproduces a *misbehaving* connector that embeds the injected
    token in its exception message, so the test can prove the Doer redacts it before it
    can reach the audit 'error' field or the response.
    """

    def __init__(self, *, leak_credential: bool = False) -> None:
        self._leak = leak_credential

    def execute(self, tool, op, args, credential):
        if self._leak:
            raise RuntimeError(f"upstream 401 (token={credential})")
        raise RuntimeError("connection reset by peer")


def test_connector_failure_returns_deny_emits_failed_no_credential_leak():
    """A connector exception → deny response, outcome=failed record, and no credential
    anywhere on the failure path (record or response)."""
    secret_value = "cred-super-secret-token"
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    runtime, sink, _ = _make_runtime(
        grants,
        connectors={"calendar": _RaisingConnector(leak_credential=True)},
        secret_map={"calendar": secret_value},
    )

    response = runtime.handle_request(
        AgentRequest(
            tool="calendar",
            op="create_event",
            args={"title": "will fail", "password": "hunter2"},
            idempotency_key="turn-fail:1",
        )
    )

    # (a) The response is a clean deny, not an exception, not an allow.
    assert response.decision_kind == "deny"
    assert response.result is None

    # (b) The audit sink has exactly one record with outcome="failed"; chain valid.
    records = sink.records()
    assert len(records) == 1
    assert records[0].outcome == "failed"
    assert records[0].decision == "allow"  # decided allow, execution then failed
    assert records[0].error is not None
    verify_chain(records)

    # (c) The credential never appears — not in the record (even though the connector
    #     tried to leak it) and not in the response. args are hashed, so the raw
    #     "password" arg is absent too.
    record_blob = records[0].model_dump_json()
    assert secret_value not in record_blob, "credential leaked into the audit record"
    assert "hunter2" not in record_blob, "raw args leaked into the audit record"
    assert records[0].argsDigest.startswith("sha256:")
    response_blob = str(dataclasses.asdict(response))
    assert secret_value not in response_blob, "credential leaked into the response"


def test_connector_failure_wal_not_committed():
    """After a connector failure the reversible WAL entry is compensated, never committed."""
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    store = InMemoryStore()
    runtime, _, _ = _make_runtime(
        grants,
        connectors={"calendar": _RaisingConnector()},
        enforcement_store=store,
    )

    runtime.handle_request(
        AgentRequest(tool="calendar", op="create_event", args={"title": "x"}, idempotency_key=None)
    )

    ledger = list(store._ledger.values())  # test-only access to the in-memory WAL
    assert len(ledger) == 1
    assert ledger[0].status == "compensated"


# ---------------------------------------------------------------------------
# Test 5 — Rename-invariance, end-to-end (#171 exit predicate)
#
# The DoD is "a consumer-defined op with a correct classification gates IDENTICALLY
# regardless of its name." The unit assertion in test_manifest.py proves the table
# carries classification-not-name; THIS proves the whole broker does — a
# consumer-INVENTED op name the base has never seen is driven through the real PDP
# decision (untainted → allow, tainted → require_approval) and produces byte-identical
# decisions to a base-shaped reference op that shares its effect/external/reversible
# triple. Same triple in, same verb out — the name is inert.
# ---------------------------------------------------------------------------


def _rename_invariance_runtime() -> tuple[BrokerRuntime, InMemorySink]:
    """A runtime granting BOTH a consumer-invented op and a same-classification
    reference op — same external-write-recoverable shape as notify.send."""
    invented = ToolOp(tool="widget", op="frobnicate", effect="write", external=True, reversible=True)
    reference = ToolOp(tool="notify", op="send", effect="write", external=True, reversible=True)
    # Guard the premise: the two ops share the exact classification triple the PDP
    # keys on, differing ONLY in name — so any decision difference is name-sensitivity.
    assert (invented.effect, invented.external, invented.reversible) == (
        reference.effect, reference.external, reference.reversible
    )
    sink = InMemorySink()
    doer = Doer(
        connectors={
            "widget": StubConnector(result={"ok": True}),
            "notify": StubConnector(result={"ok": True}),
        },
        secrets=FakeSecretsProvider({"widget": "cred-widget", "notify": "cred-notify"}),
    )
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[
            _make_grant("widget.frobnicate", level=AutonomyLevel.on_loop),
            _make_grant("notify.send", level=AutonomyLevel.on_loop),
        ],
        optable=ToolOpTable([invented, reference]),
        doer=doer,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )
    return runtime, sink


def test_invented_op_gates_identically_untainted():
    """Untainted turn: the invented op and the reference op both ALLOW and execute —
    the base gated on classification, never on the (never-before-seen) name."""
    runtime, _ = _rename_invariance_runtime()

    invented = runtime.handle_request(
        AgentRequest(tool="widget", op="frobnicate", args={"x": 1}, idempotency_key="u-widget")
    )
    runtime.new_turn()
    reference = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "hi"}, idempotency_key="u-notify")
    )

    assert invented.decision_kind == "allow"
    assert reference.decision_kind == invented.decision_kind


def test_invented_op_gates_identically_when_tainted():
    """Tainted turn (an untrusted source ingested this turn): BOTH ops escalate to
    require_approval via the standing tainted_external_write cut — identically. Taint,
    not the op name, is what flips the decision, and it flips both the same way."""
    runtime, _ = _rename_invariance_runtime()

    invented = runtime.handle_request(
        AgentRequest(tool="widget", op="frobnicate", args={"x": 1}, idempotency_key="t-widget"),
        ingested_sources=["email:attacker"],  # untrusted (not "internal:") → taints the turn
    )
    runtime.new_turn()
    reference = runtime.handle_request(
        AgentRequest(tool="notify", op="send", args={"message": "hi"}, idempotency_key="t-notify"),
        ingested_sources=["email:attacker"],
    )

    assert invented.decision_kind == "require_approval"
    assert reference.decision_kind == invented.decision_kind
