"""Chaos tests: injected dependency faults must produce loud failures.

The invariant: when any broker dependency (enforcement store, audit sink,
secrets provider, connector) fails, the broker round-trip must never return a
BrokerResponse with decision_kind="allow" that would make the fault look like a
success. A store or audit fault surfaces as an exception; a connector or
credential failure of an allowed call becomes a deny-shaped reply with an
outcome="failed" audit record (sa#102, #35).

Each test wires one fault-injecting fake from broker.chaos into an otherwise
valid BrokerRuntime and calls handle_request() against an operation whose
PDP decision is "allow".  The test asserts that an exception propagates to
the caller rather than a silent success response.

All tests run AWS-free (InMemoryStore, InMemorySink, fakes only).

Run with:
    cd broker && ./.venv/bin/python -m pytest tests/test_chaos.py -q
"""

from __future__ import annotations

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.chaos import (
    AuditError,
    ConnectorError,
    FaultAuditSink,
    FaultConnector,
    FaultEnforcementStore,
    FaultSecretsProvider,
    SecretsError,
    StoreError,
)
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.pdp import Facts
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.schemas import BrokeredCall, Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH


# ---------------------------------------------------------------------------
# Shared builders — mirrors the pattern in test_runtime.py
# ---------------------------------------------------------------------------

_PRINCIPAL_DATA = {
    "agentId": "chaos-test-agent",
    "skill": "general",
    "user": "alice",
    "tier": "B",
}
_PRINCIPAL = Principal(**_PRINCIPAL_DATA)


def _make_grant(action_class: str, level: AutonomyLevel = AutonomyLevel.out_of_loop) -> Grant:
    return Grant.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": level,
            "envelopeHash": "chaos-envelope-hash",
            "promotedBy": "chaos-reviewer",
            "evidence": "chaos-evidence-ref",
            "ts": "2026-06-28T00:00:00Z",
            "lastSafeLevel": "in-loop",
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "chaos-owner",
        }
    )


def _allow_pip(call: BrokeredCall) -> Facts:
    """PIP that always says allow (out-of-loop, within budget, human reachable)."""
    return Facts(
        grant_present=True,
        grant_level=AutonomyLevel.out_of_loop,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=True,
        human_reachable=True,
        transform_op=None,
    )


def _calendar_request() -> AgentRequest:
    """A simple internal reversible write — PDP decides 'allow' with out-of-loop grant."""
    return AgentRequest(
        tool="calendar",
        op="create_event",
        args={"title": "chaos test", "start": "2026-07-01T09:00:00Z"},
        idempotency_key=None,  # no deduplication; each call is fresh
    )


def _make_runtime(
    *,
    connector=None,
    secrets=None,
    enforcement_store=None,
    audit_sink=None,
) -> BrokerRuntime:
    """Build a BrokerRuntime with the given (possibly fault-injecting) dependencies.

    Any parameter left as None gets a healthy stub so only one fault is active
    per test.
    """
    resolved_connector = connector or StubConnector(result={"event_id": "evt-chaos"})
    resolved_secrets = secrets or FakeSecretsProvider({"calendar": "cred-calendar"})
    doer = Doer(
        connectors={"calendar": resolved_connector},
        secrets=resolved_secrets,
    )
    return BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_make_grant("calendar.create_event")],
        optable=ToolOpTable(
            [ToolOp(tool="calendar", op="create_event", effect="write", external=False, reversible=True)]
        ),
        doer=doer,
        pip=_allow_pip,
        enforcement_store=enforcement_store or InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=audit_sink or InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


# ---------------------------------------------------------------------------
# Test 1 — Store error: write_ledger raises before any execution
#
# When DynamoDB (or the in-memory fake) fails during the WAL write, the broker
# must not proceed to execute the connector.  The exception must propagate to
# the caller — not be swallowed into a silent allow.
# ---------------------------------------------------------------------------


def test_store_write_ledger_failure_is_loud():
    """write_ledger raises → handle_request propagates StoreError; connector not called."""
    stub_connector = StubConnector(result={"event_id": "evt-1"})
    fault_store = FaultEnforcementStore(fail_on={"write_ledger"})
    runtime = _make_runtime(
        connector=stub_connector,
        enforcement_store=fault_store,
    )

    with pytest.raises(StoreError):
        runtime.handle_request(_calendar_request())

    # The WAL write failed before the connector was reached.
    assert len(stub_connector.calls) == 0, (
        "connector must not execute when the WAL write fails"
    )


# ---------------------------------------------------------------------------
# Test 2 — Store error: try_increment_counter raises (not just returns False)
#
# DynamoDB raising during an atomic counter decrement is distinct from the
# counter being exhausted (which returns False).  A raised exception must
# propagate loudly; the connector must not execute.
# ---------------------------------------------------------------------------


def test_store_counter_increment_error_is_loud():
    """try_increment_counter raises → handle_request propagates StoreError."""
    stub_connector = StubConnector(result={"event_id": "evt-2"})
    fault_store = FaultEnforcementStore(fail_on={"try_increment_counter"})
    runtime = _make_runtime(
        connector=stub_connector,
        enforcement_store=fault_store,
    )

    with pytest.raises(StoreError):
        runtime.handle_request(_calendar_request())

    assert len(stub_connector.calls) == 0, (
        "connector must not execute when the counter increment raises"
    )


# ---------------------------------------------------------------------------
# Test 3 — Audit sink failure
#
# After the connector executes (the side effect occurs), the broker attempts to
# write the AuditRecord.  If the audit sink raises, the broker must NOT report
# the action as a success.  The caller must receive an exception, not a
# BrokerResponse with decision_kind="allow".
#
# Design note: in the current implementation the connector call precedes the
# audit write (audit is emitted "at the moment of the side effect", per
# pep.py).  This means the action has taken place when the audit fails.
# The WAL ledger entry is marked "escalated" (for irreversible) or
# "compensated" (for reversible) to flag the gap for human review.
# The key invariant here is that the broker does NOT return "allow" — the
# caller is informed loudly that something went wrong.
# ---------------------------------------------------------------------------


def test_audit_sink_failure_is_loud_not_silent_success():
    """Audit append raises → handle_request raises; result is never 'allow'."""
    stub_connector = StubConnector(result={"event_id": "evt-3"})
    runtime = _make_runtime(
        connector=stub_connector,
        audit_sink=FaultAuditSink(),
    )

    with pytest.raises(AuditError):
        runtime.handle_request(_calendar_request())

    # The connector DID execute (side effect happened before audit).
    # This is intentional — see the design note above.
    assert len(stub_connector.calls) == 1, (
        "connector executes before audit emit; side effect occurred"
    )


# ---------------------------------------------------------------------------
# Test 4 — Secrets provider failure
#
# The Doer fetches the connector credential at execute time.  If the Secrets
# Manager call fails, the connector never receives a credential and must not
# be called.  It must never look like a success either.
#
# It is NOT a store/audit fault, though: the broker's own machinery is intact and
# the PDP allowed the call, so it is an execution failure of an allowed call and
# is recorded as one (#35). Before #35 this test asserted the exception escaped,
# which is exactly how an allowed call ended up with no audit record.
# ---------------------------------------------------------------------------


def test_secrets_failure_is_audited_never_silent():
    """fetch_secret raises → failed audit + deny-shaped reply; connector not called."""
    stub_connector = StubConnector(result={"event_id": "evt-4"})
    audit_sink = InMemorySink()
    runtime = _make_runtime(
        connector=stub_connector,
        secrets=FaultSecretsProvider(),
        audit_sink=audit_sink,
    )

    response = runtime.handle_request(_calendar_request())

    assert response.decision_kind == "deny"
    assert response.execution_outcome == "failed"
    assert len(stub_connector.calls) == 0, (
        "connector must not execute when the secrets fetch fails"
    )
    records = audit_sink.records()
    assert [(r.decision, r.outcome) for r in records] == [("allow", "failed")]
    assert SecretsError.__name__ in (records[0].error or "")
    # The backend's own message stays off the tape; only its type is recorded.
    assert "simulated Secrets Manager failure" not in (records[0].error or "")


# ---------------------------------------------------------------------------
# Test 5 — Connector failure (timeout / network error)
#
# The connector raises after the credential is fetched (the real GitHubConnector
# can now 401 / time out / hit a network error — the old StubConnector never
# could). A connector failure is DISTINCT from a store/secrets/audit fault: the
# broker must NOT report success, but it also must not surface a raw 500. Instead
# it (sa#102):
#   - marks the WAL entry compensated/escalated via enforce()'s saga,
#   - emits an AuditRecord with outcome="failed" (the invariant), and
#   - returns a clean deny-shaped BrokerResponse (never propagates).
# The connector's error text (and any credential) stays on the broker-private tape,
# never on the agent-facing response.
# ---------------------------------------------------------------------------


def test_connector_failure_returns_deny_and_ledger_reflects_failure():
    """connector.execute raises → clean deny + failed audit + non-committed WAL."""
    audit_sink = InMemorySink()
    fault_connector = FaultConnector(error=ConnectorError("simulated timeout"))
    fault_store = FaultEnforcementStore()  # no faults; passthrough to InMemoryStore
    runtime = _make_runtime(
        connector=fault_connector,
        enforcement_store=fault_store,
        audit_sink=audit_sink,
    )

    # No exception surfaces — the failure becomes a deny, not a 500.
    response = runtime.handle_request(_calendar_request())
    assert response.decision_kind == "deny"
    assert response.result is None
    # The specific connector error stays broker-private; the reason is generic.
    assert "simulated timeout" not in (response.reason or "")

    # An AuditRecord with outcome="failed" is on the tape (never silent).
    records = audit_sink.records()
    assert len(records) == 1
    assert records[0].outcome == "failed"
    assert records[0].decision == "allow"  # we decided allow; execution then failed

    # The WAL entry must exist and must NOT be committed (the connector failed).
    # calendar.create_event is reversible=True, so enforce() calls compensate_ledger.
    all_ledger = fault_store._inner._ledger  # test-only access to inner store
    assert len(all_ledger) == 1, "one WAL entry should have been written"
    entry = next(iter(all_ledger.values()))
    assert entry.status in ("compensated", "escalated"), (
        f"WAL entry must be compensated or escalated after connector failure; "
        f"got status={entry.status!r}"
    )
    assert entry.status != "committed", (
        "WAL entry must never be committed when the connector failed"
    )
