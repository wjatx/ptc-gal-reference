"""A second principal cannot burn a first principal's pending approval.

An external implementer's finding against delegated-authority resolvers: a
single-use approval that a third party can CONSUME without using it (approve it
into a no-op, reject it, force it to expire, or coalesce onto it) is as good as
denied to its owner. Here the owner is principal A, the third party is
principal B, and the two share one intent store, which is the case the PEP's
foreign-principal guard exists for (the store keys only on intent id).

What each test pins:

* B's out-of-band verbs on A's intent (approve, reject, describe, flag) change
  nothing, and afterwards A's owner still releases it, executing A's STORED call.
* B cannot force A's past-expiry intent into ``expired`` either; only A's own
  action judges and records that.
* B submitting a call identical to A's (same tool, op and args) lands in its own
  intent with dedup on or off, and releasing B's does not consume A's.

B is parametrized over every component of the principal key, including the
on-behalf-of case: the same agent acting for a different user.

Coverage already elsewhere, cited rather than repeated: a foreign agentId on
approve/reject/flag in test_out_of_band_approval.py (TestForeignIntentGuard,
TestFlagIntent.test_foreign_intent_refused); the pure dedup id binding the
principal in test_approval_queue.py (test_dedup_id_is_per_principal and
neighbours); double approval by the SAME principal in
test_out_of_band_approval.py::TestApproveIntent::test_double_approval_refused.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.schemas import Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.envelope import ApprovalQueue
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH
from safe_agents.broker.tests.test_runtime import _make_pip

_A = {"agentId": "agent-a", "skill": "finance", "user": "alice", "tier": "B"}
# B differs from A in exactly one component of the principal key.
# The same-agent variants are the ones that went red on first run (2026-09-19):
# the PEP's ownership check compared agentId alone, so the same agent acting for
# bob released alice's frozen call through bob's connector and credentials, and
# alice's owner was then refused "not pending". Fixed by BrokerRuntime._owns_intent
# comparing the whole principal.
_B_VARIANTS = [
    pytest.param({**_A, "agentId": "agent-b"}, id="other-agent"),
    pytest.param({**_A, "user": "bob"}, id="same-agent-on-behalf-of-other-user"),
    pytest.param({**_A, "skill": "support"}, id="same-agent-other-skill"),
    pytest.param({**_A, "tier": "D"}, id="same-agent-other-tier"),
]
_ARGS = {"amount": 500, "to": "acct-xyz"}
_FOREIGN = "intent belongs to a different principal"


def _grant(principal: dict) -> Grant:
    return Grant.model_validate(
        {
            "principal": principal,
            "actionClass": "payments.transfer",
            "level": AutonomyLevel.on_loop,
            "envelopeHash": "test-envelope-hash",
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


def _runtime(
    principal: dict, intent_store: InMemoryIntentStore, *, dedup: bool = False
) -> tuple[BrokerRuntime, StubConnector]:
    """A runtime bound to ``principal`` over the SHARED intent store."""
    connector = StubConnector(result={"tx_id": f"tx-{principal['user']}"})
    runtime = BrokerRuntime(
        principal=Principal(**principal),
        grants=[_grant(principal)],
        optable=ToolOpTable(
            [ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False)]
        ),
        doer=Doer(
            connectors={"payments": connector},
            secrets=FakeSecretsProvider({"payments": "cred-payments"}),
        ),
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        enforcement_store=InMemoryStore(),
        intent_store=intent_store,
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
        approval_queue=ApprovalQueue(dedup=True) if dedup else None,
    )
    return runtime, connector


def _hold(runtime: BrokerRuntime) -> str:
    response = runtime.handle_request(AgentRequest(tool="payments", op="transfer", args=_ARGS))
    assert response.decision_kind == "require_approval"
    return response.intent_id


def _assert_a_releases(store, a_runtime, a_conn, a_id: str) -> None:
    """A's owner releases A's intent, and what runs is A's STORED call."""
    assert store.get_intent(a_id).status == "pending"
    result = a_runtime.approve_intent(a_id, approved_by="owner-of-a")
    assert result.executed is True, result
    assert store.get_intent(a_id).status == "executed"
    assert store.get_intent(a_id).approvedBy == "owner-of-a"
    assert store.get_intent(a_id).materializedRequest.principal.model_dump() == _A
    assert len(a_conn.calls) == 1


@pytest.mark.parametrize("b", _B_VARIANTS)
def test_other_principal_cannot_consume_a_pending_intent(b: dict) -> None:
    store = InMemoryIntentStore()
    a_runtime, a_conn = _runtime(_A, store)
    b_runtime, b_conn = _runtime(b, store)
    a_id = _hold(a_runtime)

    assert b_runtime.approve_intent(a_id, approved_by="owner-of-b").rejection_reason == _FOREIGN
    assert b_runtime.reject_intent(a_id, "owner-of-b").rejection_reason == _FOREIGN
    assert b_runtime.describe_intent(a_id) is None
    assert b_runtime.flag_intent(a_id, flagged_by="owner-of-b").rejection_reason == _FOREIGN

    # Nothing claimed, nothing run, nobody recorded as the approver.
    intent = store.get_intent(a_id)
    assert (intent.status, intent.approvedBy) == ("pending", None)
    assert a_conn.calls == [] and b_conn.calls == []

    _assert_a_releases(store, a_runtime, a_conn, a_id)


@pytest.mark.parametrize("b", _B_VARIANTS)
def test_other_principal_cannot_force_expiry(b: dict) -> None:
    """B acting on A's past-expiry intent records nothing; only A's action expires it."""
    store = InMemoryIntentStore()
    a_runtime, _ = _runtime(_A, store)
    b_runtime, _ = _runtime(b, store)
    a_id = _hold(a_runtime)
    held = store.get_intent(a_id)
    store.put_intent(
        held.model_copy(
            update={"expiry": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}
        )
    )

    for act in (
        lambda: b_runtime.approve_intent(a_id, approved_by="owner-of-b"),
        lambda: b_runtime.reject_intent(a_id, "owner-of-b"),
    ):
        assert act().rejection_reason == _FOREIGN
        assert store.get_intent(a_id).status == "pending"

    assert a_runtime.approve_intent(a_id, approved_by="owner-of-a").rejection_reason == (
        "intent expired"
    )
    assert store.get_intent(a_id).status == "expired"


@pytest.mark.parametrize("dedup", [False, True], ids=["dedup-off", "dedup-on"])
@pytest.mark.parametrize("b", _B_VARIANTS)
def test_identical_call_from_other_principal_does_not_coalesce_or_consume(
    b: dict, dedup: bool
) -> None:
    store = InMemoryIntentStore()
    a_runtime, a_conn = _runtime(_A, store, dedup=dedup)
    b_runtime, b_conn = _runtime(b, store, dedup=dedup)
    a_id = _hold(a_runtime)

    response = b_runtime.handle_request(AgentRequest(tool="payments", op="transfer", args=_ARGS))
    assert response.decision_kind == "require_approval"
    b_id = response.intent_id
    assert b_id != a_id, "B's identical call coalesced onto A's intent"
    assert store.get_intent(b_id).materializedRequest.principal.model_dump() == b
    assert store.get_intent(a_id).materializedRequest.principal.model_dump() == _A

    # B's owner releases B's own intent: it runs B's call on B's runtime, and
    # A's intent, keyed on its own stored call, is untouched.
    assert b_runtime.approve_intent(b_id, approved_by="owner-of-b").executed is True
    assert len(b_conn.calls) == 1 and a_conn.calls == []

    _assert_a_releases(store, a_runtime, a_conn, a_id)
