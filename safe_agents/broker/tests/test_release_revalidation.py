"""Release-time revalidation on the out-of-band approval seam (#9).

A human approval answers the approval requirement and nothing else. Before #9 the
release path handed the stored call straight to the Doer under a synthesized allow,
so a grant revoked, demoted or capped between the hold and the release still
executed, and the release drew no per-op budget. Now the release routes through the
same enforce() pipeline an inline /call uses, with a decider wrapper that folds a
fresh require_approval back to allow so a ratified hold cannot loop into a second
hold.

Proves, through the public runtime surface with in-memory fakes (no AWS, no network):

  - a grant revoked between hold and release REFUSES: nothing reaches the connector,
    the intent lands in the terminal "refused" state, and the tape carries the reason;
  - an exhausted per-op action cap REFUSES the same way;
  - a normal release DRAWS the per-op budget counter (it did not before);
  - an unchanged world — the PDP still saying require_approval — executes exactly
    once and lands "executed"; no loop, no second hold;
  - a revalidation that returns transform REFUSES (WYSIWYE: a release never runs
    anything other than the bytes the human saw);
  - reject_intent is untouched by any of it.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.engine import RELEASE_REFUSED_REASON_PREFIX
from safe_agents.broker.audit import InMemorySink, verify_chain
from safe_agents.broker.enforcement import (
    ACTION_CAP_SUFFIX,
    InMemoryStore,
    scoped_counter_key,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.pdp import Facts
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.schemas import Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH

_PRINCIPAL_DATA = {
    "agentId": "agent-release-revalidation",
    "skill": "general",
    "user": "alice",
    "tier": "B",
}
_PRINCIPAL = Principal(**_PRINCIPAL_DATA)

_COUNTER_CAP = 100.0
_APPROVER = "owner:maintainer@example.com"


# ---------------------------------------------------------------------------
# Fixtures — a PIP whose Facts can be swapped between hold and release
# ---------------------------------------------------------------------------


class _MutablePip:
    """A PIP callable holding ONE mutable Facts, so a test can move the world.

    The real PIP re-reads the grant store and the counters on every call, which is
    exactly what makes release-time revalidation meaningful. This fake stands in for
    that: the hold reads ``facts``, the test then reassigns ``facts``, and the
    release reads whatever is there now.
    """

    def __init__(self, facts: Facts) -> None:
        self.facts = facts
        self.reads = 0

    def __call__(self, call) -> Facts:  # noqa: ANN001 — BrokeredCall
        self.reads += 1
        return self.facts


def _facts(
    *,
    grant_present: bool = True,
    grant_level: AutonomyLevel = AutonomyLevel.in_loop,
    cap_budget_breached: bool = False,
    human_reachable: bool = True,
    transform_op: str | None = None,
) -> Facts:
    return Facts(
        grant_present=grant_present,
        grant_level=grant_level,
        error_budget_breached=False,
        cap_budget_breached=cap_budget_breached,
        escalation_budget_available=True,
        human_reachable=human_reachable,
        transform_op=transform_op,
    )


class _CountingConnector:
    """A StubConnector wrapper that counts how many times the connector was reached."""

    def __init__(self, result: dict) -> None:
        self._inner = StubConnector(result=result)
        self.count = 0

    def execute(self, tool, op, args, credential):  # noqa: ANN001, ANN201
        self.count += 1
        return self._inner.execute(tool, op, args, credential)

    @property
    def calls(self):
        return self._inner.calls


def _make_grant(action_class: str, level: AutonomyLevel) -> Grant:
    return Grant.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": level,
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


_PAYMENTS_OPTABLE = ToolOpTable(
    [ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False)]
)
# An external REVERSIBLE write, so the transform rule (which never fires on an
# irreversible op) can be reached at release time.
_NOTIFY_OPTABLE = ToolOpTable(
    [ToolOp(tool="notify", op="send", effect="write", external=True, reversible=True)]
)


def _build(
    *,
    tool: str,
    op: str,
    optable: ToolOpTable,
    pip: _MutablePip,
    connector: _CountingConnector,
    enforcement_store: InMemoryStore,
    intent_store: InMemoryIntentStore,
    counter_cap: float = _COUNTER_CAP,
) -> tuple[BrokerRuntime, InMemorySink]:
    sink = InMemorySink()
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_make_grant(f"{tool}.{op}", AutonomyLevel.in_loop)],
        optable=optable,
        doer=Doer(
            connectors={tool: connector},
            secrets=FakeSecretsProvider({tool: f"cred-{tool}"}),
        ),
        pip=pip,
        enforcement_store=enforcement_store,
        intent_store=intent_store,
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=counter_cap,
    )
    return runtime, sink


def _payments_world(
    hold_facts: Facts | None = None,
    *,
    counter_cap: float = _COUNTER_CAP,
):
    """A payments.transfer runtime whose facts can be swapped between hold and release."""
    pip = _MutablePip(hold_facts or _facts())
    connector = _CountingConnector({"tx_id": "tx-released"})
    store = InMemoryStore()
    intent_store = InMemoryIntentStore()
    runtime, sink = _build(
        tool="payments",
        op="transfer",
        optable=_PAYMENTS_OPTABLE,
        pip=pip,
        connector=connector,
        enforcement_store=store,
        intent_store=intent_store,
        counter_cap=counter_cap,
    )
    return runtime, sink, pip, connector, store, intent_store


def _hold(runtime, intent_store, *, tool="payments", op="transfer", args=None) -> str:
    """Drive a call that the PDP holds, and return the pending intent's id."""
    response = runtime.handle_request(
        AgentRequest(tool=tool, op=op, args=args or {"amount": 500, "to": "acct-xyz"})
    )
    assert response.decision_kind == "require_approval"
    assert intent_store.get_intent(response.intent_id).status == "pending"
    return response.intent_id


def _action_cap_key(tool: str, op: str) -> str:
    return scoped_counter_key(_PRINCIPAL, tool, op, ACTION_CAP_SUFFIX)


# ---------------------------------------------------------------------------
# (a) authority withdrawn between hold and release
# ---------------------------------------------------------------------------


def test_grant_revoked_between_hold_and_release_refuses():
    """A grant revoked after the hold refuses the release — the reported defect (#9)."""
    runtime, sink, pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    reads_at_hold = pip.reads

    # The world moves: the facts provider now reports no grant for this principal.
    pip.facts = _facts(grant_present=False)

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason.startswith(RELEASE_REFUSED_REASON_PREFIX)
    assert "not granted" in result.rejection_reason
    # The connector was never reached.
    assert connector.count == 0
    # The release READ fresh facts — the whole point (it read none before #9).
    assert pip.reads > reads_at_hold
    # Terminal, and distinguishable from both "executed" and an owner "rejected".
    assert intent_store.get_intent(intent_id).status == "refused"

    # The tape says a human approved and the broker still refused, and why.
    records = sink.records()
    assert [r.outcome for r in records] == ["held", "denied"]
    refusal = records[-1]
    assert refusal.decision == "deny"
    assert "not granted" in refusal.reason
    assert refusal.approvedBy == _APPROVER
    assert refusal.intentId == intent_id
    assert refusal.storedCallDigest is not None
    verify_chain(records)


def test_grant_demoted_to_no_human_reachable_refuses():
    """A demotion that removes the fallback (no human reachable) refuses the release."""
    runtime, _sink, pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)

    # The PDP's irreversible-external-write rule now falls back to deny.
    pip.facts = _facts(human_reachable=False)

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason.startswith(RELEASE_REFUSED_REASON_PREFIX)
    assert connector.count == 0
    assert intent_store.get_intent(intent_id).status == "refused"


# ---------------------------------------------------------------------------
# (b) budget exhausted between hold and release
# ---------------------------------------------------------------------------


def test_action_cap_exhausted_between_hold_and_release_refuses():
    """A per-op cap filled after the hold refuses the release at enforce()'s counter draw."""
    runtime, _sink, _pip, connector, store, intent_store = _payments_world(counter_cap=3.0)
    intent_id = _hold(runtime, intent_store)

    # Fill the SAME scoped counter the release will draw, right up to the cap.
    key = _action_cap_key("payments", "transfer")
    assert store.try_increment_counter(key, 3.0, 3.0) is True

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason == f"{RELEASE_REFUSED_REASON_PREFIX}: capacity budget exceeded"
    assert connector.count == 0
    assert intent_store.get_intent(intent_id).status == "refused"
    # The refused draw left the counter where it was — no partial spend.
    assert store.read_counter(key) == 3.0


def test_cap_breached_fact_between_hold_and_release_refuses():
    """The PDP's own cap_budget_breached fact refuses the release too."""
    runtime, _sink, pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)

    pip.facts = _facts(cap_budget_breached=True)

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert "capacity budget breached" in result.rejection_reason
    assert connector.count == 0
    assert intent_store.get_intent(intent_id).status == "refused"


# ---------------------------------------------------------------------------
# (c) a normal release draws the per-op budget
# ---------------------------------------------------------------------------


def test_normal_release_draws_the_action_cap_counter():
    """A clean release spends the op's period budget exactly as an inline call would."""
    runtime, _sink, _pip, connector, store, intent_store = _payments_world()
    key = _action_cap_key("payments", "transfer")
    assert store.read_counter(key) == 0.0  # the hold itself draws nothing

    intent_id = _hold(runtime, intent_store)
    assert store.read_counter(key) == 0.0

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is True
    assert connector.count == 1
    assert store.read_counter(key) == 1.0


# ---------------------------------------------------------------------------
# (d) an unchanged world still releases — no loop, no second hold
# ---------------------------------------------------------------------------


def test_unchanged_world_executes_exactly_once():
    """The facts that produced the hold still produce require_approval; the release runs anyway."""
    runtime, sink, pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    facts_at_hold = pip.facts

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    # The facts were never touched — revalidation re-decided require_approval and the
    # wrapper folded it to allow because the human already ratified it.
    assert pip.facts is facts_at_hold
    assert result.executed is True
    assert result.result == {"tx_id": "tx-released"}
    assert connector.count == 1
    assert intent_store.get_intent(intent_id).status == "executed"

    # Exactly one hold on the tape — the release did not materialize a second intent.
    records = sink.records()
    assert [r.outcome for r in records] == ["held", "executed"]
    assert records[-1].decision == "allow"
    assert records[-1].approvedBy == _APPROVER
    verify_chain(records)


def test_second_release_attempt_still_refused_and_executes_once():
    """The approve() CAS remains the release's exactly-once gate."""
    runtime, _sink, _pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)

    first = runtime.approve_intent(intent_id, approved_by=_APPROVER)
    second = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert first.executed is True
    assert second.executed is False
    assert "not pending" in second.rejection_reason
    assert connector.count == 1


# ---------------------------------------------------------------------------
# (e) a transform at release time refuses — WYSIWYE
# ---------------------------------------------------------------------------


def _notify_world():
    """A notify.send runtime: external + REVERSIBLE, so the transform rule can fire."""
    pip = _MutablePip(_facts())
    connector = _CountingConnector({"delivered": True})
    store = InMemoryStore()
    intent_store = InMemoryIntentStore()
    runtime, sink = _build(
        tool="notify",
        op="send",
        optable=_NOTIFY_OPTABLE,
        pip=pip,
        connector=connector,
        enforcement_store=store,
        intent_store=intent_store,
    )
    return runtime, sink, pip, connector, store, intent_store


def test_transform_at_release_refuses():
    """A release never runs anything other than the bytes the human saw."""
    runtime, _sink, pip, connector, _store, intent_store = _notify_world()
    # in-loop write with no transform available → held (rule 13).
    intent_id = _hold(
        runtime, intent_store, tool="notify", op="send", args={"body": "hello"}
    )

    # The envelope now offers a safer substitute; the PDP would downgrade the op.
    pip.facts = _facts(transform_op="draft")

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason.startswith(RELEASE_REFUSED_REASON_PREFIX)
    assert "transform" in result.rejection_reason
    assert connector.count == 0
    assert intent_store.get_intent(intent_id).status == "refused"


# ---------------------------------------------------------------------------
# (f) reject_intent is unchanged
# ---------------------------------------------------------------------------


def test_reject_intent_unchanged_by_revalidation():
    """An owner "no" still transitions to "rejected", executes nothing, draws no budget."""
    runtime, _sink, pip, connector, store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    reads_at_hold = pip.reads

    result = runtime.reject_intent(intent_id, rejected_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason == "rejected by owner"
    assert intent_store.get_intent(intent_id).status == "rejected"
    assert connector.count == 0
    # No revalidation on the reject path — nothing is being released.
    assert pip.reads == reads_at_hold
    assert store.read_counter(_action_cap_key("payments", "transfer")) == 0.0


def test_reject_after_a_refused_release_is_refused():
    """"refused" is terminal: an owner cannot then reject it."""
    runtime, _sink, pip, _connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    pip.facts = _facts(grant_present=False)
    assert runtime.approve_intent(intent_id, approved_by=_APPROVER).executed is False

    result = runtime.reject_intent(intent_id, rejected_by=_APPROVER)

    assert result.executed is False
    assert "not pending (current status: refused)" in result.rejection_reason


# ---------------------------------------------------------------------------
# A refused release is not a false action
# ---------------------------------------------------------------------------


def test_flag_refuses_a_refused_intent():
    """/flag labels ops that TOOK EFFECT; a refused release took none."""
    runtime, _sink, pip, _connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    pip.facts = _facts(grant_present=False)
    runtime.approve_intent(intent_id, approved_by=_APPROVER)

    result = runtime.flag_intent(intent_id, flagged_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason == "intent not executed (current status: refused)"


def test_describe_intent_reports_the_refused_status():
    """The approval surfaces read status through describe_intent; it must carry "refused"."""
    runtime, _sink, pip, _connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    pip.facts = _facts(grant_present=False)
    runtime.approve_intent(intent_id, approved_by=_APPROVER)

    view = runtime.describe_intent(intent_id)

    assert view is not None
    assert view.status == "refused"
    assert view.approved_by == _APPROVER


# ---------------------------------------------------------------------------
# A refused release records no promotion evidence
# ---------------------------------------------------------------------------


def test_refused_release_records_no_observation():
    """observations count ops that executed; a refused release executed nothing."""
    from safe_agents.broker.enforcement import OBSERVATIONS_SUFFIX

    runtime, _sink, pip, _connector, store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    pip.facts = _facts(grant_present=False)

    runtime.approve_intent(intent_id, approved_by=_APPROVER)

    obs_key = scoped_counter_key(
        _PRINCIPAL, "payments", "transfer", OBSERVATIONS_SUFFIX
    )
    assert store.read_counter(obs_key) == 0.0


@pytest.mark.parametrize(
    "moved_facts",
    [
        pytest.param(_facts(grant_present=False), id="grant-revoked"),
        pytest.param(_facts(cap_budget_breached=True), id="cap-breached"),
        pytest.param(_facts(human_reachable=False), id="no-human-reachable"),
    ],
)
def test_every_refusal_shape_leaves_the_connector_untouched(moved_facts):
    """Whatever moved, the release fails toward LESS authority: nothing runs."""
    runtime, _sink, pip, connector, _store, intent_store = _payments_world()
    intent_id = _hold(runtime, intent_store)
    pip.facts = moved_facts

    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason.startswith(RELEASE_REFUSED_REASON_PREFIX)
    assert connector.count == 0
    assert intent_store.get_intent(intent_id).status == "refused"
