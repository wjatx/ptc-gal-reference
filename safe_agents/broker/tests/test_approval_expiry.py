"""An approval that expires undecided is a recorded event (#163, PTC §6.12).

Pinned here, one test per piece of the clause:

  * the record: outcome "expired" (never "rejected" or "denied"), the stored call's
    coordinates, intentId, storedCallDigest, and expiredAt, the verified expiry
    instant; no actorDigest, approvedBy or evidenceBucket, because nobody acted;
  * expiry is found by a SWEEP, and judged on the verified intent at the sweep's
    instant (inclusive), never on the index attributes that nominated it;
  * exactly one record per intent, however late approvals, late rejections and
    sweeps interleave; an expired intent never executes;
  * an expiry adds nothing to observations, human_override or false_action;
  * the expiry period is fixed: it does not shorten as the queue grows.

The flood alarm's raised/cleared state and its delivery to the approver are in
test_approval_alarm.py. All in-memory; the per-backend candidate read is pinned in
test_core_store_differential.py::TestExpiryCandidates.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.engine import (
    DEFAULT_APPROVAL_EXPIRY_SECONDS,
    INTENT_EXPIRED_REASON,
    REJECTED_BY_OWNER_REASON,
)
from safe_agents.broker.approval.expiry import APPROVAL_EXPIRED_REASON
from safe_agents.broker.approval.store import principal_index_key
from safe_agents.broker.audit import hash_stored_call, verify_chain
from safe_agents.broker.enforcement import (
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    InMemoryStore,
)
from safe_agents.broker.runtime import AgentRequest, StubConnector
from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.envelope import ApprovalQueue
from safe_agents.broker.tests.test_runtime import (
    _PRINCIPAL,
    ENVELOPE_HASH,
    _make_grant,
    _make_pip,
    _make_runtime,
)

_UTC = datetime.UTC
_PROMOTION_EVIDENCE = (OBSERVATIONS_SUFFIX, HUMAN_OVERRIDE_SUFFIX, FALSE_ACTION_SUFFIX)
_OWNER = "owner:maintainer@example.com"


def _runtime(approval_queue=None, store=None):
    intent_store = InMemoryIntentStore()
    connector = StubConnector(result={"tx_id": "tx-released"})
    runtime, sink, _ = _make_runtime(
        [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)],
        connectors={"payments": connector},
        intent_store=intent_store,
        enforcement_store=store if store is not None else InMemoryStore(),
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        approval_queue=approval_queue,
    )
    return runtime, sink, intent_store, connector


def _hold(runtime, amount: int = 500) -> str:
    """A real hold through the runtime (payments.transfer always requires approval)."""
    response = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args={"amount": amount, "to": "acct-xyz"})
    )
    assert response.decision_kind == "require_approval"
    return response.intent_id


def _past_due(intent_store, intent_id: str = "intent-late", principal=_PRINCIPAL) -> Intent:
    """A pending hold whose expiry already passed on the wall clock.

    Written directly because the runtime's own holds expire an hour from now, and
    approve()/reject() judge expiry on the wall clock.
    """
    held_at = datetime.datetime.now(_UTC) - datetime.timedelta(hours=2)
    call = BrokeredCall.model_validate(
        {
            "principal": principal.model_dump(),
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 1, "to": "acct-x"},
            "manifest": {"tool": "payments", "op": "transfer", "effect": "write",
                         "external": True, "reversible": False},
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-x", "ingestedSources": []},
            "ts": held_at.isoformat(),
        }
    )
    intent = Intent(
        id=intent_id,
        materializedRequest=call,
        renderedForHuman="transfer 1 to acct-x",
        status="pending",
        expiry=(held_at + datetime.timedelta(seconds=DEFAULT_APPROVAL_EXPIRY_SECONDS)).isoformat(),
        ts=held_at.isoformat(),
    )
    intent_store.put_intent(intent)
    return intent


def _expiry_of(intent_store, intent_id: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(intent_store.get_intent(intent_id).expiry)


def _outcomes(sink, outcome: str):
    return [r for r in sink.records() if r.outcome == outcome]


def _the_one_expiry(sink):
    """The single expired record on the tape, or a failure naming what was written."""
    expired = _outcomes(sink, "expired")
    written = [(r.outcome, r.intentId) for r in sink.records()]
    assert len(expired) == 1, (
        f"exactly one expired record per intent, got {len(expired)}; the tape wrote {written}"
    )
    return expired[0]


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def test_sweep_records_an_undecided_expiry_as_its_own_outcome():
    runtime, sink, intent_store, connector = _runtime()
    intent_id = _hold(runtime)
    stored = intent_store.get_intent(intent_id)
    (hold,) = _outcomes(sink, "held")

    assert runtime.sweep_expired_intents(now=_expiry_of(intent_store, intent_id)) == 1

    record = _the_one_expiry(sink)
    assert record.decision == "require_approval"
    assert record.reason == APPROVAL_EXPIRED_REASON != REJECTED_BY_OWNER_REASON
    assert (record.principal, record.tool, record.op) == (_PRINCIPAL, "payments", "transfer")
    assert record.envelopeHash == ENVELOPE_HASH
    assert record.intentId == intent_id
    # Joined to the hold by the stored bytes, recomputed independently.
    assert record.storedCallDigest == hash_stored_call(stored.materializedRequest)
    assert record.storedCallDigest == hold.storedCallDigest
    # The instant: the intent's verified expiry, not the sweep's clock.
    assert record.expiredAt == stored.expiry
    # Nobody acted, and no evidence was written.
    assert record.actorDigest is None
    assert record.approvedBy is None
    assert record.evidenceBucket is None
    assert record.error is None
    assert _outcomes(sink, "rejected") == [] and _outcomes(sink, "denied") == []
    assert intent_store.get_intent(intent_id).status == "expired"
    assert connector.calls == []
    verify_chain(sink.records())


@pytest.mark.parametrize(
    "offset, expected",
    [
        (datetime.timedelta(microseconds=-1), 0),
        (datetime.timedelta(0), 1),  # inclusive: at the expiry instant it has expired
    ],
)
def test_sweep_judges_the_verified_expiry_at_its_own_instant(offset, expected):
    runtime, sink, intent_store, _ = _runtime()
    intent_id = _hold(runtime)
    at = _expiry_of(intent_store, intent_id) + offset
    assert runtime.sweep_expired_intents(now=at) == expected
    assert len(_outcomes(sink, "expired")) == expected


@pytest.mark.parametrize("forge_index", [False, True], ids=["honest-index", "forged-index"])
def test_sweep_leaves_other_principals_holds_alone(forge_index):
    """The index keys on the principal, and the verified stored call decides: a
    pending index attribute rewritten to name this runtime does not make another
    principal's hold its to expire (or to record on its tape)."""
    runtime, sink, intent_store, _ = _runtime()
    foreign = _PRINCIPAL.model_copy(update={"user": "mallory"})
    _past_due(intent_store, "intent-foreign", principal=foreign)
    if forge_index:
        intent_store._items["intent-foreign"]["pendingPrincipal"] = principal_index_key(_PRINCIPAL)
    assert runtime.sweep_expired_intents() == 0
    assert _outcomes(sink, "expired") == []
    assert intent_store.get_intent("intent-foreign").status == "pending"


def test_a_tampered_candidate_is_never_expired_and_surfaces_once():
    runtime, sink, intent_store, _ = _runtime()
    _past_due(intent_store)
    item = intent_store._items["intent-late"]
    intent_store._items["intent-late"] = {**item, "data": item["data"].replace("acct-x", "acct-z")}

    for _ in range(3):
        assert runtime.sweep_expired_intents() == 0

    quarantined = [r for r in sink.records() if r.tool == "intent-store" and r.op == "expire"]
    assert len(quarantined) == 1
    assert _outcomes(sink, "expired") == []
    assert intent_store._items["intent-late"]["status"] == "pending"


def test_the_index_nominates_but_the_verified_intent_decides():
    """A pending index attribute rewritten to look expired does not expire a live hold."""
    runtime, sink, intent_store, _ = _runtime()
    intent_id = _hold(runtime)
    intent_store._items[intent_id]["pendingExpiry"] = 0
    assert runtime.sweep_expired_intents() == 0
    assert intent_store.get_intent(intent_id).status == "pending"


# ---------------------------------------------------------------------------
# Exactly one record per intent, never executed
# ---------------------------------------------------------------------------


def _act(runtime, step: str):
    if step == "sweep":
        return runtime.sweep_expired_intents()
    if step == "approve":
        result = runtime.approve_intent("intent-late", approved_by=_OWNER)
    else:
        result = runtime.reject_intent("intent-late", rejected_by=_OWNER)
    assert result.executed is False
    return result


@pytest.mark.parametrize(
    "steps",
    [
        ("sweep",),
        ("sweep", "sweep"),
        ("approve",),
        ("reject",),
        ("sweep", "approve"),
        ("sweep", "reject"),
        ("approve", "sweep"),
        ("reject", "sweep"),
        ("approve", "reject", "approve", "sweep"),
    ],
    ids=lambda steps: "-".join(steps),
)
def test_one_expiry_record_per_intent_however_actions_interleave(steps):
    runtime, sink, intent_store, connector = _runtime()
    _past_due(intent_store)

    for step in steps:
        result = _act(runtime, step)
        if step != "sweep":
            assert result.rejection_reason == INTENT_EXPIRED_REASON

    record = _the_one_expiry(sink)
    assert record.intentId == "intent-late"
    assert record.actorDigest is None and record.approvedBy is None
    # A late "no" is not a human denial on the tape, and a late "yes" ran nothing.
    assert _outcomes(sink, "rejected") == []
    assert _outcomes(sink, "executed") == []
    assert connector.calls == []
    assert intent_store.get_intent("intent-late").status == "expired"
    verify_chain(sink.records())


# ---------------------------------------------------------------------------
# No promotion evidence
# ---------------------------------------------------------------------------


def _evidence_written(store: InMemoryStore) -> dict[str, float]:
    return {
        key: value
        for key, value in store._counters.items()
        if value and key.rsplit(":", 1)[-1] in _PROMOTION_EVIDENCE
    }


def test_the_evidence_probe_sees_a_real_rejection():
    """Positive control: the probe below is not blind to the counters it guards."""
    store = InMemoryStore()
    runtime, _, _, _ = _runtime(store=store)
    intent_id = _hold(runtime)
    runtime.reject_intent(intent_id, rejected_by=_OWNER)
    assert _evidence_written(store)


@pytest.mark.parametrize("steps", [("sweep",), ("approve",), ("reject",), ("sweep", "reject")])
def test_an_expiry_adds_nothing_to_promotion_evidence(steps):
    store = InMemoryStore()
    aq = ApprovalQueue(max_pending_per_op_day=1)  # alarm on: its counters are not evidence
    runtime, sink, intent_store, _ = _runtime(approval_queue=aq, store=store)
    _hold(runtime, amount=1)
    _hold(runtime, amount=2)  # past the cap: alarm raised
    _past_due(intent_store)
    for step in steps:
        _act(runtime, step)
    _the_one_expiry(sink)
    assert _evidence_written(store) == {}


# ---------------------------------------------------------------------------
# The expiry period never shortens with queue depth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("approval_queue", [None, ApprovalQueue(max_pending_per_op_day=2)])
def test_expiry_period_is_fixed_whatever_the_queue_depth(approval_queue):
    runtime, _, intent_store, _ = _runtime(approval_queue=approval_queue)
    periods = []
    for depth in range(8):  # well past the alarm cap
        intent = intent_store.get_intent(_hold(runtime, amount=depth + 1))
        held = datetime.datetime.fromisoformat(intent.ts)
        periods.append(datetime.datetime.fromisoformat(intent.expiry) - held)
    assert set(periods) == {datetime.timedelta(seconds=DEFAULT_APPROVAL_EXPIRY_SECONDS)}
