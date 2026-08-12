"""Tests for the PEP evidence-counter writers — observations + human_override (#193).

Slice B of #193: the broker PEP is the sole writer of the promotion-evidence counters.
Three write sites, all proven here through the public runtime surface:

  1. inline allow/transform execution → one `observations` increment per successfully
     executed op (reads and writes both), written LAST in the executor.
  2. approve_intent release (the out-of-band approve path that bypasses enforce()) →
     one `observations` increment, so an in-loop principal whose acting ops all route
     require_approval → approve-release can still accumulate promotion evidence.
  3. reject_intent on a CAS win → one `human_override` AND one `observations` increment
     (each terminal labeled outcome is an observation, keeping overrides/observations <= 1).

A denied op, a require_approval hold, a missing/foreign intent, and an idempotent replay
must NOT move any counter. And a label write must NEVER gate the op it labels: a store
fault on any of the three increments is logged and swallowed — the op/rejection still
completes. All tests use in-memory fakes — no AWS, no network.

Counter reads use read_counter_window(..., 2) (today + yesterday) so a UTC-midnight
rollover between the write and the assert can never split the window.
"""

from __future__ import annotations

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.engine import REJECTED_BY_OWNER_REASON
from safe_agents.broker.enforcement import (
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    InMemoryStore,
    read_counter_window,
    scoped_counter_key,
)
from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.runtime import AgentRequest, StubConnector
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.tests.test_out_of_band_approval import (
    _materialize_held_intent,
    _put_foreign_intent,
)
from safe_agents.broker.tests.test_runtime import (
    _PRINCIPAL,
    _make_grant,
    _make_pip,
    _make_runtime,
)

_WINDOW_DAYS = 2  # today + yesterday — midnight-rollover-proof for point-in-time asserts


def _obs(store, tool: str, op: str) -> float:
    return read_counter_window(store, _PRINCIPAL, tool, op, OBSERVATIONS_SUFFIX, _WINDOW_DAYS)


def _override(store, tool: str, op: str) -> float:
    return read_counter_window(store, _PRINCIPAL, tool, op, HUMAN_OVERRIDE_SUFFIX, _WINDOW_DAYS)


class _EvidenceRaisingStore:
    """Wraps an InMemoryStore but raises on evidence-LABEL increments only.

    Simulates a counters-table fault confined to the #193 label writes (observations,
    human_override). Every other operation — the action-cap / query-bytes / error-budget
    meters, idempotency records, WAL — delegates unchanged, so we isolate exactly the
    failure the guards must swallow. Detection is by the key's suffix segment
    (scoped_counter_key ends the key with ``:{suffix}``).
    """

    _RAISING_SUFFIXES = (OBSERVATIONS_SUFFIX, HUMAN_OVERRIDE_SUFFIX)

    def __init__(self, inner: InMemoryStore) -> None:
        self._inner = inner

    def try_increment_counter(self, counter_key: str, delta: float, cap: float):
        if any(counter_key.endswith(f":{s}") for s in self._RAISING_SUFFIXES):
            raise RuntimeError("simulated evidence-counter store fault")
        return self._inner.try_increment_counter(counter_key, delta, cap)

    def __getattr__(self, name):
        # Delegate everything else (read_counter, idempotency, WAL) to the real store.
        return getattr(self._inner, name)


def _calendar_runtime(store):
    """A runtime granted calendar.create_event (internal write → plain allow)."""
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    connectors = {"calendar": StubConnector(result={"event_id": "evt-1"})}
    runtime, sink, _ = _make_runtime(grants, connectors=connectors, enforcement_store=store)
    return runtime, sink


def _payments_runtime_with_store(store):
    """A payments.transfer runtime (external+irreversible → require_approval) whose
    enforcement store is caller-held so the evidence counters can be read back."""
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    connectors = {"payments": StubConnector(result={"tx_id": "tx-released"})}
    intent_store = InMemoryIntentStore()
    runtime, sink, _ = _make_runtime(
        grants,
        connectors=connectors,
        intent_store=intent_store,
        enforcement_store=store,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
    )
    return runtime, sink, intent_store


# ---------------------------------------------------------------------------
# 1 — inline execution path
# ---------------------------------------------------------------------------


def test_executed_allow_increments_observations_once_then_twice():
    """Each successfully executed inline allow adds exactly one observation."""
    store = InMemoryStore()
    runtime, _ = _calendar_runtime(store)

    runtime.handle_request(
        AgentRequest(tool="calendar", op="create_event", args={"title": "a"}, idempotency_key="k1")
    )
    assert _obs(store, "calendar", "create_event") == 1.0

    runtime.new_turn()
    runtime.handle_request(
        AgentRequest(tool="calendar", op="create_event", args={"title": "b"}, idempotency_key="k2")
    )
    assert _obs(store, "calendar", "create_event") == 2.0


def test_denied_op_does_not_increment_observations():
    """A deny (no human reachable for the approval-bound op) executes nothing → no observation."""
    store = InMemoryStore()
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    runtime, _, _ = _make_runtime(
        grants,
        connectors={"payments": StubConnector()},
        enforcement_store=store,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=False),
    )

    response = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args={"amount": 1, "to": "x"}, idempotency_key="d1")
    )

    assert response.decision_kind == "deny"
    assert _obs(store, "payments", "transfer") == 0.0


def test_require_approval_hold_does_not_increment_observations():
    """A held (require_approval) intent has executed nothing yet → no observation."""
    store = InMemoryStore()
    runtime, _, _ = _payments_runtime_with_store(store)

    response = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args={"amount": 1, "to": "x"}, idempotency_key="h1")
    )

    assert response.decision_kind == "require_approval"
    assert _obs(store, "payments", "transfer") == 0.0


def test_idempotent_replay_does_not_double_count_observations():
    """enforce()'s idempotency short-circuit runs before the executor → a replay never re-counts."""
    store = InMemoryStore()
    runtime, _ = _calendar_runtime(store)
    request = AgentRequest(
        tool="calendar", op="create_event", args={"title": "idem"}, idempotency_key="same-key"
    )

    first = runtime.handle_request(request)
    assert first.idempotent is False
    assert _obs(store, "calendar", "create_event") == 1.0

    second = runtime.handle_request(request)
    assert second.idempotent is True
    assert _obs(store, "calendar", "create_event") == 1.0


# ---------------------------------------------------------------------------
# 2 — approve-release path
# ---------------------------------------------------------------------------


def test_approve_intent_release_increments_observations():
    """The out-of-band approve-release (bypasses enforce()) still records one observation
    under the STORED call's coordinates — the seam that lets an in-loop principal promote."""
    store = InMemoryStore()
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)
    assert _obs(store, "payments", "transfer") == 0.0  # hold did not count

    result = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    assert result.executed is True
    assert _obs(store, "payments", "transfer") == 1.0


# ---------------------------------------------------------------------------
# 3 — reject path (human_override + observations, CAS win only)
# ---------------------------------------------------------------------------


def test_reject_intent_cas_win_increments_override_and_observations():
    """A real owner "no" on a live held intent labels one human_override and one observation."""
    store = InMemoryStore()
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)

    result = runtime.reject_intent(intent_id, "owner:maintainer")

    assert result.executed is False
    assert _override(store, "payments", "transfer") == 1.0
    assert _obs(store, "payments", "transfer") == 1.0


def test_reject_intent_missing_intent_does_not_increment():
    """reject_intent on an unknown id is not a CAS win → no counters move."""
    store = InMemoryStore()
    runtime, _, _ = _payments_runtime_with_store(store)

    result = runtime.reject_intent("intent-does-not-exist", "owner:maintainer")

    assert result.executed is False
    assert _override(store, "payments", "transfer") == 0.0
    assert _obs(store, "payments", "transfer") == 0.0


def test_reject_intent_foreign_principal_does_not_increment():
    """A foreign-principal intent is refused before any transition → no counters move,
    and nothing is written under EITHER principal's coordinates."""
    store = InMemoryStore()
    runtime, _, intent_store = _payments_runtime_with_store(store)
    _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")

    result = runtime.reject_intent("intent-foreign", "owner:maintainer")

    assert result.executed is False
    assert result.rejection_reason == "intent belongs to a different principal"
    assert _override(store, "payments", "transfer") == 0.0
    assert _obs(store, "payments", "transfer") == 0.0


# ---------------------------------------------------------------------------
# 4 — a label write must never gate the op it labels (friction doctrine)
# ---------------------------------------------------------------------------


def test_inline_execute_survives_raising_evidence_store():
    """A counter fault on the inline observations write does NOT fail the call: the op
    still returns its result and enforce() still records the idempotency outcome
    (a replay short-circuits, proving the outcome was persisted)."""
    store = _EvidenceRaisingStore(InMemoryStore())
    runtime, _ = _calendar_runtime(store)
    request = AgentRequest(
        tool="calendar", op="create_event", args={"title": "boom"}, idempotency_key="raise-1"
    )

    first = runtime.handle_request(request)
    assert first.decision_kind == "allow"
    assert first.result == {"event_id": "evt-1"}
    assert first.idempotent is False
    # Idempotency outcome was recorded despite the label fault → replay short-circuits.
    second = runtime.handle_request(request)
    assert second.idempotent is True


def test_approve_release_survives_raising_evidence_store():
    """A counter fault on the approve-release observations write does NOT strand the
    intent: the side effect ran, the release still reports executed, and the intent
    transitions to 'executed'."""
    store = _EvidenceRaisingStore(InMemoryStore())
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)

    result = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    assert result.executed is True
    assert intent_store.get_intent(intent_id).status == "executed"


def test_reject_survives_raising_evidence_store():
    """A counter fault on the reject labels does NOT undo the rejection: reject still
    reports the CAS win and the intent is terminally 'rejected'."""
    store = _EvidenceRaisingStore(InMemoryStore())
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)

    result = runtime.reject_intent(intent_id, "owner:maintainer")

    assert result.executed is False
    assert result.rejection_reason == REJECTED_BY_OWNER_REASON
    assert intent_store.get_intent(intent_id).status == "rejected"


# ---------------------------------------------------------------------------
# 5 — flag path (false_action, first writer; #193 Phase 6c)
# ---------------------------------------------------------------------------


def _false_action(store, tool: str, op: str, *, window: int = _WINDOW_DAYS) -> float:
    return read_counter_window(store, _PRINCIPAL, tool, op, FALSE_ACTION_SUFFIX, window)


def _put_executed_intent(store: InMemoryIntentStore, intent_id: str, ts: str) -> None:
    """Write a terminal 'executed' intent for _PRINCIPAL with a chosen creation ts.

    Bypasses the hold→approve flow so a test can pin the intent's day-key (its ts) to
    an arbitrary UTC day and prove the flag back-writes false_action on THAT day.
    """
    call = BrokeredCall.model_validate(
        {
            "principal": {
                "agentId": "agent-runtime-test",
                "skill": "general",
                "user": "alice",
                "tier": "B",
            },
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 7, "to": "acct-flag"},
            "manifest": {
                "tool": "payments",
                "op": "transfer",
                "effect": "write",
                "external": True,
                "reversible": False,
            },
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-flag", "ingestedSources": []},
            "ts": ts,
        }
    )
    store.put_intent(
        Intent(
            id=intent_id,
            materializedRequest=call,
            renderedForHuman="an executed transfer under review",
            status="executed",
            expiry="2030-01-01T00:00:00Z",
            approvedBy="owner:maintainer",
            ts=ts,
        )
    )


def test_flag_increments_false_action_under_stored_coordinates():
    """A clean flag adds exactly one false_action under the STORED (principal, tool, op),
    and moves NO observations counter (the op was counted when it executed)."""
    store = InMemoryStore()
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    obs_before = _obs(store, "payments", "transfer")
    result = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

    assert result.rejection_reason is not None
    assert _false_action(store, "payments", "transfer") == 1.0
    # The flag never touches observations.
    assert _obs(store, "payments", "transfer") == obs_before


def test_flag_back_writes_false_action_on_the_original_day():
    """A flag arriving days later lands false_action on the intent's OWN day-key, not today."""
    store = InMemoryStore()
    intent_store = InMemoryIntentStore()
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    runtime, _, _ = _make_runtime(
        grants,
        connectors={"payments": StubConnector(result={"tx_id": "t"})},
        intent_store=intent_store,
        enforcement_store=store,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
    )
    # An intent whose op executed on a fixed past UTC day.
    original_day = "20260601"
    _put_executed_intent(intent_store, "intent-old", ts="2026-06-01T12:00:00Z")

    result = runtime.flag_intent("intent-old", flagged_by="owner:maintainer")
    assert result.rejection_reason is not None

    # Landed on the original day's key exactly...
    key = scoped_counter_key(
        _PRINCIPAL, "payments", "transfer", FALSE_ACTION_SUFFIX, day=original_day
    )
    assert store.read_counter(key) == 1.0
    # ...and NOT on today's key (a wide window that INCLUDES the original day sums it;
    # a same-day-only read would miss a back-dated write).
    assert _false_action(store, "payments", "transfer", window=2) == 0.0


def test_double_flag_counts_false_action_once():
    """The idempotency marker keeps a re-flag from double-counting the evidence."""
    store = InMemoryStore()
    runtime, _, intent_store = _payments_runtime_with_store(store)
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    runtime.flag_intent(intent_id, flagged_by="owner:maintainer")
    runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

    assert _false_action(store, "payments", "transfer") == 1.0


def test_flag_ttl_deleted_intent_refuses_with_zero_writes():
    """A /flag against a TTL-deleted intent refuses gracefully and writes NOTHING.

    Executed intents retain only 7 days (sa#213 executed-intent-retention-7d); after
    DynamoDB TTL deletion the point read cannot distinguish TTL-deleted from
    never-existed, so BOTH must take the same path: a not-found refusal BEFORE the
    idempotency-marker claim — no marker, no false_action, no counter of any kind.
    A marker claimed here would poison a later legitimate flow; a false_action would
    be evidence against an op nobody reviewed (#204 tracks the coordinate form for
    flagging past the retention window)."""
    store = InMemoryStore()
    runtime, _, _ = _payments_runtime_with_store(store)

    result = runtime.flag_intent("intent-ttl-deleted-long-ago", flagged_by="owner:maintainer")

    assert result.executed is False
    assert "not found" in result.rejection_reason
    assert _false_action(store, "payments", "transfer") == 0.0
    # The refusal precedes the marker claim: the store saw ZERO counter writes.
    assert store._counters == {}


# ---------------------------------------------------------------------------
# #212 — the counter period threads from the manifest into every PEP write
# ---------------------------------------------------------------------------


def test_hour_period_runtime_writes_evidence_on_hour_buckets():
    """A runtime built with counter_period=utc-hour labels evidence on the hour
    bucket — visible to an hour-period window read, INVISIBLE to a day-period
    read (period-in-key: the formats are disjoint, so a mismatch reads zero,
    never a wrong sum)."""
    store = InMemoryStore()
    grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
    connectors = {"calendar": StubConnector(result={"event_id": "evt-1"})}
    runtime, _, _ = _make_runtime(
        grants, connectors=connectors, enforcement_store=store,
        counter_period="utc-hour",
    )

    runtime.handle_request(
        AgentRequest(tool="calendar", op="create_event", args={"title": "a"}, idempotency_key="h1")
    )

    hour_window = read_counter_window(
        store, _PRINCIPAL, "calendar", "create_event", OBSERVATIONS_SUFFIX, 2,
        period="utc-hour",
    )
    assert hour_window == 1.0
    # The day-period read sees nothing — the evidence lives on the hour key.
    assert _obs(store, "calendar", "create_event") == 0.0
