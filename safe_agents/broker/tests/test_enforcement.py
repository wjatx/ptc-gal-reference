"""Tests for broker.enforcement — the execution-integrity layer.

All tests use InMemoryStore — no AWS credentials, no moto, no network.
The atomicity logic (compare-and-set) is exercised against the in-memory fake,
which uses threading.Lock to enforce the same CAS semantics as DynamoDB.

Acceptance criteria from #45:
  - Concurrent cap test: two calls vs an exhausted cap → exactly one succeeds.
  - Idempotency replay: same idempotency key → stored outcome returned, executor
    not called a second time.
  - Stale-premise test: grant demoted between decide() and enforce() → re-decision
    used, initial allow not blindly executed.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from safe_agents.broker.enforcement import InMemoryStore, enforce
from safe_agents.broker.enforcement.types import IdempotencyRecord
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import BrokeredCall
from safe_agents.broker.schemas.common import AutonomyLevel


# ---------------------------------------------------------------------------
# Shared builders — identical to the pattern used in test_pdp.py
# ---------------------------------------------------------------------------

_PRINCIPAL = {"agentId": "agent-1", "skill": "email", "user": "alice", "tier": "B"}
_SESSION = {"turnId": "turn-1", "ingestedSources": []}
_TS = "2026-06-28T00:00:00Z"


def _call(
    effect: str = "write",
    external: bool = False,
    reversible: bool | None = True,
    tainted: bool = False,
    tool: str = "email",
    op: str = "send",
    args: dict | None = None,
) -> BrokeredCall:
    return BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL,
            "tool": tool,
            "op": op,
            "args": args or {},
            "manifest": {
                "tool": tool,
                "op": op,
                "effect": effect,
                "external": external,
                "reversible": reversible,
            },
            "taint": {"tainted": tainted, "sources": []},
            "session": _SESSION,
            "ts": _TS,
        }
    )


def _facts(**overrides) -> Facts:
    defaults = {
        "grant_present": True,
        "grant_level": AutonomyLevel.out_of_loop,
        "error_budget_breached": False,
        "cap_budget_breached": False,
        "escalation_budget_available": True,
        "human_reachable": True,
        "transform_op": None,
    }
    defaults.update(overrides)
    return Facts(**defaults)


def _static_facts(**overrides):
    """Return a fresh_facts callable that always returns the same Facts."""
    f = _facts(**overrides)
    return lambda _call: f


# ---------------------------------------------------------------------------
# Acceptance test 1 — Concurrent cap: two calls vs exhausted cap
#
# The cap is set to 100 and the counter is pre-filled to 99.  Both calls
# attempt delta=1; the first succeeds (99+1=100 ≤ 100) and the second fails
# (100+1=101 > 100).  This validates the CAS semantics of try_increment_counter.
#
# Two variants:
#   a) serialized — verifies the math directly.
#   b) concurrent — runs both calls from separate threads, verifying that the
#      Lock prevents double-success under real concurrency.
# ---------------------------------------------------------------------------


COUNTER_KEY = "agent-1:email.send:capacity:2026-06"
CAP = 100.0
DELTA = 1.0


def _make_allow_call() -> BrokeredCall:
    """An internal reversible write — PDP returns allow for out-of-loop grant."""
    return _call(effect="write", external=False, reversible=True)


def _run_enforce(store: InMemoryStore, idem_key: str | None = None) -> str:
    """Run enforce() and return the effective decision kind."""
    call = _make_allow_call()
    initial = decide(call, _facts())
    result = enforce(
        call,
        initial,
        idempotency_key=idem_key,
        counter_key=COUNTER_KEY,
        counter_delta=DELTA,
        counter_cap=CAP,
        decider=decide,
        fresh_facts=_static_facts(),
        store=store,
    )
    return result.decision.kind


class TestAtomicCap:
    def test_serialized_first_succeeds_second_denied(self) -> None:
        """With 1 unit of headroom, the first call succeeds and the second is denied."""
        store = InMemoryStore()
        # Pre-fill the counter to leave exactly 1 unit of headroom.
        store.try_increment_counter(COUNTER_KEY, CAP - DELTA, CAP)
        assert store.read_counter(COUNTER_KEY) == CAP - DELTA

        kind1 = _run_enforce(store)
        kind2 = _run_enforce(store)

        assert kind1 == "allow", "first call should succeed"
        assert kind2 == "deny", "second call should be denied (cap exhausted)"
        assert store.read_counter(COUNTER_KEY) == CAP

    def test_concurrent_exactly_one_succeeds(self) -> None:
        """Two threads racing against 1 unit of headroom → exactly one succeeds."""
        store = InMemoryStore()
        store.try_increment_counter(COUNTER_KEY, CAP - DELTA, CAP)

        results: list[str] = []
        lock = threading.Lock()

        def _worker() -> None:
            kind = _run_enforce(store)
            with lock:
                results.append(kind)

        t1 = threading.Thread(target=_worker)
        t2 = threading.Thread(target=_worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 2
        assert results.count("allow") == 1, "exactly one thread should succeed"
        assert results.count("deny") == 1, "exactly one thread should be denied"

    def test_fresh_store_allows_up_to_cap(self) -> None:
        """Calls succeed exactly until the cap is reached."""
        store = InMemoryStore()
        cap = 3.0
        successes = 0
        for _ in range(4):
            call = _make_allow_call()
            initial = decide(call, _facts())
            result = enforce(
                call,
                initial,
                idempotency_key=None,
                counter_key="k",
                counter_delta=1.0,
                counter_cap=cap,
                decider=decide,
                fresh_facts=_static_facts(),
                store=store,
            )
            if result.decision.kind == "allow":
                successes += 1

        assert successes == int(cap), "should succeed exactly cap times"


# ---------------------------------------------------------------------------
# Acceptance test 2 — Idempotency replay
#
# First enforce() with key "idem-1" stores the outcome.
# Second enforce() with the same key returns the stored outcome without
# calling the executor a second time.
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_replay_returns_first_outcome(self) -> None:
        """Replaying the same idempotency key returns the first outcome."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())

        r1 = enforce(
            call,
            initial,
            idempotency_key="idem-1",
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
        )
        r2 = enforce(
            call,
            initial,
            idempotency_key="idem-1",
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
        )

        assert r1.decision.kind == r2.decision.kind
        assert r2.idempotent is True, "second call must be flagged as idempotent"

    def test_replay_does_not_call_executor_again(self) -> None:
        """The executor is NOT called on an idempotent replay."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())
        # Return a JSON-serializable result: the engine now persists it on the
        # idempotency record, so a bare MagicMock return would fail json.dumps.
        executor = MagicMock(return_value={})

        enforce(
            call,
            initial,
            idempotency_key="idem-2",
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=executor,
        )
        enforce(
            call,
            initial,
            idempotency_key="idem-2",
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=executor,
        )

        executor.assert_called_once(), "executor must be called exactly once, not on replay"

    def test_replay_returns_cached_result_executor_called_once(self) -> None:
        """Replay returns the SAME connector result (not None) and the executor
        runs exactly once — the sa#108 regression (replay handed back None)."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())

        calls: list[int] = []
        connector_result = {"event_id": "evt-idem", "status": "created"}

        def _executor(c: BrokeredCall, d: Any) -> dict:
            calls.append(1)
            return connector_result

        common = dict(
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=_executor,
        )
        r1 = enforce(call, initial, idempotency_key="idem-result", **common)
        r2 = enforce(call, initial, idempotency_key="idem-result", **common)

        assert r1.idempotent is False
        assert r1.result == connector_result
        assert r2.idempotent is True
        assert r2.result == connector_result, "replay must return the cached result, not None"
        assert len(calls) == 1, "executor must run exactly once, not on replay"

    def test_deny_is_not_recorded_retry_reevaluates(self) -> None:
        """A deny is NOT idempotency-recorded (#148): the record's purpose is
        exactly-once side effects and a deny executed nothing. A same-key retry
        re-enters premise revalidation instead of replaying the stale refusal."""
        store = InMemoryStore()
        # Cap already at ceiling → the initial allow is downgraded to deny.
        store.try_increment_counter(COUNTER_KEY, CAP, CAP)
        call = _make_allow_call()
        initial = decide(call, _facts())

        def _executor(c: BrokeredCall, d: Any) -> dict:
            raise AssertionError("executor must not run for a denied call")

        common = dict(
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=_executor,
        )
        r1 = enforce(call, initial, idempotency_key="idem-deny", **common)
        r2 = enforce(call, initial, idempotency_key="idem-deny", **common)

        assert r1.decision.kind == "deny"
        assert r1.result is None
        assert store.get_idempotency("idem-deny") is None, "deny must not be recorded"
        assert r2.idempotent is False, "retry must re-evaluate, not replay the deny"
        assert r2.decision.kind == "deny", "cause unchanged → still denied, freshly"
        assert r2.result is None

    def test_transient_deny_then_retry_executes(self) -> None:
        """The ta#13 cutover regression (#148): a transient deny (cap exhausted)
        must not poison the key forever. Once the cause clears — here the UTC-day
        counter rollover, modeled as a fresh scoped counter key — a retry with the
        SAME idempotency key executes and records the executed outcome."""
        store = InMemoryStore()
        # Today's counter is at ceiling → deny.
        store.try_increment_counter("counter#day-1", CAP, CAP)
        call = _make_allow_call()
        initial = decide(call, _facts())

        executed: list[int] = []

        def _executor(c: BrokeredCall, d: Any) -> dict:
            executed.append(1)
            return {"status": "sent"}

        common = dict(
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=_executor,
        )
        r1 = enforce(
            call, initial, idempotency_key="digest:2026-07-08",
            counter_key="counter#day-1", **common,
        )
        assert r1.decision.kind == "deny"
        assert executed == []

        # Next UTC day: the scoped counter key rolls over, capacity is back.
        r2 = enforce(
            call, initial, idempotency_key="digest:2026-07-08",
            counter_key="counter#day-2", **common,
        )
        assert r2.idempotent is False
        assert r2.decision.kind == "allow", "retry after the cause cleared must execute"
        assert r2.result == {"status": "sent"}
        assert executed == [1]

        # The executed outcome IS recorded: a third call replays it.
        r3 = enforce(
            call, initial, idempotency_key="digest:2026-07-08",
            counter_key="counter#day-2", **common,
        )
        assert r3.idempotent is True
        assert r3.result == {"status": "sent"}
        assert executed == [1], "replay must not re-execute"

    def test_stale_stored_deny_self_heals_on_read(self) -> None:
        """A PRE-#148 stored deny record (written by older broker code) must not
        replay: Step 1 ignores it, deletes it so the key becomes recordable
        again, and the retry's executed outcome is recorded normally."""
        store = InMemoryStore()
        # Seed a legacy deny record directly, as pre-#148 Step 6 would have.
        store.put_idempotency_if_absent(
            IdempotencyRecord(
                key="idem-legacy-deny",
                decision_json='{"kind": "deny", "reason": "capacity budget breached"}',
                ts="2026-07-08T00:00:00+00:00",
            )
        )
        call = _make_allow_call()
        initial = decide(call, _facts())
        executor = MagicMock(return_value={"status": "sent"})

        common = dict(
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
            executor=executor,
        )
        r1 = enforce(call, initial, idempotency_key="idem-legacy-deny", **common)

        assert r1.idempotent is False, "a stale deny must not replay"
        assert r1.decision.kind == "allow"
        assert r1.result == {"status": "sent"}
        executor.assert_called_once()

        stored = store.get_idempotency("idem-legacy-deny")
        assert stored is not None and stored.decision().kind == "allow", (
            "the executed outcome must replace the stale deny record"
        )

        r2 = enforce(call, initial, idempotency_key="idem-legacy-deny", **common)
        assert r2.idempotent is True, "the executed outcome now replays"
        executor.assert_called_once()

    def test_require_approval_is_not_recorded_retry_reevaluates(self) -> None:
        """A require_approval is NOT idempotency-recorded (#148): it executed
        nothing, and after the world changes (grant promoted, human approves) a
        retry must re-evaluate. Duplicate holds are the approval-queue dedup
        knob's concern (sa#160), not this record's."""
        store = InMemoryStore()
        call = _make_allow_call()
        # in-loop + human reachable → require_approval from the PDP.
        approval_facts = _facts(grant_level=AutonomyLevel.in_loop, human_reachable=True)
        initial = decide(call, approval_facts)
        assert initial.kind == "require_approval"

        def _executor(c: BrokeredCall, d: Any) -> dict:
            raise AssertionError("executor must not run for require_approval")

        common = dict(
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=lambda _c: approval_facts,
            store=store,
            executor=_executor,
        )
        r1 = enforce(call, initial, idempotency_key="idem-appr", **common)
        r2 = enforce(call, initial, idempotency_key="idem-appr", **common)

        assert r1.decision.kind == "require_approval"
        assert r1.result is None
        assert store.get_idempotency("idem-appr") is None, (
            "require_approval must not be recorded"
        )
        assert r2.idempotent is False, "retry must re-evaluate, not replay"
        assert r2.decision.kind == "require_approval"
        assert r2.result is None

    def test_distinct_keys_are_independent(self) -> None:
        """Two different idempotency keys are independent — both execute."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())
        # JSON-serializable result — persisted on each key's idempotency record.
        executor = MagicMock(return_value={})

        for key in ("key-A", "key-B"):
            enforce(
                call,
                initial,
                idempotency_key=key,
                counter_key=COUNTER_KEY,
                counter_delta=DELTA,
                counter_cap=CAP,
                decider=decide,
                fresh_facts=_static_facts(),
                store=store,
                executor=executor,
            )

        assert executor.call_count == 2, "distinct keys must each execute once"

    def test_none_key_skips_deduplication(self) -> None:
        """idempotency_key=None means no deduplication — both calls execute."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())
        executor = MagicMock()

        for _ in range(2):
            enforce(
                call,
                initial,
                idempotency_key=None,
                counter_key=COUNTER_KEY,
                counter_delta=DELTA,
                counter_cap=CAP,
                decider=decide,
                fresh_facts=_static_facts(),
                store=store,
                executor=executor,
            )

        assert executor.call_count == 2


# ---------------------------------------------------------------------------
# Acceptance test 3 — Stale premise
#
# The initial decide() returns "allow" (grant is out-of-loop).  By the time
# enforce() is called, the grant has been demoted to "in-loop".  Premise
# revalidation re-calls decide() with fresh Facts (in-loop, human reachable)
# and the enforcement must use the new "require_approval" decision rather than
# executing the stale "allow".
# ---------------------------------------------------------------------------


class TestStalePremise:
    def test_demoted_grant_triggers_re_decision(self) -> None:
        """Grant demoted between decide() and enforce() → re-decision, not blind execute."""
        store = InMemoryStore()
        call = _make_allow_call()

        # Initial facts: out-of-loop → decide() returns allow.
        initial_facts = _facts(grant_level=AutonomyLevel.out_of_loop)
        initial_decision = decide(call, initial_facts)
        assert initial_decision.kind == "allow"

        # By enforcement time the grant has been demoted to in-loop.
        # fresh_facts returns the demoted state.
        demoted_facts = _facts(
            grant_level=AutonomyLevel.in_loop,
            human_reachable=True,
        )

        result = enforce(
            call,
            initial_decision,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=lambda _c: demoted_facts,
            store=store,
        )

        assert result.decision.kind == "require_approval", (
            "demoted grant must produce require_approval, not allow"
        )

    def test_demoted_grant_does_not_call_executor(self) -> None:
        """When re-decision overrides allow → require_approval, executor is not called."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial_decision = decide(call, _facts(grant_level=AutonomyLevel.out_of_loop))
        assert initial_decision.kind == "allow"

        executor = MagicMock()
        demoted_facts = _facts(grant_level=AutonomyLevel.in_loop, human_reachable=True)

        enforce(
            call,
            initial_decision,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=lambda _c: demoted_facts,
            store=store,
            executor=executor,
        )

        executor.assert_not_called()

    def test_cap_exhausted_between_decide_and_enforce(self) -> None:
        """Counter exhausted between decide() and enforce() → deny, not blind execute."""
        store = InMemoryStore()
        # Pre-fill so the counter is already at cap.
        store.try_increment_counter(COUNTER_KEY, CAP, CAP)

        call = _make_allow_call()
        initial_decision = decide(call, _facts())
        assert initial_decision.kind == "allow"

        result = enforce(
            call,
            initial_decision,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
        )

        assert result.decision.kind == "deny"

    def test_fresh_facts_with_breached_budget_overrides_initial_allow(self) -> None:
        """If fresh Facts show an error-budget breach, re-decision overrides allow."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial_decision = decide(call, _facts())
        assert initial_decision.kind == "allow"

        # By enforcement time, the error budget is breached and escalation exhausted.
        stale_world = _facts(
            error_budget_breached=True,
            escalation_budget_available=False,
        )

        result = enforce(
            call,
            initial_decision,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=lambda _c: stale_world,
            store=store,
        )

        assert result.decision.kind == "deny"


# ---------------------------------------------------------------------------
# WAL (write-ahead ledger) behaviour
# ---------------------------------------------------------------------------


class TestWriteAheadLedger:
    def test_allow_commits_ledger_entry(self) -> None:
        """Successful allow → WAL entry committed."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())

        result = enforce(
            call,
            initial,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(),
            store=store,
        )

        assert result.ledger_entry_id is not None
        entry = store.get_ledger_entry(result.ledger_entry_id)
        assert entry is not None
        assert entry.status == "committed"

    def test_require_approval_leaves_entry_uncommitted(self) -> None:
        """require_approval → WAL entry stays uncommitted (HITL gate)."""
        store = InMemoryStore()
        # in-loop with human reachable → require_approval
        call = _make_allow_call()
        initial = decide(call, _facts(grant_level=AutonomyLevel.in_loop, human_reachable=True))
        assert initial.kind == "require_approval"

        result = enforce(
            call,
            initial,
            idempotency_key=None,
            counter_key=COUNTER_KEY,
            counter_delta=DELTA,
            counter_cap=CAP,
            decider=decide,
            fresh_facts=_static_facts(grant_level=AutonomyLevel.in_loop, human_reachable=True),
            store=store,
        )

        assert result.decision.kind == "require_approval"
        entry = store.get_ledger_entry(result.ledger_entry_id)
        assert entry.status == "uncommitted", (
            "HITL gate: ledger must stay uncommitted until human approves"
        )
        assert store.get_uncommitted_entries() == [entry]

    def test_executor_failure_compensates_reversible(self) -> None:
        """Executor failure on a reversible call → ledger entry compensated."""
        store = InMemoryStore()
        call = _make_allow_call()
        initial = decide(call, _facts())

        def _failing_executor(c: BrokeredCall, d: Any) -> None:
            raise RuntimeError("connector unavailable")

        with pytest.raises(RuntimeError):
            enforce(
                call,
                initial,
                idempotency_key=None,
                counter_key=COUNTER_KEY,
                counter_delta=DELTA,
                counter_cap=CAP,
                decider=decide,
                fresh_facts=_static_facts(),
                store=store,
                executor=_failing_executor,
            )

        uncommitted = store.get_uncommitted_entries()
        # No uncommitted entries — entry was compensated on failure.
        assert not uncommitted

    def test_executor_failure_escalates_irreversible(self) -> None:
        """Executor failure on an irreversible call → ledger entry escalated."""
        store = InMemoryStore()
        # External irreversible write; fresh_facts returns human reachable so
        # initial decision is require_approval — but we override via fresh_facts
        # to keep it allow for this test by making the revalidation also allow.
        # Use an internal irreversible write to get allow from the PDP.
        call = _call(effect="write", external=False, reversible=False)
        initial = decide(call, _facts(grant_level=AutonomyLevel.out_of_loop))
        assert initial.kind == "allow"

        def _failing_executor(c: BrokeredCall, d: Any) -> None:
            raise RuntimeError("write failed")

        with pytest.raises(RuntimeError):
            enforce(
                call,
                initial,
                idempotency_key=None,
                counter_key=COUNTER_KEY,
                counter_delta=DELTA,
                counter_cap=CAP,
                decider=decide,
                fresh_facts=_static_facts(grant_level=AutonomyLevel.out_of_loop),
                store=store,
                executor=_failing_executor,
            )

        uncommitted = store.get_uncommitted_entries()
        assert not uncommitted, "escalated entry should not appear as uncommitted"


# ---------------------------------------------------------------------------
# DynamoStore import — verifies lazy boto3 doesn't break the module load
# ---------------------------------------------------------------------------


def test_dynamo_store_importable_without_aws() -> None:
    """DynamoStore can be imported (not instantiated's _table) without AWS creds."""
    from safe_agents.broker.enforcement.store import DynamoStore

    ds = DynamoStore("some-table")
    # Accessing ds._table_name must not trigger boto3 import
    assert ds._table_name == "some-table"
    # DO NOT access ds._table — that would trigger lazy boto3 import
