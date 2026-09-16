"""Idempotency is a CLAIM taken before the side effect, not a record written after it.

The defect these tests pin: ``enforce()`` used to read the key at step 1 and write
the record at step 6, AFTER the executor had run. The conditional put is atomic in
all three backends, but applying it after the side effect deduplicates nothing —
two concurrent callers both read an absent key, both pass, and both execute. An
external reviewer reproduced exactly that: two concurrent calls on one key, two
side effects, both reporting ``idempotent=False``.

So the regression these tests defend is a side-effect COUNT under concurrency, not
a flag on a return value. A test that only asserts ``idempotent is True`` on the
second of two SEQUENTIAL calls passes against the broken code, which is why the
suite had one and the bug shipped anyway.

Everything runs against InMemoryStore and SqliteEnforcementStore — no AWS, no
moto. The DynamoDB half of the lifecycle is covered under moto in
test_core_store_differential.py (the claim/complete/fail conformance rows) and
test_dynamo_stores.py (the real ConditionExpressions).
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from safe_agents.broker.enforcement import InMemoryStore, enforce
from safe_agents.broker.enforcement.sqlite_store import SqliteEnforcementStore
from safe_agents.broker.enforcement.types import IdempotencyRecord
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import BrokeredCall
from safe_agents.broker.schemas.common import AutonomyLevel

# Wide enough that the losing thread's re-read lands squarely inside the winner's
# executor, which is the window the claim exists to cover. Small enough that the
# suite does not notice.
_EXECUTOR_DWELL_SECONDS = 0.05

COUNTER_KEY = "agent-1:email.send:capacity:2026-09"
CAP = 100.0
DELTA = 1.0

_PRINCIPAL = {"agentId": "agent-1", "skill": "email", "user": "alice", "tier": "B"}
_SESSION = {"turnId": "turn-1", "ingestedSources": []}
_TS = "2026-09-15T00:00:00Z"


def _call(reversible: bool | None = True) -> BrokeredCall:
    """An internal write — the PDP returns a plain allow for an out-of-loop grant."""
    return BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL,
            "tool": "email",
            "op": "send",
            "args": {},
            "manifest": {
                "tool": "email",
                "op": "send",
                "effect": "write",
                "external": False,
                "reversible": reversible,
            },
            "taint": {"tainted": False, "sources": []},
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


def _enforce(store, key: str | None, executor=None, *, facts: Facts | None = None):
    call = _call()
    world = facts or _facts()
    return enforce(
        call,
        decide(call, world),
        idempotency_key=key,
        counter_key=COUNTER_KEY,
        counter_delta=DELTA,
        counter_cap=CAP,
        decider=decide,
        fresh_facts=lambda _c: world,
        store=store,
        executor=executor,
    )


class _CountingExecutor:
    """Counts side effects and optionally dwells inside them, so a second caller
    arriving mid-flight finds the claim in flight rather than already settled."""

    def __init__(self, dwell: float = 0.0, hold: threading.Event | None = None) -> None:
        self.effects = 0
        self._dwell = dwell
        self._hold = hold
        self._lock = threading.Lock()
        # Set once the side effect has been counted; a caller that must arrive
        # DURING execution waits on this rather than on a sleep of its own.
        self.started = threading.Event()

    def __call__(self, call: BrokeredCall, decision: Any) -> dict:
        with self._lock:
            self.effects += 1
        self.started.set()
        if self._hold is not None:
            # Held open until the test says so, which makes "arrives mid-flight"
            # a fact rather than a bet on a sleep outlasting the other thread.
            assert self._hold.wait(timeout=10.0), "executor was never released"
        if self._dwell:
            time.sleep(self._dwell)
        return {"message_id": "msg-1"}


def _store_factories(tmp_path):
    """One entry per backend under test: a name and a zero-arg store factory.

    sqlite gets a FRESH store per call because its connections are single-thread,
    which is also the point — its claim atomicity has to come from BEGIN
    IMMEDIATE, not from an in-process lock a shared instance would provide. The
    file is bootstrapped once up front so the concurrent opens never race the
    journal_mode pragma (a setup artifact, not the behaviour under test).
    """
    db = tmp_path / "broker.db"
    SqliteEnforcementStore(db).read_counter("bootstrap")
    shared_memory = InMemoryStore()
    return [
        ("memory", lambda: shared_memory),
        ("sqlite", lambda: SqliteEnforcementStore(db)),
    ]


@pytest.fixture(params=["memory", "sqlite"])
def store_factory(request, tmp_path):
    return dict(_store_factories(tmp_path))[request.param]


# ===========================================================================
# The regression: a side-effect COUNT under concurrency
# ===========================================================================


def test_second_caller_during_execution_is_refused_in_flight(store_factory) -> None:
    """The exact shape the reviewer reproduced: caller two arrives while caller
    one's executor is still running. Before the claim it read an absent key and
    executed a SECOND side effect; now it finds the claim and is refused.

    The first executor is HELD open until the second caller has been answered, so
    the overlap is a fact of the test rather than a bet on one thread's sleep
    outlasting another thread's scheduling.
    """
    release = threading.Event()
    first_executor = _CountingExecutor(hold=release)
    second_executor = _CountingExecutor()
    outcomes: dict = {}

    def _first() -> None:
        outcomes["first"] = _enforce(store_factory(), "overlap-key", first_executor)

    worker = threading.Thread(target=_first)
    worker.start()
    assert first_executor.started.wait(timeout=5.0), "the first executor never ran"

    # Caller two, arriving mid-flight.
    second = _enforce(store_factory(), "overlap-key", second_executor)
    release.set()
    worker.join(timeout=5.0)
    assert not worker.is_alive()

    assert second.decision.kind == "deny"
    assert "in flight" in second.decision.reason, (
        f"the refused caller must say the key is in flight, got {second.decision.reason!r}"
    )
    assert second.idempotent is False, "a refusal is not a replay of a stored outcome"
    # It journaled no intent either: the refusal never reached the WAL.
    assert second.ledger_entry_id is None
    assert second_executor.effects == 0, "the second caller must not execute"

    assert outcomes["first"].decision.kind == "allow"
    assert outcomes["first"].result == {"message_id": "msg-1"}
    assert first_executor.effects == 1

    # And the settled claim replays: a third, sequential call adds no effect.
    third = _enforce(store_factory(), "overlap-key", second_executor)
    assert third.idempotent is True
    assert third.result == {"message_id": "msg-1"}
    assert second_executor.effects == 0, "a replay must not add a side effect"


def test_two_callers_racing_the_claim_execute_once(store_factory) -> None:
    """Both callers released from a barrier, so they contend on the conditional
    put itself rather than on an already-written claim.

    Which caller wins is genuinely a race, and so is whether the loser lands
    mid-flight (a deny) or after the winner settled (a replay) — asserting one of
    those two would be asserting the scheduler. What is NOT a race, and is the
    property under test: the side effect happens exactly once, and exactly one
    caller reports having executed it.
    """
    executor = _CountingExecutor(dwell=_EXECUTOR_DWELL_SECONDS)
    barrier = threading.Barrier(2)
    results: list = []
    results_lock = threading.Lock()

    def _worker() -> None:
        store = store_factory()
        barrier.wait(timeout=5.0)
        outcome = _enforce(store, "race-key", executor)
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)

    assert len(results) == 2
    assert executor.effects == 1, (
        f"the side effect ran {executor.effects} times under one idempotency key; "
        "exactly one caller may execute"
    )
    executed = [r for r in results if r.decision.kind == "allow" and not r.idempotent]
    assert len(executed) == 1, "exactly one caller may report having executed"
    assert executed[0].result == {"message_id": "msg-1"}

    other = next(r for r in results if r is not executed[0])
    assert (other.idempotent and other.result == {"message_id": "msg-1"}) or (
        other.decision.kind == "deny" and "in flight" in other.decision.reason
    ), f"the losing caller must replay or be refused, got {other}"


# ===========================================================================
# Claim lifecycle through enforce()
# ===========================================================================


class TestClaimLifecycle:
    def test_allow_settles_the_claim_as_executed(self) -> None:
        store = InMemoryStore()
        result = _enforce(store, "settle-allow", _CountingExecutor())

        assert result.decision.kind == "allow"
        stored = store.get_idempotency("settle-allow")
        assert stored is not None
        assert stored.status == "executed"
        assert stored.decision().kind == "allow"
        assert stored.result() == {"message_id": "msg-1"}
        assert stored.error is None

    def test_deny_releases_the_claim(self) -> None:
        """#148 holds: a deny executed nothing, so it leaves NO record at all —
        not an executed one to replay, and not a claim to block the retry."""
        store = InMemoryStore()
        store.try_increment_counter(COUNTER_KEY, CAP, CAP)  # cap at ceiling → deny
        executor = _CountingExecutor()

        first = _enforce(store, "settle-deny", executor)

        assert first.decision.kind == "deny"
        assert store.get_idempotency("settle-deny") is None, (
            "a deny must leave neither a record nor a claim"
        )
        assert executor.effects == 0

    def test_require_approval_releases_the_claim(self) -> None:
        store = InMemoryStore()
        held = _facts(grant_level=AutonomyLevel.in_loop, human_reachable=True)
        executor = _CountingExecutor()

        result = _enforce(store, "settle-appr", executor, facts=held)

        assert result.decision.kind == "require_approval"
        assert store.get_idempotency("settle-appr") is None
        assert executor.effects == 0

    def test_no_key_takes_no_claim(self) -> None:
        """idempotency_key=None skips the claim entirely — both calls execute."""
        store = InMemoryStore()
        executor = _CountingExecutor()

        _enforce(store, None, executor)
        _enforce(store, None, executor)

        assert executor.effects == 2


# ===========================================================================
# The uncertain outcome: an executor that raised burns its key
# ===========================================================================


class TestFailedClaim:
    @staticmethod
    def _boom(call: BrokeredCall, decision: Any) -> None:
        raise RuntimeError("connector timed out")

    def test_executor_failure_marks_the_claim_failed(self) -> None:
        store = InMemoryStore()

        with pytest.raises(RuntimeError, match="connector timed out"):
            _enforce(store, "burned", self._boom)

        stored = store.get_idempotency("burned")
        assert stored is not None
        assert stored.status == "failed"
        assert stored.error == "connector timed out"

    def test_retry_after_failure_is_refused_and_does_not_execute(self) -> None:
        """A local claim cannot know whether the external effect landed — a
        timeout on a transfer looks the same whether or not the money moved. So
        the retry is REFUSED rather than re-executed, and the reason says what
        the operator has to do."""
        store = InMemoryStore()
        with pytest.raises(RuntimeError):
            _enforce(store, "burned", self._boom)

        executor = _CountingExecutor()
        retry = _enforce(store, "burned", executor)

        assert retry.decision.kind == "deny"
        assert retry.idempotent is False
        assert executor.effects == 0, "a retry under a burned key must not execute"
        reason = retry.decision.reason
        assert "uncertain outcome" in reason
        assert "connector timed out" in reason, "the operator needs the original error"
        assert "NEW key" in reason

    def test_a_different_key_still_executes_after_a_failure(self) -> None:
        """The burn is per key, never a circuit breaker on the op."""
        store = InMemoryStore()
        with pytest.raises(RuntimeError):
            _enforce(store, "burned", self._boom)

        executor = _CountingExecutor()
        fresh = _enforce(store, "burned-reconciled", executor)

        assert fresh.decision.kind == "allow"
        assert executor.effects == 1

    def test_a_fault_before_execution_releases_the_claim(self) -> None:
        """Premise revalidation runs BEFORE any side effect, so a fault there
        cannot have executed anything: the key is released, not burned."""
        store = InMemoryStore()
        call = _call()
        world = _facts()

        def _exploding_facts(_c: BrokeredCall) -> Facts:
            raise RuntimeError("PIP unavailable")

        with pytest.raises(RuntimeError, match="PIP unavailable"):
            enforce(
                call,
                decide(call, world),
                idempotency_key="pip-fault",
                counter_key=COUNTER_KEY,
                counter_delta=DELTA,
                counter_cap=CAP,
                decider=decide,
                fresh_facts=_exploding_facts,
                store=store,
                executor=_CountingExecutor(),
            )

        assert store.get_idempotency("pip-fault") is None, (
            "nothing executed, so the key must stay retryable"
        )
        executor = _CountingExecutor()
        assert _enforce(store, "pip-fault", executor).decision.kind == "allow"
        assert executor.effects == 1


# ===========================================================================
# Rows written before the claim lifecycle
# ===========================================================================


class TestPreLifecycleRows:
    def test_executed_row_without_a_status_still_replays(self) -> None:
        """A record written by the pre-claim broker carries no status attribute.
        Every backend reads that absence as "executed" (the only writer that ever
        existed wrote the row after its executor returned), so the row replays
        exactly as it always did."""
        store = InMemoryStore()
        store.put_idempotency_if_absent(
            IdempotencyRecord(
                key="legacy-allow",
                decision_json='{"kind": "allow"}',
                ts="2026-07-08T00:00:00+00:00",
                result_json='{"message_id": "msg-legacy"}',
            )
        )
        executor = _CountingExecutor()

        replay = _enforce(store, "legacy-allow", executor)

        assert replay.idempotent is True
        assert replay.result == {"message_id": "msg-legacy"}
        assert executor.effects == 0

    def test_legacy_deny_row_is_evicted_and_the_key_is_reclaimed(self) -> None:
        """The #148 self-heal survives the claim: a stale non-executed record is
        neither replayed nor left to block the claim — it is deleted, the key is
        claimed fresh, and the retry's executed outcome settles it."""
        store = InMemoryStore()
        store.put_idempotency_if_absent(
            IdempotencyRecord(
                key="legacy-deny",
                decision_json='{"kind": "deny", "reason": "capacity budget breached"}',
                ts="2026-07-08T00:00:00+00:00",
            )
        )
        executor = _CountingExecutor()

        retry = _enforce(store, "legacy-deny", executor)

        assert retry.idempotent is False
        assert retry.decision.kind == "allow"
        assert executor.effects == 1
        stored = store.get_idempotency("legacy-deny")
        assert stored is not None
        assert stored.status == "executed"
        assert stored.decision().kind == "allow"
