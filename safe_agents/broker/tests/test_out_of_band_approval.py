"""Tests for the out-of-band approval seam — BrokerRuntime.approve_intent / reject_intent (sa#176).

These are the FIRST production callers of the broker's approve()/reject() engine: the
"full release path" the channels drain worker invokes when an authenticated owner
actions a held Intent. They exercise the runtime (Doer + intent store + audit sink)
end-to-end, mirroring test_approval.py's style but through the public runtime surface.

All tests use in-memory fakes — no AWS, no network.

Proves:
  - approve_intent executes the STORED materializedRequest via the Doer and emits an
    executed-audit record (mirroring the inline allow footprint).
  - approve_intent refuses a not-found / expired / already-approved intent, executing nothing.
  - reject_intent transitions to "rejected" WITHOUT executing, and refuses a non-pending intent.
  - A failing connector on the release path emits a "failed" audit record and re-raises.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import hash_args, verify_chain
from safe_agents.broker.enforcement import (
    FALSE_ACTION_SUFFIX,
    InMemoryStore,
    scoped_counter_key,
)
from safe_agents.broker.runtime import (
    AgentRequest,
    ConnectorExecutionError,
    StubConnector,
)
from safe_agents.broker.runtime.pep import FLAGGED_BY_OWNER_REASON, _utc_bucket_of
from safe_agents.broker.schemas import BrokeredCall, Intent
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.envelope import ApprovalQueue
from safe_agents.broker.tests.test_runtime import _make_grant, _make_pip, _make_runtime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RaisingConnector:
    """A connector whose execute() always raises — for the failure-audit path."""

    def execute(self, tool, op, args, credential):  # noqa: ANN001, ANN201
        raise RuntimeError("connector boom")

    @property
    def calls(self):
        return []


def _materialize_held_intent(runtime, intent_store):
    """Drive a payments.transfer through the runtime to hold a pending Intent.

    payments.transfer is external + irreversible → the PDP always returns
    require_approval, so this is the natural way to land a real pending Intent in
    the store (WYSIWYE-frozen), exactly as production does.
    """
    response = runtime.handle_request(
        AgentRequest(tool="payments", op="transfer", args={"amount": 500, "to": "acct-xyz"})
    )
    assert response.decision_kind == "require_approval"
    intent = intent_store.get_intent(response.intent_id)
    assert intent is not None and intent.status == "pending"
    return response.intent_id


def _put_expired_intent(store: InMemoryIntentStore, intent_id: str) -> None:
    """Write a pending Intent with a past expiry directly (bypasses materialize())."""
    call = BrokeredCall.model_validate(
        {
            "principal": {"agentId": "agent-runtime-test", "skill": "general", "user": "alice", "tier": "B"},
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 1, "to": "acct-x"},
            "manifest": {"tool": "payments", "op": "transfer", "effect": "write", "external": True, "reversible": False},
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-x", "ingestedSources": []},
            "ts": "2026-06-28T00:00:00Z",
        }
    )
    store.put_intent(
        Intent(
            id=intent_id,
            materializedRequest=call,
            renderedForHuman="expired test intent",
            status="pending",
            expiry=(datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(),
            approvedBy=None,
            ts="2026-06-28T00:00:00Z",
        )
    )


def _payments_runtime():
    """A runtime granted payments.transfer with a fresh intent store + StubConnector."""
    grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
    connectors = {"payments": StubConnector(result={"tx_id": "tx-released"})}
    intent_store = InMemoryIntentStore()
    runtime, sink, stubs = _make_runtime(
        grants,
        connectors=connectors,
        intent_store=intent_store,
        pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
    )
    return runtime, sink, stubs, intent_store


# ---------------------------------------------------------------------------
# approve_intent — the full release path
# ---------------------------------------------------------------------------


class TestApproveIntent:
    def test_executes_stored_call_and_emits_executed_audit(self):
        """approve_intent runs the STORED call via the Doer and emits an executed-audit."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        result = runtime.approve_intent(intent_id, approved_by="owner:maintainer@example.com")

        assert result.executed is True
        assert result.intent_id == intent_id
        assert result.result == {"tx_id": "tx-released"}

        # The connector ran exactly once, on the STORED args (WYSIWYE).
        calls = stubs["payments"].calls
        assert len(calls) == 1
        assert calls[0].tool == "payments"
        assert calls[0].op == "transfer"
        assert calls[0].args == {"amount": 500, "to": "acct-xyz"}

        # Intent is terminal: executed, with the authenticated approver recorded.
        stored = intent_store.get_intent(intent_id)
        assert stored.status == "executed"
        assert stored.approvedBy == "owner:maintainer@example.com"

        # Audit footprint mirrors an inline allow: a "held" record then an
        # "executed"/"allow" record, and the chain stays valid.
        records = sink.records()
        assert [r.outcome for r in records] == ["held", "executed"]
        assert records[-1].decision == "allow"
        assert records[-1].outcome == "executed"
        verify_chain(records)

    def test_not_found_refuses_without_executing(self):
        """approve_intent on an unknown id refuses; no connector call."""
        runtime, sink, stubs, _ = _payments_runtime()

        result = runtime.approve_intent("intent-does-not-exist", approved_by="owner:maintainer")

        assert result.executed is False
        assert "not found" in result.rejection_reason
        assert len(stubs["payments"].calls) == 0

    def test_expired_refuses_without_executing(self):
        """approve_intent on an expired intent refuses; status → expired; no connector call."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        _put_expired_intent(intent_store, "intent-expired")

        result = runtime.approve_intent("intent-expired", approved_by="owner:maintainer")

        assert result.executed is False
        assert result.rejection_reason == "intent expired"
        assert intent_store.get_intent("intent-expired").status == "expired"
        assert len(stubs["payments"].calls) == 0

    def test_double_approval_refused(self):
        """A second approve_intent on the same intent refuses (already actioned)."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        first = runtime.approve_intent(intent_id, approved_by="owner:maintainer")
        second = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        assert first.executed is True
        assert second.executed is False
        assert second.rejection_reason is not None
        # Connector ran only once despite two approve calls.
        assert len(stubs["payments"].calls) == 1

    def test_connector_failure_emits_failed_audit_and_reraises(self):
        """A failing connector on the release path emits a 'failed' record and re-raises."""
        grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
        intent_store = InMemoryIntentStore()
        runtime, sink, _ = _make_runtime(
            grants,
            connectors={"payments": _RaisingConnector()},
            intent_store=intent_store,
            pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        )
        intent_id = _materialize_held_intent(runtime, intent_store)

        with pytest.raises(ConnectorExecutionError):
            runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        records = sink.records()
        assert records[-1].outcome == "failed"
        assert records[-1].decision == "allow"


# ---------------------------------------------------------------------------
# Intent-row tamper refusal (#349) — a store rewrite between hold and release
# ---------------------------------------------------------------------------


def _tamper_frozen_call(intent_store: InMemoryIntentStore, intent_id: str, args: dict) -> None:
    """Rewrite the frozen call inside the STORED bytes, as an A4 store-write
    attacker would: args replaced, the payload re-serialized in the exact
    canonical form the store uses. Every unkeyed field is recomputed
    consistently — which is why an unkeyed stored digest (#349 option 2) would
    not refuse this row; only the broker-held HMAC key does."""
    item = intent_store._items[intent_id]
    payload = json.loads(item["data"])
    payload["materializedRequest"]["args"] = args
    item["data"] = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


class TestIntentTamperQuarantine:
    """#349 — the release path verify-then-parses the stored intent bytes.

    Before this fix approve_intent executed the stored materializedRequest with
    no row-integrity check: a rewrite between hold and release EXECUTED, with
    only after-the-fact detection via the audit-tape digests. Now the read
    quarantines: refusal BEFORE execution, loudly surfaced, never auto-repaired.
    """

    EVIL_ARGS = {"amount": 999999, "to": "acct-attacker"}

    def test_approve_refuses_tampered_intent_without_executing(self, caplog):
        """The core #349 claim: tampered stored bytes → the release REFUSES,
        the Doer never runs, and the surfacing names the integrity mechanism."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        _tamper_frozen_call(intent_store, intent_id, self.EVIL_ARGS)

        with caplog.at_level(logging.ERROR, logger="safe_agents.broker.runtime.pep"):
            result = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        assert result.executed is False
        assert "intent quarantined" in result.rejection_reason
        assert "HMAC mismatch" in result.rejection_reason
        # The rewritten call NEVER reached the connector.
        assert len(stubs["payments"].calls) == 0
        # Never auto-repaired, never transitioned: the evidence stays in place.
        assert intent_store._items[intent_id]["status"] == "pending"
        # Loud + recorded: one tamper-evident audit record naming the mechanism
        # (mirroring the sa#124 grant-quarantine surfacing), one ERROR log.
        quarantine_records = [
            r for r in sink.records() if r.reason and "intent quarantined" in r.reason
        ]
        assert len(quarantine_records) == 1
        assert quarantine_records[0].intentId == intent_id
        assert "HMAC mismatch" in quarantine_records[0].reason
        verify_chain(sink.records())
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "quarantined" in errors[0].getMessage()

    def test_untampered_intent_still_releases(self):
        """Control: with no tamper, the same flow executes the stored call."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        result = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        assert result.executed is True
        assert len(stubs["payments"].calls) == 1
        assert stubs["payments"].calls[0].args == {"amount": 500, "to": "acct-xyz"}

    def test_reject_refuses_tampered_intent(self, caplog):
        """Consistency: the deny path also verify-then-parses (no transition)."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        _tamper_frozen_call(intent_store, intent_id, self.EVIL_ARGS)

        with caplog.at_level(logging.ERROR, logger="safe_agents.broker.runtime.pep"):
            result = runtime.reject_intent(intent_id, "owner:maintainer")

        assert result.executed is False
        assert "intent quarantined" in result.rejection_reason
        assert intent_store._items[intent_id]["status"] == "pending"

    def test_describe_refuses_tampered_intent(self, caplog):
        """describe_intent never renders tampered bytes — None, loudly surfaced."""
        runtime, sink, _, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        _tamper_frozen_call(intent_store, intent_id, self.EVIL_ARGS)

        with caplog.at_level(logging.ERROR, logger="safe_agents.broker.runtime.pep"):
            view = runtime.describe_intent(intent_id)

        assert view is None
        assert any(
            r.reason and "intent quarantined" in r.reason for r in sink.records()
        )
        assert any(
            "quarantined" in r.getMessage()
            for r in caplog.records
            if r.levelno == logging.ERROR
        )


# ---------------------------------------------------------------------------
# reject_intent — the owner-said-"no" path (no execution)
# ---------------------------------------------------------------------------


class TestRejectIntent:
    def test_transitions_to_rejected_without_executing(self):
        """reject_intent moves the intent to 'rejected' and never touches the connector."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        result = runtime.reject_intent(intent_id, "owner:maintainer@example.com")

        assert result.executed is False
        assert result.rejection_reason == "rejected by owner"
        stored = intent_store.get_intent(intent_id)
        assert stored.status == "rejected"
        assert stored.approvedBy == "owner:maintainer@example.com"
        # No connector call, and no executed/failed audit record was added.
        assert len(stubs["payments"].calls) == 0
        assert [r.outcome for r in sink.records()] == ["held"]

    def test_not_found_refuses(self):
        """reject_intent on an unknown id refuses with a not-found reason."""
        runtime, sink, stubs, _ = _payments_runtime()

        result = runtime.reject_intent("intent-does-not-exist", "owner:maintainer")

        assert result.executed is False
        assert "not found" in result.rejection_reason

    def test_non_pending_refused(self):
        """reject_intent on an already-actioned (executed) intent refuses."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")  # now executed

        result = runtime.reject_intent(intent_id, "owner:maintainer")

        assert result.executed is False
        assert "not pending" in result.rejection_reason
        # Still executed exactly once; reject did not run or alter anything.
        assert len(stubs["payments"].calls) == 1
        assert intent_store.get_intent(intent_id).status == "executed"


# ---------------------------------------------------------------------------
# The cross-principal confused-deputy guard (sa#176 M1)
# ---------------------------------------------------------------------------


def _put_foreign_intent(store: InMemoryIntentStore, intent_id: str, agent_id: str) -> None:
    """Write a pending, unexpired Intent frozen for a DIFFERENT principal.

    The intent store is not principal-partitioned, so a runtime bound to
    `_PRINCIPAL` (agentId 'agent-runtime-test') could be asked to action an
    intent whose materializedRequest belongs to `agent_id`. The M1 guard must
    refuse that before any transition.
    """
    call = BrokeredCall.model_validate(
        {
            "principal": {"agentId": agent_id, "skill": "general", "user": "mallory", "tier": "B"},
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 999, "to": "acct-attacker"},
            "manifest": {"tool": "payments", "op": "transfer", "effect": "write", "external": True, "reversible": False},
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-foreign", "ingestedSources": []},
            "ts": "2026-06-28T00:00:00Z",
        }
    )
    store.put_intent(
        Intent(
            id=intent_id,
            materializedRequest=call,
            renderedForHuman="an intent belonging to another principal",
            status="pending",
            expiry=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            approvedBy=None,
            ts="2026-06-28T00:00:00Z",
        )
    )


class TestReceipts:
    """#198 — durable approval binding + effect receipts on the audit chain.

    The core claim: intentId joins a hold to its release across the intent TTL, and
    hold-side == release-side storedCallDigest makes executed==approved byte-provable
    from durable state alone (WYSIWYE, post-hoc).
    """

    def test_hold_record_carries_intent_binding(self):
        """A fresh hold stamps intentId + the digest of the call being frozen."""
        runtime, sink, _, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        hold = sink.records()[-1]
        assert hold.outcome == "held"
        assert hold.intentId == intent_id
        assert hold.storedCallDigest is not None
        assert hold.storedCallDigest.startswith("sha256:")
        assert hold.resultDigest is None  # nothing executed yet

    def test_release_record_binds_to_hold(self):
        """The #198 core assertion: release.storedCallDigest == hold.storedCallDigest,
        plus approvedBy (the latent gap-A sub-bug: never stamped on this path before)
        and the effect receipt over the connector's actual result."""
        runtime, sink, _, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        result = runtime.approve_intent(intent_id, approved_by="owner@example.com")
        assert result.executed is True

        hold, release = sink.records()
        assert release.outcome == "executed"
        assert release.approvedBy == "owner@example.com"
        assert release.intentId == intent_id
        assert release.resultDigest == hash_args({"tx_id": "tx-released"})
        assert release.storedCallDigest == hold.storedCallDigest
        verify_chain(sink.records())

    def test_failed_release_still_carries_approval_binding(self):
        """An auditor must see WHICH approval led to a failed attempt — but there is
        no result, so no resultDigest."""
        grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
        intent_store = InMemoryIntentStore()
        runtime, sink, _ = _make_runtime(
            grants,
            connectors={"payments": _RaisingConnector()},
            intent_store=intent_store,
            pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        )
        intent_id = _materialize_held_intent(runtime, intent_store)

        with pytest.raises(ConnectorExecutionError):
            runtime.approve_intent(intent_id, approved_by="owner@example.com")

        hold, failed = sink.records()
        assert failed.outcome == "failed"
        assert failed.approvedBy == "owner@example.com"
        assert failed.intentId == intent_id
        assert failed.storedCallDigest == hold.storedCallDigest
        assert failed.resultDigest is None

    def test_coalesced_hold_carries_intent_id_without_digest(self):
        """A coalesced hold's frozen call is the EARLIER hold's — its binding lives
        on that record; the shared intentId is the join, so no second digest."""
        grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
        runtime, sink, _ = _make_runtime(
            grants,
            connectors={"payments": StubConnector()},
            pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
            approval_queue=ApprovalQueue(dedup=True),
        )
        # Identical args, distinct idempotency keys — content dedup coalesces them.
        args = {"amount": 500, "to": "acct-xyz"}
        r1 = runtime.handle_request(
            AgentRequest(tool="payments", op="transfer", args=args, idempotency_key="k1")
        )
        r2 = runtime.handle_request(
            AgentRequest(tool="payments", op="transfer", args=args, idempotency_key="k2")
        )
        assert r1.intent_id == r2.intent_id

        fresh, coalesced = sink.records()
        assert fresh.storedCallDigest is not None
        assert coalesced.reason == "approval-queue-coalesced"
        assert coalesced.intentId == r1.intent_id
        assert coalesced.storedCallDigest is None
        verify_chain(sink.records())

    def test_inline_allow_carries_result_digest_without_intent(self):
        """The inline allow path writes the effect receipt; no intent is involved."""
        grants = [_make_grant("calendar.create_event", level=AutonomyLevel.on_loop)]
        connectors = {"calendar": StubConnector(result={"event_id": "evt-198"})}
        runtime, sink, _ = _make_runtime(grants, connectors=connectors)

        response = runtime.handle_request(
            AgentRequest(tool="calendar", op="create_event", args={"title": "sync"})
        )
        assert response.decision_kind == "allow"

        executed = sink.records()[-1]
        assert executed.outcome == "executed"
        assert executed.resultDigest == hash_args({"event_id": "evt-198"})
        assert executed.intentId is None
        assert executed.storedCallDigest is None
        verify_chain(sink.records())


class _FlagRaisingStore:
    """Wraps an InMemoryStore but raises on the false_action counter write only.

    Isolates the flag's PRIMARY-effect write from its idempotency marker: the marker
    claim (a cap-1 counter whose key is prefixed 'flag-marker:') delegates unchanged,
    while the false_action back-write raises — so we prove flag_intent surfaces the
    write fault instead of swallowing it.
    """

    def __init__(self, inner):
        self._inner = inner

    def try_increment_counter(self, counter_key: str, delta: float, cap: float):
        if counter_key.endswith(f":{FALSE_ACTION_SUFFIX}"):
            raise RuntimeError("simulated false_action store fault")
        return self._inner.try_increment_counter(counter_key, delta, cap)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class TestFlagIntent:
    """#193 Phase 6c — flag_intent, the first writer of the false_action counter."""

    def test_flags_executed_intent(self):
        """A clean flag on an executed intent returns FLAGGED_BY_OWNER_REASON, no execution."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")  # now executed

        result = runtime.flag_intent(intent_id, flagged_by="owner:maintainer@example.com")

        assert result.executed is False
        assert result.intent_id == intent_id
        assert result.rejection_reason == FLAGGED_BY_OWNER_REASON
        # Flag runs no connector: still exactly the one approve-release call.
        assert len(stubs["payments"].calls) == 1

    def test_flag_meters_on_execution_day_across_midnight(self):
        """The false_action counter lands on the op's EXECUTION UTC day (executedAt), not
        the HOLD day — a hold that spans UTC-midnight otherwise back-dates the flag one day
        off the observation it offsets (#193 finding 4)."""
        grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
        connectors = {"payments": StubConnector(result={"tx_id": "tx-released"})}
        intent_store = InMemoryIntentStore()
        enforcement_store = InMemoryStore()
        runtime, _, _ = _make_runtime(
            grants,
            connectors=connectors,
            intent_store=intent_store,
            enforcement_store=enforcement_store,
            pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        )
        # Held on day D 23:50; executed on D+1 00:10 (a real UTC-midnight span).
        call = BrokeredCall.model_validate(
            {
                "principal": {"agentId": "agent-runtime-test", "skill": "general", "user": "alice", "tier": "B"},
                "tool": "payments",
                "op": "transfer",
                "args": {"amount": 5, "to": "acct-xyz"},
                "manifest": {"tool": "payments", "op": "transfer", "effect": "write", "external": True, "reversible": False},
                "taint": {"tainted": False, "sources": []},
                "session": {"turnId": "turn-mid", "ingestedSources": []},
                "ts": "2026-07-13T23:50:00+00:00",
            }
        )
        intent_store.put_intent(
            Intent(
                id="i-midnight",
                materializedRequest=call,
                renderedForHuman="a transfer held across midnight",
                status="executed",
                expiry="2026-07-14T00:50:00+00:00",
                approvedBy="owner:maintainer",
                ts="2026-07-13T23:50:00+00:00",
                executedAt="2026-07-14T00:10:00+00:00",
            )
        )

        result = runtime.flag_intent("i-midnight", flagged_by="owner:maintainer@example.com")
        assert result.rejection_reason == FLAGGED_BY_OWNER_REASON

        exec_day_key = scoped_counter_key(
            call.principal, "payments", "transfer", FALSE_ACTION_SUFFIX, day="20260714"
        )
        hold_day_key = scoped_counter_key(
            call.principal, "payments", "transfer", FALSE_ACTION_SUFFIX, day="20260713"
        )
        assert enforcement_store.read_counter(exec_day_key) == 1.0
        assert enforcement_store.read_counter(hold_day_key) == 0.0

    def test_approve_stamps_executed_at(self):
        """The approved→executed release records executedAt so /flag can meter on it."""
        runtime, _, _, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        executed = intent_store.get_intent(intent_id)
        assert executed.status == "executed"
        assert executed.executedAt is not None

    def test_clean_flag_emits_pii_safe_attribution_log(self, caplog):
        """flag_intent does not persist flagged_by, so it emits a PII-safe structured log
        (digested identity + day) for attribution (#193 finding 7)."""
        import json as _json

        runtime, _, _, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        with caplog.at_level("INFO", logger="safe_agents.broker.runtime.pep"):
            runtime.flag_intent(intent_id, flagged_by="owner:maintainer@example.com")

        flag_logs = [
            _json.loads(r.message)
            for r in caplog.records
            if r.name == "safe_agents.broker.runtime.pep" and '"intent_flagged"' in r.message
        ]
        assert len(flag_logs) == 1
        entry = flag_logs[0]
        assert entry["intent_id"] == intent_id
        assert entry["flagged_by_digest"].startswith("sha256:")
        # The clear identity never appears in the log surface.
        assert "owner@example.com" not in _json.dumps(entry)
        assert "bucket" in entry

    def test_utc_bucket_of_treats_naive_timestamp_as_utc(self):
        """A tz-naive timestamp is UTC, not broker-local: near midnight `.astimezone`
        on a naive datetime would shift the bucket (#193 finding 6)."""
        # 00:10 UTC belongs to the 14th; a naive value must not be read as local.
        assert _utc_bucket_of("2026-07-14T00:10:00") == "20260714"
        # tz-aware still respected.
        assert _utc_bucket_of("2026-07-14T00:10:00+00:00") == "20260714"
        assert _utc_bucket_of("2026-07-13T23:50:00Z") == "20260713"
        # #212 — the hour period buckets the same instants at hour granularity.
        assert _utc_bucket_of("2026-07-14T00:10:00", "utc-hour") == "20260714T00"
        assert _utc_bucket_of("2026-07-13T23:50:00Z", "utc-hour") == "20260713T23"

    def test_unknown_intent_refuses_without_writing(self):
        """flag_intent on an unknown id refuses."""
        runtime, sink, stubs, _ = _payments_runtime()

        result = runtime.flag_intent("intent-does-not-exist", flagged_by="owner:maintainer")

        assert result.executed is False
        assert "not found" in result.rejection_reason

    def test_foreign_intent_refused(self):
        """flag_intent must not touch another principal's intent (confused deputy)."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")

        result = runtime.flag_intent("intent-foreign", flagged_by="owner:maintainer")

        assert result.executed is False
        assert result.rejection_reason == "intent belongs to a different principal"

    def test_non_executed_intent_refused(self):
        """A still-pending (held, not yet approved) intent cannot be flagged."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)

        result = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

        assert result.executed is False
        assert "not executed" in result.rejection_reason
        assert intent_store.get_intent(intent_id).status == "pending"

    def test_rejected_intent_refused(self):
        """A rejected intent never executed → not flaggable."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.reject_intent(intent_id, "owner:maintainer")

        result = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

        assert result.executed is False
        assert "not executed" in result.rejection_reason

    def test_double_flag_refused(self):
        """A second /flag of the same intent is refused — the marker prevents double-count."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        first = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")
        second = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

        assert first.rejection_reason == FLAGGED_BY_OWNER_REASON
        assert second.executed is False
        assert second.rejection_reason == "intent already flagged"

    def test_counter_write_failure_surfaces(self):
        """The false_action write is the PRIMARY effect: a store fault returns a failed result."""
        grants = [_make_grant("payments.transfer", level=AutonomyLevel.on_loop)]
        connectors = {"payments": StubConnector(result={"tx_id": "tx-released"})}
        intent_store = InMemoryIntentStore()
        runtime, _, _ = _make_runtime(
            grants,
            connectors=connectors,
            intent_store=intent_store,
            enforcement_store=_FlagRaisingStore(InMemoryStore()),
            pip=_make_pip(grant_level=AutonomyLevel.on_loop, human_reachable=True),
        )
        intent_id = _materialize_held_intent(runtime, intent_store)
        runtime.approve_intent(intent_id, approved_by="owner:maintainer")

        result = runtime.flag_intent(intent_id, flagged_by="owner:maintainer")

        assert result.executed is False
        assert "flag counter write failed" in result.rejection_reason


class TestForeignIntentGuard:
    def test_approve_intent_refuses_foreign_principal_without_executing(self):
        """approve_intent must not release another principal's frozen call (confused deputy)."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")

        result = runtime.approve_intent("intent-foreign", approved_by="owner:maintainer")

        assert result.executed is False
        assert result.rejection_reason == "intent belongs to a different principal"
        # Never claimed, never executed: still pending, no connector call, no audit spend.
        assert intent_store.get_intent("intent-foreign").status == "pending"
        assert len(stubs["payments"].calls) == 0
        assert [r.outcome for r in sink.records()] == []

    def test_reject_intent_refuses_foreign_principal(self):
        """reject_intent must not touch another principal's intent either."""
        runtime, sink, stubs, intent_store = _payments_runtime()
        _put_foreign_intent(intent_store, "intent-foreign", agent_id="agent-someone-else")

        result = runtime.reject_intent("intent-foreign", "owner:maintainer")

        assert result.executed is False
        assert result.rejection_reason == "intent belongs to a different principal"
        # Untouched — the foreign intent stays pending, not flipped to "rejected".
        assert intent_store.get_intent("intent-foreign").status == "pending"
