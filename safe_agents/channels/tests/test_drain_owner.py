"""sa#176 — the drain-side human-as-owner approval fork conformance.

Independent suite for the ``_process_record`` owner fork (channels/drain/handler.py).
Mirrors test_drain_handler.py's harness (fake BrokerRuntime via the ``_build_runtime``
seam, spy Receiver via the real provider loader), extended with a runtime that also
records ``approve_intent``/``reject_intent`` so the fork is observable.

Targets (from the sa#176 design answers Q3):
  4   owner COMMAND -> normal agent turn (NOT the approval fork); no owner auto-allow.
  5a  owner /approve -> release path (approve_intent); receiver path NOT taken.
  5b  approval-shaped payload from a NON-owner class -> does NOT fork (forge-safety):
      the fork keys on the unforgeable gate-8 sender_class, never on payload shape.
"""

import json
from dataclasses import dataclass
from typing import Any

import pytest

import safe_agents.channels.drain.handler as h
from safe_agents.broker.taint import TurnContext, build_trust_map

_TS = "2026-07-11T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"

_MANIFEST_YAML = """\
principal:
  agentId: example-agent
  skill: demo
  user: demo-user
  tier: B
envelope:
  polarity: abstain
"""


@dataclass(frozen=True)
class _FakeExecResult:
    """The ExecutionResult surface the handler reads: only ``.executed``."""

    executed: bool


@dataclass(frozen=True)
class _ProbeRequest:
    tool: str = "probe"
    op: str = "observe"
    args: Any = None
    idempotency_key: str | None = None


class OwnerFakeRuntime:
    """Broker surface the owner fork touches: approve/reject_intent + the turn path.

    Records every fork-relevant call so a test can assert which branch ran. The
    normal-turn path exercises session_turn()/handle_request() exactly like the
    upstream FakeRuntime; the fork path exercises approve_intent()/reject_intent().
    """

    def __init__(self) -> None:
        self._turn: TurnContext | None = None
        self.requests: list[Any] = []
        self.approve_calls: list[tuple[str, str]] = []
        self.reject_calls: list[tuple[str, str]] = []
        self.flag_calls: list[tuple[str, str]] = []

    def session_turn(self) -> TurnContext:
        if self._turn is None:
            self._turn = TurnContext(turn_id="turn:owner-test")
        return self._turn

    def handle_request(self, request: Any) -> dict:
        self.requests.append(request)
        return {"decision_kind": "allow"}

    def approve_intent(self, intent_id: str, approved_by: str) -> _FakeExecResult:
        self.approve_calls.append((intent_id, approved_by))
        return _FakeExecResult(executed=True)

    def reject_intent(self, intent_id: str, rejected_by: str) -> _FakeExecResult:
        self.reject_calls.append((intent_id, rejected_by))
        return _FakeExecResult(executed=False)

    def flag_intent(self, intent_id: str, flagged_by: str) -> _FakeExecResult:
        self.flag_calls.append((intent_id, flagged_by))
        return _FakeExecResult(executed=False)


class OwnerSpyReceiver:
    """Consumer-side spy: records deliveries and acts through the facade.

    ``calls`` is class-level so the zero-arg loader instance stays observable.
    """

    calls: list[dict] = []
    trusted_prefixes: list[str] = ["owner:", "channel:"]

    def input_trust_map(self):
        return build_trust_map(trusted_prefixes=list(type(self).trusted_prefixes))

    def receive(self, envelope, runtime) -> None:
        type(self).calls.append({"event_id": envelope.event_id, "runtime": runtime})
        runtime.handle_request(_ProbeRequest())


_SPY_PATH = f"{__name__}:OwnerSpyReceiver"


@pytest.fixture
def wired(monkeypatch, tmp_path):
    manifest_path = tmp_path / "drain-manifest.yaml"
    manifest_path.write_text(_MANIFEST_YAML)
    monkeypatch.setenv("CHANNELS_DRAIN_MANIFEST", str(manifest_path))
    monkeypatch.setenv("CHANNELS_DRAIN_RECEIVER", _SPY_PATH)

    runtimes: list[OwnerFakeRuntime] = []

    def _fake_build_runtime(manifest):
        runtime = OwnerFakeRuntime()
        runtimes.append(runtime)
        return runtime

    monkeypatch.setattr(h, "_build_runtime", _fake_build_runtime)
    monkeypatch.setattr(h, "_STATE", None)
    OwnerSpyReceiver.calls = []
    OwnerSpyReceiver.trusted_prefixes = ["owner:", "channel:"]

    yield runtimes

    h._STATE = None
    OwnerSpyReceiver.calls = []


def _owner_body(
    *,
    payload: dict,
    sender_class: str | None = "owner",
    principal: str = "example-agent",
    identity: str = "maintainer",
    event_id: str = "evt-1",
    expiry: str = _FUTURE,
) -> str:
    return json.dumps(
        {
            "event_id": event_id,
            "principal": principal,
            "sender": {"channel_type": "owner", "channel_identity": identity, "evidence": []},
            "payload": payload,
            "provenance": [
                {"zone": "owner", "source": f"owner:{identity}", "evidence": [], "label": "trusted", "ts": _TS},
                {"zone": "channels", "source": "channel:owner", "evidence": ["token:pass"], "label": "trusted", "ts": _TS},
            ],
            "sender_class": sender_class,
            "ts": _TS,
            "expiry": expiry,
        }
    )


def _sqs_event(*bodies: str) -> dict:
    return {"Records": [{"messageId": f"m{i}", "body": b} for i, b in enumerate(bodies, start=1)]}


# --- Target 4 — owner COMMAND takes the normal turn, no auto-allow -----------

def test_owner_command_takes_normal_turn_not_approval_fork(wired):
    body = _owner_body(sender_class="owner", payload={"kind": "command", "text": "/trader buy AAPL"})

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    # The owner class raised the action surface but granted NOTHING: no fork.
    assert runtime.approve_calls == []
    assert runtime.reject_calls == []
    # Normal agent turn: receiver invoked, and its brokered call went through the
    # broker's decision path (handle_request on the ingested session turn).
    assert [c["event_id"] for c in OwnerSpyReceiver.calls] == ["evt-1"]
    assert runtime.requests == [_ProbeRequest()]
    # The receiver got the no-turn-controls facade, not the raw runtime.
    facade = OwnerSpyReceiver.calls[0]["runtime"]
    assert not isinstance(facade, OwnerFakeRuntime)
    assert not hasattr(facade, "approve_intent")


# --- Target 5a — owner /approve forks to the release path --------------------

def test_owner_approval_yes_forks_to_approve_intent(wired):
    body = _owner_body(
        sender_class="owner",
        payload={"kind": "approval", "intent_id": "int-1", "decision": "yes"},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    # Forked to the release path with the AUTHENTICATED owner identity (never the payload).
    assert runtime.approve_calls == [("int-1", "owner:maintainer")]
    assert runtime.reject_calls == []
    # The normal receiver / agent-turn path was NOT taken.
    assert OwnerSpyReceiver.calls == []
    assert runtime.requests == []


def test_owner_approval_no_forks_to_reject_intent(wired):
    body = _owner_body(
        sender_class="owner",
        payload={"kind": "approval", "intent_id": "int-2", "decision": "no"},
    )

    h.handler(_sqs_event(body), None)

    [runtime] = wired
    assert runtime.reject_calls == [("int-2", "owner:maintainer")]
    assert runtime.approve_calls == []
    assert OwnerSpyReceiver.calls == []
    assert runtime.requests == []


def test_owner_malformed_approval_payload_is_terminal_drop(wired, caplog):
    # An owner-class approval with a bad decision is a permanent error: it must
    # NOT reach approve/reject_intent and must NOT redeliver (terminal drop).
    body = _owner_body(
        sender_class="owner",
        payload={"kind": "approval", "intent_id": "int-3", "decision": "maybe"},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    assert runtime.approve_calls == []
    assert runtime.reject_calls == []
    assert "drain_terminal_drop" in caplog.text


# --- Target 5b — a non-owner approval-shaped payload does NOT fork -----------

@pytest.mark.parametrize("sender_class", ["peer-agent", "external"])
def test_non_owner_approval_shaped_payload_does_not_fork(wired, sender_class):
    # Byte-for-byte an owner approval payload, but stamped with a non-owner class.
    # The fork keys on the unforgeable gate-8 sender_class, so this must fall
    # through to the normal agent-turn path — approve_intent is NOT called.
    body = _owner_body(
        sender_class=sender_class,
        payload={"kind": "approval", "intent_id": "int-1", "decision": "yes"},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    assert runtime.approve_calls == []
    assert runtime.reject_calls == []
    # Normal path taken: the payload shape alone never releases an intent.
    assert [c["event_id"] for c in OwnerSpyReceiver.calls] == ["evt-1"]
    assert runtime.requests == [_ProbeRequest()]


# --- #193 Phase 6c — owner /flag forks to flag_intent ------------------------

def test_owner_flag_forks_to_flag_intent(wired):
    body = _owner_body(
        sender_class="owner",
        payload={"kind": "flag", "intent_id": "int-9"},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    # Forked with the AUTHENTICATED owner identity (never the payload).
    assert runtime.flag_calls == [("int-9", "owner:maintainer")]
    assert runtime.approve_calls == []
    assert runtime.reject_calls == []
    # The normal receiver / agent-turn path was NOT taken.
    assert OwnerSpyReceiver.calls == []
    assert runtime.requests == []


def test_owner_malformed_flag_payload_is_terminal_drop(wired, caplog):
    # An owner-class flag missing its intent_id is a permanent error: it must NOT
    # reach flag_intent and must NOT redeliver (terminal drop).
    body = _owner_body(
        sender_class="owner",
        payload={"kind": "flag", "intent_id": None},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    assert runtime.flag_calls == []
    assert "drain_terminal_drop" in caplog.text


@pytest.mark.parametrize("sender_class", ["peer-agent", "external"])
def test_non_owner_flag_shaped_payload_does_not_fork(wired, sender_class):
    # A flag-shaped payload stamped with a non-owner class must fall through to
    # the normal agent-turn path — flag_intent keys on the unforgeable gate-8
    # sender_class, never on payload shape.
    body = _owner_body(
        sender_class=sender_class,
        payload={"kind": "flag", "intent_id": "int-9"},
    )

    resp = h.handler(_sqs_event(body), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    assert runtime.flag_calls == []
    assert [c["event_id"] for c in OwnerSpyReceiver.calls] == ["evt-1"]
    assert runtime.requests == [_ProbeRequest()]
