"""The age of every fetched input a decision depends on (PTC §6.13, GAL §6.15, #176).

Each test names the conjunct of the rule it pins:

  AS-OF      every decision's audit record carries, per input it depended on, the
             instant as of which the broker established that input;
  EARLIER    that instant is the earlier of the fetch and a time the source stated,
             so a stated time can never make an input look fresher than its fetch;
  HORIZON    the record carries the decision's horizon, the earliest instant any
             input it depended on passes its declared maximum age;
  MAX-AGE    an input past its declared age refuses the decision, before any
             counter is drawn or connector reached;
  OFF        with no declared age (the default) nothing is refused and the horizon
             is absent;
  RELEASE    a call held on a decision and released past the horizon is evaluated
             again on its own fresh inputs, and is not run on the old decision.

In-memory fakes throughout; a hand-advanced clock stands in for elapsed time.
"""

from __future__ import annotations

import datetime
from typing import Any

import pydantic
import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.engine import RELEASE_REFUSED_REASON_PREFIX
from safe_agents.broker.audit import InMemorySink, verify_chain
from safe_agents.broker.audit._hash import hash_record
from safe_agents.broker.audit._chain import ChainError
from safe_agents.broker.envelope.store import InMemoryEnvelopeStore
from safe_agents.broker.enforcement import (
    ACTION_CAP_SUFFIX,
    InMemoryStore,
    scoped_counter_key,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.pdp import Facts
from safe_agents.broker.prototype.boot_config import load_agent_manifest
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
    StubConnector,
)
from safe_agents.broker.runtime.input_age import (
    INPUT_PAST_MAX_AGE_REASON,
    DecisionInputs,
    InputAgePolicy,
    InputAsOf,
)
from safe_agents.broker.schemas import AgentManifest, AuditRecord, Grant, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH

T0 = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.UTC)
SEC = datetime.timedelta(seconds=1)
_PRINCIPAL_DATA = {"agentId": "agent-input-age", "skill": "s", "user": "u", "tier": "B"}
_PRINCIPAL = Principal(**_PRINCIPAL_DATA)
_APPROVER = "owner:maintainer@example.com"
_STARTUP_INPUTS = ("manifest", "envelope", "hmac_key")


class _Clock:
    def __init__(self, now: datetime.datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime.datetime:
        return self.now


class _CountingConnector:
    def __init__(self) -> None:
        self._inner = StubConnector(result={"ok": True})
        self.count = 0

    def execute(self, tool, op, args, credential):  # noqa: ANN001, ANN201
        self.count += 1
        return self._inner.execute(tool, op, args, credential)


def _facts(level: AutonomyLevel) -> Facts:
    return Facts(
        grant_present=True,
        grant_level=level,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=True,
        human_reachable=True,
        transform_op=None,
    )


def _grant(action_class: str) -> Grant:
    return Grant.model_validate(
        {
            "principal": _PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": "in-loop",
            "envelopeHash": ENVELOPE_HASH,
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


# An internal read the PDP allows outright, and an external irreversible write it
# holds for approval at in-loop.
_READ = ToolOp(tool="calendar", op="list", effect="read", external=False, reversible=True)
_WRITE = ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False)


def _runtime(
    *,
    clock: _Clock,
    startup: dict | None = None,
    max_age: dict[str, int] | None = None,
    op: ToolOp = _READ,
    level: AutonomyLevel = AutonomyLevel.on_loop,
):
    connector = _CountingConnector()
    store = InMemoryStore()
    intents = InMemoryIntentStore()
    sink = InMemorySink()
    policy = None
    if startup is not None or max_age is not None:
        policy = InputAgePolicy.from_seconds(startup or {}, max_age or {})
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_grant(f"{op.tool}.{op.op}")],
        optable=ToolOpTable([op]),
        doer=Doer(
            connectors={op.tool: connector},
            secrets=FakeSecretsProvider({op.tool: f"cred-{op.tool}"}),
        ),
        pip=lambda call: _facts(level),
        enforcement_store=store,
        intent_store=intents,
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        input_ages=policy,
        clock=clock,
    )
    return runtime, sink, connector, store, intents


def _startup_at(instant: datetime.datetime) -> dict:
    return {name: InputAsOf(fetched_at=instant) for name in _STARTUP_INPUTS}


def _cap_key(op: ToolOp) -> str:
    return scoped_counter_key(_PRINCIPAL, op.tool, op.op, ACTION_CAP_SUFFIX)


def _call(runtime: BrokerRuntime, op: ToolOp = _READ):
    return runtime.handle_request(AgentRequest(tool=op.tool, op=op.op, args={"n": 1}))


# ---------------------------------------------------------------------------
# EARLIER — the as-of instant, never fresher than the fetch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stated", "expected"),
    [
        (None, T0),  # no stated time: the fetch
        (T0 + 3600 * SEC, T0),  # a source claiming a later time cannot pass the fetch
        (T0 - 50 * SEC, T0 - 50 * SEC),  # an older stated answer ages from its own time
        (T0, T0),
    ],
)
def test_earlier_as_of_is_the_earlier_of_fetch_and_stated(stated, expected) -> None:
    assert InputAsOf(fetched_at=T0, stated_at=stated).as_of == expected


@pytest.mark.parametrize(
    ("stated", "evaluated_at"),
    [
        # Fetched at T0 with a 60s age. A source that stated a time an hour later
        # must not keep the input alive past T0+60s.
        (T0 + 3600 * SEC, T0 + 61 * SEC),
        (None, T0 + 61 * SEC),
        # In date from the fetch at T0+11s, but the source said its answer was
        # already 50s old, so it is past 60s.
        (T0 - 50 * SEC, T0 + 11 * SEC),
    ],
)
def test_earlier_a_stated_time_never_makes_a_startup_input_fresher(
    stated, evaluated_at
) -> None:
    clock = _Clock()
    startup = _startup_at(T0)
    startup["envelope"] = InputAsOf(fetched_at=T0, stated_at=stated)
    runtime, sink, connector, _, _ = _runtime(
        clock=clock, startup=startup, max_age={"envelope": 60}
    )
    clock.now = evaluated_at
    response = _call(runtime)
    assert response.decision_kind == "deny"
    assert response.reason.startswith(f"{INPUT_PAST_MAX_AGE_REASON}: envelope")
    assert connector.count == 0
    assert sink.records()[-1].inputsAsOf["envelope"] == min(T0, stated or T0).isoformat()


def test_earlier_two_reads_in_one_decision_keep_the_earlier() -> None:
    inputs = DecisionInputs(InputAgePolicy(), _Clock())
    inputs.establish("grant", T0 + 5 * SEC)
    inputs.establish("grant", T0)
    inputs.establish("grant", T0 + 9 * SEC)
    assert inputs.audit_fields()["inputs_as_of"] == {"grant": T0.isoformat()}


# ---------------------------------------------------------------------------
# HORIZON — the earliest instant any input the decision depended on ages out
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("max_age", "expected"),
    [
        ({}, None),  # OFF: no bound
        ({"envelope": 100}, T0 + 100 * SEC),
        ({"envelope": 100, "manifest": 40}, T0 + 40 * SEC),
        # An age declared for an input this decision never read does not bound it.
        ({"intent": 5}, None),
    ],
)
def test_horizon_is_the_earliest_declared_end(max_age, expected) -> None:
    inputs = DecisionInputs(InputAgePolicy.from_seconds(_startup_at(T0), max_age), _Clock())
    assert inputs.horizon() == expected
    fields = inputs.audit_fields()
    assert fields["horizon"] == (expected.isoformat() if expected else None)


@pytest.mark.parametrize(("offset", "stale"), [(99, False), (100, True), (101, True)])
def test_horizon_at_the_instant_itself_is_past(offset, stale) -> None:
    inputs = DecisionInputs(
        InputAgePolicy.from_seconds(_startup_at(T0), {"envelope": 100}), _Clock()
    )
    assert bool(inputs.stale(T0 + offset * SEC)) is stale


# ---------------------------------------------------------------------------
# AS-OF and OFF — every decision record carries its instants; default refuses nothing
# ---------------------------------------------------------------------------


def test_off_records_per_call_instants_and_refuses_nothing() -> None:
    clock = _Clock(T0 + 10_000_000 * SEC)  # any age at all
    runtime, sink, connector, _, _ = _runtime(clock=clock)
    response = _call(runtime)
    assert response.decision_kind == "allow"
    assert connector.count == 1
    record = sink.records()[-1]
    assert record.outcome == "executed"
    assert record.inputsAsOf == {
        "counters": clock.now.isoformat(),
        "grant": clock.now.isoformat(),
    }
    assert record.horizon is None
    verify_chain(sink.records())


def test_as_of_startup_and_per_call_inputs_on_an_allowed_call() -> None:
    clock = _Clock(T0)
    runtime, sink, _, _, _ = _runtime(
        clock=clock, startup=_startup_at(T0 - 30 * SEC), max_age={"grant": 600}
    )
    clock.now = T0 + 5 * SEC
    assert _call(runtime).decision_kind == "allow"
    record = sink.records()[-1]
    assert record.inputsAsOf == {
        "counters": (T0 + 5 * SEC).isoformat(),
        "envelope": (T0 - 30 * SEC).isoformat(),
        "grant": (T0 + 5 * SEC).isoformat(),
        "hmac_key": (T0 - 30 * SEC).isoformat(),
        "manifest": (T0 - 30 * SEC).isoformat(),
    }
    assert record.horizon == (T0 + 605 * SEC).isoformat()


def test_as_of_on_the_record_of_a_call_the_manifest_never_classified() -> None:
    clock = _Clock()
    runtime, sink, _, _, _ = _runtime(clock=clock, startup=_startup_at(T0), max_age={})
    response = runtime.handle_request(AgentRequest(tool="nope", op="nothing", args={}))
    assert response.decision_kind == "deny"
    record = sink.records()[-1]
    assert set(record.inputsAsOf) == set(_STARTUP_INPUTS)


# ---------------------------------------------------------------------------
# MAX-AGE — refusal before any counter or connector, for every startup input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _STARTUP_INPUTS)
def test_max_age_startup_input_past_its_age_refuses(name) -> None:
    clock = _Clock()
    runtime, sink, connector, store, _ = _runtime(
        clock=clock, startup=_startup_at(T0), max_age={name: 60}
    )
    clock.now = T0 + 59 * SEC
    assert _call(runtime).decision_kind == "allow"
    assert connector.count == 1
    spent = store.read_counter(_cap_key(_READ))

    clock.now = T0 + 60 * SEC
    response = _call(runtime)
    assert response.decision_kind == "deny"
    assert response.reason.startswith(f"{INPUT_PAST_MAX_AGE_REASON}: {name}")
    assert connector.count == 1  # not reached again
    assert store.read_counter(_cap_key(_READ)) == spent  # no budget drawn
    record = sink.records()[-1]
    assert record.outcome == "denied"
    assert record.reason.startswith(f"{INPUT_PAST_MAX_AGE_REASON}: {name}")
    assert record.horizon == (T0 + 60 * SEC).isoformat()
    verify_chain(sink.records())


def test_max_age_an_undeclared_input_is_never_refused() -> None:
    clock = _Clock()
    runtime, _, _, _, _ = _runtime(clock=clock, startup=_startup_at(T0), max_age={"intent": 1})
    clock.now = T0 + 10_000 * SEC
    assert _call(runtime).decision_kind == "allow"


def test_max_age_per_call_input_is_read_fresh_so_it_bounds_the_horizon_only() -> None:
    clock = _Clock()
    runtime, sink, _, _, _ = _runtime(clock=clock, startup=_startup_at(T0), max_age={"grant": 30})
    clock.now = T0 + 3600 * SEC
    assert _call(runtime).decision_kind == "allow"
    assert sink.records()[-1].horizon == (T0 + 3630 * SEC).isoformat()


# ---------------------------------------------------------------------------
# RELEASE — a held call is evaluated again on its own inputs at release
# ---------------------------------------------------------------------------


def _hold(runtime: BrokerRuntime) -> str:
    response = _call(runtime, _WRITE)
    assert response.decision_kind == "require_approval"
    return response.intent_id


def test_release_past_the_hold_horizon_is_refused_not_run_on_the_old_decision() -> None:
    clock = _Clock()
    runtime, sink, connector, store, intents = _runtime(
        clock=clock,
        startup=_startup_at(T0),
        max_age={"envelope": 100},
        op=_WRITE,
        level=AutonomyLevel.in_loop,
    )
    intent_id = _hold(runtime)
    hold = sink.records()[-1]
    assert hold.outcome == "held"
    assert hold.horizon == (T0 + 100 * SEC).isoformat()

    clock.now = T0 + 100 * SEC
    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is False
    assert result.rejection_reason.startswith(RELEASE_REFUSED_REASON_PREFIX)
    assert f"{INPUT_PAST_MAX_AGE_REASON}: envelope" in result.rejection_reason
    assert connector.count == 0
    assert store.read_counter(_cap_key(_WRITE)) == 0
    assert intents.get_intent(intent_id).status == "refused"
    refusal = sink.records()[-1]
    assert refusal.outcome == "denied"
    assert refusal.intentId == intent_id
    assert refusal.inputsAsOf["intent"] == (T0 + 100 * SEC).isoformat()
    verify_chain(sink.records())


def test_release_before_the_horizon_runs_and_records_its_own_instants() -> None:
    clock = _Clock()
    runtime, sink, connector, _, intents = _runtime(
        clock=clock,
        startup=_startup_at(T0),
        max_age={"envelope": 100, "grant": 30},
        op=_WRITE,
        level=AutonomyLevel.in_loop,
    )
    intent_id = _hold(runtime)
    hold = sink.records()[-1]
    assert "intent" not in hold.inputsAsOf
    assert hold.horizon == (T0 + 30 * SEC).isoformat()

    # Past the HOLD's horizon (its grant read was at T0 with a 30s age) but within
    # the envelope's: the release re-reads the grant, so it is not refused for the
    # hold's stale read. It is a new decision on new reads.
    clock.now = T0 + 60 * SEC
    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)

    assert result.executed is True
    assert connector.count == 1
    assert intents.get_intent(intent_id).status == "executed"
    release = sink.records()[-1]
    assert release.outcome == "executed"
    assert release.inputsAsOf["grant"] == (T0 + 60 * SEC).isoformat()
    assert release.inputsAsOf["intent"] == (T0 + 60 * SEC).isoformat()
    assert release.inputsAsOf["envelope"] == T0.isoformat()
    assert release.horizon == (T0 + 90 * SEC).isoformat()


# ---------------------------------------------------------------------------
# The record: hash-covered when present, absent from records written before it
# ---------------------------------------------------------------------------


def test_record_stripping_the_instants_breaks_the_chain() -> None:
    clock = _Clock()
    runtime, sink, _, _, _ = _runtime(clock=clock, startup=_startup_at(T0), max_age={"grant": 9})
    _call(runtime)
    record = sink.records()[-1]
    for stripped in (
        record.model_copy(update={"inputsAsOf": None}),
        record.model_copy(update={"horizon": None}),
    ):
        with pytest.raises(ChainError, match="hash mismatch"):
            verify_chain([*sink.records()[:-1], stripped])


def test_record_without_the_fields_hashes_as_it_did_before_them() -> None:
    fields = {
        "seq": 0,
        "ts": T0.isoformat(),
        "principal": _PRINCIPAL_DATA,
        "tool": "t",
        "op": "o",
        "argsDigest": "sha256:" + "0" * 64,
        "decision": "deny",
        "reason": None,
        "envelopeHash": ENVELOPE_HASH,
        "approvedBy": None,
        "outcome": "denied",
        "error": None,
        "seed": None,
        "prevHash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    record = AuditRecord(**fields, hash=hash_record(fields))
    verify_chain([record])


# ---------------------------------------------------------------------------
# The knob: image-baked, closed vocabulary, positive whole seconds, OFF by default
# ---------------------------------------------------------------------------


def _manifest(**overrides: Any) -> AgentManifest:
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
        "principal": _PRINCIPAL_DATA,
        "grant_classes": ["calendar.list", "payments.transfer"],
        "connectors": ["calendar"],
        "connector_providers": {"calendar": f"{__name__}:EchoConnector"},
        "tool_ops": [_READ.model_dump(), _WRITE.model_dump()],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


class EchoConnector:
    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        return {"echo": args}


def test_knob_defaults_to_no_declared_age() -> None:
    assert _manifest().input_max_age_seconds == {}


@pytest.mark.parametrize(
    "bad",
    [{"envelope": 0}, {"envelope": -5}, {"envelope": True}, {"envelope": 1.5}, {"enveloppe": 60}],
)
def test_knob_refuses_a_bad_declaration(bad) -> None:
    with pytest.raises(pydantic.ValidationError):
        _manifest(input_max_age_seconds=bad)


# ---------------------------------------------------------------------------
# build_runtime: where the startup inputs get their as-of instants
# ---------------------------------------------------------------------------


@pytest.fixture
def _memory_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("BROKER_STORE", "BROKER_AUDIT_BUCKET", "BROKER_AUDIT_PATH", "BROKER_SECRETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("BROKER_GRANT_LOAD", raising=False)


def test_build_store_mode_envelope_past_its_age_refuses(
    monkeypatch: pytest.MonkeyPatch, _memory_arm: None
) -> None:
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    manifest = _manifest(input_max_age_seconds={"envelope": 60})
    store = InMemoryEnvelopeStore()
    store.put_envelope(_PRINCIPAL, manifest.envelope)
    clock = _Clock()
    runtime, sink = build_runtime(manifest, envelope_store=store, clock=clock)

    clock.now = T0 + 59 * SEC
    assert _call(runtime).decision_kind == "allow"
    assert sink.records()[-1].inputsAsOf["envelope"] == T0.isoformat()

    clock.now = T0 + 60 * SEC
    response = _call(runtime)
    assert response.decision_kind == "deny"
    assert response.reason.startswith(f"{INPUT_PAST_MAX_AGE_REASON}: envelope")


def test_build_manifest_as_of_is_its_fetch_not_the_build(_memory_arm: None, tmp_path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(_manifest().model_dump_json(), encoding="utf-8")
    before = datetime.datetime.now(datetime.UTC)
    manifest = load_agent_manifest(path)
    after = datetime.datetime.now(datetime.UTC)
    assert before <= manifest._fetched_at <= after

    # Built an hour after it was read: the manifest, and the envelope that rode
    # in on it, are as old as the read.
    manifest._fetched_at = T0 - 3600 * SEC
    runtime, sink = build_runtime(manifest, clock=_Clock())
    _call(runtime)
    as_of = sink.records()[-1].inputsAsOf
    assert as_of["manifest"] == (T0 - 3600 * SEC).isoformat()
    assert as_of["envelope"] == (T0 - 3600 * SEC).isoformat()
    assert as_of["hmac_key"] == T0.isoformat()


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (T0 - 600 * SEC, T0 - 600 * SEC),  # a caller's earlier fetch replaces the build's
        (T0 + 600 * SEC, T0),  # a later one never makes the key look fresher
    ],
)
def test_build_caller_supplied_as_of_can_only_make_an_input_older(
    _memory_arm: None, given, expected
) -> None:
    runtime, sink = build_runtime(
        _manifest(), clock=_Clock(), input_as_of={"hmac_key": InputAsOf(fetched_at=given)}
    )
    _call(runtime)
    assert sink.records()[-1].inputsAsOf["hmac_key"] == expected.isoformat()


def test_build_caller_supplied_manifest_as_of_carries_the_envelope_with_it(
    _memory_arm: None,
) -> None:
    runtime, sink = build_runtime(
        _manifest(),
        clock=_Clock(),
        input_as_of={"manifest": InputAsOf(fetched_at=T0 - 600 * SEC)},
    )
    _call(runtime)
    assert sink.records()[-1].inputsAsOf["envelope"] == (T0 - 600 * SEC).isoformat()


# ---------------------------------------------------------------------------
# The drain worker: one cold start, a runtime per record
# ---------------------------------------------------------------------------


def test_drain_hands_its_cold_start_fetches_to_every_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from safe_agents.broker.prototype import broker_server
    from safe_agents.channels.drain import handler as h

    path = tmp_path / "drain-manifest.yaml"
    path.write_text(_manifest().model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("CHANNELS_DRAIN_MANIFEST", str(path))
    monkeypatch.setenv("BROKER_HMAC_KEY_SECRET_ARN", "arn:example:secret")
    monkeypatch.setenv("BROKER_HMAC_KEY", "placeholder")
    monkeypatch.setattr(h, "_fetch_hmac_key", lambda arn: "fetched-key")
    monkeypatch.setattr(h, "_HMAC_KEY_FETCHED_AT", None)

    before = datetime.datetime.now(datetime.UTC)
    h._resolve_hmac_key()
    manifest = h._load_manifest()
    after = datetime.datetime.now(datetime.UTC)
    assert before <= manifest._fetched_at <= after

    seen: dict = {}

    def _capture(manifest_arg, **kwargs):
        seen.update(kwargs)
        return object(), None

    monkeypatch.setattr(broker_server, "build_runtime", _capture)
    h._build_runtime(manifest)
    key_as_of = seen["input_as_of"]["hmac_key"].as_of
    assert before <= key_as_of <= after
