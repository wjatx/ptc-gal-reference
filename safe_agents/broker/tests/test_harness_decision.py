"""`BrokerRuntime.decide_harness_call`: a harness's own tool call, decided before it runs (#168).

The runtime half of the decision mouth (`broker/GATEWAY.md` G30 on). The route is
`test_gateway_decide.py`. What this file pins, against a runtime built from a
manifest through `build_runtime`:

- the closed answer: allow permits and writes `permitted`; deny, abstain and a
  hold refuse; a transform refuses as a configuration error; a class with no
  entry refuses and is recorded;
- the pipeline: a permit draws the per-op counter through `enforce()`;
- taint at the permit: a tainting class from an untrusted source is ingested
  before the record, and a sink failure leaves the turn tainted and refuses;
- the hold and its release: approving runs nothing; the same call asked again
  is evaluated again and permitted once; another input does not release it; a
  consumed or lapsed approval is not used again; a PDP deny at release binds; an
  approved intent under the call's id that is not this call refuses;
- the shown-input check on approval, and the held input digest on the view;
- the two model-facing sentences, verbatim as the ruling wrote them;
- faults: anything inside the runtime answers refuse, and a malformed request
  is refused and recorded;
- the release's lookup on all three intent stores.
"""

from __future__ import annotations

import dataclasses
import datetime
import os
import textwrap
from pathlib import Path
from typing import Any

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.approval.queue_guard import harness_hold_intent_id
from safe_agents.broker.approval.sqlite_store import SqliteIntentStore
from safe_agents.broker.audit import InMemorySink, hash_args, hash_stored_call
from safe_agents.broker.enforcement import ACTION_CAP_SUFFIX, InMemoryStore, scoped_counter_key
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.runtime import pep
from safe_agents.broker.runtime.harness_decision import (
    FAULT_REASON,
    HELD_SENTENCE,
    MALFORMED_REASON,
    REFUSED_SENTENCE,
    VERB_ANSWER,
    permitted_reason,
    transform_reason,
)
from safe_agents.broker.runtime.observed import HARNESS_TOOL, digest_subject
from safe_agents.broker.schemas import Abstain, Deny, ToolOp, Transform
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, PRINCIPAL, make_grant, make_pip

_BROKER_ENV = (
    "BROKER_STORE", "BROKER_MANIFEST", "BROKER_SECRETS", "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE", "BROKER_AUDIT_PATH", "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD", "BROKER_SQLITE_PATH",
)

SUBJECT = digest_subject("/home/someone/project/build.sh")
INPUT = digest_subject('{"command":"make"}')
OTHER_INPUT = digest_subject('{"command":"make install"}')
CALL = digest_subject("toolu_0001")
LATER_CALL = digest_subject("toolu_0002")
SHELL = "shell/project"
READ = "file-read/outside"
APPROVER = "owner:someone"
HOLD_REASON = "tainted harness hold: the envelope holds this tool class on a tainted turn"

# The ruling's two sentences, copied from it as literals, never imported: an edit to
# the base's constants has to fail here.
RULING_REFUSED = (
    "Refused by policy. Do not attempt the same action another way. Tell the user what was "
    "refused, and continue with any part of the task this does not affect."
)
RULING_HELD = (
    "Held for approval by policy (intent {intent_id}). Do not attempt the same action another "
    "way. Tell the user it is waiting for approval; if it is approved, the same call will be "
    "allowed once."
)


class NoConnector:
    """Named so the manifest's connector wiring loads. Reaching it fails the test."""

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        raise AssertionError("a harness decision reached a connector")


def _manifest(path: Path, *, held: tuple[str, ...], trusted: tuple[str, ...]) -> Path:
    extra = ""
    if held:
        extra += "  tainted_harness_hold:\n" + "".join(f"    - {c}\n" for c in held)
    if trusted:
        extra += "  trusted_read_sources:\n" + "".join(f'    - "{s}"\n' for s in trusted)
    path.write_text(
        textwrap.dedent(
            f"""\
            principal:
              agentId: decision-test
              skill: research
              user: local-developer
              tier: C
            grant_classes:
              - crm.post
              - {HARNESS_TOOL}.{SHELL}
              - {HARNESS_TOOL}.{READ}
              - {HARNESS_TOOL}.file-write/outside
            connectors:
              - crm
            connector_providers:
              crm: "safe_agents.broker.tests.test_harness_decision:NoConnector"
            tool_ops:
              - {{tool: crm, op: post, effect: write, external: true, reversible: true}}
              - {{tool: {HARNESS_TOOL}, op: "{SHELL}", effect: write, external: false, reversible: true}}
              - {{tool: {HARNESS_TOOL}, op: "{READ}", effect: read, external: true}}
              - {{tool: {HARNESS_TOOL}, op: "file-write/outside", effect: write, external: true, reversible: true}}
            envelope:
              polarity: abstain
              caps:
                actions_per_run: 25
              high_stakes: false
            """
        )
        + extra,
        encoding="utf-8",
    )
    return path


@pytest.fixture
def built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    made: list = []

    def build(*, held: tuple[str, ...] = (), trusted: tuple[str, ...] = ()):
        path = _manifest(tmp_path / f"m{len(made)}.yaml", held=held, trusted=trusted)
        runtime, sink = build_runtime(load_agent_manifest(path))
        made.append(runtime)
        return runtime, sink

    try:
        yield build
    finally:
        for runtime in made:
            runtime.close()


def ask(runtime, **overrides: Any):
    request = {
        "mouth": "tool-event",
        "harness": "example-harness",
        "tool_class": "shell",
        "locality": "project",
        "subject_digest": SUBJECT,
        "input_digest": INPUT,
        "call_digest": CALL,
    }
    request.update(overrides)
    return runtime.decide_harness_call(**request)


def args_of(*, input_digest: str = INPUT, call: str = CALL, locality: str = "project") -> dict:
    return {"call": call, "harness": "example-harness", "input": input_digest,
            "locality": locality, "subject": SUBJECT}


def taint(runtime) -> None:
    runtime.record_observed_event(
        mouth="tool-event", harness="example-harness", tool_class="file-read",
        locality="outside", subject_digest=SUBJECT,
    )


def counter(runtime, op: str = SHELL) -> float:
    key = scoped_counter_key(runtime._principal, HARNESS_TOOL, op, ACTION_CAP_SUFFIX,
                             period=runtime._counter_period)
    return runtime._enforcement_store.read_counter(key)


def hold(runtime, **overrides: Any):
    taint(runtime)
    decision = ask(runtime, **overrides)
    assert (decision.answer, decision.outcome) == ("refuse", "held"), decision
    return decision


# ---------------------------------------------------------------------------
# The closed answer
# ---------------------------------------------------------------------------


class TestTheAnswer:
    def test_the_mapping_is_fixed_and_only_allow_permits(self) -> None:
        assert VERB_ANSWER == {
            "allow": "permit", "deny": "refuse", "abstain": "refuse",
            "require_approval": "refuse", "transform": "refuse",
        }

    def test_an_allow_permits_and_is_recorded_at_the_coordinate(self, built) -> None:
        runtime, sink = built()
        decision = ask(runtime)
        assert (decision.answer, decision.decision_kind, decision.outcome) == ("permit", "allow", "permitted")
        assert decision.text is None and decision.intent_id is None
        records = sink.records()
        assert len(records) == 1, (
            "a permit was answered without its permitted record on the tape: "
            f"{[r.outcome for r in records]}"
        )
        (record,) = records
        assert (record.tool, record.op, record.decision, record.outcome) == (
            HARNESS_TOOL, SHELL, "allow", "permitted",
        )
        assert record.reason == permitted_reason(SHELL)
        assert "as declared by the manifest" in record.reason
        assert record.argsDigest == hash_args(args_of())
        assert record.intentId is None and record.inputsAsOf is not None

    def test_a_permit_draws_the_per_op_counter_through_enforce(self, built) -> None:
        runtime, _ = built()
        assert counter(runtime) == 0
        ask(runtime)
        ask(runtime, call_digest=LATER_CALL)
        assert counter(runtime) == 2

    def test_a_breached_cap_refuses(self, built) -> None:
        runtime, sink = built()
        key = scoped_counter_key(runtime._principal, HARNESS_TOOL, SHELL, ACTION_CAP_SUFFIX,
                                 period=runtime._counter_period)
        runtime._enforcement_store.try_increment_counter(key, runtime._counter_cap, runtime._counter_cap)
        decision = ask(runtime)
        assert decision.answer == "refuse"
        assert sink.records()[-1].outcome == "denied"

    def test_a_class_with_no_entry_is_refused_and_recorded(self, built) -> None:
        runtime, sink = built()
        decision = ask(runtime, locality="home")
        assert (decision.answer, decision.reason) == ("refuse", f"no manifest entry for {HARNESS_TOOL}.shell/home")
        (record,) = sink.records()
        assert (record.tool, record.op, record.decision, record.outcome) == (
            HARNESS_TOOL, "shell/home", "deny", "denied",
        )

    @pytest.mark.parametrize(
        ("verdict", "kind", "reason"),
        [
            pytest.param(Deny(kind="deny", reason="no"), "deny", "no", id="deny"),
            pytest.param(Abstain(kind="abstain", reason="unsure", escalate=False), "abstain", "unsure", id="abstain"),
            pytest.param(Transform(kind="transform", op="draft", args={}), "deny",
                         transform_reason(SHELL), id="transform"),
        ],
    )
    def test_every_other_verb_refuses_and_draws_nothing(self, built, monkeypatch, verdict, kind, reason) -> None:
        runtime, sink = built()
        monkeypatch.setattr(pep, "decide", lambda call, facts: verdict)
        decision = ask(runtime)
        assert (decision.answer, decision.decision_kind, decision.reason) == ("refuse", kind, reason)
        assert decision.text.startswith("Refused by policy.")
        (record,) = sink.records()
        assert (record.decision, record.outcome, record.reason) == (kind, "denied", reason)
        assert counter(runtime) == 0

    def test_a_transform_from_the_real_pdp_is_a_configuration_error(self, built, monkeypatch) -> None:
        """The PIP supplies a safer op on an untainted external write: the rule fires."""
        runtime, sink = built()
        real = runtime._pip
        monkeypatch.setattr(
            runtime, "_pip",
            lambda call: dataclasses.replace(real(call), transform_op="draft"),
        )
        decision = ask(runtime, tool_class="file-write", locality="outside")
        assert (decision.answer, decision.reason) == ("refuse", transform_reason("file-write/outside"))
        assert sink.records()[-1].decision == "deny"
        assert counter(runtime, "file-write/outside") == 0

    def test_the_two_sentences_are_the_rulings_verbatim(self, built) -> None:
        assert (REFUSED_SENTENCE, HELD_SENTENCE) == (RULING_REFUSED, RULING_HELD), (
            "the model-facing sentences no longer match the ruling's text"
        )
        runtime, _ = built(held=("shell",))
        refused = ask(runtime, locality="home")
        assert refused.text == f"{RULING_REFUSED} Reason: {refused.reason}"
        held = hold(runtime)
        assert held.text == (
            f"{RULING_HELD.format(intent_id=held.intent_id)} Reason: {held.reason}"
        )

    @pytest.mark.parametrize("sentence", [REFUSED_SENTENCE, HELD_SENTENCE], ids=["refused", "held"])
    def test_neither_sentence_names_a_release_command(self, sentence) -> None:
        lowered = sentence.lower()
        assert "release" not in lowered and "`" not in sentence and "run " not in lowered, (
            f"a model-facing sentence names how to release a hold: {sentence!r}"
        )


# ---------------------------------------------------------------------------
# Taint lands at the permit
# ---------------------------------------------------------------------------


class TestTaintAtThePermit:
    def test_a_tainting_permit_taints_the_turn_before_its_record(self, built, monkeypatch) -> None:
        runtime, sink = built()
        seen: list[bool] = []
        real_append = sink.append

        def append(record) -> None:
            seen.append(runtime.session_turn().tainted)
            real_append(record)

        monkeypatch.setattr(sink, "append", append)
        decision = ask(runtime, tool_class="file-read", locality="outside")
        assert decision.answer == "permit"
        assert seen == [True], "the permitted record was written before the turn was tainted"
        assert "harness:example-harness/file-read/outside" in runtime.session_turn().to_taint().sources

    def test_a_sink_failure_leaves_the_turn_tainted_and_refuses(self, built, monkeypatch) -> None:
        runtime, sink = built()

        def broken(_record) -> None:
            raise OSError("the tape is unwritable")

        monkeypatch.setattr(sink, "append", broken)
        decision = ask(runtime, tool_class="file-read", locality="outside")
        assert (decision.answer, decision.reason) == ("refuse", FAULT_REASON)
        assert runtime.session_turn().tainted is True

    def test_a_trusted_source_is_permitted_and_not_ingested(self, built) -> None:
        runtime, _ = built(trusted=("harness:example-harness/file-read/outside",))
        assert ask(runtime, tool_class="file-read", locality="outside").answer == "permit"
        assert runtime.session_turn().tainted is False

    def test_a_class_that_does_not_read_does_not_taint(self, built) -> None:
        runtime, _ = built()
        assert ask(runtime).answer == "permit"
        assert runtime.session_turn().tainted is False


# ---------------------------------------------------------------------------
# The hold and its release
# ---------------------------------------------------------------------------


class TestHoldAndRelease:
    def test_a_hold_refuses_now_with_its_intent_id(self, built) -> None:
        runtime, sink = built(held=("shell",))
        decision = hold(runtime)
        assert decision.intent_id == harness_hold_intent_id(runtime._principal, SHELL, INPUT)
        assert decision.reason == HOLD_REASON
        assert decision.text.startswith(f"Held for approval by policy (intent {decision.intent_id}).")
        record = sink.records()[-1]
        assert (record.outcome, record.intentId, record.argsDigest) == (
            "held", decision.intent_id, hash_args(args_of()),
        )

    def test_a_repeat_while_pending_coalesces_onto_the_same_intent(self, built) -> None:
        runtime, _ = built(held=("shell",))
        first = hold(runtime)
        again = ask(runtime, call_digest=LATER_CALL)
        assert (again.outcome, again.intent_id) == ("held", first.intent_id)

    def test_approving_runs_nothing_and_marks_the_intent_approved(self, built) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        before = len(sink.records())
        result = runtime.approve_intent(held.intent_id, APPROVER)
        assert (result.executed, result.approved_for_reissue) == (False, True)
        assert "permitted once when the harness asks again" in result.rejection_reason
        assert len(sink.records()) == before, "approving a harness hold wrote a record"
        view = runtime.describe_intent(held.intent_id)
        assert (view.status, view.approved_by) == ("approved", APPROVER)
        assert counter(runtime) == 0

    def test_the_same_call_asked_again_is_permitted_once(self, built) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        stored = runtime._intent_store.get_intent(held.intent_id).materializedRequest
        released = ask(runtime, call_digest=LATER_CALL)
        assert (released.answer, released.intent_id) == ("permit", held.intent_id)
        record = sink.records()[-1]
        assert (record.decision, record.outcome, record.intentId, record.approvedBy) == (
            "allow", "permitted", held.intent_id, APPROVER,
        )
        assert record.storedCallDigest == hash_stored_call(stored)
        assert record.argsDigest == hash_args(args_of(call=LATER_CALL))
        assert record.reason == permitted_reason(SHELL, intent_id=held.intent_id)
        assert runtime.describe_intent(held.intent_id).status == "permitted"
        assert counter(runtime) == 1
        # Consumed: the same request is decided afresh, and the turn is still tainted.
        after = ask(runtime, call_digest=LATER_CALL)
        assert (after.answer, after.outcome) == ("refuse", "held")
        assert runtime.describe_intent(held.intent_id).status == "pending"

    def test_another_input_does_not_release_or_consume_the_approval(self, built) -> None:
        runtime, _ = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        other = ask(runtime, input_digest=OTHER_INPUT)
        assert (other.answer, other.outcome) == ("refuse", "held")
        assert other.intent_id != held.intent_id
        assert runtime.describe_intent(held.intent_id).status == "approved"
        assert ask(runtime).answer == "permit"

    def test_a_release_is_evaluated_again_and_anything_stricter_binds(self, built) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        key = scoped_counter_key(runtime._principal, HARNESS_TOOL, SHELL, ACTION_CAP_SUFFIX,
                                 period=runtime._counter_period)
        runtime._enforcement_store.try_increment_counter(key, runtime._counter_cap, runtime._counter_cap)
        refused = ask(runtime)
        assert (refused.answer, refused.decision_kind) == ("refuse", "deny")
        record = sink.records()[-1]
        assert (record.outcome, record.intentId, record.approvedBy) == ("denied", held.intent_id, APPROVER)
        assert runtime.describe_intent(held.intent_id).status == "refused"

    def test_a_pdp_deny_at_release_binds(self, built, monkeypatch) -> None:
        """A grant revoked after the approval: the PDP denies at release, and that binds.

        No counter is breached here, so `enforce()` alone cannot refuse it: only the
        release decider passing a deny through does.
        """
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        monkeypatch.setattr(pep, "decide", lambda call, facts: Deny(kind="deny", reason="grant revoked"))
        refused = ask(runtime, call_digest=LATER_CALL)
        assert (refused.answer, refused.decision_kind, refused.reason) == ("refuse", "deny", "grant revoked"), (
            f"a PDP deny at release did not bind: the approval was folded over it ({refused})"
        )
        assert not any(r.outcome == "permitted" for r in sink.records())
        record = sink.records()[-1]
        assert (record.decision, record.outcome, record.intentId) == ("deny", "denied", held.intent_id)
        assert runtime.describe_intent(held.intent_id).status == "refused"
        assert counter(runtime) == 0

    @pytest.mark.parametrize(
        "planted",
        [
            pytest.param({"input": OTHER_INPUT}, id="another input"),
            pytest.param({"op": "file-write/outside"}, id="another op"),
        ],
    )
    def test_an_approved_intent_under_the_id_that_is_not_this_call_refuses(self, built, planted) -> None:
        """A row at the call's id holding another call: unreachable without a forged row.

        The id binds the op and the input digest, so this plants the row directly. The
        release check compares the stored call to the request and refuses, recorded,
        and never decides afresh or permits.
        """
        runtime, sink = built(held=("shell",))
        decoy = hold(runtime, input_digest=OTHER_INPUT)
        stored = runtime._intent_store.get_intent(decoy.intent_id)
        # Every field but the planted one matches this request, so each case reaches
        # exactly one of the release check's comparisons.
        call = stored.materializedRequest
        call = call.model_copy(update={
            "op": planted.get("op", SHELL),
            "args": {**call.args, "input": planted.get("input", INPUT)},
        })
        hold_id = harness_hold_intent_id(runtime._principal, SHELL, INPUT)
        runtime._intent_store.put_intent(
            stored.model_copy(update={
                "id": hold_id, "materializedRequest": call,
                "status": "approved", "approvedBy": APPROVER,
            })
        )
        before = len(sink.records())
        decision = ask(runtime)
        assert (decision.answer, decision.reason) == ("refuse", pep.HARNESS_RELEASE_MISMATCH_REASON), (
            f"an approved intent holding another call released this one: {decision}"
        )
        (record,) = sink.records()[before:]
        assert (record.decision, record.outcome, record.reason, record.intentId) == (
            "deny", "denied", pep.HARNESS_RELEASE_MISMATCH_REASON, hold_id,
        )
        assert runtime._intent_store.get_intent(hold_id).status == "approved"
        assert counter(runtime) == 0

    def test_an_approval_found_expired_is_recorded_once_and_decided_afresh(self, built, monkeypatch) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=2)
        monkeypatch.setattr(runtime, "_clock", lambda: later)
        decision = ask(runtime)
        assert (decision.answer, decision.outcome) == ("refuse", "held")
        expired = [r for r in sink.records() if r.outcome == "expired"]
        assert len(expired) == 1
        assert (expired[0].intentId, expired[0].approvedBy) == (held.intent_id, APPROVER)
        assert expired[0].reason == pep.HARNESS_APPROVAL_LAPSED_REASON
        assert not any(r.outcome == "permitted" for r in sink.records())

    def test_a_release_whose_record_fails_refuses_and_lands_refused(self, built, monkeypatch) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        real_append = sink.append

        def append(record) -> None:
            if record.outcome == "permitted":
                raise OSError("the tape is unwritable")
            real_append(record)

        monkeypatch.setattr(sink, "append", append)
        assert ask(runtime).answer == "refuse"
        assert runtime.describe_intent(held.intent_id).status == "refused"


# ---------------------------------------------------------------------------
# What the approval surface shows
# ---------------------------------------------------------------------------


class TestTheShownInput:
    def test_the_view_exposes_the_held_input_digest(self, built) -> None:
        runtime, _ = built(held=("shell",))
        held = hold(runtime)
        assert runtime.describe_intent(held.intent_id).input_digest == INPUT
        crm = runtime.handle_request(AgentRequest(tool="crm", op="post", args={"n": 1}))
        assert crm.decision_kind == "require_approval"
        assert runtime.describe_intent(crm.intent_id).input_digest is None

    def test_a_shown_input_that_does_not_match_is_refused_and_recorded(self, built) -> None:
        runtime, sink = built(held=("shell",))
        held = hold(runtime)
        result = runtime.approve_intent(held.intent_id, APPROVER, shown_input_digest=OTHER_INPUT)
        assert (result.executed, result.approved_for_reissue) == (False, False)
        assert result.rejection_reason == pep.SHOWN_INPUT_MISMATCH_REASON
        record = sink.records()[-1]
        assert (record.decision, record.outcome, record.reason, record.intentId) == (
            "deny", "denied", pep.SHOWN_INPUT_MISMATCH_REASON, held.intent_id,
        )
        assert runtime.describe_intent(held.intent_id).status == "pending"
        assert ask(runtime).outcome == "held"

    def test_a_shown_input_that_matches_approves(self, built) -> None:
        runtime, _ = built(held=("shell",))
        held = hold(runtime)
        result = runtime.approve_intent(held.intent_id, APPROVER, shown_input_digest=INPUT)
        assert result.approved_for_reissue is True
        assert ask(runtime).answer == "permit"

    def test_a_shown_input_for_an_intent_that_holds_none_is_refused(self, built) -> None:
        runtime, _ = built()
        taint(runtime)
        crm = runtime.handle_request(AgentRequest(tool="crm", op="post", args={"n": 1}))
        result = runtime.approve_intent(crm.intent_id, APPROVER, shown_input_digest=INPUT)
        assert result.rejection_reason == pep.SHOWN_INPUT_MISMATCH_REASON
        assert runtime.describe_intent(crm.intent_id).status == "pending"


# ---------------------------------------------------------------------------
# Faults and malformed requests answer refuse
# ---------------------------------------------------------------------------


class TestFaults:
    def test_a_fault_inside_the_runtime_answers_refuse_and_is_recorded(self, built, monkeypatch) -> None:
        runtime, sink = built()

        def broken(tool: str, op: str):
            raise RuntimeError("the table is gone")

        monkeypatch.setattr(runtime._optable, "entry", broken)
        decision = ask(runtime)
        assert (decision.answer, decision.reason) == ("refuse", FAULT_REASON)
        (record,) = sink.records()
        assert (record.decision, record.outcome) == ("deny", "denied")
        assert record.reason == f"{FAULT_REASON} (RuntimeError)"

    @pytest.mark.parametrize(
        "bad",
        [
            {"tool_class": "bash"}, {"locality": "anywhere"}, {"harness": "Not A Code"},
            {"input_digest": "make"}, {"call_digest": None}, {"subject_digest": "/etc/passwd"},
        ],
    )
    def test_a_malformed_field_is_refused_and_recorded(self, built, bad) -> None:
        runtime, sink = built()
        decision = ask(runtime, **bad)
        assert (decision.answer, decision.reason) == ("refuse", MALFORMED_REASON)
        (record,) = sink.records()
        assert (record.tool, record.op, record.outcome) == (pep.MOUTH_REFUSAL_TOOL, "tool-event", "denied")
        assert record.argsDigest == hash_args({"cause": "bad-field"})

    @pytest.mark.parametrize(("mouth", "cause"), [("tool-event", "anything"), ("Bad Mouth", "bad-body")])
    def test_a_refusal_names_only_closed_codes(self, built, mouth, cause) -> None:
        runtime, sink = built()
        with pytest.raises(ValueError):
            runtime.refuse_decision_request(mouth=mouth, cause=cause)
        assert sink.records() == []

    def test_no_decision_reaches_a_connector(self, built) -> None:
        """`NoConnector` raises if reached; every path above would have failed on it."""
        runtime, _ = built(held=("shell",))
        held = hold(runtime)
        runtime.approve_intent(held.intent_id, APPROVER)
        assert ask(runtime).answer == "permit"


# ---------------------------------------------------------------------------
# The release's lookup, on every intent store
# ---------------------------------------------------------------------------


def _memory(_tmp: Path):
    return InMemoryIntentStore(hmac_key=b"k")


def _sqlite(tmp: Path):
    return SqliteIntentStore(tmp / "intents.db", hmac_key=b"k")


def _dynamo(_tmp: Path):
    pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                        ("AWS_DEFAULT_REGION", "us-east-1")):
        os.environ.setdefault(name, value)
    from safe_agents.broker.approval.store import DynamoIntentStore  # noqa: PLC0415

    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="intents",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    return DynamoIntentStore("intents", hmac_key=b"k")


@pytest.mark.parametrize("make_store", [_memory, _sqlite, _dynamo], ids=["memory", "sqlite", "dynamo"])
def test_the_release_is_found_by_key_on_every_store(tmp_path: Path, make_store) -> None:
    """Hold, approve, ask again, ask once more: permitted exactly once.

    The approval is found by its content-derived id, so the lookup is the store's
    `get_intent`, a get by key on every backend (on DynamoDB, `GetItem`).
    """
    moto = pytest.importorskip("moto") if make_store is _dynamo else None
    context = moto.mock_aws() if moto is not None else _no_context()
    with context:
        store = make_store(tmp_path)
        runtime = BrokerRuntime(
            principal=PRINCIPAL,
            grants=[make_grant(f"{HARNESS_TOOL}.{SHELL}")],
            optable=ToolOpTable([ToolOp(tool=HARNESS_TOOL, op=SHELL, effect="write",
                                        external=False, reversible=True)]),
            doer=Doer(connectors={}, secrets=FakeSecretsProvider({})),
            pip=make_pip(harness_class_held=True),
            enforcement_store=InMemoryStore(),
            intent_store=store,
            audit_sink=InMemorySink(),
            trust_map=build_trust_map(trusted_prefixes=["internal:"]),
            envelope_hash=ENVELOPE_HASH,
        )
        taint(runtime)
        held = ask(runtime)
        assert held.outcome == "held"
        assert runtime.approve_intent(held.intent_id, APPROVER).approved_for_reissue is True
        released = ask(runtime, call_digest=LATER_CALL)
        assert (released.answer, released.intent_id) == ("permit", held.intent_id)
        assert store.get_intent(held.intent_id).status == "permitted"
        assert ask(runtime).outcome == "held"


class _no_context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None
