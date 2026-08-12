"""Tests for the LOCAL release of a held intent (#301).

sa#176 built the out-of-band approval seam and every caller of it was a cloud path
(an owner-adapter EventTrigger through a channels drain). On a laptop there is no
channel, so a held call was held until its TTL expired — the golden path dead-ended
at the exact moment the control worked. These cover the local arm:

  - ``BrokerRuntime.describe_intent`` — the READ half of WYSIWYE. approve() has always
    executed the stored bytes; nothing let an approver SEE them first.
  - ``local_release_identity`` — honest attribution for a release nobody authenticated.
  - ``release_cli`` — the terminal surface, including that a declined prompt leaves the
    intent held.

All in-memory; no AWS, no subprocess.
"""

from __future__ import annotations

import pytest

from safe_agents.broker import ceremony_identity
from safe_agents.broker.approval import IntentView
from safe_agents.broker.approval import release_cli
from safe_agents.broker.audit import hash_args
from safe_agents.broker.ceremony_identity import (
    LOCAL_IDENTITY_PREFIX,
    LOCAL_RELEASE_ROLE,
    local_release_identity,
)
from safe_agents.broker.prototype.boot_config import BrokerConfigError
from safe_agents.broker.tests.test_out_of_band_approval import (
    _materialize_held_intent,
    _payments_runtime,
)


# ---------------------------------------------------------------------------
# 1. describe_intent — the see half of WYSIWYE
# ---------------------------------------------------------------------------


def test_describe_intent_returns_the_stored_call():
    """The view describes the STORED materializedRequest, not anything re-sent."""
    runtime, _sink, _stubs, intent_store = _payments_runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)

    view = runtime.describe_intent(intent_id)

    assert isinstance(view, IntentView)
    assert view.intent_id == intent_id
    assert view.status == "pending"
    assert (view.tool, view.op) == ("payments", "transfer")
    stored = intent_store.get_intent(intent_id).materializedRequest
    assert view.args_digest == hash_args(stored.args)
    assert view.rendered_for_human == intent_store.get_intent(intent_id).renderedForHuman
    assert view.approved_by is None


def test_describe_intent_carries_no_raw_args():
    """The view exposes a digest and a broker render — never the raw args.

    An approval prompt must not become the place secrets get printed, the same
    discipline that keeps raw args off the audit tape.
    """
    runtime, _sink, _stubs, intent_store = _payments_runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)

    view = runtime.describe_intent(intent_id)

    assert not hasattr(view, "args")
    # "acct-xyz" is the stored arg value; it must not ride out on the view.
    assert "acct-xyz" not in view.args_digest


def test_describe_intent_executes_and_transitions_nothing():
    """Looking at a held intent leaves it held, with no connector call and no audit."""
    runtime, sink, stubs, intent_store = _payments_runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)
    audit_before = len(sink.records())
    calls_before = len(stubs["payments"].calls)

    runtime.describe_intent(intent_id)
    runtime.describe_intent(intent_id)

    assert intent_store.get_intent(intent_id).status == "pending"
    assert len(stubs["payments"].calls) == calls_before
    assert len(sink.records()) == audit_before


def test_describe_intent_unknown_is_none():
    runtime, _sink, _stubs, _store = _payments_runtime()
    assert runtime.describe_intent("intent-does-not-exist") is None


def test_describe_intent_refuses_a_foreign_principal():
    """Another principal's held intent reads as ABSENT, so this cannot enumerate.

    Absent and not-yours are deliberately the same answer — a distinguishable
    "exists but not yours" would confirm the existence of another agent's held call.
    """
    runtime_a, _sink, _stubs, store_a = _payments_runtime()
    intent_id = _materialize_held_intent(runtime_a, store_a)

    # A second runtime whose principal differs, pointed at the SAME intent store.
    runtime_b, _sink_b, _stubs_b, _store_b = _payments_runtime()
    runtime_b._intent_store = store_a
    runtime_b._principal = runtime_b._principal.model_copy(
        update={"agentId": "agent-somebody-else"}
    )

    assert runtime_b.describe_intent(intent_id) is None
    # ...and the intent is untouched by the refusal.
    assert store_a.get_intent(intent_id).status == "pending"


def test_describe_then_approve_agree_on_the_same_bytes():
    """What describe_intent renders is what approve_intent executes (WYSIWYE)."""
    runtime, sink, stubs, intent_store = _payments_runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)

    view = runtime.describe_intent(intent_id)
    result = runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    assert result.executed is True
    executed = stubs["payments"].calls[-1]
    assert (view.tool, view.op) == (executed.tool, executed.op)
    assert view.args_digest == hash_args(executed.args)
    # The tape binds the release to the intent the human looked at.
    released = sink.records()[-1]
    assert released.intentId == view.intent_id
    assert released.approvedBy == "owner:maintainer"


def test_describe_intent_reports_a_terminal_status():
    """After a release the view says 'executed' and names the approver."""
    runtime, _sink, _stubs, intent_store = _payments_runtime()
    intent_id = _materialize_held_intent(runtime, intent_store)
    runtime.approve_intent(intent_id, approved_by="owner:maintainer")

    view = runtime.describe_intent(intent_id)
    assert view.status == "executed"
    assert view.approved_by == "owner:maintainer"


# ---------------------------------------------------------------------------
# 2. local_release_identity — honest attribution, never authentication
# ---------------------------------------------------------------------------


def test_local_release_identity_is_derived_and_marked_solo(monkeypatch):
    monkeypatch.setattr(ceremony_identity.getpass, "getuser", lambda: "maintainer")
    monkeypatch.setattr(ceremony_identity.socket, "gethostname", lambda: "macbook.local")

    identity = local_release_identity()

    assert identity == f"{LOCAL_IDENTITY_PREFIX}maintainer@macbook#{LOCAL_RELEASE_ROLE}"
    # The `local-solo:` prefix is the honesty: a reader of raw record JSON sees on
    # its face that one operator on one machine attested this, with no second party.
    assert identity.startswith(LOCAL_IDENTITY_PREFIX)


def test_local_release_identity_cannot_forge_structure(monkeypatch):
    """Reserved separators in the OS user cannot fabricate extra identity structure."""
    monkeypatch.setattr(ceremony_identity.getpass, "getuser", lambda: "evil#owner@host")
    monkeypatch.setattr(ceremony_identity.socket, "gethostname", lambda: "box")

    identity = local_release_identity()

    assert identity.count("#") == 1
    assert identity.endswith(f"#{LOCAL_RELEASE_ROLE}")


def test_local_release_identity_refused_against_the_cloud_floor(monkeypatch):
    """On the dynamo arm a real authenticated approver exists; refuse to downgrade.

    A solo-derived `approvedBy` reaching the cloud audit tape would be a weaker
    attribution that nothing in the record reveals as a CHOICE.
    """
    monkeypatch.setenv("BROKER_STORE", "dynamo")
    with pytest.raises(BrokerConfigError, match="owner channel"):
        local_release_identity()


# ---------------------------------------------------------------------------
# 3. release_cli — the terminal surface
# ---------------------------------------------------------------------------


def _view(**overrides) -> IntentView:
    base = dict(
        intent_id="intent-abc",
        status="pending",
        tool="memory",
        op="create_entities",
        args_digest="sha256:9f2c1a",
        rendered_for_human="create 3 entities in the knowledge graph",
        expiry="2026-07-29T15:02:11+00:00",
        ts="2026-07-29T14:02:11+00:00",
        agent_id="agent:claude-code",
    )
    base.update(overrides)
    return IntentView(**base)


def test_render_shows_the_coordinates_the_digest_and_the_broker_render():
    text = release_cli.render_intent(_view())

    for expected in (
        "intent-abc",
        "memory.create_entities",
        "sha256:9f2c1a",
        "create 3 entities in the knowledge graph",
        "agent:claude-code",
    ):
        assert expected in text


def test_render_says_the_grant_is_unchanged_and_warns_against_a_retry():
    """The two things a user gets wrong: thinking release widens the grant, and
    telling the agent to re-run a call that has now already executed."""
    text = release_cli.render_intent(_view())
    assert "does not change the grant" in text
    assert "DONE" in text


def test_non_interactive_stdin_is_a_no(monkeypatch, capsys):
    """Silence is never an implied yes — `--yes` is how a human approves in advance."""
    monkeypatch.setattr(release_cli.sys.stdin, "isatty", lambda: False)
    assert release_cli._confirm("Release? ") is False
    assert "not a terminal" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("answer", "released"),
    [("y", True), ("yes", True), ("Y", True), ("n", False), ("", False), ("nope", False)],
)
def test_confirmation_requires_an_explicit_yes(monkeypatch, answer, released):
    monkeypatch.setattr(release_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: answer)
    assert release_cli._confirm("Release? ") is released


def test_interrupted_prompt_is_a_no(monkeypatch):
    """Ctrl-C at the prompt leaves the intent held rather than crashing out."""
    monkeypatch.setattr(release_cli.sys.stdin, "isatty", lambda: True)

    def _interrupt(_prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _interrupt)
    assert release_cli._confirm("Release? ") is False
