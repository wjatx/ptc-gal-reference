"""The reserved coordinate a harness's own tool call is decided at (#168, slice 2).

What this file pins, in the order a request meets it:

- the vocabulary: `harness-tool`, op `<tool_class>/<locality>`, both sides from
  closed sets, and the checked `DecisionRequest` (`schemas/harness_tool.py`,
  `runtime/observed.py`);
- the manifest: a reserved entry whose op is not a valid pair is refused at load,
  and so is a held class no entry declares;
- the agent-facing surfaces: the coordinate is never advertised, and a call that
  names it is refused and recorded before the manifest is consulted;
- the knob: `Envelope.tainted_harness_hold`, folded by the PIP into one fact and
  read by rule `tainted_harness_hold`, which holds a listed class on a tainted
  turn through the polarity seam and moves nothing while the knob is empty;
- the two new terminal words, `permitted` on a record and on an intent.

The runtime's decision method, the hold's release and the `/decide` route are not
here: they are built on top of this, and test themselves.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.approval.types import IntentView
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.prototype.broker_server import holds_harness_class
from safe_agents.broker.runtime import AgentRequest
from safe_agents.broker.runtime.observed import (
    HARNESS_TOOL,
    DecisionRequest,
    Locality,
    ToolClass,
    coordinate_op,
    digest_subject,
    parse_coordinate_op,
    validate_decision_request,
)
from safe_agents.broker.runtime.pep import HARNESS_TOOL_REFUSAL_REASON, OBSERVED_TOOL
from safe_agents.broker.schemas import (
    AgentManifest,
    AuditRecord,
    BrokeredCall,
    Envelope,
    Intent,
    ToolOp,
    compute_envelope_hash,
)
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.tests.test_runtime_observed import MALFORMED

_BROKER_ENV = (
    "BROKER_STORE", "BROKER_MANIFEST", "BROKER_SECRETS", "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE", "BROKER_AUDIT_PATH", "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD", "BROKER_SQLITE_PATH",
)

SUBJECT = digest_subject("/home/someone/project/build.sh")
INPUT = digest_subject('{"command":"make"}')
CALL = digest_subject("toolu_0001")
SHELL_PROJECT = "shell/project"
HOLD_REASON = "tainted harness hold: the envelope holds this tool class on a tainted turn"

ALL_PAIRS = [(c, loc) for c in ToolClass for loc in Locality]


def _request(**overrides: Any) -> dict[str, Any]:
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
    return request


def _harness_op(op: str = SHELL_PROJECT, **facts: Any) -> dict[str, Any]:
    return {"tool": HARNESS_TOOL, "op": op, "effect": "write", "external": False,
            "reversible": True, **facts}


# ---------------------------------------------------------------------------
# The vocabulary
# ---------------------------------------------------------------------------


class TestTheCoordinate:
    def test_the_reserved_tool_is_one_name_everywhere(self) -> None:
        assert HARNESS_TOOL == OBSERVED_TOOL == "harness-tool"

    @pytest.mark.parametrize(("tool_class", "locality"), ALL_PAIRS)
    def test_every_pair_round_trips(self, tool_class, locality) -> None:
        op = coordinate_op(tool_class.value, locality.value)
        assert op == f"{tool_class.value}/{locality.value}"
        assert parse_coordinate_op(op) == (tool_class, locality)
        assert coordinate_op(tool_class, locality) == op

    @pytest.mark.parametrize(
        "op",
        [
            "shell", "shell/", "/project", "shell/project/x", "shell//project",
            "Shell/project", "shell/Project", "bash/project", "shell/anywhere",
            " shell/project", "shell/project ", "shell\\project", "shell.project",
            "", None, 7, ["shell", "project"],
        ],
    )
    def test_anything_else_is_not_a_coordinate(self, op) -> None:
        with pytest.raises(ValueError):
            parse_coordinate_op(op)

    @pytest.mark.parametrize(("tool_class", "locality"), [("bash", "project"), ("shell", "x"), (None, "project")])
    def test_coordinate_op_refuses_a_non_member(self, tool_class, locality) -> None:
        with pytest.raises(ValueError):
            coordinate_op(tool_class, locality)


class TestTheDecisionRequest:
    def test_a_valid_request_names_its_coordinate_and_source(self) -> None:
        checked = validate_decision_request(**_request(tool_class="web-fetch", locality="remote"))
        assert isinstance(checked, DecisionRequest)
        assert checked.op == "web-fetch/remote"
        assert checked.source_id == "harness:example-harness/web-fetch/remote"
        assert checked.taints is True
        assert validate_decision_request(**_request()).taints is False

    @pytest.mark.parametrize(
        "bad",
        [
            # Every malformed shared field the report check refuses...
            *[p for p in MALFORMED if not {"result_digest", "call_digest"} & set(p.values[0])],
            # ...and the two digests a request must carry.
            pytest.param({"input_digest": None}, id="no input digest"),
            pytest.param({"input_digest": '{"command":"make"}'}, id="raw input"),
            pytest.param({"input_digest": INPUT.upper()}, id="uppercase input digest"),
            pytest.param({"call_digest": None}, id="no call digest"),
            pytest.param({"call_digest": "toolu_0001"}, id="a raw call id"),
            pytest.param({"call_digest": CALL[:-1]}, id="short call digest"),
        ],
    )
    def test_a_malformed_request_is_refused(self, bad) -> None:
        with pytest.raises(ValueError):
            validate_decision_request(**_request(**bad))


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


def _manifest(tool_ops: list[dict], **envelope: Any) -> AgentManifest:
    return AgentManifest.model_validate(
        {"tool_ops": tool_ops, "envelope": {"polarity": "abstain", **envelope}}
    )


class TestTheManifest:
    @pytest.mark.parametrize("op", [f"{c.value}/{loc.value}" for c, loc in ALL_PAIRS])
    def test_every_valid_reserved_op_loads(self, op) -> None:
        assert _manifest([_harness_op(op)]).tool_ops[0].op == op

    @pytest.mark.parametrize("op", ["shell", "bash/project", "shell/anywhere", "shell/project/x", "Shell/project", ""])
    def test_a_reserved_entry_whose_op_is_not_a_pair_is_refused_at_load(self, op) -> None:
        with pytest.raises(ValidationError, match=r"tool_ops\[1\] \(harness-tool\." ):
            _manifest([_harness_op("file-read/project"), _harness_op(op)])

    def test_the_same_op_at_another_tool_is_not_constrained(self) -> None:
        """Only the reserved tool's ops are spelled in the vocabulary."""
        assert _manifest([{**_harness_op("anything at all"), "tool": "harness"}])

    def test_a_held_class_with_no_declared_coordinate_is_refused_at_load(self) -> None:
        with pytest.raises(ValidationError, match="would hold nothing"):
            _manifest([_harness_op("file-read/project")], tainted_harness_hold=["shell"])

    def test_a_held_class_declared_at_any_locality_loads(self) -> None:
        manifest = _manifest([_harness_op("shell/outside")], tainted_harness_hold=["shell"])
        assert manifest.envelope.tainted_harness_hold == [ToolClass.SHELL]


# ---------------------------------------------------------------------------
# The knob
# ---------------------------------------------------------------------------


class TestTheKnob:
    def test_it_ships_off_and_dumps_like_every_other_field(self) -> None:
        envelope = Envelope(polarity="abstain")
        assert envelope.tainted_harness_hold == []
        assert envelope.model_dump(mode="json")["tainted_harness_hold"] == []

    def test_turning_it_on_moves_the_hash(self) -> None:
        off = compute_envelope_hash(Envelope(polarity="abstain"))
        on = compute_envelope_hash(Envelope(polarity="abstain", tainted_harness_hold=["shell"]))
        assert off != on

    @pytest.mark.parametrize(
        "value",
        [["bash"], ["SHELL"], ["shell", "shell"], ["shell/project"], [None], "shell"],
    )
    def test_anything_but_distinct_tool_classes_is_refused(self, value) -> None:
        with pytest.raises(ValidationError):
            Envelope(polarity="abstain", tainted_harness_hold=value)


def _brokered(tool: str, op: str, *, tainted: bool, principal: Any = None) -> BrokeredCall:
    sources = ["harness:example-harness/file-read/outside"] if tainted else []
    return BrokeredCall.model_validate({
        "principal": principal or {"agentId": "a", "skill": "s", "user": "u", "tier": "C"},
        "tool": tool,
        "op": op,
        "args": {"input": INPUT},
        "manifest": {"tool": tool, "op": op, "effect": "write", "external": False, "reversible": True},
        "taint": {"tainted": tainted, "sources": sources},
        "session": {"turnId": "t", "ingestedSources": sources},
        "ts": "2026-10-12T00:00:00Z",
    })


class TestThePipFact:
    """`holds_harness_class`: the knob and the coordinate, folded into one bool."""

    @pytest.mark.parametrize(
        ("tool", "op", "held", "expected"),
        [
            pytest.param(HARNESS_TOOL, "shell/project", (), False, id="empty knob"),
            pytest.param(HARNESS_TOOL, "shell/project", ("shell",), True, id="listed class"),
            pytest.param(HARNESS_TOOL, "shell/outside", ("shell",), True, id="listed class, other locality"),
            pytest.param(HARNESS_TOOL, "file-read/project", ("shell",), False, id="unlisted class"),
            pytest.param("shell", "shell/project", ("shell",), False, id="another tool, same op"),
            pytest.param("harness-tools", "shell/project", ("shell",), False, id="a near-miss tool"),
            pytest.param(HARNESS_TOOL, "not-a-pair", ("shell",), True, id="unparseable op, knob on"),
            pytest.param(HARNESS_TOOL, "not-a-pair", (), False, id="unparseable op, knob off"),
        ],
    )
    def test_the_fact(self, tool, op, held, expected) -> None:
        call = _brokered(tool, op, tainted=True)
        assert holds_harness_class(call, frozenset(ToolClass(c) for c in held)) is expected


def _facts(**kwargs: Any) -> Facts:
    base = dict(
        grant_present=True,
        grant_level=AutonomyLevel.out_of_loop,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=True,
        human_reachable=True,
    )
    return Facts(**{**base, **kwargs})


class TestTheRule:
    @pytest.mark.parametrize(
        ("tainted", "held", "kind", "reason"),
        [
            (True, True, "require_approval", HOLD_REASON),
            (False, True, "allow", None),
            (True, False, "allow", None),
            (False, False, "allow", None),
        ],
    )
    def test_it_holds_only_a_held_class_on_a_tainted_turn(self, tainted, held, kind, reason) -> None:
        decision = decide(_brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=tainted),
                          _facts(harness_class_held=held))
        assert decision.kind == kind
        assert getattr(decision, "reason", None) == reason

    @pytest.mark.parametrize(
        "manifest",
        [
            {"effect": "read", "external": False, "reversible": None},
            {"effect": "read", "external": True, "reversible": None},
            {"effect": "write", "external": True, "reversible": True},
            {"effect": "write", "external": True, "reversible": False},
        ],
    )
    def test_it_names_itself_whatever_the_consumer_declared(self, manifest) -> None:
        call = _brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=True)
        call = call.model_copy(update={"manifest": ToolOp(tool=HARNESS_TOOL, op=SHELL_PROJECT, **manifest)})
        decision = decide(call, _facts(harness_class_held=True, destination_composed=True))
        assert (decision.kind, decision.reason) == ("require_approval", HOLD_REASON)

    def test_with_no_human_it_denies_through_the_seam(self) -> None:
        decision = decide(_brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=True),
                          _facts(harness_class_held=True, human_reachable=False))
        assert (decision.kind, decision.reason) == (
            "deny", HOLD_REASON + "; no human reachable for approval",
        )

    def test_anything_stricter_still_binds(self) -> None:
        call = _brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=True)
        assert decide(call, _facts(harness_class_held=True, grant_present=False)).kind == "deny"
        capped = decide(call, _facts(harness_class_held=True, cap_budget_breached=True))
        assert (capped.kind, capped.reason) == ("deny", "capacity budget breached")


# ---------------------------------------------------------------------------
# Through build_runtime: the agent-facing refusal, the served view, the hold
# ---------------------------------------------------------------------------


class _UnusedConnector:
    """Named so the manifest's connector wiring loads; never reached here."""

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        raise AssertionError("no connector is reached in these tests")


def _write_manifest(path: Path, *, held: tuple[str, ...] = ()) -> Path:
    hold = ""
    if held:
        hold = "  tainted_harness_hold:\n" + "".join(f"    - {c}\n" for c in held)
    path.write_text(
        textwrap.dedent(
            f"""\
            principal:
              agentId: harness-test
              skill: research
              user: local-developer
              tier: C
            grant_classes:
              - crm.post
              - {HARNESS_TOOL}.{SHELL_PROJECT}
            connectors:
              - crm
            connector_providers:
              crm: "safe_agents.broker.tests.test_harness_tool:_UnusedConnector"
            tool_ops:
              - {{tool: crm, op: post, effect: write, external: true, reversible: true}}
              - {{tool: {HARNESS_TOOL}, op: "{SHELL_PROJECT}", effect: write, external: false, reversible: true}}
            envelope:
              polarity: abstain
              caps:
                actions_per_run: 25
              high_stakes: false
            """
        )
        + hold,
        encoding="utf-8",
    )
    return path


@pytest.fixture
def built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    made: list = []

    def build(*, held: tuple[str, ...] = ()):
        manifest = load_agent_manifest(_write_manifest(tmp_path / f"m{len(made)}.yaml", held=held))
        runtime, sink = build_runtime(manifest)
        made.append(runtime)
        return runtime, sink

    try:
        yield build
    finally:
        for runtime in made:
            runtime.close()


def _expect_no_connector(handle, request: AgentRequest, mechanism: str, **kwargs: Any):
    """Run `handle(request)`, failing with `mechanism` if the call reached the Doer.

    No connector is registered at the reserved tool, so a call there that the
    broker failed to refuse or hold surfaces as the Doer's own error. That error
    names the Doer, not what broke; this names what broke.
    """
    try:
        return handle(request, **kwargs)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{mechanism}: the call reached the Doer ({type(exc).__name__}: {exc})")


_NOT_REFUSED = f"a call naming {HARNESS_TOOL} was not refused before the pipeline"


def _taint(runtime) -> None:
    runtime.record_observed_event(
        mouth="tool-event", harness="example-harness", tool_class="file-read",
        locality="outside", subject_digest=SUBJECT,
    )


class TestTheAgentFacingSurfaces:
    def test_the_reserved_coordinate_is_never_served_even_when_granted(self, built) -> None:
        runtime, _ = built()
        assert [(op.tool, op.op) for op in runtime.served_registry()] == [("crm", "post")]
        assert [t.wire_name for t in GatewaySurface(runtime).tools()] == ["crm__post"]

    def test_the_table_still_resolves_it_for_the_runtime(self) -> None:
        entry = ToolOp(tool=HARNESS_TOOL, op=SHELL_PROJECT, effect="write", external=False)
        table = ToolOpTable([entry])
        assert table.entry(HARNESS_TOOL, SHELL_PROJECT) == entry
        assert table.served(None, []) == []  # type: ignore[arg-type]

    @pytest.mark.parametrize("op", [SHELL_PROJECT, "file-read/outside", "not-a-pair"])
    def test_a_call_naming_it_is_refused_and_recorded_before_the_manifest(self, built, monkeypatch, op) -> None:
        runtime, sink = built()
        looked_up: list[tuple[str, str]] = []
        real_entry = runtime._optable.entry
        monkeypatch.setattr(
            runtime._optable, "entry", lambda t, o: looked_up.append((t, o)) or real_entry(t, o)
        )
        response = _expect_no_connector(
            runtime.handle_request, AgentRequest(tool=HARNESS_TOOL, op=op, args={"x": 1}), _NOT_REFUSED
        )
        assert (response.decision_kind, response.reason) == ("deny", HARNESS_TOOL_REFUSAL_REASON)
        assert looked_up == []
        (record,) = sink.records()
        assert (record.tool, record.op, record.decision, record.outcome, record.reason) == (
            HARNESS_TOOL, op, "deny", "denied", HARNESS_TOOL_REFUSAL_REASON,
        )

    def test_refusing_it_never_drops_the_taint_its_caller_passed(self, built) -> None:
        runtime, _ = built()
        _expect_no_connector(
            runtime.handle_request,
            AgentRequest(tool=HARNESS_TOOL, op=SHELL_PROJECT, args={}),
            _NOT_REFUSED,
            ingested_sources=["email:untrusted"],
        )
        assert runtime.session_turn().tainted is True

    def test_an_mcp_call_naming_it_is_refused_and_recorded(self, built) -> None:
        runtime, sink = built()
        result = GatewaySurface(runtime).call(f"{HARNESS_TOOL}__{SHELL_PROJECT}", {"x": 1})
        assert (result.ok, result.decision_kind, result.reason) == (
            False, "deny", HARNESS_TOOL_REFUSAL_REASON,
        )
        assert [(r.tool, r.op, r.outcome) for r in sink.records()] == [
            (HARNESS_TOOL, SHELL_PROJECT, "denied"),
        ]

    def test_a_tainted_turn_makes_no_difference_to_the_refusal(self, built) -> None:
        runtime, sink = built(held=("shell",))
        _taint(runtime)
        response = _expect_no_connector(
            runtime.handle_request, AgentRequest(tool=HARNESS_TOOL, op=SHELL_PROJECT, args={}),
            _NOT_REFUSED,
        )
        assert (response.decision_kind, response.reason) == ("deny", HARNESS_TOOL_REFUSAL_REASON)
        assert sink.records()[-1].outcome == "denied"


class TestTheHoldThroughTheRuntime:
    """The internal path stays open: the PIP folds the knob and rule 7 decides."""

    def test_a_held_class_on_a_tainted_turn_is_held_and_names_the_rule(self, built) -> None:
        runtime, sink = built(held=("shell",))
        _taint(runtime)
        response = _expect_no_connector(
            runtime._handle_request,
            AgentRequest(tool=HARNESS_TOOL, op=SHELL_PROJECT, args={"input": INPUT}),
            "the held class was not held on a tainted turn: the built PIP did not fold "
            "Envelope.tainted_harness_hold, or rule 7 did not fire",
        )
        assert response.decision_kind == "require_approval"
        held = sink.records()[-1]
        assert (held.tool, held.op, held.outcome, held.reason) == (
            HARNESS_TOOL, SHELL_PROJECT, "held", HOLD_REASON,
        )

    @pytest.mark.parametrize(("held", "expected"), [((), False), (("shell",), True)])
    def test_the_built_pip_folds_the_envelope_knob(self, built, held, expected) -> None:
        """`build_runtime` threads `Envelope.tainted_harness_hold` into the PIP."""
        runtime, _ = built(held=held)
        call = _brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=True)
        assert runtime._pip(call).harness_class_held is expected

    def test_with_the_knob_empty_the_same_request_is_not_held(self, built) -> None:
        """The same coordinate, granted and tainted, with no class listed: no hold."""
        runtime, _ = built()
        call = _brokered(HARNESS_TOOL, SHELL_PROJECT, tainted=True,
                         principal=runtime._principal.model_dump())
        facts = runtime._pip(call)
        assert facts.grant_present is True
        assert decide(call, facts).kind == "allow"
        held_runtime, _ = built(held=("shell",))
        decision = decide(call, held_runtime._pip(call))
        assert (decision.kind, decision.reason) == ("require_approval", HOLD_REASON)


# ---------------------------------------------------------------------------
# The two terminal words
# ---------------------------------------------------------------------------


class TestTheTerminalWords:
    def test_permitted_is_an_audit_outcome(self) -> None:
        field = AuditRecord.model_fields["outcome"]
        assert "permitted" in field.annotation.__args__

    def test_permitted_is_an_intent_status_and_a_view_status(self) -> None:
        assert "permitted" in Intent.model_fields["status"].annotation.__args__
        assert "permitted" in IntentView.__annotations__["status"]
