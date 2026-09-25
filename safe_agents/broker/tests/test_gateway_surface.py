"""Conformance for the broker's MCP mouth — the pure half (#283).

No `mcp` SDK is imported here, by design: the gateway's decisions live in
`gateway/surface.py` and must be provable without a transport or an optional
extra. The SDK-bound half is `test_gateway_stdio.py`.

The runtime under test is composed from `examples/embedded_agent/manifest.yaml`
rather than a bespoke fixture. That example already carries the shape this needs —
one granted read and one classified-but-ungranted write — and reusing it means a
change that broke the example's premise would break this suite too, instead of the
two drifting into disagreement about what the broker does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.gateway import GatewayNameCollision, GatewaySurface
from safe_agents.broker.schemas.manifest import ToolOp

_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3] / "examples" / "embedded_agent" / "manifest.yaml"
)


@pytest.fixture
def surface(monkeypatch: pytest.MonkeyPatch):
    """A gateway over a real in-memory runtime, with no BROKER_* arm selected."""
    for var in (
        "BROKER_STORE",
        "BROKER_MANIFEST",
        "BROKER_SECRETS",
        "BROKER_SECRETS_DIR",
        "BROKER_SECRETS_FILE",
        "BROKER_AUDIT_PATH",
        "BROKER_AUDIT_BUCKET",
        "BROKER_ENVELOPE_LOAD",
        "BROKER_GRANT_LOAD",
        "BROKER_SQLITE_PATH",
    ):
        monkeypatch.delenv(var, raising=False)

    runtime, sink = build_runtime(load_agent_manifest(_MANIFEST_PATH))
    try:
        yield GatewaySurface(runtime), sink
    finally:
        runtime.close()


class TestAdvertisedTools:
    def test_lists_only_granted_ops(self, surface) -> None:
        gateway, _ = surface
        names = [tool.wire_name for tool in gateway.tools()]
        # search.query is granted; notify.send is classified but NOT granted, and
        # served_registry removes rather than refuses.
        assert names == ["search__query"]

    def test_description_is_broker_authored_from_the_classification(self, surface) -> None:
        """The advertised description must come from OUR manifest, not a server's.

        A description is model-facing steering and therefore injection surface
        (MCP-HOST.md M2). Sourcing it from the broker's own ToolOp means there is
        nothing to launder, and it tells the model what the broker thinks the op is.
        """
        gateway, _ = surface
        (tool,) = gateway.tools()
        assert tool.description.startswith("search.query — brokered read, local")
        assert "decided and recorded by the broker" in tool.description

    def test_schema_is_permissive_and_open(self, surface) -> None:
        """Pinned as a deliberate placeholder, not an accident.

        served_registry() carries no argument schema and the ratified schemas live
        in registry rows build_runtime does not return (#266 finding). A schema the
        gateway invented would have clients refuse valid calls locally — enforcement
        in the wrong place, and off the audit tape.
        """
        gateway, _ = surface
        (tool,) = gateway.tools()
        assert tool.input_schema == {"type": "object", "additionalProperties": True}


class TestCallRouting:
    def test_granted_call_executes(self, surface) -> None:
        gateway, _ = surface
        result = gateway.call("search__query", {"query": "broker"})
        assert result.ok is True
        assert result.decision_kind == "allow"
        assert result.structured["hits"][0]["topic"] == "broker"

    def test_ungranted_call_is_refused_by_the_broker_and_audited(self, surface) -> None:
        """The DoD refusal: not listed, asked for anyway, refused ON THE RECORD.

        This is the whole reason `call()` does not answer unknown names itself. The
        gateway never advertised notify__send, but a client is free to ask, and the
        refusal has to be the broker's so that it lands on the tape.
        """
        gateway, sink = surface
        before = len(sink.records())

        result = gateway.call("notify__send", {"text": "shipping it"})

        assert result.ok is False
        assert result.decision_kind == "deny"
        assert result.reason == "tool not granted to this principal"
        assert "refused by the broker" in result.text

        new_records = sink.records()[before:]
        assert [(r.decision, r.outcome) for r in new_records] == [("deny", "denied")]

    def test_a_name_with_no_separator_is_answered_by_the_mouth(self, surface) -> None:
        """The one case the gateway must answer itself — there is no coordinate.

        Everything else is handed to the broker. This is refused without an audit
        record because nothing was ever routed; the text says so plainly rather
        than inventing a (tool, op) the operator never wrote.
        """
        gateway, sink = surface
        before = len(sink.records())

        result = gateway.call("notatool", {})

        assert result.ok is False
        assert result.reason == "unroutable tool name"
        assert len(sink.records()) == before

    def test_unclassified_coordinate_is_refused_AND_recorded(self, surface) -> None:
        """Was the reverse assertion until #281 was fixed, and worth the history.

        `handle_request` denies an op absent from `tool_ops` before the PDP runs,
        and that early return used to write NOTHING — so a refusal left no line on
        the tape. This test pinned that as an "honest, uncomfortable property".

        It was the wrong thing to pin. The live gateway drill showed the gap
        correlates with the SAFEST configuration: the missileer archetype keeps a
        dangerous op out of the manifest entirely rather than denying it, so the
        hardened manifest is exactly the one whose refusals were invisible. The
        record is now written, shaped like any other broker refusal.
        """
        gateway, sink = surface
        before = len(sink.records())

        result = gateway.call("nosuch__op", {})

        assert result.ok is False
        assert result.decision_kind == "deny"
        assert "no manifest entry" in (result.reason or "")

        new = sink.records()[before:]
        assert [(r.tool, r.op, r.decision, r.outcome) for r in new] == [
            ("nosuch", "op", "deny", "denied")
        ]
        assert "no manifest entry" in (new[0].reason or "")


class TestNameCollision:
    def test_single_underscores_do_not_collide(
        self, monkeypatch: pytest.MonkeyPatch, surface
    ) -> None:
        """The common case must keep working — only the SEPARATOR is ambiguous.

        `a_b.c` and `a.b_c` flatten to `a_b__c` and `a__b_c`, which are distinct.
        Refusing these would make the gateway unusable for ordinary snake_case
        tool names, which is most of them.
        """
        gateway, _ = surface
        monkeypatch.setattr(
            gateway._runtime,
            "served_registry",
            lambda: [
                ToolOp(tool="a_b", op="c", effect="read", external=False),
                ToolOp(tool="a", op="b_c", effect="read", external=False),
            ],
        )
        assert [t.wire_name for t in gateway.tools()] == ["a__b_c", "a_b__c"]

    def test_colliding_coordinates_refuse_rather_than_shadow(
        self, monkeypatch: pytest.MonkeyPatch, surface
    ) -> None:
        """`a.b__c` and `a__b.c` both flatten to `a__b__c`; serving either is wrong.

        One would silently shadow the other and calls meant for one op would
        execute the other — a dispatch bug that reads as a working gateway.
        """
        gateway, _ = surface
        monkeypatch.setattr(
            gateway._runtime,
            "served_registry",
            lambda: [
                ToolOp(tool="a", op="b__c", effect="read", external=False),
                ToolOp(tool="a__b", op="c", effect="read", external=False),
            ],
        )
        with pytest.raises(GatewayNameCollision) as exc:
            gateway.tools()
        assert "a__b__c" in str(exc.value)


class TestRefusalIsNotFailure:
    """#281 — a control that REFUSED must not audit as an execution failure.

    Before this, a tool declared in the manifest but carrying no ratified
    registry row (key #1 present, key #2 absent) was correctly refused and then
    recorded as `decision=allow, outcome=failed` — shape-identical to a network
    blip or a crashed MCP child. Anything counting refusals counted none of them,
    and the only thing separating policy from breakage was a substring inside
    `error`.
    """

    def test_the_doer_marks_a_refusal_distinctly_from_a_failure(self) -> None:
        from safe_agents.broker.mcp.host import ToolNotCallableError
        from safe_agents.broker.runtime.doer import (
            ConnectorExecutionError,
            ConnectorRefusedError,
        )

        assert issubclass(ToolNotCallableError, ConnectorRefusedError)
        # The classification survives the deliberate un-chaining: the original
        # exception is dropped (it may carry a credential), its TYPE is not.
        assert ConnectorExecutionError("x", refused=True).refused is True
        assert ConnectorExecutionError("x").refused is False

    def test_a_refused_connector_call_audits_as_refused(self, surface) -> None:
        """Driven through the real PEP path, with a connector that refuses."""
        from safe_agents.broker.runtime.doer import ConnectorRefusedError

        gateway, sink = surface

        class _Refuser:
            def execute(self, tool, op, args, credential):  # noqa: ANN001, ARG002
                raise ConnectorRefusedError("declared but no admitted registry row")

        gateway._runtime._doer._connectors["search"] = _Refuser()
        before = len(sink.records())

        result = gateway.call("search__query", {"query": "broker"})

        assert result.ok is False
        new = sink.records()[before:]
        # decision stays as the PDP returned it — it DID allow, and saying
        # otherwise would misreport the policy engine. The outcome carries it.
        assert [(r.decision, r.outcome) for r in new] == [("allow", "refused")]
        assert "refused" in (new[0].error or "")

    def test_a_broken_connector_still_audits_as_failed(self, surface) -> None:
        """The other side of the fork, so `refused` cannot quietly absorb it."""
        gateway, sink = surface

        class _Breaker:
            def execute(self, tool, op, args, credential):  # noqa: ANN001, ARG002
                raise TimeoutError("upstream went away")

        gateway._runtime._doer._connectors["search"] = _Breaker()
        before = len(sink.records())

        gateway.call("search__query", {"query": "broker"})

        new = sink.records()[before:]
        assert [(r.decision, r.outcome) for r in new] == [("allow", "failed")]


class _Breaker:
    def execute(self, tool, op, args, credential):  # noqa: ANN001, ARG002
        raise TimeoutError("upstream went away")


class _Refuser:
    def execute(self, tool, op, args, credential):  # noqa: ANN001, ARG002
        from safe_agents.broker.runtime.doer import ConnectorRefusedError

        raise ConnectorRefusedError("declared but no admitted registry row")


def _break_connector(runtime) -> None:
    runtime._doer._connectors["search"] = _Breaker()


def _refuse_at_connector(runtime) -> None:
    runtime._doer._connectors["search"] = _Refuser()


def _drop_secrets(runtime) -> None:
    from safe_agents.broker.runtime.secrets import FakeSecretsProvider

    runtime._doer._secrets = FakeSecretsProvider({})


def _leave_alone(runtime) -> None:  # noqa: ARG001
    pass


class TestOutcomesReadDifferently:
    """The README promises a gate refusal and an execution failure read differently.

    An outside run found they did not: a declared tool whose connector failed came
    back as "refused by the broker", and a missing credential came back as a raw
    KeyError string. Each outcome now has its own framing, keyed on structured
    fields (`decision_kind`, `execution_outcome`, or the broker raising), never on
    the reason text.
    """

    @pytest.mark.parametrize(
        ("wire_name", "arrange", "decision_kind", "execution_outcome", "prefix", "absent"),
        [
            pytest.param(
                "payments__transfer",
                _leave_alone,
                "deny",
                None,
                "payments.transfer refused by the broker: no manifest entry",
                "allowed",
                id="undeclared-tool-is-a-gate-refusal",
            ),
            pytest.param(
                "search__query",
                _break_connector,
                "deny",
                "failed",
                "search.query was allowed by the broker but failed at the connector",
                "refused by the broker",
                id="declared-tool-connector-failure",
            ),
            pytest.param(
                "search__query",
                _refuse_at_connector,
                "deny",
                "refused",
                "search.query was allowed by the broker but refused at the connector",
                "refused by the broker",
                id="declared-tool-connector-refusal",
            ),
            pytest.param(
                "search__query",
                _drop_secrets,
                "error",
                None,
                "search.query did not complete: the broker hit an internal error (KeyError)",
                "unknown secret",
                id="missing-secret-is-framed-not-raw",
            ),
        ],
    )
    def test_each_outcome_has_its_own_framing(
        self, surface, wire_name, arrange, decision_kind, execution_outcome, prefix, absent
    ) -> None:
        gateway, _ = surface
        arrange(gateway._runtime)

        result = gateway.call(wire_name, {"query": "broker"})

        assert result.ok is False
        assert result.decision_kind == decision_kind
        assert result.execution_outcome == execution_outcome
        assert result.text.startswith(prefix), result.text
        assert absent not in result.text
