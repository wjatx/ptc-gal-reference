"""surface.py — the broker's MCP mouth, as pure logic (#283).

This module is deliberately **SDK-free**. It computes what the gateway advertises
and what it answers, in plain dataclasses, so the decisions can be tested without
the `mcp` extra installed and without a transport. `server.py` is the thin binding
that dresses these values in SDK types — the same split `discovery.py` (pure gate)
and `client.py` (the one SDK importer) already use on the client side.

## What a mouth is, and what it is not

The broker already has one mouth: the JSON-over-HTTP `/call` handler in
`prototype/broker_server.py`. This is a second one, speaking MCP over stdio, so a
wrapped agent sees exactly ONE MCP server whose tools are the ops the broker will
serve it. A mouth **carries** calls to `handle_request`; it never decides one. Every
call goes through the full per-call path — PDP decision, taint, budgets, audit —
because it goes through `handle_request` like every other caller.

That is why the gateway is base-side [ruling: maintainer, 2026-07-25]. A gateway
implemented inside a consumer-side wrapper would be a second broker mouth living outside
the broker, which cuts against "the broker is the one deliberately non-swappable
implementation". The product wrapper's job is to configure and launch this; not to be it.

## Listing is not authority

`tools()` reports `runtime.served_registry()` — the ops this principal was granted.
An ungranted op is absent rather than refused ("removal, not refusal",
`runtime/pep.py:311-317`). But absence from the list is a **display** property, not
a control: nothing stops a client asking for a name that was never listed, so
`call()` hands any unrecognized name to the broker rather than answering for it.
The broker is the only thing here entitled to say no, and its no is the one that
gets audited.

An op the manifest never CLASSIFIED is denied by `handle_request` before the PDP
runs (`runtime/pep.py:838-864`). That early return used to write no audit record —
a refusal with no line on the tape — which was the worse half of #281, because the
missileer archetype keeps a dangerous op OUT of the manifest rather than denying
it, so the most hardened manifest was the one whose refusals were invisible. #281
closed that: both refusal shapes now record `deny`/`denied`, and the reason string
carries which.

The honest limit that remains is about who can reach them. An ungranted op is not
advertised, so a well-behaved client never calls one — every refusal on the tape
comes from a client asking for a name it was never offered. That is the compromised
agent, which is the case worth auditing, but it does mean a deny is not something an
honest agent produces in normal operation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from safe_agents.broker.marshal import marshal_connector_result
from safe_agents.broker.runtime.pep import AgentRequest, BrokerRuntime
from safe_agents.broker.schemas.manifest import ToolOp

#: How a broker coordinate `(tool, op)` becomes one MCP tool name. Two underscores
#: because MCP clients commonly restrict tool names to `[A-Za-z0-9_-]`, which rules
#: out the broker's own `tool.op` spelling. The mapping is kept as DATA (see
#: `GatewaySurface._index`) and never re-parsed out of the wire name. A single
#: underscore in a tool or op is harmless — `a_b.c` and `a.b_c` flatten to the
#: distinct `a_b__c` and `a__b_c`. What is ambiguous is a name that CONTAINS the
#: separator: `a.b__c` and `a__b.c` both flatten to `a__b__c`, and a gateway that
#: re-parsed would dispatch to a coordinate the operator did not write.
_WIRE_SEPARATOR = "__"

#: The schema advertised for every op. The broker's `served_registry()` returns
#: `ToolOp` classifications, which carry no argument schema, and the ratified
#: schemas live in registry rows `build_runtime` does not hand back — so the mouth
#: cannot yet advertise real ones. Permissive-and-honest beats invented: a wrong
#: schema would have the client refuse valid calls locally, before the broker ever
#: sees them, which is enforcement in the wrong place by the wrong component.
#: Tracked as the #266 surface finding.
_PERMISSIVE_SCHEMA: dict[str, Any] = {"type": "object", "additionalProperties": True}

logger = logging.getLogger(__name__)

#: `decision_kind` for an answer the broker never gave: `handle_request` raised
#: before replying. Not a Decision verb, deliberately, so nothing downstream can
#: mistake an internal fault for a policy outcome.
_NO_DECISION = "error"


class GatewayNameCollision(ValueError):
    """Two broker coordinates would advertise as the same MCP tool name.

    Fail closed at construction rather than serve an ambiguous map: with
    `tool="a_b", op="c"` and `tool="a", op="b_c"` both flattening to `a_b__c`, one
    of the two would silently shadow the other and calls meant for one op would
    execute the other. Refusing names both coordinates so the operator can rename.
    """


@dataclass(frozen=True)
class GatewayTool:
    """One advertised tool: the wire name, the coordinate, and what we say about it."""

    wire_name: str
    tool: str
    op: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class GatewayResult:
    """The mouth's answer to one `tools/call`.

    `ok` is False for every non-executing decision — deny, abstain and
    require_approval alike. An approval hold is not a success: the effect has not
    happened, and a client that treated "pending" as "done" would report an action
    the broker is still holding.

    `execution_outcome` is set when the broker ALLOWED the call and the connector
    then failed or refused it (`BrokerResponse.execution_outcome`). The text reads
    differently for that case on purpose: an operator chasing a gate refusal and
    one chasing a missing credential are looking in different places.
    """

    ok: bool
    text: str
    decision_kind: str
    structured: Any = None
    reason: str | None = None
    intent_id: str | None = None
    execution_outcome: str | None = None


def _as_text(marshalled: Any) -> str:
    """Render an already-marshalled result as the text block a client displays.

    `marshal_connector_result` has made this JSON-native, so `json.dumps` is
    expected to succeed; the fallback exists because a text rendering is never
    worth raising over, having already executed the effect.
    """
    try:
        return json.dumps(marshalled, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        return str(marshalled)


def _describe(op: ToolOp) -> str:
    """Compose the advertised description from the broker's OWN classification.

    Deliberately not sourced from anything a tool server said. A description is
    model-facing steering and therefore injection surface (`broker/MCP-HOST.md` M2,
    and the reason `example-wrapper diff` renders description deltas verbatim). Everything here
    is the consumer's own manifest data, so there is nothing to launder — and it
    tells the model what the broker believes the op is, which is the fact most
    relevant to whether the call will be allowed.
    """
    parts = [f"{op.effect}"]
    parts.append("external" if op.external else "local")
    if op.reversible is not None:
        parts.append("reversible" if op.reversible else "irreversible")
    classification = ", ".join(parts)
    return (
        f"{op.tool}.{op.op} — brokered {classification}. "
        "Every call is decided and recorded by the broker before it executes."
    )


class GatewaySurface:
    """The broker as ONE MCP server, minus the transport.

    Holds a `BrokerRuntime` and nothing else. It has no connector, no credential and
    no audit-sink reference — it can only ask `handle_request`, exactly like the
    agent on the other side of it.
    """

    def __init__(self, runtime: BrokerRuntime, *, server_name: str = "safe-agents-broker") -> None:
        self._runtime = runtime
        self._server_name = server_name

    @property
    def server_name(self) -> str:
        return self._server_name

    def _index(self) -> dict[str, GatewayTool]:
        """Build the wire-name → coordinate map, refusing collisions.

        Recomputed per call rather than cached at construction: `served_registry()`
        is the runtime's live answer, and a mouth that cached its tool list would
        keep advertising a capability after the thing it reflects had changed.
        """
        index: dict[str, GatewayTool] = {}
        for op in self._runtime.served_registry():
            wire_name = f"{op.tool}{_WIRE_SEPARATOR}{op.op}"
            existing = index.get(wire_name)
            if existing is not None:
                raise GatewayNameCollision(
                    f"broker coordinates {existing.tool}.{existing.op} and "
                    f"{op.tool}.{op.op} both advertise as MCP tool {wire_name!r}; "
                    "rename one op in the manifest — the gateway will not serve an "
                    "ambiguous tool map"
                )
            index[wire_name] = GatewayTool(
                wire_name=wire_name,
                tool=op.tool,
                op=op.op,
                description=_describe(op),
                input_schema=dict(_PERMISSIVE_SCHEMA),
            )
        return index

    def tools(self) -> list[GatewayTool]:
        """What this principal is granted, in wire-name order."""
        return [self._index()[name] for name in sorted(self._index())]

    def call(self, wire_name: str, arguments: Any = None) -> GatewayResult:
        """Carry one call to the broker and shape its answer for the wire.

        An unrecognized `wire_name` is NOT answered here. It is split on the first
        separator and handed to the broker, so that the refusal is the broker's and
        lands on the audit tape when the coordinate is one the manifest classified.
        A gateway that short-circuited unknown names would be deciding, and would
        rob the tape of exactly the events most worth having on it.
        """
        known = self._index().get(wire_name)
        if known is not None:
            tool, op = known.tool, known.op
        else:
            tool, _, op = wire_name.partition(_WIRE_SEPARATOR)
            if not op:
                # No separator at all: there is no coordinate to hand over. This is
                # the one case the mouth must answer itself, and it says so plainly
                # rather than inventing a (tool, op) the operator never wrote.
                return GatewayResult(
                    ok=False,
                    text=f"{wire_name!r} is not a brokered tool name",
                    decision_kind="deny",
                    reason="unroutable tool name",
                )

        try:
            response = self._runtime.handle_request(
                AgentRequest(tool=tool, op=op, args=arguments)
            )
        except Exception as exc:  # noqa: BLE001 — frame it; never leak internals
            # The broker raised instead of replying (a secrets, store or audit fault;
            # `pep.py` lets those surface loudly rather than dress them as a deny).
            # There is no decision to report, so the text claims none: it does not
            # say the gate allowed or refused. The detail goes to stderr for the
            # operator, as the HTTP mouth does, and not to the agent, since an
            # internal message can carry paths or resource names.
            logger.error(
                "broker raised handling %s.%s: %s: %s",
                tool, op, type(exc).__name__, exc,
                exc_info=True,
            )
            return GatewayResult(
                ok=False,
                text=(
                    f"{tool}.{op} did not complete: the broker hit an internal error "
                    f"({type(exc).__name__}) before it could reply; the detail is on "
                    "the broker's stderr"
                ),
                decision_kind=_NO_DECISION,
                reason="internal broker error",
            )

        if response.decision_kind in ("allow", "transform"):
            # ONE marshal, not a third copy. `broker/marshal.py` is homed as a
            # dependency-free leaf precisely because every seam that serializes a
            # connector result needs it, and its docstring already named "a local
            # gateway, not an HTTP client" as the caller that would find it next.
            marshalled = marshal_connector_result(response.result)
            return GatewayResult(
                ok=True,
                text=_as_text(marshalled),
                decision_kind=response.decision_kind,
                structured=marshalled,
            )

        if response.decision_kind == "require_approval":
            return GatewayResult(
                ok=False,
                text=(
                    f"{tool}.{op} is held for approval "
                    f"(intent {response.intent_id}); it has NOT executed"
                ),
                decision_kind=response.decision_kind,
                reason=response.reason,
                intent_id=response.intent_id,
            )

        if response.execution_outcome is not None:
            # The gate allowed this; the connector then did not complete it. Keyed
            # on the structured field, never on the reason text. The reason is
            # generic by design (pep.py keeps the connector's error off the agent's
            # reply), so the text points at where the detail does live.
            verb = "refused" if response.execution_outcome == "refused" else "failed"
            return GatewayResult(
                ok=False,
                text=(
                    f"{tool}.{op} was allowed by the broker but {verb} at the "
                    "connector; the detail is on the broker's audit record"
                ),
                decision_kind=response.decision_kind,
                reason=response.reason,
                execution_outcome=response.execution_outcome,
            )

        return GatewayResult(
            ok=False,
            text=f"{tool}.{op} refused by the broker: {response.reason}",
            decision_kind=response.decision_kind,
            reason=response.reason,
        )
