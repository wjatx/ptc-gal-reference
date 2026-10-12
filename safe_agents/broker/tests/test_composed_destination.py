"""A destination the agent composed, on a tainted turn (PTC §6.4, PTC-52).

The control: with ``Envelope.escalate_composed_destinations`` on, a call that supplies
its op's image-baked ``ToolOp.destination_arg`` on a tainted turn is decided as an
external write. It takes the standing cut's escalation through the single polarity
seam (require_approval with a human, deny without), and the hold's audit record names
the rule. With the knob off (the default) no decision moves.

Each layer is pinned where it lives, so a mutant turns the test that names it red:

  * ``supplies_destination`` — what "the agent composed" means, as a table;
  * the PIP — the knob folds into ``Facts.destination_composed`` and nothing else;
  * the PDP rule — a table of decisions, including the precedence it shares with the
    write path and the external writes it leaves to the standing cut;
  * the schemas — a declaration dumps like egress_arg, and the knob moves the hash;
  * the manifest — a knob that would hold nothing is refused at load;
  * the runtime — held on the tape and released by a human; and with the knob off,
    every decision and every record's decision, reason and outcome is the one a
    manifest without the field produces.

What it does not test, because it is not claimed: request forgery inside a tool server
(a redirect, an internal name resolution) happens after the broker decides, and only
containment around the server closes it (broker/TAINT.md §6.1).
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.audit import hash_stored_call
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.envelope.store import InMemoryEnvelopeStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.pdp import decide
from safe_agents.broker.prototype.broker_server import _make_pip, supplies_destination
from safe_agents.broker.runtime import AgentRequest
from safe_agents.broker.schemas import (
    AgentManifest,
    BrokeredCall,
    Envelope,
    Session,
    Taint,
    ToolOp,
    compute_envelope_hash,
)
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import TurnContext
from safe_agents.broker.tests.scaffold import PRINCIPAL, make_grant, make_pip

RULE_REASON = "tainted composed destination: decided as an external write"
STANDING_REASON = "tainted external write"
SEAM_SUFFIX = "; no human reachable for approval"

_BROKER_ENV = (
    "BROKER_STORE", "BROKER_MANIFEST", "BROKER_SECRETS", "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE", "BROKER_AUDIT_PATH", "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD", "BROKER_SQLITE_PATH",
)


def _op(effect: str, external: bool, *, destination: str | None = "url", **kw: Any) -> ToolOp:
    reversible = kw.pop("reversible", True if effect == "write" else None)
    return ToolOp(
        tool="net",
        op=f"{effect}-{'ext' if external else 'int'}",
        effect=effect,
        external=external,
        reversible=reversible,
        destination_arg=destination,
        **kw,
    )


def _call(entry: ToolOp, *, tainted: bool, args: Any) -> BrokeredCall:
    sources = ["connector:web.search"] if tainted else []
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=entry.tool,
        op=entry.op,
        args=args,
        manifest=entry,
        taint=Taint(tainted=tainted, sources=sources),
        session=Session(turnId="turn-1", ingestedSources=sources),
        ts="2026-10-11T00:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# 1. What "the agent composed" means
# ---------------------------------------------------------------------------

SUPPLIES = [
    # (declared destination, args, supplies?)
    pytest.param(None, {"url": "http://10.0.0.1/"}, False, id="nothing declared"),
    pytest.param("url", {"url": "http://10.0.0.1/"}, True, id="declared key present"),
    pytest.param("url", {"query": "x"}, False, id="declared key absent"),
    pytest.param("url", {}, False, id="empty args"),
    pytest.param("url", {"url": None}, True, id="present as null"),
    pytest.param("url", {"url": ""}, True, id="present as empty string"),
    pytest.param("url", None, False, id="no args at all"),
    pytest.param("url", ["http://10.0.0.1/"], True, id="args not a mapping"),
    pytest.param("url", "http://10.0.0.1/", True, id="args a bare string"),
    pytest.param("url", {"request": {"url": "x"}}, False, id="nested is not seen"),
]


@pytest.mark.parametrize("destination, args, expected", SUPPLIES)
def test_supplies_destination(destination, args, expected) -> None:
    call = _call(_op("read", True, destination=destination), tainted=True, args=args)
    assert supplies_destination(call) is expected


# ---------------------------------------------------------------------------
# 2. The PIP folds the knob into one fact
# ---------------------------------------------------------------------------


def _real_pip(*, knob: bool):
    store = InMemoryGrantStore(hmac_key=b"test-hmac-key")
    store.put_grant(make_grant("net.read-ext"))
    return _make_pip(
        store, InMemoryStore(), 100.0, "test-envelope-hash",
        escalate_composed_destinations=knob,
    )


@pytest.mark.parametrize(
    "knob, destination, args, expected",
    [
        pytest.param(True, "url", {"url": "x"}, True, id="on, supplied"),
        pytest.param(False, "url", {"url": "x"}, False, id="off, supplied"),
        pytest.param(True, None, {"url": "x"}, False, id="on, nothing declared"),
        pytest.param(True, "url", {"q": "x"}, False, id="on, not supplied"),
    ],
)
def test_pip_destination_composed_fact(knob, destination, args, expected) -> None:
    call = _call(_op("read", True, destination=destination), tainted=True, args=args)
    assert _real_pip(knob=knob)(call).destination_composed is expected


class _WriteRefusingStore(InMemoryStore):
    """An enforcement store that records every counter write the PIP attempts."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[str] = []

    def try_increment_counter(self, counter_key: str, delta: float, cap: float) -> bool:
        self.writes.append(counter_key)
        return super().try_increment_counter(counter_key, delta, cap)


def test_pip_on_path_writes_no_counter() -> None:
    """The PIP runs twice per request and must stay side-effect-free: with the knob on
    and a destination supplied it adds one boolean, and draws no counter (no action
    cap, no query bytes, nothing)."""
    store = InMemoryGrantStore(hmac_key=b"test-hmac-key")
    store.put_grant(make_grant("net.read-ext"))
    enforcement = _WriteRefusingStore()
    pip = _make_pip(
        store, enforcement, 100.0, "test-envelope-hash",
        escalate_composed_destinations=True,
    )
    call = _call(_op("read", True, egress_arg="url"), tainted=True, args={"url": "x"})
    assert [pip(call).destination_composed for _ in range(2)] == [True, True]
    assert enforcement.writes == []


def test_pip_default_is_off() -> None:
    """An older caller that passes no knob gets the OFF fact."""
    store = InMemoryGrantStore(hmac_key=b"test-hmac-key")
    store.put_grant(make_grant("net.read-ext"))
    pip = _make_pip(store, InMemoryStore(), 100.0, "test-envelope-hash")
    call = _call(_op("read", True), tainted=True, args={"url": "x"})
    assert pip(call).destination_composed is False


# ---------------------------------------------------------------------------
# 3. The rule, as a decision table
# ---------------------------------------------------------------------------

ON_LOOP = AutonomyLevel.on_loop
IN_LOOP = AutonomyLevel.in_loop

DECISIONS = [
    # (op, tainted, facts, expected kind, expected reason)
    pytest.param(_op("read", True), True, {}, "require_approval", RULE_REASON,
                 id="tainted external read held"),
    pytest.param(_op("read", False), True, {}, "require_approval", RULE_REASON,
                 id="tainted internal read held"),
    pytest.param(_op("write", False), True, {}, "require_approval", RULE_REASON,
                 id="tainted internal write held"),
    pytest.param(_op("read", True), True, {"grant_level": IN_LOOP}, "require_approval",
                 RULE_REASON, id="ahead of the in-loop read rung-gate"),
    pytest.param(_op("write", False), True, {"grant_level": IN_LOOP}, "require_approval",
                 RULE_REASON, id="ahead of the in-loop write rule"),
    pytest.param(_op("read", True), True, {"read_source_trusted": True}, "require_approval",
                 RULE_REASON, id="a trusted source is still held"),
    pytest.param(_op("read", True), True, {"human_reachable": False}, "deny",
                 RULE_REASON + SEAM_SUFFIX, id="no human: the seam denies"),
    pytest.param(_op("write", True), True, {}, "require_approval", STANDING_REASON,
                 id="external write left to the standing cut"),
    pytest.param(_op("read", True), False, {}, "allow", None, id="untainted read allowed"),
    pytest.param(_op("write", False), False, {}, "allow", None, id="untainted write allowed"),
    pytest.param(_op("read", True), True, {"destination_composed": False}, "allow", None,
                 id="tainted, nothing composed: allowed as today"),
    pytest.param(_op("read", True), True, {"cap_budget_breached": True}, "deny",
                 "capacity budget breached", id="the cap still denies first"),
    pytest.param(_op("read", True), True, {"query_bytes_exceeded": True}, "deny",
                 "query egress bound exceeded", id="the egress bound still denies first"),
    pytest.param(_op("read", True), True, {"grant_present": False}, "deny",
                 "tool not granted to this principal", id="no grant still denies first"),
]


@pytest.mark.parametrize("entry, tainted, facts, kind, reason", DECISIONS)
def test_rule_decisions(entry, tainted, facts, kind, reason) -> None:
    facts = {"grant_level": ON_LOOP, "destination_composed": True, **facts}
    call = _call(entry, tainted=tainted, args={"url": "http://10.0.0.1/"})
    decision = decide(call, make_pip(**facts)(call))
    assert decision.kind == kind
    assert getattr(decision, "reason", None) == reason


@pytest.mark.parametrize("entry", [_op("read", True), _op("read", False), _op("write", False)])
def test_knob_off_decides_exactly_as_before(entry) -> None:
    """With the fact off, the decision is the one the table made before the rule
    existed: equal as a whole Decision, not only in verb."""
    call = _call(entry, tainted=True, args={"url": "http://10.0.0.1/"})
    off = decide(call, make_pip(grant_level=ON_LOOP)(call))
    assert off.kind == "allow"
    on = decide(call, make_pip(grant_level=ON_LOOP, destination_composed=True)(call))
    assert on.kind == "require_approval" and on != off


# ---------------------------------------------------------------------------
# 4. The schemas: a declaration dumps like egress_arg, and the knob moves the hash
# ---------------------------------------------------------------------------


def test_toolop_dumps_destination_arg_like_egress_arg() -> None:
    """Unset, the field dumps as null, as egress_arg does: nothing is hidden from the
    stored bytes to make them look as they did before the field existed."""
    entry = _op("read", True, destination=None)
    assert entry.model_dump(mode="json")["destination_arg"] is None
    assert '"destination_arg":null' in entry.model_dump_json()
    call = _call(entry, tainted=False, args={"q": 1})
    assert '"destination_arg":null' in call.model_dump_json()


def test_toolop_with_destination_round_trips() -> None:
    entry = _op("read", True, destination="url")
    assert '"destination_arg":"url"' in entry.model_dump_json()
    assert ToolOp.model_validate_json(entry.model_dump_json()) == entry
    call = _call(entry, tainted=True, args={"url": "x"})
    assert hash_stored_call(BrokeredCall.model_validate_json(call.model_dump_json())) == (
        hash_stored_call(call)
    )


@pytest.mark.parametrize("name", ["", " ", " url", "url ", "url\t", "url\n"])
def test_an_empty_or_padded_destination_name_is_refused(name) -> None:
    """A name no agent key can match would satisfy the manifest's coherence check
    while holding nothing."""
    with pytest.raises(ValueError):
        _op("read", True, destination=name)


def test_envelope_hash_off_differs_from_on() -> None:
    """The knob is dumped and hashed like any other: off (absent or explicit) is one
    hash, on is another, and both round-trip through the stored bytes."""
    default = Envelope(polarity="abstain")
    explicit_off = Envelope(polarity="abstain", escalate_composed_destinations=False)
    on = Envelope(polarity="abstain", escalate_composed_destinations=True)
    assert default.model_dump(mode="json")["escalate_composed_destinations"] is False
    assert compute_envelope_hash(explicit_off) == compute_envelope_hash(default)
    assert compute_envelope_hash(on) != compute_envelope_hash(default)
    for envelope in (default, on):
        reloaded = Envelope.model_validate_json(envelope.model_dump_json())
        assert reloaded == envelope
        assert compute_envelope_hash(reloaded) == compute_envelope_hash(envelope)


# ---------------------------------------------------------------------------
# 5. The manifest refuses a knob that would hold nothing
# ---------------------------------------------------------------------------


def _manifest_dict(*, knob: bool, destination: str | None) -> dict:
    op = {"tool": "crm", "op": "fetch", "effect": "read", "external": True}
    if destination is not None:
        op["destination_arg"] = destination
    envelope: dict = {"polarity": "abstain"}
    if knob:
        envelope["escalate_composed_destinations"] = True
    return {"envelope": envelope, "tool_ops": [op]}


def test_knob_on_with_no_destination_declared_is_refused() -> None:
    with pytest.raises(ValueError, match="no tool_ops entry declares a destination_arg"):
        AgentManifest.model_validate(_manifest_dict(knob=True, destination=None))


@pytest.mark.parametrize("knob, destination", [(True, "url"), (False, "url"), (False, None)])
def test_coherent_manifests_load(knob, destination) -> None:
    manifest = AgentManifest.model_validate(_manifest_dict(knob=knob, destination=destination))
    assert manifest.tool_ops[0].destination_arg == destination
    assert manifest.envelope.escalate_composed_destinations is knob


# ---------------------------------------------------------------------------
# 6. Through the real runtime: the tape, the release, and the OFF decisions
# ---------------------------------------------------------------------------


class OfflineNetConnector:
    """Every crm.* op, offline. Counts executions so a hold can be shown to run nothing."""

    executed: list[tuple[str, Any]] = []

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        OfflineNetConnector.executed.append((op, args))
        return {"ok": op}


def _write_manifest(path: Path, *, knob: bool | None, declare: bool) -> Path:
    url = ", destination_arg: url" if declare else ""
    dest = ", destination_arg: path" if declare else ""
    knob_line = "" if knob is None else f"  escalate_composed_destinations: {str(knob).lower()}\n"
    path.write_text(
        textwrap.dedent(
            f"""\
            principal:
              agentId: destination-test
              skill: research
              user: local-developer
              tier: C
            grant_classes: [crm.search, crm.fetch, crm.post, crm.stash]
            connectors: [crm]
            connector_providers:
              crm: "safe_agents.broker.tests.test_composed_destination:OfflineNetConnector"
            tool_ops:
              - {{tool: crm, op: search, effect: read, external: true}}
              - {{tool: crm, op: fetch, effect: read, external: true{url}}}
              - {{tool: crm, op: post, effect: write, external: true, reversible: true{url}}}
              - {{tool: crm, op: stash, effect: write, external: false, reversible: true{dest}}}
            envelope:
              polarity: abstain
              caps:
                actions_per_run: 25
            """
        )
        + knob_line,
        encoding="utf-8",
    )
    return path


SEARCH = AgentRequest(tool="crm", op="search", args={"q": "planted"})
FETCH = AgentRequest(tool="crm", op="fetch", args={"url": "http://169.254.169.254/"})
POST = AgentRequest(tool="crm", op="post", args={"url": "http://example.test/", "body": "x"})
STASH = AgentRequest(tool="crm", op="stash", args={"path": "/srv/other", "body": "x"})
SCRIPT = [FETCH, SEARCH, FETCH, POST, STASH]
ON_KINDS = ["allow", "allow", "require_approval", "require_approval", "require_approval"]
ON_HELD = [("fetch", RULE_REASON), ("post", STANDING_REASON), ("stash", RULE_REASON)]
OFF_KINDS = ["allow", "allow", "allow", "require_approval", "allow"]
_MANIFEST_PRINCIPAL = Principal(
    agentId="destination-test", skill="research", user="local-developer", tier="C"
)


def _envelope(*, knob: bool) -> Envelope:
    """The manifest's envelope, with the knob set as given (for the store)."""
    return Envelope.model_validate(
        {
            "polarity": "abstain",
            "caps": {"actions_per_run": 25},
            "escalate_composed_destinations": knob,
        }
    )


def _counters(runtime) -> dict[tuple[str, str], float]:
    """Every counter the runtime's enforcement store holds, keyed (tool.op, suffix),
    with the period bucket dropped so two runs compare across a bucket boundary."""
    counters = runtime._enforcement_store._counters
    return {(k.split(":")[1], k.split(":")[-1]): v for k, v in counters.items()}


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Build a runtime from a manifest and play SCRIPT on one fixed turn."""
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    built: list = []

    def play(
        *,
        knob: bool | None,
        declare: bool,
        stored: Envelope | None = None,
        script: list[AgentRequest] = SCRIPT,
    ):
        """``stored`` set: BROKER_ENVELOPE_LOAD=store, with ``stored`` as the in-force
        envelope in an injected store (the manifest's envelope is then not enforced)."""
        OfflineNetConnector.executed = []
        path = _write_manifest(tmp_path / f"m{len(built)}.yaml", knob=knob, declare=declare)
        envelope_store = None
        if stored is None:
            monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
        else:
            monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
            envelope_store = InMemoryEnvelopeStore()
            envelope_store.put_envelope(_MANIFEST_PRINCIPAL, stored)
        runtime, sink = build_runtime(load_agent_manifest(path), envelope_store=envelope_store)
        built.append(runtime)
        ctx = TurnContext(turn_id="turn:fixed")
        responses = [runtime.handle_request(r, turn_context=ctx) for r in script]
        return runtime, sink, responses

    try:
        yield play
    finally:
        for runtime in built:
            runtime.close()


def test_on_holds_the_composed_destination_and_names_the_rule(run) -> None:
    runtime, sink, responses = run(knob=True, declare=True)
    kinds = [r.decision_kind for r in responses]
    # The first fetch runs on a clean turn and, as an external read, taints it; the
    # search declares no destination and is allowed; every composed destination after
    # that holds.
    assert kinds == ON_KINDS
    held = [r for r in sink.records() if r.outcome == "held"]
    assert [(r.op, r.reason) for r in held] == ON_HELD
    assert all(r.storedCallDigest and r.intentId for r in held)
    # Nothing held ran: only the first fetch and the search reached the connector.
    assert [op for op, _ in OfflineNetConnector.executed] == ["fetch", "search"]
    # A hold draws nothing, and the control itself draws nothing: every counter (action
    # cap, query bytes, observations) is exactly what the knob-off broker holds after
    # running only the two calls that ran here.
    on_counters = _counters(runtime)
    baseline, _, _ = run(knob=False, declare=True, script=[FETCH, SEARCH])
    assert on_counters == _counters(baseline)
    assert on_counters[("crm.fetch", "counter")] == 1.0

    released = runtime.approve_intent(responses[2].intent_id, approved_by="owner")
    assert released.executed is True
    assert OfflineNetConnector.executed[-1] == ("fetch", FETCH.args)
    assert sink.records()[-1].approvedBy == "owner"


def test_off_allows_as_today(run) -> None:
    _, sink, responses = run(knob=False, declare=True)
    assert [r.decision_kind for r in responses] == OFF_KINDS
    assert [r.reason for r in sink.records() if r.outcome == "held"] == [STANDING_REASON]


@pytest.mark.parametrize(
    "stored_knob, manifest_knob, kinds, held",
    [
        pytest.param(True, False, ON_KINDS, ON_HELD, id="store on, manifest off: held"),
        pytest.param(False, True, OFF_KINDS, [("post", STANDING_REASON)],
                     id="store off, manifest on: not held"),
    ],
)
def test_store_loaded_envelope_switches_the_control(
    run, stored_knob, manifest_knob, kinds, held
) -> None:
    """BROKER_ENVELOPE_LOAD=store: the knob is read from the envelope in force (the
    stored one), not from the manifest's. The declarations stay image-baked: both
    manifests declare the same destinations, and only the stored envelope moves."""
    _, sink, responses = run(
        knob=manifest_knob, declare=True, stored=_envelope(knob=stored_knob)
    )
    assert [r.decision_kind for r in responses] == kinds
    assert [(r.op, r.reason) for r in sink.records() if r.outcome == "held"] == held


def _decided(sink) -> list[tuple[str, str, str, str | None, str]]:
    """What each audit record decided, parsed: the record's bytes carry the stored
    call (and so its declarations) and are not compared."""
    return [(r.tool, r.op, r.decision, r.reason, r.outcome) for r in sink.records()]


@pytest.mark.parametrize("knob", [None, False], ids=["knob absent", "knob explicitly off"])
def test_off_decides_and_records_as_without_the_field(run, knob) -> None:
    """The decisive OFF comparison. A manifest written before the field existed (no
    knob, no declaration) and one that declares destinations with the knob off play
    the same script on the same turn: every decision, and every audit record's
    decision, reason and outcome, is the same. The declaration itself is visible in
    the stored call, so a hold's storedCallDigest differs; the knob is not, while off,
    so the envelope hash does not."""
    _, legacy_sink, legacy = run(knob=None, declare=False)
    _, sink, responses = run(knob=knob, declare=True)
    assert [r.decision_kind for r in responses] == [r.decision_kind for r in legacy]
    assert _decided(sink) == _decided(legacy_sink)
    assert {r.envelopeHash for r in sink.records()} == {
        r.envelopeHash for r in legacy_sink.records()
    }
    holds = [r for r in sink.records() if r.outcome == "held"]
    legacy_holds = [r for r in legacy_sink.records() if r.outcome == "held"]
    assert holds and len(holds) == len(legacy_holds), "the script must include a hold"
    assert [r.storedCallDigest for r in holds] != [r.storedCallDigest for r in legacy_holds]


def test_the_knob_moves_the_envelope_hash_on_the_tape(run) -> None:
    """Off and on are two policies, and the tape says which one decided."""
    _, off_sink, _ = run(knob=False, declare=True)
    _, on_sink, _ = run(knob=True, declare=True)
    off_hashes = {r.envelopeHash for r in off_sink.records()}
    on_hashes = {r.envelopeHash for r in on_sink.records()}
    assert len(off_hashes) == len(on_hashes) == 1
    assert off_hashes != on_hashes
