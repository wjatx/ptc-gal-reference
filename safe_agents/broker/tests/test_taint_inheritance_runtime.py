"""Taint across a caused context, through two runtimes (PTC-51, #177).

A causing runtime and a child runtime are built from manifests by ``build_runtime``
and share one inheritance ledger, as two zones of one deployment share a store.
The causing runtime reads planted content (an external read taints its turn) and
then runs an op whose image-baked ``ToolOp`` declares ``causes_context``. The
child's first external write must be held, because its first turn starts no
cleaner than the turn that caused it.

Each test pins one half of the mechanism, so a mutant turns the test naming it
red:

  * the row write before the Doer, inline and on the approval release path;
  * the mint read, at the first mint and at every mint after ``new_turn()``;
  * the fail directions: a read that raises taints the turn and serves it, a
    write that fails stops the op;
  * the floor: neither the trust map nor ``trusted_read_sources`` lifts an
    inherited source;
  * the row's lifetime: the later of the sub-grant expiry and the horizon,
    judged with the skew bound toward more taint;
  * a cause op that is itself an external read: its own source is on the row
    before it runs, spelled as the self-ingest spells it.

What is not tested, because it is not claimed (``broker/TAINT.md`` §4.1): a
context the broker never sees created, a target the manifest misdeclares, and
taint carried by data that a later context reads back.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from safe_agents.broker.api import build_runtime
from safe_agents.broker.delegation import InMemorySubGrantStore, SubGrant
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import AgentRequest
from safe_agents.broker.runtime.inheritance import (
    INHERITANCE_UNREADABLE_SOURCE,
    INHERITED_WITHOUT_SOURCE,
)
from safe_agents.broker.schemas import AgentManifest, InheritanceRecord, Taint, ToolOp
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.taint import InMemoryInheritanceStore, connector_source_id

PARENT = Principal(agentId="planner", skill="plan", user="local-developer", tier="C")
CHILD = Principal(agentId="worker", skill="run", user="local-developer", tier="C")
SEARCH_SOURCE = "connector:crm.search"
BRIEF_SOURCE = "connector:crm.brief"
HORIZON = 3600
STANDING_REASON = "tainted external write"
T0 = datetime.datetime(2026, 10, 12, 12, 0, tzinfo=datetime.UTC)

SEARCH = AgentRequest(tool="crm", op="search", args={"q": "planted"})
POST = AgentRequest(tool="crm", op="post", args={"body": "x"})
LAUNCH = AgentRequest(tool="crm", op="launch", args={"task": "t"})
DISPATCH = AgentRequest(tool="crm", op="dispatch", args={"task": "t"})
DEFER = AgentRequest(tool="crm", op="defer", args={"task": "t"})
BRIEF = AgentRequest(tool="crm", op="brief", args={"task": "t"})
PEEK = AgentRequest(tool="crm", op="peek", args={"task": "t"})
CAUSE_OPS = ("launch", "dispatch", "brief", "peek")


class OfflineConnector:
    """Every op, offline. Records what ran and what the ledger held when it ran."""

    executed: list[tuple[str, str]] = []
    ledger: InMemoryInheritanceStore | None = None
    rows_at_launch: list[int] = []
    taint_at_launch: list[list[Taint]] = []

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        OfflineConnector.executed.append((tool, op))
        if op in CAUSE_OPS and OfflineConnector.ledger is not None:
            # The row must already be stored when the Doer reaches the connector.
            rows = OfflineConnector.ledger.live_records(CHILD, T0)
            OfflineConnector.rows_at_launch.append(len(rows))
            OfflineConnector.taint_at_launch.append([r.taint for r in rows])
        if isinstance(args, dict) and args.get("fail"):
            raise ConnectionError("the provider is unreachable")
        return {"ok": op}


_PROVIDER = "safe_agents.broker.tests.test_taint_inheritance_runtime:OfflineConnector"


class Clock:
    """A settable clock, so a row's expiry can be crossed without waiting."""

    def __init__(self, now: datetime.datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime.datetime:
        return self.now


def _cause(target: Principal | str) -> dict:
    t = target if isinstance(target, str) else target.model_dump()
    return {"target": t, "horizon_seconds": HORIZON}


def _parent_manifest(*, trusted: list[str] | None = None) -> AgentManifest:
    envelope: dict = {"polarity": "abstain", "caps": {"actions_per_run": 25}}
    if trusted is not None:
        envelope["trusted_read_sources"] = trusted
    return AgentManifest.model_validate(
        {
            "principal": PARENT.model_dump(),
            "grant_classes": [
                "crm.search", "crm.post", "crm.launch", "crm.dispatch", "crm.defer",
                "crm.brief", "crm.peek",
            ],
            "connectors": ["crm"],
            "connector_providers": {"crm": _PROVIDER},
            "tool_ops": [
                {"tool": "crm", "op": "search", "effect": "read", "external": True},
                {"tool": "crm", "op": "post", "effect": "write", "external": True,
                 "reversible": True},
                # Internal: nothing holds it, so only inheritance carries the taint.
                {"tool": "crm", "op": "launch", "effect": "write", "external": False,
                 "reversible": True, "causes_context": _cause(CHILD)},
                # External: the standing cut holds it on a tainted turn.
                {"tool": "crm", "op": "dispatch", "effect": "write", "external": True,
                 "reversible": True, "causes_context": _cause(CHILD)},
                {"tool": "crm", "op": "defer", "effect": "write", "external": False,
                 "reversible": True, "causes_context": _cause("self")},
                # An external read that causes a context: its own source rides the row.
                {"tool": "crm", "op": "brief", "effect": "read", "external": True,
                 "causes_context": _cause(CHILD)},
                # An internal read that causes a context: it adds nothing.
                {"tool": "crm", "op": "peek", "effect": "read", "external": False,
                 "causes_context": _cause(CHILD)},
            ],
            "envelope": envelope,
        }
    )


def _child_manifest(*, trusted: list[str] | None = None, skew: int = 0) -> AgentManifest:
    envelope: dict = {"polarity": "abstain", "caps": {"actions_per_run": 25}}
    if trusted is not None:
        envelope["trusted_read_sources"] = trusted
    return AgentManifest.model_validate(
        {
            "principal": CHILD.model_dump(),
            "grant_classes": ["crm.search", "crm.post"],
            "connectors": ["crm"],
            "connector_providers": {"crm": _PROVIDER},
            "tool_ops": [
                {"tool": "crm", "op": "search", "effect": "read", "external": True},
                {"tool": "crm", "op": "post", "effect": "write", "external": True,
                 "reversible": True},
            ],
            "clock_skew_seconds": skew,
            "envelope": envelope,
        }
    )


class UnreadableLedger(InMemoryInheritanceStore):
    """A ledger whose read raises, as an unreachable table does."""

    def live_records(self, target, now):
        raise ConnectionError("ledger unreachable")


class UnwritableLedger(InMemoryInheritanceStore):
    """A ledger whose write raises; its read works, so a turn still mints."""

    def put_record(self, record):
        raise ConnectionError("ledger unreachable")


class CountingLedger(InMemoryInheritanceStore):
    def __init__(self) -> None:
        super().__init__()
        self.puts = 0

    def put_record(self, record):
        self.puts += 1
        super().put_record(record)


@pytest.fixture(autouse=True)
def _memory_arm(monkeypatch):
    import os

    for var in list(os.environ):
        if var.startswith("BROKER_"):
            monkeypatch.delenv(var, raising=False)
    OfflineConnector.executed = []
    OfflineConnector.ledger = None
    OfflineConnector.rows_at_launch = []
    OfflineConnector.taint_at_launch = []


@pytest.fixture
def built():
    runtimes: list = []

    def build(manifest, store, *, clock=None, sub_grant_store=None):
        runtime, sink = build_runtime(
            manifest,
            inheritance_store=store,
            clock=clock or Clock(),
            sub_grant_store=sub_grant_store,
        )
        runtimes.append(runtime)
        return runtime, sink

    yield build
    for runtime in runtimes:
        runtime.close()


def _held_reason(sink, op: str) -> str | None:
    held = [r for r in sink.records() if r.op == op and r.outcome == "held"]
    return held[-1].reason if held else None


def _taint_and_launch(built, store, request=LAUNCH):
    parent, parent_sink = built(_parent_manifest(), store)
    assert parent.handle_request(SEARCH).decision_kind == "allow"
    turn_id = parent.session_turn().turn_id
    response = parent.handle_request(request)
    return parent, parent_sink, response, turn_id


# ---------------------------------------------------------------------------
# The row write, inline
# ---------------------------------------------------------------------------


def test_the_cause_op_writes_its_row_before_the_doer_and_the_child_is_held(built) -> None:
    store = InMemoryInheritanceStore()
    OfflineConnector.ledger = store
    _, _, response, turn_id = _taint_and_launch(built, store)
    assert response.decision_kind == "allow"

    rows = store.live_records(CHILD, T0)
    assert len(rows) == 1, "the cause op wrote no inheritance row for its declared child"
    row = rows[0]
    assert row.target == CHILD and row.causingPrincipal == PARENT
    assert row.causingTurnId == turn_id
    assert row.taint == Taint(tainted=True, sources=[SEARCH_SOURCE]), (
        f"the row carries {row.taint.sources}, not the causing call's own taint "
        f"[{SEARCH_SOURCE!r}]: an op that is not an external read added its source, or the "
        "self-ingest spelled the earlier read's source differently"
    )
    assert (row.tool, row.op) == ("crm", "launch")
    assert datetime.datetime.fromisoformat(row.notAfter) == T0 + datetime.timedelta(
        seconds=HORIZON
    )
    assert OfflineConnector.rows_at_launch == [1], "the row was not stored before the Doer ran"

    child, child_sink = built(_child_manifest(), store)
    assert child.handle_request(POST).decision_kind == "require_approval"
    assert _held_reason(child_sink, "post") == STANDING_REASON
    assert ("crm", "post") not in OfflineConnector.executed


def test_the_child_reads_the_row_when_it_mints_its_first_turn(built) -> None:
    store = InMemoryInheritanceStore()
    _taint_and_launch(built, store)
    assert store.live_records(CHILD, T0), "precondition: the row is stored"

    child, _ = built(_child_manifest(), store)
    # The source keeps its original id; no lineage prefix is added.
    assert child.session_turn().to_taint() == Taint(tainted=True, sources=[SEARCH_SOURCE])


def test_a_clean_causing_turn_writes_a_clean_row_and_the_child_acts(built) -> None:
    store = InMemoryInheritanceStore()
    parent, _ = built(_parent_manifest(), store)
    assert parent.handle_request(LAUNCH).decision_kind == "allow"
    [row] = store.live_records(CHILD, T0)
    assert row.taint == Taint(tainted=False, sources=[])

    child, _ = built(_child_manifest(), store)
    assert child.handle_request(POST).decision_kind == "allow"


def test_ops_that_declare_nothing_write_nothing(built) -> None:
    store = CountingLedger()
    parent, _ = built(_parent_manifest(), store)
    for request in (SEARCH, POST):
        parent.handle_request(request)
    assert store.puts == 0
    parent.handle_request(LAUNCH)
    assert store.puts == 1


# ---------------------------------------------------------------------------
# The write's fail direction
# ---------------------------------------------------------------------------


def test_a_failed_write_stops_the_op_and_the_tape_names_the_ledger(built) -> None:
    parent, sink, response, _ = _taint_and_launch(built, UnwritableLedger())
    assert response.decision_kind == "deny"
    assert response.execution_outcome == "failed"
    assert ("crm", "launch") not in OfflineConnector.executed
    [record] = [r for r in sink.records() if r.op == "launch"]
    assert record.outcome == "failed"
    assert "taint inheritance record" in record.error
    assert "crm.launch did not run" in record.error


def test_a_failed_write_refuses_the_release(built) -> None:
    parent, sink, response, _ = _taint_and_launch(built, UnwritableLedger(), DISPATCH)
    assert response.decision_kind == "require_approval"
    released = parent.approve_intent(response.intent_id, approved_by="owner")
    assert released.executed is False
    assert released.rejection_reason.startswith("release refused")
    assert "taint inheritance record" in released.rejection_reason
    assert parent._intent_store.get_intent(response.intent_id).status == "refused"
    assert ("crm", "dispatch") not in OfflineConnector.executed
    last = sink.records()[-1]
    assert (last.op, last.outcome, last.approvedBy) == ("dispatch", "failed", "owner")
    assert "taint inheritance record" in last.error


def test_an_ambiguous_sub_grant_is_a_failed_write(built) -> None:
    sub_grants = InMemorySubGrantStore()
    for n in (1, 2):
        sub_grants.save(_sub_grant(f"sg-{n}", T0 + datetime.timedelta(minutes=10)))
    parent, _ = built(_parent_manifest(), InMemoryInheritanceStore(), sub_grant_store=sub_grants)
    response = parent.handle_request(LAUNCH)
    assert response.decision_kind == "deny"
    assert ("crm", "launch") not in OfflineConnector.executed


# ---------------------------------------------------------------------------
# Approval is not declassification
# ---------------------------------------------------------------------------


def test_a_held_cause_op_approved_writes_the_frozen_taint_and_the_child_is_held(built) -> None:
    store = InMemoryInheritanceStore()
    parent, _, response, held_turn = _taint_and_launch(built, store, DISPATCH)
    assert response.decision_kind == "require_approval"
    assert store.live_records(CHILD, T0) == [], "a hold runs nothing and writes nothing"

    # The causing runtime rolls its turn before the human answers: the release must
    # write the taint the hold froze, not the clean turn it now holds.
    parent.new_turn()
    assert parent.session_turn().to_taint().tainted is False
    released = parent.approve_intent(response.intent_id, approved_by="owner")
    assert released.executed is True

    [row] = store.live_records(CHILD, T0)
    assert row.taint.sources == [SEARCH_SOURCE], "the release wrote no row, or a clean one"
    assert row.causingTurnId == held_turn
    child, child_sink = built(_child_manifest(), store)
    assert child.handle_request(POST).decision_kind == "require_approval"
    assert _held_reason(child_sink, "post") == STANDING_REASON


@pytest.mark.parametrize("table_declares", [True, False])
def test_the_release_reads_the_declaration_from_its_own_table(built, table_declares) -> None:
    store = InMemoryInheritanceStore()
    parent, _, response, _ = _taint_and_launch(built, store, DISPATCH)
    entries = [
        e if (e.tool, e.op) != ("crm", "dispatch") or table_declares
        else e.model_copy(update={"causes_context": None})
        for e in _parent_manifest().tool_ops
    ]
    # The frozen call carries the declaration either way; only the table decides.
    parent._optable = ToolOpTable(entries)
    assert parent.approve_intent(response.intent_id, approved_by="owner").executed is True
    assert len(store.live_records(CHILD, T0)) == (1 if table_declares else 0)


# ---------------------------------------------------------------------------
# The mint read: every mint, its floor, its fail direction
# ---------------------------------------------------------------------------


def test_an_unreadable_ledger_mints_the_turn_tainted_and_still_serves(built) -> None:
    child, child_sink = built(_child_manifest(), UnreadableLedger())
    assert child.handle_request(SEARCH).decision_kind == "allow"
    assert child.handle_request(POST).decision_kind == "require_approval"
    assert _held_reason(child_sink, "post") == STANDING_REASON
    assert INHERITANCE_UNREADABLE_SOURCE in child.session_turn().to_taint().sources


def test_new_turn_in_the_child_sheds_nothing_while_the_row_is_live(built) -> None:
    store = InMemoryInheritanceStore()
    _taint_and_launch(built, store)
    clock = Clock()
    child, _ = built(_child_manifest(), store, clock=clock)
    assert child.handle_request(POST).decision_kind == "require_approval", (
        "the child's first mint did not read the live inheritance row"
    )
    child.new_turn()
    assert child.handle_request(POST).decision_kind == "require_approval", (
        "new_turn() in the child shed inherited taint while its row is live: the mint "
        "after a rollover did not re-read the ledger"
    )

    # Past notAfter the row is ignored, and the next mint is clean.
    clock.now = T0 + datetime.timedelta(seconds=HORIZON)
    child.new_turn()
    assert child.session_turn().to_taint() == Taint(tainted=False, sources=[])
    assert child.handle_request(POST).decision_kind == "allow"


@pytest.mark.parametrize("lift", ["trusted_read_sources", "trust_map"])
def test_nothing_the_child_configures_lifts_an_inherited_source(built, lift) -> None:
    store = InMemoryInheritanceStore()
    _taint_and_launch(built, store)
    trusted = [SEARCH_SOURCE] if lift == "trusted_read_sources" else None
    child, child_sink = built(_child_manifest(trusted=trusted), store)
    if lift == "trust_map":
        child._trust_map = lambda source: True
    assert child.handle_request(POST).decision_kind == "require_approval", (
        f"the child's {lift} lifted an inherited source: the inheritance floor did not hold"
    )
    assert child.session_turn().to_taint().sources == [SEARCH_SOURCE]


@pytest.mark.parametrize(
    ("taint", "which"),
    [
        (Taint(tainted=True, sources=[SEARCH_SOURCE]), "a sourced row"),
        (Taint(tainted=True, sources=[]), "an unsourced row"),
    ],
    ids=["sourced", "unsourced"],
)
def test_a_row_for_a_principal_whose_key_collides_is_not_read(
    built, taint: Taint, which: str
) -> None:
    """Two principals can render one partition key; the stored target decides.

    Both ingest branches are pinned: the one that copies a record's sources and
    the one that taints with the synthetic source for a row that names none.
    """
    store = InMemoryInheritanceStore()
    other = CHILD.model_copy(update={"agentId": "worker#run", "skill": "x"})
    collider = CHILD.model_copy(update={"agentId": "worker", "skill": "run#x"})
    store.put_record(
        InheritanceRecord(
            id="r-other",
            target=other,
            causingPrincipal=PARENT,
            causingTurnId="turn:x",
            taint=taint,
            tool="crm",
            op="launch",
            issuedAt=T0.isoformat(),
            notAfter=(T0 + datetime.timedelta(minutes=5)).isoformat(),
        )
    )
    assert store.live_records(collider, T0), "the two principals no longer share a key"
    manifest = _child_manifest().model_copy(update={"principal": collider})
    child, _ = built(manifest, store)
    assert child.session_turn().to_taint() == Taint(tainted=False, sources=[]), (
        f"{which} whose stored target is another principal was ingested: the mint "
        f"read did not check record.target for {which}"
    )


def test_a_tainted_row_that_names_no_source_still_taints(built) -> None:
    store = InMemoryInheritanceStore()
    store.put_record(
        InheritanceRecord(
            id="r-unsourced",
            target=CHILD,
            causingPrincipal=PARENT,
            causingTurnId="turn:x",
            taint=Taint(tainted=True, sources=[]),
            tool="crm",
            op="launch",
            issuedAt=T0.isoformat(),
            notAfter=(T0 + datetime.timedelta(minutes=5)).isoformat(),
        )
    )
    child, _ = built(_child_manifest(), store)
    assert child.session_turn().to_taint() == Taint(
        tainted=True, sources=[INHERITED_WITHOUT_SOURCE]
    )


@pytest.mark.parametrize(
    "past_not_after, held",
    [(30, True), (90, False)],
    ids=["inside the skew bound: still held", "past it: clean"],
)
def test_the_skew_bound_keeps_a_row_live_longer(built, past_not_after, held) -> None:
    store = InMemoryInheritanceStore()
    _taint_and_launch(built, store)
    not_after = T0 + datetime.timedelta(seconds=HORIZON)
    clock = Clock(not_after + datetime.timedelta(seconds=past_not_after))
    child, _ = built(_child_manifest(skew=60), store, clock=clock)
    assert child.session_turn().to_taint().tainted is held


# ---------------------------------------------------------------------------
# Targets and lifetimes
# ---------------------------------------------------------------------------


def test_a_self_target_taints_the_principals_own_later_turns(built) -> None:
    store = InMemoryInheritanceStore()
    parent, sink, response, _ = _taint_and_launch(built, store, DEFER)
    assert response.decision_kind == "allow"
    [row] = store.live_records(PARENT, T0)
    assert row.target == PARENT and row.taint.sources == [SEARCH_SOURCE]
    assert store.live_records(CHILD, T0) == []
    parent.new_turn()
    assert parent.handle_request(POST).decision_kind == "require_approval", (
        "the principal's next turn after a 'self' cause op was not held: its own "
        "inheritance row was not read at the mint"
    )
    assert _held_reason(sink, "post") == STANDING_REASON


def test_without_the_deferral_the_principals_next_turn_is_clean(built) -> None:
    """The control for the self target: rolling the turn after a read alone."""
    parent, _ = built(_parent_manifest(), InMemoryInheritanceStore())
    parent.handle_request(SEARCH)
    parent.new_turn()
    assert parent.handle_request(POST).decision_kind == "allow"


def _sub_grant(sg_id: str, expiry: datetime.datetime) -> SubGrant:
    return SubGrant(
        id=sg_id,
        parentGrantId="g-parent",
        delegationChain=["g-parent"],
        principal=CHILD,
        actionClasses=["crm.post"],
        level="in-loop",
        spendCap=1.0,
        expiry=expiry.isoformat(),
        allowFurtherDelegation=False,
        treePoolCap=10.0,
        issuedAt=T0.isoformat(),
        issuedBy="broker",
        hash="not-checked-here",
    )


@pytest.mark.parametrize(
    ("sub_grant_minutes", "expected_minutes"),
    [(10, HORIZON // 60), (120, 120)],
    ids=["short sub-grant: the horizon", "long sub-grant: its expiry"],
)
def test_a_child_row_lives_until_the_later_of_its_sub_grant_and_the_horizon(
    built, sub_grant_minutes, expected_minutes
) -> None:
    sub_grants = InMemorySubGrantStore()
    sub_grants.save(_sub_grant("sg-1", T0 + datetime.timedelta(minutes=sub_grant_minutes)))
    store = InMemoryInheritanceStore()
    parent, _ = built(_parent_manifest(), store, sub_grant_store=sub_grants)
    parent.handle_request(SEARCH)
    parent.handle_request(LAUNCH)
    [row] = store.live_records(CHILD, T0)
    expected = T0 + datetime.timedelta(minutes=expected_minutes)
    assert datetime.datetime.fromisoformat(row.notAfter) == expected, (
        f"a {sub_grant_minutes}-minute sub-grant against a {HORIZON}s horizon gave notAfter "
        f"{row.notAfter}: the row's lifetime is not the later of the two"
    )

    # Just before the later bound the child is still held; at it, it acts clean.
    clock = Clock(expected - datetime.timedelta(seconds=1))
    child, _ = built(_child_manifest(), store, clock=clock)
    assert child.handle_request(POST).decision_kind == "require_approval", (
        "the child acted clean before the later of its sub-grant expiry and the horizon"
    )
    clock.now = expected
    child.new_turn()
    assert child.handle_request(POST).decision_kind == "allow"


# ---------------------------------------------------------------------------
# A cause op that is itself an external read passes on its own source
# ---------------------------------------------------------------------------


def test_an_external_read_cause_op_passes_on_its_own_source_before_it_runs(built) -> None:
    store = InMemoryInheritanceStore()
    OfflineConnector.ledger = store
    parent, _ = built(_parent_manifest(), store)
    assert parent.handle_request(BRIEF).decision_kind == "allow"

    expected = Taint(tainted=True, sources=[BRIEF_SOURCE])
    [[at_launch]] = OfflineConnector.taint_at_launch
    misspelled = any("brief" in source for source in at_launch.sources)
    assert at_launch.sources == [BRIEF_SOURCE], (
        f"when the connector ran, the stored row named {at_launch.sources}, not "
        f"[{BRIEF_SOURCE!r}]: "
        + (
            "the row spells the read's source differently from connector_source_id"
            if misspelled
            else "the read's own source was not on the row before the read ran"
        )
    )
    assert at_launch.tainted is True, (
        "the row names the read's own source but is not marked tainted"
    )
    [row] = store.live_records(CHILD, T0)
    assert row.taint == expected

    # One spelling: the row's source is the one the self-ingest put on the causing turn.
    turn_sources = parent.session_turn().to_taint().sources
    assert turn_sources == row.taint.sources, (
        f"the self-ingest put {turn_sources} on the causing turn and the row names "
        f"{row.taint.sources}: the two spell the read's source differently"
    )
    assert connector_source_id("crm", "brief") == BRIEF_SOURCE

    child, child_sink = built(_child_manifest(), store)
    assert child.session_turn().to_taint() == expected
    assert child.handle_request(POST).decision_kind == "require_approval"
    assert _held_reason(child_sink, "post") == STANDING_REASON


@pytest.mark.parametrize(
    ("request_", "expected"),
    [
        (BRIEF, [SEARCH_SOURCE, BRIEF_SOURCE]),
        (PEEK, [SEARCH_SOURCE]),
        (LAUNCH, [SEARCH_SOURCE]),
    ],
    ids=["external read: appended", "internal read: nothing", "internal write: nothing"],
)
def test_only_an_external_read_adds_its_source_to_the_call_taint(
    built, request_, expected
) -> None:
    store = InMemoryInheritanceStore()
    _taint_and_launch(built, store, request_)
    [row] = store.live_records(CHILD, T0)
    assert row.taint == Taint(tainted=True, sources=expected), (
        f"crm.{request_.op} wrote {row.taint.sources}, expected {expected}: an op that is "
        "not an external read added a source, or an external read did not"
    )


@pytest.mark.parametrize("request_", [PEEK, LAUNCH], ids=["internal read", "internal write"])
def test_an_op_that_is_not_an_external_read_leaves_a_clean_call_clean(built, request_) -> None:
    store = InMemoryInheritanceStore()
    parent, _ = built(_parent_manifest(), store)
    assert parent.handle_request(request_).decision_kind == "allow"
    [row] = store.live_records(CHILD, T0)
    assert row.taint == Taint(tainted=False, sources=[]), (
        f"crm.{request_.op} is not an external read and still tainted its row"
    )


def test_an_external_read_already_on_the_turn_is_not_named_twice(built) -> None:
    store = InMemoryInheritanceStore()
    parent, _ = built(_parent_manifest(), store)
    parent.handle_request(BRIEF)
    parent.handle_request(BRIEF)
    rows = store.live_records(CHILD, T0)
    assert [r.taint.sources for r in rows] == [[BRIEF_SOURCE], [BRIEF_SOURCE]], (
        "a read whose source the turn already carries named it twice on the row"
    )


def test_a_trusted_external_read_adds_no_source_to_the_row(built) -> None:
    """A source the consumer's trusted_read_sources names is skipped at the row, as at the self-ingest."""
    store = InMemoryInheritanceStore()
    OfflineConnector.ledger = store
    parent, _ = built(_parent_manifest(trusted=[BRIEF_SOURCE]), store)
    assert parent.handle_request(BRIEF).decision_kind == "allow"
    [[at_launch]] = OfflineConnector.taint_at_launch
    assert at_launch == Taint(tainted=False, sources=[]), (
        f"the row carried {at_launch} for a read the consumer's trusted_read_sources names: "
        "the record did not apply the trusted-source skip the self-ingest applies"
    )
    child, _ = built(_child_manifest(), store)
    assert child.handle_request(POST).decision_kind == "allow", (
        "the child was held on a source the causing runtime's consumer declared trusted"
    )


def test_an_external_read_that_fails_has_still_tainted_the_child(built) -> None:
    store = InMemoryInheritanceStore()
    parent, _ = built(_parent_manifest(), store)
    failing = AgentRequest(tool="crm", op="brief", args={"task": "t", "fail": True})
    response = parent.handle_request(failing)
    assert response.execution_outcome == "failed"
    # The causing turn took no taint from a read that returned nothing ...
    assert parent.session_turn().to_taint().tainted is False
    # ... and the child was tainted for nothing, which costs it approvals only.
    [row] = store.live_records(CHILD, T0)
    assert row.taint.sources == [BRIEF_SOURCE]
    child, _ = built(_child_manifest(), store)
    assert child.handle_request(POST).decision_kind == "require_approval"


def test_the_cause_op_entry_is_the_one_in_the_runtime_table() -> None:
    """The test manifest's declarations are what the runtime's table holds."""
    table = ToolOpTable(_parent_manifest().tool_ops)
    assert [(e.tool, e.op) for e in table.cause_entries()] == [
        ("crm", "launch"), ("crm", "dispatch"), ("crm", "defer"), ("crm", "brief"),
        ("crm", "peek"),
    ]
    assert all(isinstance(e, ToolOp) for e in table.cause_entries())
