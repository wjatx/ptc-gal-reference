"""The ceremony's blast class is derived, at propose and again at ratify.

Coverage (unit-level, same conventions as test_grants_commands.py, whose
helpers this file reuses):
- grants/blast.py truth table: the class comes from the manifest's ToolOp and
  the envelope's tighten-only high_blast overrides; an undeclared op raises.
- the propose parser no longer accepts --effect / --external / --reversible.
- propose stores the derived class and refuses an op the manifest does not
  declare; an envelope high_blast override is carried through ratify onto the
  stored PromotionRecord's predicate text.
- ratify prints the class it re-derives and refuses a stored proposal whose
  class differs in either direction, writing nothing.
- _ceremony_blast_context resolves the ToolOp facts from the manifest in both
  envelope load modes and high_blast from the in-force envelope.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants._commands_common import _ceremony_blast_context
from safe_agents.broker.grants.blast import (
    UndeclaredOperationError,
    ceremony_blast_class,
)
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.commands import _parse_args, ratify_command
from safe_agents.broker.grants.proposals import InMemoryProposalStore
from safe_agents.broker.grants.runner import RunnerConfigError
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.schemas import AgentManifest, Envelope, compute_envelope_hash
from safe_agents.broker.schemas.brokered_call import ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.tests.test_grants_commands import (
    _ARTIFACT,
    ACTION_CLASS,
    CHECKER_ARN,
    NOW,
    PRINCIPAL,
    make_grant,
    propose_args,
    ratify_args,
    run_propose,
    seed_counters,
    set_caller,
    stored_proposal_id,
)

HUMAN_RATIFICATION = "per-instance human ratification required"


def _op(effect="write", external=False, reversible=None, tool="email", op="send") -> ToolOp:
    return ToolOp(tool=tool, op=op, effect=effect, external=external, reversible=reversible)


# ACTION_CLASS declared three ways: each derives the class its name says.
MEDIUM_OPS = [_op(external=False)]
HIGH_OPS = [_op(external=True, reversible=False)]


@pytest.fixture
def stores():
    """(grant_store, record_store, proposal_store, enforcement_store), with the
    anchoring in-loop grant and passing evidence counters already in place."""
    grant_store, enforcement_store = InMemoryGrantStore(), InMemoryStore()
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    return grant_store, InMemoryPromotionRecordStore(), InMemoryProposalStore(), enforcement_store


@pytest.fixture
def artifact_path(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_text(_ARTIFACT.model_dump_json(), encoding="utf-8")
    return path


def _propose(monkeypatch, artifact_path, stores, tool_ops, high_blast=()) -> int:
    grant_store, _, proposal_store, enforcement_store = stores
    return run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        tool_ops=tool_ops, high_blast=high_blast,
    )


def _ratify(monkeypatch, stores, proposal_id, tool_ops, high_blast=()) -> int:
    grant_store, record_store, proposal_store, _ = stores
    set_caller(monkeypatch, CHECKER_ARN)
    return ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        tool_ops=tool_ops,
        high_blast=high_blast,
        now=NOW,
    )


def _assert_nothing_ratified(stores, proposal_id) -> None:
    grant_store, record_store, proposal_store, _ = stores
    assert record_store.records == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert status == "pending"


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "high_blast", "expected"),
    [
        (_op(effect="read"), (), "low"),
        (_op(effect="read", external=True), (), "low"),
        (_op(external=False), (), "medium"),
        (_op(external=True, reversible=True), (), "medium"),
        (_op(external=True, reversible=False), (), "high"),
        (_op(external=True, reversible=None), (), "high"),
        # Listed in high_blast: high regardless of what the facts derive.
        (_op(effect="read"), [ACTION_CLASS], "high"),
        (_op(external=False), [ACTION_CLASS], "high"),
        (_op(external=True, reversible=True), [ACTION_CLASS], "high"),
        # An override naming some other class changes nothing.
        (_op(external=False), ["wire.send"], "medium"),
    ],
)
def test_blast_class_truth_table(op, high_blast, expected):
    # A second, unrelated high-blast op in the table must not leak into the answer.
    tool_ops = [_op(tool="wire", op="send", external=True, reversible=False), op]
    assert ceremony_blast_class(ACTION_CLASS, tool_ops, high_blast) == expected


@pytest.mark.parametrize(
    "tool_ops",
    [
        [],
        [_op(tool="wire", op="send")],
        # Same op name under another tool, and the same tool with another op.
        [_op(tool="mail", op="send"), _op(tool="email", op="draft")],
        # Two entries spelling one "tool.op": two verdicts are as unusable as none.
        [_op(tool="email", op="send"), _op(tool="email", op="send", external=True)],
    ],
)
def test_undeclared_operation_raises(tool_ops):
    with pytest.raises(UndeclaredOperationError) as exc_info:
        ceremony_blast_class(ACTION_CLASS, tool_ops, [ACTION_CLASS])
    assert ACTION_CLASS in str(exc_info.value)


# ---------------------------------------------------------------------------
# propose
# ---------------------------------------------------------------------------


_REMOVED_FLAGS = {
    "--effect": ["--effect", "read"],
    "--external": ["--external"],
    "--reversible": ["--reversible", "true"],
}


@pytest.mark.parametrize("flag", sorted(_REMOVED_FLAGS))
def test_propose_parser_rejects_the_blast_flags(artifact_path, flag, capsys):
    """The otherwise-valid propose argv is refused the moment a removed flag
    rides along: there is no shim that accepts and ignores it."""
    argv = _propose_argv(artifact_path)
    assert _parse_args(argv).command == "propose"

    with pytest.raises(SystemExit) as exc_info:
        _parse_args(argv + _REMOVED_FLAGS[flag])
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "unrecognized arguments" in err
    assert flag in err


def _propose_argv(artifact_path) -> list[str]:
    return [
        "propose",
        "--principal-agent-id", PRINCIPAL.agentId,
        "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user,
        "--tier", PRINCIPAL.tier,
        "--action-class", ACTION_CLASS,
        "--target-level", "on-loop",
        "--evidence-bundle", "evidence-ref-001",
        "--owner-id", "maintainer",
        "--label-latency", "PT1H",
        "--artifact-json", str(artifact_path),
        "--provenance-maturity", "signed-lineage",
        "--window-n", "200",
        "--min-observations", "10",
        "--threshold", "0.05",
        "--ttl-hours", "24",
    ]


def test_propose_stores_the_derived_class_for_an_irreversible_external_op(
    monkeypatch, artifact_path, stores, capsys
):
    assert _propose(monkeypatch, artifact_path, stores, HIGH_OPS) == 0
    out = capsys.readouterr().out
    assert "blast class: high" in out
    assert "ratification must be per-instance human" in out

    (proposal,) = stores[2].list_pending(PRINCIPAL, ACTION_CLASS)
    assert proposal.blast_class == "high"
    # No operator input reaches the class: the parsed propose namespace carries
    # no ToolOp fact and nothing blast-shaped (the parser test above pins that
    # the flags themselves are refused).
    parsed = set(vars(propose_args(artifact_path)))
    assert not parsed & {"effect", "external", "reversible"}
    assert not [name for name in parsed if "blast" in name]


def test_propose_refuses_an_undeclared_op_and_stores_nothing(
    monkeypatch, artifact_path, stores, capsys
):
    rc = _propose(monkeypatch, artifact_path, stores, [_op(tool="wire", op="send")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "REFUSED" in out
    assert ACTION_CLASS in out
    assert "BROKER_MANIFEST" in out
    assert stores[2].list_pending(PRINCIPAL, ACTION_CLASS) == []


def test_envelope_high_blast_override_reaches_the_ratified_record(
    monkeypatch, artifact_path, stores, capsys
):
    """An op that derives medium but is listed in the in-force envelope's
    high_blast is proposed AND ratified as high: the human-ratification
    statement lands on the stored PromotionRecord."""
    assert ceremony_blast_class(ACTION_CLASS, MEDIUM_OPS, ()) == "medium"

    assert _propose(monkeypatch, artifact_path, stores, MEDIUM_OPS, [ACTION_CLASS]) == 0
    (proposal,) = stores[2].list_pending(PRINCIPAL, ACTION_CLASS)
    assert proposal.blast_class == "high"

    assert _ratify(monkeypatch, stores, proposal.proposal_id, MEDIUM_OPS, [ACTION_CLASS]) == 0
    (record,) = stores[1].records
    assert "blast class is high" in record.predicate
    assert HUMAN_RATIFICATION in record.predicate


def test_without_the_override_the_record_carries_no_human_ratification_statement(
    monkeypatch, artifact_path, stores
):
    """The control for the test above: same op, no override, medium."""
    assert _propose(monkeypatch, artifact_path, stores, MEDIUM_OPS) == 0
    proposal_id = stored_proposal_id(stores[2])
    assert _ratify(monkeypatch, stores, proposal_id, MEDIUM_OPS) == 0
    (record,) = stores[1].records
    assert HUMAN_RATIFICATION not in record.predicate


# ---------------------------------------------------------------------------
# ratify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("proposed_under", "ratified_under", "stored", "derived"),
    [
        # Stored medium, facts now derive high: by ToolOp, and by envelope override.
        ((MEDIUM_OPS, ()), (HIGH_OPS, ()), "medium", "high"),
        ((MEDIUM_OPS, ()), (MEDIUM_OPS, [ACTION_CLASS]), "medium", "high"),
        # The reverse: stored high, facts now derive medium.
        ((HIGH_OPS, ()), (MEDIUM_OPS, ()), "high", "medium"),
        ((MEDIUM_OPS, [ACTION_CLASS]), (MEDIUM_OPS, ()), "high", "medium"),
    ],
)
def test_ratify_refuses_a_stored_class_that_differs_from_the_derivation(
    monkeypatch, artifact_path, stores, capsys, proposed_under, ratified_under, stored, derived
):
    assert _propose(monkeypatch, artifact_path, stores, *proposed_under) == 0
    proposal_id = stored_proposal_id(stores[2])
    capsys.readouterr()

    assert _ratify(monkeypatch, stores, proposal_id, *ratified_under) == 1
    out = capsys.readouterr().out
    assert "REFUSED" in out
    assert f"stored at blast class {stored!r}" in out
    assert f"derive {derived!r}" in out
    assert "re-propose" in out
    _assert_nothing_ratified(stores, proposal_id)


def test_ratify_refuses_an_op_the_manifest_no_longer_declares(
    monkeypatch, artifact_path, stores, capsys
):
    assert _propose(monkeypatch, artifact_path, stores, MEDIUM_OPS) == 0
    proposal_id = stored_proposal_id(stores[2])
    capsys.readouterr()

    assert _ratify(monkeypatch, stores, proposal_id, [_op(tool="wire", op="send")]) == 1
    out = capsys.readouterr().out
    assert "REFUSED" in out
    assert ACTION_CLASS in out
    _assert_nothing_ratified(stores, proposal_id)


@pytest.mark.parametrize(
    ("tool_ops", "expected"), [(MEDIUM_OPS, "medium"), (HIGH_OPS, "high")]
)
def test_ratify_prints_the_class_for_the_checker(
    monkeypatch, artifact_path, stores, capsys, tool_ops, expected
):
    assert _propose(monkeypatch, artifact_path, stores, tool_ops) == 0
    proposal_id = stored_proposal_id(stores[2])
    capsys.readouterr()

    assert _ratify(monkeypatch, stores, proposal_id, tool_ops) == 0
    out = capsys.readouterr().out
    assert f"blast class: {expected}" in out
    # Shown with the rest of what the checker ratifies, before the verdict.
    assert out.index("certification term:") < out.index("blast class:") < out.index("RATIFIED")


# ---------------------------------------------------------------------------
# _ceremony_blast_context — where main() gets the facts
# ---------------------------------------------------------------------------

_OTHER_PRINCIPAL = Principal(agentId="another-agent", skill="email", user="alice", tier="B")


def _envelope(high_blast=None, actions_per_run=1) -> Envelope:
    block = {
        "polarity": "abstain",
        "caps": {"actions_per_run": actions_per_run},
        "high_stakes": False,
    }
    if high_blast is not None:
        block["confidence"] = {"min_confidence": 0.5, "high_blast": high_blast}
    return Envelope.model_validate(block)


def _set_manifest(monkeypatch, principal, envelope, tool_ops=HIGH_OPS) -> AgentManifest:
    from safe_agents.broker.prototype import broker_server

    monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
    manifest = AgentManifest(principal=principal, envelope=envelope, tool_ops=tool_ops)
    monkeypatch.setattr(broker_server, "_MANIFEST", manifest)
    return manifest


def _seed_store_envelope(monkeypatch, envelope) -> None:
    from safe_agents.broker.envelope import read as envelope_read
    from safe_agents.broker.envelope import store as envelope_store

    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    monkeypatch.setattr(envelope_store, "DynamoDBEnvelopeStore", lambda table_name: object())
    monkeypatch.setattr(envelope_read, "load_inforce_envelope", lambda store, principal: envelope)


def test_blast_context_manifest_mode(monkeypatch):
    manifest = _set_manifest(monkeypatch, PRINCIPAL, _envelope(high_blast=[ACTION_CLASS]))
    tool_ops, high_blast, envelope_hash = _ceremony_blast_context(PRINCIPAL, "t")
    assert tool_ops == HIGH_OPS
    assert high_blast == [ACTION_CLASS]
    assert envelope_hash == compute_envelope_hash(manifest.envelope)


def test_blast_context_no_confidence_knob_means_no_overrides(monkeypatch):
    _set_manifest(monkeypatch, PRINCIPAL, _envelope(high_blast=None))
    _, high_blast, _ = _ceremony_blast_context(PRINCIPAL, "t")
    assert high_blast == []


def test_blast_context_store_mode_reads_tool_ops_from_the_manifest_and_high_blast_from_the_store(
    monkeypatch,
):
    """Store mode: the manifest still supplies the ToolOp facts, and the
    overrides and the hash come from the SEEDED envelope, not the manifest's."""
    _set_manifest(monkeypatch, PRINCIPAL, _envelope(high_blast=["wire.send"]))
    seeded = _envelope(high_blast=[ACTION_CLASS], actions_per_run=7)
    _seed_store_envelope(monkeypatch, seeded)

    tool_ops, high_blast, envelope_hash = _ceremony_blast_context(PRINCIPAL, "t")
    assert tool_ops == HIGH_OPS
    assert high_blast == [ACTION_CLASS]
    assert envelope_hash == compute_envelope_hash(seeded)


@pytest.mark.parametrize("mode", ["manifest", "store"])
@pytest.mark.parametrize("manifest_principal", [_OTHER_PRINCIPAL, None])
def test_blast_context_refuses_another_principals_manifest(monkeypatch, mode, manifest_principal):
    _set_manifest(monkeypatch, manifest_principal, _envelope())
    if mode == "store":
        _seed_store_envelope(monkeypatch, _envelope())

    with pytest.raises(RunnerConfigError) as exc_info:
        _ceremony_blast_context(PRINCIPAL, "t")
    message = str(exc_info.value)
    assert PRINCIPAL.agentId in message
    assert "BROKER_MANIFEST" in message
