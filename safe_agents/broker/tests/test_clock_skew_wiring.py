"""Where each clock-skew bound is READ from (PTC-49 / GAL-42, #175).

``test_clock_skew.py`` proves every comparison applies the bound it is handed,
in the less-authority direction. This file proves each entry point hands it
the RECEIVER's own declared bound, and nothing else:

  * the broker (PIP and PEP) from ``AgentManifest.clock_skew_seconds``, via
    ``build_runtime``; a release behaves accordingly end to end;
  * ``propose`` / ``ratify`` from the same ``BROKER_MANIFEST`` manifest, and
    ``ratify_command`` / ``propose_command`` act on it;
  * the lapse runner from ``--clock-skew-seconds``, end to end;
  * MCP ``admit-ratify`` from ``--clock-skew-seconds``, and ``bulk-ratify`` /
    ``bulk-propose`` from their ``--manifest``.

A mutant that drops the bound at any of these seams (a "knob ignored" mutant)
leaves zero in its place, and the row naming that seam goes red.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants import commands as grant_commands
from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants import runner
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.proposals import InMemoryProposalStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.mcp import commands as mcp_commands
from safe_agents.broker.mcp.proposals import MemoryAdmissionProposalStore
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.runtime import BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.schemas import AgentManifest, Envelope
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests import test_grants_commands as gc
from safe_agents.broker.tests import test_mcp_bulk_ceremony as bulk
from safe_agents.broker.tests import test_mcp_registry_store as admit
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH
from safe_agents.broker.tests.test_release_revalidation import (
    _APPROVER,
    _PAYMENTS_OPTABLE,
    _PRINCIPAL,
    _CountingConnector,
    _facts,
    _hold,
    _make_grant,
    _MutablePip,
)

UTC = datetime.UTC
GAP = datetime.timedelta(seconds=10)
BOUND = datetime.timedelta(seconds=30)


# --- the broker: build_runtime reads the manifest -----------------------------


def test_build_runtime_hands_the_manifest_bound_to_the_pip_and_the_pep(monkeypatch):
    seen: dict[str, object] = {}
    real_pip, real_runtime = broker_server._make_pip, broker_server.BrokerRuntime

    def spy_pip(*args, **kwargs):
        seen["pip"] = kwargs.get("clock_skew")
        return real_pip(*args, **kwargs)

    def spy_runtime(*args, **kwargs):
        seen["pep"] = kwargs.get("clock_skew")
        return real_runtime(*args, **kwargs)

    for var in ("BROKER_STORE", "BROKER_MANIFEST", "BROKER_ENVELOPE_LOAD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")
    monkeypatch.setattr(broker_server, "_make_pip", spy_pip)
    monkeypatch.setattr(broker_server, "BrokerRuntime", spy_runtime)
    manifest = AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain"},
            "principal": {"agentId": "skew-agent", "skill": "s", "user": "u", "tier": "B"},
            "clock_skew_seconds": 45,
        }
    )
    broker_server.build_runtime(manifest)
    expected = datetime.timedelta(seconds=45)
    assert seen == {"pip": expected, "pep": expected}, (
        "build_runtime: the manifest's clock_skew_seconds must reach both the PIP "
        f"(certification term) and the PEP (hold expiry); got {seen}"
    )


@pytest.mark.parametrize(
    "bound,executed",
    [
        pytest.param(datetime.timedelta(0), True, id="zero-bound-releases"),
        # The hold's TTL is 3600s from now; a bound wider than that refuses it.
        pytest.param(datetime.timedelta(hours=2), False, id="bound-past-the-ttl-refuses"),
    ],
)
def test_a_release_through_the_runtime_applies_its_bound(bound, executed):
    connector = _CountingConnector({"tx_id": "tx"})
    intent_store = InMemoryIntentStore()
    runtime = BrokerRuntime(
        principal=_PRINCIPAL,
        grants=[_make_grant("payments.transfer", AutonomyLevel.in_loop)],
        optable=_PAYMENTS_OPTABLE,
        doer=Doer(
            connectors={"payments": connector},
            secrets=FakeSecretsProvider({"payments": "cred"}),
        ),
        pip=_MutablePip(_facts()),
        enforcement_store=InMemoryStore(),
        intent_store=intent_store,
        audit_sink=InMemorySink(),
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        clock_skew=bound,
    )
    intent_id = _hold(runtime, intent_store)
    result = runtime.approve_intent(intent_id, approved_by=_APPROVER)
    assert result.executed is executed, (
        f"BrokerRuntime.approve_intent: the hold's expiry is judged at now + the runtime's "
        f"clock_skew ({bound}), so it should {'release' if executed else 'refuse as expired'}; "
        f"got executed={result.executed}, rejection_reason={result.rejection_reason!r}"
    )
    assert connector.count == (1 if executed else 0)
    if not executed:
        assert result.rejection_reason == "intent expired"


# --- the grants ceremony: propose and ratify ---------------------------------


def _ceremony_manifest(monkeypatch, *, seconds: int, principal=gc.PRINCIPAL) -> None:
    monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
    monkeypatch.setattr(
        broker_server,
        "_MANIFEST",
        AgentManifest(
            principal=principal,
            envelope=Envelope(polarity="abstain"),
            clock_skew_seconds=seconds,
        ),
    )


@pytest.mark.parametrize("command", ["propose", "ratify"])
def test_the_ceremony_commands_read_the_bound_from_the_manifest(monkeypatch, tmp_path, command):
    _ceremony_manifest(monkeypatch, seconds=45)
    seen: dict[str, object] = {}

    def spy(args, **kwargs):
        seen["clock_skew"] = kwargs.get("clock_skew")
        return 0

    monkeypatch.setattr(grant_commands, f"{command}_command", spy)
    monkeypatch.setattr(grant_commands, "_build_stores", lambda t: (None, None))
    monkeypatch.setattr(grant_commands, "_build_proposal_store", lambda t: None)
    monkeypatch.setattr(grant_commands, "_build_enforcement_store", lambda t: None)
    monkeypatch.setattr(grant_commands, "resolve_record_signer", lambda zone=None: None)
    monkeypatch.setattr(grant_commands, "_resolve_reviewer", lambda: None)
    monkeypatch.setattr(
        grant_commands, "_ceremony_blast_context", lambda p, t: (gc.TOOL_OPS, [], "h")
    )
    artifact = tmp_path / "artifact.json"
    artifact.write_text(gc._ARTIFACT.model_dump_json(), encoding="utf-8")
    principal = [
        "--principal-agent-id", gc.PRINCIPAL.agentId, "--skill", gc.PRINCIPAL.skill,
        "--user", gc.PRINCIPAL.user, "--tier", gc.PRINCIPAL.tier,
        "--action-class", gc.ACTION_CLASS,
    ]
    rc = grant_commands.main([command] + principal + _required_extras(command, tmp_path))
    assert rc == 0
    assert seen == {"clock_skew": datetime.timedelta(seconds=45)}, (
        f"commands.main {command}: the bound must come from BROKER_MANIFEST; got {seen}"
    )


def _required_extras(command: str, tmp_path) -> list[str]:
    if command == "ratify":
        return ["--proposal-id", "p-1", "--allow-unsigned"]
    artifact = tmp_path / "artifact.json"
    return [
        "--target-level", "on-loop", "--evidence-bundle", "e", "--owner-id", "o",
        "--label-latency", "PT1H", "--artifact-json", str(artifact),
        "--provenance-maturity", "signed-lineage", "--window-n", "200",
        "--min-observations", "10", "--threshold", "0.05", "--ttl-hours", "1",
    ]


def test_the_ceremony_refuses_another_principals_bound(monkeypatch):
    from safe_agents.broker.grants._commands_common import _ceremony_clock_skew
    from safe_agents.broker.schemas.common import Principal

    other = Principal(agentId="someone-else", skill="s", user="u", tier="B")
    _ceremony_manifest(monkeypatch, seconds=45, principal=other)
    with pytest.raises(runner.RunnerConfigError, match="clock-skew bound"):
        _ceremony_clock_skew(gc.PRINCIPAL)


def _proposed(monkeypatch, tmp_path):
    stores = InMemoryGrantStore(), InMemoryPromotionRecordStore(), InMemoryProposalStore()
    enforcement = InMemoryStore()
    stores[0].put_grant(gc.make_grant())
    gc.seed_counters(enforcement)
    artifact = tmp_path / "artifact.json"
    artifact.write_text(gc._ARTIFACT.model_dump_json(), encoding="utf-8")
    assert gc.run_propose(
        monkeypatch, artifact, stores[0], stores[2], enforcement, **{"--ttl-hours": "1"}
    ) == 0
    return stores, gc.stored_proposal_id(stores[2])


@pytest.mark.parametrize("bound,rc", [(datetime.timedelta(0), 0), (BOUND, 1)])
def test_ratify_command_hands_its_bound_to_the_ceremony(monkeypatch, tmp_path, capsys, bound, rc):
    (grant_store, record_store, proposal_store), proposal_id = _proposed(monkeypatch, tmp_path)
    gc.set_caller(monkeypatch, gc.CHECKER_ARN)
    got = grant_commands.ratify_command(
        gc.ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        tool_ops=gc.TOOL_OPS,
        high_blast=(),
        signer=None,
        now=gc.NOW + datetime.timedelta(hours=1) - GAP,  # 10s before the proposal expires
        clock_skew=bound,
    )
    assert got == rc, f"ratify_command with bound {bound}: {capsys.readouterr().out}"
    if rc:
        assert "expired" in capsys.readouterr().out


@pytest.mark.parametrize("bound,refused", [(datetime.timedelta(0), False), (BOUND, True)])
def test_propose_command_judges_a_stored_term_with_its_bound(
    monkeypatch, tmp_path, capsys, bound, refused
):
    grant_store = InMemoryGrantStore()
    term = (gc.NOW + GAP).isoformat()
    grant_store.put_grant(
        gc.make_grant(level=AutonomyLevel.on_loop).model_copy(update={"certifiedUntil": term})
    )
    artifact = tmp_path / "artifact.json"
    artifact.write_text(gc._ARTIFACT.model_dump_json(), encoding="utf-8")
    gc.set_caller(monkeypatch, gc.MAKER_ARN)
    grant_commands.propose_command(
        gc.propose_args(artifact, **{"--target-level": "out-of-loop"}),
        grant_store=grant_store,
        proposal_store=InMemoryProposalStore(),
        enforcement_store=InMemoryStore(),
        envelope_hash=gc.ENVELOPE_HASH,
        tool_ops=gc.TOOL_OPS,
        high_blast=(),
        now=gc.NOW,
        clock_skew=bound,
    )
    out = capsys.readouterr().out
    assert ("certification term" in out) is refused, f"propose_command with bound {bound}: {out}"


# --- the lapse runner: --clock-skew-seconds, end to end -----------------------


@pytest.mark.parametrize("flag,lapsed", [("0", False), ("3600", True)])
def test_the_lapse_runner_reads_its_flag(monkeypatch, capsys, flag, lapsed):
    from safe_agents.broker.tests.test_grant_term_lapse import (
        ACTION_CLASS,
        PRINCIPAL,
        _promote_with_term,
    )

    term = datetime.datetime.now(UTC) + datetime.timedelta(minutes=10)
    stores = _promote_with_term(
        term.isoformat(), ratify_at=term - datetime.timedelta(hours=1)
    )
    monkeypatch.setattr(runner, "_build_stores", lambda table: stores)
    monkeypatch.setattr(issuer_keys, "resolve_evaluator_signer", lambda: None)
    rc = runner.main(
        [
            "--principal-agent-id", PRINCIPAL.agentId, "--skill", PRINCIPAL.skill,
            "--user", PRINCIPAL.user, "--tier", PRINCIPAL.tier,
            "--action-class", ACTION_CLASS, "--clock-skew-seconds", flag,
        ]
    )
    assert rc == 0
    level = stores[0].get_grant(PRINCIPAL, ACTION_CLASS).grant.level
    assert (level is AutonomyLevel.in_loop) is lapsed, (
        f"runner.main --clock-skew-seconds {flag}: {capsys.readouterr().out}"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--clock-skew-seconds", "-5"],
        ["--clock-skew-seconds", "soon"],
    ],
)
def test_the_runner_refuses_a_negative_or_non_integer_flag(argv):
    base = ["--principal-agent-id", "a", "--skill", "s", "--user", "u", "--tier", "B",
            "--action-class", "x.y"]
    with pytest.raises(SystemExit):
        runner._parse_args(base + argv)


# --- MCP admission ------------------------------------------------------------


@pytest.mark.parametrize("bound,rc", [(datetime.timedelta(0), 0), (BOUND, 1)])
def test_admit_ratify_applies_its_bound(monkeypatch, tmp_path, capsys, bound, rc):
    signer = admit.signer_from_pem("issuer:A", "zone-a", admit._keypair()[0])
    proposal_store = MemoryAdmissionProposalStore()
    path = admit.write_tool_def(tmp_path, "def.json", admit.make_tool_def())
    proposal_id = admit.run_propose(proposal_store, monkeypatch, path)  # ttl 1h at NOW
    admit.set_caller(monkeypatch, admit.CHECKER_ARN)
    got = mcp_commands.admit_ratify_command(
        admit.ratify_args(proposal_id),
        store=MemoryToolRegistry(),
        proposal_store=proposal_store,
        signer=signer,
        now=admit.NOW + datetime.timedelta(hours=1) - GAP,
        clock_skew=bound,
    )
    assert got == rc, f"admit_ratify_command with bound {bound}: {capsys.readouterr().out}"


def test_admit_ratify_main_reads_its_flag(monkeypatch):
    seen: dict[str, object] = {}

    def spy(args, **kwargs):
        seen["clock_skew"] = kwargs.get("clock_skew")
        return 0

    monkeypatch.setattr(mcp_commands, "admit_ratify_command", spy)
    monkeypatch.setattr(mcp_commands, "_build_stores", lambda t: (None, None))
    monkeypatch.setattr(mcp_commands, "resolve_record_signer", lambda zone=None: None)
    argv = [
        "admit-ratify", "--server-id", "s", "--tool-name", "t", "--proposal-id", "p",
        "--clock-skew-seconds", "45",
    ]
    assert mcp_commands.main(argv) == 0
    assert seen == {"clock_skew": datetime.timedelta(seconds=45)}, (
        f"mcp admit-ratify main: the bound must come from --clock-skew-seconds; got {seen}"
    )
    with pytest.raises(SystemExit):
        mcp_commands._parse_args(argv[:-1] + ["-1"])


def _skewed_manifest(tmp_path, names, seconds: int) -> str:
    path = bulk.write_manifest(tmp_path, names, name=f"manifest-{seconds}.yaml")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"clock_skew_seconds: {seconds}\n")
    return path


@pytest.mark.parametrize("seconds,rc", [(0, 0), (30, 1)])
def test_bulk_ratify_reads_the_manifest_bound(monkeypatch, tmp_path, capsys, seconds, rc):
    signer = admit.signer_from_pem("issuer:A", "zone-a", admit._keypair()[0])
    store, proposal_store = MemoryToolRegistry(), MemoryAdmissionProposalStore()
    got, _ = bulk.run_propose(
        tmp_path, store, proposal_store, monkeypatch, [bulk.tool_def("t1")], ["t1"]
    )  # ttl 1h at bulk.NOW
    assert got == 0
    manifest = _skewed_manifest(tmp_path, ["t1"], seconds)
    bulk.set_caller(monkeypatch, bulk.CHECKER_ARN)
    got = mcp_commands.bulk_ratify_command(
        bulk.ratify_args(manifest),
        store=store,
        proposal_store=proposal_store,
        signer=signer,
        now=bulk.NOW + datetime.timedelta(hours=1) - GAP,
    )
    out = capsys.readouterr().out
    assert got == rc, f"bulk_ratify_command, manifest bound {seconds}s: {out}"
    assert ("proposal expired" in out) is bool(rc), out


@pytest.mark.parametrize("seconds,rc", [(0, 0), (30, 2)])
def test_bulk_propose_judges_snapshot_age_with_the_manifest_bound(
    monkeypatch, tmp_path, capsys, seconds, rc
):
    # 59m50s old against the 60-minute default ceiling.
    captured = (bulk.NOW - datetime.timedelta(minutes=60) + GAP).isoformat()
    snapshot = bulk.write_snapshot(tmp_path, [bulk.tool_def("t1")], captured_at=captured)
    manifest = _skewed_manifest(tmp_path, ["t1"], seconds)
    bulk.set_caller(monkeypatch, bulk.MAKER_ARN)
    got = mcp_commands.bulk_propose_command(
        bulk.propose_args(tmp_path, manifest, snapshot),
        store=MemoryToolRegistry(),
        proposal_store=MemoryAdmissionProposalStore(),
        now=bulk.NOW,
    )
    out = capsys.readouterr().out
    assert got == rc, f"bulk_propose_command, manifest bound {seconds}s: {out}"
    if rc:
        # The refusal reports the snapshot's real age and names the bound that
        # tipped it, rather than passing the bound-adjusted age off as the age.
        assert "snapshot is 59.8 minutes old (60.3 with the manifest's 30s" in out, (
            f"bulk_propose_command snapshot-age refusal: {out}"
        )
