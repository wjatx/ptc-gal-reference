"""What may re-license a grant whose issuer standing is not held (GAL §6.10, GAL-41, #179).

A withdrawal lowers what a grant acts at with no write, and recovery is the full
promotion ceremony. This file pins that no other path brings the level back:

  ledger       only records at or before the grant's ts license it, and an
               unsigned licensing record that comes after a signed one at its
               coordinate is never history, whatever its ts or the epoch; one
               that comes before every signed record is history, and a signed
               record appended after it does not take its level away
  ceremony     re-seed, propose and ratify each refuse a grant above its
               lastSafeLevel whose issuer standing is not held, as propose and
               ratify refuse one whose lapse is unrecorded; once the withdrawal
               runner has lowered it, each proceeds, and only a new promotion
               under a key in standing raises it again; main() hands each of
               the three the deploy-bound standing check
"""

from __future__ import annotations

import datetime
import json

import pytest

from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants import commands, issuer_keys
from safe_agents.broker.grants import grant_standing as gs
from safe_agents.broker.grants.ceremony import PromotionCeremony
from safe_agents.broker.grants.proposals import InMemoryProposalStore
from safe_agents.broker.grants.withdrawal import run_withdrawal
from safe_agents.broker.schemas.brokered_call import ToolOp
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.broker.tests.grant_standing_scaffold import (
    IN,
    ON,
    OUT,
    PROMOTION_TS,
    World,
    record,
)
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    ENV_HASH,
    PRINCIPAL,
    _reproposal,
)
from safe_agents.broker.tests.test_grants_commands import propose_args

MINUTE = datetime.timedelta(minutes=1)
NEW_ENVELOPE = "sha256:envelope-after-a-far-jump-redeploy"
LATER_TS = "2026-09-03T00:00:00+00:00"
CLI_TOOL_OPS = [ToolOp(tool="notify", op="send", effect="read", external=False)]  # low blast
CLI_ARTIFACT = ConfidenceArtifact(
    confidence=0.95,
    error_prob=0.05,
    evidence=SelfConsistencyEvidence(samples=5, agreement=0.95),
    computed_at="2026-07-12T00:00:00+00:00",
)


@pytest.fixture
def world():
    return World()


def _withdrawn(world, key_id="issuer-a", **check_kwargs):
    """issuer-a's promotion stands behind an on-loop grant, then issuer-a is withdrawn."""
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw(key_id)
    check = world.check(**check_kwargs)
    check.refresh(world.clock.now)
    return check


def _lower(world):
    world.source.refresh()
    outcome = run_withdrawal(
        PRINCIPAL, ACTION_CLASS, grant_store=world.grants, record_store=world.records,
        standing=world.source, now=world.clock.now, record_signer=world.evaluator,
    )
    assert outcome.status == "lowered", outcome.reason


# ---------------------------------------------------------------------------
# Ledger: which records can license a grant
# ---------------------------------------------------------------------------


def test_a_record_after_the_grants_ts_licenses_nothing(world):
    """Only records at or before the grant's ts count.

    A reattestation signed by issuer-b and appended after the grant was last
    written, with no grant write beside it, does not describe the grant as
    stored. Counted, it would become the record the level rests on, and
    issuer-a's withdrawal would stop lowering the grant."""
    world.promoted()
    late = record("reattestation", LATER_TS)
    world.records.put_record(late, signature=world.keys["issuer-b"][0].sign_record(late))
    world.clock.now += MINUTE
    world.withdraw("issuer-a")
    check = world.check()
    check.refresh(world.clock.now)
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert not assessment.held, "a record appended after the grant's ts re-licensed it"
    assert assessment.reason.startswith(gs.FALL_KEY_WITHDRAWN)
    assert "'issuer-a'" in assessment.reason


@pytest.mark.parametrize(
    "epoch",
    [None, datetime.datetime(2026, 9, 10, tzinfo=datetime.UTC)],
    ids=["no-epoch", "epoch-after-the-signed-promotion"],
)
def test_an_unsigned_licensing_record_after_a_signed_one_is_never_history(world, epoch):
    """GAL §6.10 excuses no unsigned record by what it says about itself.

    An unsigned reattestation planted at the grant's own ts, with no grant
    write, sorts after the signed promotion beside it ('ts#reattestation' >
    'ts#promotion'). Its ts is before the epoch, or no epoch is declared, so
    read alone it would be history and the withdrawn key's grant would hold."""
    check = _withdrawn(world, signing_epoch=epoch)
    world.records.put_record(record("reattestation", PROMOTION_TS))
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert not assessment.held, "a planted unsigned record restored a withdrawn key's grant"
    assert assessment.reason.startswith(gs.FALL_NOT_ESTABLISHED)
    assert "comes after a signed record" in assessment.reason


SIGNED_AFTER = {
    "issuer-reattestation": ("reattestation", lambda world: world.keys["issuer-b"][0]),
    "evaluator-withdrawal": ("withdrawal", lambda world: world.evaluator),
}


@pytest.mark.parametrize("signed_after", sorted(SIGNED_AFTER))
@pytest.mark.parametrize(
    "epoch",
    [None, datetime.datetime(2026, 9, 2, 12, tzinfo=datetime.UTC)],
    ids=["no-epoch", "epoch-between-the-unsigned-promotion-and-the-signed-record"],
)
def test_unsigned_history_keeps_its_level_when_signing_begins_after_it(world, epoch, signed_after):
    """Standing applies from the record-signing epoch (#179, ruling 11).

    The bootstrap and the promotion behind an on-loop grant were written
    unsigned, before signing began. A signed record that licenses nothing
    (one appended after the grant's ts) then shows signing has begun at the
    coordinate. Only a signed record BEFORE the licensing one makes it 'not
    history'; one after it says nothing about when the licensing record was
    written, and counting it would take the level from every grant whose
    history predates signing."""
    world.promoted(signer=None, bootstrap_signer=None)
    record_type, signer = SIGNED_AFTER[signed_after]
    late = record(record_type, LATER_TS)
    world.records.put_record(late, signature=signer(world).sign_record(late))
    check = world.check(signing_epoch=epoch)
    check.refresh(world.clock.now)
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert assessment.held, (
        "a signed record AFTER the unsigned licensing record made it 'not history': "
        f"{assessment.reason}"
    )


# ---------------------------------------------------------------------------
# re-seed
# ---------------------------------------------------------------------------


def _reseed(world, monkeypatch, check):
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: "arn:operator")
    return commands.reseed_command(
        grant_store=world.grants,
        record_store=world.records,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash=NEW_ENVELOPE,
        signer=world.keys["issuer-b"][0],  # an issuer key still in standing
        now=world.clock.now,
        standing_check=check,
    )


def test_reseed_does_not_relicense_a_grant_past_a_withdrawn_key(world, monkeypatch, capsys):
    """Re-seed runs on every far-jump redeploy. Its reattestation, signed by an
    issuer key in standing, would become the licensing record and bring the
    withdrawn key's on-loop back with no promotion."""
    check = _withdrawn(world)
    ledger = len(world.records.records)
    assert _reseed(world, monkeypatch, check) == 1
    assert gs.FALL_KEY_WITHDRAWN in capsys.readouterr().err
    assert len(world.records.records) == ledger, "re-seed wrote a reattestation"
    assert world.stored_grant().envelopeHash == ENV_HASH
    assert not check.assess(world.stored_grant(), world.clock.now).held


def test_reseed_refuses_while_standing_is_not_established(world, monkeypatch):
    world.promoted()
    world.served["text"] = "unreadable"
    check = world.check()
    check.refresh(world.clock.now)  # nothing accepted: standing is not established
    assert _reseed(world, monkeypatch, check) == 1
    assert world.stored_grant().envelopeHash == ENV_HASH


def test_reseed_proceeds_at_the_lowered_level_once_the_withdrawal_is_recorded(world, monkeypatch):
    check = _withdrawn(world)
    _lower(world)
    assert _reseed(world, monkeypatch, check) == 0
    stored = world.stored_grant()
    assert (stored.level, stored.envelopeHash) == (IN, NEW_ENVELOPE)


def test_reseed_is_unchanged_without_a_standing_source(world, monkeypatch):
    world.promoted()
    world.withdraw()
    assert _reseed(world, monkeypatch, None) == 0
    assert world.stored_grant().level is ON


def _bind_the_cli(world, monkeypatch, tmp_path, *, caller):
    """main() with the deploy-bound ISSUER_STANDING_* env the broker reads, and
    the world's stores, manifest facts and issuer-b signer in place of AWS."""
    for role_env in issuer_keys.ALL_ROLE_ENVS:
        for name in issuer_keys.role_env_names(role_env):
            monkeypatch.delenv(name, raising=False)
    doc_file = tmp_path / "issuer-standing.json"
    doc_file.write_text(world.served["text"], encoding="utf-8")
    authority_file = tmp_path / "authority.json"
    authority_file.write_text(json.dumps({"authority-1": world.authority_pem}), encoding="utf-8")
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_FILE_ENV, str(doc_file))
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV, str(10**9))
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV, str(authority_file))
    monkeypatch.setattr(commands, "_build_stores", lambda _t: (world.grants, world.records))
    monkeypatch.setattr(
        commands, "_manifest_context", lambda _t: (PRINCIPAL, [ACTION_CLASS], NEW_ENVELOPE, [])
    )
    monkeypatch.setattr(commands, "_ceremony_blast_context", lambda _p, _t: (CLI_TOOL_OPS, [], ENV_HASH))
    monkeypatch.setattr(commands, "_ceremony_clock_skew", lambda _p: datetime.timedelta(0))
    monkeypatch.setattr(commands, "resolve_record_signer", lambda zone=None: world.keys["issuer-b"][0])
    monkeypatch.setattr(commands, "_resolve_reviewer", lambda: None)
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: caller)


def _withdrawn_for_the_cli(world, monkeypatch, tmp_path, *, caller):
    """issuer-a's promotion stands behind an on-loop grant; issuer-a is withdrawn
    in the deploy-bound document and no withdrawal record is written."""
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    _bind_the_cli(world, monkeypatch, tmp_path, caller=caller)


def test_the_cli_reads_the_deploy_bound_standing_for_re_seed(world, monkeypatch, tmp_path, capsys):
    """main() builds the guard from the same ISSUER_STANDING_* env the broker reads."""
    _withdrawn_for_the_cli(world, monkeypatch, tmp_path, caller="arn:operator")
    assert commands.main(["re-seed"]) == 1
    assert gs.FALL_KEY_WITHDRAWN in capsys.readouterr().err
    assert world.stored_grant().envelopeHash == ENV_HASH


def test_the_cli_reads_the_deploy_bound_standing_for_propose(world, monkeypatch, tmp_path, capsys):
    """main(['propose']) hands the ceremony the deploy-bound standing check.

    Everything else about the proposal is eligible, so without the check the
    maker would stage an on-loop -> out-of-loop proposal anchored on a level
    the grant no longer acts at."""
    _withdrawn_for_the_cli(world, monkeypatch, tmp_path, caller="arn:maker")
    proposals = InMemoryProposalStore()
    enforcement = InMemoryStore()
    tool, _, op = ACTION_CLASS.partition(".")
    key = scoped_counter_key(PRINCIPAL, tool, op, commands.OBSERVATIONS_SUFFIX)
    assert enforcement.try_increment_counter(key, 100.0, 1e9)
    monkeypatch.setattr(commands, "_build_proposal_store", lambda _t: proposals)
    monkeypatch.setattr(commands, "_build_enforcement_store", lambda _t: enforcement)
    artifact = tmp_path / "artifact.json"
    artifact.write_text(CLI_ARTIFACT.model_dump_json(), encoding="utf-8")
    argv = [
        "propose",
        "--principal-agent-id", PRINCIPAL.agentId, "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user, "--tier", PRINCIPAL.tier,
        "--action-class", ACTION_CLASS, "--target-level", "out-of-loop",
        "--evidence-bundle", "fresh-evidence", "--owner-id", "owner:ops",
        "--label-latency", "PT1H", "--artifact-json", str(artifact),
        "--provenance-maturity", "signed-lineage", "--window-n", "200",
        "--min-observations", "10", "--threshold", "0.05", "--ttl-hours", "24",
        "--covered",
    ]
    rc = commands.main(argv)
    out = capsys.readouterr().out
    assert proposals.list_pending(PRINCIPAL, ACTION_CLASS) == [], (
        "main(['propose']) stored a proposal over an unrecorded withdrawal: the CLI "
        "did not pass the issuer standing check to propose"
    )
    assert rc == 1
    assert gs.FALL_KEY_WITHDRAWN in out, f"propose refused, but not on issuer standing: {out!r}"


def test_the_cli_reads_the_deploy_bound_standing_for_ratify(world, monkeypatch, tmp_path, capsys):
    """main(['ratify']) hands the ceremony the deploy-bound standing check.

    The grant is stored on-loop and acts in-loop because issuer-a is withdrawn.
    Without the check the ceremony would promote from the stored level, signing
    out-of-loop under issuer-b with no promotion through in-loop."""
    _withdrawn_for_the_cli(world, monkeypatch, tmp_path, caller="arn:checker")
    proposals = InMemoryProposalStore()
    proposals.put_proposal(_reproposal(from_level=ON, target_level=OUT))
    monkeypatch.setattr(commands, "_build_proposal_store", lambda _t: proposals)
    ledger = len(world.records.records)
    argv = [
        "ratify",
        "--principal-agent-id", PRINCIPAL.agentId, "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user, "--tier", PRINCIPAL.tier,
        "--action-class", ACTION_CLASS, "--proposal-id", "prop-re",
    ]
    rc = commands.main(argv)
    out = capsys.readouterr().out
    assert world.stored_grant().level is ON, (
        "main(['ratify']) promoted over an unrecorded withdrawal: the CLI did not "
        "pass the issuer standing check to the ceremony"
    )
    assert rc == 1
    assert len(world.records.records) == ledger, "ratify wrote a record"
    assert gs.FALL_KEY_WITHDRAWN in out, f"ratify refused, but not on issuer standing: {out!r}"


# ---------------------------------------------------------------------------
# propose and ratify
# ---------------------------------------------------------------------------


def test_propose_refuses_to_anchor_on_an_unrecorded_withdrawal(world, monkeypatch, capsys, tmp_path):
    check = _withdrawn(world)
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: "arn:maker")
    proposals = InMemoryProposalStore()
    args = propose_args(
        tmp_path / "unread-artifact.json",
        **{
            "--principal-agent-id": PRINCIPAL.agentId,
            "--skill": PRINCIPAL.skill,
            "--user": PRINCIPAL.user,
            "--tier": PRINCIPAL.tier,
            "--action-class": ACTION_CLASS,
            "--target-level": "out-of-loop",
        },
    )
    rc = commands.propose_command(
        args,
        grant_store=world.grants,
        proposal_store=proposals,
        enforcement_store=InMemoryStore(),
        envelope_hash=ENV_HASH,
        tool_ops=[ToolOp(tool="notify", op="send", effect="write", external=True)],
        high_blast=(),
        now=world.clock.now,
        standing_check=check,
    )
    assert rc == 1
    assert gs.FALL_KEY_WITHDRAWN in capsys.readouterr().out
    assert proposals.list_pending(PRINCIPAL, ACTION_CLASS) == []


def _ratify(world, proposal, check):
    return PromotionCeremony(
        grant_store=world.grants,
        promotion_record_store=world.records,
        record_signer=world.keys["issuer-b"][0],
        standing_check=check,
    ).execute(proposal, "checker-bob", now=world.clock.now)


def test_ratify_refuses_to_promote_over_an_unrecorded_withdrawal(world):
    """Stored on-loop, acting in-loop because issuer-a is withdrawn: promoting
    from the stored level would raise the grant from a level it no longer holds."""
    check = _withdrawn(world)
    result = _ratify(world, _reproposal(from_level=ON, target_level=OUT), check)
    assert result.status == "rejected"
    assert gs.FALL_KEY_WITHDRAWN in result.reason
    assert world.stored_grant().level is ON


def test_recovery_is_a_new_promotion_from_the_lowered_level_under_a_key_in_standing(world):
    check = _withdrawn(world)
    _lower(world)
    result = _ratify(world, _reproposal(from_level=IN, target_level=ON), check)
    assert result.status == "ratified", result.reason
    assert world.stored_grant().level is ON
    assert check.assess(world.stored_grant(), world.clock.now).held
