"""Two signing roles, and verification that binds record type to role.

GAL-SPEC §6.10 requires EVERY ledger record to be signed; GAL §6.7.2 requires
the demotion evaluator to be a SEPARATE identity from the issuer. Satisfying
the first by handing the evaluator the issuer key would break the second — it
could then mint promotion records — so the fix is a second signing role, and a
verifier that refuses a key of the wrong role.

What this file pins, in four groups:

  roles        the record-type → role mapping, and that a cross-role signature
               fails with a reason naming the mechanism (not "unknown key")
  config       the EVALUATOR env contract mirrors the ISSUER one exactly,
               because both run one parameterized code path; and a key_id
               claimed by both roles refuses at cold start
  writers      every record-writing path signs with ITS role's key when one is
               configured, and refuses (never degrades) when half-configured
  epoch        the audit's history-awareness is an explicit, stated instant —
               never a silent exemption of old rows

The epoch's evaluation instant is an explicit input (``now``), the same
discipline as the grant term: a ledger must not get to decide whether its own
epoch is in force.
"""

from __future__ import annotations

import datetime
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants.audit import (
    RECORD_SIGNATURE_VERIFIES,
    RECORD_SIGNING_EPOCH_VALID,
    ANNOTATION_SIGNING_EPOCH_APPLIED,
    ANNOTATION_SIGNING_EPOCH_UNENFORCEABLE,
    ANNOTATION_SIGNING_EPOCH_UNSET,
    AuditDataset,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.record_signing import (
    EVALUATOR_ROLE,
    ISSUER_ROLE,
    RECORD_ROLE_UNRESOLVED,
    RECORD_SIGNER_ROLE_AMBIGUOUS,
    RECORD_SIGNER_WRONG_ROLE,
    RECORD_TYPE_SIGNING_ROLE,
    RoleKeyResolvers,
    canonical_record_payload,
    signer_from_pem,
    signing_role_for_record_type,
    verify_record_by_type,
)
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.channels.keys import key_resolver_from_map

PRINCIPAL = Principal(agentId="agent-roles", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
HMAC_KEY = b"test-hmac-key-roles"
ENVELOPE_HASH = "sha256:env-roles"

TS = "2026-07-01T00:00:00+00:00"

ALL_RECORD_TYPES = ("promotion", "bootstrap", "tightening", "demotion", "lapse")


# ---------------------------------------------------------------------------
# Fixtures — one key per role, as a real floor provisions them
# ---------------------------------------------------------------------------


def _keypair(key_id: str):
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    return signer_from_pem(key_id, "zone-test", private_pem), public_pem


@pytest.fixture
def roles():
    """(issuer_signer, evaluator_signer, RoleKeyResolvers) with DISTINCT keys."""
    issuer_signer, issuer_pem = _keypair("issuer:roles-test")
    evaluator_signer, evaluator_pem = _keypair("evaluator:roles-test")
    return (
        issuer_signer,
        evaluator_signer,
        RoleKeyResolvers(
            issuer=key_resolver_from_map({"issuer:roles-test": issuer_pem}),
            evaluator=key_resolver_from_map({"evaluator:roles-test": evaluator_pem}),
        ),
    )


def _record(record_type: str, *, ts: str = TS, **overrides) -> PromotionRecord:
    """A well-shaped record of each type — the schema enforces per-type shape."""
    common = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        evidence="evidence-ref-roles",
        envelopeHash=ENVELOPE_HASH,
        ts=ts,
    )
    per_type = {
        "promotion": dict(
            fromLevel="in-loop",
            toLevel="on-loop",
            predicate="predicate passed",
            proposedBy="maker-alice",
            ratifiedBy="checker-bob",
        ),
        "bootstrap": dict(
            fromLevel=None,
            toLevel="in-loop",
            predicate=None,
            proposedBy="seeder",
            ratifiedBy="seeder",
        ),
        "tightening": dict(
            fromLevel="on-loop",
            toLevel="in-loop",
            predicate=None,
            proposedBy="operator",
            ratifiedBy="operator",
        ),
        "demotion": dict(
            fromLevel="on-loop",
            toLevel="in-loop",
            predicate=None,
            proposedBy=DEMOTION_RATIFIER,
            ratifiedBy=DEMOTION_RATIFIER,
            triggeredBy=["budget_breach"],
            demotionReason="failing",
        ),
        "lapse": dict(
            fromLevel="on-loop",
            toLevel="in-loop",
            predicate=None,
            proposedBy=DEMOTION_RATIFIER,
            ratifiedBy=DEMOTION_RATIFIER,
            triggeredBy=[],
            demotionReason="pending-evidence",
        ),
    }[record_type]
    return PromotionRecord(**{**common, **per_type, **overrides})


def _signer_for(record_type: str, issuer_signer, evaluator_signer):
    return (
        issuer_signer
        if RECORD_TYPE_SIGNING_ROLE[record_type] == ISSUER_ROLE
        else evaluator_signer
    )


# ---------------------------------------------------------------------------
# The mapping itself
# ---------------------------------------------------------------------------


def test_every_schema_record_type_has_a_signing_role():
    """A new record type must not arrive with no role — it would verify as
    RECORD_ROLE_UNRESOLVED forever, which reads as a broken audit rather than
    as the missing mapping it is."""
    from typing import get_args

    import safe_agents.broker.schemas.promotion_record as pr_module

    declared = set(get_args(pr_module.PromotionRecord.model_fields["recordType"].annotation))
    assert declared == set(RECORD_TYPE_SIGNING_ROLE), (
        "the record-type vocabulary and the signing-role map have diverged"
    )
    assert set(ALL_RECORD_TYPES) == declared


@pytest.mark.parametrize("record_type", ALL_RECORD_TYPES)
def test_each_record_type_verifies_under_its_own_role(record_type, roles):
    issuer_signer, evaluator_signer, resolvers = roles
    record = _record(record_type)
    signer = _signer_for(record_type, issuer_signer, evaluator_signer)

    result = verify_record_by_type(
        canonical_record_payload(record),
        signer.sign_record(record),
        record_type=record_type,
        resolvers=resolvers,
    )

    assert result.ok, result.reason


@pytest.mark.parametrize("record_type", ALL_RECORD_TYPES)
def test_the_other_role_s_key_fails_with_the_wrong_role_reason(record_type, roles):
    """The whole point of the second identity: an evaluator-signed promotion
    (authority minted from the automatic side) and an issuer-signed demotion
    are BOTH refused, and the reason names the mechanism rather than reading as
    an unknown key."""
    issuer_signer, evaluator_signer, resolvers = roles
    record = _record(record_type)
    wrong = (
        evaluator_signer
        if RECORD_TYPE_SIGNING_ROLE[record_type] == ISSUER_ROLE
        else issuer_signer
    )

    result = verify_record_by_type(
        canonical_record_payload(record),
        wrong.sign_record(record),
        record_type=record_type,
        resolvers=resolvers,
    )

    assert not result.ok
    assert result.reason == RECORD_SIGNER_WRONG_ROLE


def test_a_key_id_in_both_maps_fails_closed(roles):
    """One key cannot hold two roles. Refused rather than resolved in either
    direction — resolving it 'helpfully' would restore exactly the collapse the
    split exists to prevent."""
    shared_signer, shared_pem = _keypair("shared:both-roles")
    shared = key_resolver_from_map({"shared:both-roles": shared_pem})
    ambiguous = RoleKeyResolvers(issuer=shared, evaluator=shared)
    record = _record("promotion")

    result = verify_record_by_type(
        canonical_record_payload(record),
        shared_signer.sign_record(record),
        record_type="promotion",
        resolvers=ambiguous,
    )

    assert not result.ok
    assert result.reason == RECORD_SIGNER_ROLE_AMBIGUOUS


@pytest.mark.parametrize(
    "record_type,configured",
    [("promotion", EVALUATOR_ROLE), ("demotion", ISSUER_ROLE)],
    ids=["promotion-without-issuer-keys", "demotion-without-evaluator-keys"],
)
def test_a_role_with_no_verify_keys_never_passes(record_type, configured, roles):
    """A role we cannot check is not a role that passes."""
    issuer_signer, evaluator_signer, _ = roles
    signer = _signer_for(record_type, issuer_signer, evaluator_signer)
    _, pem = _keypair("unused:key")
    other_map = key_resolver_from_map({"unused:key": pem})
    resolvers = (
        RoleKeyResolvers(evaluator=other_map)
        if configured == EVALUATOR_ROLE
        else RoleKeyResolvers(issuer=other_map)
    )

    record = _record(record_type)
    result = verify_record_by_type(
        canonical_record_payload(record),
        signer.sign_record(record),
        record_type=record_type,
        resolvers=resolvers,
    )

    assert not result.ok
    assert result.reason == RECORD_ROLE_UNRESOLVED


def test_signing_role_for_an_unknown_record_type_is_none():
    assert signing_role_for_record_type("not-a-record-type") is None


# ---------------------------------------------------------------------------
# Config — the evaluator env contract mirrors the issuer one, one code path
# ---------------------------------------------------------------------------

ROLE_ENVS = [
    pytest.param(issuer_keys.ISSUER_ROLE_ENV, id="issuer"),
    pytest.param(issuer_keys.EVALUATOR_ROLE_ENV, id="evaluator"),
]


@pytest.fixture(autouse=True)
def _no_ambient_signing_env(monkeypatch):
    """Both roles' env, cleared. A developer's shell must not decide which
    identity a test's records were signed by."""
    for role_env in issuer_keys.SIGNING_ROLE_ENVS:
        for name in (
            role_env.key_secret_arn_env,
            role_env.key_file_env,
            role_env.key_id_env,
            role_env.zone_env,
            role_env.verify_keys_param_env,
        ):
            monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_signing_is_off_with_no_source(role_env):
    assert issuer_keys.resolve_signer_for_role(role_env, "development") is None


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_half_configured_signing_refuses(role_env, monkeypatch):
    """A key_id with no key SOURCE means the operator intended to sign.
    Degrading to an unsigned record mints a weaker artifact than was asked
    for — fail toward less authority."""
    monkeypatch.setenv(role_env.key_id_env, "key-1")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match=role_env.key_id_env):
        issuer_keys.resolve_signer_for_role(role_env, "development")


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_a_source_without_a_key_id_refuses(role_env, monkeypatch):
    monkeypatch.setenv(role_env.key_secret_arn_env, "arn:aws:secretsmanager:::secret:x")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match=role_env.key_id_env):
        issuer_keys.resolve_signer_for_role(role_env, "development")


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_a_source_without_a_zone_refuses(role_env, monkeypatch):
    """The zone is part of the attribution the signature carries, so it is
    required for BOTH roles — an evaluator signature with no zone is a record
    nobody can attribute."""
    monkeypatch.setenv(role_env.key_secret_arn_env, "arn:aws:secretsmanager:::secret:x")
    monkeypatch.setenv(role_env.key_id_env, "key-1")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match=role_env.zone_env):
        issuer_keys.resolve_signer_for_role(role_env)


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_two_sources_refuse(role_env, monkeypatch):
    monkeypatch.setenv(role_env.key_secret_arn_env, "arn:aws:secretsmanager:::secret:x")
    monkeypatch.setenv(role_env.key_file_env, "/tmp/key.pem")
    monkeypatch.setenv(role_env.key_id_env, "key-1")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="exactly one"):
        issuer_keys.resolve_signer_for_role(role_env, "development")


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_a_configured_role_resolves_a_signer(role_env, monkeypatch):
    signer, _pem = _keypair("key-1")
    private_pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    monkeypatch.setenv(role_env.key_secret_arn_env, "arn:aws:secretsmanager:::secret:x")
    monkeypatch.setenv(role_env.key_id_env, "key-1")
    monkeypatch.setattr(issuer_keys, "_fetch_secret", lambda arn: private_pem)

    resolved = issuer_keys.resolve_signer_for_role(role_env, "development")

    assert resolved is not None
    assert (resolved.key_id, resolved.zone) == ("key-1", "development")


def test_the_named_entry_points_select_the_right_role(monkeypatch):
    """resolve_record_signer stays the ISSUER's (cluster manifests and CDK bind
    that name); the evaluator has its own."""
    private_pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    monkeypatch.setattr(issuer_keys, "_fetch_secret", lambda arn: private_pem)
    monkeypatch.setenv(issuer_keys.EVALUATOR_SIGNING_KEY_SECRET_ARN_ENV, "arn:x")
    monkeypatch.setenv(issuer_keys.EVALUATOR_SIGNING_KEY_ID_ENV, "evaluator-1")
    monkeypatch.setenv(issuer_keys.EVALUATOR_SIGNING_ZONE_ENV, "development")

    assert issuer_keys.resolve_record_signer() is None  # issuer unconfigured
    evaluator = issuer_keys.resolve_evaluator_signer()
    assert evaluator is not None and evaluator.key_id == "evaluator-1"


def test_record_key_resolvers_are_none_when_neither_role_is_configured():
    assert issuer_keys.resolve_record_key_resolvers() is None


def test_record_key_resolvers_build_both_maps(monkeypatch):
    _, issuer_pem = _keypair("issuer-1")
    _, evaluator_pem = _keypair("evaluator-1")
    params = {
        "/issuer": json.dumps({"issuer-1": issuer_pem}),
        "/evaluator": json.dumps({"evaluator-1": evaluator_pem}),
    }
    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/issuer")
    monkeypatch.setenv(issuer_keys.EVALUATOR_VERIFY_KEYS_PARAM_ENV, "/evaluator")
    monkeypatch.setattr(issuer_keys, "_fetch_parameter", lambda name: params[name])

    resolvers = issuer_keys.resolve_record_key_resolvers()

    assert resolvers.issuer("issuer-1") is not None
    assert resolvers.evaluator("evaluator-1") is not None
    assert resolvers.issuer("evaluator-1") is None
    assert resolvers.roles_resolving("issuer-1") == (ISSUER_ROLE,)


def test_a_key_id_in_both_verify_params_refuses_at_cold_start(monkeypatch):
    """Caught where the message can name both parameters and the key, rather
    than per-record at verify time."""
    _, pem = _keypair("shared-1")
    params = {
        "/issuer": json.dumps({"shared-1": pem}),
        "/evaluator": json.dumps({"shared-1": pem}),
    }
    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/issuer")
    monkeypatch.setenv(issuer_keys.EVALUATOR_VERIFY_KEYS_PARAM_ENV, "/evaluator")
    monkeypatch.setattr(issuer_keys, "_fetch_parameter", lambda name: params[name])

    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="shared-1"):
        issuer_keys.resolve_record_key_resolvers()


# ---------------------------------------------------------------------------
# Writers — every path signs with its own role's key
# ---------------------------------------------------------------------------


def _grant(**overrides) -> Grant:
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level="on-loop",
        envelopeHash=ENVELOPE_HASH,
        promotedBy="alice",
        evidence="evidence-ref-roles",
        ts=TS,
        lastSafeLevel="in-loop",
        demotionTriggers=["budget_breach"],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    return Grant(**defaults)


def _stores():
    return InMemoryGrantStore(hmac_key=HMAC_KEY), InMemoryPromotionRecordStore()


@pytest.fixture
def stub_operator(monkeypatch):
    """The ceremony's operator identity, without STS.

    Same convention as test_grants_commands: the command surface derives
    identity from STS GetCallerIdentity, so an un-stubbed unit test reaches the
    network and its result depends on whatever credentials the process happens
    to hold.
    """
    from safe_agents.broker.grants import commands

    arn = "arn:aws:sts::000000000000:assumed-role/PromotionRole/roles-test"
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: arn)
    return arn


def _verify_written(record_store, record, resolvers) -> bool:
    return verify_record_by_type(
        record_store.stored_data_for(record),
        record_store.signature_for(record),
        record_type=record.recordType,
        resolvers=resolvers,
    ).ok


def test_seed_signs_the_bootstrap_record_with_the_issuer_key(roles, stub_operator, capsys):
    from safe_agents.broker.grants.commands import seed_command

    issuer_signer, _evaluator_signer, resolvers = roles
    grant_store, record_store = _stores()

    assert seed_command(
        grant_store=grant_store,
        record_store=record_store,
        grants=[_grant(level="in-loop")],
        signer=issuer_signer,
    ) == 0

    record = record_store.records[0]
    assert record.recordType == "bootstrap"
    assert _verify_written(record_store, record, resolvers)
    assert "signed (issuer DSSE)" in capsys.readouterr().out


def test_seed_without_a_signer_still_writes_unsigned(roles, stub_operator):
    """No signing configured = local/dev behaviour unchanged."""
    from safe_agents.broker.grants.commands import seed_command

    grant_store, record_store = _stores()
    assert seed_command(
        grant_store=grant_store,
        record_store=record_store,
        grants=[_grant(level="in-loop")],
    ) == 0
    assert record_store.signature_for(record_store.records[0]) is None


def test_tighten_signs_the_tightening_record_with_the_issuer_key(roles, stub_operator, capsys):
    import argparse

    from safe_agents.broker.grants.commands import tighten_command

    issuer_signer, _evaluator_signer, resolvers = roles
    grant_store, record_store = _stores()
    grant_store.put_grant(_grant())

    args = argparse.Namespace(
        principal_agent_id=PRINCIPAL.agentId,
        skill=PRINCIPAL.skill,
        user=PRINCIPAL.user,
        tier=PRINCIPAL.tier,
        action_class=ACTION_CLASS,
        evidence="voluntary tightening",
    )
    assert tighten_command(
        args, grant_store=grant_store, record_store=record_store, signer=issuer_signer
    ) == 0

    record = record_store.records[-1]
    assert record.recordType == "tightening"
    assert _verify_written(record_store, record, resolvers)
    assert "signed=yes (issuer DSSE)" in capsys.readouterr().out


def test_demotion_signs_with_the_evaluator_key(roles):
    from safe_agents.broker.grants.demotion import (
        DemotionMetrics,
        apply_demotion,
        evaluate_demotion_triggers,
    )
    from safe_agents.broker.schemas.common import DemotionTrigger

    _issuer_signer, evaluator_signer, resolvers = roles
    grant_store, record_store = _stores()
    grant = _grant()
    grant_store.put_grant(grant)
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    result = evaluate_demotion_triggers(
        stored, DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    )

    _updated, record = apply_demotion(
        stored,
        result,
        store=grant_store,
        record_store=record_store,
        record_signer=evaluator_signer,
    )

    assert record.recordType == "demotion"
    assert _verify_written(record_store, record, resolvers)


def test_a_demotion_signed_by_the_issuer_does_not_verify(roles):
    """The refusal that gives the separate identity its meaning — stated at the
    writer level, not only in the pure verifier."""
    from safe_agents.broker.grants.demotion import (
        DemotionMetrics,
        apply_demotion,
        evaluate_demotion_triggers,
    )
    from safe_agents.broker.schemas.common import DemotionTrigger

    issuer_signer, _evaluator_signer, resolvers = roles
    grant_store, record_store = _stores()
    grant_store.put_grant(_grant())
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    result = evaluate_demotion_triggers(
        stored, DemotionMetrics(tripped=frozenset({DemotionTrigger.budget_breach}))
    )

    _updated, record = apply_demotion(
        stored,
        result,
        store=grant_store,
        record_store=record_store,
        record_signer=issuer_signer,
    )

    assert not _verify_written(record_store, record, resolvers)


def test_lapse_signs_with_the_evaluator_key(roles):
    from safe_agents.broker.grants.lapse import apply_lapse

    _issuer_signer, evaluator_signer, resolvers = roles
    grant_store, record_store = _stores()
    grant = _grant(certifiedUntil="2026-07-10T00:00:00+00:00")
    grant_store.put_grant(grant)
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant

    _updated, record = apply_lapse(
        stored,
        store=grant_store,
        record_store=record_store,
        now=datetime.datetime(2026, 7, 11, tzinfo=datetime.UTC),
        record_signer=evaluator_signer,
    )

    assert record.recordType == "lapse"
    assert _verify_written(record_store, record, resolvers)


def test_the_runner_refuses_half_configured_evaluator_signing(monkeypatch, capsys):
    """The unattended path: a half-configured evaluator key exits 2 rather than
    quietly writing unsigned records all night."""
    from safe_agents.broker.grants import runner

    grant_store, record_store = _stores()
    grant_store.put_grant(_grant())
    monkeypatch.setattr(runner, "_build_stores", lambda _table: (grant_store, record_store))
    monkeypatch.setenv(issuer_keys.EVALUATOR_SIGNING_KEY_ID_ENV, "evaluator-1")

    rc = runner.main(
        [
            "--principal-agent-id", PRINCIPAL.agentId,
            "--skill", PRINCIPAL.skill,
            "--user", PRINCIPAL.user,
            "--tier", PRINCIPAL.tier,
            "--action-class", ACTION_CLASS,
        ]
    )

    assert rc == 2
    assert issuer_keys.EVALUATOR_SIGNING_KEY_ID_ENV in capsys.readouterr().err
    assert record_store.records == []


# ---------------------------------------------------------------------------
# The epoch — history is an explicit cut, never a silent exemption
# ---------------------------------------------------------------------------

EPOCH = "2026-07-01T00:00:00+00:00"
NOW = datetime.datetime(2026, 8, 1, tzinfo=datetime.UTC)


def _dataset(records: list[PromotionRecord], *, signed_by=None) -> AuditDataset:
    """A ledger-only dataset: records, no grants.

    Deliberate isolation. The grant-level rules (LEDGER_COUNTERPART,
    LEVEL_DROP_RECORDED, GRANT_TERM_RATIFIED) judge a grant against its ledger
    and would fire on any single-record fixture, so including a grant would
    make these tests assert on a mixture and drift every time an unrelated rule
    changed. Every assertion below is about RECORD_SIGNATURE_VERIFIES and the
    epoch, and nothing else can fire.
    """
    entries = []
    for record in records:
        signer = signed_by(record) if signed_by is not None else None
        entries.append(
            AuditedRecord(
                record=record,
                signature=signer.sign_record(record) if signer is not None else None,
                raw_data=canonical_record_payload(record),
            )
        )
    return AuditDataset(records=tuple(entries))


def _signature_findings(report):
    return [v for v in report.violations if v.rule == RECORD_SIGNATURE_VERIFIES]


@pytest.mark.parametrize(
    "ts,expect_violation",
    [
        ("2026-06-30T23:59:59+00:00", False),
        (EPOCH, True),
        ("2026-07-01T00:00:01+00:00", True),
    ],
    ids=["before-epoch-exempt", "exactly-at-epoch-enforced", "after-epoch-enforced"],
)
def test_the_epoch_boundary_decides_whether_an_unsigned_record_is_a_violation(
    ts, expect_violation, roles
):
    """At-or-after, so the boundary instant itself is IN scope — an epoch whose
    own instant were exempt would leave a one-tick hole nobody would test."""
    _issuer, _evaluator, resolvers = roles
    report = run_audit(
        _dataset([_record("tightening", ts=ts)]),
        record_key_resolver=resolvers,
        signing_epoch=EPOCH,
        now=NOW,
    )

    assert bool(_signature_findings(report)) is expect_violation


def test_a_pre_epoch_record_is_reported_as_an_annotation_naming_the_epoch(roles):
    """Green-with-annotation: the exemption is stated, with the instant that
    licenses it, so a reader never mistakes the cut for coverage."""
    _issuer, _evaluator, resolvers = roles
    report = run_audit(
        _dataset([_record("demotion", ts="2026-06-01T00:00:00+00:00")]),
        record_key_resolver=resolvers,
        signing_epoch=EPOCH,
        now=NOW,
    )

    assert report.violations == ()
    annotation = next(
        a for a in report.annotations if a.startswith(ANNOTATION_SIGNING_EPOCH_APPLIED)
    )
    assert EPOCH in annotation
    assert "1 record(s)" in annotation


@pytest.mark.parametrize("record_type", ALL_RECORD_TYPES)
def test_in_epoch_records_of_every_type_verify_when_correctly_signed(record_type, roles):
    issuer_signer, evaluator_signer, resolvers = roles
    report = run_audit(
        _dataset(
            [_record(record_type, ts="2026-07-05T00:00:00+00:00")],
            signed_by=lambda r: _signer_for(r.recordType, issuer_signer, evaluator_signer),
        ),
        record_key_resolver=resolvers,
        signing_epoch=EPOCH,
        now=NOW,
    )

    assert report.violations == ()


def test_with_no_epoch_todays_scope_holds_and_says_so(roles):
    """Unset keeps the pre-epoch scope — an unsigned tightening is NOT a
    finding — but the report must SAY the requirement is unenforced. Silence
    here is the failure mode: a green audit that never checked."""
    _issuer, _evaluator, resolvers = roles
    report = run_audit(
        _dataset([_record("tightening", ts="2026-09-01T00:00:00+00:00")]),
        record_key_resolver=resolvers,
    )

    assert _signature_findings(report) == []
    assert any(a.startswith(ANNOTATION_SIGNING_EPOCH_UNSET) for a in report.annotations)


def test_with_no_epoch_an_unsigned_promotion_is_still_a_violation(roles):
    """The pre-epoch scope is unchanged, not relaxed."""
    _issuer, _evaluator, resolvers = roles
    report = run_audit(
        _dataset([_record("promotion")]), record_key_resolver=resolvers
    )

    assert len(_signature_findings(report)) == 1


def test_an_epoch_in_the_future_is_a_violation_not_a_quiet_pass(roles):
    """A future epoch exempts every record ever written: a control that is
    configured and does nothing, which reads as coverage. The comparison is
    against the SUPPLIED instant, never against the ledger's own timestamps."""
    _issuer, _evaluator, resolvers = roles
    future = "2027-01-01T00:00:00+00:00"

    report = run_audit(
        # Records dated AFTER the future epoch: if the check derived "now" from
        # the data instead of the supplied instant, the epoch would look past
        # and this violation would vanish.
        _dataset([_record("tightening", ts="2027-06-01T00:00:00+00:00")]),
        record_key_resolver=resolvers,
        signing_epoch=future,
        now=NOW,
    )

    epoch_findings = [v for v in report.violations if v.rule == RECORD_SIGNING_EPOCH_VALID]
    assert len(epoch_findings) == 1
    assert future in epoch_findings[0].detail
    assert NOW.isoformat() in epoch_findings[0].detail


# The SAME instant, spelled three legal ISO-8601 ways. Only the first is the
# ledger's canonical form (store.validate_record_ts); an operator's env is under
# no such guard, so all three must land on identical verdicts.
EQUIVALENT_EPOCHS = [
    pytest.param("2026-07-01T00:00:00+00:00", id="canonical"),
    pytest.param("2026-07-01T00:00:00Z", id="zulu"),
    pytest.param("2026-07-01T02:00:00+02:00", id="non-utc-offset"),
]


@pytest.mark.parametrize("epoch_form", EQUIVALENT_EPOCHS)
@pytest.mark.parametrize(
    "ts,expect_violation",
    [
        ("2026-06-30T23:59:59+00:00", False),
        ("2026-07-01T00:00:00+00:00", True),
        ("2026-07-01T00:00:01+00:00", True),
    ],
    ids=["second-before", "same-second-as-epoch", "second-after"],
)
def test_equivalent_epoch_spellings_give_identical_verdicts(
    epoch_form, ts, expect_violation, roles
):
    """The comparison is lexical, so both sides must be in the ledger's
    canonical form — the epoch is normalized before any compare.

    Unnormalized, this is wrong in the DANGEROUS direction and only for some
    spellings, which is why it needs a test per spelling rather than one per
    boundary. '+' (0x2B) sorts before 'Z' (0x5A), so against a 'Z'-spelled
    epoch the same-second record (canonical, '+00:00') compares as EARLIER and
    is silently exempted; a non-UTC offset is wrong by its whole offset. Both
    shed enforcement quietly — the failure the epoch exists to prevent.
    """
    _issuer, _evaluator, resolvers = roles
    report = run_audit(
        _dataset([_record("tightening", ts=ts)]),
        record_key_resolver=resolvers,
        signing_epoch=epoch_form,
        now=NOW,
    )

    assert bool(_signature_findings(report)) is expect_violation


@pytest.mark.parametrize("epoch_form", EQUIVALENT_EPOCHS)
def test_a_non_canonical_epoch_is_reported_in_both_forms(epoch_form, roles):
    """An epoch silently reinterpreted covers a different set of rows than the
    operator intended, so the annotation shows what their value normalized to
    whenever it differs from what they typed."""
    _issuer, _evaluator, resolvers = roles
    canonical = "2026-07-01T00:00:00+00:00"

    report = run_audit(
        _dataset([_record("demotion", ts="2026-06-01T00:00:00+00:00")]),
        record_key_resolver=resolvers,
        signing_epoch=epoch_form,
        now=NOW,
    )

    annotation = next(
        a for a in report.annotations if a.startswith(ANNOTATION_SIGNING_EPOCH_APPLIED)
    )
    assert canonical in annotation
    if epoch_form != canonical:
        assert epoch_form in annotation


def test_an_epoch_without_an_evaluation_instant_is_refused(roles):
    """Ruling: the instant is an explicit INPUT. Defaulting it to the wall
    clock inside a pure rule would put a clock in the auditor; deriving it from
    the records would let the ledger judge its own epoch."""
    _issuer, _evaluator, resolvers = roles
    with pytest.raises(ValueError, match="explicit evaluation instant"):
        run_audit(
            _dataset([_record("promotion")]),
            record_key_resolver=resolvers,
            signing_epoch=EPOCH,
        )


@pytest.mark.parametrize(
    "bad", ["2026-07-01T00:00:00", "not-an-instant"], ids=["naive", "unparseable"]
)
def test_an_ambiguous_epoch_is_refused(bad, roles):
    _issuer, _evaluator, resolvers = roles
    with pytest.raises(ValueError):
        run_audit(
            _dataset([_record("promotion")]),
            record_key_resolver=resolvers,
            signing_epoch=bad,
            now=NOW,
        )


def test_no_verify_keys_at_all_skips_loudly_and_annotates():
    report = run_audit(_dataset([_record("promotion")]), signing_epoch=EPOCH, now=NOW)

    assert RECORD_SIGNATURE_VERIFIES in report.skipped_rules
    assert any(
        a.startswith(ANNOTATION_SIGNING_EPOCH_UNENFORCEABLE) for a in report.annotations
    )
    assert report.violations == ()


@pytest.mark.parametrize("role_env", ROLE_ENVS)
def test_a_file_held_key_refuses_on_windows(role_env, monkeypatch, tmp_path):
    """Windows has no group/other mode bits, so the owner-only gate cannot be
    evaluated there. Loading the key anyway would skip the gate; the file arm
    refuses instead and says why."""
    monkeypatch.delenv("BROKER_STORE", raising=False)
    monkeypatch.setattr("sys.platform", "win32")
    key = tmp_path / "key.pem"
    key.write_text("unused", encoding="utf-8")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="not supported on Windows"):
        issuer_keys._read_local_key_file(str(key), role_env)
