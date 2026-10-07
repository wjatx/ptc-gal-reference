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
  epoch        setting it requires a verifying signature on every record. A
               record's own ts excuses nothing, and unsigned history is
               excused only by a signed acknowledgment of its stored bytes

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
from safe_agents.broker.grants.acknowledgments import (
    AcknowledgmentRecord,
    canonical_ack_payload,
    sign_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    LEDGER_COUNTERPART,
    LEVEL_LEDGER_CONSISTENT,
    RECORD_SIGNATURE_VERIFIES,
    RECORD_SIGNING_EPOCH_VALID,
    ANNOTATION_SIGNING_EPOCH_UNENFORCEABLE,
    ANNOTATION_SIGNING_EPOCH_UNSET,
    AuditDataset,
    AuditedAcknowledgment,
    AuditedGrant,
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
    stored_record_digest_hex,
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

ALL_RECORD_TYPES = ("promotion", "bootstrap", "tightening", "demotion", "lapse", "reattestation")


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
        "reattestation": dict(
            fromLevel="on-loop",
            toLevel="on-loop",
            predicate=None,
            proposedBy="operator",
            ratifiedBy="operator",
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
# The epoch: once set, every record is signed or individually acknowledged
# ---------------------------------------------------------------------------

EPOCH = "2026-07-01T00:00:00+00:00"
NOW = datetime.datetime(2026, 8, 1, tzinfo=datetime.UTC)
BEFORE_EPOCH = "2026-06-01T00:00:00+00:00"
AFTER_EPOCH = "2026-07-05T00:00:00+00:00"

# A record's ts on either side of the epoch, and on it. The audit used to read
# this field to decide whether an unsigned record was exempt.
TS_AROUND_EPOCH = [
    pytest.param("2026-06-30T23:59:59+00:00", id="second-before-epoch"),
    pytest.param(EPOCH, id="exactly-at-epoch"),
    pytest.param("2026-07-01T00:00:01+00:00", id="second-after-epoch"),
]


def _entry(record: PromotionRecord, signer=None) -> AuditedRecord:
    return AuditedRecord(
        record=record,
        signature=signer.sign_record(record) if signer is not None else None,
        raw_data=canonical_record_payload(record),
    )


def _dataset(records: list[PromotionRecord], *, signed_by=None) -> AuditDataset:
    """A ledger-only dataset: records, no grants.

    Deliberate isolation. The grant-level rules (LEDGER_COUNTERPART,
    LEVEL_DROP_RECORDED, GRANT_TERM_RATIFIED) judge a grant against its ledger
    and would fire on any single-record fixture, so including a grant would
    make these tests assert on a mixture and drift every time an unrelated rule
    changed. Every assertion below is about RECORD_SIGNATURE_VERIFIES and the
    epoch. One ledger-level rule does fire on these fixtures: a lone demotion or
    lapse has nothing before it, which EVALUATOR_RECORD_CONTINUOUS reports. The
    tests that use one therefore assert on the signature findings alone.
    """
    return AuditDataset(
        records=tuple(
            _entry(record, signed_by(record) if signed_by is not None else None)
            for record in records
        )
    )


def _signature_findings(report):
    return [v for v in report.violations if v.rule == RECORD_SIGNATURE_VERIFIES]


def _unsigned_detail(record: PromotionRecord) -> str:
    """The finding for an unsigned record, spelled out in full.

    Pinned as a literal because it is a contract: an acknowledgment binds the
    sha256 of this exact string, so rewording it un-waives every stored
    acknowledgment of an unsigned record.
    """
    digest = stored_record_digest_hex(canonical_record_payload(record))
    from_level = record.fromLevel.value if record.fromLevel else "no grant"
    return (
        f"{record.recordType} record ts={record.ts} {from_level} -> {record.toLevel.value} "
        f"(stored bytes sha256:{digest}) carries no DSSE signature; it must be signed by the "
        f"{RECORD_TYPE_SIGNING_ROLE[record.recordType]} identity"
    )


def _acknowledgment(violation, signer) -> AuditedAcknowledgment:
    """A stored acknowledgment of ``violation``, signed by ``signer``."""
    ack = AcknowledgmentRecord(
        rule=violation.rule,
        coordinate=violation.coordinate,
        detailDigest=violation_detail_digest(violation.detail),
        rationale="unsigned history from before record signing was adopted",
        acknowledgedBy="arn:aws:sts::000000000000:assumed-role/CheckerRole/roles-test",
        ts="2026-07-20T00:00:00+00:00",
    )
    return AuditedAcknowledgment(
        ack=ack,
        signature=sign_acknowledgment(ack, signer),
        raw_data=canonical_ack_payload(ack),
    )


def _audit(dataset: AuditDataset, resolvers, *, epoch: str | None = EPOCH):
    return run_audit(
        dataset,
        record_key_resolver=resolvers,
        signing_epoch=epoch,
        now=NOW if epoch is not None else None,
    )


@pytest.mark.parametrize("record_type", ALL_RECORD_TYPES)
@pytest.mark.parametrize("ts", TS_AROUND_EPOCH)
def test_with_the_epoch_set_an_unsigned_record_is_a_finding_whatever_its_type_or_ts(
    ts, record_type, roles
):
    """No record excuses itself. A ts before the epoch used to exempt an
    unsigned record, and that field is written by whoever wrote the row."""
    _issuer, _evaluator, resolvers = roles
    record = _record(record_type, ts=ts)

    report = _audit(_dataset([record]), resolvers)

    assert [v.detail for v in _signature_findings(report)] == [_unsigned_detail(record)]
    assert report.acknowledged == ()
    # Nothing is reported as exempt, because nothing is.
    assert report.annotations == ()


@pytest.mark.parametrize("record_type", ALL_RECORD_TYPES)
@pytest.mark.parametrize("ts", [BEFORE_EPOCH, AFTER_EPOCH], ids=["before-epoch", "after-epoch"])
def test_correctly_signed_records_of_every_type_verify_on_either_side_of_the_epoch(
    ts, record_type, roles
):
    issuer_signer, evaluator_signer, resolvers = roles
    report = _audit(
        _dataset(
            [_record(record_type, ts=ts)],
            signed_by=lambda r: _signer_for(r.recordType, issuer_signer, evaluator_signer),
        ),
        resolvers,
    )

    assert not _signature_findings(report)
    assert report.annotations == ()


@pytest.mark.parametrize(
    "honest_ledger,hidden_rule",
    [(True, LEVEL_LEDGER_CONSISTENT), (False, LEDGER_COUNTERPART)],
    ids=["over-level-grant", "orphan-grant"],
)
def test_a_planted_unsigned_pre_epoch_bootstrap_cannot_launder_a_grant(
    honest_ledger, hidden_rule, roles
):
    """The attack this rule was changed for. A party with write access to
    RECORD# rows and NO key plants an unsigned bootstrap to out-of-loop and
    dates it before the epoch. It used to count as exempt history, its toLevel
    became the ledger-derived level, and a grant at out-of-loop audited clean.
    """
    issuer_signer, _evaluator, resolvers = roles
    grant = AuditedGrant(grant=_grant(level="out-of-loop", lastSafeLevel="in-loop"))
    honest = (
        [_entry(_record("bootstrap", ts="2026-05-01T00:00:00+00:00"), issuer_signer)]
        if honest_ledger
        else []
    )
    planted = _record("bootstrap", ts=BEFORE_EPOCH, toLevel="out-of-loop")

    without_plant = _audit(AuditDataset(grants=(grant,), records=tuple(honest)), resolvers)
    assert {v.rule for v in without_plant.violations} == {hidden_rule}

    report = _audit(
        AuditDataset(grants=(grant,), records=(*honest, _entry(planted))), resolvers
    )

    # The plant still hides the grant-level finding, since the derived level is
    # read off the ledger as it stands. What it can no longer do is pass.
    assert [(v.rule, v.detail) for v in report.violations] == [
        (RECORD_SIGNATURE_VERIFIES, _unsigned_detail(planted))
    ]
    assert report.acknowledged == ()


# Same coordinate, same type, same ts, different stored bytes: what a writer
# with no key can put in place of a record somebody acknowledged.
REPLACEMENTS = [
    pytest.param(record_type, EPOCH, {"evidence": "rewritten-after-acknowledgment"}, id=record_type)
    for record_type in ALL_RECORD_TYPES
] + [
    pytest.param("bootstrap", EPOCH, {"toLevel": "out-of-loop"}, id="bootstrap-raised"),
    # With no epoch only a promotion is in scope, and the binding holds there too.
    pytest.param("promotion", None, {"toLevel": "out-of-loop"}, id="promotion-raised-epoch-unset"),
]


@pytest.mark.parametrize("record_type,epoch,rewrite", REPLACEMENTS)
def test_an_acknowledgment_excuses_the_stored_bytes_it_was_made_for_and_no_others(
    record_type, epoch, rewrite, roles
):
    """Honest unsigned history is excused one record at a time, by a signed
    acknowledgment. The finding names the sha256 of the stored bytes, so the
    acknowledgment follows those bytes and not the slot they sit in."""
    issuer_signer, _evaluator, resolvers = roles
    record = _record(record_type, ts=BEFORE_EPOCH)
    (finding,) = _signature_findings(_audit(_dataset([record]), resolvers, epoch=epoch))
    ack = _acknowledgment(finding, issuer_signer)

    excused = _audit(
        AuditDataset(records=(_entry(record),), acknowledgments=(ack,)), resolvers, epoch=epoch
    )
    assert not _signature_findings(excused)
    assert [a.violation for a in excused.acknowledged] == [finding]

    replaced = _record(record_type, ts=BEFORE_EPOCH, **rewrite)
    assert (replaced.recordType, replaced.ts) == (record.recordType, record.ts)
    after = _audit(
        AuditDataset(records=(_entry(replaced),), acknowledgments=(ack,)), resolvers, epoch=epoch
    )
    assert [v.detail for v in _signature_findings(after)] == [_unsigned_detail(replaced)]
    assert after.acknowledged == ()


def test_an_acknowledgment_signed_by_the_evaluator_excuses_nothing(roles):
    """A waiver mints green, so it is the issuer's to sign. The automatic side
    cannot excuse an unsigned record any more than it can sign a promotion."""
    _issuer, evaluator_signer, resolvers = roles
    record = _record("tightening", ts=BEFORE_EPOCH)
    (finding,) = _signature_findings(_audit(_dataset([record]), resolvers))

    report = _audit(
        AuditDataset(
            records=(_entry(record),),
            acknowledgments=(_acknowledgment(finding, evaluator_signer),),
        ),
        resolvers,
    )

    assert {v.rule for v in report.violations} == {
        RECORD_SIGNATURE_VERIFIES,
        ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    }
    assert report.acknowledged == ()


@pytest.mark.parametrize(
    "bad_signature",
    ["stranger-key", "not-a-dsse-envelope"],
    ids=["unknown-signer", "mangled-signature-attribute"],
)
def test_an_acknowledged_signature_failure_is_bound_to_its_stored_bytes_too(
    bad_signature, roles
):
    """The same replacement, against a record that carries a signature which
    fails. The failure reason is reproducible without a key (a stranger's key,
    or a junk attribute), so the reason alone cannot identify the record."""
    issuer_signer, _evaluator, resolvers = roles
    stranger, _pem = _keypair("issuer:retired")

    def entry(record: PromotionRecord) -> AuditedRecord:
        if bad_signature == "stranger-key":
            return _entry(record, stranger)
        return AuditedRecord(
            record=record, signature=bad_signature, raw_data=canonical_record_payload(record)
        )

    record = _record("promotion", ts=AFTER_EPOCH)
    (finding,) = _signature_findings(_audit(AuditDataset(records=(entry(record),)), resolvers))
    assert "failed signature verification" in finding.detail
    ack = _acknowledgment(finding, issuer_signer)

    excused = _audit(
        AuditDataset(records=(entry(record),), acknowledgments=(ack,)), resolvers
    )
    assert [a.violation for a in excused.acknowledged] == [finding]

    replaced = _record("promotion", ts=AFTER_EPOCH, toLevel="out-of-loop")
    after = _audit(
        AuditDataset(records=(entry(replaced),), acknowledgments=(ack,)), resolvers
    )
    (new_finding,) = _signature_findings(after)
    assert stored_record_digest_hex(canonical_record_payload(replaced)) in new_finding.detail
    assert after.acknowledged == ()


@pytest.mark.parametrize("signed", [False, True], ids=["unsigned", "signed"])
def test_an_entry_with_no_stored_bytes_is_a_finding_no_acknowledgment_excuses(signed, roles):
    """With no stored bytes there is nothing for a signature to verify against
    and nothing for an acknowledgment to bind, so the finding stands."""
    issuer_signer, _evaluator, resolvers = roles
    record = _record("bootstrap", ts=BEFORE_EPOCH)
    entry = AuditedRecord(
        record=record,
        signature=issuer_signer.sign_record(record) if signed else None,
        raw_data=None,
    )
    (finding,) = _signature_findings(_audit(AuditDataset(records=(entry,)), resolvers))
    assert "has no stored bytes" in finding.detail
    assert "sha256:" not in finding.detail

    report = _audit(
        AuditDataset(
            records=(entry,), acknowledgments=(_acknowledgment(finding, issuer_signer),)
        ),
        resolvers,
    )

    assert _signature_findings(report) == [finding]
    assert report.acknowledged == ()


@pytest.mark.parametrize(
    "record_type,expect_finding",
    [
        ("promotion", True),
        ("bootstrap", False),
        ("tightening", False),
        ("demotion", False),
        ("lapse", False),
        ("reattestation", False),
    ],
)
def test_with_no_epoch_the_narrower_scope_holds_and_says_so(record_type, expect_finding, roles):
    """Unset keeps the narrower scope: an unsigned promotion is a finding and
    the other unsigned types are not. The report must SAY the all-types
    requirement is unenforced. Silence here is the failure mode: a green audit
    that never checked."""
    _issuer, _evaluator, resolvers = roles
    report = _audit(
        _dataset([_record(record_type, ts="2026-09-01T00:00:00+00:00")]), resolvers, epoch=None
    )

    assert bool(_signature_findings(report)) is expect_finding
    (annotation,) = report.annotations
    assert annotation.startswith(ANNOTATION_SIGNING_EPOCH_UNSET)


@pytest.mark.parametrize("record_type", ["lapse", "reattestation"])
def test_with_no_epoch_a_signature_that_is_carried_must_still_verify(record_type, roles):
    """Checked-if-present: the narrower scope never meant a wrong-role
    signature passes. For a reattestation that is the evaluator's key on a
    record that re-licenses a grant."""
    issuer_signer, evaluator_signer, resolvers = roles
    wrong = issuer_signer if record_type == "lapse" else evaluator_signer
    report = _audit(
        _dataset([_record(record_type)], signed_by=lambda _r: wrong), resolvers, epoch=None
    )

    findings = _signature_findings(report)
    assert len(findings) == 1, (
        f"with no signing epoch, a {record_type} record that carries a signature must "
        f"still be verified under its type's role; got {len(findings)} finding(s) for "
        "one signed by the other role's key"
    )
    assert RECORD_SIGNER_WRONG_ROLE in findings[0].detail


FUTURE_EPOCH = "2027-01-01T00:00:00+00:00"


@pytest.mark.parametrize(
    "ts",
    [BEFORE_EPOCH, "2026-07-15T00:00:00+00:00", "2027-06-01T00:00:00+00:00"],
    ids=["before-now", "between-now-and-epoch", "after-the-future-epoch"],
)
def test_an_epoch_in_the_future_is_a_violation_and_narrows_nothing(ts, roles):
    """A future epoch names an adoption that has not happened. It is reported,
    and every record is checked as if the epoch were in force: a misconfigured
    epoch must never buy a quieter audit. The comparison is against the
    SUPPLIED instant, never against the ledger's own timestamps, which is why
    one case dates its record after the future epoch."""
    _issuer, _evaluator, resolvers = roles
    record = _record("tightening", ts=ts)

    report = _audit(_dataset([record]), resolvers, epoch=FUTURE_EPOCH)

    (epoch_finding,) = [v for v in report.violations if v.rule == RECORD_SIGNING_EPOCH_VALID]
    assert FUTURE_EPOCH in epoch_finding.detail
    assert NOW.isoformat() in epoch_finding.detail
    assert [v.detail for v in _signature_findings(report)] == [_unsigned_detail(record)]


def test_a_future_epoch_stays_a_violation_when_every_record_is_signed(roles):
    """The epoch finding stands on its own. It is un-waivable, so the report
    stays red until the configuration is corrected."""
    issuer_signer, _evaluator, resolvers = roles
    report = _audit(
        _dataset([_record("tightening")], signed_by=lambda _r: issuer_signer),
        resolvers,
        epoch=FUTURE_EPOCH,
    )

    assert [v.rule for v in report.violations] == [RECORD_SIGNING_EPOCH_VALID]


@pytest.mark.parametrize(
    "epoch_form,expect_future",
    [
        # NOW is 2026-08-01T00:00:00+00:00. Each spelling is judged by the
        # instant it names: the first reads later than NOW as text and is an
        # hour EARLIER, the second reads earlier and is half an hour LATER.
        ("2026-08-01T01:00:00+02:00", False),
        ("2026-07-31T23:30:00-01:00", True),
        ("2026-08-01T00:00:00Z", False),
        ("2026-08-01T00:00:01Z", True),
    ],
    ids=["offset-earlier-instant", "offset-later-instant", "equal-to-now", "second-after-now"],
)
def test_the_epoch_is_judged_by_the_instant_it_names_not_its_spelling(
    epoch_form, expect_future, roles
):
    issuer_signer, _evaluator, resolvers = roles
    report = _audit(
        _dataset([_record("tightening")], signed_by=lambda _r: issuer_signer),
        resolvers,
        epoch=epoch_form,
    )

    assert (RECORD_SIGNING_EPOCH_VALID in {v.rule for v in report.violations}) is expect_future


# The SAME instant, spelled three legal ISO-8601 ways. Only the first is the
# ledger's canonical form (store.validate_record_ts); an operator's env is under
# no such guard, so all three must land on identical verdicts.
EQUIVALENT_EPOCHS = [
    pytest.param("2026-07-01T00:00:00+00:00", id="canonical"),
    pytest.param("2026-07-01T00:00:00Z", id="zulu"),
    pytest.param("2026-07-01T02:00:00+02:00", id="non-utc-offset"),
]


@pytest.mark.parametrize("epoch_form", EQUIVALENT_EPOCHS)
@pytest.mark.parametrize("ts", TS_AROUND_EPOCH)
def test_no_spelling_of_the_epoch_excuses_an_unsigned_record(epoch_form, ts, roles):
    """The audit once compared each record's ts to the epoch as text, and a
    'Z' or offset spelling moved the boundary. No such comparison is left, so
    every spelling gives the one verdict on both sides of the instant."""
    _issuer, _evaluator, resolvers = roles
    report = _audit(_dataset([_record("tightening", ts=ts)]), resolvers, epoch=epoch_form)

    assert len(_signature_findings(report)) == 1


@pytest.mark.parametrize(
    "epoch_form",
    ["2027-01-01T00:00:00+00:00", "2027-01-01T00:00:00Z", "2027-01-01T02:00:00+02:00"],
    ids=["canonical", "zulu", "non-utc-offset"],
)
def test_a_non_canonical_epoch_is_reported_in_both_forms(epoch_form, roles):
    """An epoch silently reinterpreted is a different instant from the one the
    operator meant, so the finding shows what their value normalized to
    whenever it differs from what they typed."""
    _issuer, _evaluator, resolvers = roles

    report = _audit(_dataset([_record("promotion")]), resolvers, epoch=epoch_form)

    (finding,) = [v for v in report.violations if v.rule == RECORD_SIGNING_EPOCH_VALID]
    assert FUTURE_EPOCH in finding.detail
    assert epoch_form in finding.detail


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
