"""Promotion-record DSSE signing conformance (lifecycle Phase 4, adopts #181).

Proves the pure `record_signing` module: sign → verify round-trips, and every
forgery mode fails closed with its own reason — a tampered record field, a
signature borrowed from a different record, an unknown signer, an attribution
splice, wrong DSSE/statement type constants, and malformed envelopes (which
must never raise). Key resolution is out of scope here (it belongs to the
ceremony command-side binding, mirroring channels.keys).
"""

from __future__ import annotations

import base64
import copy
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.grants.record_signing import (
    canonical_record_payload,
    RECORD_PREDICATE_TYPE,
    RECORD_SIGNATURE_INVALID,
    RECORD_SIGNATURE_MALFORMED,
    RECORD_SIGNATURE_MISSING,
    RECORD_SIGNER_UNKNOWN,
    RecordSigner,
    signer_from_pem,
    verify_record,
)
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.promotion_record import PromotionRecord
from safe_agents.channels.keys import key_resolver_from_map

_TS = "2026-07-12T00:00:00+00:00"

PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")


def make_record(**overrides) -> PromotionRecord:
    defaults = dict(
        recordType="promotion",
        actionClass="email.send",
        principal=PRINCIPAL,
        fromLevel=AutonomyLevel.in_loop,
        toLevel=AutonomyLevel.on_loop,
        evidence="s3://evidence/email.send/2026-07-12",
        predicate="error_prob*blast_radius < 0.01 over 30d",
        proposedBy="model:proposer",
        ratifiedBy="human:maintainer",
        envelopeHash="sha256:abc123",
        ts=_TS,
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


# ---------------------------------------------------------------------------
# Key + signer fixtures
# ---------------------------------------------------------------------------


def _keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 key."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        sk.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    return priv, pub


@pytest.fixture
def signer_and_resolver():
    priv, pub = _keypair()
    signer = signer_from_pem("issuer:A", "zone-a", priv)
    resolver = key_resolver_from_map({"issuer:A": pub})
    return signer, resolver


# ---------------------------------------------------------------------------
# Round trip + audit-index predicate fields
# ---------------------------------------------------------------------------


def test_sign_verify_round_trip(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    assert verify_record(canonical_record_payload(record), envelope, resolver).ok


def test_envelope_is_json_serializable_with_index_fields_in_clear(signer_and_resolver):
    signer, _ = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    # Storable as-is beside the ledger item's record blob.
    statement = json.loads(base64.b64decode(json.loads(json.dumps(envelope))["payload"]))
    assert statement["predicateType"] == RECORD_PREDICATE_TYPE
    assert statement["predicate"]["signer"] == {"key_id": "issuer:A", "zone": "zone-a"}
    # An auditor indexes who/what/when/under-which-envelope without parsing the record.
    assert statement["predicate"]["record"] == {
        "recordType": "promotion",
        "ts": _TS,
        "actionClass": "email.send",
        "proposedBy": "model:proposer",
        "ratifiedBy": "human:maintainer",
        "envelopeHash": "sha256:abc123",
    }


# ---------------------------------------------------------------------------
# Forgery modes — each fails closed with its own reason
# ---------------------------------------------------------------------------


def test_tampered_record_field_fails_closed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    # The level change is escalated post-signing: the stored record no longer
    # matches the signed subject digest.
    escalated = record.model_copy(update={"toLevel": AutonomyLevel.out_of_loop})
    result = verify_record(canonical_record_payload(escalated), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


def test_signature_borrowed_from_different_record_rejected(signer_and_resolver):
    signer, resolver = signer_and_resolver
    other = make_record(actionClass="ledger.append")
    envelope = signer.sign_record(other)  # validly signed — but for OTHER
    result = verify_record(canonical_record_payload(make_record()), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


def test_unknown_keyid_quarantines(signer_and_resolver):
    signer, _ = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    result = verify_record(canonical_record_payload(record), envelope, lambda key_id: None)
    assert not result.ok and result.reason == RECORD_SIGNER_UNKNOWN


def test_wrong_payload_type_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    envelope["payloadType"] = "application/json"
    result = verify_record(canonical_record_payload(record), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


@pytest.mark.parametrize("field", ["_type", "predicateType"])
def test_wrong_statement_type_constants_invalid(signer_and_resolver, field):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement[field] = "https://example.com/other/v1"
    envelope["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    result = verify_record(canonical_record_payload(record), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


def test_keyid_signer_splice_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    priv_b, pub_b = _keypair()
    signer_b = signer_from_pem("issuer:B", "zone-b", priv_b)
    record = make_record()
    envelope = signer.sign_record(record)
    # Splice B's (valid, resolvable) signature under A's statement: the
    # signature's keyid no longer matches predicate.signer.key_id.
    envelope["signatures"] = signer_b.sign_record(record)["signatures"]
    resolver_both = key_resolver_from_map(
        {"issuer:B": pub_b}
    )  # B resolves; the splice must still fail on attribution, not resolution
    result = verify_record(canonical_record_payload(record), envelope, resolver_both)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


def test_empty_or_absent_signatures_missing(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    for sigs in ([], None):
        broken = dict(envelope, signatures=sigs)
        result = verify_record(canonical_record_payload(record), broken, resolver)
        assert not result.ok and result.reason == RECORD_SIGNATURE_MISSING
    no_key = {k: v for k, v in envelope.items() if k != "signatures"}
    result = verify_record(canonical_record_payload(record), no_key, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_MISSING


@pytest.mark.parametrize(
    "mutate",
    [
        lambda env: "not-a-dict",
        lambda env: {k: v for k, v in env.items() if k != "payload"},
        lambda env: dict(env, payload="!!not-base64!!"),
        lambda env: dict(env, payload=base64.b64encode(b"not json").decode()),
        lambda env: dict(env, payload=base64.b64encode(b'"a json string"').decode()),
        lambda env: dict(env, signatures=["not-a-dict"]),
        lambda env: dict(env, signatures=[{"keyid": "issuer:A"}]),  # no sig
        lambda env: dict(env, signatures=[{"sig": env["signatures"][0]["sig"]}]),  # no keyid
        lambda env: dict(env, signatures={"keyid": "issuer:A"}),  # not a list
    ],
    ids=[
        "non-dict-envelope",
        "missing-payload",
        "bad-b64-payload",
        "payload-not-json",
        "payload-not-object",
        "signature-not-dict",
        "signature-missing-sig",
        "signature-missing-keyid",
        "signatures-not-list",
    ],
)
def test_malformed_envelope_never_raises(signer_and_resolver, mutate):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    broken = mutate(copy.deepcopy(envelope))
    result = verify_record(canonical_record_payload(record), broken, resolver)
    assert not result.ok
    assert result.reason == RECORD_SIGNATURE_MALFORMED


def test_statement_missing_subject_or_signer_malformed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    for missing in ("subject", "predicate"):
        broken_statement = {k: v for k, v in statement.items() if k != missing}
        broken = dict(
            envelope,
            payload=base64.b64encode(
                json.dumps(broken_statement, sort_keys=True, separators=(",", ":")).encode()
            ).decode(),
        )
        result = verify_record(canonical_record_payload(record), broken, resolver)
        assert not result.ok and result.reason == RECORD_SIGNATURE_MALFORMED


def test_bad_signature_bytes_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    envelope["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
    result = verify_record(canonical_record_payload(record), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


def test_multi_signature_one_bad_fails(signer_and_resolver):
    signer, resolver = signer_and_resolver
    record = make_record()
    envelope = signer.sign_record(record)
    good = envelope["signatures"][0]
    forged = dict(good, sig=base64.b64encode(b"\x01" * 64).decode())
    # A valid signature does not excuse a forged one riding alongside it.
    envelope["signatures"] = [good, forged]
    result = verify_record(canonical_record_payload(record), envelope, resolver)
    assert not result.ok and result.reason == RECORD_SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# The issuer key is injected — the module has no ambient key path
# ---------------------------------------------------------------------------


def test_signer_is_key_injected_pure():
    import inspect

    from safe_agents.broker.grants import record_signing

    # No env/secret reads anywhere in the module: keys arrive only via the
    # injected RecordSigner / resolver (cold-start resolution is the ceremony
    # command's job, mirroring channels.keys).
    source = inspect.getsource(record_signing)
    assert "os.environ" not in source
    assert "boto3" not in source
    params = inspect.signature(RecordSigner.sign_record).parameters
    assert set(params) == {"self", "record"}
