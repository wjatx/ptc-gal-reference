"""A lapse record carries the term that expired: its stored and signed bytes.

#165; GAL §5.2, §6.7.6.

L3: a lapse record with no `certifiedUntil` parses, verifies, passes the
store's guard and is not an audit finding. L4: a lapse record written and
signed before the field was allowed keeps its bytes and its signature. L6: the
field is inside what the evaluator signs.

The clause table and the shared harness are in lapse_term_scaffold.py.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from safe_agents.broker.grants.audit import (
    RECORD_SIGNATURE_VERIFIES,
    AuditDataset,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.lapse import apply_lapse, build_lapse
from safe_agents.broker.grants.record_signing import (
    RoleKeyResolvers,
    build_record_statement,
    canonical_record_payload,
    signer_from_pem,
    stored_record_digest_hex,
    verify_record_by_type,
)
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.tests import lapse_term_scaffold as harness
from safe_agents.broker.tests import test_grant_term_lapse as base
from safe_agents.broker.tests.lapse_term_scaffold import (
    _SHAPES,
    LATER_TERM,
    _lapses,
    _seeded,
    _typed,
)
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    AFTER,
    HMAC_KEY,
    PRINCIPAL,
    TERM,
    _grant,
)
from safe_agents.channels.keys import key_resolver_from_map

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
stores = harness.stores


# ===========================================================================
# L3 and L4 — absence is accepted, and no stored byte moved
# ===========================================================================

# Produced by the code BEFORE the field was allowed on a lapse record (672b316):
# build_lapse, canonical_record_payload and RecordSigner.sign_record, with the
# deterministic Ed25519 key derived from bytes(range(32, 64)) below. Ed25519
# signing is deterministic, so the current code must reproduce these exact
# bytes and this exact signature for a lapse record that carries no term.
_LEGACY_LAPSE_PAYLOAD = (
    '{"actionClass":"email.send","attestation":null,"demotionReason":"pending-evidence",'
    '"envelopeHash":"sha256:env-legacy","evidence":"certification term expired: '
    'certifiedUntil=2026-08-01T01:00:00+00:00","fromLevel":"on-loop","predicate":null,'
    '"principal":{"agentId":"legacy-agent","skill":"mail","tier":"B","user":"ops"},'
    '"proposedBy":"system:demotion-evaluator","ratifiedBy":"system:demotion-evaluator",'
    '"recordType":"lapse","toLevel":"in-loop","triggeredBy":[],'
    '"ts":"2026-08-31T01:00:00+00:00"}'
)
_LEGACY_LAPSE_ENVELOPE = {
    "payloadType": "application/vnd.in-toto+json",
    "payload": (
        "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGUiOnsicmVjb3JkIjp7"
        "ImFjdGlvbkNsYXNzIjoiZW1haWwuc2VuZCIsImVudmVsb3BlSGFzaCI6InNoYTI1NjplbnYtbGVnYWN5IiwicHJv"
        "cG9zZWRCeSI6InN5c3RlbTpkZW1vdGlvbi1ldmFsdWF0b3IiLCJyYXRpZmllZEJ5Ijoic3lzdGVtOmRlbW90aW9u"
        "LWV2YWx1YXRvciIsInJlY29yZFR5cGUiOiJsYXBzZSIsInRzIjoiMjAyNi0wOC0zMVQwMTowMDowMCswMDowMCJ9"
        "LCJzaWduZXIiOnsia2V5X2lkIjoiZXZhbHVhdG9yOmxlZ2FjeSIsInpvbmUiOiJ6b25lLWxlZ2FjeSJ9fSwicHJl"
        "ZGljYXRlVHlwZSI6Imh0dHBzOi8vc2FmZS1hZ2VudHMuZGV2L3Byb21vdGlvbi1yZWNvcmQvdjEiLCJzdWJqZWN0"
        "IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiNTM0ODUzZGMzMDNkMTFjYjAwYzA0MmMxYzcyM2U3OTNkZjI5NjFhNzk3"
        "Y2M1OTk5NWY1MDkyMWE2OTRlZWEzMSJ9LCJuYW1lIjoicHJvbW90aW9uLXJlY29yZCJ9XX0="
    ),
    "signatures": [
        {
            "keyid": "evaluator:legacy",
            "sig": "y0axojFwCXjYjGSb5Oi+EFGedqvHuakh+oQYIsqgyYFaqC4O5dLDCScnpKRdOA9MWnX4Gf8Lh4sH7sCzKAmJAw==",
        }
    ],
}


def _legacy_evaluator():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    resolvers = RoleKeyResolvers(
        issuer=key_resolver_from_map({}),
        evaluator=key_resolver_from_map({"evaluator:legacy": public_pem}),
    )
    return signer_from_pem("evaluator:legacy", "zone-legacy", private_pem), resolvers


def _parse_legacy(invariant: str) -> PromotionRecord:
    try:
        return PromotionRecord.model_validate_json(_LEGACY_LAPSE_PAYLOAD)
    except ValidationError as exc:
        pytest.fail(
            f"{invariant}: a lapse record written before the field was allowed must "
            f"still parse, and the schema refused it: {exc}"
        )


class TestL3AbsenceAccepted:
    def test_a_lapse_record_without_the_field_parses_and_verifies(self):
        _, resolvers = _legacy_evaluator()
        record = _parse_legacy("L3 ABSENCE ACCEPTED")
        assert record.recordType == "lapse" and record.certifiedUntil is None, (
            "L3 ABSENCE ACCEPTED: a lapse record written before the field was allowed "
            "must parse, with certifiedUntil None"
        )
        result = verify_record_by_type(
            _LEGACY_LAPSE_PAYLOAD, _LEGACY_LAPSE_ENVELOPE, record_type="lapse", resolvers=resolvers
        )
        assert result.ok, (
            "L3 ABSENCE ACCEPTED: a signed lapse record without certifiedUntil must "
            f"still verify under the evaluator role, got {result.reason}"
        )

    def test_the_store_guard_accepts_a_lapse_record_without_it(self, stores):
        grant = _grant()
        grant_store, record_store = _seeded(stores, grant)
        read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
        updated, record = build_lapse(grant, AFTER)
        bare = record.model_copy(update={"certifiedUntil": None})
        try:
            grant_store.write_record_and_grant(bare, updated, record_store, expected=read)
        except Exception as exc:
            pytest.fail(
                "L3 ABSENCE ACCEPTED: the field is optional, so a lapse write whose "
                f"record carries none must be accepted, got {type(exc).__name__}: {exc}"
            )
        assert [r.certifiedUntil for r in _lapses(record_store)] == [None]

    def test_a_lapse_record_without_it_is_not_an_audit_finding(self):
        issuer_signer, evaluator_signer, resolvers = base._role_signers()
        grant = _grant()
        grant_store, record_store = base._stores_with(grant, issuer_signer)
        read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
        updated, record = build_lapse(grant, AFTER)
        bare = record.model_copy(update={"certifiedUntil": None})
        grant_store.write_record_and_grant(
            bare, updated, record_store, signature=evaluator_signer.sign_record(bare), expected=read
        )
        report = run_audit(
            base._dataset_from_stores(grant_store, record_store),
            hmac_key=HMAC_KEY,
            record_key_resolver=resolvers,
        )
        assert report.violations == (), (
            "L3 ABSENCE ACCEPTED: a lapse record lacking certifiedUntil must not be an "
            f"audit finding, got {[(v.rule, v.detail) for v in report.violations]}"
        )


class TestL4NoStoredBytesChange:
    def test_a_legacy_lapse_record_keeps_its_bytes_and_its_signature(self):
        signer, _ = _legacy_evaluator()
        record = _parse_legacy("L4 NO STORED BYTES CHANGE")
        assert canonical_record_payload(record) == _LEGACY_LAPSE_PAYLOAD, (
            "L4 NO STORED BYTES CHANGE: a lapse record with no certifiedUntil must "
            "serialize to the bytes the pre-field code stored"
        )
        assert signer.sign_record(record) == _LEGACY_LAPSE_ENVELOPE, (
            "L4 NO STORED BYTES CHANGE: signing a lapse record with no certifiedUntil "
            "must reproduce the pre-field signature"
        )

    @pytest.mark.parametrize("record_type", sorted(_SHAPES))
    def test_a_null_term_is_omitted_for_every_record_type(self, record_type):
        payload = json.loads(canonical_record_payload(PromotionRecord(**_typed(record_type))))
        assert "certifiedUntil" not in payload, (
            f"L4 NO STORED BYTES CHANGE: a {record_type} record with a null "
            "certifiedUntil must omit the key from its canonical form"
        )

    def test_carrying_the_term_adds_one_key_and_changes_nothing_else(self):
        _, record = build_lapse(_grant(), AFTER)
        carried = json.loads(canonical_record_payload(record))
        bare = json.loads(
            canonical_record_payload(record.model_copy(update={"certifiedUntil": None}))
        )
        assert carried == {**bare, "certifiedUntil": TERM}, (
            "L4 NO STORED BYTES CHANGE: carrying the term must add the certifiedUntil "
            "key to the canonical form and move no other field"
        )


# ===========================================================================
# L6 — the term is inside what the evaluator signs
# ===========================================================================

_FIELD = f'"certifiedUntil":"{TERM}"'


def test_L6_the_term_is_inside_the_digest_the_signature_binds():
    """The mechanism under the tamper test below, asserted on its own. The
    signed statement's subject is a digest of the record's canonical bytes, and
    verification digests the stored bytes verbatim. A digest that left the term
    out, on either side, would make two lapse records differing only in their
    term indistinguishable to the signature."""
    _, record = build_lapse(_grant(), AFTER)
    signed, at_rest = {}, {}
    for term in (TERM, LATER_TERM, None):
        variant = record.model_copy(update={"certifiedUntil": term})
        statement = json.loads(build_record_statement(variant, key_id="k", zone="z"))
        signed[term] = statement["subject"][0]["digest"]["sha256"]
        at_rest[term] = stored_record_digest_hex(canonical_record_payload(variant))
    assert len(set(signed.values())) == 3, (
        "L6 BOUND BY THE SIGNATURE: the digest the evaluator signs must cover "
        "certifiedUntil, and lapse records that differ only in their term (two "
        f"terms, and none) signed to {len(set(signed.values()))} distinct digest(s)"
    )
    assert len(set(at_rest.values())) == 3, (
        "L6 BOUND BY THE SIGNATURE: the digest verification takes of a stored lapse "
        "record must cover certifiedUntil, and stored bytes that differ only in the "
        f"term digested to {len(set(at_rest.values()))} distinct value(s)"
    )
    assert signed == at_rest, (
        "L6 BOUND BY THE SIGNATURE: signing and verification must digest the same "
        "bytes of a lapse record, certifiedUntil included"
    )


@pytest.mark.parametrize(
    "tamper",
    [
        lambda raw: raw.replace(_FIELD, f'"certifiedUntil":"{LATER_TERM}"'),
        lambda raw: raw.replace(_FIELD + ",", ""),
    ],
    ids=["term-changed", "term-removed"],
)
def test_L6_tampering_with_a_signed_lapse_records_term_fails_verification(tamper):
    issuer_signer, evaluator_signer, resolvers = base._role_signers()
    grant_store, record_store = base._stores_with(_grant(), issuer_signer)
    _, record = apply_lapse(
        _grant(), store=grant_store, record_store=record_store, now=AFTER,
        record_signer=evaluator_signer,
    )
    stored = record_store.stored_data_for(record)
    envelope = record_store.signature_for(record)
    assert _FIELD in stored, (
        "L6 BOUND BY THE SIGNATURE: the bytes the evaluator signs must contain the "
        "lapse record's certifiedUntil"
    )
    assert verify_record_by_type(
        stored, envelope, record_type="lapse", resolvers=resolvers
    ).ok, "L6 BOUND BY THE SIGNATURE: the untouched signed lapse record must verify"

    tampered = tamper(stored)
    # The edit touched the field and nothing else: the evidence string, which
    # also names the term, is byte for byte what was signed.
    assert tampered != stored and json.loads(tampered)["evidence"] == record.evidence
    assert not verify_record_by_type(
        tampered, envelope, record_type="lapse", resolvers=resolvers
    ).ok, (
        "L6 BOUND BY THE SIGNATURE: a stored lapse record whose certifiedUntil was "
        "changed or removed after signing must fail verification"
    )

    dataset = base._dataset_from_stores(grant_store, record_store)
    forged = tuple(
        AuditedRecord(record=e.record, signature=e.signature, raw_data=tampered)
        if e.record.recordType == "lapse"
        else e
        for e in dataset.records
    )
    report = run_audit(
        AuditDataset(
            grants=dataset.grants, records=forged, proposals=(), envelopes=(),
            acknowledgments=(), parse_violations=(),
        ),
        hmac_key=HMAC_KEY,
        record_key_resolver=resolvers,
    )
    assert RECORD_SIGNATURE_VERIFIES in {v.rule for v in report.violations}, (
        "L6 BOUND BY THE SIGNATURE: the audit must report a lapse record whose "
        "certifiedUntil was altered at rest"
    )

