"""The signed standing document (GAL §6.10, GAL-41, #179): shape, signature, succession.

What this file pins, in four groups:

  document     states and reason codes are RFC 5280's names, each state carries
               exactly its own fields, and there is no hold state
  signature    a document is accepted only under a standing-authority key, over
               the payload bytes as carried, for the role it names
  succession   what may follow an accepted document: a higher version, no key
               rebound, no state moved backward, no withdrawal dropped, no
               standing-authority key listed
  records      a withdrawn key's records verify as record_signer_withdrawn
               whatever their ts and whichever reason; a retired key's verify

Source loading, age and the env contract are in test_key_standing_source.py.
"""

from __future__ import annotations

import base64
import datetime
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from safe_agents.broker.grants import key_standing as ks
from safe_agents.broker.grants.record_signing import (
    ISSUER_ROLE,
    RECORD_SIGNATURE_INVALID,
    RECORD_SIGNER_WITHDRAWN,
    RoleKeyResolvers,
    canonical_record_payload,
    signer_from_pem,
    verify_record_by_type,
)
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.channels.keys import key_resolver_from_map

T0 = datetime.datetime(2026, 10, 1, tzinfo=datetime.UTC)


def keypair(key_id: str, zone: str = "zone-test"):
    """(RecordSigner, public PEM) for a fresh Ed25519 key."""
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return signer_from_pem(key_id, zone, private_pem), public_pem


@pytest.fixture
def world():
    """A standing authority, two issuer keys, and a version-1 issuer document."""
    authority, authority_pem = keypair("authority-1")
    issuer_a, issuer_a_pem = keypair("issuer-a")
    issuer_b, issuer_b_pem = keypair("issuer-b")
    keys = ks.add_key({}, "issuer-a", issuer_a_pem)
    keys = ks.add_key(keys, "issuer-b", issuer_b_pem)
    v1 = ks.next_document(None, role=ISSUER_ROLE, keys=keys, issued_at=T0, signer=authority)
    return {
        "authority": authority,
        "authority_pem": authority_pem,
        "resolver": key_resolver_from_map({"authority-1": authority_pem}),
        "issuer_a": issuer_a,
        "issuer_b": issuer_b,
        "issuer_a_pem": issuer_a_pem,
        "v1": v1,
    }


def entry(state: str, pem: str, **fields) -> dict:
    return {"publicKey": pem, "state": state, **fields}


# ---------------------------------------------------------------------------
# Document shape
# ---------------------------------------------------------------------------

AT = "2026-10-02T00:00:00+00:00"
LATER = "2026-10-03T00:00:00+00:00"


@pytest.mark.parametrize(
    ("state", "fields", "ok"),
    [
        ("active", {}, True),
        ("active", {"retiredAt": AT, "retiredReason": "superseded"}, False),
        ("retired", {"retiredAt": AT, "retiredReason": "superseded"}, True),
        ("retired", {"retiredAt": AT, "retiredReason": "cessationOfOperation"}, True),
        ("retired", {"retiredAt": AT}, False),
        ("retired", {"retiredAt": AT, "retiredReason": "keyCompromise"}, False),
        ("withdrawn", {"withdrawnAt": AT, "withdrawnReason": "keyCompromise"}, True),
        ("withdrawn", {"withdrawnAt": AT, "withdrawnReason": "privilegeWithdrawn"}, True),
        ("withdrawn", {"withdrawnAt": AT, "withdrawnReason": "superseded"}, False),
        (
            "withdrawn",
            {"retiredAt": AT, "retiredReason": "superseded", "withdrawnAt": LATER,
             "withdrawnReason": "keyCompromise"},
            True,
        ),
        (
            "withdrawn",
            {"retiredAt": LATER, "retiredReason": "superseded", "withdrawnAt": AT,
             "withdrawnReason": "keyCompromise"},
            False,
        ),
        ("withdrawn", {"withdrawnAt": "2026-10-02T00:00:00", "withdrawnReason": "keyCompromise"},
         False),
        ("hold", {}, False),
        ("certificateHold", {}, False),
    ],
)
def test_each_state_carries_exactly_its_own_fields(state, fields, ok, world):
    data = entry(state, world["issuer_a_pem"], **fields)
    if ok:
        assert ks.KeyStandingEntry.model_validate(data).state == state
    else:
        with pytest.raises(ValidationError):
            ks.KeyStandingEntry.model_validate(data)


def test_the_vocabulary_is_rfc_5280s_and_has_no_hold():
    assert ks.RETIRED_REASONS == ("superseded", "cessationOfOperation")
    assert ks.WITHDRAWN_REASONS == ("keyCompromise", "privilegeWithdrawn")
    assert ks.KEY_WITHDRAWN == "withdrawn"


def test_every_field_dumps_null_or_not(world):
    """Pre-release structure rule: no omit-when-off serializer."""
    payload = json.loads(ks.canonical_standing_bytes(world["v1"]))
    assert set(payload["keys"]["issuer-a"]) == {
        "publicKey", "state", "retiredAt", "retiredReason", "withdrawnAt", "withdrawnReason"
    }
    assert set(payload) == {"role", "version", "issuedAt", "signer", "keys"}


# ---------------------------------------------------------------------------
# Signature: verify the carried bytes, then parse them
# ---------------------------------------------------------------------------


def test_a_signed_document_verifies_and_its_digest_binds_the_payload(world):
    text = ks.sign_standing_document(world["v1"], world["authority"])
    document, digest = ks.verify_standing_envelope(text, authority=world["resolver"], role="issuer")
    assert document == world["v1"]
    payload = base64.b64decode(json.loads(text)["payload"])
    assert payload == ks.canonical_standing_bytes(world["v1"])
    import hashlib

    assert digest == hashlib.sha256(payload).hexdigest()


def _tamper(text: str, how: str, world) -> str:
    envelope = json.loads(text)
    if how == "unsigned":
        envelope["signatures"] = []
    elif how == "payload":
        payload = json.loads(base64.b64decode(envelope["payload"]))
        payload["keys"]["issuer-a"]["state"] = "active"
        payload["version"] = 99
        envelope["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    elif how == "relabel":
        envelope["signatures"][0]["keyid"] = "authority-2"
    elif how == "two_signatures":
        envelope["signatures"].append(dict(envelope["signatures"][0]))
    elif how == "payload_type":
        envelope["payloadType"] = "application/vnd.in-toto+json"
    elif how == "not_json":
        return text[:-3]
    return json.dumps(envelope)


@pytest.mark.parametrize(
    ("how", "verdict"),
    [
        ("unsigned", ks.STANDING_SIGNATURE_INVALID),
        ("payload", ks.STANDING_SIGNATURE_INVALID),
        ("relabel", ks.STANDING_SIGNER_UNKNOWN),
        ("two_signatures", ks.STANDING_SIGNATURE_INVALID),
        ("payload_type", ks.STANDING_MALFORMED),
        ("not_json", ks.STANDING_MALFORMED),
    ],
)
def test_an_unsigned_or_altered_document_is_refused(how, verdict, world):
    text = _tamper(ks.sign_standing_document(world["v1"], world["authority"]), how, world)
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.verify_standing_envelope(text, authority=world["resolver"], role="issuer")
    assert caught.value.verdict == verdict


def test_a_document_signed_by_an_issuer_key_is_refused(world):
    """Only the third role's keys sign standing. An issuer key, even a known one, does not."""
    v1 = world["v1"].model_copy(
        update={"signer": ks.StandingSigner(keyId="issuer-a", zone="zone-test")}
    )
    text = ks.sign_standing_document(v1, world["issuer_a"])
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.verify_standing_envelope(text, authority=world["resolver"], role="issuer")
    assert caught.value.verdict == ks.STANDING_SIGNER_UNKNOWN


def test_an_issuer_document_is_refused_as_the_evaluator_document(world):
    text = ks.sign_standing_document(world["v1"], world["authority"])
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.verify_standing_envelope(text, authority=world["resolver"], role="evaluator")
    assert caught.value.verdict == ks.STANDING_WRONG_ROLE


def test_a_signer_field_naming_another_key_is_refused(world):
    other, other_pem = keypair("authority-2")
    resolver = key_resolver_from_map(
        {"authority-1": world["authority_pem"], "authority-2": other_pem}
    )
    forged = world["v1"].model_copy(
        update={"signer": ks.StandingSigner(keyId="authority-2", zone="zone-test")}
    )
    payload = ks.canonical_standing_bytes(forged)
    sig = world["authority"].sign_pae(ks.pae(ks.STANDING_PAYLOAD_TYPE, payload))
    text = json.dumps({
        "payloadType": ks.STANDING_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": "authority-1", "sig": base64.b64encode(sig).decode()}],
    })
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.verify_standing_envelope(text, authority=resolver, role="issuer")
    assert caught.value.verdict == ks.STANDING_SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# Succession
# ---------------------------------------------------------------------------


def _next(previous, keys, world, *, version=None, issued_at=T0):
    document = ks.KeyStandingDocument(
        role="issuer",
        version=version if version is not None else previous.version + 1,
        issuedAt=ks.format_standing_instant(issued_at),
        signer=previous.signer,
        keys=keys,
    )
    return document


def test_one_way_transitions_are_accepted(world):
    v1 = world["v1"]
    retired = ks.retire_key(v1.keys, "issuer-a", "superseded", T0)
    v2 = _next(v1, retired, world)
    ks.check_successor(v1, v2, {})
    withdrawn = ks.withdraw_key(retired, "issuer-a", "keyCompromise", T0)
    v3 = _next(v2, withdrawn, world)
    ks.check_successor(v2, v3, {})
    assert v3.keys["issuer-a"].retiredReason == "superseded"


@pytest.mark.parametrize("version", [1, 0])
def test_a_rollback_is_refused(version, world):
    v1 = world["v1"]
    if version == 0:
        with pytest.raises(ValidationError):
            _next(v1, dict(v1.keys), world, version=0)
        return
    same_version = _next(v1, dict(v1.keys), world, version=1, issued_at=T0 + datetime.timedelta(1))
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.check_successor(v1, same_version, {})
    assert caught.value.verdict == ks.STANDING_ROLLBACK


def _backward(world):
    v1 = world["v1"]
    retired = ks.retire_key(v1.keys, "issuer-a", "superseded", T0)
    withdrawn = ks.withdraw_key(v1.keys, "issuer-a", "keyCompromise", T0)
    return v1, retired, withdrawn


@pytest.mark.parametrize(
    ("before", "after", "verdict"),
    [
        ("retired", "active", ks.STANDING_TRANSITION_REFUSED),
        ("withdrawn", "active", ks.STANDING_TRANSITION_REFUSED),
        ("withdrawn", "retired", ks.STANDING_TRANSITION_REFUSED),
        ("retired", "retired_redated", ks.STANDING_TRANSITION_REFUSED),
        ("withdrawn", "withdrawn_other_reason", ks.STANDING_TRANSITION_REFUSED),
        ("active", "rebound", ks.STANDING_KEY_REBOUND),
    ],
)
def test_backward_moves_and_edits_are_refused(before, after, verdict, world):
    v1, retired, withdrawn = _backward(world)
    _, other_pem = keypair("other")
    pem = world["issuer_a_pem"]
    states = {
        "active": dict(v1.keys),
        "retired": retired,
        "withdrawn": withdrawn,
        "retired_redated": {**retired, "issuer-a": ks.KeyStandingEntry(
            publicKey=pem, state="retired", retiredAt=LATER, retiredReason="superseded")},
        "withdrawn_other_reason": {**withdrawn, "issuer-a": ks.KeyStandingEntry(
            publicKey=pem, state="withdrawn", withdrawnAt=withdrawn["issuer-a"].withdrawnAt,
            withdrawnReason="privilegeWithdrawn")},
        "rebound": {**v1.keys, "issuer-a": ks.KeyStandingEntry(publicKey=other_pem, state="active")},
    }
    accepted = _next(v1, states[before], world)
    candidate = _next(accepted, states[after], world)
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.check_successor(accepted, candidate, {})
    assert caught.value.verdict == verdict


def test_a_document_lacking_a_seen_withdrawal_is_refused_whatever_its_version(world):
    """Withdrawal is terminal, so a document without one already seen is a rollback by inspection."""
    v1, _, withdrawn = _backward(world)
    seen = {"issuer-a": withdrawn["issuer-a"]}
    dropped = {k: v for k, v in withdrawn.items() if k != "issuer-a"}
    candidate = _next(v1, dropped, world, version=50)
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.check_successor(None, candidate, seen)
    assert caught.value.verdict == ks.STANDING_WITHDRAWAL_DROPPED


def test_a_document_listing_a_standing_authority_key_is_refused(world):
    keys = ks.add_key(world["v1"].keys, "sneaky", world["authority_pem"])
    candidate = _next(world["v1"], keys, world)
    raw = ks.public_key_raw(world["authority_pem"])
    with pytest.raises(ks.StandingDocumentRefused) as caught:
        ks.check_authority_not_listed(candidate, frozenset({"authority-1"}), frozenset({raw}))
    assert caught.value.verdict == ks.STANDING_AUTHORITY_KEY_LISTED


@pytest.mark.parametrize(
    ("op", "key_id", "reason"),
    [
        ("retire", "issuer-a", "keyCompromise"),
        ("withdraw", "issuer-a", "superseded"),
        ("retire", "nobody", "superseded"),
        ("add", "issuer-a", None),
        ("retire_twice", "issuer-a", "superseded"),
        ("withdraw_twice", "issuer-a", "keyCompromise"),
        ("readd_withdrawn", "issuer-a", None),
        ("readd_withdrawn_bytes_new_id", "issuer-a2", None),
        ("add_listed_bytes_new_id", "issuer-a2", None),
    ],
)
def test_the_ceremony_transitions_refuse_what_the_rules_forbid(op, key_id, reason, world):
    keys = world["v1"].keys
    pem = world["issuer_a_pem"]
    with pytest.raises(ks.StandingTransitionError):
        if op == "retire":
            ks.retire_key(keys, key_id, reason, T0)
        elif op == "withdraw":
            ks.withdraw_key(keys, key_id, reason, T0)
        elif op == "add":
            ks.add_key(keys, key_id, pem)
        elif op == "retire_twice":
            ks.retire_key(ks.retire_key(keys, key_id, reason, T0), key_id, reason, T0)
        elif op == "withdraw_twice":
            ks.withdraw_key(ks.withdraw_key(keys, key_id, reason, T0), key_id, reason, T0)
        elif op == "readd_withdrawn":
            ks.add_key(ks.withdraw_key(keys, key_id, "keyCompromise", T0), key_id, pem)
        elif op == "readd_withdrawn_bytes_new_id":
            ks.add_key(ks.withdraw_key(keys, "issuer-a", "keyCompromise", T0), key_id, pem)
        else:
            ks.add_key(keys, key_id, pem)


def test_one_public_key_under_two_key_ids_is_refused_by_verifier_and_successor_check(world):
    withdrawn = ks.withdraw_key(world["v1"].keys, "issuer-a", "keyCompromise", T0)
    renamed = ks.KeyStandingEntry(publicKey=world["issuer_a_pem"], state="active")
    doubled = ks.KeyStandingDocument(
        role=ISSUER_ROLE, version=2, issuedAt="2026-10-01T01:00:00+00:00",
        signer=ks.StandingSigner(keyId="authority-1", zone="zone-test"),
        keys={**withdrawn, "issuer-a2": renamed},
    )
    for refuse in (
        lambda: ks.verify_standing_envelope(
            ks.sign_standing_document(doubled, world["authority"]),
            authority=world["resolver"], role=ISSUER_ROLE,
        ),
        lambda: ks.check_successor(world["v1"], doubled, {}),
    ):
        with pytest.raises(ks.StandingDocumentRefused) as caught:
            refuse()
        assert caught.value.verdict == ks.STANDING_KEY_DUPLICATED


# ---------------------------------------------------------------------------
# Records: withdrawn voids whatever the ts; retired keeps verifying
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-standing", skill="email", user="alice", tier="B")


def _promotion(ts: str) -> PromotionRecord:
    return PromotionRecord(
        principal=PRINCIPAL, actionClass="email.send", recordType="promotion",
        fromLevel="in-loop", toLevel="on-loop", evidence="evidence://x", predicate="passed",
        proposedBy="arn:maker", ratifiedBy="arn:checker", envelopeHash="sha256:e", ts=ts,
    )


class _States:
    def __init__(self, states):
        self.states = states

    def key_state(self, key_id):
        return self.states.get(key_id)


@pytest.mark.parametrize(
    ("state", "ts", "expect"),
    [
        ("active", "2026-09-01T00:00:00+00:00", None),
        ("retired", "2026-09-01T00:00:00+00:00", None),
        ("withdrawn", "2026-09-01T00:00:00+00:00", RECORD_SIGNER_WITHDRAWN),
        ("withdrawn", "2020-01-01T00:00:00+00:00", RECORD_SIGNER_WITHDRAWN),
        ("withdrawn", "2030-01-01T00:00:00+00:00", RECORD_SIGNER_WITHDRAWN),
    ],
)
def test_a_withdrawn_keys_records_fail_whatever_their_ts_and_a_retired_keys_verify(
    state, ts, expect, world
):
    record = _promotion(ts)
    stored = canonical_record_payload(record)
    envelope = world["issuer_a"].sign_record(record)
    resolvers = RoleKeyResolvers(
        issuer=key_resolver_from_map({"issuer-a": world["issuer_a_pem"]}),
        standing={ISSUER_ROLE: _States({"issuer-a": state})},
    )
    result = verify_record_by_type(stored, envelope, record_type="promotion", resolvers=resolvers)
    assert (result.ok, result.reason, result.key_id) == (
        expect is None, expect, "issuer-a"
    )


@pytest.mark.parametrize("reason", ks.WITHDRAWN_REASONS)
def test_both_withdrawal_reasons_void_records_signed_before_the_withdrawal(reason, world):
    """GAL-41 ruling 8: a withdrawal voids every record the key signed, for either reason."""
    keys = ks.withdraw_key(world["v1"].keys, "issuer-a", reason, T0)
    record = _promotion("2026-01-01T00:00:00+00:00")  # long before withdrawnAt
    lookup = _States({k: e.state for k, e in keys.items()})
    result = verify_record_by_type(
        canonical_record_payload(record),
        world["issuer_a"].sign_record(record),
        record_type="promotion",
        resolvers=RoleKeyResolvers(
            issuer=key_resolver_from_map({"issuer-a": world["issuer_a_pem"]}),
            standing={ISSUER_ROLE: lookup},
        ),
    )
    assert result.reason == RECORD_SIGNER_WITHDRAWN


def test_a_tampered_record_by_a_withdrawn_key_reads_as_a_signature_failure(world):
    record = _promotion("2026-09-01T00:00:00+00:00")
    stored = canonical_record_payload(record).replace("on-loop", "out-of-loop")
    resolvers = RoleKeyResolvers(
        issuer=key_resolver_from_map({"issuer-a": world["issuer_a_pem"]}),
        standing={ISSUER_ROLE: _States({"issuer-a": "withdrawn"})},
    )
    result = verify_record_by_type(
        stored, world["issuer_a"].sign_record(record), record_type="promotion", resolvers=resolvers
    )
    assert (result.reason, result.key_id) == (RECORD_SIGNATURE_INVALID, None)


def test_without_standing_records_verify_as_they_always_did(world):
    record = _promotion("2026-09-01T00:00:00+00:00")
    result = verify_record_by_type(
        canonical_record_payload(record),
        world["issuer_a"].sign_record(record),
        record_type="promotion",
        resolvers=RoleKeyResolvers(issuer=key_resolver_from_map({"issuer-a": world["issuer_a_pem"]})),
    )
    assert (result.ok, result.key_id) == (True, "issuer-a")
