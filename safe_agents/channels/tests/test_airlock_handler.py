"""The Lambda handler end-to-end against hand-rolled AWS fakes.

Drives the whole binding (manifest → secrets → build_airlock → dispatch → SQS)
with fakes injected through the handler's boto3 seam factories. Proves the
200-always response discipline, the accepted-envelope enqueue, silent drops,
replay dedupe, and that the handler never raises.
"""

import base64
import json
import logging
from types import SimpleNamespace

import pytest

import safe_agents.channels.airlock.handler as h
from safe_agents.channels import keys as keys_mod
from safe_agents.channels.manifest import UNCONFIGURED_ZONE
from safe_agents.channels.publish import stamp_outbound
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.schemas.event_trigger import MAX_ENVELOPE_BYTES, MAX_FORWARD_BYTES
from safe_agents.channels.signing import ChainSigner

_TOKEN = "test-airlock-token"  # peer:example's own token
_STRANGER_TOKEN = "test-stranger-token"  # an authenticated peer the trust map does not map
# The webhook token secret as stored: one entry per peer.
_WEBHOOK_SECRET = json.dumps({"peer:example": _TOKEN, "peer:stranger": _STRANGER_TOKEN})
_TS = "2026-07-08T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"
# The airlock's own zone, as its manifest below declares it.
_ZONE = "example-airlock"
# What `zone` defaulted to before it became required. No airlock answers to it now.
_RETIRED_DEFAULT_ZONE = "channels"

_MANIFEST_YAML = f"""\
zone: {_ZONE}
adapter:
  channel_type: webhook
  token_header: x-airlock-token
trust_map:
  - channel_type: webhook
    channel_identity: peer:example
    principal: example-agent
    sender_class: peer-agent
verdict_sink: false
dedupe_ttl_days: 30
"""


class _FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeDynamoClient:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def get_item(self, *, TableName, Key, ConsistentRead=False):
        pk = Key["dedupe_pk"]["S"]
        return {"Item": self.items[pk]} if pk in self.items else {}

    def put_item(self, *, TableName, Item, ConditionExpression=None):
        pk = Item["dedupe_pk"]["S"]
        if ConditionExpression and "attribute_not_exists" in ConditionExpression and pk in self.items:
            raise _FakeClientError("ConditionalCheckFailedException")
        self.items[pk] = Item


class FakeS3Client:
    def __init__(self) -> None:
        self.puts: list[dict] = []

    def put_object(self, *, Bucket, Key, Body, ContentType=None):
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType})


class FakeSqsClient:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def send_message(self, *, QueueUrl, MessageBody):
        self.messages.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})


@pytest.fixture
def wired(monkeypatch, tmp_path):
    manifest_path = tmp_path / "channels-manifest.yaml"
    manifest_path.write_text(_MANIFEST_YAML, encoding="utf-8")

    monkeypatch.setenv("CHANNELS_MANIFEST", str(manifest_path))
    monkeypatch.setenv("CHANNELS_DEDUPE_TABLE", "dedupe-table")
    monkeypatch.setenv("CHANNELS_DROP_BUCKET", "drop-bucket")
    monkeypatch.setenv("CHANNELS_ACCEPTED_QUEUE_URL", "https://sqs.example/accepted")
    monkeypatch.setenv("CHANNELS_WEBHOOK_SECRET_ARN", "arn:aws:secretsmanager:::secret/webhook")

    fakes = SimpleNamespace(dynamo=FakeDynamoClient(), s3=FakeS3Client(), sqs=FakeSqsClient())
    monkeypatch.setattr(h, "_dynamodb_client", lambda: fakes.dynamo)
    monkeypatch.setattr(h, "_s3_client", lambda: fakes.s3)
    monkeypatch.setattr(h, "_sqs_client", lambda: fakes.sqs)
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: _WEBHOOK_SECRET)
    monkeypatch.setattr(h, "_STATE", None)

    yield fakes

    h._STATE = None


def _envelope_json(event_id: str = "evt-1", *, audience: str = _ZONE) -> str:
    return json.dumps(
        {
            "event_id": event_id,
            "principal": "example-agent",
            "audience": audience,
            "sender": {
                "channel_type": "webhook",
                "channel_identity": "peer:example",
                "evidence": ["sig:pass"],
            },
            "payload": {"msg": "hello"},
            "provenance": [
                {"zone": "peer", "source": "peer:example", "evidence": [], "label": "trusted", "ts": _TS}
            ],
            "ts": _TS,
            "expiry": _FUTURE,
        }
    )


def _event(body: str, *, token: str | None = _TOKEN, base64_encoded: bool = False) -> dict:
    headers = {} if token is None else {"x-airlock-token": token}
    payload = base64.b64encode(body.encode()).decode() if base64_encoded else body
    return {
        "requestContext": {"http": {"method": "POST"}},
        "headers": headers,
        "body": payload,
        "isBase64Encoded": base64_encoded,
    }


def test_valid_request_enqueues_stamped_envelope(wired):
    resp = h.handler(_event(_envelope_json()), None)

    assert resp["statusCode"] == 200
    assert json.loads(resp["body"]) == {"ok": True}
    assert len(wired.sqs.messages) == 1

    stamped = EventTrigger.model_validate_json(wired.sqs.messages[0]["MessageBody"])
    assert stamped.principal == "example-agent"
    assert stamped.sender_class == "peer-agent"  # set from the trust-map resolution
    assert len(stamped.provenance) == 2  # peer origin hop + the receiver's own stamp
    assert stamped.provenance[-1].zone == _ZONE


def test_base64_body_is_decoded_and_accepted(wired):
    resp = h.handler(_event(_envelope_json(), base64_encoded=True), None)
    assert resp["statusCode"] == 200
    assert len(wired.sqs.messages) == 1


@pytest.mark.parametrize(
    "token",
    [pytest.param("wrong-token", id="wrong"), pytest.param("\ud800x", id="lone-surrogate")],
)
def test_bad_token_drops_silently_without_enqueue(wired, token):
    # A lone surrogate cannot be encoded for the compare; it must fail gate 1
    # as `authenticity_failed`, not escape as a handler error.
    resp = h.handler(_event(_envelope_json(), token=token), None)

    assert resp["statusCode"] == 200
    assert json.loads(resp["body"]) == {"ok": True}  # silent to the sender
    assert wired.sqs.messages == []

    assert len(wired.s3.puts) == 1
    drop = wired.s3.puts[0]
    assert drop["Key"].startswith("channels/drops/")
    record = json.loads(drop["Body"])
    assert record["reason"] == "authenticity_failed"


def test_replay_enqueues_only_once(wired):
    event = _event(_envelope_json(event_id="evt-replay"))

    first = h.handler(event, None)
    second = h.handler(event, None)

    assert first["statusCode"] == 200
    assert second["statusCode"] == 200
    assert len(wired.sqs.messages) == 1  # the replay dedupes, no second enqueue


def test_unmapped_sender_drops_without_enqueue(wired):
    body = json.loads(_envelope_json())
    body["sender"]["channel_identity"] = "peer:stranger"
    body["principal"] = "example-agent"

    resp = h.handler(_event(json.dumps(body), token=_STRANGER_TOKEN), None)

    assert resp["statusCode"] == 200
    assert wired.sqs.messages == []
    assert json.loads(wired.s3.puts[0]["Body"])["reason"] == "unmapped"


def test_empty_event_returns_200_without_raising(wired):
    resp = h.handler({}, None)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"]) == {"ok": True}
    assert wired.sqs.messages == []


def test_handler_swallows_internal_errors(wired):
    def _boom(**kwargs):
        raise RuntimeError("sqs is down")

    wired.sqs.send_message = _boom

    resp = h.handler(_event(_envelope_json()), None)
    assert resp["statusCode"] == 200  # 200-always even when a seam raises


def test_replay_with_different_identity_casing_still_dedupes(wired):
    # A mapped sender must not mint a fresh dedupe key by re-spelling its own
    # identity: "Peer:Example" and "peer:example" carrying the same event_id
    # are one signal, enqueued once.
    cased = json.loads(_envelope_json(event_id="evt-case"))
    cased["sender"]["channel_identity"] = "Peer:Example"

    first = h.handler(_event(json.dumps(cased)), None)
    second = h.handler(_event(_envelope_json(event_id="evt-case")), None)

    assert first["statusCode"] == 200
    assert second["statusCode"] == 200
    assert len(wired.sqs.messages) == 1


def test_undecodable_body_drops_malformed_without_enqueue(wired):
    # Valid base64 of invalid UTF-8: the decode fails before dispatch, and the
    # airlock records a `malformed` drop rather than silently returning 200.
    event = _event(_envelope_json())
    event["body"] = base64.b64encode(b"\xff\xfe\xfd").decode()
    event["isBase64Encoded"] = True

    resp = h.handler(event, None)

    assert resp["statusCode"] == 200
    assert wired.sqs.messages == []
    assert json.loads(wired.s3.puts[0]["Body"])["reason"] == "malformed"


# ---------------------------------------------------------------------------
# Chain verification and the wire form, through the real handler
# ---------------------------------------------------------------------------


def _drop_reasons(wired) -> list[tuple[str, str | None]]:
    records = [json.loads(put["Body"]) for put in wired.s3.puts]
    return [(r["reason"], r.get("detail")) for r in records if "reason" in r]


def _outbound(
    signer=None, *, payload=None, evidence=None, event_id="evt-1", audience=_ZONE
) -> EventTrigger:
    return stamp_outbound(
        zone="zone-a",
        agent_identity="example",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=False,
        event_id=event_id,
        principal="example-agent",
        audience=audience,
        payload=payload or {"msg": "hello"},
        ts=_TS,
        expiry=_FUTURE,
        evidence=evidence,
        signer=signer,
    )


@pytest.fixture
def verifying(wired, monkeypatch):
    """The handler with BROKER_VERIFY_KEYS_SECRET_ARN set and one peer enrolled."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    entry = {
        "public_key": pub,
        "zone": "zone-a",
        "sender_identities": ["peer:example"],
        "signer_posture": 2,
        "custody_evidence": "declared",
    }
    monkeypatch.setenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, "arn:verify")
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:A": entry}))
    monkeypatch.setattr(h, "_STATE", None)
    return wired, ChainSigner(key_id="broker:A", zone="zone-a", _private_key=key)


def test_handler_with_verification_on_accepts_signed_and_drops_unsigned(verifying):
    wired, signer = verifying

    h.handler(_event(_outbound().to_wire()), None)  # unsigned
    assert wired.sqs.messages == []
    assert _drop_reasons(wired) == [("chain_signature_missing", None)]

    h.handler(_event(_outbound(signer).to_wire()), None)
    assert len(wired.sqs.messages) == 1
    stamped = EventTrigger.model_validate_json(wired.sqs.messages[0]["MessageBody"])
    assert stamped.provenance[-1].evidence == ["token:pass", "sig:pass", "custody:declared"]


def test_a_forged_copy_does_not_shadow_the_genuine_message(verifying):
    """A failed verification must not claim the dedupe key: the forged copy
    arrives first, and the genuine one with the same event id still lands."""
    wired, signer = verifying
    genuine = _outbound(signer)
    forged = json.loads(genuine.to_wire())
    forged["payload"] = {"msg": "something else"}

    h.handler(_event(json.dumps(forged)), None)
    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    assert _drop_reasons(wired) == [("chain_signature_invalid", None)]

    h.handler(_event(genuine.to_wire()), None)
    assert len(wired.sqs.messages) == 1


def test_a_request_addressed_to_another_airlock_enqueues_nothing(wired):
    resp = h.handler(_event(_envelope_json(audience="another-airlock")), None)

    assert resp["statusCode"] == 200  # silent to the sender, like every drop
    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    assert _drop_reasons(wired) == [("audience_mismatch", None)]
    # It claimed no dedupe key: the same event id addressed here is delivered.
    h.handler(_event(_envelope_json()), None)
    assert len(wired.sqs.messages) == 1


@pytest.mark.parametrize(
    "audience,reason",
    [
        pytest.param(UNCONFIGURED_ZONE, "unmapped", id="addressed to the placeholder zone"),
        pytest.param(_ZONE, "audience_mismatch", id="addressed to a configured zone"),
        pytest.param(_RETIRED_DEFAULT_ZONE, "audience_mismatch", id="addressed to the old default"),
    ],
)
def test_an_airlock_with_no_manifest_drops_everything(wired, monkeypatch, audience, reason):
    """`CHANNELS_MANIFEST` unset is a supported deploy. It runs as the placeholder
    zone with an empty trust map, so even an envelope that names it is dropped."""
    monkeypatch.delenv("CHANNELS_MANIFEST")

    resp = h.handler(_event(_envelope_json(audience=audience)), None)

    assert resp["statusCode"] == 200
    assert h._STATE.airlock.zone == UNCONFIGURED_ZONE
    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    assert _drop_reasons(wired) == [(reason, None)]


def test_a_configured_manifest_that_names_no_zone_accepts_nothing(
    wired, monkeypatch, tmp_path, caplog
):
    """A manifest that is configured never inherits a zone it did not name: not
    the placeholder, and not the old default. It fails to load, and the handler
    answers 200 with nothing accepted."""
    zoneless = tmp_path / "zoneless.yaml"
    zoneless.write_text(_MANIFEST_YAML.replace(f"zone: {_ZONE}\n", ""), encoding="utf-8")
    monkeypatch.setenv("CHANNELS_MANIFEST", str(zoneless))

    for audience in (_RETIRED_DEFAULT_ZONE, UNCONFIGURED_ZONE, _ZONE):
        assert h.handler(_event(_envelope_json(audience=audience)), None)["statusCode"] == 200

    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    assert h._STATE is None
    assert "sets no `zone`" in caplog.text


def test_an_envelope_signed_for_another_airlock_is_dropped_unverified(verifying):
    """Verification ON, the signer enrolled, the signature genuine. The record
    names no signer: the envelope was never this airlock's to verify."""
    wired, signer = verifying

    h.handler(_event(_outbound(signer, audience="another-airlock").to_wire()), None)

    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    records = [json.loads(put["Body"]) for put in wired.s3.puts]
    assert [(r["reason"], r["chain_verified"], r["signer_key_id"]) for r in records] == [
        ("audience_mismatch", False, None)
    ]
    # The signer's envelope for THIS airlock, same event id, is accepted.
    h.handler(_event(_outbound(signer).to_wire()), None)
    assert len(wired.sqs.messages) == 1


def test_the_forwarded_body_is_the_wire_form(wired):
    h.handler(_event(_outbound(payload={"note": "café \uffff"}).to_wire()), None)
    body = wired.sqs.messages[0]["MessageBody"]
    assert body.isascii()
    assert EventTrigger.model_validate_json(body).to_wire(max_bytes=MAX_FORWARD_BYTES) == body


def _padded_to(size: int) -> EventTrigger:
    # The evidence string lands on the sender claim and on the hop: two bytes a character.
    base = len(_outbound(evidence=[""]).to_wire())
    odd = (size - base) % 2
    envelope = _outbound(evidence=["x" * ((size - base) // 2)], event_id="evt-1" + "y" * odd)
    assert len(envelope.to_wire(max_bytes=None)) == size
    return envelope


def test_an_envelope_at_the_inbound_ceiling_is_forwarded_and_one_past_it_is_dropped(wired):
    """The receiver's stamp makes an accepted envelope larger. The forward has
    its own, higher ceiling so that what gate 3 accepts always goes through."""
    h.handler(_event(_padded_to(MAX_ENVELOPE_BYTES).to_wire()), None)
    assert len(wired.sqs.messages) == 1
    forwarded = len(wired.sqs.messages[0]["MessageBody"])
    assert MAX_ENVELOPE_BYTES < forwarded <= MAX_FORWARD_BYTES

    wired.sqs.messages.clear()
    wired.dynamo.items.clear()
    # A sender cannot stamp one this large, so it is built past stamp_outbound.
    # One more character on whatever event id the padding settled on, so the size
    # is one past the ceiling whichever way `_padded_to` rounded.
    at_ceiling = _padded_to(MAX_ENVELOPE_BYTES)
    over = at_ceiling.model_copy(update={"event_id": at_ceiling.event_id + "z"})
    assert len(over.to_wire(max_bytes=None)) == MAX_ENVELOPE_BYTES + 1
    h.handler(_event(over.to_wire(max_bytes=None)), None)
    assert wired.sqs.messages == [] and wired.dynamo.items == {}
    assert _drop_reasons(wired)[-1] == ("malformed", "not_forwardable")


# ---------------------------------------------------------------------------
# What the sender is told (channels/ADAPTERS.md §"What the sender is told")
# ---------------------------------------------------------------------------

# The three bodies, as the exact bytes a sender reads.
_UNIFORM = '{"ok": true}'
_PERMANENT = '{"ok": false, "refusal": "permanent"}'
_TRANSIENT = '{"ok": false, "refusal": "transient"}'


def _install_screen(screen) -> None:
    """Give the cached airlock a screen; the manifest-built one ships OFF."""
    from dataclasses import replace

    state = h._get_state()
    h._STATE = replace(state, airlock=replace(state.airlock, screen=screen))


def _stranger_json(event_id: str = "evt-1", **fields) -> str:
    body = json.loads(_envelope_json(event_id))
    body["sender"]["channel_identity"] = "peer:stranger"
    body.update(fields)
    return json.dumps(body)


def _mapped_json(event_id: str = "evt-1", **fields) -> str:
    body = json.loads(_envelope_json(event_id))
    body.update(fields)
    return json.dumps(body)


def _drops(wired) -> list[tuple[str, str | None]]:
    records = [
        json.loads(put["Body"]) for put in wired.s3.puts if put["Key"].startswith("channels/drops/")
    ]
    return [(r["reason"], r.get("detail")) for r in records]


def test_every_path_that_tells_nothing_answers_the_same_bytes(wired):
    """Acceptance, screen refusal, screen_error, replay, a gate-1 failure, an
    unmapped peer's unparseable body, an unmapped identity, an unmapped peer
    claiming a mapped identity, an undecodable body, a non-POST and an
    unexpected exception: one status, one body, byte for byte. (Gate 2 reads
    the identity from the token, so it cannot fail after gate 1 passes.)"""
    responses = {}

    responses["accepted"] = h.handler(_event(_envelope_json("evt-ok")), None)
    responses["replay"] = h.handler(_event(_envelope_json("evt-ok")), None)
    responses["authenticity failed"] = h.handler(
        _event(_envelope_json("evt-tok"), token="wrong-token"), None
    )
    responses["unmapped, not json"] = h.handler(_event("not json", token=_STRANGER_TOKEN), None)
    responses["unmapped"] = h.handler(
        _event(_stranger_json("evt-stranger"), token=_STRANGER_TOKEN), None
    )
    responses["claims a mapped identity"] = h.handler(
        _event(_envelope_json("evt-claim"), token=_STRANGER_TOKEN), None
    )
    undecodable = _event("")
    undecodable["body"] = base64.b64encode(b"\xff\xfe").decode()
    undecodable["isBase64Encoded"] = True
    responses["undecodable"] = h.handler(undecodable, None)
    get = _event(_envelope_json("evt-get"))
    get["requestContext"]["http"]["method"] = "GET"
    responses["not a POST"] = h.handler(get, None)

    _install_screen(lambda envelope: False)
    responses["screen refused"] = h.handler(_event(_envelope_json("evt-refused")), None)

    def crashing_screen(envelope):
        raise RuntimeError("classifier down")

    _install_screen(crashing_screen)
    responses["screen error"] = h.handler(_event(_envelope_json("evt-crash")), None)

    _install_screen(None)
    wired.sqs.send_message = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("sqs down"))
    responses["handler error"] = h.handler(_event(_envelope_json("evt-sqs")), None)

    assert {name: (r["statusCode"], r["body"]) for name, r in responses.items()} == {
        name: (200, _UNIFORM) for name in responses
    }
    # The screen refusals were dedupe-marked like any handled message.
    assert ("screen_refused", None) in _drops(wired)
    assert ("screen_refused", "screen_error") in _drops(wired)
    assert len(wired.dynamo.items) == 4  # evt-ok, evt-refused, evt-crash, evt-sqs


_EXPIRED_TS = "2000-01-01T00:00:00+00:00"


@pytest.mark.parametrize(
    "body,reason",
    [
        pytest.param(
            lambda make: json.dumps({**json.loads(make()), "payload": "not an object"}),
            ("malformed", None),
            id="malformed",
        ),
        pytest.param(
            lambda make: make(audience="another-airlock"),
            ("audience_mismatch", None),
            id="audience-mismatch",
        ),
        pytest.param(
            lambda make: make(ts=_EXPIRED_TS, expiry=_EXPIRED_TS),
            ("expired", None),
            id="expired",
        ),
        pytest.param(
            lambda make: make(principal="another-agent"),
            ("principal_mismatch", None),
            id="principal-mismatch",
        ),
    ],
)
def test_a_pre_screen_refusal_is_permanent_toward_a_mapped_sender_only(wired, body, reason):
    mapped = h.handler(_event(body(_mapped_json)), None)
    assert (mapped["statusCode"], mapped["body"]) == (200, _PERMANENT)

    stranger = h.handler(_event(body(_stranger_json), token=_STRANGER_TOKEN), None)
    assert (stranger["statusCode"], stranger["body"]) == (200, _UNIFORM)

    expected_stranger = ("unmapped", None) if reason[0] == "principal_mismatch" else reason
    assert _drops(wired) == [reason, expected_stranger]
    assert wired.sqs.messages == [] and wired.dynamo.items == {}


def test_a_chain_refusal_is_permanent_toward_a_mapped_sender(verifying):
    wired, signer = verifying
    genuine = _outbound(signer)
    forged = json.loads(genuine.to_wire())
    forged["payload"] = {"msg": "something else"}
    unknown = ChainSigner(key_id="broker:Z", zone="zone-a", _private_key=signer._private_key)

    bodies = [
        h.handler(_event(_outbound().to_wire()), None)["body"],
        h.handler(_event(json.dumps(forged)), None)["body"],
        h.handler(_event(_outbound(unknown).to_wire()), None)["body"],
    ]

    assert bodies == [_PERMANENT] * 3
    assert [reason for reason, _ in _drops(wired)] == [
        "chain_signature_missing",
        "chain_signature_invalid",
        "chain_signer_unknown",
    ]


# --- the verification-key source ------------------------------------------------


@pytest.fixture
def keys_down(verifying, monkeypatch):
    """Verification configured, and the keys secret unreachable until `up` is set."""
    wired, signer = verifying
    entry_json = keys_mod._fetch_secret("arn:verify")
    source = SimpleNamespace(up=False, fetches=0)

    def fetch(arn):
        source.fetches += 1
        if not source.up:
            raise ConnectionError("secrets manager unreachable")
        return entry_json

    monkeypatch.setattr(keys_mod, "_fetch_secret", fetch)
    monkeypatch.setattr(h, "_STATE", None)
    return wired, signer, source


def test_an_unavailable_key_source_is_transient_and_retried_until_it_answers(keys_down):
    wired, signer, source = keys_down
    message = _event(_outbound(signer).to_wire())

    first = h.handler(message, None)
    assert (first["statusCode"], first["body"]) == (200, _TRANSIENT)
    assert source.fetches == 2  # the cold start, then this request
    assert _drops(wired) == [("not_evaluated", "key_source")]
    assert wired.dynamo.items == {} and wired.sqs.messages == []

    assert h.handler(message, None)["body"] == _TRANSIENT
    assert source.fetches == 3  # fetched again: a failure is never cached

    source.up = True
    retried = h.handler(message, None)
    # The same message, evaluated afresh: the transient answer claimed nothing.
    assert (retried["statusCode"], retried["body"]) == (200, _UNIFORM)
    assert len(wired.sqs.messages) == 1
    assert source.fetches == 4

    h.handler(_event(_outbound(signer, event_id="evt-2").to_wire()), None)
    assert len(wired.sqs.messages) == 2
    assert source.fetches == 4  # cached once it succeeded


def test_an_unavailable_key_source_tells_an_unmapped_sender_nothing(keys_down):
    wired, _, source = keys_down

    resp = h.handler(_event(_stranger_json(), token=_STRANGER_TOKEN), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert _drops(wired) == [("not_evaluated", "key_source")]
    assert wired.dynamo.items == {}


def test_a_request_that_fails_gate_1_does_not_fetch_the_keys(keys_down):
    wired, signer, source = keys_down

    resp = h.handler(_event(_outbound(signer).to_wire(), token="wrong-token"), None)

    assert resp["body"] == _UNIFORM
    assert source.fetches == 1  # the cold start only
    assert _drops(wired) == [("authenticity_failed", None)]


def test_an_unavailable_key_source_does_not_touch_an_airlock_that_builds_its_envelope(
    keys_down, monkeypatch, tmp_path
):
    wired, _, source = keys_down
    manifest = tmp_path / "owner-manifest.yaml"
    manifest.write_text(
        f"""\
zone: {_ZONE}
adapter:
  kind: owner
routing:
  /agent: example-agent
trust_map:
  - channel_type: owner
    channel_identity: maintainer
    principal: example-agent
    sender_class: owner
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CHANNELS_MANIFEST", str(manifest))
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: _TOKEN)  # the bot's one token
    command = json.dumps(
        {
            "sender": {"channel_type": "owner", "channel_identity": "maintainer"},
            "event_id": "evt-owner",
            "text": "/agent status",
            "ts": _TS,
            "expiry": _FUTURE,
        }
    )

    resp = h.handler(_event(command), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert len(wired.sqs.messages) == 1
    assert _drops(wired) == []
    assert source.fetches == 1  # the cold start; gate 3.5 never asked


_SECRET_SENTINEL = "SENTINEL-verify-keys-value-7f3c"


@pytest.mark.parametrize(
    "field", ["public_key", "sender_identities", "signer_posture", "custody_evidence"]
)
def test_a_malformed_key_secret_never_reaches_the_log(verifying, monkeypatch, caplog, field):
    """The secret is the key map; a fault in it is logged by setting and type,
    never by the value that was wrong."""
    wired, signer = verifying
    entry = json.loads(keys_mod._fetch_secret("arn:verify"))["broker:A"]
    entry[field] = _SECRET_SENTINEL
    monkeypatch.setattr(
        keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:A": entry})
    )
    caplog.set_level(logging.DEBUG)

    resp = h.handler(_event(_outbound(signer).to_wire()), None)

    assert resp["body"] == _TRANSIENT  # the failing path ran
    assert _drops(wired) == [("not_evaluated", "key_source")]
    assert caplog.records, "the failure was logged"
    for record in caplog.records:
        rendered = caplog.handler.format(record)
        assert _SECRET_SENTINEL not in rendered
        assert _SECRET_SENTINEL not in repr(record.args)


def test_with_verification_off_the_key_source_is_never_fetched(wired, monkeypatch):
    def fetch(arn):
        raise AssertionError("verification is OFF; nothing should fetch keys")

    monkeypatch.setattr(keys_mod, "_fetch_secret", fetch)

    resp = h.handler(_event(_envelope_json()), None)

    assert resp["body"] == _UNIFORM and len(wired.sqs.messages) == 1
    assert h._STATE.verify_chain is None


def test_a_webhook_token_that_cannot_be_fetched_still_fails_the_cold_start(wired, monkeypatch):
    def fetch(arn):
        raise ConnectionError("secrets manager unreachable")

    monkeypatch.setattr(h, "_fetch_webhook_token", fetch)

    resp = h.handler(_event(_envelope_json()), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert h._STATE is None
    assert wired.s3.puts == [] and wired.sqs.messages == []


# --- the per-peer token ---------------------------------------------------------


@pytest.mark.parametrize(
    "claimed", ["peer:example", "peer:nobody"], ids=["claims-mapped", "claims-unmapped"]
)
def test_a_token_holder_learns_nothing_about_an_identity_it_claims(wired, claimed):
    """The probe a shared token allowed: an authenticated peer claims another
    identity and reads the answer. Its token names it, so the claim is refused
    as its own malformed envelope, and the answer does not depend on whether the
    claimed identity is mapped."""
    body = json.loads(_envelope_json())
    body["sender"]["channel_identity"] = claimed

    resp = h.handler(_event(json.dumps(body), token=_STRANGER_TOKEN), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert _drops(wired) == [("malformed", "sender_identity_mismatch")]
    assert wired.sqs.messages == [] and wired.dynamo.items == {}


_SECRET_TOKEN_SENTINEL = "SENTINEL-webhook-token-5be1"


@pytest.mark.parametrize(
    "secret,fault",
    [
        pytest.param(_SECRET_TOKEN_SENTINEL, "bare token string", id="old-shared-form"),
        pytest.param("{}", "empty object", id="empty-map"),
        pytest.param(
            json.dumps({"peer:example": _SECRET_TOKEN_SENTINEL, "peer:b": _SECRET_TOKEN_SENTINEL}),
            "gives one token to more than one identity",
            id="one-token-two-peers",
        ),
    ],
)
def test_a_webhook_secret_that_is_not_a_token_map_fails_the_cold_start(
    wired, monkeypatch, caplog, secret, fault
):
    """No usable map leaves no way to authenticate anyone: every request is
    answered the uniform body, nothing is cached, and the log names the fault
    without any value from the secret."""
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: secret)
    caplog.set_level(logging.DEBUG)

    resp = h.handler(_event(_envelope_json(), token=_SECRET_TOKEN_SENTINEL), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert h._STATE is None
    assert wired.s3.puts == [] and wired.sqs.messages == []
    assert "handler_error" in caplog.text and fault in caplog.text
    for record in caplog.records:
        assert "SENTINEL" not in caplog.handler.format(record)


def test_a_mapped_owner_is_told_nothing_of_a_refusal(wired, monkeypatch, tmp_path):
    """The owner token is shared by every owner, so the owner adapter is not
    per-sender: a mapped owner refused before the screen reads the uniform body."""
    manifest = tmp_path / "owner-manifest.yaml"
    manifest.write_text(
        f"""\
zone: {_ZONE}
adapter:
  kind: owner
routing:
  /agent: example-agent
trust_map:
  - channel_type: owner
    channel_identity: maintainer
    principal: example-agent
    sender_class: owner
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CHANNELS_MANIFEST", str(manifest))
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: _TOKEN)
    expired = json.dumps(
        {
            "sender": {"channel_type": "owner", "channel_identity": "maintainer"},
            "event_id": "evt-owner",
            "text": "/agent status",
            "ts": _EXPIRED_TS,
            "expiry": _EXPIRED_TS,
        }
    )

    resp = h.handler(_event(expired), None)

    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert _drops(wired) == [("expired", None)]


# --- the dedupe store -------------------------------------------------------------


@pytest.mark.parametrize("failing", ["get_item", "put_item"])
def test_an_unavailable_dedupe_store_is_transient_and_claims_nothing(wired, failing):
    def down(**kwargs):
        raise ConnectionError("dynamodb unreachable")

    setattr(wired.dynamo, failing, down)

    resp = h.handler(_event(_envelope_json()), None)

    assert (resp["statusCode"], resp["body"]) == (200, _TRANSIENT)
    assert _drops(wired) == [("not_evaluated", "dedupe_store")]
    assert wired.dynamo.items == {} and wired.sqs.messages == []


def test_a_resend_after_a_dedupe_store_outage_is_accepted_once(wired):
    # The transient answer claimed nothing, so the sender's re-send of the same
    # envelope is evaluated afresh once the store answers, and a further copy
    # dedupes like any replay.
    working_get_item = wired.dynamo.get_item

    def down(**kwargs):
        raise ConnectionError("dynamodb unreachable")

    wired.dynamo.get_item = down
    message = _event(_envelope_json(event_id="evt-outage"))

    assert h.handler(message, None)["body"] == _TRANSIENT
    assert wired.dynamo.items == {} and wired.sqs.messages == []

    wired.dynamo.get_item = working_get_item
    resent = h.handler(message, None)
    assert (resent["statusCode"], resent["body"]) == (200, _UNIFORM)
    assert len(wired.sqs.messages) == 1

    again = h.handler(message, None)
    assert (again["statusCode"], again["body"]) == (200, _UNIFORM)
    assert len(wired.sqs.messages) == 1
    assert _drops(wired) == [("not_evaluated", "dedupe_store")]


def test_a_lost_race_to_claim_the_key_is_not_a_store_failure(wired):
    # A concurrent copy claimed the key between this copy's read and write. The
    # store swallows that ConditionalCheckFailed, so it is not `not_evaluated`.
    def lost_race(**kwargs):
        raise _FakeClientError("ConditionalCheckFailedException")

    wired.dynamo.put_item = lost_race

    resp = h.handler(_event(_envelope_json()), None)

    assert resp["body"] == _UNIFORM
    assert _drops(wired) == []
