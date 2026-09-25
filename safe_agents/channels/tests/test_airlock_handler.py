"""sa#152 — the Lambda handler end-to-end against hand-rolled AWS fakes.

Drives the whole binding (manifest → secrets → build_airlock → dispatch → SQS)
with fakes injected through the handler's boto3 seam factories. Proves the
200-always response discipline, the accepted-envelope enqueue, silent drops,
replay dedupe, and that the handler never raises.
"""

import base64
import json
from types import SimpleNamespace

import pytest

import safe_agents.channels.airlock.handler as h
from safe_agents.channels.schemas import EventTrigger

_TOKEN = "test-airlock-token"
_TS = "2026-07-08T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"

_MANIFEST_YAML = """\
zone: channels
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
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: _TOKEN)
    monkeypatch.setattr(h, "_STATE", None)

    yield fakes

    h._STATE = None


def _envelope_json(event_id: str = "evt-1") -> str:
    return json.dumps(
        {
            "event_id": event_id,
            "principal": "example-agent",
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
    assert stamped.provenance[-1].zone == "channels"


def test_base64_body_is_decoded_and_accepted(wired):
    resp = h.handler(_event(_envelope_json(), base64_encoded=True), None)
    assert resp["statusCode"] == 200
    assert len(wired.sqs.messages) == 1


def test_bad_token_drops_silently_without_enqueue(wired):
    resp = h.handler(_event(_envelope_json(), token="wrong-token"), None)

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

    resp = h.handler(_event(json.dumps(body)), None)

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
