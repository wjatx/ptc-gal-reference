"""sa#152 — SignedWebhookAdapter conformance.

The webhook adapter is the concrete edge exercised by dispatch's gates 1-3:
constant-time token verification (gate 1), normalized identity extraction (gate
2), and the schema check (gate 3, including the channel_type-mismatch rejection).
"""

import json

import pytest

from safe_agents.channels.manifest import WebhookAdapterConfig
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.webhook import SignedWebhookAdapter, WebhookRequest

_TOKEN = "s3cr3t-token"
_TS = "2026-07-08T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"


def _adapter(config: WebhookAdapterConfig | None = None, token: str = _TOKEN) -> SignedWebhookAdapter:
    return SignedWebhookAdapter(config or WebhookAdapterConfig(), token)


def _req(body: str = "", token: str | None = _TOKEN, header_key: str = "x-airlock-token") -> WebhookRequest:
    headers = {} if token is None else {header_key: token}
    return WebhookRequest(headers=headers, body=body)


def _body(**overrides) -> str:
    env = {
        "event_id": "evt-1",
        "principal": "example-agent",
        "sender": {"channel_type": "webhook", "channel_identity": "peer:example", "evidence": []},
        "payload": {"k": "v"},
        "provenance": [
            {"zone": "peer", "source": "peer:example", "evidence": [], "label": "trusted", "ts": _TS}
        ],
        "ts": _TS,
        "expiry": _FUTURE,
    }
    env.update(overrides)
    return json.dumps(env)


# --- gate 1: verify_token -------------------------------------------------

def test_verify_token_accepts_matching_token():
    assert _adapter().verify_token(_req(token=_TOKEN)) is True


def test_verify_token_rejects_wrong_token():
    assert _adapter().verify_token(_req(token="not-the-token")) is False


def test_verify_token_rejects_missing_header():
    assert _adapter().verify_token(_req(token=None)) is False


def test_verify_token_honors_configured_header_name():
    adapter = _adapter(WebhookAdapterConfig(token_header="x-custom-token"))
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-custom-token")) is True
    # Right token under the default header the adapter isn't looking at ⇒ missing ⇒ False.
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-airlock-token")) is False


def test_channel_type_comes_from_config():
    assert _adapter(WebhookAdapterConfig(channel_type="webhook")).channel_type == "webhook"


# --- gate 2: extract_identity --------------------------------------------

def test_extract_identity_normalizes_case_and_whitespace():
    body = _body(
        sender={"channel_type": "webhook", "channel_identity": "  Peer:EXAMPLE  ", "evidence": []}
    )
    assert _adapter().extract_identity(_req(body=body)) == "peer:example"


def test_extract_identity_raises_on_malformed_json():
    with pytest.raises(Exception):
        _adapter().extract_identity(_req(body="{not valid json"))


def test_extract_identity_raises_on_missing_sender():
    with pytest.raises(Exception):
        _adapter().extract_identity(_req(body=json.dumps({"no": "sender"})))


# --- gate 3: normalize ----------------------------------------------------

def test_normalize_returns_typed_envelope():
    env = _adapter().normalize(_req(body=_body()))
    assert isinstance(env, EventTrigger)
    assert env.principal == "example-agent"
    assert env.sender.channel_identity == "peer:example"


def test_normalize_rejects_channel_type_mismatch():
    body = _body(
        sender={"channel_type": "telegram", "channel_identity": "peer:example", "evidence": []}
    )
    with pytest.raises(ValueError, match="does not match adapter channel_type"):
        _adapter().normalize(_req(body=body))


def test_normalize_raises_on_malformed_json():
    with pytest.raises(Exception):
        _adapter().normalize(_req(body="{bad"))


def test_normalize_propagates_pydantic_validation_error():
    # Missing required fields (principal, sender, payload, provenance, ...).
    with pytest.raises(Exception):
        _adapter().normalize(_req(body=json.dumps({"event_id": "evt-1"})))


def test_normalize_canonicalizes_sender_identity_for_dedupe():
    # Gate 6 keys on the emitted envelope's sender.channel_identity: every wire
    # spelling of one identity must yield ONE dedupe key, or a mapped sender
    # could replay a single event_id unlimited times by varying casing.
    keys = set()
    for variant in ("Peer:Example", "PEER:EXAMPLE", "  peer:example  "):
        body = _body(
            sender={"channel_type": "webhook", "channel_identity": variant, "evidence": []}
        )
        env = _adapter().normalize(_req(body=body))
        assert env.sender.channel_identity == "peer:example"
        keys.add(env.dedupe_key())
    assert len(keys) == 1


@pytest.mark.parametrize("variant", ["peer:example", "Peer:Example", "  PEER:EXAMPLE  "])
def test_normalize_sender_identity_matches_extract_identity(variant):
    # dispatch's gate-3 sender-transport-binding check (channels/ADAPTERS.md)
    # requires normalize()'s envelope.sender.channel_identity to equal THIS
    # request's extract_identity() result. Both derive from the same wire
    # field via the same canonicalization, so the invariant holds for every
    # spelling — proven directly rather than assumed.
    body = _body(sender={"channel_type": "webhook", "channel_identity": variant, "evidence": []})
    request = _req(body=body)
    adapter = _adapter()
    assert adapter.normalize(request).sender.channel_identity == adapter.extract_identity(request)
