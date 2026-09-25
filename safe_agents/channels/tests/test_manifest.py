"""sa#152 — ChannelsManifest / build_airlock conformance.

Covers the friction-doctrine defaults (screen OFF, empty trust map ⇒ everything
drops), the loud failure for an enabled-but-unregistered screen kind, and a YAML
round-trip through `load_channels_manifest`.
"""

import pytest
from pydantic import ValidationError

from safe_agents.channels.manifest import (
    AirlockRuntime,
    ChannelsManifest,
    ScreenConfig,
    WebhookAdapterConfig,
    build_airlock,
    load_channels_manifest,
)
from safe_agents.channels.webhook import SignedWebhookAdapter

_TOKEN = "example-token"

_EXAMPLE_YAML = """\
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


def test_empty_manifest_defaults():
    m = ChannelsManifest()
    assert m.zone == "channels"
    assert m.screen is None  # OFF — the friction-doctrine default
    assert m.trust_map == []
    assert m.verdict_sink is False
    assert m.dedupe_ttl_days == 30
    assert m.adapter.channel_type == "webhook"
    assert m.adapter.token_header == "x-airlock-token"


def test_build_airlock_empty_manifest_is_off_and_drops_everything():
    rt = build_airlock(ChannelsManifest(), token=_TOKEN)
    assert isinstance(rt, AirlockRuntime)
    assert rt.screen is None
    assert rt.zone == "channels"
    assert isinstance(rt.adapter, SignedWebhookAdapter)
    assert rt.adapter.channel_type == "webhook"
    # Empty trust map ⇒ no sender resolves ⇒ dispatch gate 5 drops (unmapped).
    assert rt.trust_map.resolve("webhook", "peer:example") is None


def test_unknown_screen_kind_raises_loudly():
    m = ChannelsManifest(screen=ScreenConfig(kind="mystery-classifier"))
    with pytest.raises(ValueError, match="mystery-classifier"):
        build_airlock(m, token=_TOKEN)


def test_screen_none_builds_without_a_screen():
    assert build_airlock(ChannelsManifest(screen=None), token=_TOKEN).screen is None


def test_yaml_round_trip(tmp_path):
    path = tmp_path / "channels-manifest.yaml"
    path.write_text(_EXAMPLE_YAML, encoding="utf-8")

    m = load_channels_manifest(path)

    assert m.zone == "channels"
    assert m.adapter == WebhookAdapterConfig()
    assert len(m.trust_map) == 1
    entry = m.trust_map[0]
    assert entry.channel_type == "webhook"
    assert entry.channel_identity == "peer:example"
    assert entry.principal == "example-agent"
    assert entry.sender_class == "peer-agent"
    assert m.screen is None
    assert m.dedupe_ttl_days == 30

    # The loaded manifest builds a resolving airlock.
    rt = build_airlock(m, token=_TOKEN)
    resolution = rt.trust_map.resolve("webhook", "peer:example")
    assert resolution is not None
    assert resolution.principal == "example-agent"


def test_loader_rejects_non_mapping(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        load_channels_manifest(path)


def test_manifest_forbids_unknown_keys():
    with pytest.raises(ValidationError):
        ChannelsManifest.model_validate({"zone": "channels", "not_a_field": True})


def test_token_header_is_lowercased():
    # WebhookRequest.headers is lowercase-keyed; a mixed-case manifest value
    # would otherwise miss every lookup and silently drop all traffic.
    assert WebhookAdapterConfig(token_header="X-Airlock-Token").token_header == "x-airlock-token"


def test_routing_on_non_owner_adapter_fails_loudly():
    # `routing` is consumed ONLY by the owner adapter; a webhook manifest that
    # sets it would silently ignore the consumer's addressing intent — the
    # friction doctrine forbids a control that looks wired but isn't.
    with pytest.raises(ValidationError, match="routing"):
        ChannelsManifest.model_validate({"routing": {"/trader": "example-agent"}})


def test_routing_on_owner_adapter_is_accepted():
    m = ChannelsManifest.model_validate(
        {"adapter": {"kind": "owner"}, "routing": {"/trader": "example-agent"}}
    )
    assert m.routing == {"/trader": "example-agent"}
    assert m.adapter.kind == "owner"


def test_empty_routing_on_webhook_is_fine():
    # The empty manifest (webhook default, no routing) must stay byte-for-byte valid.
    assert ChannelsManifest().routing == {}


def test_unknown_adapter_kind_fails_validation_loudly():
    # An unknown adapter kind is rejected at manifest validation by the
    # discriminated union (the user-facing fail-loud path) — it never reaches
    # build_airlock's defensive registry-drift check. Friction doctrine: a
    # misnamed adapter fails loudly, it does not silently degrade.
    with pytest.raises(ValidationError):
        ChannelsManifest.model_validate({"adapter": {"kind": "mystery-adapter"}})
