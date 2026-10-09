"""ChannelsManifest / build_airlock conformance.

Covers the friction-doctrine defaults (screen OFF, empty trust map ⇒ everything
drops), the loud failure for an enabled-but-unregistered screen kind, a YAML
round-trip through `load_channels_manifest`, and the zone id: required, with no
default, and different in every shipped example manifest.
"""

from datetime import datetime
from itertools import permutations
from pathlib import Path

import pytest
from pydantic import ValidationError

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.manifest import (
    ADAPTER_REGISTRY,
    UNCONFIGURED_ZONE,
    AirlockRuntime,
    ChannelsManifest,
    OwnerAdapterConfig,
    ScreenConfig,
    WebhookAdapterConfig,
    build_airlock,
    load_channels_manifest,
)
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.webhook import SignedWebhookAdapter, WebhookRequest, WebhookTokenMapError

# The webhook token secret as stored: one entry per peer. The owner factory takes
# whatever string it is handed as the bot's one token.
_TOKEN = '{"peer:example": "example-token"}'
# The zone the manifests built here name. Any id will do; none is a default.
_ZONE = "example-airlock"

_EXAMPLE_YAML = f"""\
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


def test_a_manifest_that_names_only_its_zone_takes_every_other_default():
    m = ChannelsManifest(zone=_ZONE)
    assert m.zone == _ZONE
    assert m.screen is None  # OFF — the friction-doctrine default
    assert m.trust_map == []
    assert m.verdict_sink is False
    assert m.dedupe_ttl_days == 30
    assert m.adapter.channel_type == "webhook"
    assert m.adapter.token_header == "x-airlock-token"


def test_build_airlock_zone_only_manifest_is_off_and_drops_everything():
    rt = build_airlock(ChannelsManifest(zone=_ZONE), token=_TOKEN)
    assert isinstance(rt, AirlockRuntime)
    assert rt.screen is None
    assert rt.zone == _ZONE
    assert isinstance(rt.adapter, SignedWebhookAdapter)
    assert rt.adapter.channel_type == "webhook"
    # Empty trust map ⇒ no sender resolves ⇒ dispatch gate 5 drops (unmapped).
    assert rt.trust_map.resolve("webhook", "peer:example") is None


def test_a_webhook_airlock_refuses_a_bare_token_secret():
    """The shared single-token form is refused at build, by name, so the cold
    start fails rather than authenticating every peer as no one."""
    with pytest.raises(WebhookTokenMapError, match="bare token string"):
        build_airlock(ChannelsManifest(zone=_ZONE), token="example-token")


def test_an_owner_airlock_takes_its_token_as_a_bare_string():
    manifest = ChannelsManifest(zone=_ZONE, adapter=OwnerAdapterConfig())
    adapter = build_airlock(manifest, token="example-token").adapter
    assert adapter.credential_per_sender is False
    request = WebhookRequest(headers={"x-airlock-token": "example-token"}, body="")
    assert adapter.verify_token(request) is True


def test_unknown_screen_kind_raises_loudly():
    m = ChannelsManifest(zone=_ZONE, screen=ScreenConfig(kind="mystery-classifier"))
    with pytest.raises(ValueError, match="mystery-classifier"):
        build_airlock(m, token=_TOKEN)


def test_screen_none_builds_without_a_screen():
    assert build_airlock(ChannelsManifest(zone=_ZONE, screen=None), token=_TOKEN).screen is None


def test_yaml_round_trip(tmp_path):
    path = tmp_path / "channels-manifest.yaml"
    path.write_text(_EXAMPLE_YAML, encoding="utf-8")

    m = load_channels_manifest(path)

    assert m.zone == _ZONE
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
        ChannelsManifest.model_validate({"zone": _ZONE, "not_a_field": True})


def test_token_header_is_lowercased():
    # WebhookRequest.headers is lowercase-keyed; a mixed-case manifest value
    # would otherwise miss every lookup and silently drop all traffic.
    assert WebhookAdapterConfig(token_header="X-Airlock-Token").token_header == "x-airlock-token"


def test_routing_on_non_owner_adapter_fails_loudly():
    # `routing` is consumed ONLY by the owner adapter; a webhook manifest that
    # sets it would silently ignore the consumer's addressing intent — the
    # friction doctrine forbids a control that looks wired but isn't.
    with pytest.raises(ValidationError, match="routing"):
        ChannelsManifest.model_validate({"zone": _ZONE, "routing": {"/trader": "example-agent"}})


def test_routing_on_owner_adapter_is_accepted():
    m = ChannelsManifest.model_validate(
        {"zone": _ZONE, "adapter": {"kind": "owner"}, "routing": {"/trader": "example-agent"}}
    )
    assert m.routing == {"/trader": "example-agent"}
    assert m.adapter.kind == "owner"


def test_empty_routing_on_webhook_is_fine():
    # A manifest that names only its zone (webhook default, no routing) stays valid.
    assert ChannelsManifest(zone=_ZONE).routing == {}


def test_unknown_adapter_kind_fails_validation_loudly():
    # An unknown adapter kind is rejected at manifest validation by the
    # discriminated union (the user-facing fail-loud path) — it never reaches
    # build_airlock's defensive registry-drift check. Friction doctrine: a
    # misnamed adapter fails loudly, it does not silently degrade.
    with pytest.raises(ValidationError):
        ChannelsManifest.model_validate({"zone": _ZONE, "adapter": {"kind": "mystery-adapter"}})


@pytest.mark.parametrize(
    "config",
    [WebhookAdapterConfig(), OwnerAdapterConfig()],
    ids=lambda config: config.kind,
)
def test_every_registered_adapter_factory_takes_the_airlock_zone(config):
    """`build_airlock` calls each factory the same way: config, token, routing
    and the airlock's own zone. The webhook factory ignores the last two."""
    assert set(ADAPTER_REGISTRY) == {"signed-webhook", "owner"}
    adapter = ADAPTER_REGISTRY[config.kind](config, _TOKEN, {}, "some-zone")
    assert adapter.channel_type == config.channel_type
    with pytest.raises(TypeError):
        ADAPTER_REGISTRY[config.kind](config, _TOKEN, {})


# ---------------------------------------------------------------------------
# The zone id. It names one airlock deployment and is the `audience` an envelope
# must carry to be accepted there (channels/SIGNING.md S9), so it is required,
# has no default, and differs in every manifest this repository ships.
# ---------------------------------------------------------------------------

_ZONELESS_YAML = _EXAMPLE_YAML.replace(f"zone: {_ZONE}\n", "")


def test_zone_is_required_and_has_no_default():
    assert ChannelsManifest.model_fields["zone"].is_required()


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param({}, id="nothing set"),
        pytest.param({"trust_map": [], "verdict_sink": False}, id="other fields set"),
        pytest.param({"zone": None}, id="zone left empty"),
    ],
)
def test_a_manifest_without_a_zone_is_refused_and_told_why(raw):
    with pytest.raises(ValidationError) as refused:
        ChannelsManifest.model_validate(raw)
    message = str(refused.value)
    assert "sets no `zone`" in message and "no default" in message
    assert "each environment" in message  # says what the id has to be distinct from


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_ZONELESS_YAML, id="zone omitted"),
        pytest.param("zone:\n" + _ZONELESS_YAML, id="zone left empty"),
    ],
)
def test_a_manifest_file_without_a_zone_does_not_load(tmp_path, body):
    assert f"zone: {_ZONE}" not in body
    path = tmp_path / "channels-manifest.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValidationError, match="sets no `zone`, and there is no default"):
        load_channels_manifest(path)


_NOT_EXACT = "zone must be a non-empty string with no surrounding whitespace"


@pytest.mark.parametrize(
    "zone,refusal",
    [
        pytest.param("", _NOT_EXACT, id="empty"),
        pytest.param(" ", _NOT_EXACT, id="a space"),
        pytest.param("\t\n", _NOT_EXACT, id="whitespace only"),
        pytest.param(" example-airlock", _NOT_EXACT, id="leading space"),
        pytest.param("example-airlock ", _NOT_EXACT, id="trailing space"),
        pytest.param("example-airlock\n", _NOT_EXACT, id="trailing newline"),
        pytest.param(7, "valid string", id="not a string"),
    ],
)
def test_a_zone_that_could_never_match_is_refused(zone, refusal):
    """The rule a verification key's zone is held to. The id is refused and never
    trimmed: an airlock's zone is compared exactly with each envelope's audience."""
    with pytest.raises(ValidationError, match=refusal):
        ChannelsManifest(zone=zone)


def test_zone_is_kept_exactly_as_written():
    assert ChannelsManifest(zone="Example-Airlock.2").zone == "Example-Airlock.2"


_EXAMPLES = Path(__file__).resolve().parents[3] / "examples"
# Every channels manifest the repository ships, and the zone id it declares.
_SHIPPED_ZONES = {
    "webhook_peer/channels-manifest.yaml": "webhook-peer-example",
    "webhook_peer/channels-manifest-screened.yaml": "webhook-peer-screened-example",
    "owner_channel/channels-manifest.yaml": "owner-channel-example",
    "owner_channel/channels-manifest-development.yaml": "owner-channel-development",
    "owner_channel/channels-manifest-gal-development.yaml": "owner-channel-gal-development",
}
_NOW = datetime.fromisoformat("2026-07-08T00:00:00+00:00")


def _shipped(name: str) -> ChannelsManifest:
    return load_channels_manifest(_EXAMPLES / name)


def test_every_shipped_manifest_is_listed_and_names_its_own_zone():
    on_disk = {
        p.relative_to(_EXAMPLES).as_posix() for p in _EXAMPLES.glob("*/channels-manifest*.yaml")
    }
    assert on_disk == set(_SHIPPED_ZONES)
    zones = {name: _shipped(name).zone for name in _SHIPPED_ZONES}
    assert zones == _SHIPPED_ZONES
    # No two share an id, and none is the placeholder of an airlock with no manifest.
    assert len(set(zones.values())) == len(zones)
    assert UNCONFIGURED_ZONE not in zones.values()


class _AlreadyNormalized(InboundAdapter):
    """Hands `dispatch` an envelope as an adapter of its channel type parsed it."""

    def __init__(self, envelope: EventTrigger) -> None:
        self.channel_type = envelope.sender.channel_type
        self._envelope = envelope

    def verify_token(self, request) -> bool:
        return True

    def extract_identity(self, request) -> str:
        return self._envelope.sender.channel_identity

    def normalize(self, request) -> EventTrigger:
        return self._envelope


def _deliver(receiver: ChannelsManifest, *, audience: str) -> tuple[EventTrigger | None, list]:
    """Deliver, to the airlock built from `receiver`, an envelope from the one
    sender its trust map admits. Only the `audience` is the caller's to choose."""
    airlock = build_airlock(receiver, token=_TOKEN)
    (admitted,) = receiver.trust_map
    envelope = EventTrigger.model_validate(
        {
            "event_id": "evt-1",
            "principal": admitted.principal,
            "audience": audience,
            "sender": {
                "channel_type": admitted.channel_type,
                "channel_identity": admitted.channel_identity,
                "evidence": [],
            },
            "payload": {"msg": "hello"},
            "provenance": [
                {
                    "zone": "sending-zone",
                    "source": "internal:test",
                    "evidence": [],
                    "label": "trusted",
                    "ts": _NOW.isoformat(),
                }
            ],
            "ts": _NOW.isoformat(),
            "expiry": "2099-01-01T00:00:00+00:00",
        }
    )
    drops: list = []
    accepted = dispatch(
        "request",
        adapter=_AlreadyNormalized(envelope),
        trust_map=airlock.trust_map,
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone=airlock.zone,
    )
    return accepted, drops


@pytest.mark.parametrize("receiver", sorted(_SHIPPED_ZONES))
def test_a_shipped_airlock_accepts_an_envelope_addressed_to_it(receiver):
    """The control for the test below: addressed to its own zone, the same
    envelope is accepted, so the audience is the only thing refused there."""
    manifest = _shipped(receiver)
    accepted, drops = _deliver(manifest, audience=manifest.zone)
    assert drops == []
    assert accepted is not None and accepted.provenance[-1].zone == _SHIPPED_ZONES[receiver]


@pytest.mark.parametrize(
    "addressed_to,receiver",
    sorted(permutations(_SHIPPED_ZONES, 2)),
    ids=lambda name: name.removesuffix(".yaml"),
)
def test_an_envelope_addressed_to_one_shipped_airlock_is_refused_at_every_other(
    addressed_to, receiver
):
    accepted, drops = _deliver(_shipped(receiver), audience=_shipped(addressed_to).zone)
    assert accepted is None
    assert [(d.reason, d.detail) for d in drops] == [("audience_mismatch", None)]
