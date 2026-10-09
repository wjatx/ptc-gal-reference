"""channels.manifest — the typed consumer config for the inbound airlock.

The channels analogue of `broker/schemas/manifest.py`'s `AgentManifest`: a
consumer supplies a `ChannelsManifest` (in-image YAML, `extra="forbid"`) and the
airlock is built ENTIRELY from it — no channel-specific constant is baked into
base source. `build_airlock` is the composition root; a manifest that sets
nothing but its `zone` is the safe agent-agnostic floor (empty trust map ⇒ every
sender unmapped ⇒ everything drops, per channels/dispatch.py gate 5).

The injection screen ships OFF (docs/friction-doctrine.md): `screen=None`. A
manifest that DOES enable a screen must name a `kind` registered in
`SCREEN_REGISTRY`; an unregistered kind raises loudly rather than silently
falling back to no screen — a control that looks enabled but isn't is a latent
safety bug the friction doctrine forbids. The registry is populated by
importing `safe_agents.channels.screens` (reference-tier), which
`build_airlock` does lazily and only on the enabled path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.owner import build as _build_owner_adapter
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.schemas.event_trigger import ZONE_ID_RULE, is_zone_id
from safe_agents.channels.screening import ScreenVerdict
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry
from safe_agents.channels.webhook import SignedWebhookAdapter, parse_token_map

# A screen is any callable turning an envelope into a pass/refuse judgment; a
# factory builds one from its manifest `params` block.
Screen = Callable[[EventTrigger], "ScreenVerdict | bool"]
ScreenFactory = Callable[[dict], Screen]

# Registry of screen kinds a manifest may name. EMPTY at import: it is populated
# by importing `safe_agents.channels.screens` (which build_airlock does lazily,
# only on the enabled path), so an enabled-but-unregistered kind is an authoring
# error caught loudly at build time.
SCREEN_REGISTRY: dict[str, ScreenFactory] = {}


class WebhookAdapterConfig(BaseModel):
    """Config for `SignedWebhookAdapter` — the webhook shape, no secrets.

    The tokens never live here: the identity → token map is fetched from
    Secrets Manager and injected at build time (`webhook.parse_token_map`
    gives its shape). Only the non-sensitive header name does.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["signed-webhook"] = "signed-webhook"
    channel_type: str = "webhook"
    token_header: str = "x-airlock-token"

    @field_validator("token_header")
    @classmethod
    def _lowercase_token_header(cls, value: str) -> str:
        # WebhookRequest.headers is lowercase-keyed (HTTP header names are
        # case-insensitive); a mixed-case manifest value would otherwise miss
        # every lookup and silently drop all traffic as authenticity_failed.
        return value.lower()


class OwnerAdapterConfig(BaseModel):
    """Config for `OwnerInboundAdapter` — the human-as-owner shape.

    Like the webhook config, the token lives in Secrets Manager and is injected
    at build time; only the non-sensitive header name is config. The address →
    principal `routing` block is NOT here — it is `ChannelsManifest.routing`,
    passed to the adapter factory, because the same routing table is the
    handler's per-principal config key at N>1 (design answers Q2/Q4).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["owner"] = "owner"
    channel_type: str = "owner"
    token_header: str = "x-airlock-token"

    @field_validator("token_header")
    @classmethod
    def _lowercase_token_header(cls, value: str) -> str:
        # WebhookRequest.headers is lowercase-keyed (HTTP header names are
        # case-insensitive); a mixed-case manifest value would otherwise miss
        # every lookup and silently drop all traffic as authenticity_failed.
        return value.lower()


# An adapter factory builds a concrete `InboundAdapter` from its typed config,
# the injected token secret, the manifest routing table, and the airlock's own
# zone. The signature is uniform across kinds (webhook ignores routing and zone)
# so `build_airlock` dispatches without a per-kind conditional. The token secret
# arrives as the raw `SecretString` and each factory reads it in its own kind's
# shape: the webhook factory parses an identity → token map (a bare string is
# refused), and the owner factory takes the bot's one token as it is. The zone
# is what an adapter that builds the envelope itself writes as its `audience`.
AdapterFactory = Callable[[BaseModel, str, "dict[str, str]", str], InboundAdapter]

# Registry of adapter kinds a manifest may name. Unlike SCREEN_REGISTRY (whose
# implementations pull in vendor SDKs and so must import lazily), adapters are
# pure stdlib — so this registry is populated EAGERLY at import. An enabled-but-
# unregistered kind is caught loudly at build time (docs/friction-doctrine.md).
ADAPTER_REGISTRY: dict[str, AdapterFactory] = {
    "signed-webhook": lambda config, token, routing, zone: SignedWebhookAdapter(
        config, parse_token_map(token)
    ),
    "owner": lambda config, token, routing, zone: _build_owner_adapter(
        config, token, routing, zone
    ),
}


class ScreenConfig(BaseModel):
    """Which screen to build and its opaque construction params."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    params: dict = Field(default_factory=dict)


# The zone an airlock runs as when no manifest is configured (`CHANNELS_MANIFEST`
# unset). That airlock has an empty trust map and drops every sender, so the id
# names a receiver nothing can be delivered to. It is a named placeholder for
# that one case and never a value a configured manifest falls back to.
UNCONFIGURED_ZONE = "unconfigured"

_ZONE_REQUIRED = (
    "channels manifest sets no `zone`, and there is no default. `zone` is the id of "
    "this one airlock deployment: it is stamped on every envelope accepted here and "
    "is the `audience` an inbound envelope must name. Give each deployment its own "
    "id, including each environment of the same agent: where two airlocks share an "
    "id and enrol the same signer key, an envelope signed for one verifies at the "
    "other (channels/SIGNING.md S9)."
)


class ChannelsManifest(BaseModel):
    """The whole inbound airlock as consumer config.

    `zone` is required and has no default. It is the id of this one airlock
    deployment: the provenance zone stamped on every accepted envelope, and the
    `audience` an envelope must name to be accepted here (dispatch gate 3,
    channels/SIGNING.md S9). Two deployments that enrol any of the same signer
    keys must not share an id, including two environments of the same agent,
    and a default would give every deployment built from it the same one.
    Nothing here can check that two deployments chose different ids.

    Every other field defaults. A manifest that sets only `zone` has an empty
    trust map and drops every sender; the handler runs exactly that, as
    `UNCONFIGURED_ZONE`, when `CHANNELS_MANIFEST` is unset.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    zone: str
    adapter: WebhookAdapterConfig | OwnerAdapterConfig = Field(
        default_factory=WebhookAdapterConfig, discriminator="kind"
    )
    # Address-token → principal-id, friendly-name indirection ONLY: the owner
    # adapter's `normalize` resolves the command's leading address token through
    # this table (a miss passes the raw token through as the claimed principal).
    # The trust map stays the SOLE authorization authority — gate 5 never sees
    # the token (design answers Q2). Empty dict, the default, is no indirection
    # at all. Only the owner adapter consumes it; a non-owner manifest that
    # sets it is a config error (see `_routing_requires_owner_adapter`).
    routing: dict[str, str] = Field(default_factory=dict)
    trust_map: list[TrustMapEntry] = Field(default_factory=list)
    # None == OFF, the friction-doctrine default (docs/friction-doctrine.md).
    screen: ScreenConfig | None = None
    verdict_sink: bool = False
    dedupe_ttl_days: int = 30

    @model_validator(mode="before")
    @classmethod
    def _zone_has_no_default(cls, data: object) -> object:
        # The generic "Field required" would not tell an operator what a zone is
        # or why no default exists. A YAML `zone:` with no value loads as None
        # and gets the same answer.
        if isinstance(data, dict) and data.get("zone") is None:
            raise ValueError(_ZONE_REQUIRED)
        return data

    @field_validator("zone")
    @classmethod
    def _zone_is_an_exact_id(cls, value: str) -> str:
        # The rule a verification key's zone is held to (`keys._peer_key`): the
        # id is refused, never trimmed, so what is written is what is compared.
        if not is_zone_id(value):
            raise ValueError(f"zone {ZONE_ID_RULE}")
        return value

    @field_validator("adapter", mode="before")
    @classmethod
    def _default_adapter_kind(cls, value: object) -> object:
        # BACK-COMPAT: existing YAML has a kind-less adapter dict. Inject the
        # webhook discriminator before the union resolves so a pre-owner-channel
        # manifest keeps resolving to WebhookAdapterConfig. A dict that DOES name
        # a kind, or an already-constructed config instance, passes untouched.
        if isinstance(value, dict) and "kind" not in value:
            return {**value, "kind": "signed-webhook"}
        return value

    @model_validator(mode="after")
    def _routing_requires_owner_adapter(self) -> "ChannelsManifest":
        # Only the owner adapter consumes `routing`; every other kind ignores it.
        # A `routing` block on a non-owner manifest is silently dead config — the
        # friction doctrine forbids a control that looks wired but isn't, so fail
        # loudly at load rather than drop the consumer's addressing intent.
        if self.routing and self.adapter.kind != "owner":
            raise ValueError(
                f"`routing` is set but adapter kind is {self.adapter.kind!r}, which "
                f"ignores it; only the 'owner' adapter consumes a routing block. "
                f"Remove `routing` or select the owner adapter."
            )
        return self


@dataclass(frozen=True)
class AirlockRuntime:
    """The built, ready-to-dispatch airlock: a live adapter plus resolved seams.

    Held module-globally by the Lambda handler and passed straight into
    `channels.dispatch.dispatch`; the durable seams (dedupe store, drop/verdict
    sinks, the accepted-queue send) are the handler's to bind.
    """

    adapter: InboundAdapter
    trust_map: ChannelTrustMap
    screen: Screen | None
    verdict_sink: bool
    zone: str
    dedupe_ttl_days: int


def build_airlock(manifest: ChannelsManifest, *, token: str) -> AirlockRuntime:
    """Construct the airlock from `manifest` and the injected token secret.

    `token` is the secret's `SecretString` as stored; the adapter factory reads
    it in its kind's shape (see `ADAPTER_REGISTRY`).

    Raises `ValueError` if the manifest enables a screen whose `kind` is not in
    `SCREEN_REGISTRY`, or names an adapter `kind` not in `ADAPTER_REGISTRY` — a
    configured-but-unbuildable seam must fail loudly, not silently degrade to
    pass-through (docs/friction-doctrine.md). A webhook token secret that is
    not a usable identity → token map raises `webhook.WebhookTokenMapError`, a
    `ValueError` whose message carries no value from the secret.
    """
    factory = ADAPTER_REGISTRY.get(manifest.adapter.kind)
    if factory is None:
        raise ValueError(
            f"channels manifest names adapter kind {manifest.adapter.kind!r}, but no "
            f"factory is registered for it (ADAPTER_REGISTRY knows "
            f"{sorted(ADAPTER_REGISTRY)!r}). A configured adapter that cannot be built "
            f"must fail loudly, not silently drop all traffic (docs/friction-doctrine.md)."
        )
    adapter = factory(manifest.adapter, token, manifest.routing, manifest.zone)
    trust_map = ChannelTrustMap(entries=list(manifest.trust_map))

    screen: Screen | None = None
    if manifest.screen is not None:
        # Populate SCREEN_REGISTRY lazily and only on the enabled path — the OFF
        # default imports no screen implementation (and no vendor SDK) at all.
        import safe_agents.channels.screens  # noqa: F401,PLC0415

        factory = SCREEN_REGISTRY.get(manifest.screen.kind)
        if factory is None:
            raise ValueError(
                f"channels manifest enables screen kind {manifest.screen.kind!r}, but no "
                f"factory is registered for it (SCREEN_REGISTRY knows "
                f"{sorted(SCREEN_REGISTRY)!r}). A configured screen that silently does "
                f"nothing is forbidden (docs/friction-doctrine.md); register the kind or "
                f"remove the screen block to run OFF."
            )
        screen = factory(manifest.screen.params)

    return AirlockRuntime(
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        verdict_sink=manifest.verdict_sink,
        zone=manifest.zone,
        dedupe_ttl_days=manifest.dedupe_ttl_days,
    )


def load_channels_manifest(path: str | Path) -> ChannelsManifest:
    """Read a `ChannelsManifest` from a YAML file.

    A minimal `yaml.safe_load` + `model_validate`, mirroring the broker's
    `load_agent_manifest` posture (broker/prototype/broker_server.py): raises
    `FileNotFoundError` if `path` is absent, `ValueError` if it is not a YAML
    mapping, and `pydantic.ValidationError` if the manifest is malformed.
    """
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"channels manifest {path} must be a YAML mapping; got {type(raw).__name__}"
        )
    return ChannelsManifest.model_validate(raw)
