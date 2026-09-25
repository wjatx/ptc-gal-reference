"""channels.manifest — the typed consumer config for the inbound airlock (sa#152).

The channels analogue of `broker/schemas/manifest.py`'s `AgentManifest`: a
consumer supplies a `ChannelsManifest` (in-image YAML, `extra="forbid"`) and the
airlock is built ENTIRELY from it — no channel-specific constant is baked into
base source. `build_airlock` is the composition root; the empty manifest is the
safe agent-agnostic default (empty trust map ⇒ every sender unmapped ⇒ everything
drops, per channels/dispatch.py gate 5).

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
from safe_agents.channels.screening import ScreenVerdict
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry
from safe_agents.channels.webhook import SignedWebhookAdapter

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

    The token itself never lives here (it is fetched from Secrets Manager and
    injected at build time); only the non-sensitive header name does.
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
    """Config for `OwnerInboundAdapter` — the human-as-owner shape (sa#176).

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
# the injected token, and the manifest routing table. The signature is uniform
# across kinds (webhook ignores routing) so `build_airlock` dispatches without a
# per-kind conditional.
AdapterFactory = Callable[[BaseModel, str, "dict[str, str]"], InboundAdapter]

# Registry of adapter kinds a manifest may name. Unlike SCREEN_REGISTRY (whose
# implementations pull in vendor SDKs and so must import lazily), adapters are
# pure stdlib — so this registry is populated EAGERLY at import. An enabled-but-
# unregistered kind is caught loudly at build time (docs/friction-doctrine.md).
ADAPTER_REGISTRY: dict[str, AdapterFactory] = {
    "signed-webhook": lambda config, token, routing: SignedWebhookAdapter(config, token),
    "owner": lambda config, token, routing: _build_owner_adapter(config, token, routing),
}


class ScreenConfig(BaseModel):
    """Which screen to build and its opaque construction params."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    params: dict = Field(default_factory=dict)


class ChannelsManifest(BaseModel):
    """The whole inbound airlock as consumer config.

    Every field defaults, so `ChannelsManifest()` is the empty manifest: the
    handler uses it when `CHANNELS_MANIFEST` is unset, and its empty trust map
    drops every sender — the safe default for a base with no consumer wired.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    zone: str = "channels"
    adapter: WebhookAdapterConfig | OwnerAdapterConfig = Field(
        default_factory=WebhookAdapterConfig, discriminator="kind"
    )
    # Address-token → principal-id, friendly-name indirection ONLY: the owner
    # adapter's `normalize` resolves the command's leading address token through
    # this table (a miss passes the raw token through as the claimed principal).
    # The trust map stays the SOLE authorization authority — gate 5 never sees
    # the token (design answers Q2). Empty dict ⇒ byte-for-byte the empty
    # manifest. Only the owner adapter consumes it; a non-owner manifest that
    # sets it is a config error (see `_routing_requires_owner_adapter`).
    routing: dict[str, str] = Field(default_factory=dict)
    trust_map: list[TrustMapEntry] = Field(default_factory=list)
    # None == OFF, the friction-doctrine default (docs/friction-doctrine.md).
    screen: ScreenConfig | None = None
    verdict_sink: bool = False
    dedupe_ttl_days: int = 30

    @field_validator("adapter", mode="before")
    @classmethod
    def _default_adapter_kind(cls, value: object) -> object:
        # BACK-COMPAT: existing YAML has a kind-less adapter dict. Inject the
        # webhook discriminator before the union resolves so a pre-sa#176
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
    """Construct the airlock from `manifest` and the injected webhook `token`.

    Raises `ValueError` if the manifest enables a screen whose `kind` is not in
    `SCREEN_REGISTRY`, or names an adapter `kind` not in `ADAPTER_REGISTRY` — a
    configured-but-unbuildable seam must fail loudly, not silently degrade to
    pass-through (docs/friction-doctrine.md).
    """
    factory = ADAPTER_REGISTRY.get(manifest.adapter.kind)
    if factory is None:
        raise ValueError(
            f"channels manifest names adapter kind {manifest.adapter.kind!r}, but no "
            f"factory is registered for it (ADAPTER_REGISTRY knows "
            f"{sorted(ADAPTER_REGISTRY)!r}). A configured adapter that cannot be built "
            f"must fail loudly, not silently drop all traffic (docs/friction-doctrine.md)."
        )
    adapter = factory(manifest.adapter, token, manifest.routing)
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
