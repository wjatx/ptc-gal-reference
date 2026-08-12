"""sa#176 — OwnerInboundAdapter + owner-channel dispatch conformance.

Independent conformance suite for the human-as-owner inbound adapter. Mirrors
the webhook-adapter unit idiom (test_webhook_adapter.py) for gates 1-3 and the
dispatch-driven idiom (test_adapters.py::test_screen_pass_changes_nothing) for
the full gate run. The drain-side approval fork lives in test_drain_owner.py.

Targets (from the sa#176 design answers Q3):
  1  mapped address + trusted identity -> all gates -> stamped, sender_class owner
  2  unmapped address -> principal_mismatch at gate 5
  3  unknown identity -> unmapped (distinct from target 2)
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.manifest import ChannelsManifest, OwnerAdapterConfig
from safe_agents.channels.owner import (
    APPROVE_COMMAND,
    FLAG_COMMAND,
    KIND,
    OwnerInboundAdapter,
    build as build_owner_adapter,
)
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.trust_map import CLASS_HOP_LABEL, ChannelTrustMap, TrustMapEntry
from safe_agents.channels.webhook import WebhookRequest

_TOKEN = "s3cr3t-owner-token"
_TS = "2026-07-11T00:00:00+00:00"
_EXPIRY = "2026-07-11T01:00:00+00:00"
_NOW = datetime.fromisoformat(_TS)


def _adapter(
    *, routing: dict | None = None, config: OwnerAdapterConfig | None = None, token: str = _TOKEN
) -> OwnerInboundAdapter:
    return OwnerInboundAdapter(config or OwnerAdapterConfig(), token, routing or {})


def _req(body: str = "", *, token: str | None = _TOKEN, header_key: str = "x-airlock-token") -> WebhookRequest:
    headers = {} if token is None else {header_key: token}
    return WebhookRequest(headers=headers, body=body)


def _owner_body(
    text: str = "/trader buy AAPL",
    *,
    channel_type: str = "owner",
    identity: str = "maintainer",
    event_id: str = "evt-1",
    ts: str = _TS,
    expiry: str = _EXPIRY,
    omit_text: bool = False,
    omit_sender: bool = False,
) -> str:
    body: dict = {
        "sender": {"channel_type": channel_type, "channel_identity": identity},
        "event_id": event_id,
        "text": text,
        "ts": ts,
        "expiry": expiry,
    }
    if omit_text:
        del body["text"]
    if omit_sender:
        del body["sender"]
    return json.dumps(body)


# --- module constants --------------------------------------------------------

def test_module_constants_are_the_owner_grammar():
    assert KIND == "owner"
    assert APPROVE_COMMAND == "/approve"
    assert FLAG_COMMAND == "/flag"


# --- adapter-unit: interface + gate 1 (verify_token) -------------------------

def test_owner_adapter_satisfies_inbound_interface():
    assert isinstance(_adapter(), InboundAdapter)


def test_build_factory_yields_owner_adapter():
    adapter = build_owner_adapter(OwnerAdapterConfig(), _TOKEN, {"/trader": "example-agent"})
    assert isinstance(adapter, OwnerInboundAdapter)
    assert adapter.channel_type == "owner"


def test_verify_token_accepts_matching_token():
    assert _adapter().verify_token(_req(token=_TOKEN)) is True


def test_verify_token_rejects_wrong_token():
    assert _adapter().verify_token(_req(token="not-the-token")) is False


def test_verify_token_rejects_missing_header():
    assert _adapter().verify_token(_req(token=None)) is False


def test_verify_token_honors_configured_header_name():
    adapter = _adapter(config=OwnerAdapterConfig(token_header="x-owner-token"))
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-owner-token")) is True
    # Right token under the DEFAULT header the adapter isn't looking at -> missing -> False.
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-airlock-token")) is False


# --- adapter-unit: gate 2 (extract_identity) ---------------------------------

def test_extract_identity_normalizes_case_and_whitespace():
    body = _owner_body(identity="  MAINTAINER  ")
    assert _adapter().extract_identity(_req(body=body)) == "maintainer"


def test_extract_identity_raises_on_malformed_json():
    with pytest.raises(Exception):
        _adapter().extract_identity(_req(body="{not valid json"))


def test_extract_identity_raises_on_missing_sender():
    with pytest.raises(Exception):
        _adapter().extract_identity(_req(body=json.dumps({"no": "sender"})))


# --- adapter-unit: gate 3 (normalize) — fresh chain + classification ---------

def test_normalize_builds_fresh_chain_command_envelope():
    env = _adapter(routing={"/trader": "example-agent"}).normalize(
        _req(body=_owner_body("/trader buy AAPL", identity="maintainer"))
    )
    assert isinstance(env, EventTrigger)
    # Fresh chain: exactly one seed hop, trusted floor, source namespaced "owner:".
    assert len(env.provenance) == 1
    seed = env.provenance[0]
    assert seed.label == "trusted"
    assert seed.source.startswith("owner:")
    assert seed.source == "owner:maintainer"
    # sender_class is receiver-owned: unset until the gate-8 stamp.
    assert env.sender_class is None
    # Routing HIT resolves the address to the deployment principal.
    assert env.principal == "example-agent"
    assert env.payload == {"kind": "command", "text": "/trader buy AAPL"}


def test_normalize_passes_raw_address_through_on_routing_miss():
    # Routing MISS: the raw token rides as the claimed principal so gate 5, not
    # normalize, is the authorization authority (design answers Q2/Q3).
    env = _adapter(routing={}).normalize(_req(body=_owner_body("/trader buy AAPL")))
    assert env.principal == "/trader"


def test_normalize_classifies_approval_command():
    env = _adapter(routing={"/approve": "example-agent"}).normalize(
        _req(body=_owner_body("/approve int-42 yes"))
    )
    assert env.principal == "example-agent"
    assert env.payload == {"kind": "approval", "intent_id": "int-42", "decision": "yes"}


def test_normalize_approval_no_decision():
    env = _adapter(routing={"/approve": "example-agent"}).normalize(
        _req(body=_owner_body("/approve int-7 no"))
    )
    assert env.payload == {"kind": "approval", "intent_id": "int-7", "decision": "no"}


def test_normalize_classifies_flag_command():
    env = _adapter(routing={"/flag": "example-agent"}).normalize(
        _req(body=_owner_body("/flag int-42"))
    )
    assert env.principal == "example-agent"
    assert env.payload == {"kind": "flag", "intent_id": "int-42"}


def test_normalize_seed_hop_timestamp_from_body():
    env = _adapter().normalize(_req(body=_owner_body(ts=_TS)))
    assert env.provenance[0].ts == _TS


@pytest.mark.parametrize("variant", ["maintainer", "MAINTAINER", "  Maintainer  "])
def test_normalize_sender_identity_matches_extract_identity(variant):
    # dispatch's gate-3 sender-transport-binding check (channels/ADAPTERS.md)
    # requires normalize()'s envelope.sender.channel_identity to equal THIS
    # request's extract_identity() result — proven directly for the owner
    # adapter's fresh-chain construction path too.
    request = _req(body=_owner_body(identity=variant))
    adapter = _adapter()
    assert adapter.normalize(request).sender.channel_identity == adapter.extract_identity(request)


# --- adapter-unit: gate 3 malformed-raising paths ----------------------------

def test_normalize_raises_on_channel_type_mismatch():
    with pytest.raises(ValueError, match="does not match adapter channel_type"):
        _adapter().normalize(_req(body=_owner_body(channel_type="telegram")))


def test_normalize_raises_on_address_less_message():
    with pytest.raises(ValueError, match="no address token"):
        _adapter().normalize(_req(body=_owner_body("   ")))


def test_normalize_raises_on_missing_text_field():
    with pytest.raises(Exception):
        _adapter().normalize(_req(body=_owner_body(omit_text=True)))


@pytest.mark.parametrize(
    "text",
    [
        "/approve int-1",            # too few tokens
        "/approve int-1 yes extra",  # too many tokens
        "/approve int-1 maybe",      # decision not in yes|no
        "/approve int-1 YES",        # case-sensitive: not "yes"
    ],
)
def test_normalize_raises_on_malformed_approval(text):
    with pytest.raises(ValueError, match="malformed approval command"):
        _adapter().normalize(_req(body=_owner_body(text)))


@pytest.mark.parametrize(
    "text",
    [
        "/flag",                # too few tokens (no intent_id)
        "/flag int-1 extra",    # too many tokens
    ],
)
def test_normalize_raises_on_malformed_flag(text):
    with pytest.raises(ValueError, match="malformed flag command"):
        _adapter().normalize(_req(body=_owner_body(text)))


# --- Reserved verbs must be registered in the REFERENCE manifests' routing -------
# A reserved verb absent from routing resolves to itself (the raw "/verb" token) and
# gate-5-drops as principal_mismatch, so a live /flag or /approve would terminal-drop at
# the drain. Guard against that by driving the REAL manifest routing through the REAL
# normalize (never a hand-built routing dict) for every reserved verb.

_REPO_ROOT = Path(__file__).resolve().parents[3]
_OWNER_MANIFESTS = [
    _REPO_ROOT / "examples" / "owner_channel" / "channels-manifest.yaml",
    _REPO_ROOT / "examples" / "owner_channel" / "channels-manifest-development.yaml",
]
# Each reserved verb paired with a well-formed argument tail its grammar accepts.
_RESERVED_VERB_COMMANDS = {
    APPROVE_COMMAND: f"{APPROVE_COMMAND} int-1 yes",
    FLAG_COMMAND: f"{FLAG_COMMAND} int-1",
}


@pytest.mark.parametrize("manifest_path", _OWNER_MANIFESTS, ids=lambda p: p.name)
@pytest.mark.parametrize("verb,command", sorted(_RESERVED_VERB_COMMANDS.items()))
def test_reference_manifest_routes_every_reserved_verb(manifest_path, verb, command):
    manifest = ChannelsManifest.model_validate(yaml.safe_load(manifest_path.read_text()))
    assert isinstance(manifest.adapter, OwnerAdapterConfig)
    adapter = OwnerInboundAdapter(manifest.adapter, _TOKEN, manifest.routing)

    env = adapter.normalize(
        _req(body=_owner_body(command, channel_type=manifest.adapter.channel_type))
    )

    # Resolved to the deployment principal via routing — NOT passed through as the raw
    # verb (which is what a missing routing entry would produce).
    assert env.principal != verb
    assert env.principal == manifest.routing[verb]


# --- Target 1 — mapped address + trusted identity -> all gates -> stamped ----

def test_owner_mapped_trusted_runs_all_gates_and_stamps():
    identity = "maintainer"
    adapter = _adapter(routing={"/trader": "example-agent"})
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="owner",
                channel_identity=identity,
                principal="example-agent",
                sender_class="owner",
            )
        ]
    )
    request = _req(body=_owner_body("/trader buy AAPL", identity=identity))
    # normalize is pure — snapshot the pre-stamp envelope to prove exactly one hop appended.
    pre = adapter.normalize(request)

    result = dispatch(
        request,
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="channels",
    )

    assert result is not None
    assert result.sender_class == "owner"
    assert result.principal == "example-agent"
    # Exactly one appended provenance hop, labelled the deterministic owner label.
    assert len(result.provenance) == len(pre.provenance) + 1
    assert result.provenance[:-1] == pre.provenance
    hop = result.provenance[-1]
    assert CLASS_HOP_LABEL["owner"] == "trusted"
    assert hop.label == CLASS_HOP_LABEL["owner"]


# --- Target 2 — unmapped address -> principal_mismatch at gate 5 -------------

def test_owner_unmapped_address_drops_principal_mismatch():
    identity = "maintainer"
    # Empty routing: normalize passes "/trader" through as the CLAIMED principal.
    adapter = _adapter(routing={})
    # The identity IS mapped — but to a DIFFERENT principal than the raw token.
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="owner",
                channel_identity=identity,
                principal="example-agent",
                sender_class="owner",
            )
        ]
    )
    request = _req(body=_owner_body("/trader buy AAPL", identity=identity))
    drops: list = []

    result = dispatch(
        request,
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="channels",
    )

    assert result is None
    assert drops[-1].reason == "principal_mismatch"


# --- Target 3 — unknown identity -> unmapped (distinct from target 2) --------

def test_owner_unknown_identity_drops_unmapped():
    # Address routes cleanly; the IDENTITY has no trust-map row at all.
    adapter = _adapter(routing={"/trader": "example-agent"})
    trust_map = ChannelTrustMap(entries=[])
    request = _req(body=_owner_body("/trader buy AAPL", identity="stranger"))
    drops: list = []

    result = dispatch(
        request,
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="channels",
    )

    assert result is None
    assert drops[-1].reason == "unmapped"
