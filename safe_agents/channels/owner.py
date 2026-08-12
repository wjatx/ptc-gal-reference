"""channels.owner — the human-as-owner inbound adapter (sa#176, reference-tier).

The second concrete `InboundAdapter` (channels/adapters.py), for the owner
channel: a human owner sends a RAW command (e.g. `/trader buy AAPL`, or an
approval reply `/approve <intent_id> yes|no`) over an authenticated transport,
and `normalize` CONSTRUCTS a fresh-chain `EventTrigger` from it — unlike the
webhook adapter, whose peer already POSTs a full envelope. The consumer's
transport shim wraps the raw command in the small JSON body this adapter parses.

Reference-tier per docs/contract-vs-reference.md — it binds the contract-tier
interfaces to the owner-command grammar and is exercised by the same conformance
idiom the ABCs are. No transport client, no consumer identity, and no
channel-specific literal beyond the owner-command grammar lives here — the
airlock stays channel-agnostic (channels/ADAPTERS.md §"What an adapter is").

Two things a reviewer MUST check (per the sa#176 design answers):

(a) `/approve` addressing at N=1. Addressing is an adapter-`normalize`
    responsibility — the first whitespace token of the command is the address.
    The consumer registers their address tokens (including `/approve`) →
    principal in the manifest `routing` block. On a routing MISS the raw token
    passes through as the *claimed* principal; gate 5 then rejects it
    `principal_mismatch` (the trust map is the SOLE authorization authority —
    `normalize` never drops on an unknown address, only on a malformed one).
    An owner who types a raw principal id is therefore admitted iff the trust
    map already authorizes them for that principal — an undocumented alias, not
    a trust hole (design answers Q2/Q3). NO default principal is ever
    synthesized: an address-less message raises → gate-3 `malformed`.

(b) The seed hop's `label="trusted"` is a FLOOR, not a grant. It is earned by
    gate-1 authentication (secret-token verify), but the consumer's receiver
    `InputTrustMap` stays authoritative via the one-way rule (TRUST-MAPPING.md,
    `ingest_chain`): a trusted seed does NOT auto-un-taint the turn. An
    `untrusted` seed, by contrast, would taint every owner turn and collapse
    owner≈external — so the owner would trip the lethal-trifecta cut on their
    own explicit command (design answers, seed-label sub-question).
"""

from __future__ import annotations

import hmac
import json
from typing import TYPE_CHECKING, Any

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry, SenderIdentity

if TYPE_CHECKING:  # config lives in manifest.py; type-only import avoids an import cycle
    from safe_agents.channels.manifest import OwnerAdapterConfig

KIND = "owner"
# The reserved approval verb — base protocol, not a consumer literal. An owner
# addresses an approval reply with this token exactly as any other command.
APPROVE_COMMAND = "/approve"
# The reserved flag verb — the owner's third out-of-band command (beside approve
# and the raw agent command). "/flag <intent_id>" marks an already-executed op as
# reviewed-wrong, writing the false_action evidence label (#193 Phase 6c).
FLAG_COMMAND = "/flag"


class OwnerInboundAdapter(InboundAdapter):
    """Owner-command adapter: the owner sends a raw command, not an envelope.

    `verify_token` (gate 1) is a constant-time compare of the configured header
    against the shared token, run before the body is parsed — byte-identical to
    the webhook adapter. `extract_identity` (gate 2) reads the sender identity
    from the JSON body. `normalize` (gate 3) is the heart: it parses the raw
    command, classifies it as `command` vs `approval`, resolves the address
    token to a claimed principal through the `routing` block, and constructs a
    fresh-chain `EventTrigger` with a single seed provenance hop.
    """

    def __init__(
        self, config: "OwnerAdapterConfig", token: str, routing: dict[str, str]
    ) -> None:
        # channel_type is instance state (from config), satisfying the ABC's
        # `channel_type: str` — the airlock resolves the trust map against it.
        self.channel_type = config.channel_type
        self._token_header = config.token_header
        self._token = token
        self._routing = dict(routing)

    def verify_token(self, request: Any) -> bool:
        provided = request.headers.get(self._token_header)
        if provided is None:
            return False
        return hmac.compare_digest(provided, self._token)

    def extract_identity(self, request: Any) -> str:
        # Any parse/shape failure propagates → dispatch's gate 2 drops `malformed`.
        data = json.loads(request.body)
        identity = data["sender"]["channel_identity"]
        return _canonical_identity(identity)

    def normalize(self, request: Any) -> EventTrigger:
        # This call IS the schema gate (channels/ADAPTERS.md §InboundAdapter);
        # any parse/shape failure raises → dispatch's gate 3 drops `malformed`.
        data = json.loads(request.body)

        # A sender must not pose as another channel (same guard the webhook
        # adapter has): the body's declared channel_type must match this adapter.
        if data["sender"]["channel_type"] != self.channel_type:
            raise ValueError(
                f"sender.channel_type {data['sender']['channel_type']!r} does not match "
                f"adapter channel_type {self.channel_type!r}"
            )

        text = data["text"]
        tokens = text.split()
        if not tokens:
            # Address-less message → gate-3 `malformed`. NO default principal,
            # ever — defaulting is the ambiguity that becomes a misroute hazard
            # at N>1 (design answers, address-less edge case).
            raise ValueError("owner command carries no address token")

        addr = tokens[0]
        # Routing HIT maps the friendly token to the deployment principal; MISS
        # passes the RAW token through as the claimed principal so gate 5 (the
        # sole authorization authority) rejects it `principal_mismatch`. Never
        # drop here — the routing block is ergonomic indirection, not a second
        # allow-list (design answers Q2/Q3).
        principal = self._routing.get(addr, addr)

        if addr == APPROVE_COMMAND:
            # Reserved approval grammar: exactly `/approve <intent_id> yes|no`.
            if len(tokens) != 3 or tokens[2] not in ("yes", "no"):
                raise ValueError(
                    f"malformed approval command: expected '/approve <intent_id> yes|no', "
                    f"got {text!r}"
                )
            payload: dict = {"kind": "approval", "intent_id": tokens[1], "decision": tokens[2]}
        elif addr == FLAG_COMMAND:
            # Reserved flag grammar: exactly `/flag <intent_id>`.
            if len(tokens) != 2:
                raise ValueError(
                    f"malformed flag command: expected '/flag <intent_id>', got {text!r}"
                )
            payload = {"kind": "flag", "intent_id": tokens[1]}
        else:
            payload = {"kind": "command", "text": text}

        canonical = _canonical_identity(data["sender"]["channel_identity"])

        # Exactly ONE origin hop. label="trusted" is a FLOOR earned by gate-1
        # auth — NOT a grant: the consumer's receiver InputTrustMap stays
        # authoritative via the one-way rule (ingest_chain), so this does NOT
        # auto-trust the turn. An untrusted seed would taint every owner turn
        # and collapse owner≈external (design answers, seed-label sub-question).
        seed_entry = ProvenanceEntry(
            zone=self.channel_type,
            source=f"owner:{canonical}",
            evidence=[],
            label="trusted",
            ts=data["ts"],
        )

        # Let pydantic ValidationErrors propagate → dispatch's gate 3 drops `malformed`.
        return EventTrigger(
            schema_version=1,
            event_id=data["event_id"],
            principal=principal,
            sender=SenderIdentity(
                channel_type=self.channel_type,
                channel_identity=canonical,
                evidence=[],
            ),
            payload=payload,
            provenance=[seed_entry],
            ts=data["ts"],
            expiry=data["expiry"],
        )


def _canonical_identity(raw: str) -> str:
    """The adapter's one normalization rule; gates 5 and 6 must see the same value."""
    return raw.strip().casefold()


def build(
    config: "OwnerAdapterConfig", token: str, routing: dict[str, str]
) -> OwnerInboundAdapter:
    """Registry factory: build an `OwnerInboundAdapter` (channels/manifest.py)."""
    return OwnerInboundAdapter(config, token, routing)
