"""channels.webhook — the signed-webhook inbound adapter (sa#152, reference-tier).

The first concrete `InboundAdapter` (channels/adapters.py), shaped for the sa#8
A2A wire: a peer zone POSTs an `EventTrigger` envelope as a JSON body, proving
transport authenticity with a shared secret-token header. Reference-tier per
docs/contract-vs-reference.md — it binds the contract-tier interfaces to the
webhook transport and is exercised by the same conformance idiom the ABCs are.

No transport client, no consumer identity, and no channel-specific literal
beyond the webhook shape lives here — the airlock stays channel-agnostic
(channels/ADAPTERS.md §"What an adapter is").
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.schemas import EventTrigger

if TYPE_CHECKING:  # config lives in manifest.py; type-only import avoids an import cycle
    from safe_agents.channels.manifest import WebhookAdapterConfig


@dataclass(frozen=True)
class WebhookRequest:
    """The transport-neutral request the Lambda handler and tests both build.

    `headers` is lowercase-keyed (the handler lowercases API Gateway's headers
    before constructing this); `body` is the decoded request body as text.
    """

    headers: dict[str, str]
    body: str


class SignedWebhookAdapter(InboundAdapter):
    """Secret-token webhook adapter: the peer POSTs an EventTrigger as JSON.

    `verify_token` (gate 1) is a constant-time compare of the configured header
    against the shared token, run before the body is parsed. `extract_identity`
    (gate 2) and `normalize` (gate 3) both parse the JSON body; `normalize`
    additionally rejects a body whose `sender.channel_type` disagrees with this
    adapter's own type, so a peer cannot pose as a different channel.
    """

    def __init__(self, config: "WebhookAdapterConfig", token: str) -> None:
        # channel_type is instance state (from config), satisfying the ABC's
        # `channel_type: str` — the airlock resolves the trust map against it.
        self.channel_type = config.channel_type
        self._token_header = config.token_header
        self._token = token

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
        # pydantic ValidationErrors propagate → dispatch's gate 3 drops `malformed`.
        envelope = EventTrigger.model_validate(json.loads(request.body))
        if envelope.sender.channel_type != self.channel_type:
            raise ValueError(
                f"sender.channel_type {envelope.sender.channel_type!r} does not match "
                f"adapter channel_type {self.channel_type!r}"
            )
        # The emitted envelope must carry the SAME identity the trust map matched:
        # dedupe_key() keys on sender.channel_identity, so a casing/whitespace wire
        # variant would otherwise give a mapped sender a fresh dedupe key per spelling
        # (unlimited replays of one event_id past gate 6).
        canonical = _canonical_identity(envelope.sender.channel_identity)
        if canonical != envelope.sender.channel_identity:
            envelope = envelope.model_copy(
                update={
                    "sender": envelope.sender.model_copy(
                        update={"channel_identity": canonical}
                    )
                }
            )
        return envelope


def _canonical_identity(raw: str) -> str:
    """The adapter's one normalization rule; gates 5 and 6 must see the same value."""
    return raw.strip().casefold()
