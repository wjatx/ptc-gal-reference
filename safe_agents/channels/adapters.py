"""channels.adapters — the channel-adapter interfaces.

See channels/ADAPTERS.md for the normative contract; this module is the
canonical typed encoding of `InboundAdapter` and `OutboundAdapter`.
Contract-tier per docs/contract-vs-reference.md: any third-party adapter
implements these interfaces and is exercised by
safe_agents/channels/tests/test_adapters.py, the conformance suite.

Adapters receive their configuration by injection or environment — neither
interface carries config fields (channels/ADAPTERS.md §"What an adapter
is"): instance values (secrets, endpoints) never enter contract surface.
"""

from abc import ABC, abstractmethod
from typing import Any

from safe_agents.channels.schemas import EventTrigger


class InboundAdapter(ABC):
    """The channel-specific edge of the airlock's inbound gate.

    One inbound adapter per channel ("telegram", "peer-agent", …); the
    airlock dispatch loop contains no channel conditionals — everything
    channel-specific lives behind this interface (channels/ADAPTERS.md).
    """

    channel_type: str

    # True for an adapter whose `normalize` BUILDS the envelope from a raw
    # message (an owner command), False for one that parses an envelope a
    # sending broker produced. Only the second kind has a signed chain, so only
    # it is subject to chain verification (channels/SIGNING.md S5).
    originates_envelope: bool = False

    # True when the gate-1 credential is bound to one sender identity, so that a
    # sender authenticated at gate 1 is authenticated AS the identity gate 2
    # returns. Only then may the dispatcher tell a mapped sender a refusal class
    # (channels/ADAPTERS.md §"What the sender is told"); with a credential
    # shared across senders, any holder could claim any identity and learn from
    # the answer whether the trust map holds it.
    credential_per_sender: bool = False

    @abstractmethod
    def verify_token(self, request: Any) -> bool:
        """Verify the transport-layer authenticity proof.

        Must run BEFORE the body is parsed — unauthenticated bytes must
        never reach a parser. Failure is gate 1's drop
        (`authenticity_failed`, channels/ADAPTERS.md §"Gate ordering").
        """
        raise NotImplementedError

    @abstractmethod
    def extract_identity(self, request: Any) -> str:
        """Return the sender's NORMALIZED channel identity.

        Normalization (canonical chat id, lower-cased domain) is the
        adapter's job; `ChannelTrustMap.resolve` is an exact-match lookup
        and performs no normalization of its own.
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(self, request: Any) -> EventTrigger:
        """Produce the typed `EventTrigger` — this call IS the schema check.

        Supersedes the earlier `extract_payload(request) -> bytes` sketch
        (channels/ADAPTERS.md §"Supersession"): where a raw original exists,
        it is stored out-of-band and referenced via `payload_ref` +
        `payload_digest` — never embedded (`channels/SCHEMAS.md` C2).
        """
        raise NotImplementedError


class OutboundAdapter(ABC):
    """The notifier seam: agent replies and the `require_approval` push.

    Never an agent-side path around the broker (channels/ADAPTERS.md
    §"Floor note") — the `OutboundAdapter` is where the broker-side
    connector (or the notifier) touches the channel.
    """

    channel_type: str

    @abstractmethod
    def deliver(self, principal: str, rendered_output: str, channel_metadata: dict) -> str:
        """Deliver `rendered_output` to `principal`; return a delivery reference.

        The reference is recorded to the audit trail by the caller.
        """
        raise NotImplementedError
