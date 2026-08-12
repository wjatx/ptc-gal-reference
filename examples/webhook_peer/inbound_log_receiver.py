"""inbound_log_receiver.py — webhook-peer's CONSUMER-OWNED drain Receiver (sa#166).

webhook-peer is now BOTH the airlock (receiver) consumer for the sa#8 A2A driving
case AND, with this file, a drain consumer: the worked example of an
airlock-accepted peer envelope draining end-to-end to a ledger. The image-baked
``CHANNELS_DRAIN_RECEIVER`` names this class by dotted path
(``examples.webhook_peer.inbound_log_receiver:InboundLogReceiver``) and the drain
worker imports, zero-arg instantiates, and protocol-checks it — the same
fail-closed injection discipline as missileer's ``duty_log_receiver.py`` and the
sa#141 connector seam.

The consumer writes ONLY against public surfaces: the ``Receiver`` protocol
(``safe_agents.channels.drain.receiver``) and the ``EventTrigger`` schema
(``safe_agents.channels.schemas``) — never ``safe_agents.broker`` internals.

Deliberate contrast with missileer, worth stating plainly: missileer is the
ALWAYS-TAINTED internal-observer archetype (it trusts nothing, so every drained
envelope taints the turn). webhook-peer is the PEER-AGENT INBOUND archetype — its
airlock (`channels-manifest.yaml`) already admits its one mapped peer
(`peer:example` -> principal `example-agent`), so a chain the airlock accepted
carries a `peer` origin hop plus a `channel:webhook` stamp hop. This receiver's
own trust map extends that same trust to the drain side by trusting sources
prefixed `"peer:"` or `"channel:"`, so an accepted peer envelope drains UNTAINTED
rather than always-tainted. This is still abstain-safe: the only op this
consumer is granted is an observation (``ledger.append``) — there is no
effecting op in the served registry to escalate to, so any non-allow broker
outcome (e.g. from a chain that does NOT carry those trusted hops) is itself the
safe, complete handling of the envelope.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from safe_agents.channels.drain.receiver import Receiver
from safe_agents.channels.schemas import EventTrigger

# webhook-peer's OWN per-source trust policy (TRUST-MAPPING.md §"Two maps"): the
# drain side extends the same trust the airlock already granted its one mapped
# peer — an accepted chain's `peer` origin hop and `channel:webhook` stamp hop
# both read as trusted here. A peer's "trusted" chain label is still a floor,
# never a grant: a source outside these prefixes taints the turn regardless of
# how the sender labeled it.
_TRUSTED_SOURCE_PREFIXES = ("peer:", "channel:")

# The observer's own identity segment in the ledger key layout — matches the
# drain manifest's principal, config here rather than caller-supplied at the seam.
_AGENT_SEGMENT = "example-agent"


@dataclass(frozen=True)
class _BrokeredRequest:
    """The duck-typed request surface ``BrokerRuntime.handle_request`` reads.

    Consumer-owned on purpose: the broker's own request type is internal, and
    the runtime only ever reads these four attributes.
    """

    tool: str
    op: str
    args: Any
    idempotency_key: str | None


def _dedupe_digest(envelope: EventTrigger) -> str:
    """A deterministic digest of the D4 contract fields.

    Hashing (rather than concatenating raw values) keeps the raw channel
    identity out of the enforcement store's idempotency records — the same
    PII discipline as the drop log's ``sha256:`` identity digests.
    """
    material = f"{envelope.sender.channel_identity}\n{envelope.event_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class InboundLogReceiver:
    """Record each accepted inbound peer signal on the ledger, exactly once.

    The abstain-safe archetype's answer to "a peer envelope arrived": append an
    observation record (``ledger.append`` — a grant this consumer already
    holds) and stop. No effecting op exists in the served registry to escalate
    to; a broker outcome other than ``allow`` is itself the safe outcome here,
    so the receiver never retries or works around it.
    """

    def input_trust_map(self) -> Callable[[str], bool]:
        """webhook-peer's own source-trust policy — the map the receiver OWNS."""

        def _trusts(source: str) -> bool:
            return source.startswith(_TRUSTED_SOURCE_PREFIXES)

        return _trusts

    def receive(self, envelope: EventTrigger, runtime: Any) -> None:
        digest = _dedupe_digest(envelope)
        # PII-safe by construction: the record carries the identity DIGEST,
        # never the raw channel identity or the payload content.
        observation = json.dumps(
            {
                "event": "inbound_observed",
                "event_id": envelope.event_id,
                "identity_digest": f"sha256:{digest}",
                "sender_class": envelope.sender_class,
                "observed_ts": envelope.ts,
            }
        )
        request = _BrokeredRequest(
            tool="ledger",
            op="append",
            args={
                "kind": "ledger_delta",
                "logical_date": envelope.ts[:10],
                "content": observation,
                "agent": _AGENT_SEGMENT,
                # A digest-derived run_id also makes the S3 KEY deterministic
                # per (sender, event) — the append-only conditional put is a
                # second, storage-level backstop behind the broker's dedupe.
                "run_id": f"evt-{digest[:12]}",
            },
            # D4: deterministic on (sender.channel_identity, event_id) — a
            # duplicate delivery presents the SAME key, and the broker replays
            # the stored outcome instead of executing a second append.
            idempotency_key=f"example-agent:drain:{digest}",
        )
        response = runtime.handle_request(request)
        # Abstain polarity: any non-allow outcome means the broker chose the
        # safe direction (e.g. an untrusted-source chain that ended up
        # tainted). The signal stays on the queue's redrive path only for real
        # faults, which raise out of handle_request — a decided deny/abstain
        # is a completed, correct handling of this envelope.
        _ = response


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the drain's fail-closed check does.
assert isinstance(InboundLogReceiver(), Receiver)
