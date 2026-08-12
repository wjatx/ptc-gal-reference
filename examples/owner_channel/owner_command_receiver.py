"""owner_command_receiver.py — owner-channel's CONSUMER-OWNED drain Receiver (sa#176).

owner-channel stands on BOTH channels seams: the inbound airlock (a
``ChannelsManifest`` admitting its one mapped human owner) AND, with this file,
the drain — the worked example of an airlock-accepted owner COMMAND draining
end-to-end to a ledger. The image-baked ``CHANNELS_DRAIN_RECEIVER`` names this
class by dotted path
(``examples.owner_channel.owner_command_receiver:OwnerCommandReceiver``) and the
drain worker imports, zero-arg instantiates, and protocol-checks it — the same
fail-closed injection discipline as webhook-peer's ``inbound_log_receiver.py``
and the sa#141 connector seam.

This receiver handles ONLY the owner COMMAND path. An owner APPROVAL envelope
(``/approve <intent_id> yes|no``) forks in the BASE drain handler
(``channels/drain/handler.py``) to ``approve_intent``/``reject_intent`` BEFORE
any receiver runs — that fork requires ``sender_class == "owner"`` (stamped at
the airlock's gate 8, unforgeable on the wire) and actions the STORED
materializedRequest (WYSIWYE), so a human message's own taint cannot change what
executes. By the time ``receive`` is called the payload is always
``{"kind": "command", ...}``.

The consumer writes ONLY against public surfaces: the ``Receiver`` protocol
(``safe_agents.channels.drain.receiver``) and the ``EventTrigger`` schema
(``safe_agents.channels.schemas``) — never ``safe_agents.broker`` internals.

Discipline worth stating plainly (sa#176): ``sender_class == "owner"`` RAISES the
owner's action surface but is a FLOOR, never a grant. The airlock's owner seed
hop carries ``label="trusted"`` earned by gate-1 auth, and this receiver's own
trust map extends that same trust to the drain side by trusting sources prefixed
``"owner:"`` or ``"channel:"`` — so an accepted owner command drains UNTAINTED
rather than tainting the turn. But the broker still DECIDES every call: there is
no owner auto-allow here. It stays abstain-safe regardless — the only op this
consumer is granted is an observation (``ledger.append``); there is no effecting
op in the served registry to escalate to, so any non-allow broker outcome is
itself the safe, complete handling of the command.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from safe_agents.channels.drain.receiver import Receiver
from safe_agents.channels.schemas import EventTrigger

# owner-channel's OWN per-source trust policy (TRUST-MAPPING.md §"Two maps"): the
# drain side extends the same trust the airlock already granted its one mapped
# owner — an accepted chain's `owner:` origin hop and `channel:` stamp hop both
# read as trusted here. An owner's "trusted" chain label is still a FLOOR, never a
# grant: a source outside these prefixes taints the turn regardless of how the
# sender labeled it.
_TRUSTED_SOURCE_PREFIXES = ("owner:", "channel:")

# The observer's own identity segment in the ledger key layout — matches the
# drain manifest's principal, config here rather than caller-supplied at the seam.
# (Kept as a module constant for the reference consumer; a variant principal
# overrides the class attribute below, never this constant.)
_AGENT_SEGMENT = "owner-example-agent"


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


class OwnerCommandReceiver:
    """Record each accepted owner command on the ledger, exactly once.

    The abstain-safe archetype's answer to "an owner command arrived": append an
    observation record (``ledger.append`` — a grant this consumer already holds)
    and stop. No effecting op exists in the served registry to escalate to; a
    broker outcome other than ``allow`` is itself the safe outcome here, so the
    receiver never retries or works around it.
    """

    # The principal this receiver records under — MUST equal the drain
    # manifest's principal.agentId (ledger key layout AND the D4 idempotency
    # namespace). A variant principal subclasses and overrides ONLY this.
    agent_segment: str = _AGENT_SEGMENT

    def input_trust_map(self) -> Callable[[str], bool]:
        """owner-channel's own source-trust policy — the map the receiver OWNS."""

        def _trusts(source: str) -> bool:
            return source.startswith(_TRUSTED_SOURCE_PREFIXES)

        return _trusts

    def receive(self, envelope: EventTrigger, runtime: Any) -> None:
        digest = _dedupe_digest(envelope)
        # PII-safe by construction: the record carries the identity DIGEST and
        # the command payload's kind, never the raw channel identity.
        observation = json.dumps(
            {
                "event": "owner_command_observed",
                "event_id": envelope.event_id,
                "identity_digest": f"sha256:{digest}",
                "sender_class": envelope.sender_class,
                "payload_kind": envelope.payload.get("kind"),
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
                "agent": self.agent_segment,
                # A digest-derived run_id also makes the S3 KEY deterministic
                # per (sender, event) — the append-only conditional put is a
                # second, storage-level backstop behind the broker's dedupe.
                "run_id": f"evt-{digest[:12]}",
            },
            # D4: deterministic on (sender.channel_identity, event_id) — a
            # duplicate delivery presents the SAME key, and the broker replays
            # the stored outcome instead of executing a second append.
            idempotency_key=f"{self.agent_segment}:drain:{digest}",
        )
        response = runtime.handle_request(request)
        # Abstain polarity: any non-allow outcome means the broker chose the
        # safe direction (e.g. an untrusted-source chain that ended up tainted).
        # The command stays on the queue's redrive path only for real faults,
        # which raise out of handle_request — a decided deny/abstain is a
        # completed, correct handling of this command.
        _ = response


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the drain's fail-closed check does.
assert isinstance(OwnerCommandReceiver(), Receiver)
