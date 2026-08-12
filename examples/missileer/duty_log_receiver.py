"""duty_log_receiver.py — missileer's CONSUMER-OWNED drain Receiver (sa#155 proof).

This is the worked example of the drain's receiver seam (channels/DRAIN.md): the
image-baked ``CHANNELS_DRAIN_RECEIVER`` names this class by dotted path
(``examples.missileer.duty_log_receiver:DutyLogReceiver``) and the drain worker
imports, zero-arg instantiates, and protocol-checks it — the same fail-closed
injection discipline as the sa#141 connector seam this example already carries
(``trackfeed_connector.py``). The base ships the protocol, never an
implementation: what an accepted envelope *means* is consumer code, and this
file is that meaning for missileer.

The consumer writes ONLY against public surfaces: the ``Receiver`` protocol
(``safe_agents.channels.drain.receiver``) and the ``EventTrigger`` schema
(``safe_agents.channels.schemas``) — never ``safe_agents.broker`` internals (the
consumer-boundary AST guard gates that). Two consequences worth noticing:

- The ``InputTrustMap`` is just ``Callable[[str], bool]``, so the receiver's own
  per-source trust policy is a plain consumer-written function — no base import,
  no base default. Missileer trusts only its internal command surface; every
  other source taints the turn, and under abstain polarity a tainted turn can
  only make the broker MORE conservative. Over-tainting is safe here.
- The brokered call is duck-typed: the drain hands ``receive`` a brokered-call
  facade exposing only ``handle_request`` (no turn controls — DRAIN.md D2),
  which reads ``tool`` / ``op`` / ``args`` / ``idempotency_key`` off the request
  object, so the consumer supplies its own tiny frozen dataclass rather than
  importing the broker's internal ``AgentRequest``.

Idempotency (DRAIN.md D4) is the load-bearing demonstration. The queue delivers
at-least-once and the worker ships NO dedupe store by contract, so ``receive``
derives a deterministic ``idempotency_key`` from exactly the contract fields —
``(sender.channel_identity, event_id)`` — and the broker's enforcement layer
does the rest: a replayed key returns the stored outcome without re-executing
(``broker/enforcement/engine.py`` step 1). A duplicate delivery therefore
replays the first append instead of double-acting — provided the enforcement
store is shared across worker invocations (in production, ``BROKER_STORE``
selects the DynamoDB store; an in-memory store dedupes only within one
process, which is exactly why the key must still be deterministic).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from safe_agents.channels.drain.receiver import Receiver
from safe_agents.channels.schemas import EventTrigger

# Missileer's OWN per-source trust policy (TRUST-MAPPING.md §"Two maps"): only
# its internal command surface is trusted. A peer's "trusted" chain label is a
# floor, never a grant — a source outside this tuple taints the turn regardless
# of how the sender labeled it.
_TRUSTED_SOURCE_PREFIXES = ("internal:",)

# The observer's own identity segments in the ledger key layout — matches the
# manifest's principal, config here rather than caller-supplied at the seam.
_AGENT_SEGMENT = "missileer-watch"


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


class DutyLogReceiver:
    """Record each accepted inbound signal on the duty ledger, exactly once.

    The abstain-safe archetype's answer to "an envelope arrived": append an
    observation record (``ledger.append`` — a grant missileer already holds)
    and stop. No effecting op exists in the served registry to escalate to;
    a broker outcome other than ``allow`` (deny / require_approval / abstain —
    e.g. because the ingested chain tainted the turn) is itself the safe
    outcome here, so the receiver never retries or works around it.
    """

    def input_trust_map(self) -> Callable[[str], bool]:
        """Missileer's own source-trust policy — the map the receiver OWNS."""

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
            idempotency_key=f"missileer:drain:{digest}",
        )
        response = runtime.handle_request(request)
        # Abstain polarity: any non-allow outcome means the broker chose the
        # safe direction (e.g. a tainted turn escalated the write). The signal
        # stays on the queue's redrive path only for real faults, which raise
        # out of handle_request — a decided deny/abstain is a completed,
        # correct handling of this envelope.
        _ = response


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the drain's fail-closed check does.
assert isinstance(DutyLogReceiver(), Receiver)
