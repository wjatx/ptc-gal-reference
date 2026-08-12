"""channels.drain.receiver — the consumer Receiver seam (sa#155).

The drain worker is base reference code; what an accepted envelope *means* to
an agent is consumer code. The Receiver is that seam: the consumer supplies a
class implementing the protocol below, named by an image-baked dotted provider
path (``"pkg.module:ClassName"``) — the same injection discipline as the
broker's ``connector_providers`` (sa#141, ``broker/prototype/connector_registry.py``):
importlib-loaded, zero-arg instantiated, protocol-checked, fail-closed with a
typed error. A provider path is honored ONLY from the image-baked environment
(``CHANNELS_DRAIN_RECEIVER``), never from anything store-loaded and never from
the message itself (channels/DRAIN.md D6).
"""

from __future__ import annotations

import importlib
from typing import Protocol, runtime_checkable

from safe_agents.broker.taint.propagation import InputTrustMap
from safe_agents.channels.schemas import EventTrigger


@runtime_checkable
class Receiver(Protocol):
    """What a consumer must implement to act on accepted envelopes.

    Minimal by design — two members, matching the worker contract
    (channels/SCHEMAS.md §"Consume seam", channels/DRAIN.md):

    - ``input_trust_map()`` returns the receiver's own ``InputTrustMap`` — the
      per-agent source-trust policy `ingest_chain` combines with the chain's
      label floor. The receiver OWNS its map (TRUST-MAPPING.md §"Two maps");
      the base never supplies a default.
    - ``receive(envelope, runtime)`` is the action hook, called only AFTER the
      envelope's provenance chain has been ingested into the broker-held turn.
      ``runtime`` is NOT the raw ``BrokerRuntime``: it is a minimal
      brokered-call facade exposing ONLY ``handle_request(request)`` — no
      ``new_turn()``/``session_turn()``, so the receiver cannot roll the
      ingested taint away before acting (DRAIN.md D2). Every action must go
      through it (the agent's only egress is the broker). ``receive`` MUST be
      idempotent on ``(sender.channel_identity, event_id)`` — the airlock
      handoff is at-most-once with possible concurrent duplicates (DRAIN.md D4).
    """

    def input_trust_map(self) -> InputTrustMap:
        """The receiver's own per-source trust policy for turn ingestion."""
        ...

    def receive(self, envelope: EventTrigger, runtime: object) -> None:
        """Act on one ingested envelope through the brokered-call facade."""
        ...


class ReceiverProviderError(Exception):
    """Raised when the receiver provider path cannot yield a usable Receiver.

    Covers: missing/malformed path, unimportable module, missing class
    attribute, a class that is not zero-arg instantiable, and an instance that
    does not satisfy the ``Receiver`` protocol. Always names the offending
    path — a broken receiver is an operator error to fix loudly, never
    something to degrade into a silent message drop (DRAIN.md D6).
    """


def load_receiver(path: str) -> Receiver:
    """Import + instantiate + protocol-check the receiver provider path.

    Mirrors ``connector_registry._load_provider`` exactly: fail closed with a
    typed ``ReceiverProviderError`` at every step. Callers pass ONLY the
    image-baked ``CHANNELS_DRAIN_RECEIVER`` value here.
    """
    module_name, colon, class_name = path.partition(":")
    if not colon or not module_name or not class_name or ":" in class_name:
        raise ReceiverProviderError(
            f"receiver provider {path!r} is not a valid provider path; expected "
            '"pkg.module:ClassName" (exactly one colon, non-empty parts)'
        )
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ReceiverProviderError(
            f"receiver provider {path!r}: module {module_name!r} cannot be "
            f"imported ({exc})"
        ) from exc
    try:
        receiver_class = getattr(module, class_name)
    except AttributeError:
        raise ReceiverProviderError(
            f"receiver provider {path!r}: module {module_name!r} has no "
            f"attribute {class_name!r}"
        ) from None
    try:
        instance = receiver_class()
    except Exception as exc:
        raise ReceiverProviderError(
            f"receiver provider {path!r}: {class_name!r} is not zero-arg "
            f"instantiable ({exc})"
        ) from exc
    if not isinstance(instance, Receiver):
        raise ReceiverProviderError(
            f"receiver provider {path!r}: {class_name!r} does not satisfy the "
            "Receiver protocol (missing input_trust_map() and/or "
            "receive(envelope, runtime))"
        )
    return instance
