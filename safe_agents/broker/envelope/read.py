"""load_inforce_envelope — the source-agnostic read seam the broker calls at
startup (Phase 3 Slice B of the broker-destub epic, sa#136). Slice B is now
wired: build_runtime calls this once at startup when BROKER_ENVELOPE_LOAD=store
(broker/prototype/broker_server.py::build_runtime) and fails fast if it raises.

Kept as its own function (rather than a method on EnvelopeStore) so a future
source — Streams-backed cache invalidation, a file-backed dev fallback,
whatever sa#122 eventually needs — can swap in behind the same signature
without touching call sites.
"""

from __future__ import annotations

from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.common import Principal

from .store import EnvelopeStore


class EnvelopeNotFoundError(LookupError):
    """Raised when no envelope has been seeded for principal.

    Fail loudly rather than silently defaulting an envelope — the same
    no-silent-default posture Envelope.polarity itself enforces (see
    schemas/envelope.py). A broker with no envelope in force must not start
    under an implicit one.
    """


def load_inforce_envelope(store: EnvelopeStore, principal: Principal) -> Envelope:
    """Return the Envelope currently in force for principal.

    Raises EnvelopeNotFoundError if store has nothing seeded for this
    principal. build_runtime calls this once at startup for the broker's single
    principal (BROKER_ENVELOPE_LOAD=store) and fails fast if it raises — exactly
    like the existing BROKER_GRANT_LOAD="read" path fails closed when a granted
    action class has no seeded grant.
    """
    envelope = store.get_envelope(principal)
    if envelope is None:
        raise EnvelopeNotFoundError(
            f"No envelope seeded for principal {principal!r}. Run the seed step "
            "(safe_agents.broker.envelope.seed_envelope, or the "
            "prototype/seed_envelope.py out-of-band script) first."
        )
    return envelope
