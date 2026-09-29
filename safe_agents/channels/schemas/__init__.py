"""channels.schemas — the EventTrigger envelope and its sub-types.

See channels/SCHEMAS.md for the authoritative field-by-field contract.
"""

from .event_trigger import (
    MAX_PAYLOAD_BYTES,
    ChainSignature,
    EventTrigger,
    ProvenanceEntry,
    SenderIdentity,
)

__all__ = [
    "EventTrigger",
    "SenderIdentity",
    "ProvenanceEntry",
    "ChainSignature",
    "MAX_PAYLOAD_BYTES",
]
