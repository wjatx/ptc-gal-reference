"""channels — inbound airlock and outbound notifier contracts; see channels/SCHEMAS.md."""

from .adapters import InboundAdapter, OutboundAdapter
from .dispatch import dispatch
from .manifest import (
    SCREEN_REGISTRY,
    AirlockRuntime,
    ChannelsManifest,
    ScreenConfig,
    WebhookAdapterConfig,
    build_airlock,
    load_channels_manifest,
)
from .schemas import MAX_PAYLOAD_BYTES, EventTrigger, ProvenanceEntry, SenderIdentity
from .screening import (
    INJECTION_SUSPECTED,
    SCREEN_ERROR,
    ScreenRecord,
    ScreenVerdict,
    make_screen_record,
)
from .stores import DynamoDbDedupeStore, S3DropSink, S3VerdictSink
from .trust_map import (
    CLASS_HOP_LABEL,
    ChannelTrustMap,
    DropReason,
    DropRecord,
    SenderClass,
    TrustMapEntry,
    TrustResolution,
    ingest_chain,
    make_drop_record,
    stamp_inbound,
)
from .webhook import SignedWebhookAdapter, WebhookRequest

__all__ = [
    "EventTrigger",
    "SenderIdentity",
    "ProvenanceEntry",
    "MAX_PAYLOAD_BYTES",
    "CLASS_HOP_LABEL",
    "ChannelTrustMap",
    "DropReason",
    "DropRecord",
    "SenderClass",
    "TrustMapEntry",
    "TrustResolution",
    "ingest_chain",
    "make_drop_record",
    "stamp_inbound",
    "INJECTION_SUSPECTED",
    "SCREEN_ERROR",
    "ScreenRecord",
    "ScreenVerdict",
    "make_screen_record",
    "InboundAdapter",
    "OutboundAdapter",
    "dispatch",
    "AirlockRuntime",
    "ChannelsManifest",
    "ScreenConfig",
    "WebhookAdapterConfig",
    "SCREEN_REGISTRY",
    "build_airlock",
    "load_channels_manifest",
    "SignedWebhookAdapter",
    "WebhookRequest",
    "DynamoDbDedupeStore",
    "S3DropSink",
    "S3VerdictSink",
]
