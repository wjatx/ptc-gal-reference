"""channels.trust_map — the inbound trust-mapping framework (sa#81).

See channels/TRUST-MAPPING.md for the normative contract; this module is the
typed encoding. `ChannelTrustMap` answers the airlock question — a
transport-verified channel identity has addressed this agent, who is that,
and what may the receiver do about it — by deterministic, exact-match config
lookup. `stamp_inbound` is the only sanctioned path from a wire `EventTrigger`
to a worker-ready one. `ingest_chain` bridges the provenance chain into the
broker-held turn (`broker/taint`) under the one-way rule's label floor:
authenticity never cleans, and a sender-asserted "trusted" label is a floor
the receiver's own `InputTrustMap` can still fail.
"""

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from safe_agents.broker.taint.context import TurnContext
from safe_agents.broker.taint.propagation import InputTrustMap
from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry
from safe_agents.channels.schemas.event_trigger import require_tz_aware

SenderClass = Literal["owner", "peer-agent", "external"]

# Deterministic function of the class alone, never a per-entry config knob
# (TRUST-MAPPING.md §"Sender classes"). What varies per consumer is
# membership (which identities map to which class), never this mapping.
CLASS_HOP_LABEL: dict[SenderClass, Literal["trusted", "untrusted"]] = {
    "owner": "trusted",
    "peer-agent": "trusted",
    "external": "untrusted",
}

IDENTITY_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Short machine codes only — structurally incapable of holding free text (no
# whitespace, no capitals, length-capped). Shared with the screening seam
# (channels/screening.py) so any gate-specific reason/detail code is drawn
# from a closed vocabulary: a drop or verdict record can never become an
# injection vector for model-derived text.
MACHINE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def digest_identity(channel_identity: str) -> str:
    """Digest a channel identity into the `sha256:<64-hex>` form drop/verdict records store."""
    return "sha256:" + hashlib.sha256(channel_identity.encode("utf-8")).hexdigest()


class TrustMapEntry(BaseModel):
    """One membership row: which principal/class a channel identity may address."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_type: str
    channel_identity: str
    principal: str
    sender_class: SenderClass


class TrustResolution(BaseModel):
    """The result of a successful `ChannelTrustMap.resolve` lookup."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: str
    sender_class: SenderClass


class ChannelTrustMap(BaseModel):
    """Deterministic (channel_type, channel_identity) -> resolution lookup.

    Exact-match only: no wildcards, no normalization, no model call
    (TRUST-MAPPING.md §"The map shape"). Identity normalization is the
    adapter's job (sa#80), performed before this seam.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: list[TrustMapEntry]

    @model_validator(mode="after")
    def _no_duplicate_identity_keys(self) -> "ChannelTrustMap":
        seen: set[tuple[str, str]] = set()
        for entry in self.entries:
            key = (entry.channel_type, entry.channel_identity)
            if key in seen:
                raise ValueError(
                    f"duplicate (channel_type, channel_identity) in trust map: {key!r}"
                )
            seen.add(key)
        return self

    def resolve(self, channel_type: str, channel_identity: str) -> TrustResolution | None:
        """Exact-match lookup. None means drop (unmapped)."""
        for entry in self.entries:
            if entry.channel_type == channel_type and entry.channel_identity == channel_identity:
                return TrustResolution(principal=entry.principal, sender_class=entry.sender_class)
        return None


DropReason = Literal[
    "authenticity_failed",
    "malformed",
    "chain_signature_missing",
    "chain_signature_invalid",
    "chain_signer_unknown",
    "expired",
    "unmapped",
    "principal_mismatch",
    "screen_refused",
]


class DropRecord(BaseModel):
    """A PII-safe record of a dropped inbound signal (TRUST-MAPPING.md §DropRecord).

    Carries a digest of the channel identity, never the raw value — the same
    discipline as `AuditRecord.argsDigest`. `detail` is an optional
    gate-specific machine code (e.g. the screen's refuse reason) — never
    content-derived free text; MACHINE_CODE_RE keeps it a closed vocabulary
    so the drop log itself cannot become an injection vector.

    `chain_verified`/`signer_key_id` are evidence-of-check (sa#161 Phase A1,
    the `sig:pass` provenance-hop precedent in `channels/SIGNING.md`): they
    let an off-path watchdog attribute this drop at the authentication
    strength the airlock actually verified. `signer_key_id` is a public key
    NAME (the DSSE `key_id`), not PII, but it may only be set alongside
    `chain_verified=True` — evidence may never name a signer the gate didn't
    actually verify.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_type: str
    identity_digest: str
    reason: DropReason
    ts: str
    detail: str | None = None
    chain_verified: bool = False
    signer_key_id: str | None = None

    @field_validator("identity_digest")
    @classmethod
    def digest_format(cls, v: str) -> str:
        if not IDENTITY_DIGEST_RE.match(v):
            raise ValueError(f"identity_digest must match 'sha256:<64-hex>': {v!r}")
        return v

    @field_validator("ts")
    @classmethod
    def ts_is_tz_aware(cls, v: str) -> str:
        return require_tz_aware(v, "DropRecord.ts")

    @field_validator("detail")
    @classmethod
    def detail_is_machine_code(cls, v: str | None) -> str | None:
        if v is not None and not MACHINE_CODE_RE.match(v):
            raise ValueError(f"detail must be a machine code matching {MACHINE_CODE_RE.pattern!r}: {v!r}")
        return v

    @model_validator(mode="after")
    def _signer_requires_verified_chain(self) -> "DropRecord":
        if self.signer_key_id is not None and not self.chain_verified:
            raise ValueError("signer_key_id may only be set when chain_verified is True")
        return self


def make_drop_record(
    channel_type: str,
    channel_identity: str,
    reason: DropReason,
    ts: str,
    *,
    detail: str | None = None,
    chain_verified: bool = False,
    signer_key_id: str | None = None,
) -> DropRecord:
    """Build a `DropRecord`, digesting `channel_identity` so no caller stores it raw."""
    return DropRecord(
        channel_type=channel_type,
        identity_digest=digest_identity(channel_identity),
        reason=reason,
        ts=ts,
        detail=detail,
        chain_verified=chain_verified,
        signer_key_id=signer_key_id,
    )


def stamp_inbound(
    envelope: EventTrigger,
    resolution: TrustResolution,
    *,
    zone: str,
    source: str,
    evidence: list[str],
    ts: str,
) -> EventTrigger:
    """Append the receiver's own provenance hop and set `sender_class`.

    The only sanctioned path from a wire envelope to a worker-ready envelope
    (TRUST-MAPPING.md §"The map shape"; closes `channels/SCHEMAS.md` C4). The
    hop label is deterministic from `CLASS_HOP_LABEL`, never asserted by the
    caller, and the append is additive only — see `EventTrigger.stamped`: no
    resolution result ever renders a tainted envelope clean.
    """
    entry = ProvenanceEntry(
        zone=zone,
        source=source,
        evidence=evidence,
        label=CLASS_HOP_LABEL[resolution.sender_class],
        ts=ts,
    )
    return envelope.stamped(entry, sender_class=resolution.sender_class)


def ingest_chain(
    envelope: EventTrigger, turn_context: TurnContext, receiver_map: InputTrustMap
) -> None:
    """Feed every provenance source into the broker-held turn under the label floor.

    A source taints the turn unless BOTH its chain label is "trusted" AND the
    receiver's own `InputTrustMap` trusts it (TRUST-MAPPING.md §"The one-way
    rule", consequence 2). Chain labels arrive from the sending zone and could
    be forged by a compromised peer, so the receiver's map is authoritative
    for the receiving turn: a peer that stamps "trusted" on its origin
    launders nothing. Deterministic — no model call, no wall clock.
    """
    for entry in envelope.provenance:
        label = entry.label

        def _trusted_by_floor(source: str, label: str = label) -> bool:
            return label == "trusted" and bool(receiver_map(source))

        turn_context.ingest_source(entry.source, _trusted_by_floor)
