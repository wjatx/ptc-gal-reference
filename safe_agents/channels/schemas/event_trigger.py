"""EventTrigger — the normalized inbound/outbound signal envelope.

One record type at two seams (publish and consume); see channels/SCHEMAS.md
for the authoritative field-by-field contract. This module is the canonical
typed encoding — the markdown's TypeScript block is illustrative only.
"""

import base64
import binascii
import json
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Contract ceiling on the serialized `payload` size (channels/SCHEMAS.md
# §"payload / payload_ref / payload_digest"). Consumers may bound lower.
MAX_PAYLOAD_BYTES = 65536

# Ceilings on the whole envelope in wire form (`EventTrigger.to_wire`). A sender
# may send, and an airlock accepts, up to MAX_ENVELOPE_BYTES. The airlock then adds
# its own hop and the sender class and forwards up to MAX_FORWARD_BYTES, which is
# the smallest message limit of any queue a reference transport uses (256 KiB).
# The gap between the two is the room the receiver's stamp may take, so an
# envelope accepted at the first ceiling always fits under the second.
MAX_ENVELOPE_BYTES = 196608
MAX_FORWARD_BYTES = 262144

# An envelope is signed once, by the broker that sends it. The cap leaves room
# for co-signers and stops one captured signature being repeated to make a
# receiver verify it thousands of times before any budget gate runs.
MAX_CHAIN_SIGNATURES = 8

# An Ed25519 signature is 64 bytes.
_SIGNATURE_BYTES = 64

# Matched with `fullmatch`: under `match`, a trailing `$` also accepts one
# trailing newline, which let a digest with "\n" appended through the schema gate.
_PAYLOAD_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _non_blank(v: str, field_name: str) -> str:
    if not v.strip():
        raise ValueError(f"{field_name} must be non-empty and non-whitespace")
    return v


def require_tz_aware(v: str, field_name: str) -> str:
    """Validate `v` parses as ISO-8601 and carries tzinfo; return it unchanged.

    The field stays a plain str on the wire (SCHEMAS.md declares `ts`/`expiry`
    as strings); this only rejects unparseable or naive timestamps.
    """
    try:
        parsed = datetime.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be ISO-8601: {v!r} ({exc})") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must carry timezone info: {v!r}")
    return v


class SenderIdentity(BaseModel):
    """WHO, at the transport layer, plus the verifying adapter's evidence.

    `evidence` is stamped by the adapter that PERFORMED the check — a receiver
    must not treat this as its own verification (channels/SCHEMAS.md
    §"sender.evidence").
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_type: str
    channel_identity: str
    evidence: list[str] = []


class ProvenanceEntry(BaseModel):
    """One append-only hop in the provenance chain.

    `label` is this hop's OWN judgment of its OWN source under its OWN trust
    map; `evidence` is the authenticity checks it performed for this hop. The
    two axes are independent — see channels/SCHEMAS.md §"Taint".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    zone: str
    source: str
    evidence: list[str] = []
    label: Literal["trusted", "untrusted"]
    ts: str

    @field_validator("source")
    @classmethod
    def source_is_namespaced(cls, v: str) -> str:
        """Enforce the `{scheme}:{value}` shape (channels/SCHEMAS.md §C8)."""
        scheme, sep, value = v.partition(":")
        if not sep or not scheme or not value:
            raise ValueError(
                f"provenance source must be namespaced '{{scheme}}:{{value}}': {v!r}"
            )
        return v

    @field_validator("ts")
    @classmethod
    def ts_is_tz_aware(cls, v: str) -> str:
        return require_tz_aware(v, "ProvenanceEntry.ts")


class ChainSignature(BaseModel):
    """One broker's cryptographic signature over the envelope it sends.

    Turns provenance from *asserted* into *authenticated*: a receiver can verify
    which broker committed to the chain-as-it-left-that-zone instead of trusting
    an unauthenticated chain (channels/SIGNING.md). Signing is per envelope: the
    sending broker signs the full chain as it leaves its zone, so `covers` is
    the chain length and a verifier refuses any signature whose `covers` is not
    the whole chain.

    The signature is over a DSSE pre-authentication encoding of an in-toto-style
    statement (`safe_agents.channels.signing`); it is never authored by the
    agent, only by the broker's workload identity. `key_id` names the public key
    a receiver resolves to verify — the subject-key binding that makes a hop
    attributable to the broker that asserted it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str
    zone: str
    covers: int = Field(ge=1)
    payload_type: str
    sig: str

    @field_validator("key_id", "zone", "sig")
    @classmethod
    def _non_blank(cls, v: str, info) -> str:
        return _non_blank(v, info.field_name)

    @field_validator("sig")
    @classmethod
    def sig_is_strict_base64_of_a_signature(cls, v: str) -> str:
        """Exactly one spelling per signature. A lenient decoder discards
        characters outside the alphabet, which leaves `sig` free to carry
        arbitrary padding on an envelope that still verifies, and even a strict
        one accepts sixteen strings for the same 64 bytes, because the last
        character has four bits that encode nothing. Only the canonical
        encoding of the decoded bytes is accepted."""
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("sig must be strict base64") from exc
        if len(raw) != _SIGNATURE_BYTES:
            raise ValueError(f"sig must decode to {_SIGNATURE_BYTES} bytes, got {len(raw)}")
        if base64.b64encode(raw).decode("ascii") != v:
            raise ValueError("sig must be the canonical base64 encoding of the signature")
        return v


class EventTrigger(BaseModel):
    """The normalized envelope any inbound (or outbound) signal becomes.

    Provenance is append-only — `stamped()` is the only growth path. There is
    deliberately no writable taint field; `tainted` is derived from the chain
    (see the property docstring below and channels/SCHEMAS.md §"Taint").
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    event_id: str
    principal: str
    # the zone id of the receiver this envelope is addressed to. Required: an
    # envelope with no named receiver verifies at every receiver that enrols
    # the sender's key (channels/SIGNING.md S9). Compared exactly at the airlock.
    audience: str
    sender: SenderIdentity
    payload: dict
    payload_digest: str | None = None
    payload_ref: str | None = None
    # append-only chain, min length 1 — taint derives from this (§"Taint")
    provenance: list[ProvenanceEntry] = Field(min_length=1)
    # the sending broker's signature over the whole envelope
    # (channels/SIGNING.md). Empty on an unsigned chain; verification is a
    # receiver-side knob that ships OFF (docs/friction-doctrine.md).
    chain_signatures: list[ChainSignature] = Field(
        default_factory=list, max_length=MAX_CHAIN_SIGNATURES
    )
    # receiver-owned (§C4): absent on the wire, set only by the trust-map gate
    sender_class: Literal["owner", "peer-agent", "external"] | None = None
    ts: str
    expiry: str

    @field_validator("event_id")
    @classmethod
    def event_id_non_blank(cls, v: str) -> str:
        return _non_blank(v, "event_id")

    @field_validator("principal")
    @classmethod
    def principal_non_blank(cls, v: str) -> str:
        return _non_blank(v, "principal")

    @field_validator("audience")
    @classmethod
    def audience_non_blank(cls, v: str) -> str:
        return _non_blank(v, "audience")

    @field_validator("payload_digest")
    @classmethod
    def digest_format(cls, v: str | None) -> str | None:
        if v is not None and not _PAYLOAD_DIGEST_RE.fullmatch(v):
            raise ValueError(f"payload_digest must match 'sha256:<64-hex>': {v!r}")
        return v

    @field_validator("payload")
    @classmethod
    def payload_within_cap(cls, v: dict) -> dict:
        size = len(json.dumps(v, separators=(",", ":")).encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload serializes to {size} bytes, exceeds MAX_PAYLOAD_BYTES={MAX_PAYLOAD_BYTES}"
            )
        return v

    @field_validator("ts")
    @classmethod
    def ts_is_tz_aware(cls, v: str) -> str:
        return require_tz_aware(v, "EventTrigger.ts")

    @field_validator("expiry")
    @classmethod
    def expiry_is_tz_aware(cls, v: str) -> str:
        return require_tz_aware(v, "EventTrigger.expiry")

    @model_validator(mode="after")
    def payload_ref_requires_digest(self) -> "EventTrigger":
        if self.payload_ref is not None and self.payload_digest is None:
            raise ValueError("payload_ref set requires payload_digest to also be set")
        return self

    @property
    def tainted(self) -> bool:
        """Derived, non-strippable taint label: true iff any hop is untrusted.

        There is deliberately no writable taint field on this envelope — see
        channels/SCHEMAS.md §"Taint" and broker/TAINT.md §1. The label is
        always recomputed from the provenance chain, never asserted.
        """
        return any(entry.label == "untrusted" for entry in self.provenance)

    def to_wire(self, *, max_bytes: int | None = MAX_ENVELOPE_BYTES) -> str:
        """The envelope as the JSON text one zone hands to the next.

        The one serialization every hop uses, so that "this envelope can be
        forwarded" is a property checked once instead of assumed at each send.
        The text is ASCII (every other character escaped), within ``max_bytes``,
        and parses back to an equal envelope with the parser a receiving worker
        uses. An envelope that fails any of those raises ``ValueError``: a NaN, a
        lone surrogate, nesting deeper than the parser accepts, or a size past
        the ceiling would otherwise be accepted here and lost at the next hop.
        """
        body = json.dumps(
            self.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"), allow_nan=False
        )
        if max_bytes is not None and len(body) > max_bytes:
            raise ValueError(f"envelope is {len(body)} bytes in wire form, over {max_bytes}")
        if EventTrigger.model_validate_json(body) != self:
            raise ValueError("envelope does not survive its own wire form unchanged")
        return body

    def dedupe_key(self) -> tuple[str, str]:
        """The C1 dedupe key: (sender.channel_identity, event_id)."""
        return (self.sender.channel_identity, self.event_id)

    def is_expired(self, now: datetime) -> bool:
        """Whether `now` is past `expiry`.

        Deterministic and testable: the caller supplies `now` (must be
        timezone-aware); this never reads the wall clock itself
        (channels/SCHEMAS.md §"expiry").
        """
        if now.tzinfo is None:
            raise ValueError("is_expired requires a timezone-aware `now`")
        return now > datetime.fromisoformat(self.expiry)

    def stamped(
        self,
        entry: ProvenanceEntry,
        sender_class: Literal["owner", "peer-agent", "external"] | None = None,
    ) -> "EventTrigger":
        """Return a NEW envelope with `entry` appended to the provenance chain.

        The only growth path — prior entries are never edited or removed
        (channels/SCHEMAS.md §C3). `sender_class` is updated only when the
        argument is provided; omitting it leaves an existing value intact
        rather than clearing it, since sender_class is receiver-owned (§C4)
        and only the trust-mapping gate should set it explicitly.
        """
        updates: dict = {"provenance": [*self.provenance, entry]}
        if sender_class is not None:
            updates["sender_class"] = sender_class
        return self.model_copy(update=updates)
