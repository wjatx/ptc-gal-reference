"""channels.signing — authenticate the outbound provenance chain (Phase 4).

Turns `stamp_outbound`'s provenance from *asserted* into *authenticated*. The
sending broker signs the chain-as-it-leaves-its-zone with its workload identity;
a receiving airlock verifies the signature and quarantines a forged or unsigned
chain (mirroring the grant-HMAC loud-quarantine). This is what lets a
receiver trust a cross-broker lineage without trusting the transport, and is the
gate that moves the §9 rung (see docs/PTC.md, docs/tce-signing-shape.md).

Shape (decided in docs/tce-signing-shape.md), name-agnostic:

  * The signature is over a **DSSE** pre-authentication encoding (PAE) of an
    **in-toto-style statement**: ``subject`` = a hash of the actual inline
    payload, plus the raw-original reference when the envelope names one,
    ``predicate`` = the ordered provenance hops. DSSE is the structural fit for
    a chain predicate and its PAE signing is language-portable.
  * Signing is **per envelope**: the sending broker signs the full chain as it
    leaves its zone (``covers`` = ``len(provenance)``), preserved upstream hops
    included. Inbound signatures are not carried across a relay
    (channels/SIGNING.md S2).
  * Keys are **Ed25519** (asymmetric → non-repudiation: a receiver holds only the
    public key and cannot forge a sender's chain). The private key belongs to the
    broker's workload identity and is resolved by the broker at cold start — the
    agent never holds it (agent-holds-no-credentials).

This module is pure and key-injected: it never reads a secret or the wall clock.
Cold-start key resolution (``BROKER_SIGNING_KEY_SECRET_ARN`` → private key;
verification-key map → public keys) lives in the transport bindings, mirroring
the grant-HMAC ``_resolve_hmac_key`` seam.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Callable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from safe_agents.channels.schemas import ChainSignature, EventTrigger, ProvenanceEntry

# The DSSE payloadType and in-toto statement/predicate type URIs. Name-agnostic
# (no PTC/TCE) pending the maintainer's LF naming pass; the predicate type is versioned so a
# future normative wire schema can bump it.
#
# v2 (GHSA-wfrf-hcqh-pw8x): v1 bound the declared ``payload_digest`` IN PLACE OF
# the inline payload whenever a ``payload_ref`` was present, and did not bind the
# reference at all, so a signed inline envelope verified with its payload
# swapped. v2 always binds the inline payload and binds the reference beside it.
# The statement changed shape, so the URI moved rather than being redefined in
# place; a v2 verifier rejects a v1 signature.
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://safe-agents.dev/provenance-chain/v2"

# The one digest algorithm `payload_digest` may name, and the only spelling of a
# digest the statement will bind: lowercase hex, nothing before or after. One
# raw original must have exactly one signed spelling, so this does not normalize.
# EventTrigger enforces the same shape on the wire.
DIGEST_ALGORITHM = "sha256"
_RAW_DIGEST_RE = re.compile(rf"{DIGEST_ALGORITHM}:([0-9a-f]{{64}})")

# A key resolver maps a signature's ``key_id`` to the verifying public key, or
# None when the signer is unknown (→ the chain is quarantined). The airlock
# closes one over its cold-start verification-key map, exactly as `dispatch`'s
# `screen` seam is injected.
KeyResolver = Callable[[str], Ed25519PublicKey | None]


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

# Drop/quarantine reasons — kept here so the airlock gate and its DropReason
# literal stay in lockstep with what verification can actually return.
SIGNATURE_MISSING = "chain_signature_missing"
SIGNATURE_INVALID = "chain_signature_invalid"
SIGNER_UNKNOWN = "chain_signer_unknown"


@dataclass(frozen=True)
class ChainVerifyResult:
    """Outcome of verifying an envelope's chain signatures.

    ``reason`` is one of the ``SIGNATURE_*`` / ``SIGNER_UNKNOWN`` constants on
    failure, else None. On failure the airlock quarantines the chain and drops —
    never treats an unverified chain as authoritative (mirrors the grant-HMAC
    quarantine).

    ``signer_key_id``/``signer_zone`` are evidence-of-check (per the campaign watchdog and
    the ``sig:pass`` provenance-hop precedent in ``channels/SIGNING.md``): on
    success they name the signer of the FULL-COVER signature — the sending
    broker's commitment to the chain as it left its zone — so a downstream
    watchdog can attribute the event at the authentication strength the
    airlock actually verified. They stay None on any failure; a gate that
    didn't verify must never name a signer it didn't check.
    """

    ok: bool
    reason: str | None = None
    signer_key_id: str | None = None
    signer_zone: str | None = None


# ---------------------------------------------------------------------------
# Canonical statement + DSSE PAE
# ---------------------------------------------------------------------------


def _inline_payload_hex(payload: dict) -> str:
    """The 64-hex sha256 of the canonical inline ``payload``."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_identity(raw: str) -> str:
    """The one identity-canonicalization rule, mirrored from the adapters.

    Must produce byte-identical output to `SignedWebhookAdapter`'s and
    `OwnerInboundAdapter`'s own `_canonical_identity` (`safe_agents/channels/
    webhook.py`, `safe_agents/channels/owner.py`) — duplicated here rather than
    imported, matching those two modules' own duplication of each other,
    because `signing.py` stays adapter-free. Applied at BOTH sign time
    (`BoundContext` construction in `stamp_outbound`) and verify time
    (`BoundContext.of`) so an honest signer's wire spelling and the post-
    `normalize` canonical form the receiver's gate 3.5 actually sees always
    agree, regardless of which side canonicalized first (idempotent).
    """
    return raw.strip().casefold()


@dataclass(frozen=True)
class BoundContext:
    """The envelope fields every signature commits to, beyond its hop prefix.

    Binding these into the signed statement is what makes the signature more
    than a bare chain assertion: the payload (so it can't be swapped) and the
    raw-original reference beside it (``_subjects``), the anti-replay identity — ``event_id``/``principal``/``expiry`` — so a valid
    signed envelope cannot be replayed under a fresh dedupe key or an extended
    TTL (the airlock's expiry gate keys on exactly these), and
    ``sender_channel_identity`` — so a valid signed envelope cannot be replayed
    under a fresh *dedupe* key either. ``EventTrigger.dedupe_key()`` is
    ``(sender.channel_identity, event_id)``; before this field existed,
    ``sender.channel_identity`` rode outside the signature entirely, so a
    captured signed envelope could be replayed with a mutated sender claim,
    landing a fresh dedupe key (and, pre-dedupe, a fresh watchdog attribution
    bucket) without ever breaking the signature (`channels/WATCHDOG.md`
    §"Replay soundness"). Canonicalized via `canonical_identity` so an honest
    signer's wire spelling and the receiver's post-`normalize` form always
    agree.
    """

    payload: dict
    payload_digest: str | None
    payload_ref: str | None
    event_id: str
    principal: str
    expiry: str
    sender_channel_identity: str

    @classmethod
    def of(cls, envelope: EventTrigger) -> "BoundContext":
        return cls(
            payload=envelope.payload,
            payload_digest=envelope.payload_digest,
            payload_ref=envelope.payload_ref,
            event_id=envelope.event_id,
            principal=envelope.principal,
            expiry=envelope.expiry,
            sender_channel_identity=canonical_identity(envelope.sender.channel_identity),
        )


def _subjects(context: BoundContext) -> list[dict]:
    """The statement's subjects: what the signature commits the content to.

    The first subject is ALWAYS a hash of the *actual* inline ``payload``, which
    the receiver recomputes from the envelope it was handed, whatever else that
    envelope carries. No field on the envelope can stand in for it.

    When the envelope names a raw original, a second subject binds its
    ``payload_digest`` and, when set, its ``payload_ref``. Whether that subject
    exists is therefore signed too: a reference or digest cannot be attached to,
    changed on, or stripped from a signed envelope. That the bytes behind the
    reference match the digest is the dereferencing zone's check, not this one's
    (reference-tier, channels/SCHEMAS.md).

    A reference with no digest, or a digest this statement cannot name, raises:
    signing must refuse rather than leave part of the envelope outside the
    bound set, and a verifier treats the same condition as a failed signature.
    """
    subjects: list[dict] = [
        {"name": "payload", "digest": {DIGEST_ALGORITHM: _inline_payload_hex(context.payload)}}
    ]
    if context.payload_digest is None:
        if context.payload_ref is not None:
            raise ValueError("payload_ref set requires payload_digest to also be set")
        return subjects
    matched = _RAW_DIGEST_RE.fullmatch(context.payload_digest)
    if matched is None:
        raise ValueError(
            f"payload_digest must be '{DIGEST_ALGORITHM}:<64 lowercase hex>': "
            f"{context.payload_digest!r}"
        )
    raw_original: dict = {"name": "raw_original", "digest": {DIGEST_ALGORITHM: matched.group(1)}}
    if context.payload_ref is not None:
        raw_original["uri"] = context.payload_ref
    subjects.append(raw_original)
    return subjects


def build_statement(
    provenance_prefix: Sequence[ProvenanceEntry],
    context: BoundContext,
    *,
    key_id: str,
    zone: str,
) -> bytes:
    """Serialize the in-toto statement a single signature commits to.

    Canonical JSON (sorted keys, no whitespace, ASCII) so sign and verify agree
    byte-for-byte. ``subject`` binds the inline payload and any raw-original
    reference (``_subjects``); ``predicate.hops`` is the hop
    prefix; ``predicate.signer`` binds this signature's ``key_id``/``zone`` (so
    per-hop attribution is non-malleable — an attacker cannot relabel who signed
    without breaking the signature); ``predicate.envelope`` binds the anti-replay
    identity, INCLUDING the canonicalized ``sender_channel_identity`` — the
    dedupe key's sender half (`BoundContext`'s docstring).
    """
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": _subjects(context),
        "predicate": {
            "hops": [entry.model_dump(mode="json") for entry in provenance_prefix],
            "signer": {"key_id": key_id, "zone": zone},
            "envelope": {
                "event_id": context.event_id,
                "principal": context.principal,
                "expiry": context.expiry,
                "sender_channel_identity": context.sender_channel_identity,
            },
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (the bytes actually signed/verified).

    ``DSSEv1 <len(type)> <type> <len(payload)> <payload>`` — the standard PAE
    that binds the payloadType to the payload so a signature can't be replayed
    under a different type.
    """
    return b"".join(
        [
            b"DSSEv1 ",
            str(len(payload_type)).encode("utf-8"),
            b" ",
            payload_type.encode("utf-8"),
            b" ",
            str(len(payload)).encode("utf-8"),
            b" ",
            payload,
        ]
    )


# ---------------------------------------------------------------------------
# Key (de)serialization — the broker resolves these at cold start, never here
# ---------------------------------------------------------------------------


def load_private_key(pem: str | bytes) -> Ed25519PrivateKey:
    """Parse a PEM-encoded Ed25519 private key (the broker's signing key)."""
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be an Ed25519 private key")
    return key


def load_public_key(pem: str | bytes) -> Ed25519PublicKey:
    """Parse a PEM-encoded Ed25519 public key (a peer broker's verify key)."""
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("verification key must be an Ed25519 public key")
    return key


# ---------------------------------------------------------------------------
# Signer — the sender-side seam stamp_outbound calls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainSigner:
    """A broker-held Ed25519 signing identity.

    Bundles the private key with the ``key_id`` a receiver resolves and the
    ``zone`` the hop is attributed to. Constructed at broker cold start from a
    Secrets-Manager-held key (never in the agent image); passed into
    ``stamp_outbound`` so the module stays pure.
    """

    key_id: str
    zone: str
    _private_key: Ed25519PrivateKey

    def sign_prefix(
        self,
        provenance_prefix: Sequence[ProvenanceEntry],
        context: BoundContext,
    ) -> ChainSignature:
        """Sign the chain prefix this broker commits to, as it leaves this zone.

        The signature binds the prefix, the payload and anti-replay identity
        (``context``), and this signer's own ``key_id``/``zone`` — so neither the
        signed content nor its attribution can be altered without breaking it.
        """
        statement = build_statement(
            provenance_prefix, context, key_id=self.key_id, zone=self.zone
        )
        sig = self._private_key.sign(pae(DSSE_PAYLOAD_TYPE, statement))
        return ChainSignature(
            key_id=self.key_id,
            zone=self.zone,
            covers=len(provenance_prefix),
            payload_type=DSSE_PAYLOAD_TYPE,
            sig=base64.b64encode(sig).decode("ascii"),
        )


def signer_from_pem(key_id: str, zone: str, pem: str | bytes) -> ChainSigner:
    """Build a ChainSigner from a PEM private key (cold-start convenience)."""
    return ChainSigner(key_id=key_id, zone=zone, _private_key=load_private_key(pem))


# ---------------------------------------------------------------------------
# Verifier — the receiver-side seam the airlock gate calls
# ---------------------------------------------------------------------------


def _verify_one(
    signature: ChainSignature,
    provenance: Sequence[ProvenanceEntry],
    context: BoundContext,
    public_key: Ed25519PublicKey,
) -> bool:
    prefix = provenance[: signature.covers]
    try:
        # Rebuild the statement with the signature's OWN key_id/zone: an attacker
        # who rewrites those fields produces a statement the signer never signed
        # → fail. Inside the try: a reference or digest the statement cannot name
        # (`_subjects` raises) is a failed signature, not an exception escaping
        # the gate.
        statement = build_statement(
            prefix, context, key_id=signature.key_id, zone=signature.zone
        )
        public_key.verify(base64.b64decode(signature.sig), pae(signature.payload_type, statement))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_chain(envelope: EventTrigger, key_resolver: KeyResolver) -> ChainVerifyResult:
    """Verify every chain signature and require full coverage of the chain.

    Fails closed (mirrors grant-HMAC):

      * no signatures at all → ``SIGNATURE_MISSING``;
      * a signer whose ``key_id`` the resolver doesn't know → ``SIGNER_UNKNOWN``;
      * ``covers`` outside ``[1, len(provenance)]``, a signature whose declared
        ``zone`` isn't the top hop it covers, or a bad signature →
        ``SIGNATURE_INVALID``;
      * no signature covers the full chain (so the sending broker didn't commit
        to the hop it just added) → ``SIGNATURE_INVALID``.

    Every present signature must verify — a valid full-cover signature does not
    excuse a forged prefix signature riding alongside it. The signed statement
    binds the inline payload, the raw-original reference and digest when the
    envelope carries them, the anti-replay identity (``event_id``/``principal``/
    ``expiry``/``sender.channel_identity``), and the signature's own
    ``key_id``/``zone``, so none of those can be altered post-signature; the
    zone-matches-top-hop check ties each signature to the hop its broker
    actually added (per-hop attribution). Binding ``sender.channel_identity``
    closes the dedupe-key replay hole: `EventTrigger.dedupe_key()` is
    ``(sender.channel_identity, event_id)``, so a captured signature that didn't
    bind the sender half could be replayed under a mutated sender claim without
    invalidating the signature (`channels/WATCHDOG.md` §"Replay soundness").
    """
    signatures = envelope.chain_signatures
    if not signatures:
        return ChainVerifyResult(ok=False, reason=SIGNATURE_MISSING)

    context = BoundContext.of(envelope)
    n = len(envelope.provenance)
    for signature in signatures:
        if not 1 <= signature.covers <= n:
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)
        if envelope.provenance[signature.covers - 1].zone != signature.zone:
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)
        public_key = key_resolver(signature.key_id)
        if public_key is None:
            return ChainVerifyResult(ok=False, reason=SIGNER_UNKNOWN)
        if not _verify_one(signature, envelope.provenance, context, public_key):
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)

    full_cover = next((signature for signature in signatures if signature.covers == n), None)
    if full_cover is None:
        return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)

    return ChainVerifyResult(ok=True, signer_key_id=full_cover.key_id, signer_zone=full_cover.zone)


def make_gate(key_resolver: KeyResolver | None) -> Callable[[EventTrigger], ChainVerifyResult] | None:
    """Build the airlock verify gate, or None when verification ships OFF.

    Returns None when ``key_resolver`` is None (no required signers configured) —
    the airlock skips the gate and unsigned peers pass, today's behavior
    (docs/friction-doctrine.md: every bound is a knob shipping OFF). When a
    resolver is supplied, the returned callable is `dispatch`'s verify seam.
    """
    if key_resolver is None:
        return None
    return lambda envelope: verify_chain(envelope, key_resolver)
