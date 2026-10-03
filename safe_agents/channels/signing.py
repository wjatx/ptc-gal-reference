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
    ``predicate`` = the ordered provenance hops, the signer, and every other
    field of the envelope except the two named in ``UNSIGNED_FIELDS``. DSSE is
    the structural fit for a chain predicate and its PAE signing is
    language-portable.
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
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from safe_agents.channels.schemas import ChainSignature, EventTrigger

# The DSSE payloadType and in-toto statement/predicate type URIs. Name-agnostic
# (no PTC/TCE) pending the maintainer's LF naming pass; the predicate type is versioned so a
# future normative wire schema can bump it.
#
# v1 (GHSA-wfrf-hcqh-pw8x) bound the declared ``payload_digest`` IN PLACE OF
# the inline payload whenever a ``payload_ref`` was present, and did not bind the
# reference at all, so a signed inline envelope verified with its payload
# swapped. v1 also signed an enumerated list of envelope fields, and that list
# was found short three times (the sender identity, the reference, then ``ts``
# and ``sender.evidence``). The statement now always binds the inline payload,
# binds the reference beside it, and signs the whole envelope by default: the fields left
# out are the ones named in ``UNSIGNED_FIELDS``, not the ones somebody
# remembered to put in.
#
# Each change of shape moved the URI rather than redefining it in place. v2 was
# the first of the two fixes alone and existed on the main branch for a day; v3
# is the statement described here. A verifier rejects every other version.
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://safe-agents.dev/provenance-chain/v3"

# The one digest algorithm `payload_digest` may name, and the only spelling of a
# digest the statement will bind: lowercase hex, nothing before or after. One
# raw original must have exactly one signed spelling, so this does not normalize.
# EventTrigger enforces the same shape on the wire.
DIGEST_ALGORITHM = "sha256"
_RAW_DIGEST_RE = re.compile(rf"{DIGEST_ALGORITHM}:([0-9a-f]{{64}})")

# A key resolver maps a ``key_id`` to its public key, or None when the key is
# unknown. The grant-record, acknowledgment and tool-admission signers share
# this shape; the provenance chain uses the scoped `PeerKeyResolver` below.
KeyResolver = Callable[[str], Ed25519PublicKey | None]

# The posture a receiver records for a signer, on the posture ladder of
# docs/posture-ladder.md. Posture 1 is a local wrapper: the signing key sits
# under the same OS user as the signer's agent, so the agent can reach it. At
# posture 2 and above the key is on the far side of a boundary the signer's
# platform enforces.
SIGNER_POSTURES = frozenset({1, 2, 3})
AGENT_SEPARATED_MIN_POSTURE = 2

# Evidence classes of a custody record (PTC-SPEC §7.1). The vocabulary is closed.
# ``declared`` is the receiver's operator writing down what was established
# with the peer's operator out of band: the receiver checks nothing. ``attested``
# is a reserved name for evidence a receiver can check. No procedure in this
# version produces it, so configuration load refuses it (`keys._peer_key`).
CUSTODY_DECLARED = "declared"
CUSTODY_ATTESTED = "attested"
CUSTODY_EVIDENCE_CLASSES = frozenset({CUSTODY_DECLARED, CUSTODY_ATTESTED})
ACCEPTED_CUSTODY_EVIDENCE = frozenset({CUSTODY_DECLARED})
# Weakest first. A statement resting on several records names the weakest.
_CUSTODY_EVIDENCE_STRENGTH = {CUSTODY_DECLARED: 0, CUSTODY_ATTESTED: 1}

# The prefix of the hop-evidence entry a receiver stamps when every signature
# on a chain it verified was made by a key recorded in agent-separated custody,
# e.g. ``custody:declared``. The entry names a record consulted. It is never
# evidence of a check performed on the peer.
CUSTODY_EVIDENCE_PREFIX = "custody:"


def weakest_custody_evidence(classes: Iterable[str]) -> str | None:
    """The weakest evidence class among ``classes``, or None when there are none."""
    return min(classes, key=_CUSTODY_EVIDENCE_STRENGTH.__getitem__, default=None)


@dataclass(frozen=True)
class PeerKey:
    """A peer broker's verification key, what it may sign for, and its custody record.

    Being known to the receiver does not let a key speak for every peer. Without
    a scope, any enrolled broker could sign an envelope naming another broker's
    zone and identity, and the receiver would record it as verified.

    ``zone`` is the one zone whose hops this key may sign. ``sender_identities``
    are the ``sender.channel_identity`` values, in canonical form, that an
    envelope this key signs in full may claim. Both come from the receiver's own
    configuration, never from the envelope.

    ``signer_posture`` and ``custody_evidence`` are the custody record: the
    posture (docs/posture-ladder.md) the receiver's operator recorded for the
    signer, and the evidence class of that record. Both are also the receiver's
    own configuration. The record is an assumption about the peer written down
    where a gate can read it and an audit can question it. Nothing here checks
    the peer, and the record has no bearing on whether a signature verifies.
    """

    public_key: Ed25519PublicKey
    zone: str
    sender_identities: frozenset[str]
    signer_posture: int
    custody_evidence: str

    @property
    def agent_separated_custody(self) -> bool:
        """Whether the record says the signer's agent cannot reach this key.

        True from posture 2 up. At posture 1 the key sits under the same OS
        user as the signer's agent, and an agent under injection can produce a
        chain that verifies.
        """
        return self.signer_posture >= AGENT_SEPARATED_MIN_POSTURE


# Maps a signature's ``key_id`` to the scoped key, or None when the signer is
# unknown (→ the chain is quarantined). The airlock closes one over its
# cold-start verification-key map, exactly as `dispatch`'s `screen` seam is
# injected.
PeerKeyResolver = Callable[[str], PeerKey | None]


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

# Drop/quarantine reasons — kept here so the airlock gate and its DropReason
# literal stay in lockstep with what verification can actually return.
SIGNATURE_MISSING = "chain_signature_missing"
SIGNATURE_INVALID = "chain_signature_invalid"
SIGNER_UNKNOWN = "chain_signer_unknown"

# Machine codes for a drop record's ``detail``, both under SIGNATURE_INVALID: a
# known key used outside the scope the receiver configured for it. The reason
# stays in the forgery class, because the envelope claims an origin its signer
# may not speak for.
SIGNER_ZONE_MISMATCH = "signer_zone_mismatch"
SIGNER_IDENTITY_OUT_OF_SCOPE = "signer_identity_out_of_scope"


@dataclass(frozen=True)
class ChainVerifyResult:
    """Outcome of verifying an envelope's chain signatures.

    ``reason`` is one of the ``SIGNATURE_*`` / ``SIGNER_UNKNOWN`` constants on
    failure, else None. On failure the airlock quarantines the chain and drops —
    never treats an unverified chain as authoritative (mirrors the grant-HMAC
    quarantine). ``detail`` narrows a failure with one of the ``SIGNER_*`` machine
    codes above, or is None.

    ``signer_key_id``/``signer_zone`` are evidence-of-check (per the campaign watchdog and
    the ``sig:pass`` provenance-hop precedent in ``channels/SIGNING.md``): on
    success they name the signer of the first signature — the sending
    broker's commitment to the envelope as it left its zone — so a downstream
    watchdog can attribute the event at the authentication strength the
    airlock actually verified. They stay None on any failure; a gate that
    didn't verify must never name a signer it didn't check.

    ``agent_separated_custody``/``custody_evidence`` report the custody records
    of the keys that signed (channels/SIGNING.md S10). On success the first is
    True only when EVERY signature was made by a key recorded in agent-separated
    custody, and the second is the weakest evidence class among those keys'
    records. They report records the receiver consulted in its own
    configuration, never a check performed on the peer. On any failure they
    stay at False and None, under the same rule as the signer fields.
    """

    ok: bool
    reason: str | None = None
    signer_key_id: str | None = None
    signer_zone: str | None = None
    detail: str | None = None
    agent_separated_custody: bool = False
    custody_evidence: str | None = None


# ---------------------------------------------------------------------------
# Canonical statement + DSSE PAE
# ---------------------------------------------------------------------------

# How each top-level EventTrigger field relates to the signed statement. A field
# named in none of these three sets is signed as part of ``predicate.envelope``,
# so a field added to the envelope later is bound without anyone remembering to
# add it. test_signing.py asserts the partition covers the model.
#
#   SUBJECT_FIELDS   bound as the statement's subjects (`_subjects`).
#   HOP_FIELDS       bound as ``predicate.hops``, every hop in order.
#   UNSIGNED_FIELDS  outside the signature, each for a reason: ``sender_class``
#                    is the receiver's to set and the receiver discards the wire
#                    value; ``chain_signatures`` are the signatures themselves.
SUBJECT_FIELDS = frozenset({"payload", "payload_digest", "payload_ref"})
HOP_FIELDS = frozenset({"provenance"})
UNSIGNED_FIELDS = frozenset({"sender_class", "chain_signatures"})


def _inline_payload_hex(payload: dict) -> str:
    """The 64-hex sha256 of the canonical inline ``payload``.

    Refuses a payload JSON cannot carry as given (NaN, a non-string key, a
    tuple). Such a payload is rewritten on the way to the wire, so a signature
    over the in-process value would cover content the receiver never sees.
    """
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    if json.loads(canonical) != payload:
        raise ValueError("payload does not survive a JSON round trip unchanged")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_identity(raw: str) -> str:
    """The one identity-canonicalization rule, mirrored from the adapters.

    Must produce byte-identical output to `SignedWebhookAdapter`'s and
    `OwnerInboundAdapter`'s own `_canonical_identity` (`safe_agents/channels/
    webhook.py`, `safe_agents/channels/owner.py`) — duplicated here rather than
    imported, matching those two modules' own duplication of each other,
    because `signing.py` stays adapter-free. Applied by `bound_envelope` at both
    sign time and verify time, so an honest signer's wire spelling and the post-
    `normalize` canonical form the receiver's gate 3.5 actually sees always
    agree, regardless of which side canonicalized first (idempotent).
    """
    return raw.strip().casefold()


def bound_envelope(envelope: EventTrigger) -> dict:
    """The envelope fields a signature commits to beyond its subjects and hops.

    Everything on the envelope except the fields bound elsewhere in the
    statement and the two in ``UNSIGNED_FIELDS``. This is what makes a signature
    more than a bare chain assertion: the anti-replay identity
    (``event_id``/``principal``/``expiry``), so a valid signed envelope cannot be
    replayed under a fresh dedupe key or an extended TTL; ``audience``, so an
    envelope signed for one receiver cannot be re-addressed to another; the
    whole sender claim; and ``ts``, which receivers record.

    ``sender.channel_identity`` is the one value bound in canonical form.
    ``EventTrigger.dedupe_key()`` is ``(sender.channel_identity, event_id)``, so
    leaving it out would let a captured envelope be replayed under a mutated
    sender claim (`channels/WATCHDOG.md` §"Replay soundness"), and binding the
    wire spelling would fail an honest sender whose spelling the receiver's
    `normalize` canonicalizes before the gate runs.
    """
    view = envelope.model_dump(
        mode="json", exclude=set(SUBJECT_FIELDS | HOP_FIELDS | UNSIGNED_FIELDS)
    )
    view["sender"]["channel_identity"] = canonical_identity(envelope.sender.channel_identity)
    return view


def _subjects(envelope: EventTrigger) -> list[dict]:
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
        {"name": "payload", "digest": {DIGEST_ALGORITHM: _inline_payload_hex(envelope.payload)}}
    ]
    if envelope.payload_digest is None:
        if envelope.payload_ref is not None:
            raise ValueError("payload_ref set requires payload_digest to also be set")
        return subjects
    matched = _RAW_DIGEST_RE.fullmatch(envelope.payload_digest)
    if matched is None:
        raise ValueError(
            f"payload_digest must be '{DIGEST_ALGORITHM}:<64 lowercase hex>': "
            f"{envelope.payload_digest!r}"
        )
    raw_original: dict = {"name": "raw_original", "digest": {DIGEST_ALGORITHM: matched.group(1)}}
    if envelope.payload_ref is not None:
        raw_original["uri"] = envelope.payload_ref
    subjects.append(raw_original)
    return subjects


def build_statement(envelope: EventTrigger, *, key_id: str, zone: str) -> bytes:
    """Serialize the in-toto statement a single signature commits to.

    Canonical JSON (sorted keys, no whitespace, ASCII) so sign and verify agree
    byte-for-byte. ``subject`` binds the inline payload and any raw-original
    reference (`_subjects`); ``predicate.hops`` is the whole provenance chain, in
    order; ``predicate.signer`` binds this signature's ``key_id``/``zone`` (so
    attribution is non-malleable — an attacker cannot relabel who signed without
    breaking the signature); ``predicate.envelope`` binds every other signed
    field (`bound_envelope`).

    Every signature covers the full chain. A statement over a prefix would say
    nothing about the hops after it, and it would be byte-identical to a
    full-cover statement for the envelope with those later hops removed, so a
    party with no key could cut a chain back to it.
    """
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": _subjects(envelope),
        "predicate": {
            "hops": [entry.model_dump(mode="json") for entry in envelope.provenance],
            "signer": {"key_id": key_id, "zone": zone},
            "envelope": bound_envelope(envelope),
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

    def sign_envelope(self, envelope: EventTrigger) -> ChainSignature:
        """Sign the envelope as it leaves this zone.

        Takes the finished envelope, never a set of fields beside it, so what is
        signed and what is sent cannot differ. The signature binds the whole
        chain, the content, every other signed field, and this signer's own
        ``key_id``/``zone`` — so neither the signed content nor its attribution
        can be altered without breaking it.

        Refuses (``ValueError``) an envelope that cannot make the trip in wire
        form (`EventTrigger.to_wire`): signing it would produce a signature over
        content the receiver can never be handed.
        """
        envelope.to_wire()
        statement = build_statement(envelope, key_id=self.key_id, zone=self.zone)
        sig = self._private_key.sign(pae(DSSE_PAYLOAD_TYPE, statement))
        return ChainSignature(
            key_id=self.key_id,
            zone=self.zone,
            covers=len(envelope.provenance),
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
    signature: ChainSignature, envelope: EventTrigger, public_key: Ed25519PublicKey
) -> bool:
    try:
        # Rebuild the statement with the signature's OWN key_id/zone: an attacker
        # who rewrites those fields produces a statement the signer never signed
        # → fail. Inside the try: content the statement cannot name (`_subjects`
        # and `_inline_payload_hex` raise) is a failed signature, not an
        # exception escaping the gate.
        statement = build_statement(envelope, key_id=signature.key_id, zone=signature.zone)
        public_key.verify(
            base64.b64decode(signature.sig, validate=True),
            pae(signature.payload_type, statement),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_chain(envelope: EventTrigger, key_resolver: PeerKeyResolver) -> ChainVerifyResult:
    """Verify every chain signature; each must cover, and be scoped to, the whole envelope.

    Fails closed (mirrors grant-HMAC):

      * no signatures at all → ``SIGNATURE_MISSING``;
      * a signer whose ``key_id`` the resolver doesn't know → ``SIGNER_UNKNOWN``;
      * a ``covers`` that is not the full chain, a ``payload_type`` other than
        the one DSSE type, a signature whose declared ``zone`` isn't the top
        hop, or a bad signature → ``SIGNATURE_INVALID``;
      * a key signing for a zone other than its own, or from a key not scoped
        to the envelope's ``sender.channel_identity`` → ``SIGNATURE_INVALID``,
        with a ``detail`` naming which.

    Every present signature must pass every check — one good signature does not
    excuse another that fails. The signed statement binds the inline payload,
    the raw-original reference and digest when the envelope carries them, the
    whole chain, every other field of the envelope outside ``UNSIGNED_FIELDS``,
    and the signature's own ``key_id``/``zone``, so none of those can be altered
    post-signature. The zone-matches-top-hop check ties each signature to the
    hop its broker added, and the key's own scope ties that broker to the zone
    and sender identity it is enrolled for.

    A key's custody record takes no part in any of that. A chain signed by a
    key recorded at posture 1 passes or fails on the checks above; the result
    then reports that not every signing key is in agent-separated custody.
    """
    signatures = envelope.chain_signatures
    if not signatures:
        return ChainVerifyResult(ok=False, reason=SIGNATURE_MISSING)

    n = len(envelope.provenance)
    sender_identity = canonical_identity(envelope.sender.channel_identity)
    signing_keys: list[PeerKey] = []
    for signature in signatures:
        if signature.covers != n or signature.payload_type != DSSE_PAYLOAD_TYPE:
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)
        if envelope.provenance[n - 1].zone != signature.zone:
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)
        key = key_resolver(signature.key_id)
        if key is None:
            return ChainVerifyResult(ok=False, reason=SIGNER_UNKNOWN)
        if key.zone != signature.zone:
            return ChainVerifyResult(
                ok=False, reason=SIGNATURE_INVALID, detail=SIGNER_ZONE_MISMATCH
            )
        if not _verify_one(signature, envelope, key.public_key):
            return ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID)
        # After the signature verified: the key that vouches for the envelope
        # must be scoped to its sender.
        if sender_identity not in key.sender_identities:
            return ChainVerifyResult(
                ok=False, reason=SIGNATURE_INVALID, detail=SIGNER_IDENTITY_OUT_OF_SCOPE
            )
        signing_keys.append(key)

    first = signatures[0]
    return ChainVerifyResult(
        ok=True,
        signer_key_id=first.key_id,
        signer_zone=first.zone,
        agent_separated_custody=all(key.agent_separated_custody for key in signing_keys),
        custody_evidence=weakest_custody_evidence(key.custody_evidence for key in signing_keys),
    )


def make_gate(
    key_resolver: PeerKeyResolver | None,
) -> Callable[[EventTrigger], ChainVerifyResult] | None:
    """Build the airlock verify gate, or None when verification ships OFF.

    Returns None when ``key_resolver`` is None (no required signers configured) —
    the airlock skips the gate and unsigned peers pass, today's behavior
    (docs/friction-doctrine.md: every bound is a knob shipping OFF). When a
    resolver is supplied, the returned callable is `dispatch`'s verify seam.
    """
    if key_resolver is None:
        return None
    return lambda envelope: verify_chain(envelope, key_resolver)


# ---------------------------------------------------------------------------
# Provenance maturity the receiver's records support (channels/SIGNING.md S10)
# ---------------------------------------------------------------------------

# The two maturities a receiver's verification configuration can distinguish.
# The strings are the ones `safe_agents/broker/grants/predicate.py` names in
# `ProvenanceMaturity`. They are restated here because this module imports
# nothing from the broker, and `test_signing.py` holds the two in step.
MATURITY_LINEAGE = "lineage"
MATURITY_SIGNED_LINEAGE = "signed-lineage"


@dataclass(frozen=True)
class ProvenanceTier:
    """A provenance maturity and, at ``signed-lineage``, the evidence class under it.

    ``custody_evidence`` is None below ``signed-lineage``. At ``signed-lineage``
    it is always set, because the class travels with the tier (PTC-SPEC §7.1):
    a statement of ``signed-lineage`` that omits the class reads as stronger
    than the records behind it. ``declared`` means the tier rests on an
    operator's written statement about each signing peer, which the receiver
    has not checked.
    """

    maturity: str
    custody_evidence: str | None = None


_LINEAGE_TIER = ProvenanceTier(maturity=MATURITY_LINEAGE)


def deployment_provenance_tier(
    *, verification_configured: bool, enrolled_keys: Iterable[PeerKey]
) -> ProvenanceTier:
    """The maturity a receiver's verification configuration supports, as a whole.

    ``signed-lineage`` only when verification is configured, at least one key is
    enrolled, and every enrolled key is recorded in agent-separated custody.
    One enrolled key recorded otherwise holds the deployment at ``lineage``: a
    grant's rung is held per capability, and nothing downstream of the airlock
    separates what that key's traffic influenced from the rest.

    Zero enrolled keys is ``lineage``. A receiver that enrols nobody accepts no
    signed chain, so it has no custody record to rest the higher tier on, and
    "every enrolled key" must not be satisfied by there being none.

    This reads the receiver's own records and nothing else. It does not feed
    the promotion predicate, whose maturity is still a proposer assertion.
    """
    keys = tuple(enrolled_keys)
    if not verification_configured or not keys:
        return _LINEAGE_TIER
    if not all(key.agent_separated_custody for key in keys):
        return _LINEAGE_TIER
    return ProvenanceTier(
        maturity=MATURITY_SIGNED_LINEAGE,
        custody_evidence=weakest_custody_evidence(key.custody_evidence for key in keys),
    )


def envelope_provenance_tier(result: ChainVerifyResult | None) -> ProvenanceTier:
    """The maturity one envelope's verification result supports.

    ``result`` is what the verify gate returned for the envelope, or None when
    the gate did not run on it (verification off, or an envelope the receiving
    adapter built itself). ``signed-lineage`` only when the gate ran, passed,
    and every signature was made by a key recorded in agent-separated custody.
    Everything else is ``lineage``, including a result that failed: the airlock
    drops that envelope, and this function never reports it above the floor.
    """
    if (
        result is None
        or not result.ok
        or not result.agent_separated_custody
        or result.custody_evidence is None
    ):
        return _LINEAGE_TIER
    return ProvenanceTier(
        maturity=MATURITY_SIGNED_LINEAGE, custody_evidence=result.custody_evidence
    )
