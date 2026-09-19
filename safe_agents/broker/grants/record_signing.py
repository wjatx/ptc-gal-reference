"""grants.record_signing — sign the promotion-record ledger (lifecycle Phase 4).

Turns a PromotionRecord from *asserted* into *non-repudiable*: who proposed, who
ratified, over which evidence window, under which in-force envelopeHash. This is
the SECOND statement type carried by the #181 signing machinery (adopt, don't
invent) — the same DSSE PAE over an in-toto-style statement that authenticates
the outbound provenance chain, reused here for the ceremony ledger
(broker/grant-lifecycle.md, docs/tce-signing-shape.md).

Shape, name-agnostic:

  * The signature is over a **DSSE** pre-authentication encoding (PAE) of an
    **in-toto-style statement**: ``subject`` = the sha256 of the canonical
    record JSON (binding the FULL record), ``predicate`` = the signer identity
    plus the record's audit-index fields in the clear (recordType, ts,
    actionClass, proposedBy, ratifiedBy, envelopeHash) so a verifier/auditor
    can index without parsing the payload.
  * The signing key belongs to one of TWO Ed25519 identities, both separate
    from the broker's chain-signing key. The **issuer** signs the ceremony /
    operator side (``promotion``, ``bootstrap``, ``tightening``); the
    **evaluator** — the separate system identity of GAL §6.7.2, the automatic
    no-model side — signs ``demotion`` and ``lapse``. Handing the evaluator the
    issuer key would let it mint promotion records, collapsing the ceremony
    boundary, so the split is a second KEY, not a field on one key. The broker
    holds neither, symmetric with "the broker cannot write grants", and neither
    private key is ever in the agent image (agent-holds-no-credentials).
  * The resulting DSSE envelope is stored as a storage-layer attribute BESIDE
    the ledger item's record blob — never a field on the PromotionRecord schema
    itself (SCHEMAS.md §7 is frozen; the signature wraps the record).

This module is pure and key-injected: it never reads a secret, an env var, or
the wall clock. Cold-start key resolution (``ISSUER_SIGNING_KEY_SECRET_ARN`` /
``EVALUATOR_SIGNING_KEY_SECRET_ARN`` → private key; ``*_SIGNING_KEY_ID``)
belongs to the command-side binding in ``grants.issuer_keys``, mirroring
channels.keys — never here. What IS here is the pure half of the role rule:
the record-type → role MAPPING, and a verifier that selects the resolver by
that mapping so a key of the wrong role fails closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.schemas.promotion_record import PromotionRecord
from safe_agents.channels.signing import (
    DSSE_PAYLOAD_TYPE,
    STATEMENT_TYPE,
    KeyResolver,
    load_private_key,
    pae,
)

# The in-toto predicate type for a signed promotion record. Name-agnostic and
# versioned, same convention as the chain predicate type in channels.signing —
# a future normative wire schema can bump it.
RECORD_PREDICATE_TYPE = "https://safe-agents.dev/promotion-record/v1"


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

# Quarantine reasons — module-level constants so the ledger reader and any
# audit surface stay in lockstep with what verification can actually return,
# mirroring SIGNATURE_MISSING etc. in channels.signing.
RECORD_SIGNATURE_MISSING = "record_signature_missing"
RECORD_SIGNATURE_MALFORMED = "record_signature_malformed"
RECORD_SIGNATURE_INVALID = "record_signature_invalid"
RECORD_SIGNER_UNKNOWN = "record_signer_unknown"

# Role-binding failures (the second signing role). Distinct from
# RECORD_SIGNER_UNKNOWN on purpose: "nobody knows this key" and "the wrong
# identity signed this record type" are different incidents, and collapsing
# them would hide the one that matters — an evaluator key on a promotion
# record is an attempt to mint authority from the no-model side.
RECORD_SIGNER_WRONG_ROLE = "record_signer_wrong_role"
RECORD_SIGNER_ROLE_AMBIGUOUS = "record_signer_role_ambiguous"
RECORD_ROLE_UNRESOLVED = "record_role_unresolved"


# ---------------------------------------------------------------------------
# Signing roles — which identity may sign which record type
# ---------------------------------------------------------------------------

#: The ceremony/operator side. Every record type whose write is a human-driven
#: act, including the ones that mint or re-shape authority.
ISSUER_ROLE = "issuer"

#: The automatic, deterministic, no-model side (GAL §6.7.2's separate system
#: identity). It only ever LOWERS authority, so it never needs the issuer key.
EVALUATOR_ROLE = "evaluator"

SIGNING_ROLES: tuple[str, ...] = (ISSUER_ROLE, EVALUATOR_ROLE)

#: The record-type → role rule, in one place. GAL-SPEC §6.10 requires EVERY
#: ledger record to be signed; §6.7.2 requires the demotion evaluator to be a
#: separate identity. Both hold only if the split runs all the way through
#: verification — an auditor that accepted any known key for any record type
#: would make the second identity decorative.
RECORD_TYPE_SIGNING_ROLE: Mapping[str, str] = {
    "promotion": ISSUER_ROLE,
    "bootstrap": ISSUER_ROLE,
    "tightening": ISSUER_ROLE,
    "demotion": EVALUATOR_ROLE,
    "lapse": EVALUATOR_ROLE,
}


def signing_role_for_record_type(record_type: str) -> str | None:
    """The role whose key may sign ``record_type``, or None if it has no rule.

    None is reachable only for a record type outside the schema's closed
    vocabulary (which cannot parse), and callers treat it as unverifiable —
    fail closed, never "no role required, so anything passes".
    """
    return RECORD_TYPE_SIGNING_ROLE.get(record_type)


@dataclass(frozen=True)
class RecordVerifyResult:
    """Outcome of verifying a stored record's DSSE envelope.

    ``reason`` is one of the ``RECORD_*`` constants on failure, else None. On
    failure the reader quarantines the ledger item loudly — never treats an
    unverified level change as authoritative (mirrors the grant-HMAC
    quarantine, sa#124).
    """

    ok: bool
    reason: str | None = None


# ---------------------------------------------------------------------------
# Shared DSSE verification core — one implementation, two ledgers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DsseVerifyReasons:
    """The failure-reason vocabulary a caller maps onto the shared verifier.

    Each ledger keeps its OWN constant strings (so its reader/auditor stay in
    lockstep with what it can return) but the verification LOGIC is one shared
    implementation — the promotion ledger and the MCP admission ledger differ
    only in predicate type, subject-digest fn, and these four strings.
    """

    missing: str
    malformed: str
    invalid: str
    signer_unknown: str


def verify_dsse_record(
    envelope: dict,
    *,
    expected_predicate_type: str,
    subject_digest_hex: str,
    key_resolver: KeyResolver,
    reasons: DsseVerifyReasons,
) -> str | None:
    """Verify a DSSE/in-toto envelope against a caller-recomputed subject digest.

    The shared core behind both ``verify_record`` (promotion ledger) and
    ``verify_admission_record`` (MCP admission ledger). Returns ``None`` on
    success, else the matching ``reasons.*`` string. Fails closed, each mode
    distinct:

      * envelope not a dict / structurally broken / undecodable payload →
        ``reasons.malformed``;
      * no signatures at all → ``reasons.missing``;
      * a signer whose ``key_id`` the resolver doesn't know →
        ``reasons.signer_unknown``;
      * wrong ``payloadType`` / ``_type`` / ``predicateType``, a subject digest
        that doesn't match ``subject_digest_hex`` (a signature borrowed from a
        different record), a signature ``keyid`` that doesn't match the
        statement's ``predicate.signer.key_id`` (an attribution splice), or a
        signature that doesn't verify → ``reasons.invalid``.

    Every present signature must verify; at least one is required. The subject
    digest is supplied by the caller, recomputed from the record AS STORED — the
    payload's own claim is never trusted over that recomputation.
    """
    if not isinstance(envelope, dict):
        return reasons.malformed
    signatures = envelope.get("signatures")
    if not signatures:
        return reasons.missing
    if not isinstance(signatures, list):
        return reasons.malformed

    payload_type = envelope.get("payloadType")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return reasons.invalid

    try:
        statement_bytes = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(statement_bytes)
    except (KeyError, TypeError, ValueError, binascii.Error):
        return reasons.malformed
    if not isinstance(statement, dict):
        return reasons.malformed

    if statement.get("_type") != STATEMENT_TYPE:
        return reasons.invalid
    if statement.get("predicateType") != expected_predicate_type:
        return reasons.invalid

    # Rebind the subject to the record as STORED: a signature lifted from a
    # different record carries a digest that cannot match this one.
    try:
        subject_hex = statement["subject"][0]["digest"]["sha256"]
        signer_key_id = statement["predicate"]["signer"]["key_id"]
    except (KeyError, IndexError, TypeError):
        return reasons.malformed
    if subject_hex != subject_digest_hex:
        return reasons.invalid

    signed_bytes = pae(payload_type, statement_bytes)
    for signature in signatures:
        if not isinstance(signature, dict) or "keyid" not in signature or "sig" not in signature:
            return reasons.malformed
        # An attacker cannot relabel who signed: the statement's own signer
        # binding must match the signature's keyid.
        if signature["keyid"] != signer_key_id:
            return reasons.invalid
        public_key = key_resolver(signature["keyid"])
        if public_key is None:
            return reasons.signer_unknown
        try:
            public_key.verify(base64.b64decode(signature["sig"], validate=True), signed_bytes)
        except (InvalidSignature, TypeError, ValueError, binascii.Error):
            return reasons.invalid

    return None


_RECORD_VERIFY_REASONS = DsseVerifyReasons(
    missing=RECORD_SIGNATURE_MISSING,
    malformed=RECORD_SIGNATURE_MALFORMED,
    invalid=RECORD_SIGNATURE_INVALID,
    signer_unknown=RECORD_SIGNER_UNKNOWN,
)


# ---------------------------------------------------------------------------
# Canonical record bytes + statement
# ---------------------------------------------------------------------------


def canonical_record_payload(record: PromotionRecord) -> str:
    """The ONE serialization of a record — what gets STORED and what gets signed.

    Canonical JSON: sorted keys, no whitespace, ASCII. Storage and the signing
    basis must be the same bytes (#246): the ledger stores exactly this string
    as the item's data, the signature binds its sha256, and verification
    digests the STORED bytes verbatim — never a re-serialization of the parsed
    record, which would silently re-derive the basis from whatever the model
    class looks like *today* and read every intact pre-growth record as a
    signature failure.
    """
    payload = record.model_dump(mode="json")
    # certifiedUntil (#255) is OMITTED when None: every record written before the
    # field existed, and every record that carries no term, serializes to exactly
    # the pre-#255 bytes, so its stored bytes and its DSSE subject digest are
    # unchanged (pinned in test_grant_term_lapse.py). A set term is inside the
    # payload and so inside the signature.
    if payload.get("certifiedUntil") is None:
        payload.pop("certifiedUntil", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_record_bytes(record: PromotionRecord) -> bytes:
    """canonical_record_payload as UTF-8 bytes (the sign-side digest input)."""
    return canonical_record_payload(record).encode("utf-8")


def _record_digest_hex(record: PromotionRecord) -> str:
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def stored_record_digest_hex(stored: str | bytes) -> str:
    """sha256 over the stored record bytes VERBATIM — the verify-side basis.

    Verification must digest what is on disk, not what the parsed model
    re-serializes to (#246: integrity indicts tampering, never evolution).
    """
    data = stored.encode("utf-8") if isinstance(stored, str) else stored
    return hashlib.sha256(data).hexdigest()


def build_record_statement(record: PromotionRecord, *, key_id: str, zone: str) -> bytes:
    """Serialize the in-toto statement a record signature commits to.

    Canonical JSON so sign and verify agree byte-for-byte. ``subject`` binds
    the full record via its canonical-JSON sha256; ``predicate.signer`` binds
    this signature's ``key_id``/``zone`` (attribution is non-malleable);
    ``predicate.record`` carries the audit-index identity fields in the clear.
    """
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": RECORD_PREDICATE_TYPE,
        "subject": [{"name": "promotion-record", "digest": {"sha256": _record_digest_hex(record)}}],
        "predicate": {
            "signer": {"key_id": key_id, "zone": zone},
            "record": {
                "recordType": record.recordType,
                "ts": record.ts,
                "actionClass": record.actionClass,
                "proposedBy": record.proposedBy,
                "ratifiedBy": record.ratifiedBy,
                "envelopeHash": record.envelopeHash,
            },
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# Signer — the ceremony command-side seam
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordSigner:
    """The ISSUER's Ed25519 signing identity.

    Bundles the private key with the ``key_id`` a verifier resolves and the
    ``zone`` the record is attributed to. Constructed at ceremony-command cold
    start from a Secrets-Manager-held key (never in the agent image, never
    held by the broker); passed in so the module stays pure.
    """

    key_id: str
    zone: str
    _private_key: Ed25519PrivateKey

    def sign_pae(self, pae_bytes: bytes) -> bytes:
        """Sign pre-encoded DSSE PAE bytes with the issuer key.

        The public seam for OTHER issuer-signed ledgers (e.g. the MCP admission
        ledger) that build their own statement shapes: they keep their statement
        builders local and borrow only the key material, never the key itself.
        """
        return self._private_key.sign(pae_bytes)

    def sign_record(self, record: PromotionRecord) -> dict:
        """Sign the record; return a standard JSON-serializable DSSE envelope.

        The envelope is stored beside the ledger item's record blob (never on
        the schema). The signature binds the full record (subject digest) and
        this signer's own ``key_id``/``zone`` — neither the level change nor
        its attribution can be altered without breaking it.
        """
        statement = build_record_statement(record, key_id=self.key_id, zone=self.zone)
        sig = self.sign_pae(pae(DSSE_PAYLOAD_TYPE, statement))
        return {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(statement).decode("ascii"),
            "signatures": [
                {"keyid": self.key_id, "sig": base64.b64encode(sig).decode("ascii")}
            ],
        }


def signer_from_pem(key_id: str, zone: str, pem: str | bytes) -> RecordSigner:
    """Build a RecordSigner from a PEM private key (cold-start convenience)."""
    return RecordSigner(key_id=key_id, zone=zone, _private_key=load_private_key(pem))


# ---------------------------------------------------------------------------
# Verifier — the ledger-reader / auditor seam
# ---------------------------------------------------------------------------


def verify_record(
    stored: str | bytes, envelope: dict, key_resolver: KeyResolver
) -> RecordVerifyResult:
    """Verify the STORED record bytes against their stored DSSE envelope.

    Since #246 the input is the stored serialization itself (the ledger item's
    data string), never a parsed-and-re-serialized model: the subject digest
    is the sha256 over exactly those bytes, so additive PromotionRecord schema
    growth can never flip a valid signature to INVALID. Sign-side,
    ``canonical_record_payload`` is what the store writes, so stored bytes and
    signed bytes are the same string by construction.

    Fails closed, each mode with its own reason:

      * envelope not a dict / structurally broken / undecodable payload →
        ``RECORD_SIGNATURE_MALFORMED``;
      * no signatures at all → ``RECORD_SIGNATURE_MISSING``;
      * a signer whose ``key_id`` the resolver doesn't know →
        ``RECORD_SIGNER_UNKNOWN``;
      * wrong ``payloadType``/``_type``/``predicateType``, a subject digest
        that doesn't match the sha256 over the stored bytes (a signature
        borrowed from a different record, or a post-signing byte tamper), a
        signature ``keyid`` that doesn't match the statement's
        ``predicate.signer.key_id`` (an attribution splice), or a signature
        that doesn't verify → ``RECORD_SIGNATURE_INVALID``.

    Every present signature must verify; at least one is required. The subject
    digest comes from the bytes as stored — the payload's own claim is never
    trusted over the recomputation.
    """
    reason = verify_dsse_record(
        envelope,
        expected_predicate_type=RECORD_PREDICATE_TYPE,
        subject_digest_hex=stored_record_digest_hex(stored),
        key_resolver=key_resolver,
        reasons=_RECORD_VERIFY_REASONS,
    )
    return RecordVerifyResult(ok=reason is None, reason=reason)


# ---------------------------------------------------------------------------
# Role-bound verification — the record type picks the key map
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoleKeyResolvers:
    """The verify-side key maps, one per signing role.

    Injected, like every other key in this module: the cold-start resolution
    of ``ISSUER_VERIFY_KEYS_PARAM`` / ``EVALUATOR_VERIFY_KEYS_PARAM`` lives in
    ``grants.issuer_keys``. A role with no resolver is NOT a role that passes —
    a record needing it verifies as ``RECORD_ROLE_UNRESOLVED``.
    """

    issuer: KeyResolver | None = None
    evaluator: KeyResolver | None = None

    def for_role(self, role: str) -> KeyResolver | None:
        return {ISSUER_ROLE: self.issuer, EVALUATOR_ROLE: self.evaluator}.get(role)

    def configured_roles(self) -> tuple[str, ...]:
        return tuple(role for role in SIGNING_ROLES if self.for_role(role) is not None)

    def roles_resolving(self, key_id: str) -> tuple[str, ...]:
        """Every configured role whose map knows ``key_id``.

        More than one is a CONFIGURATION error, not a key with two roles: the
        whole point of the split is that the evaluator cannot produce a
        promotion signature. Reported by the verifier as
        ``RECORD_SIGNER_ROLE_AMBIGUOUS`` and refused; ``issuer_keys`` refuses
        the same overlap at cold start, where it can name both parameters.
        """
        return tuple(
            role
            for role in SIGNING_ROLES
            if (resolver := self.for_role(role)) is not None and resolver(key_id) is not None
        )


def envelope_signer_key_id(envelope: object) -> str | None:
    """The ``keyid`` a DSSE envelope's first signature claims, or None.

    Best-effort and untrusted — used only to say WHY verification failed (a
    known key of the wrong role vs. a key nobody knows). It is never the basis
    for accepting anything: ``verify_dsse_record`` re-binds the keyid to the
    statement's own ``predicate.signer.key_id`` and verifies the signature.
    """
    if not isinstance(envelope, dict):
        return None
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return None
    first = signatures[0]
    key_id = first.get("keyid") if isinstance(first, dict) else None
    return key_id if isinstance(key_id, str) else None


def verify_record_by_type(
    stored: str | bytes,
    envelope: dict,
    *,
    record_type: str,
    resolvers: RoleKeyResolvers,
) -> RecordVerifyResult:
    """Verify a stored record against the key map its RECORD TYPE selects.

    The role binding, end to end: ``RECORD_TYPE_SIGNING_ROLE`` picks the
    resolver, and a signature from the other role's key fails — an
    evaluator-signed ``promotion`` (an attempt to mint authority from the
    automatic side) and an issuer-signed ``demotion`` alike. Failure modes
    beyond :func:`verify_record`'s:

      * the record type maps to no role, or that role has no verify keys
        configured → ``RECORD_ROLE_UNRESOLVED`` (a role we cannot check is
        never a role that passes);
      * the signing key_id is known to the OTHER role → ``RECORD_SIGNER_WRONG_ROLE``;
      * the signing key_id is known to BOTH roles → ``RECORD_SIGNER_ROLE_AMBIGUOUS``,
        refused rather than resolved in either direction.
    """
    role = signing_role_for_record_type(record_type)
    if role is None:
        return RecordVerifyResult(ok=False, reason=RECORD_ROLE_UNRESOLVED)
    resolver = resolvers.for_role(role)
    if resolver is None:
        return RecordVerifyResult(ok=False, reason=RECORD_ROLE_UNRESOLVED)

    key_id = envelope_signer_key_id(envelope)
    if key_id is not None:
        holders = resolvers.roles_resolving(key_id)
        if len(holders) > 1:
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNER_ROLE_AMBIGUOUS)
        if holders and holders[0] != role:
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNER_WRONG_ROLE)

    return verify_record(stored, envelope, resolver)
