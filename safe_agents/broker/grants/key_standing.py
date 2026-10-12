"""grants.key_standing: the signed standing document for a signing role.

GAL §6.10 (GAL-41, #179): whether a record was validly signed and whether its
signer still has standing are different questions. This module holds the pure
half of the second one: the document that says which keys a role holds and in
what state, how it is signed and verified, and which changes from one version
to the next are allowed.

Prior art, adopted
------------------
* **Reason codes** are RFC 5280 §5.3.1's names. ``superseded`` and
  ``cessationOfOperation`` retire a key: it signs nothing new and every record
  it signed keeps standing. ``keyCompromise`` and ``privilegeWithdrawn``
  withdraw it: no record it signed has standing, whatever that record's ``ts``.
  A record's ``ts`` is part of what the key signed, so whoever held a
  compromised key can backdate anything it forges. Only a third-party time
  attestation could spare records made before the compromise, and none exists
  here, so both withdrawal reasons void everything.
* **The document's shape** follows The Update Framework's signed, versioned
  statement of which keys hold which role: a monotone ``version``, an
  ``issuedAt`` instant, and a signature by a key that holds neither of the roles
  it describes (the standing authority). A verifier refuses a version no higher
  than one it has accepted, which is rollback protection.
* **One divergence, on purpose.** X.509 has a reversible ``certificateHold``.
  There is no hold state here. Withdrawal is terminal and nothing leaves it, so
  a document that lacks a withdrawal a verifier has already seen is a rollback
  by inspection. A key that must be trusted again is a new key pair under a new
  key id: no document lists one public key twice, and a key id or key bytes
  already in the document are never added again.

Integrity binds stored bytes
----------------------------
The document is serialized once (``canonical_standing_bytes``), and those bytes
are the DSSE payload. A verifier decodes the payload, verifies the signature
over exactly those bytes, and only then parses them. Nothing here re-serializes
a document to check it.

This module never reads the environment, a file or the clock. Fetching, the
per-process accept rules and the maximum age live in ``grants.standing_source``;
the env contract lives in ``grants.issuer_keys`` and ``grants.standing_keys``.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
from typing import Literal, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError, model_validator

from safe_agents.broker.grants.record_signing import (
    EVALUATOR_ROLE,
    ISSUER_ROLE,
    RecordSigner,
)
from safe_agents.channels.signing import KeyResolver, load_public_key, pae

#: The third signing role. It signs standing documents and nothing else, and
#: no key it holds may appear in a document it signs (``AUTHORITY_KEY_LISTED``).
STANDING_AUTHORITY_ROLE = "standing-authority"

#: The roles a standing document can describe. The standing authority's own
#: keys are bound at deploy, never described by a document they sign.
STANDING_ROLES: tuple[str, ...] = (ISSUER_ROLE, EVALUATOR_ROLE)

#: DSSE payload type of a signed standing document. Versioned like the record
#: predicate type, so a later wire change can bump it.
STANDING_PAYLOAD_TYPE = "application/vnd.safe-agents.key-standing.v1+json"

KEY_ACTIVE = "active"
KEY_RETIRED = "retired"
KEY_WITHDRAWN = "withdrawn"

KeyState = Literal["active", "retired", "withdrawn"]
RetiredReason = Literal["superseded", "cessationOfOperation"]
WithdrawnReason = Literal["keyCompromise", "privilegeWithdrawn"]
StandingRole = Literal["issuer", "evaluator"]

RETIRED_REASONS: tuple[str, ...] = ("superseded", "cessationOfOperation")
WITHDRAWN_REASONS: tuple[str, ...] = ("keyCompromise", "privilegeWithdrawn")

# Why a candidate document is refused. Module constants so the loader, the
# ceremony command and the tests stay in lockstep with what can be returned.
STANDING_MALFORMED = "malformed"
STANDING_SIGNATURE_INVALID = "signature_invalid"
STANDING_SIGNER_UNKNOWN = "signer_unknown"
STANDING_WRONG_ROLE = "wrong_role"
STANDING_ROLLBACK = "rollback"
STANDING_WITHDRAWAL_DROPPED = "withdrawal_dropped"
STANDING_TRANSITION_REFUSED = "transition_refused"
STANDING_KEY_REBOUND = "key_rebound"
STANDING_AUTHORITY_KEY_LISTED = "authority_key_listed"
STANDING_KEY_DUPLICATED = "key_duplicated"


class StandingDocumentRefused(ValueError):
    """A candidate standing document that must not be accepted.

    ``verdict`` is one of the ``STANDING_*`` refusal constants. The previously
    accepted document, if any, stays in force.
    """

    def __init__(self, verdict: str, detail: str) -> None:
        super().__init__(f"{verdict}: {detail}")
        self.verdict = verdict
        self.detail = detail


class StandingTransitionError(ValueError):
    """A state change the ceremony refuses: backward, from withdrawn, or unknown key."""


def parse_standing_instant(value: str, field: str) -> datetime.datetime:
    """Parse an explicit UTC instant, or raise ValueError naming ``field``.

    Naive and non-UTC values are refused, so every reader takes the same
    instant from the same string.
    """
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} {value!r} is not a parseable ISO-8601 instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError(
            f"{field} {value!r} must be an explicit UTC instant (offset 'Z' or '+00:00')"
        )
    return parsed


def format_standing_instant(instant: datetime.datetime) -> str:
    """The one spelling a ceremony writes an instant in: UTC, ``+00:00``."""
    if instant.tzinfo is None:
        raise ValueError("a standing instant must be timezone-aware")
    return instant.astimezone(datetime.UTC).isoformat()


def public_key_raw(pem: str) -> bytes:
    """The raw 32 bytes of an Ed25519 public key, for comparing keys across roles."""
    return load_public_key(pem).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class KeyStandingEntry(BaseModel):
    """One key in a role's standing document: its public key and its state.

    ``active`` carries no dates. ``retired`` carries ``retiredAt`` and
    ``retiredReason``. ``withdrawn`` carries ``withdrawnAt`` and
    ``withdrawnReason``, and keeps the retirement pair when it was retired
    first. Every field dumps, null or not.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    publicKey: str
    state: KeyState
    retiredAt: str | None = None
    retiredReason: RetiredReason | None = None
    withdrawnAt: str | None = None
    withdrawnReason: WithdrawnReason | None = None

    @model_validator(mode="after")
    def _shape_matches_state(self) -> "KeyStandingEntry":
        load_public_key(self.publicKey)
        retired = (self.retiredAt, self.retiredReason)
        withdrawn = (self.withdrawnAt, self.withdrawnReason)
        if self.state == KEY_ACTIVE and (any(v is not None for v in retired + withdrawn)):
            raise ValueError("an active key carries no retirement or withdrawal fields")
        if self.state == KEY_RETIRED and (
            None in retired or any(v is not None for v in withdrawn)
        ):
            raise ValueError(
                "a retired key carries retiredAt and retiredReason and no withdrawal fields"
            )
        if self.state == KEY_WITHDRAWN:
            if None in withdrawn:
                raise ValueError("a withdrawn key carries withdrawnAt and withdrawnReason")
            if (self.retiredAt is None) != (self.retiredReason is None):
                raise ValueError("retiredAt and retiredReason are set together or not at all")
        retired_at = (
            parse_standing_instant(self.retiredAt, "retiredAt") if self.retiredAt else None
        )
        withdrawn_at = (
            parse_standing_instant(self.withdrawnAt, "withdrawnAt") if self.withdrawnAt else None
        )
        if retired_at and withdrawn_at and withdrawn_at < retired_at:
            raise ValueError("withdrawnAt must not be earlier than retiredAt")
        return self


class StandingSigner(BaseModel):
    """Which standing-authority key signed the document, and its zone.

    Inside the signed bytes, so attribution cannot be relabelled: a verifier
    refuses a document whose ``keyId`` differs from the signature's ``keyid``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    keyId: str = Field(min_length=1)
    zone: str = Field(min_length=1)


class KeyStandingDocument(BaseModel):
    """One role's keys and their states, as of ``issuedAt``, at ``version``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: StandingRole
    version: StrictInt = Field(ge=1)
    issuedAt: str
    signer: StandingSigner
    keys: dict[str, KeyStandingEntry]

    @model_validator(mode="after")
    def _well_formed(self) -> "KeyStandingDocument":
        parse_standing_instant(self.issuedAt, "issuedAt")
        if any(not key_id for key_id in self.keys):
            raise ValueError("a key id must be a non-empty string")
        return self

    def issued_at(self) -> datetime.datetime:
        return parse_standing_instant(self.issuedAt, "issuedAt")


# ---------------------------------------------------------------------------
# Serialization, signing and verification
# ---------------------------------------------------------------------------


def canonical_standing_bytes(document: KeyStandingDocument) -> bytes:
    """The ONE serialization of a document: what is signed and what is carried."""
    payload = document.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sign_standing_document(document: KeyStandingDocument, signer: RecordSigner) -> str:
    """Sign ``document`` with the standing authority's key; return the envelope text.

    The text is what a parameter or a file holds. Refuses a document whose
    ``signer`` names a different key or zone than the one signing it.
    """
    if (document.signer.keyId, document.signer.zone) != (signer.key_id, signer.zone):
        raise ValueError(
            "the document's signer field must name the key and zone that sign it"
        )
    payload = canonical_standing_bytes(document)
    sig = signer.sign_pae(pae(STANDING_PAYLOAD_TYPE, payload))
    envelope = {
        "payloadType": STANDING_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": signer.key_id, "sig": base64.b64encode(sig).decode("ascii")}],
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


def _refuse_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """A JSON object naming a key twice is refused, never resolved last-wins."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"the JSON object names {key!r} twice")
        result[key] = value
    return result


def verify_standing_envelope(
    text: str | bytes, *, authority: KeyResolver, role: str
) -> tuple[KeyStandingDocument, str]:
    """Verify a signed standing document, then parse it. Return it and its digest.

    The digest is the sha256 of the payload bytes as carried. Refuses
    (``StandingDocumentRefused``) an envelope that is not exactly one DSSE
    signature over a document of ``role`` by a key ``authority`` knows. The
    signature is checked over the decoded payload bytes BEFORE they are parsed.
    """
    try:
        envelope = json.loads(text, object_pairs_hook=_refuse_duplicate_keys)
    except (TypeError, ValueError) as exc:
        raise StandingDocumentRefused(STANDING_MALFORMED, f"not JSON ({exc})") from exc
    if not isinstance(envelope, dict) or envelope.get("payloadType") != STANDING_PAYLOAD_TYPE:
        raise StandingDocumentRefused(
            STANDING_MALFORMED, f"not a DSSE envelope of type {STANDING_PAYLOAD_TYPE}"
        )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise StandingDocumentRefused(
            STANDING_SIGNATURE_INVALID, "a standing document carries exactly one signature"
        )
    signature = signatures[0]
    if not isinstance(signature, dict) or not isinstance(signature.get("keyid"), str):
        raise StandingDocumentRefused(STANDING_MALFORMED, "the signature has no keyid")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        sig = base64.b64decode(signature["sig"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise StandingDocumentRefused(STANDING_MALFORMED, "payload or sig is not base64") from exc
    public_key = authority(signature["keyid"])
    if public_key is None:
        raise StandingDocumentRefused(
            STANDING_SIGNER_UNKNOWN,
            f"key {signature['keyid']!r} is not a standing-authority key bound at deploy",
        )
    try:
        public_key.verify(sig, pae(STANDING_PAYLOAD_TYPE, payload))
    except InvalidSignature as exc:
        raise StandingDocumentRefused(
            STANDING_SIGNATURE_INVALID, "the signature does not verify over the payload"
        ) from exc
    try:
        document = KeyStandingDocument.model_validate(
            json.loads(payload, object_pairs_hook=_refuse_duplicate_keys)
        )
    except (ValueError, ValidationError) as exc:
        raise StandingDocumentRefused(
            STANDING_MALFORMED, f"the signed payload is not a standing document ({exc})"
        ) from exc
    if document.signer.keyId != signature["keyid"]:
        raise StandingDocumentRefused(
            STANDING_SIGNATURE_INVALID, "the document's signer differs from the signature's keyid"
        )
    if document.role != role:
        raise StandingDocumentRefused(
            STANDING_WRONG_ROLE, f"a {document.role} document offered as the {role} document"
        )
    check_distinct_key_bytes(document)
    return document, hashlib.sha256(payload).hexdigest()


def check_distinct_key_bytes(document: KeyStandingDocument) -> None:
    """Refuse a document that lists one public key under two key ids (raises).

    Withdrawal is terminal for a key, not only for a key id. A document that
    listed a withdrawn key's bytes again under a new id as ``active`` would let
    whoever holds the compromised private key sign records that verify under an
    entry in standing.
    """
    seen: dict[bytes, str] = {}
    for key_id, entry in document.keys.items():
        raw = public_key_raw(entry.publicKey)
        if raw in seen:
            raise StandingDocumentRefused(
                STANDING_KEY_DUPLICATED,
                f"keys {seen[raw]!r} and {key_id!r} name the same public key; one key "
                "holds one entry, and a key trusted again is a new key pair",
            )
        seen[raw] = key_id


# ---------------------------------------------------------------------------
# What may change between versions
# ---------------------------------------------------------------------------


def _moves_forward(old: KeyStandingEntry, new: KeyStandingEntry) -> bool:
    """True iff ``new`` is ``old`` or a one-way step on from it.

    Allowed: active to retired, active to withdrawn, retired to withdrawn with
    the retirement pair kept. A state that does not change keeps every field.
    """
    if old.state == new.state:
        return old == new
    if old.state == KEY_ACTIVE:
        return new.state in (KEY_RETIRED, KEY_WITHDRAWN)
    if old.state == KEY_RETIRED and new.state == KEY_WITHDRAWN:
        return (new.retiredAt, new.retiredReason) == (old.retiredAt, old.retiredReason)
    return False


def check_successor(
    accepted: KeyStandingDocument | None,
    candidate: KeyStandingDocument,
    seen_withdrawn: Mapping[str, KeyStandingEntry],
) -> None:
    """Refuse ``candidate`` if it cannot follow ``accepted`` (raises).

    ``seen_withdrawn`` is every withdrawal this process has accepted. The
    candidate must carry each one unchanged, whatever its version, and must
    not list a seen-withdrawn key's bytes under any other key id. Against the
    accepted document it must have a higher version, rebind no key id to a
    different public key, list no accepted key's bytes under a new key id, and
    move no key's state backward.
    """
    check_distinct_key_bytes(candidate)
    for key_id, entry in seen_withdrawn.items():
        if candidate.keys.get(key_id) != entry:
            raise StandingDocumentRefused(
                STANDING_WITHDRAWAL_DROPPED,
                f"key {key_id!r} was seen withdrawn and the candidate does not say so",
            )
    known = dict(accepted.keys) if accepted is not None else {}
    known.update(seen_withdrawn)
    known_bytes = {public_key_raw(e.publicKey): k for k, e in known.items()}
    for key_id, entry in candidate.keys.items():
        if key_id in known:
            continue
        earlier = known_bytes.get(public_key_raw(entry.publicKey))
        if earlier is not None:
            raise StandingDocumentRefused(
                STANDING_KEY_REBOUND,
                f"new key id {key_id!r} names the public key already listed as {earlier!r}; "
                "a key trusted again is a new key pair",
            )
    if accepted is None:
        return
    if candidate.version <= accepted.version:
        raise StandingDocumentRefused(
            STANDING_ROLLBACK,
            f"version {candidate.version} is not greater than accepted version "
            f"{accepted.version}",
        )
    for key_id, old in accepted.keys.items():
        new = candidate.keys.get(key_id)
        if new is None:
            continue
        if new.publicKey != old.publicKey:
            raise StandingDocumentRefused(
                STANDING_KEY_REBOUND, f"key id {key_id!r} names a different public key"
            )
        if not _moves_forward(old, new):
            raise StandingDocumentRefused(
                STANDING_TRANSITION_REFUSED,
                f"key {key_id!r} moves from {old.state} to {new.state}, or changes "
                "a recorded date or reason",
            )


def check_authority_not_listed(
    document: KeyStandingDocument,
    authority_key_ids: frozenset[str],
    authority_public_keys: frozenset[bytes],
) -> None:
    """Refuse a document that lists a standing-authority key, by id or by key bytes.

    The standing authority is a third role. A key it holds that also held the
    issuer or evaluator role would let one key both sign records and decide
    whether those records have standing.
    """
    for key_id, entry in document.keys.items():
        if key_id in authority_key_ids or public_key_raw(entry.publicKey) in authority_public_keys:
            raise StandingDocumentRefused(
                STANDING_AUTHORITY_KEY_LISTED,
                f"key {key_id!r} is a standing-authority key; the third role's keys "
                "are never the issuer's or the evaluator's",
            )


# ---------------------------------------------------------------------------
# Transitions the ceremony may make
# ---------------------------------------------------------------------------


def add_key(
    keys: Mapping[str, KeyStandingEntry], key_id: str, public_key_pem: str
) -> dict[str, KeyStandingEntry]:
    """Add ``key_id`` as active.

    A key id already in the document is refused, withdrawn or not, and so is a
    public key already in the document under any key id: a key trusted again is
    a new key pair under a new key id, never a withdrawn key under a new name.
    """
    if key_id in keys:
        raise StandingTransitionError(
            f"key id {key_id!r} is already in the document ({keys[key_id].state}); "
            "a key id is never reused"
        )
    raw = public_key_raw(public_key_pem)
    for existing_id, existing in keys.items():
        if public_key_raw(existing.publicKey) == raw:
            raise StandingTransitionError(
                f"the public key offered for {key_id!r} is already in the document as "
                f"{existing_id!r} ({existing.state}); a key trusted again is a new key pair"
            )
    return {**keys, key_id: KeyStandingEntry(publicKey=public_key_pem, state=KEY_ACTIVE)}


def retire_key(
    keys: Mapping[str, KeyStandingEntry], key_id: str, reason: str, at: datetime.datetime
) -> dict[str, KeyStandingEntry]:
    """Retire an active key. Its records keep standing."""
    if reason not in RETIRED_REASONS:
        raise StandingTransitionError(f"retirement reason must be one of {RETIRED_REASONS}")
    entry = _require_key(keys, key_id)
    if entry.state != KEY_ACTIVE:
        raise StandingTransitionError(f"key {key_id!r} is {entry.state}; only an active key retires")
    retired = KeyStandingEntry(
        publicKey=entry.publicKey,
        state=KEY_RETIRED,
        retiredAt=format_standing_instant(at),
        retiredReason=reason,
    )
    return {**keys, key_id: retired}


def withdraw_key(
    keys: Mapping[str, KeyStandingEntry], key_id: str, reason: str, at: datetime.datetime
) -> dict[str, KeyStandingEntry]:
    """Withdraw an active or retired key. Terminal: no record it signed has standing."""
    if reason not in WITHDRAWN_REASONS:
        raise StandingTransitionError(f"withdrawal reason must be one of {WITHDRAWN_REASONS}")
    entry = _require_key(keys, key_id)
    if entry.state == KEY_WITHDRAWN:
        raise StandingTransitionError(f"key {key_id!r} is already withdrawn; withdrawal is terminal")
    withdrawn = KeyStandingEntry(
        publicKey=entry.publicKey,
        state=KEY_WITHDRAWN,
        retiredAt=entry.retiredAt,
        retiredReason=entry.retiredReason,
        withdrawnAt=format_standing_instant(at),
        withdrawnReason=reason,
    )
    return {**keys, key_id: withdrawn}


def _require_key(keys: Mapping[str, KeyStandingEntry], key_id: str) -> KeyStandingEntry:
    entry = keys.get(key_id)
    if entry is None:
        raise StandingTransitionError(f"key {key_id!r} is not in the document")
    return entry


def next_document(
    previous: KeyStandingDocument | None,
    *,
    role: str,
    keys: Mapping[str, KeyStandingEntry],
    issued_at: datetime.datetime,
    signer: RecordSigner,
) -> KeyStandingDocument:
    """The next version: one past ``previous`` (or 1), issued at ``issued_at``.

    Runs ``check_successor`` against ``previous`` so the ceremony can never
    sign a document a verifier would refuse to follow it.
    """
    if previous is not None and previous.role != role:
        raise StandingTransitionError(f"the current document is for {previous.role}, not {role}")
    document = KeyStandingDocument(
        role=role,
        version=(previous.version + 1) if previous is not None else 1,
        issuedAt=format_standing_instant(issued_at),
        signer=StandingSigner(keyId=signer.key_id, zone=signer.zone),
        keys=dict(keys),
    )
    seen = (
        {k: e for k, e in previous.keys.items() if e.state == KEY_WITHDRAWN}
        if previous is not None
        else {}
    )
    check_successor(previous, document, seen)
    return document
