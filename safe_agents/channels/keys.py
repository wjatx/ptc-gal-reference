"""channels.keys — cold-start resolution of the chain-signing keys (Phase 4).

The impure seam that turns Secrets-Manager-held keys into the pure objects
``channels.signing`` consumes: the broker's Ed25519 signing identity on the
sender side, and the peer verification-key map on the receiver side. Kept
separate from ``signing`` (which stays pure and key-injected) and from
``publish`` (the typed stamping clause), so the boto3 fetch lives in exactly one
place — mirroring the drain's ``_resolve_hmac_key`` seam.

Both fetches ship OFF: with no ARN configured the sender emits an unsigned chain
and the receiver skips verification (unsigned peers pass, today's behavior —
docs/friction-doctrine.md). A set-but-unfetchable ARN fails closed loudly rather
than silently degrading to no signing / no verification.

The module-level ``_fetch_secret`` seam is monkeypatched in tests so no live AWS
is needed. Keys — private and public — are never logged.
"""

from __future__ import annotations

import json
import os

from safe_agents.channels.schemas.event_trigger import ZONE_ID_RULE, is_zone_id
from safe_agents.channels.signing import (
    ACCEPTED_CUSTODY_EVIDENCE,
    CUSTODY_ATTESTED,
    SIGNER_POSTURES,
    ChainSigner,
    KeyResolver,
    PeerKey,
    canonical_identity,
    load_public_key,
    signer_from_pem,
)

# Env names — the sender's signing key (a Secrets-Manager ARN → PEM private key),
# the key_id a receiver resolves it by, and the receiver's verification-key map
# (an ARN → JSON ``{key_id: {public_key, zone, sender_identities, signer_posture,
# custody_evidence}}``, see `peer_key_resolver_from_map`). All optional; absence = OFF.
SIGNING_KEY_SECRET_ARN_ENV = "BROKER_SIGNING_KEY_SECRET_ARN"
SIGNING_KEY_ID_ENV = "BROKER_SIGNING_KEY_ID"
VERIFY_KEYS_SECRET_ARN_ENV = "BROKER_VERIFY_KEYS_SECRET_ARN"


class SigningConfigError(RuntimeError):
    """A signing/verification key ARN is set but could not be resolved.

    Fails the invocation closed rather than silently running unsigned /
    unverified — the same posture as the drain's HMAC-key resolution.
    """


def _fetch_secret(secret_arn: str) -> str:
    """Fetch a secret's string value from Secrets Manager (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_arn)["SecretString"]


def resolve_signer(zone: str) -> ChainSigner | None:
    """Build the broker's ChainSigner from its cold-start environment, or None.

    Returns None when no signing-key ARN is configured (the sender emits an
    unsigned chain). Requires ``BROKER_SIGNING_KEY_ID`` when the ARN is set — a
    signer with no ``key_id`` a receiver could resolve is a misconfiguration, not
    a silent default.
    """
    secret_arn = os.environ.get(SIGNING_KEY_SECRET_ARN_ENV)
    if not secret_arn:
        return None
    key_id = os.environ.get(SIGNING_KEY_ID_ENV)
    if not key_id:
        raise SigningConfigError(
            f"{SIGNING_KEY_SECRET_ARN_ENV} is set but {SIGNING_KEY_ID_ENV} is not; "
            "a signer needs a key_id the receiver can resolve"
        )
    try:
        pem = _fetch_secret(secret_arn)
        return signer_from_pem(key_id, zone, pem)
    except SigningConfigError:
        raise
    except Exception as exc:
        raise SigningConfigError(
            f"{SIGNING_KEY_SECRET_ARN_ENV} is set but the signing key could not be "
            f"resolved ({type(exc).__name__})"
        ) from exc


def key_resolver_from_map(pem_by_key_id: dict[str, str]) -> KeyResolver:
    """Turn a ``{key_id: public_key_pem}`` map into a KeyResolver.

    Parses every PEM up front (so a malformed key fails at cold start, not on the
    first inbound chain) and returns a closure that maps an unknown key_id to
    None — which verification treats as an unknown signer and quarantines.
    """
    parsed = {key_id: load_public_key(pem) for key_id, pem in pem_by_key_id.items()}
    return lambda key_id: parsed.get(key_id)


# The fields of one verification-key entry. Closed: an unrecognized field is a
# configuration error, never ignored.
_CUSTODY_FIELDS = frozenset({"signer_posture", "custody_evidence"})
_PEER_KEY_FIELDS = frozenset({"public_key", "zone", "sender_identities"}) | _CUSTODY_FIELDS
_PEER_KEY_SHAPE = (
    '{"public_key": "<PEM>", "zone": "<zone>", "sender_identities": ["<identity>", ...], '
    '"signer_posture": <1|2|3>, "custody_evidence": "declared"}'
)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse a JSON object that names a key twice.

    The default parser keeps the last one silently, so a second entry for a
    ``key_id`` would replace the first, key and scope both, with nothing said.
    """
    seen: dict[str, object] = {}
    for name, value in pairs:
        if name in seen:
            raise SigningConfigError(f"verification-keys secret names {name!r} more than once")
        seen[name] = value
    return seen


def _peer_key(key_id: str, entry: object) -> PeerKey:
    """Parse one verification-key entry, naming the key and the fault on error.

    The message carries the ``key_id`` and the expected shape, never key
    material. A bare PEM string is the pre-scope format and is refused: a key
    with no scope would be trusted to sign for every zone and every sender.

    The custody record (``signer_posture``, ``custody_evidence``) is required
    and has no default. A default would write down, on the operator's behalf, a
    statement about a peer that nobody made.
    """
    if not isinstance(entry, dict):
        raise SigningConfigError(
            f"verification key {key_id!r} must be an object of the form {_PEER_KEY_SHAPE}"
        )
    missing_custody = sorted(_CUSTODY_FIELDS - set(entry))
    if missing_custody:
        raise SigningConfigError(
            f"verification key {key_id!r} has no custody record: missing "
            f"{', '.join(missing_custody)}; an entry has the form {_PEER_KEY_SHAPE}"
        )
    if set(entry) != _PEER_KEY_FIELDS:
        raise SigningConfigError(
            f"verification key {key_id!r} must be an object of the form {_PEER_KEY_SHAPE}"
        )
    posture, custody_evidence = entry["signer_posture"], entry["custody_evidence"]
    # `type(...) is int`: True and False are ints to isinstance, and 2.0 == 2.
    if type(posture) is not int or posture not in SIGNER_POSTURES:
        raise SigningConfigError(
            f"verification key {key_id!r}: signer_posture must be one of the integers "
            f"{sorted(SIGNER_POSTURES)} (docs/posture-ladder.md)"
        )
    if custody_evidence == CUSTODY_ATTESTED:
        raise SigningConfigError(
            f"verification key {key_id!r}: custody_evidence {CUSTODY_ATTESTED!r} is reserved; "
            "no procedure in this version produces it, so a record cannot claim it"
        )
    if not isinstance(custody_evidence, str) or custody_evidence not in ACCEPTED_CUSTODY_EVIDENCE:
        raise SigningConfigError(
            f"verification key {key_id!r}: custody_evidence must be one of "
            f"{sorted(ACCEPTED_CUSTODY_EVIDENCE)}"
        )
    zone, identities = entry["zone"], entry["sender_identities"]
    if not is_zone_id(zone):
        raise SigningConfigError(f"verification key {key_id!r}: zone {ZONE_ID_RULE}")
    if (
        not isinstance(identities, list)
        or not identities
        or not all(isinstance(identity, str) and identity.strip() for identity in identities)
    ):
        raise SigningConfigError(
            f"verification key {key_id!r}: sender_identities must be a non-empty list of "
            "non-empty strings"
        )
    try:
        public_key = load_public_key(entry["public_key"])
    except Exception as exc:
        # The exception type only: a parser's message can echo what it was given.
        raise SigningConfigError(
            f"verification key {key_id!r}: public_key is not a PEM-encoded Ed25519 "
            f"public key ({type(exc).__name__})"
        ) from None
    return PeerKey(
        public_key=public_key,
        zone=zone,
        sender_identities=frozenset(canonical_identity(identity) for identity in identities),
        signer_posture=posture,
        custody_evidence=custody_evidence,
    )


class EnrolledPeerKeys:
    """The receiver's enrolled verification keys: a `PeerKeyResolver` that can be listed.

    Calling it resolves one ``key_id``, as `verify_chain` needs. ``enrolled``
    lists every key, which is what `signing.deployment_provenance_tier` reads to
    say what the receiver's custody records support as a whole.
    """

    def __init__(self, key_by_id: dict[str, PeerKey]) -> None:
        self._key_by_id = dict(key_by_id)

    def __call__(self, key_id: str) -> PeerKey | None:
        return self._key_by_id.get(key_id)

    @property
    def enrolled(self) -> tuple[PeerKey, ...]:
        return tuple(self._key_by_id.values())


def peer_key_resolver_from_map(entry_by_key_id: dict[str, object]) -> EnrolledPeerKeys:
    """Turn the verification-keys map into a resolver.

    The map is ``{key_id: {public_key, zone, sender_identities, signer_posture,
    custody_evidence}}``. Each key carries the one zone it may sign for, the
    sender identities an envelope it signs may claim, and its custody record
    (`signing.PeerKey`). Every entry is parsed up front, so a malformed one
    fails at cold start and not on the first inbound chain. An unknown key_id
    resolves to None, which verification treats as an unknown signer and
    quarantines.
    """
    return EnrolledPeerKeys(
        {key_id: _peer_key(key_id, entry) for key_id, entry in entry_by_key_id.items()}
    )


def resolve_verification_keys() -> EnrolledPeerKeys | None:
    """Build the receiver's PeerKeyResolver from its cold-start environment, or None.

    Returns None when no verification-keys ARN is configured — the airlock skips
    the signature gate and unsigned peers pass. When the ARN is set, its
    SecretString is the JSON map `peer_key_resolver_from_map` takes; a
    set-but-unfetchable or malformed value fails closed.
    """
    secret_arn = os.environ.get(VERIFY_KEYS_SECRET_ARN_ENV)
    if not secret_arn:
        return None
    try:
        entry_by_key_id = json.loads(_fetch_secret(secret_arn), object_pairs_hook=_no_duplicate_keys)
        if not isinstance(entry_by_key_id, dict):
            raise ValueError("verification-keys secret must be a JSON object")
        return peer_key_resolver_from_map(entry_by_key_id)
    except SigningConfigError:
        raise
    except Exception as exc:
        # `from None`: a JSON decode error carries the whole document it was
        # parsing, and that document is the secret.
        raise SigningConfigError(
            f"{VERIFY_KEYS_SECRET_ARN_ENV} is set but the verification keys could not "
            f"be resolved ({type(exc).__name__})"
        ) from None
