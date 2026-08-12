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

from safe_agents.channels.signing import ChainSigner, KeyResolver, load_public_key, signer_from_pem

# Env names — the sender's signing key (a Secrets-Manager ARN → PEM private key),
# the key_id a receiver resolves it by, and the receiver's verification-key map
# (an ARN → JSON ``{key_id: public_key_pem}``). All optional; absence = OFF.
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


def resolve_verification_keys() -> KeyResolver | None:
    """Build the receiver's KeyResolver from its cold-start environment, or None.

    Returns None when no verification-keys ARN is configured — the airlock skips
    the signature gate and unsigned peers pass. When the ARN is set, its
    SecretString is a JSON ``{key_id: public_key_pem}`` map; a set-but-unfetchable
    or malformed value fails closed.
    """
    secret_arn = os.environ.get(VERIFY_KEYS_SECRET_ARN_ENV)
    if not secret_arn:
        return None
    try:
        pem_by_key_id = json.loads(_fetch_secret(secret_arn))
        if not isinstance(pem_by_key_id, dict):
            raise ValueError("verification-keys secret must be a JSON object")
        return key_resolver_from_map(pem_by_key_id)
    except Exception as exc:
        raise SigningConfigError(
            f"{VERIFY_KEYS_SECRET_ARN_ENV} is set but the verification keys could not "
            f"be resolved ({type(exc).__name__})"
        ) from exc
