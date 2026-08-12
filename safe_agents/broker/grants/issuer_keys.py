"""grants.issuer_keys — cold-start resolution of the ISSUER's signing/verify keys.

The impure seam that turns an operator-held Ed25519 key into the pure
``RecordSigner`` that ``grants.record_signing`` consumes — the ceremony
command-side binding that module's docstring defers to, mirroring
``channels.keys`` (the #181 pattern this adopts).

Two key SOURCES, exactly one of which may be set: a Secrets Manager ARN (the
cloud floor) or, since #226, a local PEM file (the no-AWS floor — refused on
the dynamo arm, and refused outright if the file is readable beyond its
owner). Both converge on the same signer; nothing downstream knows which.

The issuer identity is SEPARATE from the broker's chain-signing key: the grant
issuer signs promotions; the broker cannot (symmetric with "the broker cannot
write grants"). The private key is never in the agent image and never held by
the broker — it is resolved here, at ceremony-command cold start, under the
ceremony operator's own credentials.

The verify side (#194) is deliberately asymmetric: the issuer's PUBLIC keys
live in an SSM parameter (``{key_id: public_key_pem}`` JSON map), NOT in
Secrets Manager — verify keys are public material, and the read-only audit
watcher keeps reading no Secrets Manager at all (the namespace-split doctrine;
the ``*/issuer/*`` PRIVATE key stays promotion-side only).

Ships OFF: with NO signing env configured at all, ``resolve_record_signer``
returns None — ratify then REFUSES unless the operator passes an explicit
``--allow-unsigned`` (which stores the record UNSIGNED with a loud warning),
and acknowledge refuses outright. Half-configured — a key_id without the key ARN, or the ARN
without a key_id/zone — REFUSES (#196): the operator intended to sign, so
degrading to an unsigned record is minting a weaker artifact than asked for;
with no parameter name configured, ``resolve_issuer_verify_keys`` returns None
and the audit skips RECORD_SIGNATURE_VERIFIES loudly. A set-but-unresolvable
value fails closed on both paths rather than silently degrading — the same
posture as ``channels.keys``.

The module-level ``_fetch_secret`` / ``_fetch_parameter`` seams are
monkeypatched in tests so no live AWS is needed. Keys are never logged.
"""

from __future__ import annotations

import json
import os

from safe_agents.broker.grants.record_signing import RecordSigner, signer_from_pem
from safe_agents.channels.keys import key_resolver_from_map
from safe_agents.channels.signing import KeyResolver

# Env names — the issuer's signing key (a Secrets-Manager ARN -> PEM private
# key), the key_id a ledger verifier resolves it by, and the zone the record is
# attributed to (overridable per-invocation via the ratify command's --zone).
# All optional; absence of the ARN = OFF (ratify refuses unless
# --allow-unsigned; acknowledge refuses outright).
ISSUER_SIGNING_KEY_SECRET_ARN_ENV = "ISSUER_SIGNING_KEY_SECRET_ARN"
ISSUER_SIGNING_KEY_ID_ENV = "ISSUER_SIGNING_KEY_ID"
ISSUER_SIGNING_ZONE_ENV = "ISSUER_SIGNING_ZONE"

# The LOCAL arm's signing-key source (#226's end-to-end arc): a path to a file
# holding the PEM private key, for a machine with no Secrets Manager to reach.
# Deliberately a bare PEM in a named file, NOT a structured secrets format. One
# key, one file, no schema: this is a SIGNING key resolved by path, not a leaf in
# a credential map, so #126's leaf rule (docs/config-provenance.md, "Secret
# naming") governs the connector credentials beside it and not this.
# Mutually exclusive with the ARN, and REFUSED on the dynamo arm.
ISSUER_SIGNING_KEY_FILE_ENV = "ISSUER_SIGNING_KEY_FILE"

# The read-only verify side (#194): an SSM parameter NAME whose value is a JSON
# ``{key_id: public_key_pem}`` map of the issuer's PUBLIC keys. Optional;
# absence = OFF (the audit skips RECORD_SIGNATURE_VERIFIES, loudly).
ISSUER_VERIFY_KEYS_PARAM_ENV = "ISSUER_VERIFY_KEYS_PARAM"


class IssuerSigningConfigError(RuntimeError):
    """The issuer signing-key ARN is set but could not be resolved.

    Fails the ceremony closed rather than silently storing an unsigned record
    when signing was configured — the same posture as channels.keys.
    """


def _fetch_secret(secret_arn: str) -> str:
    """Fetch a secret's string value from Secrets Manager (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_arn)["SecretString"]


def _read_local_key_file(path: str) -> str:
    """Read the issuer's PEM private key from a local file (the #226 arm).

    Two refusals, both failing toward signing nothing:

    * **The dynamo arm.** On the real floor the issuer key is IAM-controlled
      material in Secrets Manager; a file path there is authority the operator
      did not name through the sanctioned channel — the same gate
      ``ceremony_identity`` puts on a solo identity, for the same reason.
    * **Loose file mode.** A private signing key readable by group or other is
      not a private key. Refusing beats warning: the whole value of the ledger
      signature is that only the issuer could have produced it.
    """
    import stat  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from safe_agents.broker.prototype.boot_config import (  # noqa: PLC0415
        is_dynamo_arm,
        resolve_store_arm,
    )

    if is_dynamo_arm():
        raise IssuerSigningConfigError(
            f"{ISSUER_SIGNING_KEY_FILE_ENV} is set but BROKER_STORE="
            f"{resolve_store_arm()} — refusing to sign ledger records for the "
            "real floor with a key from a local file. On the DynamoDB arm the "
            f"issuer key is Secrets-Manager-held material: set "
            f"{ISSUER_SIGNING_KEY_SECRET_ARN_ENV} instead. The file arm exists "
            "for the local (no-AWS) floor."
        )
    key_path = Path(path)
    try:
        mode = key_path.stat().st_mode
    except OSError as exc:
        raise IssuerSigningConfigError(
            f"{ISSUER_SIGNING_KEY_FILE_ENV}={path} could not be read ({exc})"
        ) from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IssuerSigningConfigError(
            f"{ISSUER_SIGNING_KEY_FILE_ENV}={path} is mode "
            f"{stat.S_IMODE(mode):04o} — refusing to load an issuer signing key "
            "readable beyond its owner (a private key that is not private "
            f"cannot carry attribution). Run: chmod 600 {path}"
        )
    return key_path.read_text(encoding="utf-8")


def _fetch_parameter(name: str) -> str:
    """Fetch an SSM parameter's value (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency

    return boto3.client("ssm").get_parameter(Name=name)["Parameter"]["Value"]


def resolve_issuer_verify_keys() -> KeyResolver | None:
    """Build the auditor's read-only issuer KeyResolver, or None (#194).

    Returns None when ISSUER_VERIFY_KEYS_PARAM is unset — the audit skips
    RECORD_SIGNATURE_VERIFIES and says so in skipped_rules. When set, the SSM
    parameter's value is a JSON ``{key_id: public_key_pem}`` map (an empty map
    is valid: an environment whose issuer is not yet provisioned resolves every
    key_id to unknown, so any signed record appearing there fails LOUD). A
    set-but-unfetchable or malformed value fails closed rather than silently
    skipping a rule the operator configured to run.
    """
    param_name = os.environ.get(ISSUER_VERIFY_KEYS_PARAM_ENV)
    if not param_name:
        return None
    try:
        pem_by_key_id = json.loads(_fetch_parameter(param_name))
        if not isinstance(pem_by_key_id, dict):
            raise ValueError("issuer verify-keys parameter must be a JSON object")
        return key_resolver_from_map(pem_by_key_id)
    except Exception as exc:
        raise IssuerSigningConfigError(
            f"{ISSUER_VERIFY_KEYS_PARAM_ENV} is set but the issuer verify keys "
            f"could not be resolved ({type(exc).__name__})"
        ) from exc


def resolve_record_signer(zone: str | None = None) -> RecordSigner | None:
    """Build the issuer's RecordSigner from the cold-start environment, or None.

    Returns None only when NO signing env is configured (ratify then refuses
    unless --allow-unsigned was passed; acknowledge refuses). A key_id
    without the ARN
    refuses (#196) — half-configured signing never degrades to unsigned.
    When the ARN is set, both a
    ``key_id`` (ISSUER_SIGNING_KEY_ID) and a zone (the ``zone`` argument, else
    ISSUER_SIGNING_ZONE) are required — a signer a verifier cannot resolve or
    attribute is a misconfiguration, never a silent default.
    """
    secret_arn = os.environ.get(ISSUER_SIGNING_KEY_SECRET_ARN_ENV)
    key_file = os.environ.get(ISSUER_SIGNING_KEY_FILE_ENV)
    if secret_arn and key_file:
        raise IssuerSigningConfigError(
            f"both {ISSUER_SIGNING_KEY_SECRET_ARN_ENV} and "
            f"{ISSUER_SIGNING_KEY_FILE_ENV} are set — the issuer's signing key "
            "has two candidate sources and picking one silently would attribute "
            "records to a key the operator may not have meant. Set exactly one."
        )
    if not secret_arn and not key_file:
        # Half-configured signing REFUSES (#196): a key_id without any key
        # SOURCE means the operator intended to sign — degrading to an unsigned
        # record here already produced one audit violation live (the Phase 6
        # drill's unsigned 03:31 record). Fail toward less authority, the
        # #190 write-order polarity applied to config.
        if os.environ.get(ISSUER_SIGNING_KEY_ID_ENV):
            raise IssuerSigningConfigError(
                f"{ISSUER_SIGNING_KEY_ID_ENV} is set but neither "
                f"{ISSUER_SIGNING_KEY_SECRET_ARN_ENV} nor "
                f"{ISSUER_SIGNING_KEY_FILE_ENV} is — signing is "
                "half-configured; refusing rather than storing an unsigned "
                "record. Set a key source or unset the issuer signing env."
            )
        return None
    source_env = (
        ISSUER_SIGNING_KEY_SECRET_ARN_ENV if secret_arn else ISSUER_SIGNING_KEY_FILE_ENV
    )
    key_id = os.environ.get(ISSUER_SIGNING_KEY_ID_ENV)
    if not key_id:
        raise IssuerSigningConfigError(
            f"{source_env} is set but "
            f"{ISSUER_SIGNING_KEY_ID_ENV} is not; a signer needs a key_id a "
            "ledger verifier can resolve"
        )
    effective_zone = zone or os.environ.get(ISSUER_SIGNING_ZONE_ENV)
    if not effective_zone:
        raise IssuerSigningConfigError(
            f"{source_env} is set but no zone is "
            f"configured; pass --zone or set {ISSUER_SIGNING_ZONE_ENV}"
        )
    try:
        pem = _fetch_secret(secret_arn) if secret_arn else _read_local_key_file(key_file)
        return signer_from_pem(key_id, effective_zone, pem)
    except IssuerSigningConfigError:
        raise
    except Exception as exc:
        raise IssuerSigningConfigError(
            f"{source_env} is set but the issuer signing "
            f"key could not be resolved ({type(exc).__name__})"
        ) from exc
