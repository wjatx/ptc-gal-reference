"""grants.issuer_keys — cold-start resolution of the ledger signing/verify keys.

The impure seam that turns an operator-held Ed25519 key into the pure
``RecordSigner`` that ``grants.record_signing`` consumes — the command-side
binding that module's docstring defers to, mirroring ``channels.keys`` (the
#181 pattern this adopts).

**Two ROLES, two key sources, one code path.** GAL-SPEC §6.10 requires every
ledger record to be signed, and §6.7.2 requires the demotion evaluator to be a
separate identity from the issuer. Handing the evaluator the issuer key to
satisfy the first would break the second — it could then mint promotion
records — so there are two signing identities:

  * ``issuer``    — signs ``promotion``, ``bootstrap`` and ``tightening``:
    the ceremony/operator side, which already holds this key.
  * ``evaluator`` — signs ``demotion`` and ``lapse``: the automatic, no-model
    side, which only ever lowers authority.

Each role reads its OWN env names (``ISSUER_*`` / ``EVALUATOR_*``) through the
same generic resolver below. The separation is deliberately in the SOURCE of
the key material, never a role field parsed out of one shared map: a field is
something a store-loaded config could set, and the authority split would then
be a value rather than a boundary (docs/config-provenance.md).

Two key SOURCES per role, exactly one of which may be set: a Secrets Manager
ARN (the cloud floor) or, since #226, a local PEM file (the no-AWS floor —
refused on the dynamo arm, and refused outright if the file is readable beyond
its owner). Both converge on the same signer; nothing downstream knows which.

The verify side (#194) is deliberately asymmetric: the PUBLIC keys live in an
SSM parameter (``{key_id: public_key_pem}`` JSON map), NOT in Secrets Manager —
verify keys are public material, and the read-only audit watcher keeps reading
no Secrets Manager at all (the namespace-split doctrine; the ``*/issuer/*`` and
``*/evaluator/*`` PRIVATE keys stay write-side only). A key_id appearing in
BOTH roles' verify maps is a configuration error and refuses here, at cold
start, where both parameter names can be named — a key with two roles is no
split at all.

Ships OFF, per role: with NO signing env configured for a role,
``resolve_record_signer`` / ``resolve_evaluator_signer`` return None and that
role's writers keep today's unsigned behaviour (ratify is the exception — it
REFUSES unless the operator passes ``--allow-unsigned``, and acknowledge
refuses outright). Half-configured — a key_id without the key source, or a key
source without a key_id/zone — REFUSES (#196): the operator intended to sign,
so degrading to an unsigned record is minting a weaker artifact than asked for.
With no parameter name configured, the verify resolver is None and the audit
skips RECORD_SIGNATURE_VERIFIES loudly. A set-but-unresolvable value fails
closed on both paths rather than silently degrading — the same posture as
``channels.keys``.

The module-level ``_fetch_secret`` / ``_fetch_parameter`` seams are
monkeypatched in tests so no live AWS is needed. Keys are never logged.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from safe_agents.broker.grants.record_signing import (
    EVALUATOR_ROLE,
    ISSUER_ROLE,
    RecordSigner,
    RoleKeyResolvers,
    signer_from_pem,
)
from safe_agents.channels.keys import key_resolver_from_map
from safe_agents.channels.signing import KeyResolver

# Env names — the issuer's signing key (a Secrets-Manager ARN -> PEM private
# key), the key_id a ledger verifier resolves it by, and the zone the record is
# attributed to (overridable per-invocation via a command's --zone).
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

# The EVALUATOR's four, mirroring the issuer contract exactly — same two
# mutually-exclusive sources, same half-configured refusal, same dynamo-arm
# refusal on the file arm, same public verify parameter. Separate NAMES are the
# control: which key an identity can reach is decided by what its environment
# is given, which on the cloud floor is decided by IAM.
EVALUATOR_SIGNING_KEY_SECRET_ARN_ENV = "EVALUATOR_SIGNING_KEY_SECRET_ARN"
EVALUATOR_SIGNING_KEY_ID_ENV = "EVALUATOR_SIGNING_KEY_ID"
EVALUATOR_SIGNING_ZONE_ENV = "EVALUATOR_SIGNING_ZONE"
EVALUATOR_SIGNING_KEY_FILE_ENV = "EVALUATOR_SIGNING_KEY_FILE"
EVALUATOR_VERIFY_KEYS_PARAM_ENV = "EVALUATOR_VERIFY_KEYS_PARAM"


class IssuerSigningConfigError(RuntimeError):
    """A ledger signing/verify key is configured but could not be resolved.

    Fails the ceremony closed rather than silently storing an unsigned record
    when signing was configured — the same posture as channels.keys. Named for
    the issuer because that was the only role when it was introduced; it covers
    both roles (and the cross-role overlap refusal).
    """


@dataclass(frozen=True)
class SigningRoleEnv:
    """The env contract for ONE signing role — the only thing that differs.

    Everything else about resolving a signer or a verify map is shared, so the
    two roles run the same code path and neither can drift into a weaker rule
    than the other.
    """

    role: str
    key_secret_arn_env: str
    key_file_env: str
    key_id_env: str
    zone_env: str
    verify_keys_param_env: str


ISSUER_ROLE_ENV = SigningRoleEnv(
    role=ISSUER_ROLE,
    key_secret_arn_env=ISSUER_SIGNING_KEY_SECRET_ARN_ENV,
    key_file_env=ISSUER_SIGNING_KEY_FILE_ENV,
    key_id_env=ISSUER_SIGNING_KEY_ID_ENV,
    zone_env=ISSUER_SIGNING_ZONE_ENV,
    verify_keys_param_env=ISSUER_VERIFY_KEYS_PARAM_ENV,
)

EVALUATOR_ROLE_ENV = SigningRoleEnv(
    role=EVALUATOR_ROLE,
    key_secret_arn_env=EVALUATOR_SIGNING_KEY_SECRET_ARN_ENV,
    key_file_env=EVALUATOR_SIGNING_KEY_FILE_ENV,
    key_id_env=EVALUATOR_SIGNING_KEY_ID_ENV,
    zone_env=EVALUATOR_SIGNING_ZONE_ENV,
    verify_keys_param_env=EVALUATOR_VERIFY_KEYS_PARAM_ENV,
)

SIGNING_ROLE_ENVS: tuple[SigningRoleEnv, ...] = (ISSUER_ROLE_ENV, EVALUATOR_ROLE_ENV)


def _fetch_secret(secret_arn: str) -> str:
    """Fetch a secret's string value from Secrets Manager (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_arn)["SecretString"]


def _read_local_key_file(path: str, role_env: SigningRoleEnv) -> str:
    """Read a role's PEM private key from a local file (the #226 arm).

    Two refusals, both failing toward signing nothing:

    * **The dynamo arm.** On the real floor a ledger signing key is
      IAM-controlled material in Secrets Manager; a file path there is
      authority the operator did not name through the sanctioned channel — the
      same gate ``ceremony_identity`` puts on a solo identity, for the same
      reason.
    * **Loose file mode.** A private signing key readable by group or other is
      not a private key. Refusing beats warning: the whole value of the ledger
      signature is that only that role's identity could have produced it.
    """
    import stat  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from safe_agents.broker.prototype.boot_config import (  # noqa: PLC0415
        is_dynamo_arm,
        resolve_store_arm,
    )

    if is_dynamo_arm():
        raise IssuerSigningConfigError(
            f"{role_env.key_file_env} is set but BROKER_STORE="
            f"{resolve_store_arm()} — refusing to sign ledger records for the "
            f"real floor with a key from a local file. On the DynamoDB arm the "
            f"{role_env.role} key is Secrets-Manager-held material: set "
            f"{role_env.key_secret_arn_env} instead. The file arm exists "
            "for the local (no-AWS) floor."
        )
    key_path = Path(path)
    try:
        mode = key_path.stat().st_mode
    except OSError as exc:
        raise IssuerSigningConfigError(
            f"{role_env.key_file_env}={path} could not be read ({exc})"
        ) from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IssuerSigningConfigError(
            f"{role_env.key_file_env}={path} is mode "
            f"{stat.S_IMODE(mode):04o} — refusing to load a {role_env.role} signing key "
            "readable beyond its owner (a private key that is not private "
            f"cannot carry attribution). Run: chmod 600 {path}"
        )
    return key_path.read_text(encoding="utf-8")


def _fetch_parameter(name: str) -> str:
    """Fetch an SSM parameter's value (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency

    return boto3.client("ssm").get_parameter(Name=name)["Parameter"]["Value"]


# ---------------------------------------------------------------------------
# The shared resolvers — parameterized by role, identical rules
# ---------------------------------------------------------------------------


def _verify_keys_for_role(
    role_env: SigningRoleEnv,
) -> tuple[frozenset[str], KeyResolver] | None:
    """The role's known key_ids and its KeyResolver, or None when unconfigured.

    The key_id SET comes back beside the resolver so the cross-role overlap
    check can see what each map holds — a closure alone cannot be enumerated.
    An empty map is valid: an environment whose signer is not yet provisioned
    resolves every key_id to unknown, so any signed record appearing there
    fails LOUD.
    """
    param_name = os.environ.get(role_env.verify_keys_param_env)
    if not param_name:
        return None
    try:
        pem_by_key_id = json.loads(_fetch_parameter(param_name))
        if not isinstance(pem_by_key_id, dict):
            raise ValueError("verify-keys parameter must be a JSON object")
        # key_resolver_from_map parses every PEM up front, so a malformed key
        # fails HERE, at cold start, not on the first record verified.
        resolver = key_resolver_from_map(pem_by_key_id)
    except Exception as exc:
        raise IssuerSigningConfigError(
            f"{role_env.verify_keys_param_env} is set but the {role_env.role} verify "
            f"keys could not be resolved ({type(exc).__name__})"
        ) from exc
    return frozenset(pem_by_key_id), resolver


def resolve_verify_keys_for_role(role_env: SigningRoleEnv) -> KeyResolver | None:
    """Build one role's read-only KeyResolver, or None when unconfigured (#194)."""
    resolved = _verify_keys_for_role(role_env)
    return None if resolved is None else resolved[1]


def resolve_signer_for_role(
    role_env: SigningRoleEnv, zone: str | None = None
) -> RecordSigner | None:
    """Build one role's RecordSigner from the cold-start environment, or None.

    Returns None only when NO signing env is configured for the role. A key_id
    without a key SOURCE refuses (#196) — half-configured signing never
    degrades to unsigned. When a source is set, both a key_id and a zone (the
    ``zone`` argument, else the role's zone env) are required: a signer a
    verifier cannot resolve or attribute is a misconfiguration, never a silent
    default.
    """
    secret_arn = os.environ.get(role_env.key_secret_arn_env)
    key_file = os.environ.get(role_env.key_file_env)
    if secret_arn and key_file:
        raise IssuerSigningConfigError(
            f"both {role_env.key_secret_arn_env} and "
            f"{role_env.key_file_env} are set — the {role_env.role}'s signing key "
            "has two candidate sources and picking one silently would attribute "
            "records to a key the operator may not have meant. Set exactly one."
        )
    if not secret_arn and not key_file:
        # Half-configured signing REFUSES (#196): a key_id without any key
        # SOURCE means the operator intended to sign — degrading to an unsigned
        # record here already produced one audit violation live (the Phase 6
        # drill's unsigned 03:31 record). Fail toward less authority, the
        # #190 write-order polarity applied to config.
        if os.environ.get(role_env.key_id_env):
            raise IssuerSigningConfigError(
                f"{role_env.key_id_env} is set but neither "
                f"{role_env.key_secret_arn_env} nor "
                f"{role_env.key_file_env} is — {role_env.role} signing is "
                "half-configured; refusing rather than storing an unsigned "
                f"record. Set a key source or unset the {role_env.role} signing env."
            )
        return None
    source_env = role_env.key_secret_arn_env if secret_arn else role_env.key_file_env
    key_id = os.environ.get(role_env.key_id_env)
    if not key_id:
        raise IssuerSigningConfigError(
            f"{source_env} is set but "
            f"{role_env.key_id_env} is not; a signer needs a key_id a "
            "ledger verifier can resolve"
        )
    effective_zone = zone or os.environ.get(role_env.zone_env)
    if not effective_zone:
        raise IssuerSigningConfigError(
            f"{source_env} is set but no zone is "
            f"configured; pass --zone or set {role_env.zone_env}"
        )
    try:
        pem = (
            _fetch_secret(secret_arn)
            if secret_arn
            else _read_local_key_file(key_file, role_env)
        )
        return signer_from_pem(key_id, effective_zone, pem)
    except IssuerSigningConfigError:
        raise
    except Exception as exc:
        raise IssuerSigningConfigError(
            f"{source_env} is set but the {role_env.role} signing "
            f"key could not be resolved ({type(exc).__name__})"
        ) from exc


# ---------------------------------------------------------------------------
# Per-role entry points — the names cluster manifests and CDK already bind to
# ---------------------------------------------------------------------------


def resolve_issuer_verify_keys() -> KeyResolver | None:
    """Build the auditor's read-only ISSUER KeyResolver, or None (#194)."""
    return resolve_verify_keys_for_role(ISSUER_ROLE_ENV)


def resolve_evaluator_verify_keys() -> KeyResolver | None:
    """Build the auditor's read-only EVALUATOR KeyResolver, or None."""
    return resolve_verify_keys_for_role(EVALUATOR_ROLE_ENV)


def resolve_record_signer(zone: str | None = None) -> RecordSigner | None:
    """Build the ISSUER's RecordSigner from the cold-start environment, or None.

    The ceremony/operator side: promotion, bootstrap and tightening records,
    plus the MCP admission ledger and acknowledgment waivers.
    """
    return resolve_signer_for_role(ISSUER_ROLE_ENV, zone)


def resolve_evaluator_signer(zone: str | None = None) -> RecordSigner | None:
    """Build the EVALUATOR's RecordSigner from the cold-start environment, or None.

    The automatic no-model side: demotion and lapse records. Deliberately NOT
    the issuer key — an evaluator holding that could mint promotion records,
    which is the ceremony boundary GAL §6.7.2 exists to draw.
    """
    return resolve_signer_for_role(EVALUATOR_ROLE_ENV, zone)


def resolve_record_key_resolvers() -> RoleKeyResolvers | None:
    """Both roles' verify maps, or None when NEITHER is configured.

    Refuses a key_id present in both maps: a key with two roles is no split at
    all, and the failure must be loud at cold start rather than per-record at
    verify time — here, the message can name both parameters and the key.
    """
    issuer = _verify_keys_for_role(ISSUER_ROLE_ENV)
    evaluator = _verify_keys_for_role(EVALUATOR_ROLE_ENV)
    if issuer is None and evaluator is None:
        return None
    shared = sorted(
        (issuer[0] if issuer else frozenset()) & (evaluator[0] if evaluator else frozenset())
    )
    if shared:
        raise IssuerSigningConfigError(
            f"key_id(s) {shared} appear in BOTH "
            f"{ISSUER_VERIFY_KEYS_PARAM_ENV} and {EVALUATOR_VERIFY_KEYS_PARAM_ENV} — "
            "one key cannot hold two signing roles, or the evaluator could mint "
            "promotion records. Provision a separate key per role."
        )
    return RoleKeyResolvers(
        issuer=issuer[1] if issuer else None,
        evaluator=evaluator[1] if evaluator else None,
    )
