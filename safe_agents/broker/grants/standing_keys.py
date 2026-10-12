"""grants.standing_keys: resolving each role's standing source from the environment.

The impure seam between the env contract in ``grants.issuer_keys`` and the
per-process ``grants.standing_source.StandingSource``. Every value read here is
bound at deploy: the document's location (``<ROLE>_STANDING_PARAM`` or
``<ROLE>_STANDING_FILE``), its maximum age (``<ROLE>_STANDING_MAX_AGE_SECONDS``)
and the standing authority's public keys
(``STANDING_AUTHORITY_VERIFY_KEYS_PARAM`` or ``..._FILE``). None of them is read
from a store, a grant or a record.

Refusals at startup, each failing toward checking more rather than less:

* a role with both a standing source and a flat verify-key map (two candidate
  sources for which signatures count);
* a standing source with both transports set, with no maximum age, or with an
  age that is not a positive whole number of seconds;
* a standing source with no standing-authority keys to verify it under;
* a per-agent maximum age longer than the deploy-bound one, or one given for a
  role with no standing source;
* a key held by two roles, by key id or by key bytes, the standing authority
  included.

There is no default age and no base ceiling on it, beyond the hundred-year
bound every declared age has so its end stays a representable instant.
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass
from typing import Mapping

from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants.issuer_keys import (
    EVALUATOR_ROLE_ENV,
    ISSUER_ROLE_ENV,
    SIGNING_ROLE_ENVS,
    STANDING_AUTHORITY_ROLE_ENV,
    IssuerSigningConfigError,
    SigningRoleEnv,
)
from safe_agents.broker.grants.key_standing import public_key_raw
from safe_agents.broker.grants.record_signing import RoleKeyResolvers
from safe_agents.broker.grants.standing_source import StandingSource
from safe_agents.broker.runtime.input_age import utc_now
from safe_agents.broker.schemas.common import MAX_DECLARABLE_AGE_SECONDS
from safe_agents.channels.signing import KeyResolver

#: The decision input a per-agent manifest shortens a role's age under
#: (``AgentManifest.input_max_age_seconds``). Only the issuer has one: an
#: evaluator key's withdrawal changes no enforced level, so no broker decision
#: depends on the evaluator's standing.
STANDING_INPUT_NAMES: Mapping[str, str] = {ISSUER_ROLE_ENV.role: "issuer_standing"}


@dataclass(frozen=True)
class AuthorityKeys:
    """The standing authority's public keys, as bound at deploy."""

    key_ids: frozenset[str]
    resolver: KeyResolver
    public_keys: frozenset[bytes]


@dataclass(frozen=True)
class RoleVerifyMaterial:
    """One role's verify keys, and the standing source they came from if any."""

    key_ids: frozenset[str]
    resolver: KeyResolver
    public_keys: frozenset[bytes]
    source: StandingSource | None


def _env(name: str | None) -> str | None:
    return os.environ.get(name) if name else None


def standing_configured(role_env: SigningRoleEnv) -> bool:
    return bool(_env(role_env.standing_param_env) or _env(role_env.standing_file_env))


def resolve_standing_authority_keys() -> AuthorityKeys | None:
    """The third role's public keys, or None when none are configured."""
    resolved = issuer_keys._verify_keys_for_role(STANDING_AUTHORITY_ROLE_ENV)
    if resolved is None:
        return None
    key_ids, resolver, raw = resolved
    return AuthorityKeys(key_ids=key_ids, resolver=resolver, public_keys=raw)


def deploy_max_age(role_env: SigningRoleEnv) -> datetime.timedelta:
    """The role's deploy-bound maximum age. Required: there is no default."""
    name = role_env.standing_max_age_env
    text = _env(name)
    if not text:
        raise IssuerSigningConfigError(
            f"a {role_env.role} standing source is configured but {name} is not; a "
            "standing document needs a declared maximum age, and there is no default"
        )
    try:
        seconds = int(text)
    except ValueError as exc:
        raise IssuerSigningConfigError(
            f"{name}={text!r} is not a whole number of seconds"
        ) from exc
    if seconds <= 0 or seconds > MAX_DECLARABLE_AGE_SECONDS:
        raise IssuerSigningConfigError(
            f"{name}={seconds} must be a positive number of seconds no larger than "
            f"{MAX_DECLARABLE_AGE_SECONDS}"
        )
    return datetime.timedelta(seconds=seconds)


def effective_max_age(
    role_env: SigningRoleEnv, per_agent_seconds: int | None
) -> datetime.timedelta:
    """The age a process applies: the deploy-bound one, or a per-agent one no longer.

    A per-agent value may only shorten the deploy-bound age. A longer one is
    refused rather than clamped: an operator who asked for a wider window must
    learn that it was not granted.
    """
    deploy = deploy_max_age(role_env)
    if per_agent_seconds is None:
        return deploy
    if isinstance(per_agent_seconds, bool) or not isinstance(per_agent_seconds, int):
        raise IssuerSigningConfigError("a per-agent standing age is a whole number of seconds")
    if per_agent_seconds <= 0:
        raise IssuerSigningConfigError("a per-agent standing age must be positive")
    per_agent = datetime.timedelta(seconds=per_agent_seconds)
    if per_agent > deploy:
        raise IssuerSigningConfigError(
            f"the per-agent {role_env.role} standing age ({per_agent_seconds}s) is longer "
            f"than the deploy-bound {role_env.standing_max_age_env} "
            f"({int(deploy.total_seconds())}s); a per-agent value may only shorten it"
        )
    return per_agent


def resolve_standing_source(
    role_env: SigningRoleEnv,
    *,
    per_agent_max_age_seconds: int | None = None,
    clock=utc_now,
) -> StandingSource | None:
    """Build ``role_env``'s standing source, or None when none is configured.

    Fetches nothing: the caller decides when to ``refresh``. Refuses every
    configuration error listed in the module docstring.
    """
    param = _env(role_env.standing_param_env)
    path = _env(role_env.standing_file_env)
    if not param and not path:
        if per_agent_max_age_seconds is not None:
            raise IssuerSigningConfigError(
                f"a per-agent {role_env.role} standing age is declared but no "
                f"{role_env.standing_param_env} or {role_env.standing_file_env} is set; "
                "an age for a source that does not exist bounds nothing"
            )
        return None
    if param and path:
        raise IssuerSigningConfigError(
            f"both {role_env.standing_param_env} and {role_env.standing_file_env} are set; "
            "set exactly one"
        )
    if _env(role_env.verify_keys_param_env) or _env(role_env.verify_keys_file_env):
        raise IssuerSigningConfigError(
            f"the {role_env.role} has both a standing document and a flat verify-key "
            f"map ({role_env.verify_keys_param_env} / {role_env.verify_keys_file_env}); "
            "the document replaces the map, so set exactly one"
        )
    max_age = effective_max_age(role_env, per_agent_max_age_seconds)
    authority = resolve_standing_authority_keys()
    if authority is None:
        raise IssuerSigningConfigError(
            f"a {role_env.role} standing source is configured but neither "
            f"{STANDING_AUTHORITY_ROLE_ENV.verify_keys_param_env} nor "
            f"{STANDING_AUTHORITY_ROLE_ENV.verify_keys_file_env} is; an unsigned or "
            "unverifiable standing document is never accepted"
        )
    if param:
        label = f"{role_env.standing_param_env}={param}"

        def fetch() -> str:
            return issuer_keys._fetch_parameter(param)
    else:
        label = f"{role_env.standing_file_env}={path}"

        def fetch() -> str:
            return issuer_keys._read_verify_keys_file(path)

    return StandingSource(
        role=role_env.role,
        fetch=fetch,
        source_label=label,
        authority=authority.resolver,
        authority_key_ids=authority.key_ids,
        authority_public_keys=authority.public_keys,
        max_age=max_age,
        clock=clock,
    )


def resolve_standing_sources(
    *, per_agent_max_age_seconds: Mapping[str, int] | None = None, clock=utc_now
) -> dict[str, StandingSource]:
    """Every configured role's standing source, keyed by role. Empty when none is.

    ``per_agent_max_age_seconds`` is keyed by role. For a broker, pass the
    issuer's from ``AgentManifest.input_max_age_seconds["issuer_standing"]``.
    """
    ages = per_agent_max_age_seconds or {}
    sources: dict[str, StandingSource] = {}
    for role_env in SIGNING_ROLE_ENVS:
        source = resolve_standing_source(
            role_env, per_agent_max_age_seconds=ages.get(role_env.role), clock=clock
        )
        if source is not None:
            sources[role_env.role] = source
    return sources


def role_verify_material(role_env: SigningRoleEnv) -> RoleVerifyMaterial | None:
    """One role's verify keys: from its standing document, else its flat map.

    A standing source is fetched once here and must be accepted, or this
    refuses: a configured source that cannot be read or verified never becomes
    a skipped signature rule.
    """
    source = resolve_standing_source(role_env)
    if source is None:
        resolved = issuer_keys._verify_keys_for_role(role_env)
        if resolved is None:
            return None
        key_ids, resolver, raw = resolved
        return RoleVerifyMaterial(key_ids, resolver, raw, None)
    load = source.refresh()
    if not load.accepted:
        raise IssuerSigningConfigError(
            f"{source.source_label}: the {role_env.role} standing document was not "
            f"accepted ({load.verdict}: {load.detail})"
        )
    document = source.document
    raw = frozenset(public_key_raw(entry.publicKey) for entry in document.keys.values())
    return RoleVerifyMaterial(source.known_key_ids(), source.key_resolver(), raw, source)


def resolve_role_key_resolvers() -> RoleKeyResolvers | None:
    """Both record-signing roles' verify keys, with standing where configured.

    See ``issuer_keys.resolve_record_key_resolvers``, which delegates here.
    """
    issuer = role_verify_material(ISSUER_ROLE_ENV)
    evaluator = role_verify_material(EVALUATOR_ROLE_ENV)
    if issuer is None and evaluator is None:
        return None
    _refuse_shared_keys(issuer, evaluator)
    standing = {
        role: material.source
        for role, material in ((ISSUER_ROLE_ENV.role, issuer), (EVALUATOR_ROLE_ENV.role, evaluator))
        if material is not None and material.source is not None
    }
    return RoleKeyResolvers(
        issuer=issuer.resolver if issuer else None,
        evaluator=evaluator.resolver if evaluator else None,
        standing=standing,
    )


def _source_name(role_env: SigningRoleEnv) -> str:
    if standing_configured(role_env):
        return role_env.standing_file_env if _env(role_env.standing_file_env) else (
            role_env.standing_param_env
        )
    return issuer_keys._verify_keys_source_env(role_env)


def _refuse_shared_keys(
    issuer: RoleVerifyMaterial | None, evaluator: RoleVerifyMaterial | None
) -> None:
    empty_ids: frozenset[str] = frozenset()
    empty_raw: frozenset[bytes] = frozenset()
    shared = sorted(
        (issuer.key_ids if issuer else empty_ids) & (evaluator.key_ids if evaluator else empty_ids)
    )
    if shared:
        raise IssuerSigningConfigError(
            f"key_id(s) {shared} appear in BOTH {_source_name(ISSUER_ROLE_ENV)} and "
            f"{_source_name(EVALUATOR_ROLE_ENV)}; one key cannot hold two signing roles, "
            "or the evaluator could mint promotion records. Provision a separate key per role."
        )
    if (issuer.public_keys if issuer else empty_raw) & (
        evaluator.public_keys if evaluator else empty_raw
    ):
        raise IssuerSigningConfigError(
            f"one public key appears under different key ids in {_source_name(ISSUER_ROLE_ENV)} "
            f"and {_source_name(EVALUATOR_ROLE_ENV)}; one key cannot hold two signing roles"
        )
    authority = resolve_standing_authority_keys()
    if authority is None:
        return
    for material, role_env in ((issuer, ISSUER_ROLE_ENV), (evaluator, EVALUATOR_ROLE_ENV)):
        if material is None:
            continue
        if material.key_ids & authority.key_ids or material.public_keys & authority.public_keys:
            raise IssuerSigningConfigError(
                f"a standing-authority key appears in {_source_name(role_env)}; the third "
                "role's keys are never the issuer's or the evaluator's"
            )
