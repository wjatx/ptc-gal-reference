"""Credential-resolution strategies — the pluggable seam between a connector tool
and its LIVE credential (#173).

Before #173 the Doer resolved a connector's credential as one static secret string:
``secrets.fetch_secret(leaf)``. Real backends need more — an OAuth access token
minted from a broker-held refresh token, an STS-assumed role, the broker's own
ambient identity. This module generalizes credential resolution into a pluggable
*strategy* the Doer invokes per call, at execute time.

Floor invariant preserved (doctrine #1 — no raw passthrough): the broker resolves
the live credential; only that credential reaches the Doer/connector, never the
agent. Long-lived material (a refresh token, a role's trust) stays broker-side —
what a connector receives is the short-lived, minted result. "agent holds no
credentials" holds while "a credential" generalizes from a static string to a
rotated token.

The strategy CATALOG here is base-owned and CLOSED. A manifest's ``connector_auth``
block *selects* a strategy by the ``AuthStrategy`` enum and *configures* it with a
string ``params`` map — there is no import-path seam (unlike ``connector_providers``),
so nothing store-loaded can inject a resolution strategy. Selecting a strategy the
base has not implemented fails loudly at broker build, never silently.

Exports:
    CredentialProvider          — the Protocol the Doer depends on.
    StaticSecret                — the default; identical to the pre-#173 behavior.
    OAuthRefresh                — broker-held refresh token → minted access token;
                                  the refresh token never leaves the broker.
    AssumedRole                 — STS-assume a per-capability scoped role at execute
                                  time (#175); the connector runs with short-lived
                                  role credentials whose blast radius == the role's
                                  declared IAM scope, never the broker's own identity.
    build_credential_strategies — compile a manifest connector_auth block into a
                                  tool → CredentialProvider map.
    CredentialStrategyError     — raised for a malformed/unsupported strategy config
                                  (fail at broker build, not at the wire).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from safe_agents.broker.schemas import AuthStrategy, ConnectorAuth

from .connector import AssumedRoleCredential, Credential
from .secrets import RotatableSecretsProvider, SecretsProvider


class CredentialStrategyError(Exception):
    """Raised when a connector_auth entry is malformed or names an unimplemented
    strategy. Surfaced at broker build (strategy compilation), never at the wire —
    a boot-time failure, not a per-call surprise.
    """


@runtime_checkable
class CredentialProvider(Protocol):
    """Resolve one connector tool's LIVE credential at execute time.

    The Doer holds a CredentialProvider per tool and calls ``resolve`` inside
    ``execute()`` — the credential is fetched lazily, used, and discarded. The agent
    process has no path to this object (invariant 1: the agent holds no credentials).

    ``secret_name`` is the tool→leaf mapping the Doer already computes (the
    ``connector_secrets`` override or the default leaf == tool name). ``StaticSecret``
    fetches exactly that leaf; a non-static strategy may use it as a default or ignore
    it in favor of leaves named in its own params (``AssumedRole`` uses no secret at
    all — its credential is an assumed identity, not a stored string).

    The resolved ``Credential`` is a plain ``str`` for the string strategies and an
    ``AssumedRoleCredential`` bundle for ``assumed_role`` (#175). Whatever the shape,
    only the resolved credential crosses into the connector; long-lived material
    (a refresh token, a role's trust) stays broker-side.
    """

    def resolve(self, *, secrets: SecretsProvider, secret_name: str) -> Credential:
        """Return the live credential for this call (a string, or a role bundle)."""
        ...


class StaticSecret:
    """The default strategy — byte-for-byte the pre-#173 behavior.

    Fetches the single secret leaf the Doer computed and returns it verbatim. This is
    the degenerate case the whole seam generalizes: a Doer with no strategy for a tool
    falls back to this, so an unconfigured connector behaves exactly as it did before.
    """

    def resolve(self, *, secrets: SecretsProvider, secret_name: str) -> str:
        return secrets.fetch_secret(secret_name)

    @classmethod
    def from_params(cls, params: dict[str, str]) -> "StaticSecret":
        if params:
            raise CredentialStrategyError(
                f"static_secret takes no params; got {sorted(params)!r}"
            )
        return cls()


@dataclass(frozen=True)
class _TokenRequest:
    """The inputs to one OAuth refresh-grant exchange, resolved broker-side.

    Carries the *resolved* refresh token and client secret (already fetched from the
    secrets store) — this object never leaves the broker and is the argument to the
    injectable token fetcher, so a test fetcher can assert on it without a network call.
    """

    token_url: str
    client_id: str
    refresh_token: str
    client_secret: str | None
    scope: str | None


# A token fetcher performs the actual refresh-grant HTTP exchange and returns the
# access token. Injectable so conformance tests run without a network (the default
# is a urllib POST); the request object is fully resolved before it is called.
@dataclass(frozen=True)
class _TokenGrant:
    """What a refresh grant returns. ``rotated_refresh_token`` is the successor
    the authorization server issued, when it issues one (#238).

    The fetcher used to return a bare ``access_token`` string, which silently
    DISCARDED any rotated refresh token — and a vendor that rotates invalidates
    the old one on use, so discarding it destroys the chain and strands the
    credential until a human re-authorizes. A real brokerage does exactly this, and
    OAuth 2.1 recommends it for public clients, so this is the common case rather
    than an exotic one.
    """

    access_token: str
    rotated_refresh_token: str | None = None
    expires_in: int | None = None


TokenFetcher = Callable[[_TokenRequest], _TokenGrant]

#: Refresh this long before the server's stated expiry, so a token cannot go
#: stale in flight between the cache check and the far end validating it.
_EXPIRY_SKEW_SECONDS = 300.0


def _urllib_token_fetcher(request: _TokenRequest) -> str:
    """Default token fetcher — a stdlib urllib POST of the refresh grant.

    Imports urllib lazily so the module stays import-clean in environments that never
    exercise the network path. Posts an ``application/x-www-form-urlencoded`` refresh
    grant and returns the ``access_token`` from the JSON response. Raises
    CredentialStrategyError with a credential-free message on any failure — the Doer
    additionally redacts, but this layer must not embed the token in the first place.
    """
    import urllib.error  # noqa: PLC0415
    import urllib.parse  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    form = {
        "grant_type": "refresh_token",
        "refresh_token": request.refresh_token,
        "client_id": request.client_id,
    }
    if request.client_secret is not None:
        form["client_secret"] = request.client_secret
    if request.scope is not None:
        form["scope"] = request.scope

    body = urllib.parse.urlencode(form).encode("utf-8")
    http_request = urllib.request.Request(  # noqa: S310 — token_url is operator config, not agent input
        request.token_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_request, timeout=10) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError) as exc:
        # Deliberately do NOT interpolate the request (it holds the refresh token).
        raise CredentialStrategyError(
            f"oauth_refresh token exchange with {request.token_url!r} failed: "
            f"{type(exc).__name__}"
        ) from None

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise CredentialStrategyError(
            f"oauth_refresh token endpoint {request.token_url!r} returned no access_token"
        )
    # A rotated refresh token is only interesting when it actually DIFFERS: a
    # server that echoes the same value back has not rotated, and persisting it
    # would be a pointless write to the secret store on every single call.
    rotated = payload.get("refresh_token")
    if not isinstance(rotated, str) or not rotated or rotated == request.refresh_token:
        rotated = None
    expires_in = payload.get("expires_in")
    if not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0:
        expires_in = None
    return _TokenGrant(
        access_token=access_token,
        rotated_refresh_token=rotated,
        expires_in=expires_in,
    )


class OAuthRefresh:
    """Mint an OAuth access token from a broker-held refresh token, at execute time.

    The refresh token (and optional client secret) are secret leaves the broker reads
    from the SecretsProvider; the access token is minted per call via the refresh
    grant and returned as the connector's credential. The refresh token never leaves
    the broker — the connector, and certainly the agent, only ever see the short-lived
    access token (doctrine #1: no raw passthrough of long-lived material).

    v1 mints fresh per call (stateless, always-correct — no token cache to invalidate).
    A TTL-aware cache is a connector-lifecycle follow-on (#173.2, deferred).

    Params (in ``ConnectorAuth.params``):
        token_url           (required) — the OAuth token endpoint.
        client_id           (required) — the OAuth client id.
        refresh_token_leaf  (optional) — secret leaf holding the refresh token;
                                         defaults to the Doer's tool→leaf mapping.
        client_secret_leaf  (optional) — secret leaf holding the client secret
                                         (omit for a public client).
        scope               (optional) — requested scope.
    """

    _REQUIRED = ("token_url", "client_id")
    _OPTIONAL = ("refresh_token_leaf", "client_secret_leaf", "scope")

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        refresh_token_leaf: str | None = None,
        client_secret_leaf: str | None = None,
        scope: str | None = None,
        token_fetcher: TokenFetcher | None = None,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._refresh_token_leaf = refresh_token_leaf
        self._client_secret_leaf = client_secret_leaf
        self._scope = scope
        self._token_fetcher = token_fetcher or _urllib_token_fetcher
        # In-memory access-token cache, per refresh leaf. Deliberately NOT
        # persisted: an access token is short-lived bearer material and belongs
        # in process memory only — the durable thing is the refresh chain.
        self._cache: dict[str, tuple[str, float]] = {}
        self._cache_lock = threading.Lock()

    def resolve(self, *, secrets: SecretsProvider, secret_name: str) -> str:
        refresh_leaf = self._refresh_token_leaf or secret_name
        with self._cache_lock:
            cached = self._cache.get(refresh_leaf)
            if cached is not None and time.monotonic() < cached[1]:
                return cached[0]
        return self._mint(secrets, refresh_leaf)

    def _mint(self, secrets: SecretsProvider, refresh_leaf: str) -> str:
        refresh_token = secrets.fetch_secret(refresh_leaf)
        client_secret = (
            secrets.fetch_secret(self._client_secret_leaf)
            if self._client_secret_leaf
            else None
        )
        request = _TokenRequest(
            token_url=self._token_url,
            client_id=self._client_id,
            refresh_token=refresh_token,
            client_secret=client_secret,
            scope=self._scope,
        )
        grant = self._token_fetcher(request)
        # "Rotated" means DIFFERENT. The default fetcher already normalises an
        # echoed-back identical token to None, but the check belongs here too:
        # `resolve` is the only place that holds both the sent and the returned
        # value, so an injected fetcher cannot cause a pointless write to the
        # secret store on every call by being less careful.
        rotated = grant.rotated_refresh_token
        if rotated is not None and rotated != refresh_token:
            self._persist_rotation(secrets, refresh_leaf, rotated)
        # Cache only when the server told us how long the token is good for. A
        # grant with no expires_in is not assumed to last: minting again is
        # wasteful, serving a dead token is a broken call.
        if grant.expires_in is not None:
            lifetime = max(0.0, float(grant.expires_in) - _EXPIRY_SKEW_SECONDS)
            if lifetime > 0:
                with self._cache_lock:
                    self._cache[refresh_leaf] = (
                        grant.access_token,
                        time.monotonic() + lifetime,
                    )
        return grant.access_token

    def invalidate(self, refresh_leaf: str | None = None) -> None:
        """Drop cached access tokens, forcing the next resolve to mint.

        The escape hatch for the case the cache cannot see: a token revoked
        server-side before its stated expiry. A caller that observes a 401 from
        the resource server calls this and retries.
        """
        with self._cache_lock:
            if refresh_leaf is None:
                self._cache.clear()
            else:
                self._cache.pop(refresh_leaf, None)

    @staticmethod
    def _persist_rotation(
        secrets: SecretsProvider, refresh_leaf: str, rotated: str
    ) -> None:
        """Write the successor refresh token back to its leaf, or fail LOUDLY.

        By the time this runs the exchange has already succeeded, which means the
        authorization server has already INVALIDATED the token we sent. The chain
        now exists only in ``rotated``. Persisting it is therefore not
        housekeeping — it is the difference between a credential that keeps
        working and one that is dead the moment this function returns.

        Two failure modes, both raised rather than logged, because the damage is
        already done and the only useful thing left is an accurate message:

        * **The provider cannot write.** Degrading to "return the access token
          anyway" would hand back one working call and leave a destroyed
          credential behind — the next call fails with an opaque
          ``invalid_grant`` and nothing connects it to this moment. That exact
          silence cost an hour of misdiagnosis when it was found (#238).
        * **The write itself failed.** Same reasoning; the successor is lost.

        Nothing here interpolates a token into a message.
        """
        if not isinstance(secrets, RotatableSecretsProvider):
            raise CredentialStrategyError(
                f"oauth_refresh: the authorization server ROTATED the refresh token "
                f"for leaf {refresh_leaf!r}, but the configured secrets provider "
                f"({type(secrets).__name__}) cannot write it back. The token just "
                f"used is now invalid server-side and the successor cannot be "
                f"stored, so this credential chain is BROKEN and needs a fresh "
                f"authorization. Use a provider implementing RotatableSecretsProvider "
                f"(e.g. DirSecretsProvider) for any vendor that rotates."
            )
        try:
            secrets.store_secret(refresh_leaf, rotated)
        except Exception as exc:
            raise CredentialStrategyError(
                f"oauth_refresh: failed to persist the ROTATED refresh token to leaf "
                f"{refresh_leaf!r} ({type(exc).__name__}). The previous token is "
                f"already invalid server-side, so this credential chain is BROKEN "
                f"and needs a fresh authorization."
            ) from None

    @classmethod
    def from_params(cls, params: dict[str, str]) -> "OAuthRefresh":
        missing = [key for key in cls._REQUIRED if not params.get(key)]
        if missing:
            raise CredentialStrategyError(
                f"oauth_refresh requires params {list(cls._REQUIRED)!r}; missing {missing!r}"
            )
        unknown = set(params) - set(cls._REQUIRED) - set(cls._OPTIONAL)
        if unknown:
            raise CredentialStrategyError(
                f"oauth_refresh got unknown params {sorted(unknown)!r}; "
                f"allowed {list(cls._REQUIRED + cls._OPTIONAL)!r}"
            )
        return cls(
            token_url=params["token_url"],
            client_id=params["client_id"],
            refresh_token_leaf=params.get("refresh_token_leaf"),
            client_secret_leaf=params.get("client_secret_leaf"),
            scope=params.get("scope"),
        )


@dataclass(frozen=True)
class _AssumeRoleRequest:
    """The inputs to one STS assume-role call, resolved broker-side.

    Carries only operator config (a role ARN, a session name) — no secret material,
    because an assumed role is an *identity*, not a stored credential. Injectable so a
    conformance test can assert on it without an AWS call.
    """

    role_arn: str
    session_name: str
    duration_seconds: int | None
    external_id: str | None
    region: str | None


# An assumer performs the actual STS assume-role and returns the short-lived bundle.
# Injectable so conformance tests run without AWS (the default is a boto3 STS call).
RoleAssumer = Callable[[_AssumeRoleRequest], AssumedRoleCredential]


def _boto3_role_assumer(request: _AssumeRoleRequest) -> AssumedRoleCredential:
    """Default assumer — a boto3 STS ``assume_role`` of the scoped role.

    Imports boto3 lazily so the module stays import-clean where the AWS path is never
    exercised. Returns the short-lived credentials as an ``AssumedRoleCredential``.
    Raises CredentialStrategyError with a credential-free message on any failure — the
    Doer additionally redacts, but this layer must not embed the material to begin with.
    """
    import boto3  # noqa: PLC0415
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415

    sts = boto3.client("sts", region_name=request.region)
    kwargs: dict[str, object] = {
        "RoleArn": request.role_arn,
        "RoleSessionName": request.session_name,
    }
    if request.duration_seconds is not None:
        kwargs["DurationSeconds"] = request.duration_seconds
    if request.external_id is not None:
        kwargs["ExternalId"] = request.external_id
    try:
        response = sts.assume_role(**kwargs)
        creds = response["Credentials"]
    except (BotoCoreError, ClientError, KeyError) as exc:
        # Do NOT interpolate the response (it holds the secret key + session token).
        raise CredentialStrategyError(
            f"assumed_role assume-role of {request.role_arn!r} failed: {type(exc).__name__}"
        ) from None

    expiration = creds.get("Expiration")
    return AssumedRoleCredential(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration=expiration.isoformat() if hasattr(expiration, "isoformat") else expiration,
    )


class AssumedRole:
    """Assume a per-capability scoped IAM role at execute time via STS (#175).

    The role is provisioned by the deploy (``infra/lib/``, CDK) scoped to exactly the
    capability's declared IAM (``AgentManifest.capability_iam``) and trusting the broker
    identity. This strategy assumes it per call and hands the connector the resulting
    short-lived STS credentials — so the connector's blast radius equals the role's
    declared scope, not the broker's full identity. An out-of-scope action is denied by
    IAM, not by the broker (doctrine 2: the credential is an identity; scope it).

    No secret leaf is read — the credential is the assumed role, minted fresh per call
    (stateless; a TTL cache is the #173.2 lifecycle follow-on). Long-lived material (the
    role's trust) stays in IAM, never crosses into the connector (doctrine 1).

    Params (in ``ConnectorAuth.params``):
        role_arn          (required) — the ARN of the scoped role to assume.
        session_name      (optional) — the STS RoleSessionName (CloudTrail attribution);
                                        defaults to ``safe-agents-connector``.
        duration_seconds  (optional) — session lifetime; STS default if omitted.
        external_id       (optional) — the ExternalId for the trust policy, if required.
        region            (optional) — STS regional endpoint override.
    """

    _REQUIRED = ("role_arn",)
    _OPTIONAL = ("session_name", "duration_seconds", "external_id", "region")
    _DEFAULT_SESSION_NAME = "safe-agents-connector"

    def __init__(
        self,
        *,
        role_arn: str,
        session_name: str | None = None,
        duration_seconds: int | None = None,
        external_id: str | None = None,
        region: str | None = None,
        role_assumer: RoleAssumer | None = None,
    ) -> None:
        self._role_arn = role_arn
        self._session_name = session_name or self._DEFAULT_SESSION_NAME
        self._duration_seconds = duration_seconds
        self._external_id = external_id
        self._region = region
        self._role_assumer = role_assumer or _boto3_role_assumer

    def resolve(
        self, *, secrets: SecretsProvider, secret_name: str
    ) -> AssumedRoleCredential:
        request = _AssumeRoleRequest(
            role_arn=self._role_arn,
            session_name=self._session_name,
            duration_seconds=self._duration_seconds,
            external_id=self._external_id,
            region=self._region,
        )
        return self._role_assumer(request)

    @classmethod
    def from_params(cls, params: dict[str, str]) -> "AssumedRole":
        missing = [key for key in cls._REQUIRED if not params.get(key)]
        if missing:
            raise CredentialStrategyError(
                f"assumed_role requires params {list(cls._REQUIRED)!r}; missing {missing!r}"
            )
        unknown = set(params) - set(cls._REQUIRED) - set(cls._OPTIONAL)
        if unknown:
            raise CredentialStrategyError(
                f"assumed_role got unknown params {sorted(unknown)!r}; "
                f"allowed {list(cls._REQUIRED + cls._OPTIONAL)!r}"
            )
        duration_raw = params.get("duration_seconds")
        try:
            duration = int(duration_raw) if duration_raw is not None else None
        except ValueError:
            raise CredentialStrategyError(
                f"assumed_role duration_seconds must be an integer; got {duration_raw!r}"
            ) from None
        return cls(
            role_arn=params["role_arn"],
            session_name=params.get("session_name"),
            duration_seconds=duration,
            external_id=params.get("external_id"),
            region=params.get("region"),
        )


# The base-owned, closed strategy catalog. A manifest selects by the enum; an entry
# absent here is a strategy the base declares but has not implemented yet — selecting
# it fails loudly at build (below), never silently.
_STRATEGY_FACTORIES: dict[AuthStrategy, Callable[[dict[str, str]], CredentialProvider]] = {
    AuthStrategy.STATIC_SECRET: StaticSecret.from_params,
    AuthStrategy.OAUTH_REFRESH: OAuthRefresh.from_params,
    AuthStrategy.ASSUMED_ROLE: AssumedRole.from_params,
}


def build_credential_strategies(
    connector_auth: dict[str, ConnectorAuth],
) -> dict[str, CredentialProvider]:
    """Compile a manifest ``connector_auth`` block into a tool → CredentialProvider map.

    Called once at broker build. A tool absent from the returned map falls back to
    ``StaticSecret`` in the Doer, so the empty block yields an empty map and the
    pre-#173 behavior. An unimplemented or malformed strategy raises
    CredentialStrategyError here — a loud boot failure, not a per-call surprise.
    """
    strategies: dict[str, CredentialProvider] = {}
    for tool, auth in connector_auth.items():
        factory = _STRATEGY_FACTORIES.get(auth.strategy)
        if factory is None:
            raise CredentialStrategyError(
                f"connector_auth[{tool!r}] selects strategy {auth.strategy.value!r}, "
                "which the base does not implement yet"
            )
        strategies[tool] = factory(auth.params)
    return strategies
