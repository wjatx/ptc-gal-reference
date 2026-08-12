"""Tests for #173 — the connector-auth-strategy seam (PTC Phase 3a).

Proves clauses C1-C5 of ``broker/CONNECTOR-AUTH.md`` against the already-shipped
core seam (``safe_agents/broker/schemas/connector_auth.py``,
``safe_agents/broker/runtime/credentials.py``, ``Doer``'s ``credential_strategies``
param). Mirrors the structure of ``test_connector_providers.py``: test-local
connector doubles, a ``_manifest(**overrides)`` helper, grouped test classes.

  C1 — static unchanged: an unconfigured tool resolves the credential exactly as
       before #173 (fetch the leaf verbatim).
  C2 — no passthrough: oauth_refresh resolves an ACCESS token broker-side; the
       connector never sees the refresh token, and the fetcher receives the
       resolved refresh token (proving the broker read it).
  C3 — closed catalog: a still-reserved strategy (ambient_identity) and unknown
       ConnectorAuth fields fail closed. (assumed_role is implemented as of #175 —
       its own coverage lives in test_iam_scoping.py.)
  C4 — fail at build: malformed oauth_refresh params (missing required / unknown)
       and non-empty static_secret params raise at strategy-compile time.
  C5 — defaults: ConnectorAuth() defaults to static_secret; an empty
       connector_auth block compiles to an empty strategy map.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pydantic
import pytest
import yaml

from safe_agents.broker.manifest import CATALOG
from safe_agents.broker.runtime import Doer, FakeSecretsProvider
from safe_agents.broker.runtime.credentials import (
    CredentialStrategyError,
    OAuthRefresh,
    StaticSecret,
    _TokenGrant,
    _TokenRequest,
    build_credential_strategies,
)
from safe_agents.broker.schemas import (
    AgentManifest,
    AuthStrategy,
    BrokeredCall,
    ConnectorAuth,
    HeaderSource,
    Principal,
    Session,
    Taint,
)
from safe_agents.broker.schemas.decision import Allow

_EXAMPLES_ROOT = Path(__file__).resolve().parents[3] / "examples"

_TEST_PRINCIPAL = Principal(agentId="test-agent", skill="t", user="u", tier="B")


def _manifest(**overrides) -> AgentManifest:
    """A minimal valid AgentManifest; overrides merge shallow (mirrors
    test_connector_providers's helper)."""
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
        "principal": {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"},
        "grant_classes": ["github.whoami"],
        "connectors": ["github"],
        "tool_ops": [e for e in CATALOG if e.tool == "github" and e.op == "whoami"],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


class RecordingConnector:
    """Records every credential it receives; never returns it."""

    def __init__(self) -> None:
        self.seen_credentials: list[str] = []

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        self.seen_credentials.append(credential)
        return {"status": "ok", "tool": tool, "op": op}


def _call(principal, tool: str = "github", op: str = "whoami") -> BrokeredCall:
    manifest_entry = next(e for e in CATALOG if e.tool == tool and e.op == op)
    return BrokeredCall(
        principal=principal,
        tool=tool,
        op=op,
        args={},
        manifest=manifest_entry,
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="test-credential-strategies", ingestedSources=[]),
        ts="2026-07-11T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# C1 — static unchanged
# ---------------------------------------------------------------------------

class TestStaticSecretUnchanged:
    def test_static_secret_resolves_leaf_verbatim(self) -> None:
        secrets = FakeSecretsProvider({"x": "leaf-value"})
        assert StaticSecret().resolve(secrets=secrets, secret_name="x") == "leaf-value"

    def test_doer_with_no_strategies_uses_static_secret(self) -> None:
        connector = RecordingConnector()
        secrets = FakeSecretsProvider({"github": "static-cred"})
        doer = Doer(connectors={"github": connector}, secrets=secrets)

        result = doer.execute(_call(_TEST_PRINCIPAL), Allow(kind="allow"))

        assert result.result["status"] == "ok"
        assert connector.seen_credentials == ["static-cred"]


# ---------------------------------------------------------------------------
# C2 — no passthrough of long-lived material
# ---------------------------------------------------------------------------

class TestOAuthRefreshNoPassthrough:
    def test_connector_receives_access_token_not_refresh_token(self) -> None:
        refresh_token = "refresh-super-secret"
        access_token = "minted-access-token"
        secrets = FakeSecretsProvider({"api": refresh_token})

        captured_requests: list[_TokenRequest] = []

        def fake_fetcher(request: _TokenRequest) -> _TokenGrant:
            captured_requests.append(request)
            # No rotation: this server hands back the same refresh token forever.
            return _TokenGrant(access_token=access_token)

        strategy = OAuthRefresh(
            token_url="https://auth.example.test/oauth/token",
            client_id="example-client",
            token_fetcher=fake_fetcher,
        )
        connector = RecordingConnector()
        doer = Doer(
            connectors={"api": connector},
            secrets=secrets,
            credential_strategies={"api": strategy},
        )

        # Route to the "api" tool: reuse a CATALOG-shaped entry via manual override —
        # build a BrokeredCall directly rather than via CATALOG (api.query is not a
        # base op; construct the manifest entry inline).
        from safe_agents.broker.manifest import ToolOp

        entry = ToolOp(tool="api", op="query", effect="read", external=True, egress_arg="query")
        call = BrokeredCall(
            principal=_TEST_PRINCIPAL,
            tool="api",
            op="query",
            args={"query": "hello"},
            manifest=entry,
            taint=Taint(tainted=False, sources=[]),
            session=Session(turnId="test-credential-strategies-oauth", ingestedSources=[]),
            ts="2026-07-11T00:00:00Z",
        )

        result = doer.execute(call, Allow(kind="allow"))

        assert result.result["status"] == "ok"
        # The connector saw only the minted access token.
        assert connector.seen_credentials == [access_token]
        assert refresh_token not in connector.seen_credentials
        # The fetcher (broker-side) received the RESOLVED refresh token, proving
        # the broker — not the connector — read it from the secrets store.
        assert len(captured_requests) == 1
        assert captured_requests[0].refresh_token == refresh_token
        assert captured_requests[0].token_url == "https://auth.example.test/oauth/token"
        assert captured_requests[0].client_id == "example-client"

    def test_oauth_refresh_resolve_returns_access_token_directly(self) -> None:
        secrets = FakeSecretsProvider({"custom-leaf": "the-refresh-token"})
        seen: list[_TokenRequest] = []

        def fetcher(request: _TokenRequest) -> _TokenGrant:
            seen.append(request)
            return _TokenGrant(access_token="the-access-token")

        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="custom-leaf",
            client_secret_leaf=None,
            token_fetcher=fetcher,
        )
        credential = strategy.resolve(secrets=secrets, secret_name="ignored-default")
        assert credential == "the-access-token"
        assert seen[0].refresh_token == "the-refresh-token"
        assert seen[0].client_secret is None


# ---------------------------------------------------------------------------
# C3 — closed catalog
# ---------------------------------------------------------------------------

class TestClosedCatalog:
    def test_reserved_strategy_raises_at_build(self) -> None:
        # ambient_identity remains a reserved name (declared in the enum, no factory) —
        # selecting it fails loudly at build. assumed_role is implemented as of #175.
        with pytest.raises(CredentialStrategyError):
            build_credential_strategies(
                {"api": ConnectorAuth(strategy=AuthStrategy.AMBIENT_IDENTITY, params={})}
            )

    def test_connector_auth_rejects_extra_fields(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            ConnectorAuth.model_validate({"strategy": "static_secret", "bogus": "nope"})


# ---------------------------------------------------------------------------
# C4 — fail at build, not at the wire
# ---------------------------------------------------------------------------

class TestFailAtBuild:
    def test_oauth_refresh_missing_required_params(self) -> None:
        with pytest.raises(CredentialStrategyError):
            build_credential_strategies(
                {"api": ConnectorAuth(strategy=AuthStrategy.OAUTH_REFRESH, params={"token_url": "https://x"})}
            )

    def test_oauth_refresh_unknown_param(self) -> None:
        with pytest.raises(CredentialStrategyError):
            build_credential_strategies(
                {
                    "api": ConnectorAuth(
                        strategy=AuthStrategy.OAUTH_REFRESH,
                        params={
                            "token_url": "https://x",
                            "client_id": "c",
                            "surprise": "nope",
                        },
                    )
                }
            )

    def test_static_secret_with_params_rejected(self) -> None:
        with pytest.raises(CredentialStrategyError):
            build_credential_strategies(
                {"api": ConnectorAuth(strategy=AuthStrategy.STATIC_SECRET, params={"x": "y"})}
            )


# ---------------------------------------------------------------------------
# C5 — defaults
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_connector_auth_defaults_to_static_secret(self) -> None:
        assert ConnectorAuth().strategy == AuthStrategy.STATIC_SECRET
        assert ConnectorAuth().params == {}

    def test_empty_connector_auth_compiles_to_empty_map(self) -> None:
        assert build_credential_strategies({}) == {}


# ---------------------------------------------------------------------------
# End-to-end — the oauth_api example manifest
# ---------------------------------------------------------------------------

class TestOAuthApiExampleManifest:
    def test_manifest_declares_oauth_refresh(self) -> None:
        manifest_path = _EXAMPLES_ROOT / "oauth_api" / "manifest.yaml"
        data = yaml.safe_load(manifest_path.read_text())
        manifest = AgentManifest.model_validate(data)

        auth = manifest.connector_auth["api"]
        assert auth.strategy == AuthStrategy.OAUTH_REFRESH
        assert auth.params["token_url"] == "https://auth.example.test/oauth/token"
        assert auth.params["client_id"] == "example-client"
        assert auth.params["refresh_token_leaf"] == "api-refresh-token"

        # Compiles cleanly (no build-time error) and produces exactly one strategy.
        strategies = build_credential_strategies(manifest.connector_auth)
        assert set(strategies) == {"api"}
        assert isinstance(strategies["api"], OAuthRefresh)


# ---------------------------------------------------------------------------
# C10 — the header_map declaration's own validation (#237)
# ---------------------------------------------------------------------------


class TestHeaderMapDeclaration:
    """`header_map` is consumer-facing YAML, so every way it can be written
    wrong should fail at LOAD with a message naming the problem — not at the
    wire as a vendor's opaque 401, which is the failure these refusals exist to
    prevent someone debugging.
    """

    def test_scheme_only_entry_is_legal(self) -> None:
        auth = ConnectorAuth(header_map={"Authorization": HeaderSource(scheme="Bearer")})
        assert auth.header_map["Authorization"].scheme == "Bearer"

    def test_field_entries_are_legal(self) -> None:
        auth = ConnectorAuth(
            header_map={
                "X-Api-Key": HeaderSource(field="key"),
                "X-Client-Id": HeaderSource(field="client"),
            }
        )
        assert {n: s.field for n, s in auth.header_map.items()} == {
            "X-Api-Key": "key",
            "X-Client-Id": "client",
        }

    def test_non_token_header_name_refuses(self) -> None:
        with pytest.raises(pydantic.ValidationError, match="valid HTTP field name"):
            ConnectorAuth(header_map={"X Api Key": HeaderSource(field="key")})

    def test_transport_owned_header_refuses(self) -> None:
        """A header the transport sets per request overrides anything declared
        here, so declaring one is config that can never take effect — dead
        config is a masked misconfiguration, so refuse rather than drop."""
        with pytest.raises(pydantic.ValidationError, match="sets on every request"):
            ConnectorAuth(header_map={"MCP-Session-Id": HeaderSource(scheme="Bearer")})

    def test_case_colliding_header_names_refuse(self) -> None:
        """HTTP field names are case-insensitive; two entries for one field
        leaves which value wins to dict ordering."""
        with pytest.raises(pydantic.ValidationError, match="case-insensitive"):
            ConnectorAuth(
                header_map={
                    "X-Api-Key": HeaderSource(field="a"),
                    "x-api-key": HeaderSource(field="b"),
                }
            )

    def test_mixed_credential_shapes_refuse(self) -> None:
        """One resolved credential cannot be both a bare string and a JSON map,
        so a manifest asking for both is refused here rather than resolving to
        whichever shape the credential happens to have that day."""
        with pytest.raises(pydantic.ValidationError, match="mixes credential shapes"):
            ConnectorAuth(
                header_map={
                    "Authorization": HeaderSource(scheme="Bearer"),
                    "X-Client-Id": HeaderSource(field="client"),
                }
            )

    def test_scheme_is_a_token_not_a_template(self) -> None:
        """The whole reason `scheme` is safe to put in config is that it cannot
        carry interpolation — if it could, it would be a way to write arbitrary
        text into an outbound header."""
        with pytest.raises(pydantic.ValidationError, match="auth-scheme token"):
            ConnectorAuth(
                header_map={"Authorization": HeaderSource(scheme="Bearer {token}")}
            )

    def test_header_source_forbids_unknown_keys(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            ConnectorAuth.model_validate(
                {"header_map": {"Authorization": {"schema": "Bearer"}}}
            )

    def test_absent_header_map_is_the_default(self) -> None:
        assert ConnectorAuth().header_map == {}


# ---------------------------------------------------------------------------
# End-to-end — the oauth_remote_mcp example manifest (C10, #237)
# ---------------------------------------------------------------------------


class TestOAuthRemoteMcpExampleManifest:
    """The remote-delivery example must keep validating as the schema moves.

    An example that silently rots is worse than none: it is the artifact a
    consumer copies, so it is pinned here rather than trusted to review.
    """

    def test_manifest_declares_header_delivery_and_compiles(self) -> None:
        manifest_path = _EXAMPLES_ROOT / "oauth_remote_mcp" / "manifest.yaml"
        data = yaml.safe_load(manifest_path.read_text())
        manifest = AgentManifest.model_validate(data)

        auth = manifest.connector_auth["vendor_mcp"]
        assert auth.strategy == AuthStrategy.OAUTH_REFRESH
        # Delivery is declared, and it names a header — never a credential.
        assert auth.header_map["Authorization"].scheme == "Bearer"
        assert auth.header_map["Authorization"].field is None
        # A public client: no client_secret_leaf, which is exactly the
        # `token_endpoint_auth_methods_supported: ["none"]` shape.
        assert "client_secret_leaf" not in auth.params

        strategies = build_credential_strategies(manifest.connector_auth)
        assert set(strategies) == {"vendor_mcp"}
        assert isinstance(strategies["vendor_mcp"], OAuthRefresh)

    def test_example_declares_respawn_because_reconnect_is_the_reauth_path(
        self,
    ) -> None:
        """The example's `respawn` block is load-bearing, not decoration.

        Credentials re-resolve per connect, so an expired token recovers only if
        a reconnect happens at all — and respawn ships OFF. A future edit
        dropping this block would leave the example demonstrating a server whose
        token can never renew, which is the subtle wrong thing to copy.
        """
        manifest_path = _EXAMPLES_ROOT / "oauth_remote_mcp" / "manifest.yaml"
        manifest = AgentManifest.model_validate(
            yaml.safe_load(manifest_path.read_text())
        )
        respawn = manifest.mcp_servers["vendor_mcp"].respawn
        assert respawn is not None, "a remote server on an expiring credential needs respawn"
        assert respawn.max_attempts >= 1


# ---------------------------------------------------------------------------
# C11 — rotating refresh tokens (#238, found live against a real brokerage)
# ---------------------------------------------------------------------------


class _ReadOnlySecrets:
    """A provider that can fetch but NOT store — the pre-#238 shape."""

    def __init__(self, secrets: dict) -> None:
        self._secrets = dict(secrets)

    def fetch_secret(self, secret_name: str) -> str:
        return self._secrets[secret_name]


class TestRotatingRefreshToken:
    """A vendor that rotates invalidates the token it was sent. Persisting the
    successor is the difference between a chain that continues and a credential
    that is dead on return.
    """

    def _rotating_fetcher(self, issued: list[str]):
        """Mints a NEW refresh token every call and REFUSES any token it has
        already retired — the toy equivalent of what a real brokerage does. Refusing
        the retired token is what makes these tests non-vacuous: a strategy that
        fails to persist cannot pass by replaying the original."""

        def fetcher(request: _TokenRequest) -> _TokenGrant:
            if request.refresh_token in issued[:-1]:
                raise CredentialStrategyError("invalid_grant: refresh token retired")
            successor = f"refresh-{len(issued)}"
            issued.append(successor)
            return _TokenGrant(
                access_token=f"access-{len(issued)}", rotated_refresh_token=successor
            )

        return fetcher

    def test_rotated_token_is_persisted_and_the_chain_continues(self) -> None:
        issued = ["refresh-0"]
        secrets = FakeSecretsProvider({"leaf": "refresh-0"})
        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="leaf",
            token_fetcher=self._rotating_fetcher(issued),
        )

        first = strategy.resolve(secrets=secrets, secret_name="leaf")
        assert first == "access-2"
        # The successor replaced the spent token in the store.
        assert secrets.fetch_secret("leaf") == "refresh-1"

        # THE point of the feature: a second resolve succeeds, because it sends
        # the persisted successor rather than the retired original.
        second = strategy.resolve(secrets=secrets, secret_name="leaf")
        assert second == "access-3"
        assert secrets.fetch_secret("leaf") == "refresh-2"

    def test_a_read_only_provider_refuses_loudly_rather_than_stranding_the_chain(
        self,
    ) -> None:
        """The pre-#238 behaviour, now an error instead of silent destruction.

        The exchange has already succeeded, so the old token is invalid
        server-side. Returning the access token anyway would buy one working
        call and leave a dead credential — the next call fails with an opaque
        `invalid_grant` far from the cause.
        """
        secrets = _ReadOnlySecrets({"leaf": "refresh-0"})
        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="leaf",
            token_fetcher=self._rotating_fetcher(["refresh-0"]),
        )
        with pytest.raises(CredentialStrategyError) as excinfo:
            strategy.resolve(secrets=secrets, secret_name="leaf")
        message = str(excinfo.value)
        assert "ROTATED" in message and "BROKEN" in message
        assert "refresh-" not in message, "the failure message rendered a token"

    def test_a_failing_write_also_refuses_loudly(self) -> None:
        class FailingStore(FakeSecretsProvider):
            def store_secret(self, secret_name: str, value: str) -> None:
                raise OSError("read-only file system")

        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="leaf",
            token_fetcher=self._rotating_fetcher(["refresh-0"]),
        )
        with pytest.raises(CredentialStrategyError, match="BROKEN"):
            strategy.resolve(
                secrets=FailingStore({"leaf": "refresh-0"}), secret_name="leaf"
            )

    def test_a_non_rotating_server_never_writes_to_the_store(self) -> None:
        """Byte-for-byte the old behaviour where the server does not rotate: an
        echoed-back identical token is not a rotation and must not cause a write
        on every single call."""
        writes: list[tuple] = []

        class CountingStore(FakeSecretsProvider):
            def store_secret(self, secret_name: str, value: str) -> None:
                writes.append((secret_name, value))
                super().store_secret(secret_name, value)

        def echoing_fetcher(request: _TokenRequest) -> _TokenGrant:
            # Same value back — RFC-permitted, and not a rotation.
            return _TokenGrant(
                access_token="access", rotated_refresh_token=request.refresh_token
            )

        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="leaf",
            token_fetcher=echoing_fetcher,
        )
        store = CountingStore({"leaf": "refresh-0"})
        assert strategy.resolve(secrets=store, secret_name="leaf") == "access"
        assert writes == [], f"an unchanged token was written back: {writes}"


# ---------------------------------------------------------------------------
# C12 — access-token cache (#173.2, made load-bearing by #238)
# ---------------------------------------------------------------------------


class TestAccessTokenCache:
    """A real brokerage's access tokens carry `expires_in` of ~4.7 DAYS, yet the broker
    resolved a credential per CONNECT — minting a fresh token, and burning a
    refresh-token rotation, every time. Against a vendor that rotates and
    dislikes being hammered, that is not merely wasteful: it is what made the
    credential chain fragile. Caching is the design, not an optimisation.
    """

    def _counting_fetcher(self, calls: list, *, expires_in: int | None = 3600):
        def fetcher(request: _TokenRequest) -> _TokenGrant:
            calls.append(request.refresh_token)
            return _TokenGrant(
                access_token=f"access-{len(calls)}",
                rotated_refresh_token=f"refresh-{len(calls)}",
                expires_in=expires_in,
            )

        return fetcher

    def _strategy(self, fetcher):
        return OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            refresh_token_leaf="leaf",
            token_fetcher=fetcher,
        )

    def test_a_cached_token_is_reused_and_does_not_rotate_again(self) -> None:
        """The headline: repeat resolves neither call the token endpoint nor
        advance the refresh chain."""
        calls: list = []
        secrets = FakeSecretsProvider({"leaf": "refresh-0"})
        strategy = self._strategy(self._counting_fetcher(calls))

        first = strategy.resolve(secrets=secrets, secret_name="leaf")
        after_first = secrets.fetch_secret("leaf")
        others = [strategy.resolve(secrets=secrets, secret_name="leaf") for _ in range(5)]

        assert others == [first] * 5, "a cached resolve returned a different token"
        assert len(calls) == 1, f"expected ONE mint across six resolves, got {len(calls)}"
        assert secrets.fetch_secret("leaf") == after_first, (
            "the refresh chain advanced on a cached resolve — the exact hammering "
            "that made the live chain fragile"
        )

    def test_the_cache_expires_and_re_mints(self, monkeypatch) -> None:
        calls: list = []
        secrets = FakeSecretsProvider({"leaf": "refresh-0"})
        # Lifetime = expires_in - skew, so 301 leaves one second of cache.
        strategy = self._strategy(self._counting_fetcher(calls, expires_in=301))

        clock = {"now": 1000.0}
        monkeypatch.setattr(
            "safe_agents.broker.runtime.credentials.time.monotonic",
            lambda: clock["now"],
        )
        strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 1
        clock["now"] += 0.5
        strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 1, "re-minted while still inside the cache window"
        clock["now"] += 10.0
        strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 2, "did not re-mint after the cache window elapsed"

    def test_no_expires_in_means_no_caching(self) -> None:
        """A server that does not state a lifetime is not assumed to have one:
        serving a dead token is worse than minting again."""
        calls: list = []
        secrets = FakeSecretsProvider({"leaf": "refresh-0"})
        strategy = self._strategy(self._counting_fetcher(calls, expires_in=None))
        for _ in range(3):
            strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 3

    def test_invalidate_forces_a_fresh_mint(self) -> None:
        """The escape hatch for revocation the cache cannot observe."""
        calls: list = []
        secrets = FakeSecretsProvider({"leaf": "refresh-0"})
        strategy = self._strategy(self._counting_fetcher(calls))
        strategy.resolve(secrets=secrets, secret_name="leaf")
        strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 1
        strategy.invalidate("leaf")
        strategy.resolve(secrets=secrets, secret_name="leaf")
        assert len(calls) == 2

    def test_cache_is_keyed_per_leaf(self) -> None:
        """Two leaves must never share a cached token."""
        calls: list = []
        secrets = FakeSecretsProvider({"a": "refresh-a", "b": "refresh-b"})
        strategy = OAuthRefresh(
            token_url="https://auth.example.test/token",
            client_id="cid",
            token_fetcher=self._counting_fetcher(calls),
        )
        first = strategy.resolve(secrets=secrets, secret_name="a")
        second = strategy.resolve(secrets=secrets, secret_name="b")
        assert first != second
        assert len(calls) == 2, "one leaf's token was served for another"
