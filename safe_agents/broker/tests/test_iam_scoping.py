"""Tests for #175 — per-capability IAM scoping (PTC Phase 3a).

Covers the safe_agents/-side of #175: the `assumed_role` credential strategy
(`credentials.AssumedRole`), the `AssumedRoleCredential` bundle it resolves, the
Doer widening + bundle-aware redaction, and the `capability_iam` manifest block
(`schemas.capability_iam.CapabilityIam`) the deploy consumes.

The CDK provisioning half (a role scoped to exactly the declared IAM) is proven by
the infra synth tests + the worked example, not here — but the invariant this file
guards is the runtime one: the broker resolves an assumed-role identity broker-side
and hands the connector ONLY the short-lived bundle (doctrine 1), whose blast radius
is the role's scope (doctrine 2), and never leaks the secret material on an error.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pydantic
import pytest
import yaml

from safe_agents.broker.manifest import CATALOG
from safe_agents.broker.runtime import (
    AssumedRoleCredential,
    Doer,
    FakeSecretsProvider,
)
from safe_agents.broker.runtime.credentials import (
    AssumedRole,
    CredentialStrategyError,
    _AssumeRoleRequest,
    build_credential_strategies,
)
from safe_agents.broker.schemas import (
    AgentManifest,
    AuthStrategy,
    BrokeredCall,
    CapabilityIam,
    ConnectorAuth,
    Principal,
    Session,
    Taint,
)
from safe_agents.broker.schemas.decision import Allow

_EXAMPLES_ROOT = Path(__file__).resolve().parents[3] / "examples"

_TEST_PRINCIPAL = Principal(agentId="test-agent", skill="t", user="u", tier="B")

_BUNDLE = AssumedRoleCredential(
    access_key_id="ASIAEXAMPLE",
    secret_access_key="secret-key-material",
    session_token="session-token-material",
    expiration="2026-07-11T01:00:00Z",
)


def _fake_assumer(recorder: list[_AssumeRoleRequest]):
    def assume(request: _AssumeRoleRequest) -> AssumedRoleCredential:
        recorder.append(request)
        return _BUNDLE

    return assume


def _s3_call(op: str = "read", args: dict | None = None) -> BrokeredCall:
    entry = _S3_ENTRY
    return BrokeredCall(
        principal=_TEST_PRINCIPAL,
        tool="s3",
        op=op,
        args=args or {},
        manifest=entry,
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="test-iam-scoping", ingestedSources=[]),
        ts="2026-07-11T00:00:00Z",
    )


from safe_agents.broker.manifest import ToolOp  # noqa: E402

_S3_ENTRY = ToolOp(tool="s3", op="read", effect="read", external=True, egress_arg="key")


# ---------------------------------------------------------------------------
# AssumedRoleCredential — the bundle never renders its secret material
# ---------------------------------------------------------------------------

class TestAssumedRoleCredential:
    def test_str_hides_secret_material(self) -> None:
        text = str(_BUNDLE)
        assert "ASIAEXAMPLE" in text  # akid is an identifier, left visible
        assert "secret-key-material" not in text
        assert "session-token-material" not in text

    def test_redaction_values_are_secret_fields_only(self) -> None:
        values = _BUNDLE.redaction_values()
        assert set(values) == {"secret-key-material", "session-token-material"}
        # The access-key id (an identifier, not a secret) is NOT redacted.
        assert "ASIAEXAMPLE" not in values

    def test_empty_fields_are_dropped_from_redaction(self) -> None:
        bundle = AssumedRoleCredential(access_key_id="AK", secret_access_key="", session_token="")
        assert bundle.redaction_values() == ()


# ---------------------------------------------------------------------------
# AssumedRole strategy — resolves an identity broker-side, reads no secret
# ---------------------------------------------------------------------------

class TestAssumedRoleStrategy:
    def test_resolve_returns_bundle_via_injected_assumer(self) -> None:
        recorder: list[_AssumeRoleRequest] = []
        strategy = AssumedRole(
            role_arn="arn:aws:iam::123456789012:role/s3-read",
            session_name="s3-reader",
            role_assumer=_fake_assumer(recorder),
        )
        secrets = FakeSecretsProvider({})  # no secret leaf needed

        credential = strategy.resolve(secrets=secrets, secret_name="unused")

        assert credential is _BUNDLE
        assert len(recorder) == 1
        assert recorder[0].role_arn == "arn:aws:iam::123456789012:role/s3-read"
        assert recorder[0].session_name == "s3-reader"

    def test_resolve_reads_no_secret_leaf(self) -> None:
        # An assumed role is an identity, not a stored secret — the strategy must not
        # touch the secrets store (doctrine: no long-lived material to hold).
        class ExplodingSecrets:
            def fetch_secret(self, name: str) -> str:  # pragma: no cover - must not run
                raise AssertionError(f"AssumedRole must not fetch a secret; asked for {name!r}")

        strategy = AssumedRole(
            role_arn="arn:aws:iam::123456789012:role/s3-read",
            role_assumer=_fake_assumer([]),
        )
        strategy.resolve(secrets=ExplodingSecrets(), secret_name="anything")

    def test_default_session_name(self) -> None:
        recorder: list[_AssumeRoleRequest] = []
        strategy = AssumedRole(
            role_arn="arn:aws:iam::123456789012:role/s3-read",
            role_assumer=_fake_assumer(recorder),
        )
        strategy.resolve(secrets=FakeSecretsProvider({}), secret_name="x")
        assert recorder[0].session_name == "safe-agents-connector"


# ---------------------------------------------------------------------------
# from_params — closed catalog, fail at build
# ---------------------------------------------------------------------------

class TestAssumedRoleFromParams:
    def test_requires_role_arn(self) -> None:
        with pytest.raises(CredentialStrategyError, match="role_arn"):
            AssumedRole.from_params({})

    def test_rejects_unknown_param(self) -> None:
        with pytest.raises(CredentialStrategyError, match="unknown"):
            AssumedRole.from_params({"role_arn": "arn:...", "surprise": "nope"})

    def test_duration_must_be_integer(self) -> None:
        with pytest.raises(CredentialStrategyError, match="duration_seconds"):
            AssumedRole.from_params({"role_arn": "arn:...", "duration_seconds": "not-a-number"})

    def test_optional_params_flow_through(self) -> None:
        recorder: list[_AssumeRoleRequest] = []
        strategy = AssumedRole.from_params(
            {
                "role_arn": "arn:aws:iam::123456789012:role/s3-read",
                "session_name": "sess",
                "duration_seconds": "900",
                "external_id": "ext",
                "region": "us-east-1",
            }
        )
        strategy._role_assumer = _fake_assumer(recorder)  # type: ignore[attr-defined]
        strategy.resolve(secrets=FakeSecretsProvider({}), secret_name="x")
        req = recorder[0]
        assert req.duration_seconds == 900
        assert req.external_id == "ext"
        assert req.region == "us-east-1"

    def test_build_credential_strategies_compiles_assumed_role(self) -> None:
        strategies = build_credential_strategies(
            {
                "s3": ConnectorAuth(
                    strategy=AuthStrategy.ASSUMED_ROLE,
                    params={"role_arn": "arn:aws:iam::123456789012:role/s3-read"},
                )
            }
        )
        assert isinstance(strategies["s3"], AssumedRole)


# ---------------------------------------------------------------------------
# Doer end-to-end — connector receives the bundle; error redaction covers it
# ---------------------------------------------------------------------------

class _BundleConnector:
    def __init__(self, boom: bool = False) -> None:
        self.seen: list[Any] = []
        self._boom = boom

    def execute(self, tool: str, op: str, args: Any, credential: Any) -> Any:
        self.seen.append(credential)
        if self._boom:
            # A careless connector that embeds the whole bundle's material in its error.
            raise RuntimeError(
                f"backend rejected creds {credential.secret_access_key} / "
                f"{credential.session_token}"
            )
        return {"status": "ok"}


class TestDoerAssumedRoleEndToEnd:
    def test_connector_receives_bundle_not_string(self) -> None:
        connector = _BundleConnector()
        strategy = AssumedRole(role_arn="arn:...", role_assumer=_fake_assumer([]))
        doer = Doer(
            connectors={"s3": connector},
            secrets=FakeSecretsProvider({}),
            credential_strategies={"s3": strategy},
        )
        doer.execute(_s3_call(), Allow(kind="allow"))
        assert connector.seen == [_BUNDLE]
        assert isinstance(connector.seen[0], AssumedRoleCredential)

    def test_bundle_material_redacted_from_connector_error(self) -> None:
        from safe_agents.broker.runtime.doer import ConnectorExecutionError

        connector = _BundleConnector(boom=True)
        strategy = AssumedRole(role_arn="arn:...", role_assumer=_fake_assumer([]))
        doer = Doer(
            connectors={"s3": connector},
            secrets=FakeSecretsProvider({}),
            credential_strategies={"s3": strategy},
        )
        with pytest.raises(ConnectorExecutionError) as exc_info:
            doer.execute(_s3_call(), Allow(kind="allow"))
        message = str(exc_info.value)
        assert "secret-key-material" not in message
        assert "session-token-material" not in message
        assert "***redacted-credential***" in message


# ---------------------------------------------------------------------------
# CapabilityIam schema + AgentManifest coherence
# ---------------------------------------------------------------------------

def _manifest(**overrides) -> AgentManifest:
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
        "principal": {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"},
        "tool_ops": [e for e in CATALOG if e.tool == "github" and e.op == "whoami"],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


class TestCapabilityIamSchema:
    def test_requires_non_empty_actions_and_resources(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            CapabilityIam(actions=[], resources=["arn:aws:s3:::bucket/*"])
        with pytest.raises(pydantic.ValidationError):
            CapabilityIam(actions=["s3:GetObject"], resources=[])

    def test_rejects_blank_entries(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            CapabilityIam(actions=["  "], resources=["arn:aws:s3:::bucket/*"])

    def test_valid_declaration(self) -> None:
        cap = CapabilityIam(actions=["s3:GetObject"], resources=["arn:aws:s3:::bucket/*"])
        assert cap.actions == ["s3:GetObject"]


class TestManifestCapabilityIamCoherence:
    def test_capability_iam_requires_assumed_role_strategy(self) -> None:
        with pytest.raises(pydantic.ValidationError, match="assumed_role"):
            _manifest(
                capability_iam={
                    "s3": {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::b/*"]}
                },
                # no connector_auth entry → defaults to static_secret → mismatch
            )

    def test_capability_iam_with_assumed_role_is_valid(self) -> None:
        manifest = _manifest(
            connector_auth={
                "s3": {"strategy": "assumed_role", "params": {"role_arn": "arn:...:role/s3"}}
            },
            capability_iam={
                "s3": {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::b/*"]}
            },
        )
        assert manifest.capability_iam["s3"].actions == ["s3:GetObject"]

    def test_assumed_role_without_capability_iam_is_allowed(self) -> None:
        # An assumed_role strategy may reference an externally-provisioned role — the
        # reverse coupling is intentionally not required.
        manifest = _manifest(
            connector_auth={
                "s3": {"strategy": "assumed_role", "params": {"role_arn": "arn:...:role/s3"}}
            },
        )
        assert manifest.connector_auth["s3"].strategy is AuthStrategy.ASSUMED_ROLE


# ---------------------------------------------------------------------------
# End-to-end — the scoped_s3 example manifest (C6-C8)
# ---------------------------------------------------------------------------

class TestScopedS3ExampleManifest:
    def test_manifest_declares_assumed_role_and_capability_iam(self) -> None:
        manifest_path = _EXAMPLES_ROOT / "scoped_s3" / "manifest.yaml"
        data = yaml.safe_load(manifest_path.read_text())
        manifest = AgentManifest.model_validate(data)

        auth = manifest.connector_auth["s3"]
        assert auth.strategy is AuthStrategy.ASSUMED_ROLE
        assert auth.params["role_arn"].startswith("arn:aws:iam::")

        cap = manifest.capability_iam["s3"]
        assert cap.actions == ["s3:GetObject"]
        assert cap.resources == ["arn:aws:s3:::scoped-s3-example-bucket/*"]

        # Compiles cleanly and produces exactly one assumed_role strategy.
        strategies = build_credential_strategies(manifest.connector_auth)
        assert isinstance(strategies["s3"], AssumedRole)
