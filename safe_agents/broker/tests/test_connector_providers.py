"""Tests for sa#141 slice 1 — consumer-supplied connectors + secret injection.

Four layers, matching the design:

  1. **Schema.** ``AgentManifest.connector_providers`` validates provider-path
     shape at load time; ``connector_secrets`` maps names only; extra="forbid"
     still holds.
  2. **Registry seam.** ``resolve_connectors(names, providers=...)`` resolves a
     provider path first (import + zero-arg instantiate + Connector protocol
     check, ``ConnectorProviderError`` on any failure), then the base registry,
     then fails closed (``UnknownConnectorError``) — the one sanctioned
     injection seam.
  3. **Secret mapping end-to-end.** ``build_runtime`` derives the Doer's
     ``secret_name_for`` from ``connector_secrets``; the provider connector's
     ``execute`` receives the MAPPED secret's value.
  4. **Store cannot inject.** The envelope store loads an ``Envelope``, which
     has no provider/import-path field — a store-controlled artifact can never
     reach ``resolve_connectors``' providers argument, which is fed solely from
     the image-baked manifest object in the composition root.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pydantic
import pytest

from safe_agents.broker.manifest import CATALOG, CATALOG_TABLE
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.prototype.connector_registry import (
    ConnectorProviderError,
    UnknownConnectorError,
    resolve_connectors,
)
from safe_agents.broker.schemas import AgentManifest, BrokeredCall, Envelope, Session, Taint
from safe_agents.broker.schemas.decision import Allow

_THIS_MODULE = "safe_agents.broker.tests.test_connector_providers"


# ---------------------------------------------------------------------------
# Test-local provider classes (imported by dotted path through the registry)
# ---------------------------------------------------------------------------

class DummyConnector:
    """A well-behaved consumer connector: zero-arg, satisfies the protocol,
    records the credential each execute() received (never returns it)."""

    def __init__(self) -> None:
        self.seen_credentials: list[str] = []

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        self.seen_credentials.append(credential)
        return {"status": "dummy-ok", "tool": tool, "op": op}


class NotAConnector:
    """Zero-arg instantiable but lacks execute() — must fail the protocol check."""


class NeedsArgsConnector:
    """Protocol-shaped but NOT zero-arg instantiable — must fail closed."""

    def __init__(self, required: str) -> None:
        self.required = required

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        return None


def _manifest(**overrides) -> AgentManifest:
    """A minimal valid AgentManifest; overrides merge shallow (mirrors
    test_broker_debake's helper)."""
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
        "principal": {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"},
        "grant_classes": ["github.whoami"],
        "connectors": ["github"],
        "tool_ops": [e for e in CATALOG if e.tool == "github" and e.op == "whoami"],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


# ---------------------------------------------------------------------------
# 1. Schema — provider-path validation + extra="forbid"
# ---------------------------------------------------------------------------

class TestManifestSchema:
    VALID_PATHS = [
        "pkg.module:ClassName",
        "a:B",
        f"{_THIS_MODULE}:DummyConnector",
    ]
    INVALID_PATHS = [
        "no.colon.at.all",
        ":ClassOnly",
        "module.only:",
        "two:colons:here",
        "",
        ".relative:Cls",  # relative import would raise TypeError past the registry taxonomy
    ]

    @pytest.mark.parametrize("path", VALID_PATHS)
    def test_valid_provider_path_accepted(self, path: str) -> None:
        m = _manifest(connector_providers={"github": path})
        assert m.connector_providers == {"github": path}

    @pytest.mark.parametrize("path", INVALID_PATHS)
    def test_invalid_provider_path_rejected(self, path: str) -> None:
        with pytest.raises(pydantic.ValidationError, match="provider"):
            _manifest(connector_providers={"github": path})

    def test_defaults_are_empty(self) -> None:
        m = _manifest()
        assert m.connector_providers == {}
        assert m.connector_secrets == {}

    def test_connector_secrets_maps_names(self) -> None:
        m = _manifest(connector_secrets={"github": "my/custom/secret"})
        assert m.connector_secrets == {"github": "my/custom/secret"}

    def test_empty_secret_name_rejected(self) -> None:
        with pytest.raises(pydantic.ValidationError, match="non-empty secret leaf"):
            _manifest(connector_secrets={"github": ""})

    def test_extra_forbid_still_holds(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            _manifest(surprise_field="nope")


# ---------------------------------------------------------------------------
# 2. Registry seam — provider-first resolution, fail closed on any breakage
# ---------------------------------------------------------------------------

class TestProviderResolution:
    def test_provider_happy_path(self) -> None:
        resolved = resolve_connectors(
            ["widget"], providers={"widget": f"{_THIS_MODULE}:DummyConnector"}
        )
        assert isinstance(resolved["widget"], DummyConnector)

    def test_provider_overrides_base_name(self) -> None:
        resolved = resolve_connectors(
            ["github"], providers={"github": f"{_THIS_MODULE}:DummyConnector"}
        )
        assert isinstance(resolved["github"], DummyConnector)

    def test_empty_providers_is_old_behavior(self) -> None:
        assert set(resolve_connectors(["github", "ledger"], providers={})) == {
            "github",
            "ledger",
        }
        assert resolve_connectors([], providers=None) == {}

    # (providers dict, error-message fragment) — each a distinct failure mode,
    # every one fails closed with a loud path-naming ConnectorProviderError.
    BROKEN_PROVIDERS = [
        ({"widget": "no.such.module.anywhere:Thing"}, "cannot be imported"),
        ({"widget": f"{_THIS_MODULE}:NoSuchClass"}, "no attribute"),
        ({"widget": f"{_THIS_MODULE}:NotAConnector"}, "Connector protocol"),
        ({"widget": f"{_THIS_MODULE}:NeedsArgsConnector"}, "zero-arg"),
    ]

    @pytest.mark.parametrize("providers,fragment", BROKEN_PROVIDERS)
    def test_broken_provider_fails_closed(self, providers: dict, fragment: str) -> None:
        with pytest.raises(ConnectorProviderError, match=fragment) as exc:
            resolve_connectors(["widget"], providers=providers)
        # The error must name the offending path so the operator can fix it.
        assert providers["widget"] in str(exc.value)

    def test_unknown_name_still_fails_closed(self) -> None:
        with pytest.raises(UnknownConnectorError):
            resolve_connectors(
                ["bogus"], providers={"widget": f"{_THIS_MODULE}:DummyConnector"}
            )

    def test_first_bad_name_stops_resolution(self) -> None:
        # The bad provider comes first in input order — nothing after it resolves.
        with pytest.raises(ConnectorProviderError):
            resolve_connectors(
                ["widget", "github"],
                providers={"widget": f"{_THIS_MODULE}:NotAConnector"},
            )


# ---------------------------------------------------------------------------
# 3. Secret mapping end-to-end — connector_secrets reaches the Doer
# ---------------------------------------------------------------------------

class TestSecretMappingEndToEnd:
    def _github_call(self, principal) -> BrokeredCall:
        manifest_entry = CATALOG_TABLE.entry("github", "whoami")
        assert manifest_entry is not None
        return BrokeredCall(
            principal=principal,
            tool="github",
            op="whoami",
            args={},
            manifest=manifest_entry,
            taint=Taint(tainted=False, sources=[]),
            session=Session(turnId="test-connector-providers", ingestedSources=[]),
            ts="2026-07-08T00:00:00Z",
        )

    def test_mapped_secret_value_reaches_provider_connector(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The mapped name exists in the secrets file; the default name does not —
        # so receiving the right VALUE proves connector_secrets drove the lookup.
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"custom/github-secret": "sekrit-value"}))
        monkeypatch.setenv("BROKER_SECRETS_FILE", str(secrets_file))

        manifest = _manifest(
            connector_providers={"github": f"{_THIS_MODULE}:DummyConnector"},
            connector_secrets={"github": "custom/github-secret"},
        )
        runtime, _ = build_runtime(manifest)
        doer = runtime._doer
        connector = doer._connectors["github"]
        assert isinstance(connector, DummyConnector)

        result = doer.execute(self._github_call(runtime._principal), Allow(kind="allow"))
        assert result.result["status"] == "dummy-ok"
        assert connector.seen_credentials == ["sekrit-value"]

    def test_empty_connector_secrets_preserves_name_identity(self) -> None:
        # No connector_secrets → secret name == tool name (today's behavior).
        runtime, _ = build_runtime(
            _manifest(connector_providers={"github": f"{_THIS_MODULE}:DummyConnector"})
        )
        assert runtime._doer._secret_name_for("github") == "github"

    def test_mapping_only_applies_to_declared_names(self) -> None:
        runtime, _ = build_runtime(
            _manifest(connector_secrets={"github": "custom/github-secret"})
        )
        name_for = runtime._doer._secret_name_for
        assert name_for("github") == "custom/github-secret"
        assert name_for("ledger") == "ledger"  # undeclared → identity


# ---------------------------------------------------------------------------
# 5. Prefix resolution — a connector_secrets value is a LEAF, not a full id (sa#164)
# ---------------------------------------------------------------------------

class TestPrefixedSecretLeafResolution:
    """`_PrefixedSecrets` treats its input as a leaf under `<prefix>/connectors/`,
    whether it's the default `leaf == tool` or a `connector_secrets` override.

    Regression for sa#164: an override value must resolve to
    `<prefix>/connectors/<leaf>`, never be passed through raw — otherwise the
    documented "maps to a secret NAME" contract silently double-prefixes or misses.
    """

    class _RecordingInner:
        def __init__(self) -> None:
            self.requested: list[str] = []

        def fetch_secret(self, secret_id: str) -> str:
            self.requested.append(secret_id)
            return "value"

    def test_leaf_resolves_under_prefix(self) -> None:
        inner = self._RecordingInner()
        prefixed = broker_server._PrefixedSecrets(inner, "safe-agents/development")
        prefixed.fetch_secret("track-feed-token")
        # The override leaf is resolved under <prefix>/connectors/, NOT passed raw.
        assert inner.requested == [
            "safe-agents/development/connectors/track-feed-token"
        ]

    def test_no_prefix_passes_leaf_through(self) -> None:
        inner = self._RecordingInner()
        prefixed = broker_server._PrefixedSecrets(inner, "")
        prefixed.fetch_secret("track-feed-token")
        assert inner.requested == ["track-feed-token"]


# ---------------------------------------------------------------------------
# 4. Store-cannot-inject invariant — providers only from the baked manifest
# ---------------------------------------------------------------------------

class TestStoreCannotInject:
    """BROKER_ENVELOPE_LOAD=store loads an Envelope, never an AgentManifest.
    The Envelope schema must have no provider/import-path field, and the ONLY
    feed of resolve_connectors' providers argument in the composition root must
    be the manifest object — so store contents can never inject code."""

    def test_envelope_schema_has_no_provider_field(self) -> None:
        forbidden = re.compile(r"provider|import|connector", re.IGNORECASE)
        hits = [f for f in Envelope.model_fields if forbidden.search(f)]
        assert not hits, (
            f"Envelope grew provider/import-path-shaped fields {hits}; the store-"
            "loaded envelope must never carry code-injection config"
        )

    def test_envelope_rejects_provider_keys(self) -> None:
        # extra="forbid" — a store-poisoned envelope carrying provider paths fails
        # validation before it could reach anything.
        with pytest.raises(pydantic.ValidationError):
            Envelope.model_validate(
                {"polarity": "abstain", "connector_providers": {"x": "evil.mod:Klass"}}
            )

    def test_providers_arg_fed_solely_from_manifest(self) -> None:
        # Grep-guard in the debake style: every providers= feed in the composition
        # root must read manifest.connector_providers, nothing else.
        src = Path(broker_server.__file__).read_text()
        feeds = re.findall(r"providers\s*=\s*([^\s,)]+)", src)
        assert feeds, "expected build_runtime to pass providers= to resolve_connectors"
        assert set(feeds) == {"manifest.connector_providers"}, (
            f"providers= fed from {feeds}; the ONLY sanctioned source is the "
            "image-baked manifest object"
        )
