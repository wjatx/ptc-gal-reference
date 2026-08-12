"""test_broker_debake.py — broker-debaking P2 acceptance (sa#113).

Two layers, matching the phase's two-part definition-of-done:

1. **Grep-guard (deterministic exit predicate).** ``TestDebakeGuard`` reads the
   composition root (``broker_server.py``) source and asserts NO agent-specific
   constant remains — not "the tests are green", but "the baked value is gone".
   Green ≠ gone; this proves gone.
2. **Behavior.** ``build_runtime(manifest)`` builds the runtime entirely from an
   AgentManifest — principal, served registry, counter cap, connectors — with the
   BROKER_GRANT_CLASSES override and fail-closed edges intact. Plus the connector
   registry seam in isolation.

AWS-free: build_runtime defaults to in-memory stores + fake secrets + in-memory
audit (no BROKER_STORE), so every test constructs with no AWS / network.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import build_runtime, load_agent_manifest
from safe_agents.broker.prototype.connector_registry import (
    UnknownConnectorError,
    known_connector_names,
    resolve_connectors,
)
from safe_agents.broker.schemas import AgentManifest

_BROKER_SERVER_SRC = Path(broker_server.__file__)
_EXAMPLE_MANIFEST = Path(broker_server._DEFAULT_MANIFEST_PATH)


def _manifest(**overrides) -> AgentManifest:
    """A minimal valid AgentManifest for behavior tests; overrides merge shallow."""
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
        "principal": {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"},
        "grant_classes": ["search.query", "notify.send"],
        "connectors": ["github", "search"],
        # #171 — classifications are consumer-owned and travel in the manifest;
        # build_runtime compiles these into the runtime's ToolOpTable. Carry every
        # op these behavior tests grant (incl. github.whoami for the env override).
        "tool_ops": [
            {"tool": "search", "op": "query", "effect": "read", "external": True},
            {"tool": "notify", "op": "send", "effect": "write", "external": True,
             "reversible": True},
            {"tool": "github", "op": "whoami", "effect": "read", "external": True},
        ],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


# ---------------------------------------------------------------------------
# 1. Grep-guard — no agent-specific constant survives in the composition root
# ---------------------------------------------------------------------------

class TestDebakeGuard:
    """The deterministic exit predicate: the baked constants are GONE, not merely
    unused. Each pattern is a value/identifier that must never reappear in
    broker_server.py — if one does, the config has re-accreted into the code."""

    # (pattern, human-readable reason) — regexes over the source. Word boundaries
    # keep _COUNTER_CAP from matching the allowed generic _DEFAULT_COUNTER_CAP.
    FORBIDDEN = [
        (r"_PRINCIPAL_DATA", "baked principal dict must be manifest-sourced"),
        (r"_DEFAULT_ACTION_CLASSES", "baked action-class list must be manifest-sourced"),
        (r"_GRANTED_ACTION_CLASSES", "baked granted-class list must be manifest-sourced"),
        (r"(?<![A-Z_])_COUNTER_CAP\b", "baked counter cap must come from envelope.caps"),
        (r'"example-agent"', "the agent identity must not be a code literal"),
        (r"'example-agent'", "the agent identity must not be a code literal"),
        (r'"advisor"', "the agent skill must not be a code literal"),
        # The hardcoded connectors dict — connector CLASSES instantiated in the
        # composition root. They now live in connector_registry (base machinery,
        # selected by name from the manifest). Prose mentions the class names
        # WITHOUT parens; the instantiation `Foo(` is the baked-wiring signal.
        (r"GitHubConnector\(", "connectors must resolve via the registry, not be wired here"),
        (r"AlpacaConnector\(", "connectors must resolve via the registry, not be wired here"),
        (r"TelegramConnector\(", "connectors must resolve via the registry, not be wired here"),
        (r"LedgerConnector\(", "connectors must resolve via the registry, not be wired here"),
        (r"SearchConnector\(", "connectors must resolve via the registry, not be wired here"),
    ]

    @pytest.mark.parametrize("pattern,reason", FORBIDDEN)
    def test_no_agent_specific_constant(self, pattern: str, reason: str) -> None:
        src = _BROKER_SERVER_SRC.read_text()
        hits = [
            f"  line {i}: {ln.strip()}"
            for i, ln in enumerate(src.splitlines(), 1)
            if re.search(pattern, ln)
        ]
        assert not hits, (
            f"agent-specific constant re-accreted in {_BROKER_SERVER_SRC.name} "
            f"(pattern {pattern!r}: {reason}):\n" + "\n".join(hits)
        )

    def test_build_runtime_requires_a_manifest(self) -> None:
        """Structural proof the constants can't be re-baked: there is no
        zero-arg build_runtime() — a manifest is mandatory."""
        with pytest.raises(TypeError):
            build_runtime()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# 2. build_runtime(manifest) — every agent-specific value comes from the manifest
# ---------------------------------------------------------------------------

class TestBuildRuntimeFromManifest:
    def test_principal_from_manifest(self) -> None:
        runtime, _ = build_runtime(_manifest())
        assert runtime._principal.agentId == "test-agent"

    def test_served_registry_matches_grant_classes(self) -> None:
        runtime, _ = build_runtime(_manifest(grant_classes=["search.query", "notify.send"]))
        served = {f"{t.tool}.{t.op}" for t in runtime.served_registry()}
        assert served == {"search.query", "notify.send"}

    def test_counter_cap_from_envelope_caps(self) -> None:
        runtime, _ = build_runtime(
            _manifest(envelope={"polarity": "abstain", "caps": {"actions_per_run": 42}})
        )
        assert runtime._counter_cap == 42.0

    def test_counter_cap_falls_back_when_caps_absent(self) -> None:
        # No caps block at all → the generic platform default, not a crash — but
        # ONLY for read-effect grants (#205: granted writes must NAME their cap).
        runtime, _ = build_runtime(
            _manifest(envelope={"polarity": "abstain"}, grant_classes=["search.query"])
        )
        assert runtime._counter_cap == broker_server._DEFAULT_COUNTER_CAP

    def test_grant_classes_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # BROKER_GRANT_CLASSES is the harness override — it must beat the manifest.
        monkeypatch.setenv("BROKER_GRANT_CLASSES", "github.whoami")
        runtime, _ = build_runtime(_manifest(grant_classes=["search.query", "notify.send"]))
        served = {f"{t.tool}.{t.op}" for t in runtime.served_registry()}
        assert served == {"github.whoami"}

    def test_missing_principal_fails_loud(self) -> None:
        with pytest.raises(ValueError, match="principal is required"):
            build_runtime(_manifest(principal=None))

    def test_unknown_connector_fails_closed(self) -> None:
        with pytest.raises(UnknownConnectorError):
            build_runtime(_manifest(connectors=["github", "not-a-connector"]))


# ---------------------------------------------------------------------------
# 3. The bundled default manifest is a fictional example (example-agent retired, P3)
# ---------------------------------------------------------------------------

class TestDefaultManifestIsFictionalExample:
    """P3 retired the example-agent default: the checked-in default manifest is now
    a deliberately-generic, obviously-fictional demo consumer that belongs to NO real
    agent. It must still build a runtime end-to-end, and example-agent must be gone."""

    def test_default_manifest_is_the_fictional_demo(self) -> None:
        manifest = load_agent_manifest(_EXAMPLE_MANIFEST)
        assert manifest.principal is not None
        assert manifest.principal.agentId == "example-advisor"
        # example-agent is retired — it must not be the default principal any more.
        assert manifest.principal.agentId != "example-agent"
        # The demo advisor is abstain-safe; polarity is never silently defaulted.
        assert manifest.envelope.polarity == "abstain"

    def test_retired_consumer_absent_from_default_manifest(self) -> None:
        # Belt-and-suspenders: the literal string must not survive anywhere in the file.
        assert "example-agent" not in _EXAMPLE_MANIFEST.read_text()

    def test_default_runtime_serves_its_grant_classes(self) -> None:
        manifest = load_agent_manifest(_EXAMPLE_MANIFEST)
        runtime, _ = build_runtime(manifest)
        served = {f"{t.tool}.{t.op}" for t in runtime.served_registry()}
        assert served == set(manifest.grant_classes)


# ---------------------------------------------------------------------------
# 4. Connector registry seam — by name, fail closed on unknown
# ---------------------------------------------------------------------------

class TestConnectorRegistry:
    def test_known_names_are_the_five_base_connectors(self) -> None:
        assert set(known_connector_names()) == {
            "github", "notify", "ledger", "search", "peer",
        }

    def test_resolve_returns_instances_for_named_connectors(self) -> None:
        resolved = resolve_connectors(["github", "ledger"])
        assert set(resolved) == {"github", "ledger"}

    def test_resolve_empty_is_empty(self) -> None:
        assert resolve_connectors([]) == {}

    def test_unknown_name_raises_with_the_known_set(self) -> None:
        with pytest.raises(UnknownConnectorError) as exc:
            resolve_connectors(["github", "bogus"])
        # The error names the offending connector and lists what IS resolvable.
        assert "bogus" in str(exc.value)
        assert "github" in str(exc.value)


# ---------------------------------------------------------------------------
# 5. load_agent_manifest — broker-side loader, fails loud on bad input
# ---------------------------------------------------------------------------

class TestLoadAgentManifest:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_agent_manifest(tmp_path / "nope.yaml")

    def test_non_mapping_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("- just\n- a\n- list\n")
        with pytest.raises(ValueError, match="must be a YAML mapping"):
            load_agent_manifest(p)

    def test_missing_polarity_is_not_silently_defaulted(self, tmp_path: Path) -> None:
        # polarity is never defaulted — a missing one is a hard validation error.
        p = tmp_path / "no_polarity.yaml"
        p.write_text("envelope:\n  caps:\n    actions_per_run: 1\n")
        with pytest.raises(Exception):  # pydantic.ValidationError
            load_agent_manifest(p)
