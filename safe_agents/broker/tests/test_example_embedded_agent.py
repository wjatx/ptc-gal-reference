"""Tests for the embedded_agent worked example (#266).

The example proves the broker is usable as a LIBRARY — embedded in a plain Python
program through `safe_agents.broker.api` — rather than only as a service configured
by a manifest and a consumer image. These tests pin the three claims its README
makes, so the claims cannot rot into documentation-only assertions:

  1. the manifest parses and its classified-but-ungranted gap is real;
  2. running the agent yields allow-then-deny, with the deny a POLICY refusal
     (the PDP's "tool not granted"), not a missing manifest entry;
  3. the example imports nothing outside the two sanctioned tiers.

Claim 3 overlaps `test_consumer_boundary.py`'s sweep of `examples/` by design: that
guard proves no example reaches broker internals, while this one proves THIS example
positively exercises `broker.api`. An example that quietly stopped importing the
public surface would keep the guard green and stop demonstrating anything.

Lives here rather than beside the example because `examples/` is not on any pytest
path — `testpaths` (pyproject.toml) names `safe_agents`, `reliability`,
`observability`, and no CI job names `examples/`. The convention this file follows
is `test_example_confidence_budget.py`'s: example code in `examples/`, its test here.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

from safe_agents.broker.schemas import AgentManifest

_EXAMPLE_ROOT = Path(__file__).resolve().parents[3] / "examples" / "embedded_agent"
_MANIFEST_PATH = _EXAMPLE_ROOT / "manifest.yaml"

# The two tiers a consumer may import [ruling: maintainer, 2026-07-26]: what it FILLS and
# what it RUNS. Anything else under safe_agents.broker is internal.
_SANCTIONED_BROKER_MODULES = {"safe_agents.broker.api", "safe_agents.broker.schemas"}


def _manifest() -> AgentManifest:
    return AgentManifest.model_validate(yaml.safe_load(_MANIFEST_PATH.read_text()))


class TestEmbeddedAgentManifest:
    def test_manifest_parses(self) -> None:
        manifest = _manifest()
        assert manifest.principal is not None
        assert manifest.principal.agentId == "embedded-assistant"

    def test_the_deny_op_is_classified_but_not_granted(self) -> None:
        """The gap that makes the refusal a policy decision rather than a typo.

        `notify.send` must be present in tool_ops (so the runtime resolves it and the
        PDP gets to rule) and absent from grant_classes (so the PDP rules against it).
        Closing either half would turn the example's demonstration into a different,
        weaker one — an absent entry denies before the PDP ever runs.
        """
        manifest = _manifest()
        classified = {f"{op.tool}.{op.op}" for op in manifest.tool_ops}
        assert "notify.send" in classified
        assert "notify.send" not in manifest.grant_classes
        assert "search.query" in manifest.grant_classes

    def test_the_allow_path_is_consumer_supplied_and_therefore_offline(self) -> None:
        """`search` must be overridden via connector_providers.

        Every base connector reaches the network or AWS at execute() time, so an
        example claiming "no account, no credentials" cannot leave the allow path on
        a base implementation.
        """
        manifest = _manifest()
        provider = manifest.connector_providers.get("search")
        assert provider == (
            "examples.embedded_agent.local_search_connector:LocalSearchConnector"
        )


class TestEmbeddedAgentRun:
    def test_run_allows_the_granted_op_and_denies_the_ungranted_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The example's claim is that it runs with NO BROKER_* configuration; assert
        # that by clearing the arm-selecting variables rather than trusting the
        # ambient environment (a stray BROKER_STORE would otherwise silently change
        # which backends this test proved).
        for var in (
            "BROKER_STORE",
            "BROKER_MANIFEST",
            "BROKER_SECRETS",
            "BROKER_SECRETS_DIR",
            "BROKER_SECRETS_FILE",
            "BROKER_AUDIT_PATH",
            "BROKER_AUDIT_BUCKET",
            "BROKER_ENVELOPE_LOAD",
            "BROKER_GRANT_LOAD",
            "BROKER_SQLITE_PATH",
        ):
            monkeypatch.delenv(var, raising=False)

        from examples.embedded_agent.agent import run

        outcomes = dict((coord, (kind, reason)) for coord, kind, reason in run())

        assert outcomes["search.query"][0] == "allow"
        # The deny is the PDP's, not the runtime's pre-PDP manifest lookup. Pinning
        # the reason string is the point: "no manifest entry for notify.send" would
        # mean the example had decayed into demonstrating a missing classification.
        kind, reason = outcomes["notify.send"]
        assert kind == "deny"
        assert reason == "tool not granted to this principal"


class TestEmbeddedAgentImportSurface:
    def test_the_example_imports_only_the_sanctioned_broker_tiers(self) -> None:
        """Positively assert the example exercises `broker.api`.

        The consumer-boundary guard proves examples do not reach INTERNALS. This
        proves this example still reaches the PUBLIC surface — the property that
        makes it a demonstration rather than a program that happens to pass.
        """
        broker_imports: set[str] = set()
        for path in sorted(_EXAMPLE_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    module = node.module
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("safe_agents.broker"):
                            broker_imports.add(alias.name)
                    continue
                else:
                    continue
                if module.startswith("safe_agents.broker"):
                    broker_imports.add(module)

        assert "safe_agents.broker.api" in broker_imports, (
            "the embedding example must import safe_agents.broker.api — that import "
            "IS the thing it demonstrates"
        )
        assert broker_imports <= _SANCTIONED_BROKER_MODULES, (
            f"example imports outside the sanctioned tiers: "
            f"{sorted(broker_imports - _SANCTIONED_BROKER_MODULES)}"
        )
