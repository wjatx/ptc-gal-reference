"""test_consumer_boundary.py — the base/consumer boundary as a hard CI gate (P3).

Broker-debaking P3 stands up fictional example consumers under ``examples/`` and makes
the base/consumer boundary a gate, not a convention. Three things are asserted here:

1. **No example reaches into broker INTERNALS.** A consumer stands on the base's public
   surface — ``safe_agents.broker.schemas`` (what it FILLS) and ``safe_agents.broker.api``
   (what it RUNS), the TWO allowed broker subpackages [#266] — and supplies a manifest;
   ANY other ``safe_agents.broker.<X>`` import is a reach into internals. The check is an ALLOWLIST (not an enumerated
   denylist), so it catches both import forms and stays correct as internal modules are
   added — see the detector below. Any ``.py`` under ``examples/`` is scanned — the
   examples tree is populated now, and (2) keeps the gate honest regardless.
2. **The gate has TEETH.** ``test_probe_is_flagged`` runs the same detector against
   synthetic bad import strings — spanning the dotted, bare package-import, and
   multi-line parenthesized forms — and asserts each IS flagged. "Green" therefore
   means the gate would actually block an internal import, not that ``examples/``
   merely happens to be empty of Python. (DoD: "fails on a deliberate internal-import
   probe and is green otherwise.")
3. **The composition root is agent-agnostic.** ``broker_server.py`` must name no
   specific consumer identity (example-agent / any example agentId) — the P2 grep-guard
   approach, re-applied at the consumer boundary.

AWS-free: only source parsing and in-memory ``build_runtime``.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import build_runtime, load_agent_manifest

# <root>/safe_agents/broker/tests/ -> parents[3] == repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_EXAMPLES_DIR = _REPO_ROOT / "examples"
_BROKER_SERVER_SRC = Path(broker_server.__file__)


# ---------------------------------------------------------------------------
# The detector — an AST walk with an ALLOWLIST. `safe_agents.broker.schemas` (the
# typed AgentManifest / Envelope surface) is the ONE broker subpackage an example may
# import; ANY other `safe_agents.broker.<X>` reference is a reach into internals.
#
# Walking the parsed AST (not scanning source lines) removes ALL text-parsing
# fragility at once — multi-line parenthesized imports, `as` aliases, indented /
# conditional / nested imports — and an allowlist (vs enumerating the ~14 internal
# subpackages) stays correct as new internal modules land, no re-enumeration.
# ---------------------------------------------------------------------------

_BROKER_PKG = "safe_agents.broker"
# The TWO broker subpackages that are the public consumer surface [ruling: maintainer,
# 2026-07-26, #266]: **a consumer may import what it FILLS and what it RUNS,
# never what DECIDES.**
#
#   schemas — what it FILLS: the seven contract types, AgentManifest, Envelope.
#   api     — what it RUNS: build_runtime + the runtime objects it returns.
#
# Everything else is internal, and two of those deserve naming because the docs
# used to publish them. `runtime` re-exports Doer, SecretsProvider and the
# credential strategies — what EXECUTES; and the PDP is what DECIDES. A consumer
# able to import either can route around the decision it is meant to be subject
# to, which is precisely what "the broker is the one deliberately non-swappable
# implementation" forbids. So a consumer gets the runtime, never its parts.
#
# History worth keeping, since this set has moved twice: the #219 widening to
# `{schemas, mcp}` existed solely so a consumer provider class could compose
# stdio_host_factory + a ToolRegistryStore by hand; #221's native construction
# retired that pattern and the widening was reverted. The #266 addition of `api`
# is the opposite kind of change — not a mechanism a consumer composes by hand,
# but the one entry point two published docs already promised while this guard
# forbade it.
_PUBLIC_BROKER_SURFACES = frozenset({"schemas", "api"})


def _first_segment_after_broker(dotted: str) -> str | None:
    """For a `safe_agents.broker.<X>...` module path, the `<X>` segment (else None).

    `safe_agents.broker.schemas.envelope` -> `schemas`; `safe_agents.broker` (no
    subpackage) or an unrelated module -> None.
    """
    prefix = _BROKER_PKG + "."
    if not dotted.startswith(prefix):
        return None
    return dotted[len(prefix):].split(".", 1)[0]


def _internal_import_hits(source: str) -> list[str]:
    """Return broker-INTERNAL imports in ``source`` (empty == clean).

    Parses ``source`` and walks every ``import`` / ``from ... import`` node; a hit is
    any import that reaches a ``safe_agents.broker`` subpackage other than the
    allowlisted ``schemas``. Comments/prose naming an internal module never parse as
    an import node, so they cannot trip the gate. A ``SyntaxError`` propagates — a
    probe or example file that does not parse is an authoring error, not a silent pass.

    Scope: this is a STATIC-import guard — it does NOT catch dynamic
    ``importlib.import_module("safe_agents.broker.<internal>")`` or bare-package
    ``import safe_agents.broker`` followed by attribute access. That is intentional: a
    runtime import hook would be disproportionate for a CI gate. A future reader should
    not assume dynamic imports are gated.
    """
    hits: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # `import safe_agents.broker.<X>` (optionally `as alias`)
            for alias in node.names:
                seg = _first_segment_after_broker(alias.name)
                if seg is not None and seg not in _PUBLIC_BROKER_SURFACES:
                    hits.append(f"  line {node.lineno}: import {alias.name} -> reaches {seg!r}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == _BROKER_PKG:
                # `from safe_agents.broker import <name>[, ...]` — each imported name
                # is itself the subpackage; flag any that is not `schemas`.
                for alias in node.names:
                    if alias.name not in _PUBLIC_BROKER_SURFACES:
                        hits.append(
                            f"  line {node.lineno}: from {module} import {alias.name} "
                            f"-> reaches {alias.name!r}"
                        )
            else:
                # `from safe_agents.broker.<X>[...] import ...` — the subpackage is in
                # the module path (relative imports have module without the prefix and
                # are ignored — an example is not a submodule of the broker package).
                seg = _first_segment_after_broker(module)
                if seg is not None and seg not in _PUBLIC_BROKER_SURFACES:
                    hits.append(f"  line {node.lineno}: from {module} import ... -> reaches {seg!r}")
    return hits


# ---------------------------------------------------------------------------
# 1. Teeth — the detector actually flags an internal import (proves green ≠ empty)
# ---------------------------------------------------------------------------

class TestBoundaryGuardHasTeeth:
    # Every one of these MUST be flagged. They span every shape a text-scan could
    # miss: the bare package-import form, internal subpackages a hand-written denylist
    # never enumerates (manifest/envelope/delegation/chaos), the `as`-alias form, and
    # the MULTI-LINE parenthesized form — the last is exactly why the detector walks
    # the AST rather than scanning lines.
    INTERNAL_PROBES = [
        "from safe_agents.broker.runtime.pep import PEP",   # dotted (original)
        "from safe_agents.broker import pep",               # bare package-import form
        "from safe_agents.broker import runtime, schemas",  # mixed: runtime still flagged
        "import safe_agents.broker.runtime",                # bare `import ...` form
        "import safe_agents.broker.runtime as rt",          # `as` alias
        "from safe_agents.broker.manifest import get_manifest_entry",
        "from safe_agents.broker.envelope import compute_envelope_hash",
        "from safe_agents.broker.delegation import x",
        "from safe_agents.broker.chaos import x",
        "from safe_agents.broker import (\n    pep,\n    schemas,\n)",  # multi-line parenthesized
        # The MCP-host tier is internal again since #221 (native construction
        # retired the consumer-composed provider pattern; the #219 widening was
        # explicitly flagged reversible).
        "from safe_agents.broker.mcp import stdio_host_factory",
        "from safe_agents.broker.mcp.factory import stdio_host_factory",
        "from safe_agents.broker.mcp.registry import DynamoToolRegistry",
    ]

    @pytest.mark.parametrize("probe", INTERNAL_PROBES)
    def test_probe_is_flagged(self, probe: str) -> None:
        assert _internal_import_hits(probe + "\n"), (
            f"boundary guard is toothless — internal-import probe {probe!r} was NOT "
            "flagged; the detector would let a real example reach into internals"
        )

    # Both public tiers — in every import shape — must NOT trip the gate.
    PUBLIC_IMPORTS = [
        # Tier 1: what a consumer FILLS.
        "from safe_agents.broker.schemas import AgentManifest",
        "from safe_agents.broker import schemas",
        "from safe_agents.broker.schemas.envelope import Envelope",
        "import safe_agents.broker.schemas",
        # Tier 2: what a consumer RUNS (#266).
        "from safe_agents.broker.api import build_runtime",
        "from safe_agents.broker.api import build_runtime, BrokerRuntime",
        "from safe_agents.broker import api",
        "import safe_agents.broker.api",
    ]

    @pytest.mark.parametrize("ok", PUBLIC_IMPORTS)
    def test_public_import_is_not_flagged(self, ok: str) -> None:
        assert _internal_import_hits(ok + "\n") == []


class TestPublicSurfaceIsExactlyTheRuling:
    """The façade's contents are the ruling, so they are asserted, not trusted.

    `api.py` is a curated re-export list; the whole reason it exists instead of a
    public package is that a list can be checked. Two directions matter, and the
    second is the one that rots quietly: that the promised names ARE there, and
    that what DECIDES and what EXECUTES are NOT — a well-meaning later edit
    adding `Doer` for a test's convenience would silently publish the executor.
    """

    def test_the_promised_names_are_importable(self) -> None:
        from safe_agents.broker import api

        for name in ("build_runtime", "load_agent_manifest", "BrokerRuntime"):
            assert hasattr(api, name), f"api.py no longer exports {name!r}"

    def test_what_decides_and_executes_stays_unpublished(self) -> None:
        from safe_agents.broker import api

        for forbidden in (
            "Doer",  # what EXECUTES
            "SecretsProvider",  # credential resolution
            "PEP",
            "PDP",  # what DECIDES
            "StaticSecret",
            "OAuthRefresh",
            "AssumedRole",  # credential strategies
        ):
            assert forbidden not in (api.__all__ or ()), (
                f"{forbidden!r} is in broker.api.__all__ — a consumer gets the "
                "runtime, never its parts (#266 ruling)"
            )


# ---------------------------------------------------------------------------
# 2. No example under examples/ imports broker internals (green today, gated forever)
# ---------------------------------------------------------------------------

class TestExamplesDoNotImportInternals:
    def test_no_example_python_imports_broker_internals(self) -> None:
        offenders: list[str] = []
        for py in sorted(_EXAMPLES_DIR.rglob("*.py")):
            hits = _internal_import_hits(py.read_text())
            if hits:
                offenders.append(f"{py.relative_to(_REPO_ROOT)}:\n" + "\n".join(hits))
        assert not offenders, (
            "an example reached into broker internals (consumers may only use the "
            "public `safe_agents.broker.{schemas, api}` surfaces [#266]):\n"
            + "\n\n".join(offenders)
        )


# ---------------------------------------------------------------------------
# 3. Composition root names no specific consumer (P2 grep-guard, at the boundary)
# ---------------------------------------------------------------------------

class TestCompositionRootIsAgentAgnostic:
    # Consumer identities that live in manifests, never in the composition root.
    FORBIDDEN_IDENTITIES = ["example-agent", "missileer", "sepsis", "example-advisor"]

    @pytest.mark.parametrize("identity", FORBIDDEN_IDENTITIES)
    def test_broker_server_names_no_consumer(self, identity: str) -> None:
        src = _BROKER_SERVER_SRC.read_text()
        hits = [
            f"  line {i}: {ln.strip()}"
            for i, ln in enumerate(src.splitlines(), 1)
            if identity in ln
        ]
        assert not hits, (
            f"composition root {_BROKER_SERVER_SRC.name} names consumer {identity!r} — "
            "agent-specific identity must live in a manifest, not the base code:\n"
            + "\n".join(hits)
        )


# ---------------------------------------------------------------------------
# 4. Both real example consumers build a runtime end-to-end
# ---------------------------------------------------------------------------

class TestExampleConsumersBuildRuntime:
    """missileer (abstain-safe) + sepsis-detection (act-safe) prove the base is
    polarity-blind: the SAME build_runtime serves each, differing only in the
    declared polarity carried through from the manifest."""

    @pytest.mark.parametrize(
        "name,expected_polarity",
        [("missileer", "abstain"), ("sepsis-detection", "act")],
    )
    def test_example_builds_and_serves_its_grant_classes(
        self, name: str, expected_polarity: str
    ) -> None:
        manifest = load_agent_manifest(_EXAMPLES_DIR / name / "manifest.yaml")
        assert manifest.envelope.polarity == expected_polarity
        runtime, _ = build_runtime(manifest)
        served = {f"{t.tool}.{t.op}" for t in runtime.served_registry()}
        assert served == set(manifest.grant_classes)


# ---------------------------------------------------------------------------
# 5. The sa#141 injection seam has a worked example consumer (missileer)
# ---------------------------------------------------------------------------

class TestExampleProviderConnector:
    """missileer supplies its OWN `search` connector via connector_providers — the
    one sanctioned injection seam. Prove the example resolves end-to-end: the
    manifest declares the provider + a mapped secret NAME, build_runtime wires the
    consumer class (not the base SearchConnector), and the example file itself
    passes the same AST boundary guard as every other example."""

    def _missileer_manifest(self):
        return load_agent_manifest(_EXAMPLES_DIR / "missileer" / "manifest.yaml")

    def test_manifest_declares_provider_and_secret_name(self) -> None:
        manifest = self._missileer_manifest()
        assert manifest.connector_providers == {
            "search": "examples.missileer.trackfeed_connector:TrackFeedConnector"
        }
        # Leaves only, never values — the mapped Secrets Manager LEAF (sa#164).
        assert manifest.connector_secrets == {"search": "track-feed-token"}

    def test_build_runtime_wires_the_consumer_connector(self) -> None:
        from examples.missileer.trackfeed_connector import TrackFeedConnector

        manifest = self._missileer_manifest()
        runtime, _ = build_runtime(manifest)
        doer = runtime._doer
        # The provider class won the `search` name; the other names stay base.
        assert type(doer._connectors["search"]) is TrackFeedConnector
        assert set(doer._connectors) == set(manifest.connectors)
        # connector_secrets drives the Doer's secret-name mapping; undeclared
        # names keep the default name == tool-name identity.
        assert doer._secret_name_for("search") == "track-feed-token"
        assert doer._secret_name_for("ledger") == "ledger"

    def test_provider_module_passes_the_boundary_guard(self) -> None:
        # Redundant with the rglob sweep above, but pins the sa#141 example by
        # name: the consumer connector imports only public surfaces.
        src = (_EXAMPLES_DIR / "missileer" / "trackfeed_connector.py").read_text()
        assert _internal_import_hits(src) == []
        assert "safe_agents.connectors" in src  # written against the public surface
