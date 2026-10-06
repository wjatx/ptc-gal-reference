"""The client tier, `safe_agents.broker.client`: what importing it does and does not load.

The tier is published on one ground: a client carries frames and consults
nothing, so a process that only asks need not hold anything that decides. That
is a claim about imports, and it is checked here two ways. A fresh interpreter
imports the tier and reports what arrived (the real effect, including anything a
package `__init__` drags in). The source of every module in the package is
parsed for what it imports (the cause, and it names the offending line).

No SDK and no broker runtime is needed by anything in this file.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
_CLIENT_PACKAGE = "safe_agents.broker.client"
_CLIENT_DIR = REPO_ROOT / "safe_agents" / "broker" / "client"

# What must never arrive with the client tier: what decides, what composes the
# runtime, what holds it, and the two heavy third-party packages behind them.
_RUNTIME_MODULES = (
    "safe_agents.broker.runtime.pep",
    "safe_agents.broker.prototype.broker_server",
    "safe_agents.broker.gateway",
    "safe_agents.broker.gateway.surface",
    "safe_agents.broker.api",
    "safe_agents.broker.schemas",
)
_THIRD_PARTY = ("pydantic", "mcp", "yaml")

_PROBE = """
import importlib, json, sys
before = set(sys.modules)
importlib.import_module(sys.argv[1])
arrived = sorted(set(sys.modules) - before)
print(json.dumps({
    "arrived": arrived,
    "stdlib": sorted(sys.stdlib_module_names),
}))
"""


def _arrivals(module: str) -> tuple[set[str], set[str]]:
    """Import `module` in a fresh interpreter: (modules that arrived, stdlib names)."""
    done = subprocess.run(
        [sys.executable, "-c", _PROBE, module],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    return set(report["arrived"]), set(report["stdlib"])


class TestImportingTheTierLoadsNoRuntime:
    def test_the_runtime_is_absent_after_importing_the_tier(self) -> None:
        arrived, _ = _arrivals(_CLIENT_PACKAGE)
        assert f"{_CLIENT_PACKAGE}.network" in arrived and f"{_CLIENT_PACKAGE}.stdio" in arrived
        loaded = [name for name in _RUNTIME_MODULES if name in arrived]
        assert loaded == [], f"importing the client tier loaded the broker runtime: {loaded}"

    def test_nothing_from_the_base_arrives_but_the_tier_itself(self) -> None:
        """Stronger than a list of forbidden names, which only knows today's modules."""
        arrived, _ = _arrivals(_CLIENT_PACKAGE)
        base = {name for name in arrived if name == "safe_agents" or name.startswith("safe_agents.")}
        allowed = {"safe_agents", "safe_agents.broker"}
        strays = sorted(
            name for name in base - allowed
            if name != _CLIENT_PACKAGE and not name.startswith(_CLIENT_PACKAGE + ".")
        )
        assert strays == [], f"the client tier imported from the rest of the base: {strays}"

    def test_nothing_outside_the_standard_library_arrives(self) -> None:
        arrived, stdlib = _arrivals(_CLIENT_PACKAGE)
        tops = {name.split(".", 1)[0] for name in arrived}
        foreign = sorted(tops - stdlib - {"safe_agents"})
        assert foreign == [], f"the client tier is standard library only, but loaded: {foreign}"
        assert not [name for name in _THIRD_PARTY if name in tops]

    @pytest.mark.parametrize(
        "module",
        [
            pytest.param("safe_agents.broker.api", id="what a consumer runs"),
            pytest.param("safe_agents.broker.gateway.stdio_client", id="the client's old internal path"),
        ],
    )
    def test_the_probe_sees_the_runtime_when_it_is_loaded(self, module: str) -> None:
        """The control. The same probe, pointed at an import that does load the
        runtime, must say so, or the absence above proves nothing. The second case
        is also why the clients moved: their old path sits under a package whose
        `__init__` loads the surface and the runtime with it."""
        arrived, _ = _arrivals(module)
        assert "safe_agents.broker.runtime.pep" in arrived


class TestTheTiersSourceReachesNothing:
    def _imports(self, path: Path) -> list[tuple[int, str]]:
        found: list[tuple[int, str]] = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if isinstance(node, ast.Import):
                found.extend((node.lineno, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.append((node.lineno, ("." * node.level) + (node.module or "")))
        return found

    def test_every_module_imports_only_the_standard_library_and_the_tier(self) -> None:
        """Checked on every import statement, wherever it sits: one inside a
        function would not show up in the fresh-interpreter probe until called."""
        sources = sorted(_CLIENT_DIR.glob("*.py"))
        assert {p.name for p in sources} >= {"__init__.py", "_frames.py", "stdio.py", "network.py"}
        offenders: list[str] = []
        for path in sources:
            for lineno, name in self._imports(path):
                top = name.split(".", 1)[0]
                inside = name == _CLIENT_PACKAGE or name.startswith(_CLIENT_PACKAGE + ".")
                if name == "__future__" or inside or top in sys.stdlib_module_names:
                    continue
                offenders.append(f"{path.name}:{lineno}: {name}")
        assert offenders == [], (
            "the client tier is published on the ground that it carries frames and "
            "consults nothing, but it imports: " + ", ".join(offenders)
        )

    def test_no_module_imports_by_name_at_run_time(self) -> None:
        """An import the parser cannot see would walk past the check above."""
        for path in sorted(_CLIENT_DIR.glob("*.py")):
            names = {name.split(".", 1)[0] for _, name in self._imports(path)}
            assert "importlib" not in names, f"{path.name} imports importlib"
            assert "__import__" not in path.read_text(encoding="utf-8"), path.name


class TestTheOldPathStillResolves:
    def test_the_internal_path_hands_back_the_tiers_own_objects(self) -> None:
        from safe_agents.broker import client
        from safe_agents.broker.client import stdio
        from safe_agents.broker.gateway import stdio_client as old

        assert old.GatewayClient is client.GatewayClient
        assert old.GatewayClientError is client.GatewayClientError
        assert old.result_text is client.result_text
        assert old.env_without_broker_config is stdio.env_without_broker_config
        assert old.BROKER_ENV_VARS is stdio.BROKER_ENV_VARS

    def test_both_clients_share_one_set_of_calls(self) -> None:
        """One definition of what is sent, so the two transports cannot drift."""
        from safe_agents.broker.client import GatewayClient, NetworkGatewayClient
        from safe_agents.broker.client._frames import McpCalls

        for name in ("initialize", "list_tools", "call_tool"):
            assert getattr(GatewayClient, name) is getattr(McpCalls, name)
            assert getattr(NetworkGatewayClient, name) is getattr(McpCalls, name)
