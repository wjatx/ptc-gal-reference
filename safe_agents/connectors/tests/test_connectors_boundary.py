"""Connector-boundary tests (sa#106 Phase 4).

Asserts the shared-vs-agent-owned split holds structurally:
  1. safe_agents.connectors imports cleanly and exposes the protocol + the
     shared connectors (github, telegram).
  2. The SDK core imports with NO hard dependency on any single-agent connector:
     importing safe_agents.connectors / broker / pipeline pulls in no
     `example_connector` module. This stands in for "a venv where the agent-owned
     connector's deps are absent" — that connector is stdlib-only, so the
     meaningful, deterministic check is that the SDK core's import graph never
     reaches it.
"""
from __future__ import annotations

import subprocess
import sys

from safe_agents.connectors import (
    Connector,
    ConnectorCall,
    GitHubConnector,
    LedgerConnector,
    SearchConnector,
    StubConnector,
    TelegramConnector,
)


def test_connectors_package_imports_and_exposes_shared_connectors() -> None:
    """`import safe_agents.connectors` works and re-exports protocol + shared connectors."""
    # Protocol + test doubles re-exported from the broker runtime.
    assert Connector is not None
    assert ConnectorCall is not None
    assert StubConnector is not None
    # Shared connectors are the real classes.
    assert GitHubConnector.__name__ == "GitHubConnector"
    assert TelegramConnector.__name__ == "TelegramConnector"
    assert LedgerConnector.__name__ == "LedgerConnector"
    assert SearchConnector.__name__ == "SearchConnector"


def test_shared_connectors_satisfy_the_connector_protocol() -> None:
    """github (at minimum) is importable AND a structural Connector."""
    # Connector is a runtime_checkable Protocol with an execute(...) method.
    assert isinstance(GitHubConnector(), Connector)
    assert isinstance(TelegramConnector(), Connector)
    assert isinstance(LedgerConnector(), Connector)
    assert isinstance(SearchConnector(), Connector)


def test_sdk_core_has_no_hard_single_agent_connector_dependency() -> None:
    """Importing the SDK core must not pull in any single-agent connector.

    Run in a FRESH interpreter so the assertion is independent of whatever other
    tests already imported into this process's sys.modules.
    """
    code = (
        "import safe_agents.connectors, safe_agents.broker, safe_agents.pipeline\n"
        "import sys\n"
        "leaked = sorted(m for m in sys.modules if 'example_connector' in m.lower())\n"
        "assert not leaked, f'SDK core imported single-agent connector(s): {leaked}'\n"
        "print('OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"SDK core import leaked a single-agent connector dependency.\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "OK" in proc.stdout
