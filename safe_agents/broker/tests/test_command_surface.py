"""test_command_surface.py — the published command surface, held to the code.

`docs/consuming-the-sdk.md` section 2 publishes six ``python -m`` commands that a
consumer may run as child processes. A consumer builds on those module paths and on
the subcommands and flags the table names, so a rename here breaks someone who
cannot see this repository's tests. Three things are asserted:

1. **Each published module exists and can be run.** It resolves, and it is runnable
   with ``-m`` (a module with a ``main``, or a package with a ``__main__``).
2. **Each published subcommand and flag is still accepted.** The command's own
   ``--help`` is asked, in a child process, the way a consumer would ask it.
3. **The document and this file agree.** Every command the document's table names
   is listed here, and every command listed here is in the table, so neither can
   gain or lose a row alone.

The gateway takes no arguments and starts serving on stdin, so it has no ``--help``
to ask. For it, (1) is the whole check.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

# <root>/safe_agents/broker/tests/ -> parents[3] == repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOC = _REPO_ROOT / "docs" / "consuming-the-sdk.md"

_GATEWAY = "safe_agents.broker.gateway"

#: module -> the subcommands and flags the document publishes for it.
PUBLISHED_COMMANDS: dict[str, tuple[str, ...]] = {
    _GATEWAY: (),
    "safe_agents.broker.mcp.commands": (
        "snapshot",
        "show",
        "diff",
        "admit-propose",
        "admit-ratify",
        "admit-reject",
        "bulk-propose",
        "bulk-ratify",
    ),
    "safe_agents.broker.grants.commands": (
        "seed",
        "re-seed",
        "propose",
        "ratify",
        "reject",
        "acknowledge",
        "tighten",
    ),
    "safe_agents.broker.grants.audit_command": ("--sqlite", "--table", "--json"),
    "safe_agents.broker.approval.release_cli": ("intent_id", "--yes", "--json"),
    "safe_agents.broker.auditor.tape_cli": ("--path", "--s3-bucket", "--verify", "--json"),
}


def _help_text(module: str) -> str:
    completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [sys.executable, "-m", module, "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, (
        f"`python -m {module} --help` exited {completed.returncode}: {completed.stderr}"
    )
    return completed.stdout


@pytest.mark.parametrize("module", sorted(PUBLISHED_COMMANDS))
def test_published_module_is_runnable(module: str) -> None:
    spec = importlib.util.find_spec(module)
    assert spec is not None, f"published command module {module} does not exist"
    if spec.submodule_search_locations is not None:
        assert importlib.util.find_spec(f"{module}.__main__") is not None, (
            f"{module} is a package with no __main__, so `python -m {module}` cannot run"
        )


@pytest.mark.parametrize(
    "module", sorted(m for m, forms in PUBLISHED_COMMANDS.items() if forms)
)
def test_published_forms_are_accepted(module: str) -> None:
    text = _help_text(module)
    # Whole-token match: `propose` must not be satisfied by `admit-propose`.
    tokens = set(re.findall(r"[A-Za-z0-9_-]+", text))
    missing = [form for form in PUBLISHED_COMMANDS[module] if form not in tokens]
    assert not missing, f"`python -m {module}` no longer accepts {missing}"


def _documented() -> dict[str, str]:
    """The command table's rows: module -> the row's 'Published forms' cell."""
    rows: dict[str, str] = {}
    for line in _DOC.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\| `python -m (safe_agents\.[a-z_.]+)` \|.*\| (.*) \|$", line)
        if match:
            rows[match.group(1)] = match.group(2)
    return rows


@pytest.mark.skipif(not _DOC.exists(), reason="docs are not shipped in the wheel")
def test_document_and_code_agree() -> None:
    documented = _documented()
    assert set(documented) == set(PUBLISHED_COMMANDS), (
        "docs/consuming-the-sdk.md and PUBLISHED_COMMANDS name different commands: "
        f"only documented {sorted(set(documented) - set(PUBLISHED_COMMANDS))}, "
        f"only listed {sorted(set(PUBLISHED_COMMANDS) - set(documented))}"
    )
    for module, forms in PUBLISHED_COMMANDS.items():
        cell_forms = set(re.findall(r"`<?([A-Za-z0-9_-]+)", documented[module]))
        if module == _GATEWAY:
            continue
        assert cell_forms == set(forms), (
            f"{module}: the document publishes {sorted(cell_forms)}, "
            f"this file lists {sorted(forms)}"
        )
