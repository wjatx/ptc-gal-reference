"""Conformance guard: every text-mode file open names its encoding.

Python 3.12 decodes a text file in the LOCALE's encoding when none is given. That
is UTF-8 on macOS and Linux and the ANSI code page (cp1252 for most testers) on
Windows, and this tree's manifests, specifications and docs are UTF-8 full of
em-dashes, arrows and ≠. Before this guard, running the suite under a Latin-1
locale on macOS (the nearest stand-in for Windows a Mac can run) failed or errored
237 tests. The failure is silent on the platforms we develop on, so only a check
that does not depend on the platform can hold the line.

An AST walk over the Python in the laptop path, flagging `open()`, `Path.open()`,
`read_text()`, `write_text()` and `os.fdopen()` calls in text mode with no
`encoding=` argument. Binary modes (any mode string containing "b") are exempt,
as are the stdlib openers that take no encoding (`os.open`, `tarfile.open`, ...).
A call whose mode is not a string literal is flagged: the walker cannot see
whether it is binary, and neither can a reader.

`ruff`'s PLW1514 covers part of this but is a preview rule, and it only resolves
`read_text` on receivers it can prove are `Path`s, which missed most of the sites
this guard found. Data-driven self-test below, in the house pattern of
`test_no_naive_datetime_conformance.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# safe_agents/broker/tests/<this>  parents[3] = repository root
REPO_ROOT = Path(__file__).resolve().parents[3]

# Every root whose Python runs on a tester's laptop: the package, its tests, the
# reliability library, the examples, the runner-contract stub and the scripts.
SCANNED_ROOTS = ("safe_agents", "reliability", "examples", "scripts", "agents")

_OPENERS_WITHOUT_ENCODING = {"os", "tarfile", "_tarfile", "zipfile", "gzip", "io", "webbrowser"}
_TEXT_IO_METHODS = {"read_text", "write_text", "open", "fdopen"}


def _mode_argument(call: ast.Call, name: str, is_builtin_open: bool) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "mode":
            return keyword.value
    if is_builtin_open and len(call.args) >= 2:
        return call.args[1]
    if name == "open" and not is_builtin_open and call.args:
        return call.args[0]  # Path.open(mode, ...)
    if name == "fdopen" and len(call.args) >= 2:
        return call.args[1]
    return None


def find_unspecified_encodings(tree: ast.AST, filename: str) -> list[str]:
    """Return one 'filename:line: message' string per text open with no encoding."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_builtin_open = isinstance(func, ast.Name) and func.id == "open"
        if is_builtin_open:
            name = "open"
        elif isinstance(func, ast.Attribute) and func.attr in _TEXT_IO_METHODS:
            name = func.attr
            if (
                name == "open"
                and isinstance(func.value, ast.Name)
                and func.value.id in _OPENERS_WITHOUT_ENCODING
            ):
                continue
        else:
            continue
        if any(keyword.arg in ("encoding", None) for keyword in node.keywords):
            continue  # explicit encoding, or **kwargs that may carry one
        if name == "read_text" and node.args:
            continue  # read_text(encoding) passed positionally
        if name == "write_text" and len(node.args) >= 2:
            continue
        mode = _mode_argument(node, name, is_builtin_open)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" in mode.value:
            continue
        violations.append(
            f"{filename}:{node.lineno}: {name}() in text mode with no encoding= "
            "(the default is the locale's, cp1252 on most Windows hosts)"
        )
    return violations


def _scanned_files() -> list[Path]:
    return [
        path
        for root in SCANNED_ROOTS
        for path in sorted((REPO_ROOT / root).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]


def test_every_text_open_names_its_encoding() -> None:
    violations: list[str] = []
    for path in _scanned_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(REPO_ROOT).as_posix()
        violations.extend(find_unspecified_encodings(tree, rel))
    assert violations == [], (
        "text-mode file I/O without an explicit encoding (add encoding=\"utf-8\"):\n"
        + "\n".join(violations)
    )


def test_the_scan_covers_the_package() -> None:
    """A guard that walked nothing would pass forever; make that visible."""
    assert len(_scanned_files()) > 300


FLAGGED = [
    ("builtin_open_default_mode", "open(p)\n"),
    ("builtin_open_text_mode", "open(p, 'w')\n"),
    ("path_open", "p.open()\n"),
    ("path_open_text_mode", "p.open('a')\n"),
    ("read_text", "p.read_text()\n"),
    ("write_text", "p.write_text(s)\n"),
    ("fdopen_text", "os.fdopen(fd, 'w')\n"),
    ("non_literal_mode", "open(p, mode)\n"),
]

ALLOWED = [
    ("builtin_open_utf8", "open(p, encoding='utf-8')\n"),
    ("builtin_open_binary", "open(p, 'rb')\n"),
    ("builtin_open_binary_keyword", "open(p, mode='ab')\n"),
    ("path_open_utf8", "p.open('w', encoding='utf-8')\n"),
    ("path_open_binary", "p.open('rb')\n"),
    ("read_text_utf8", "p.read_text(encoding='utf-8')\n"),
    ("read_text_positional", "p.read_text('utf-8')\n"),
    ("write_text_utf8", "p.write_text(s, encoding='utf-8')\n"),
    ("fdopen_binary", "os.fdopen(fd, 'wb')\n"),
    ("os_open", "os.open(p, os.O_RDONLY)\n"),
    ("tarfile_open", "tarfile.open(fileobj=b, mode='r:gz')\n"),
    ("kwargs_passthrough", "open(p, **kw)\n"),
]


@pytest.mark.parametrize(("label", "source"), FLAGGED, ids=[c[0] for c in FLAGGED])
def test_walker_flags(label: str, source: str) -> None:
    assert find_unspecified_encodings(ast.parse(source), label), label


@pytest.mark.parametrize(("label", "source"), ALLOWED, ids=[c[0] for c in ALLOWED])
def test_walker_allows(label: str, source: str) -> None:
    assert find_unspecified_encodings(ast.parse(source), label) == [], label
