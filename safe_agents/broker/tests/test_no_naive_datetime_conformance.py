"""Conformance guard (sa#213, class C): no naive-datetime construction
anywhere in base source.

An AST walk over every non-test .py file under safe_agents/, forbidding the
patterns that construct or normalize a datetime WITHOUT staying
timezone-aware:

  - datetime.now() / datetime.datetime.now() with no tz argument
  - datetime.utcnow() / datetime.datetime.utcnow() (always naive, no override
    possible)
  - datetime.today() / date.today() (always naive/local, no override possible)
  - bare .astimezone() with zero arguments (converts to the LOCAL system
    timezone — the exact footgun period_bucket_of avoids by always calling
    .astimezone(datetime.UTC) explicitly)
  - time.localtime / time.mktime / time.ctime references

This guard was pre-verified clean at write time (every clock read in the base
is tz-aware); it exists to keep it that way. It names no specific call site —
it walks ALL non-test source under safe_agents/, so a NEW naive-datetime call
anywhere trips it. Data-driven: one walker, a table of forbidden/allowed
snippets self-testing that the walker still catches what it claims to.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# safe_agents/broker/tests/test_no_naive_datetime_conformance.py
#   parents[0]=tests  [1]=broker  [2]=safe_agents
SAFE_AGENTS_ROOT = Path(__file__).resolve().parents[2]

_ALWAYS_NAIVE_METHODS = {"utcnow", "today"}
_TZ_ARG_KEYWORDS = {"tz", "timezone"}
_TIME_MODULE_FORBIDDEN_ATTRS = {"localtime", "mktime", "ctime"}


def _receiver_name(expr: ast.expr) -> str | None:
    """Best-effort name of the object hosting an attribute access.

    For `datetime.now()` (func=Attribute(attr='now', value=Name('datetime'))),
    returns 'datetime'. For `datetime.datetime.now()` (value is itself an
    Attribute with attr='datetime'), also returns 'datetime'. Anything else
    (a computed expression, subscript, call result, ...) returns None —
    conservatively not flagged, per the "prefer flagging where the receiver
    name is datetime/date" guidance for ambiguous cases.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def find_forbidden_datetime_patterns(tree: ast.AST, filename: str) -> list[str]:
    """Return one 'filename:line: message' string per forbidden pattern found."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method = node.func.attr
            receiver = _receiver_name(node.func.value)

            if method == "now" and receiver == "datetime":
                has_tz_arg = bool(node.args) or any(
                    kw.arg in _TZ_ARG_KEYWORDS for kw in node.keywords
                )
                if not has_tz_arg:
                    violations.append(
                        f"{filename}:{node.lineno}: datetime.now() with no tz "
                        "argument — returns a naive datetime"
                    )
                continue

            if method in _ALWAYS_NAIVE_METHODS and receiver in ("datetime", "date"):
                violations.append(
                    f"{filename}:{node.lineno}: {receiver}.{method}() always "
                    "returns a naive datetime/date"
                )
                continue

            if method == "astimezone" and not node.args and not node.keywords:
                violations.append(
                    f"{filename}:{node.lineno}: bare .astimezone() with no "
                    "argument converts to the LOCAL system timezone"
                )
                continue

        if isinstance(node, ast.Attribute) and node.attr in _TIME_MODULE_FORBIDDEN_ATTRS:
            if _receiver_name(node.value) == "time":
                violations.append(
                    f"{filename}:{node.lineno}: time.{node.attr} reference — "
                    "naive/local wall-clock API"
                )
    return violations


def _non_test_source_files() -> list[Path]:
    return [
        path
        for path in SAFE_AGENTS_ROOT.rglob("*.py")
        if "/tests/" not in path.as_posix() and path.name != "conftest.py"
    ]


class TestNoNaiveDatetimeConformance:
    """The guard: PASSES today (every clock read in base source is tz-aware)."""

    def test_no_forbidden_naive_datetime_pattern_in_base_source(self) -> None:
        all_violations: list[str] = []
        for path in _non_test_source_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            rel = path.relative_to(SAFE_AGENTS_ROOT.parent)
            all_violations.extend(find_forbidden_datetime_patterns(tree, str(rel)))
        assert all_violations == [], (
            "naive-datetime construction found in base source:\n"
            + "\n".join(all_violations)
        )


class TestWalkerSelfTest:
    """Feed the walker known snippets via ast.parse so it can't silently stop
    catching what it claims to forbid — and confirm the allowed forms it must
    NOT flag stay clean (a real call site written exactly this way exists in
    enforcement/store.py's period_bucket_of)."""

    FORBIDDEN_CASES = [
        ("datetime_datetime_now_no_tz", "import datetime\ndatetime.datetime.now()\n"),
        ("datetime_now_bare_no_tz", "from datetime import datetime\ndatetime.now()\n"),
        ("datetime_utcnow", "import datetime\ndatetime.datetime.utcnow()\n"),
        ("datetime_today", "import datetime\ndatetime.datetime.today()\n"),
        ("date_today", "from datetime import date\ndate.today()\n"),
        ("bare_astimezone_any_receiver", "x.astimezone()\n"),
        ("time_localtime", "import time\ntime.localtime()\n"),
        ("time_mktime_reference", "import time\ntime.mktime(x)\n"),
        ("time_ctime", "import time\ntime.ctime()\n"),
    ]

    ALLOWED_CASES = [
        ("now_with_tz_positional", "import datetime\ndatetime.datetime.now(datetime.UTC)\n"),
        ("now_with_tz_keyword", "import datetime\ndatetime.datetime.now(tz=datetime.UTC)\n"),
        ("astimezone_with_tz_arg", "x.astimezone(datetime.UTC)\n"),
        (
            "period_bucket_of_real_style",
            "moment.astimezone(datetime.UTC).strftime(fmt)\n",
        ),
    ]

    @pytest.mark.parametrize(("label", "source"), FORBIDDEN_CASES)
    def test_catches_forbidden_pattern(self, label: str, source: str) -> None:
        tree = ast.parse(source)
        violations = find_forbidden_datetime_patterns(tree, "snippet.py")
        assert violations, f"walker failed to catch {label!r}: {source!r}"

    @pytest.mark.parametrize(("label", "source"), ALLOWED_CASES)
    def test_does_not_flag_allowed_pattern(self, label: str, source: str) -> None:
        tree = ast.parse(source)
        violations = find_forbidden_datetime_patterns(tree, "snippet.py")
        assert violations == [], f"walker false-positived on {label!r}: {violations}"
