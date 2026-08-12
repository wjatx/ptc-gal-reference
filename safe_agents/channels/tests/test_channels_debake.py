"""test_channels_debake.py — the sa#139 no-base-literals invariant, for channels.

sa#176 adds ``owner.py``, a *transport-generic* base adapter (the human-as-owner
channel). Transport-generic is the whole point: which concrete transport an owner
speaks — Telegram, Slack, a bot token, a chat id — is CONSUMER config carried in a
manifest, never a literal in the base package. This guard keeps that real, mirroring
``broker/tests/test_broker_debake.py``'s ``TestDebakeGuard`` (grep-guard: prove the
literal is GONE, not merely that tests are green) and the sibling
``test_consumer_boundary.py`` (AST walk to kill text-parsing fragility).

Why an AST walk and not a raw line-regex:
    The broker guard tolerates a class NAME in prose while forbidding the wiring
    form ``Foo(`` — a mention is not a binding. Channels has the same shape: the
    transport-agnostic ``InboundAdapter`` docstring illustrates a channel with
    ``"telegram"``, and "inbound signal" is generic English prose throughout the
    docstrings/comments. Those are mentions, not consumer bindings. So we scan only
    the AST's *non-docstring string literals* and *identifiers* — a real binding (a
    string value, a dict key, an identifier like ``chat_id``) — and skip docstrings
    (excluded explicitly) and comments (never in the AST). Import module names are
    NOT scanned, so the stdlib ``signal`` module could never false-trip the guard.

AWS-free: pure source parsing.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

import safe_agents.channels as channels_pkg

# <root>/safe_agents/channels/tests/  ->  the channels package dir
_CHANNELS_DIR = Path(channels_pkg.__file__).parent
_REPO_ROOT = _CHANNELS_DIR.parents[1]


# Consumer TRANSPORT fields/names + consumer IDENTITY strings that would never
# legitimately be a base binding. Matched case-insensitively (re.search) against
# extracted identifiers / non-docstring string literals — NOT whole source lines.
FORBIDDEN: list[tuple[str, str]] = [
    (r"telegram", "Telegram is a consumer transport, not a base binding"),
    (r"chat_id", "a chat_id is a consumer-transport field"),
    (r"bot_token", "a bot_token is a consumer-transport credential field"),
    (r"slack", "Slack is a consumer transport, not a base binding"),
    (r"discord", "Discord is a consumer transport, not a base binding"),
    (r"whatsapp", "WhatsApp is a consumer transport, not a base binding"),
    (r"signal", "Signal is a consumer transport, not a base binding"),
    (r"example-agent", "a consumer identity must never be a base literal"),
    (r"advisor", "a consumer identity must never be a base literal"),
    (r"missileer", "a consumer identity must never be a base literal"),
]


def _base_sources() -> Iterator[Path]:
    """Every base ``.py`` under the channels package — excluding ``tests/``.

    ``screens/`` (the sanctioned Bedrock reference classifier) is deliberately NOT
    excluded: the forbidden list names consumer transports/identities, none of which
    the reference screen legitimately mentions, so it cannot false-positive here.
    """
    for py in sorted(_CHANNELS_DIR.rglob("*.py")):
        if "tests" in py.parts:
            continue
        yield py


def _scannable_texts(source: str) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, text)`` for each identifier / non-docstring string literal.

    Docstrings (module/class/function) are excluded by identity; comments never enter
    the AST; import module names are not scanned. What remains is exactly the set of
    *bindings* — the only place a consumer literal could actually live.
    """
    tree = ast.parse(source)

    docstring_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstring_ids.add(id(body[0].value))

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", -1)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstring_ids:
                yield lineno, node.value
        elif isinstance(node, ast.Name):
            yield lineno, node.id
        elif isinstance(node, ast.arg):
            yield lineno, node.arg
        elif isinstance(node, ast.Attribute):
            yield lineno, node.attr
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield lineno, node.arg
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield lineno, node.name


def _hits(source: str) -> list[tuple[int, str, str, str]]:
    """``(lineno, text, pattern, reason)`` for every forbidden match (empty == clean)."""
    out: list[tuple[int, str, str, str]] = []
    for lineno, text in _scannable_texts(source):
        for pattern, reason in FORBIDDEN:
            if re.search(pattern, text, re.IGNORECASE):
                out.append((lineno, text, pattern, reason))
    return out


# ---------------------------------------------------------------------------
# 1. The invariant — no consumer transport/identity literal in channels base source
# ---------------------------------------------------------------------------

class TestChannelsDebakeGuard:
    """The deterministic exit predicate: a transport/identity literal is GONE from the
    channels base package, not merely unused. Green here means the base stays
    transport-agnostic — every concrete channel binding lives in a consumer manifest."""

    def test_no_consumer_literal_in_base_source(self) -> None:
        offenders: list[str] = []
        for py in _base_sources():
            rel = py.relative_to(_REPO_ROOT)
            for lineno, text, pattern, reason in _hits(py.read_text()):
                offenders.append(
                    f"  {rel}:{lineno}: {text!r} matches {pattern!r} ({reason})"
                )
        assert not offenders, (
            "consumer transport/identity literal re-accreted in channels BASE source "
            "— it belongs in a consumer manifest, not the base package:\n"
            + "\n".join(offenders)
        )


# ---------------------------------------------------------------------------
# 2. Teeth — the guard actually fires, so green means "clean", not "scanned nothing"
# ---------------------------------------------------------------------------

class TestChannelsDebakeGuardHasTeeth:
    # Real BINDING shapes — each MUST be flagged: identifier target, string value,
    # dict key, and a hyphenated identity string.
    BINDING_PROBES = [
        ('chat_id = "12345"', "chat_id"),
        ('channel_type = "telegram"', "telegram"),
        ('adapters = {"slack": build()}', "slack"),
        ('token = bot_token', "bot_token"),
        ('WEBHOOK = "discord"', "discord"),
        ('principal = "example-agent"', "example-agent"),
    ]

    @pytest.mark.parametrize("probe,token", BINDING_PROBES)
    def test_binding_is_flagged(self, probe: str, token: str) -> None:
        hits = _hits(probe + "\n")
        assert hits, (
            f"channels debake guard is toothless — binding {probe!r} was NOT flagged; "
            "a real consumer literal in base source would slip through"
        )
        assert any(token in text for _, text, _, _ in hits)

    # Prose that legitimately appears in current base source MUST NOT be flagged —
    # these mirror the exact shapes present today (a transport-agnostic ABC docstring
    # illustrating "telegram"; "inbound signal" in a docstring; a signal comment).
    CLEAN_PROBES = [
        '"""One inbound adapter per channel (\'telegram\', \'peer-agent\')."""',
        'def handle():\n    """A record of a dropped inbound signal."""\n    return 1',
        'x = 1  # only POST carries an inbound signal',
    ]

    @pytest.mark.parametrize("probe", CLEAN_PROBES)
    def test_prose_mention_is_not_flagged(self, probe: str) -> None:
        assert _hits(probe + "\n") == [], (
            "guard false-positives on a docstring/comment mention — it would flag the "
            "transport-agnostic ADAPTERS docstring and every 'inbound signal' in prose"
        )
