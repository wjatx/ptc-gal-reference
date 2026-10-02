"""A small shell reader for test_pinned_fetches.py: text in, pipelines of stages out.

It exists so the fetch rules can ask structural questions ("where does this curl's
output go?", "which command does this pipe feed?") instead of pattern-matching a
line, which answers wrongly in both directions: `dnf install -y curl` is not a
download, and `sh -c "$(curl ...)"` is one. It understands quoting, `$(...)`,
backticks, `<(...)`, pipes, `;`/`&&`/`||` and redirections. It is not a shell
grammar. Keywords are ordinary words, a here-document body is read as commands, and
nothing is expanded. It never raises on odd input and always makes progress.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

Pipeline = list["Stage"]


@dataclass
class Stage:
    """One command of a pipeline."""

    words: list[str] = field(default_factory=list)
    #: Where stdout was redirected (`> file`), or None. `>&2` and `2>` are not stdout files.
    stdout_to: str | None = None
    #: Nested command (`$(...)`, backticks) and process (`<(...)`) substitutions.
    subs: list[tuple[str, list[Pipeline]]] = field(default_factory=list)


_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"})
#: Commands that run another command, with the flags of theirs that take a value.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"}),
    "$SUDO": frozenset(),
    "${SUDO}": frozenset(),
    "env": frozenset({"-u", "-C", "-S"}),
    "exec": frozenset({"-a"}),
    "command": frozenset(),
    "nohup": frozenset(),
    "nice": frozenset({"-n"}),
}


def basename(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def argv(stage: Stage) -> list[str]:
    """The stage's words from the command word on: leading keywords, `VAR=value`
    assignments and known wrappers (sudo, env, exec, ...) are dropped. A wrapper this
    does not know (a script's own function, `runuser`) is returned as the command."""
    words, i = stage.words, 0
    while i < len(words):
        word = words[i]
        if word in _KEYWORDS or _ASSIGNMENT.match(word):
            i += 1
        elif word in _WRAPPERS:
            valued = _WRAPPERS[word]
            i += 1
            while i < len(words) and (words[i].startswith("-") or _ASSIGNMENT.match(words[i])):
                i += 2 if words[i] in valued else 1
        else:
            break
    return words[i:]


def walk(pipelines: list[Pipeline]):
    """Every stage, nested substitutions included."""
    for pipeline in pipelines:
        for stage in pipeline:
            yield stage
            for _kind, inner in stage.subs:
                yield from walk(inner)


def parse(text: str) -> list[Pipeline]:
    return _Reader(text).script(closer=None)


class _Reader:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self._closers: list[str | None] = []

    def _closing_backtick(self) -> bool:
        return bool(self._closers) and self._closers[-1] == "`"

    def script(self, closer: str | None) -> list[Pipeline]:
        self._closers.append(closer)
        try:
            return self._script(closer)
        finally:
            self._closers.pop()

    def _script(self, closer: str | None) -> list[Pipeline]:
        s = self.s
        pipelines: list[Pipeline] = []
        pipeline: Pipeline = []
        stage = Stage()
        depth = 0

        def end_stage() -> None:
            nonlocal stage
            if stage.words or stage.subs or stage.stdout_to is not None:
                pipeline.append(stage)
            stage = Stage()

        def end_pipeline() -> None:
            nonlocal pipeline
            end_stage()
            if pipeline:
                pipelines.append(pipeline)
            pipeline = []

        while self.i < len(s):
            c = s[self.i]
            if c == "`" and closer == "`":
                self.i += 1
                break
            if c in " \t":
                self.i += 1
            elif c == "#":
                end = s.find("\n", self.i)
                self.i = len(s) if end < 0 else end
            elif c in "\n;":
                self.i += 1
                end_pipeline()
            elif c == "&":
                if s.startswith("&>", self.i):
                    self.i += 3 if s.startswith("&>>", self.i) else 2
                    stage.stdout_to = self._target(stage)
                else:
                    self.i += 2 if s.startswith("&&", self.i) else 1
                    end_pipeline()
            elif c == "|":
                if s.startswith("||", self.i):
                    self.i += 2
                    end_pipeline()
                else:
                    self.i += 2 if s.startswith("|&", self.i) else 1
                    end_stage()
            elif c == "(":
                self.i += 1
                depth += 1
                end_pipeline()
            elif c == ")":
                self.i += 1
                if depth == 0 and closer == ")":
                    break
                depth = max(0, depth - 1)
                end_pipeline()
            elif c in "<>" and not s.startswith(("<(", ">("), self.i):
                self._redirect(stage, fd=None)
            else:
                word = self._word(stage)
                at_redirect = self.i < len(s) and s[self.i] in "<>" and not s.startswith(("<(", ">("), self.i)
                if word.isdigit() and at_redirect:
                    self._redirect(stage, fd=word)
                else:
                    stage.words.append(word)
        end_pipeline()
        return pipelines

    def _target(self, stage: Stage) -> str:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        return self._word(stage)

    def _redirect(self, stage: Stage, fd: str | None) -> None:
        s = self.s
        op = next(op for op in ("<<<", "<<-", "<<", "<&", "<", ">>", ">&", ">|", ">") if s.startswith(op, self.i))
        self.i += len(op)
        target = self._target(stage)
        if not op.startswith(">") or fd not in (None, "1"):
            return
        if op == ">&" and (target.isdigit() or target == "-"):
            return
        stage.stdout_to = target

    def _substitution(self, stage: Stage, kind: str, closer: str, skip: int) -> str:
        self.i += skip
        stage.subs.append((kind, self.script(closer)))
        return "<()" if kind == "proc" else "$()"

    def _dollar(self, stage: Stage) -> str | None:
        """Consume `$((..))`, `$(..)` or `${..}` at the cursor; None if it is none of them."""
        s = self.s
        if s.startswith("$((", self.i) or s.startswith("${", self.i):
            close = "))" if s.startswith("$((", self.i) else "}"
            end = s.find(close, self.i)
            end = len(s) if end < 0 else end + len(close)
            text, self.i = s[self.i:end], end
            return text
        if s.startswith("$(", self.i):
            return self._substitution(stage, "cmd", ")", skip=2)
        return None

    def _word(self, stage: Stage) -> str:
        s = self.s
        out: list[str] = []
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\n;&|)" or (c == "`" and self._closing_backtick()):
                break
            if c in "<>":
                if not s.startswith(("<(", ">("), self.i):
                    break
                out.append(self._substitution(stage, "proc", ")", skip=2))
            elif c == "(":
                if not (out and s.startswith("()", self.i)):
                    break
                out.append("()")  # a function definition: `name() {`
                self.i += 2
            elif c == "\\":
                out.append(s[self.i + 1:self.i + 2])
                self.i += 2
            elif c == "'":
                end = s.find("'", self.i + 1)
                end = len(s) if end < 0 else end
                out.append(s[self.i + 1:end])
                self.i = end + 1
            elif c == '"':
                self.i += 1
                self._double_quoted(stage, out)
            elif c == "`":
                out.append(self._substitution(stage, "cmd", "`", skip=1))
            elif c == "$" and (text := self._dollar(stage)) is not None:
                out.append(text)
            else:
                out.append(c)
                self.i += 1
        return "".join(out)

    def _double_quoted(self, stage: Stage, out: list[str]) -> None:
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "`" and self._closing_backtick():
                return
            if c == "\\":
                out.append(s[self.i + 1:self.i + 2])
                self.i += 2
            elif c == "`":
                out.append(self._substitution(stage, "cmd", "`", skip=1))
            elif c == "$" and (text := self._dollar(stage)) is not None:
                out.append(text)
            else:
                out.append(c)
                self.i += 1
