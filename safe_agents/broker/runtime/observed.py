"""observed.py — the vocabulary of a tool event a harness reports.

A coding harness has tools of its own (a shell, file reads and writes, a web
fetch) whose calls never become broker calls. Its hooks can report each one
after it ran. The broker records such a report and lets a reported read taint
the session turn (`broker/GATEWAY.md`, the tool-event mouth; `broker/TAINT.md`
§2). It decides nothing about the call: the call has already happened.

This module is the vocabulary a report is spelled in, and the check that a
report is spelled in it. Standard library only, so a mouth can refuse a
malformed report before it enters the runtime, and the runtime re-checks every
field itself (`BrokerRuntime.record_observed_event`), because a mouth is not
trusted to have checked.

What a report may carry is deliberately narrow: two short codes in a bounded
alphabet (which mouth, which harness), one member each of two closed enums
(what kind of tool, where its subject was), and digests. The harness code is
NOT a closed set: any code so spelled is accepted, and only a consumer's
`trusted_read_sources` gives one meaning. A path, a URL, a command line or any
content is not accepted in any field: the only bytes a reporter chooses freely
are a code's letters and digits and a digest's hex.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum

#: The shape of a mouth code, a harness code and a refusal-cause code: the only
#: short strings a mouth supplies that reach the tape. A caller-authored value
#: cannot be spelled in this alphabet at this length by accident.
SHORT_CODE = re.compile(r"[a-z][a-z0-9_-]{0,39}")

#: The one digest form a report may carry: `sha256:` and 64 lowercase hex digits.
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

#: The family every reported source id belongs to (`broker/TAINT.md` §1).
HARNESS_SOURCE_PREFIX = "harness:"


class ToolClass(str, Enum):
    """What kind of built-in tool the harness ran, as its adapter classified it."""

    FILE_READ = "file-read"
    FILE_WRITE = "file-write"
    FILE_EDIT = "file-edit"
    SHELL = "shell"
    WEB_FETCH = "web-fetch"
    WEB_SEARCH = "web-search"
    OTHER = "other"


class Locality(str, Enum):
    """Where the call's subject was, as the harness's adapter classified it."""

    PROJECT = "project"
    HOME = "home"
    OUTSIDE = "outside"
    REMOTE = "remote"
    UNKNOWN = "unknown"


#: The classes whose report taints the session turn: each one brings content
#: into the agent's context. A shell command can read too, but its class says
#: nothing about whether it did, and that is the harness's to classify
#: (`broker/GATEWAY.md`, Known limits).
TAINTING_CLASSES: frozenset[ToolClass] = frozenset(
    {ToolClass.FILE_READ, ToolClass.WEB_FETCH, ToolClass.WEB_SEARCH}
)


@dataclass(frozen=True)
class ObservedEvent:
    """One report, every field checked against its vocabulary."""

    mouth: str
    harness: str
    tool_class: ToolClass
    locality: Locality
    subject_digest: str
    result_digest: str | None = None

    @property
    def source_id(self) -> str:
        """The source this report ingests: `harness:<harness>/<class>/<locality>`.

        Built from codes alone, so a consumer's `trusted_read_sources` can trust
        a class of read without ever seeing a path.
        """
        return (
            f"{HARNESS_SOURCE_PREFIX}{self.harness}/"
            f"{self.tool_class.value}/{self.locality.value}"
        )

    @property
    def taints(self) -> bool:
        return self.tool_class in TAINTING_CLASSES


def _code(name: str, value: object) -> str:
    if not isinstance(value, str) or not SHORT_CODE.fullmatch(value):
        raise ValueError(f"{name} must be a short lowercase code, got {value!r}")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(
            f"{name} must be 'sha256:' and 64 lowercase hex digits, got {value!r}"
        )
    return value


def _member(name: str, enum: type[Enum], value: object) -> Enum:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {value!r}")
    try:
        return enum(value)
    except ValueError:
        valid = ", ".join(member.value for member in enum)
        raise ValueError(f"{name} must be one of: {valid}; got {value!r}") from None


def validate_observed_event(
    *,
    mouth: object,
    harness: object,
    tool_class: object,
    locality: object,
    subject_digest: object,
    result_digest: object = None,
) -> ObservedEvent:
    """Check every field against its vocabulary, or raise ValueError.

    Nothing is coerced. A value of the wrong type is refused rather than
    converted, so what reaches the tape is exactly what was checked.
    """
    return ObservedEvent(
        mouth=_code("mouth", mouth),
        harness=_code("harness", harness),
        tool_class=_member("tool_class", ToolClass, tool_class),  # type: ignore[arg-type]
        locality=_member("locality", Locality, locality),  # type: ignore[arg-type]
        subject_digest=_digest("subject_digest", subject_digest),
        result_digest=None if result_digest is None else _digest("result_digest", result_digest),
    )


def digest_subject(subject: str) -> str:
    """The digest a report carries for a subject: SHA-256 over its UTF-8 bytes.

    A harness adapter computes this from the path or URL it saw; a reader who
    has a candidate path computes it again and compares. The two match only
    when both spell the subject the same way, which is the adapter's to state.
    """
    return "sha256:" + hashlib.sha256(subject.encode("utf-8")).hexdigest()
