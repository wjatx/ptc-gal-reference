"""observed.py — the vocabulary of a tool event a harness reports.

A coding harness has tools of its own (a shell, file reads and writes, a web
fetch) whose calls never become broker calls. Its hooks can report each one
after it ran. The broker records such a report and lets a reported read taint
the session turn (`broker/GATEWAY.md`, the tool-event mouth; `broker/TAINT.md`
§2). It decides nothing about the call: the call has already happened.

A harness's hook can also ask before a call runs. That request is decided at
the reserved coordinate `harness-tool`, op `<tool_class>/<locality>`
(`schemas/harness_tool.py`), and is spelled in the same vocabulary plus two
digests: the call's input as the adapter serialized it, and the harness's own
call id. `DecisionRequest` is that request, checked.

This module is the vocabulary a report or a request is spelled in, and the
check that one is spelled in it. It holds no runtime state, so a mouth can
refuse a malformed body before it enters the runtime, and the runtime
re-checks every field itself (`BrokerRuntime.record_observed_event`), because a
mouth is not trusted to have checked. The two closed sets, the reserved tool
name and the coordinate spelling live in `schemas/harness_tool.py`, a leaf the
manifest schema can import, and are re-exported here.

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

from safe_agents.broker.schemas.harness_tool import (
    COORDINATE_SEPARATOR,
    HARNESS_TOOL,
    Locality,
    ToolClass,
    coordinate_op,
    member,
    parse_coordinate_op,
)

__all__ = [
    "COORDINATE_SEPARATOR",
    "DIGEST",
    "DecisionRequest",
    "HARNESS_SOURCE_PREFIX",
    "HARNESS_TOOL",
    "Locality",
    "ObservedEvent",
    "SHORT_CODE",
    "TAINTING_CLASSES",
    "ToolClass",
    "coordinate_op",
    "digest_subject",
    "parse_coordinate_op",
    "validate_decision_request",
    "validate_observed_event",
]

#: The shape of a mouth code, a harness code and a refusal-cause code: the only
#: short strings a mouth supplies that reach the tape. A caller-authored value
#: cannot be spelled in this alphabet at this length by accident.
SHORT_CODE = re.compile(r"[a-z][a-z0-9_-]{0,39}")

#: The one digest form a report may carry: `sha256:` and 64 lowercase hex digits.
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

#: The family every reported source id belongs to (`broker/TAINT.md` §1).
HARNESS_SOURCE_PREFIX = "harness:"


#: The classes whose report taints the session turn: each one brings content
#: into the agent's context. A shell command can read too, but its class says
#: nothing about whether it did, and that is the harness's to classify
#: (`broker/GATEWAY.md`, Known limits).
TAINTING_CLASSES: frozenset[ToolClass] = frozenset(
    {ToolClass.FILE_READ, ToolClass.WEB_FETCH, ToolClass.WEB_SEARCH}
)


def _source_id(harness: str, tool_class: ToolClass, locality: Locality) -> str:
    """`harness:<harness>/<class>/<locality>`: the coordinate's op, prefixed by the harness."""
    return f"{HARNESS_SOURCE_PREFIX}{harness}/{coordinate_op(tool_class, locality)}"


@dataclass(frozen=True)
class ObservedEvent:
    """One report, every field checked against its vocabulary."""

    mouth: str
    harness: str
    tool_class: ToolClass
    locality: Locality
    subject_digest: str
    result_digest: str | None = None
    #: The harness's own id for the call, digested, so this report pairs with the
    #: decision asked before the call ran. None when the report carries none.
    call_digest: str | None = None

    @property
    def source_id(self) -> str:
        """The source this report ingests: `harness:<harness>/<class>/<locality>`.

        Built from codes alone, so a consumer's `trusted_read_sources` can trust
        a class of read without ever seeing a path.
        """
        return _source_id(self.harness, self.tool_class, self.locality)

    @property
    def taints(self) -> bool:
        return self.tool_class in TAINTING_CLASSES


@dataclass(frozen=True)
class DecisionRequest:
    """One request to decide a harness's own tool call before it runs, checked.

    Every field is a code, a member of a closed set, or a digest. `input_digest`
    covers the full tool input as the adapter serialized it; it becomes the
    decided call's `argsDigest` and binds the release of a hold. `call_digest`
    is the harness's own id for the call, digested, so the decision and the
    post-call report pair on the tape without a harness identifier in the clear.
    """

    mouth: str
    harness: str
    tool_class: ToolClass
    locality: Locality
    subject_digest: str
    input_digest: str
    call_digest: str

    @property
    def op(self) -> str:
        """The reserved coordinate's op this request is decided at."""
        return coordinate_op(self.tool_class, self.locality)

    @property
    def source_id(self) -> str:
        """The source a permit of a tainting class ingests (`ObservedEvent.source_id`)."""
        return _source_id(self.harness, self.tool_class, self.locality)

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


def validate_observed_event(
    *,
    mouth: object,
    harness: object,
    tool_class: object,
    locality: object,
    subject_digest: object,
    result_digest: object = None,
    call_digest: object = None,
) -> ObservedEvent:
    """Check every field against its vocabulary, or raise ValueError.

    Nothing is coerced. A value of the wrong type is refused rather than
    converted, so what reaches the tape is exactly what was checked.
    """
    return ObservedEvent(
        mouth=_code("mouth", mouth),
        harness=_code("harness", harness),
        tool_class=member("tool_class", ToolClass, tool_class),  # type: ignore[arg-type]
        locality=member("locality", Locality, locality),  # type: ignore[arg-type]
        subject_digest=_digest("subject_digest", subject_digest),
        result_digest=None if result_digest is None else _digest("result_digest", result_digest),
        call_digest=None if call_digest is None else _digest("call_digest", call_digest),
    )


def validate_decision_request(
    *,
    mouth: object,
    harness: object,
    tool_class: object,
    locality: object,
    subject_digest: object,
    input_digest: object,
    call_digest: object,
) -> DecisionRequest:
    """Check every field of a decision request against its vocabulary, or raise ValueError.

    The same checks as `validate_observed_event`, and both digests are required:
    a request that cannot bind its input or pair with its report is malformed.
    Nothing is coerced.
    """
    return DecisionRequest(
        mouth=_code("mouth", mouth),
        harness=_code("harness", harness),
        tool_class=member("tool_class", ToolClass, tool_class),  # type: ignore[arg-type]
        locality=member("locality", Locality, locality),  # type: ignore[arg-type]
        subject_digest=_digest("subject_digest", subject_digest),
        input_digest=_digest("input_digest", input_digest),
        call_digest=_digest("call_digest", call_digest),
    )


def digest_subject(subject: str) -> str:
    """The digest a report carries for a subject: SHA-256 over its UTF-8 bytes.

    A harness adapter computes this from the path or URL it saw; a reader who
    has a candidate path computes it again and compares. The two match only
    when both spell the subject the same way, which is the adapter's to state.
    """
    return "sha256:" + hashlib.sha256(subject.encode("utf-8")).hexdigest()
