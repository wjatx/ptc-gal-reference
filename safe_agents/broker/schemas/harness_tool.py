"""harness_tool.py — the vocabulary a harness's own tool call is spelled in.

A coding harness has tools of its own (a shell, file reads and writes, a web
fetch) whose calls never become broker calls. The tool-event mouth records such
a call after it ran, and the decision mouth is asked about one before it runs
(`broker/GATEWAY.md` G21 on). Both spell the call in the two closed sets here.

A decision is made at one reserved coordinate: tool `harness-tool`, op
`<tool_class>/<locality>`, spelled as the tail of the source id
`harness:<harness>/<tool_class>/<locality>` so that one string names a class at
a locality everywhere. The coordinate's `ToolOp` facts are the consumer's own
declaration in the image-baked manifest's `tool_ops`. The base declares no
facts for any class.

Standard library only, and a leaf: the schemas validate a manifest's reserved
entries against it, and the runtime's report vocabulary (`runtime/observed.py`)
re-exports it, without either importing the other.
"""

from __future__ import annotations

from enum import Enum

#: The reserved `tool` of a harness's own tool call. A record of an observed
#: call carries it, and a decision request is decided at it. Never a connector:
#: the broker never runs a call at this coordinate, the harness does.
HARNESS_TOOL = "harness-tool"

#: Joins the tool class to the locality in a reserved coordinate's `op`.
COORDINATE_SEPARATOR = "/"


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


def member(name: str, enum: type[Enum], value: object) -> Enum:
    """The member of `enum` spelled exactly `value`, or ValueError naming `name`.

    Nothing is coerced: a value that is not a string is refused, not converted.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {value!r}")
    try:
        return enum(value)
    except ValueError:
        valid = ", ".join(item.value for item in enum)
        raise ValueError(f"{name} must be one of: {valid}; got {value!r}") from None


def coordinate_op(tool_class: object, locality: object) -> str:
    """The reserved coordinate's `op` for a class at a locality: `<class>/<locality>`.

    Raises ValueError when either is not a member of its closed set.
    """
    checked_class = member("tool_class", ToolClass, tool_class)
    checked_locality = member("locality", Locality, locality)
    return f"{checked_class.value}{COORDINATE_SEPARATOR}{checked_locality.value}"


def parse_coordinate_op(op: object) -> tuple[ToolClass, Locality]:
    """The class and locality a reserved coordinate's `op` names, or ValueError.

    The inverse of `coordinate_op`. Exactly one separator, each side exactly a
    member of its closed set. Anything else is refused.
    """
    if not isinstance(op, str):
        raise ValueError(f"a {HARNESS_TOOL} op must be a string, got {op!r}")
    tool_class, separator, locality = op.partition(COORDINATE_SEPARATOR)
    if not separator or COORDINATE_SEPARATOR in locality:
        raise ValueError(
            f"a {HARNESS_TOOL} op must be '<tool_class>{COORDINATE_SEPARATOR}<locality>', "
            f"got {op!r}"
        )
    return (
        member("tool_class", ToolClass, tool_class),  # type: ignore[return-value]
        member("locality", Locality, locality),  # type: ignore[return-value]
    )
