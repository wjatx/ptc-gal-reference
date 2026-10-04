"""The ceremony's blast class — derived from declared facts, never asserted.

One pure function, shared by ``propose`` (the maker) and ``ratify`` (the
checker): the class comes from the ToolOp the image-baked manifest declares for
the action class, raised by the in-force envelope's tighten-only ``high_blast``
overrides. Neither command accepts the class, or the facts behind it, as input.
"""

from __future__ import annotations

from typing import Collection, Iterable

from safe_agents.broker.schemas.brokered_call import ToolOp
from safe_agents.broker.schemas.evidence import BlastClass, effective_blast_class


class UndeclaredOperationError(LookupError):
    """The manifest's ``tool_ops`` does not classify the proposed action class."""


def ceremony_blast_class(
    action_class: str, tool_ops: Iterable[ToolOp], high_blast: Collection[str]
) -> BlastClass:
    """The blast class a promotion of ``action_class`` is proposed and ratified at.

    Finds the ToolOp whose ``tool.op`` IS ``action_class`` (the same key
    ``effective_blast_class`` matches overrides on) and returns its effective
    class under ``high_blast``. There is deliberately NO default and NO
    fallback: an operation the manifest does not declare has no facts to derive
    from, so it raises rather than being read as some class.
    """
    declared = [op for op in tool_ops if f"{op.tool}.{op.op}" == action_class]
    if len(declared) != 1:
        # AgentManifest rejects a duplicate (tool, op) at load; two entries can
        # still spell one "tool.op" (a dot inside a name), and two verdicts for
        # one action class are as unusable as none.
        found = "no entry" if not declared else f"{len(declared)} entries"
        raise UndeclaredOperationError(
            f"the manifest's tool_ops declares {found} for action class "
            f"{action_class!r}; the blast class is derived from that declaration "
            "and there is no default"
        )
    return effective_blast_class(declared[0], high_blast)
