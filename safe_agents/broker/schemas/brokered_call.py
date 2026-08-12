"""BrokeredCall schema — the typed envelope the PEP materializes from a tool call.

The PDP never sees free text. The manifest entry (effect/external/reversible) is
looked up from the static tool manifest in code, never from anything the model says.
See SCHEMAS.md §2 and broker/README.md §"The request → decision → audit flow".
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .common import Principal
from .evidence import ConfidenceArtifact


class ToolOp(BaseModel):
    """Static tool manifest entry — classifies each operation once, in code.

    The three fields (effect/external/reversible) drive most policy.
    They come from code so the model can't assert its 'send' is really a 'draft'.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    op: str
    # default-deny applies to 'write'
    effect: Literal["read", "write"]
    # does this op cross a trust boundary to an external party?
    external: bool
    # Is a wrong execution RECOVERABLE? True when a mistake is either literally undoable
    # (a discardable draft, a deletable event) OR structurally bounded so its blast radius
    # is small (e.g. a fixed, broker-held destination/amount the model cannot widen). False
    # only when a mistake is BOTH irreversible AND unbounded — a wire, an arbitrary external
    # send. This is the "high-blast?" fact the PDP keys on: reversible=False on an external
    # write → require_approval every call (rule 8); reversible≠False + untainted → allowable
    # autonomously (rules 6/10); a tainted turn requires approval regardless (rule 7). The
    # name is shorthand for "recoverable"; absent for reads (not applicable).
    reversible: bool | None = None
    # sa#137 — the name of the arg whose value egresses to an external provider (the
    # covert-exfil channel; e.g. "query" for search.query). Code-resident, never
    # model-supplied. When set, the PIP bounds that arg's UTF-8 byte length against
    # Envelope.max_query_bytes / query_egress_budget and the PEP meters cumulative
    # egress bytes. None (the default) = this op egresses no agent-composed argument.
    egress_arg: str | None = None


class Taint(BaseModel):
    """Source-based taint flag — propagated deterministically, never judged by the model.

    Data from untrusted sources (inbound email, web fetches, CRM free-text) is marked
    tainted at ingestion; the flag rides the turn. An external write in a tainted turn
    defaults to require_approval or deny. See broker/README.md §"Taint tracking".
    """

    model_config = ConfigDict(extra="forbid")

    tainted: bool
    # the untrusted ingestion sources that tainted this turn
    sources: list[str]


class Session(BaseModel):
    """Per-turn session metadata — feeds taint and audit."""

    model_config = ConfigDict(extra="forbid")

    turnId: str
    # untrusted sources touched this turn
    ingestedSources: list[str]


class BrokeredCall(BaseModel):
    """The typed request the PDP decides on.

    Materialized by the PEP from a raw tool call; the PDP never sees free text.
    """

    model_config = ConfigDict(extra="forbid")

    principal: Principal
    tool: str
    op: str
    # the model-supplied arguments (opaque; typed as Any — the PDP validates via manifest)
    args: Any
    # LOOKED UP from the static manifest, NOT model-supplied
    manifest: ToolOp
    # source-based, deterministic; rides the turn
    taint: Taint
    session: Session
    ts: str
    # The typed constructed-confidence artifact attached to this proposed action
    # (#184). Optional: None when the agent supplied none — meets_bar treats a
    # missing artifact as below-bar ONLY when a bar is configured, and the
    # error-budget draw treats it as error_prob=1.0 (the probability ceiling,
    # not an invented domain number) so omission can never dodge the budget.
    confidence: ConfidenceArtifact | None = None
