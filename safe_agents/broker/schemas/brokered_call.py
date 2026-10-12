"""BrokeredCall schema — the typed envelope the PEP materializes from a tool call.

The PDP never sees free text. The manifest entry (effect/external/reversible) is
looked up from the static tool manifest in code, never from anything the model says.
See SCHEMAS.md §2 and broker/README.md §"The request → decision → audit flow".
"""

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .common import MAX_DECLARABLE_AGE_SECONDS, Principal
from .evidence import ConfidenceArtifact

# The one target spelling that means "a later run of the principal that caused it".
SELF_TARGET = "self"


class CausesContext(BaseModel):
    """An op's declaration that running it causes a context to exist (PTC-51, #177).

    Image-baked on a ``ToolOp`` in the manifest's ``tool_ops``, never read from a
    call's arguments. When the op runs, the broker writes an inheritance record
    for ``target`` before it calls the connector, and every turn ``target``'s
    runtime mints ingests the causing turn's sources from it
    (``broker/TAINT.md``). The declaration is the only switch: an op without one
    writes nothing.

    ``target`` is the literal ``"self"``, a deferred run of the principal whose
    manifest declares the op, or a child principal spelled in full. Nothing else
    is accepted, so a typo cannot name a principal nobody runs as.

    ``horizon_seconds`` fixes the record's ``notAfter`` when no sub-grant to the
    target exists at write time: ``issuedAt`` plus this many seconds. Required on
    every declaration, so every record's lifetime is known at load. When a
    sub-grant to a child target exists, its expiry is used instead
    (``safe_agents.broker.taint.inheritance.resolve_not_after``).
    """

    model_config = ConfigDict(extra="forbid")

    target: Literal["self"] | Principal
    horizon_seconds: StrictInt = Field(gt=0, le=MAX_DECLARABLE_AGE_SECONDS)

    @model_validator(mode="after")
    def _child_target_is_spelled_in_full(self) -> "CausesContext":
        """A child target names every part of a principal, with no padding.

        An empty or padded part names a principal no runtime authenticates as,
        so the record would land where nobody reads it and the child would start
        clean. Refuse it at load.
        """
        if isinstance(self.target, Principal):
            for part in ("agentId", "skill", "user"):
                value = getattr(self.target, part)
                if not value or value != value.strip():
                    raise ValueError(
                        f"causes_context.target.{part} = {value!r} must be non-empty with "
                        "no leading or trailing whitespace; a child target is a principal "
                        "spelled in full"
                    )
        return self


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
    # write → require_approval every call (rule external_irreversible); reversible≠False +
    # untainted → allowable autonomously (transform_to_safer_op / supervised_write_allow); a
    # tainted turn requires approval regardless (tainted_external_write). The name is
    # shorthand for "recoverable"; absent for reads (not applicable).
    reversible: bool | None = None
    # Read-gating — the name of the arg whose value egresses to an external provider (the
    # covert-exfil channel; e.g. "query" for search.query). Code-resident, never
    # model-supplied. When set, the PIP bounds that arg's UTF-8 byte length against
    # Envelope.max_query_bytes / query_egress_budget and the PEP meters cumulative
    # egress bytes. None (the default) = this op egresses no agent-composed argument.
    egress_arg: str | None = None
    # Destination — the name of the arg whose value says WHERE the request goes (an
    # address, a host, a path on another system; e.g. "url" for a fetch). Image-baked
    # like every other ToolOp fact, never model-supplied. It is inert unless the
    # deployment turns on Envelope.escalate_composed_destinations: then, on a tainted
    # turn, a call that supplies this arg is decided as an external write (PDP rule
    # tainted_composed_destination, broker/TAINT.md §6.1). None (the default) = the op
    # takes no destination the agent can choose, and the control never touches it.
    # No leading or trailing whitespace: a padded name is a typo for a key the connector
    # reads, and it would satisfy the manifest's "the knob needs a declaration" check
    # while holding nothing.
    destination_arg: str | None = Field(default=None, pattern=r"^\S(?:.*\S)?$")
    # Causes a context (PTC-51, #177) -- running this op creates a context that will act
    # later: a deferred run of this principal ("self") or a child principal. Image-baked
    # like every other ToolOp fact, honoured only from the manifest's tool_ops, never
    # from a call. When set, the broker writes an inheritance record keyed by the target
    # before the connector runs, and the target's turns start at least as tainted as the
    # turn that caused them (broker/TAINT.md). None (the default) = the op creates no
    # context the broker is told about, and nothing is written. It dumps as null when
    # unset, as destination_arg does.
    causes_context: CausesContext | None = None

    @field_validator("causes_context", mode="wrap")
    @classmethod
    def _name_the_entry(cls, value: Any, handler: Any, info: ValidationInfo) -> Any:
        """Refuse a malformed declaration with a message that names the entry.

        A pydantic location says ``tool_ops.3.causes_context``; the operator
        reading a refused manifest needs ``tool.op``.
        """
        try:
            return handler(value)
        except ValidationError as exc:
            entry = f"{info.data.get('tool', '?')}.{info.data.get('op', '?')}"
            details = "; ".join(
                f"{'.'.join(str(p) for p in err['loc']) or 'causes_context'}: {err['msg']}"
                for err in exc.errors()
            )
            raise ValueError(
                f"tool_ops entry {entry!r} has a malformed causes_context: {details}. "
                f"The target is the literal {SELF_TARGET!r} or a child principal "
                "spelled in full, and horizon_seconds is a positive whole number of "
                "seconds."
            ) from None


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
    #. Optional: None when the agent supplied none — meets_bar treats a
    # missing artifact as below-bar ONLY when a bar is configured, and the
    # error-budget draw treats it as error_prob=1.0 (the probability ceiling,
    # not an invented domain number) so omission can never dodge the budget.
    confidence: ConfidenceArtifact | None = None
