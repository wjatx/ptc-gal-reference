"""Decision schema — the five verbs, default-deny.

Output of the pure decide(call, facts) function. Modelled as a discriminated union
on the 'kind' field; exhaustive over exactly the five variants. See SCHEMAS.md §3.
"""

from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class RenderedIntent(BaseModel):
    """Reference to the materialized intent created on a require_approval decision.

    The broker persists these bytes as an Intent record (SCHEMAS.md §4) so the human
    approves the stored materializedRequest, not anything the agent re-sends.
    """

    model_config = ConfigDict(extra="forbid")

    # stable intent identifier; referenced by the approval flow and AuditRecord
    id: str
    # what the approval channel shows the human
    renderedForHuman: str


class Allow(BaseModel):
    """Execute the typed manifest op verbatim."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["allow"]


class Deny(BaseModel):
    """Refuse, with a reason."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["deny"]
    reason: str


class Transform(BaseModel):
    """Downgrade — the broker substitutes a safer op and executes that.

    As built, op substitution is the whole of the verb: `send → draft`, with `args`
    carried through byte-for-byte (`pdp/engine.py`, pinned by
    `test_pdp.py::test_transform_passes_args_through_byte_for_byte`). The base redacts
    no field and clamps no value. `spec/PTC-SPEC.md` §PTC-25 requires the argument half
    too and marks it NOT YET IMPLEMENTED here (tracking #358), so this is a gap against
    the spec rather than the whole of the verb (#273, #353).
    The agent does not get to re-issue the original.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["transform"]
    # the substituted operation
    op: str
    # the arguments the substituted op executes with; carried through verbatim today
    args: Any


class RequireApproval(BaseModel):
    """Hold for out-of-band human approval; the turn ends.

    The broker materializes and persists the intent; the agent cannot self-release.
    What-you-see-is-what-executes: the human approves the stored materializedRequest,
    not a summary the agent wrote. See broker/README.md §"Out-of-band approval".
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["require_approval"]
    renderedIntent: RenderedIntent
    # WHY the call was held, as the PDP rule that fired phrased it. Deny and
    # Abstain have always carried this; require_approval was the odd verb out, so
    # the reason survived only inside renderedForHuman's prose and the durable
    # AuditRecord read `reason: null` — the tape could show that a call was held
    # and not say what held it (#300).
    reason: str | None = None


class Abstain(BaseModel):
    """Decline as out-of-competence or inputs-suspect; optionally escalate.

    A first-class outcome, not a failure. escalate=True spends the attention/escalation
    budget, so it is itself rationed — an adversary can DoS this channel.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["abstain"]
    # escalate=True spends the escalation budget; rationed
    escalate: bool
    reason: str


# Discriminated union over exactly the five verbs — exhaustive, no open string union.
Decision = Annotated[
    Union[Allow, Deny, Transform, RequireApproval, Abstain],
    Field(discriminator="kind"),
]
