"""Supporting types for the approval layer.

These are internal types for broker.approval — not canonical schemas.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class ApprovalResult:
    """Return value from materialize() — what the broker sends back to the agent.

    The turn ENDS after the broker returns this. The agent holds no tool that can
    approve or release the intent or change what will execute at approval time.
    """

    # "pending" — a new Intent was held. "coalesced" — an identical pending
    # Intent already existed (dedup on); this call de-amplified onto it, no new
    # hold or notification was created. Both return the intent_id the human acts on.
    status: Literal["pending", "coalesced"]
    intent_id: str


@dataclass
class NotifierEvent:
    """Event emitted to the notifier hook when a pending Intent is created.

    This is the event contract for the approval notification path. Channel-specific
    delivery (email, Slack, webhook) belongs in channels/, not here. The broker emits
    this; the injected notifier callable handles forwarding to whatever channel the
    deployment configures.

    renderedForHuman is broker-rendered from the typed BrokeredCall (via the PDP's
    RequireApproval decision) — the agent never supplies it.
    """

    intent_id: str
    rendered_for_human: str
    expiry: str  # ISO-8601 UTC
    ts: str      # ISO-8601 UTC when the intent was created


@dataclass(frozen=True)
class IntentView:
    """Read-only description of a held Intent, for an approver to look at.

    The WYSIWYE half that is not execution: before releasing a held call a human
    has to SEE it, and every approval surface — the channels owner-adapter, the
    local `example-wrapper approve` — needs the same fields. Returned by
    ``BrokerRuntime.describe_intent``.

    What it deliberately does NOT carry is the raw ``args``. ``renderedForHuman``
    is the broker-rendered text the approval path is designed around (the agent
    never supplies it), and ``args_digest`` ties that render to the exact stored
    bytes without turning an approval prompt into a place secrets get printed —
    the same discipline that keeps raw args off the audit tape.

    Frozen because a view that could be edited between the render and the release
    would reopen precisely the gap WYSIWYE closes.
    """

    intent_id: str
    status: Literal[
        "pending", "approved", "rejected", "expired", "executed", "refused", "permitted"
    ]
    tool: str
    op: str
    args_digest: str
    rendered_for_human: str
    expiry: str  # ISO-8601 UTC
    ts: str      # ISO-8601 UTC
    agent_id: str
    approved_by: str | None = None
    # The held input digest of a harness tool call held at `harness-tool` (#168):
    # what an approval surface digests the reporter's view of the input to, and
    # what approve_intent's `shown_input_digest` is checked against. None for
    # every other intent.
    input_digest: str | None = None


@dataclass
class ExecutionResult:
    """Return value from approve() — outcome of executing the materialized intent."""

    intent_id: str
    # True when the stored materializedRequest was executed.
    executed: bool
    # Result returned by the executor callback (None if no executor or if rejected).
    result: Any = None
    # Why execution was refused (e.g., "intent expired", "intent not found").
    # Present only when executed=False.
    rejection_reason: str | None = None
    # True only when THIS call moved the intent from pending to expired (#163). The
    # transition is a compare-and-set, so across every late approve, late reject and
    # sweep exactly one caller sees True, and that caller writes the expiry record.
    expired_by_this_call: bool = False
    # True only when an approval of a held harness tool call landed (#168): the
    # intent is now approved, the broker executed nothing, and the harness's next
    # request for the same call will be evaluated again and permitted once.
    approved_for_reissue: bool = False
