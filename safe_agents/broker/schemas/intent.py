"""Intent schema — durable "draft and hold" record.

When the PDP returns require_approval, the broker immediately materializes and persists
this record; the agent's turn ends. Execution happens only if a human approves through
a path authenticated to them, not the agent. See SCHEMAS.md §4.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from .brokered_call import BrokeredCall


class Intent(BaseModel):
    """Durable record of a require_approval decision.

    The load-bearing field is materializedRequest: written once at intent creation and
    never re-derived from anything the agent says after that point. The human approves
    these bytes. A compromised agent could stage a benign renderedForHuman summary over
    a malicious payload; the broker ignores the render at execution time and runs the
    stored call verbatim.
    """

    model_config = ConfigDict(extra="forbid")

    # stable identifier; referenced by the approval flow and AuditRecord
    id: str
    # FROZEN BrokeredCall the broker executes verbatim on approval — never re-derived
    materializedRequest: BrokeredCall
    # what-you-see: human-readable render pushed to the approval channel
    renderedForHuman: str
    # terminal states: rejected, expired, executed, refused
    # "refused" (#9) is the release-side terminal: a human ratified the hold, and
    # revalidating current authority at release time then refused (grant revoked or
    # demoted, per-op budget exhausted). Distinct from "rejected" (the human said no)
    # and from "approved" (the release reached the connector and it failed).
    status: Literal["pending", "approved", "rejected", "expired", "executed", "refused"]
    # hard TTL; unapproved intents auto-deny at this timestamp (ISO-8601 UTC)
    expiry: str
    # the authenticated human identity that approved; absent until approval
    approvedBy: str | None = None
    # when this intent was created
    ts: str
    # when this intent actually EXECUTED (ISO-8601 UTC); absent until the approved→
    # executed transition. The after-the-fact /flag meters false_action on the day the
    # op TOOK EFFECT, not the day it was held: near a UTC-midnight hold→release span the
    # two differ, so flag_intent derives the op's day-key from executedAt when present,
    # falling back to ts (a pre-#193 intent, or one flagged before this field existed).
    executedAt: str | None = None
