"""broker.approval — out-of-band approval: Intent materialization + WYSIWYE + notifier hook.

When the PDP returns require_approval, the broker calls materialize() to freeze the exact
BrokeredCall as a pending Intent record, persist it, and return {status: pending, intentId}
to the agent. The agent's turn ends immediately — it holds no tool that can approve or
release the intent.

On approval (via an authenticated out-of-band path, not from the agent), the broker calls
approve(). This reads materializedRequest from the store and executes EXACTLY those bytes
— never anything the agent re-sends after the turn ended. This is the WYSIWYE guarantee:
what-you-see-is-what-you-execute.

Exports:
    materialize         — called when decide() returns require_approval; returns pending result
    approve             — called by the approval path; executes the stored materializedRequest
    reject              — called by the approval path on a "no"; transitions to rejected, no execution
    IntentStore         — persistence Protocol (implement for a new backend)
    InMemoryIntentStore — thread-safe in-process fake for tests; no AWS required
    DynamoIntentStore   — production DynamoDB implementation (lazy boto3)
    QuarantinedIntentError — raised by get_intent on stored-bytes HMAC failure (#349)
    IntentAlreadyPendingError: raised by put_intent over a pending intent's id (#39)
    ReleaseRefusedError — raised by a release executor whose revalidation refused (#9)
    ApprovalResult      — return type of materialize()
    ExecutionResult     — return type of approve()
    NotifierEvent       — event contract for the notifier hook (channel delivery in channels/)

See SCHEMAS.md §4 for the Intent schema fields and the ARCHITECTURE.md for WYSIWYE.
"""

from .engine import (
    RELEASE_REFUSED_REASON_PREFIX,
    ReleaseRefusedError,
    approve,
    materialize,
    reject,
)
from .store import (
    DynamoIntentStore,
    InMemoryIntentStore,
    IntentAlreadyPendingError,
    IntentStore,
    QuarantinedIntentError,
)
from .types import ApprovalResult, ExecutionResult, IntentView, NotifierEvent

__all__ = [
    "materialize",
    "approve",
    "reject",
    "IntentStore",
    "InMemoryIntentStore",
    "DynamoIntentStore",
    "QuarantinedIntentError",
    "IntentAlreadyPendingError",
    "ReleaseRefusedError",
    "RELEASE_REFUSED_REASON_PREFIX",
    "ApprovalResult",
    "ExecutionResult",
    "IntentView",
    "NotifierEvent",
]
