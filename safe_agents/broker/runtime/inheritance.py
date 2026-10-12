"""broker.runtime.inheritance -- the PEP's two hooks into the taint inheritance ledger.

PTC-51 (#177). This is Biba's invocation property in its low-water-mark form: a
context the agent causes starts no cleaner than the turn that caused it
(``broker/TAINT.md`` §4.1). The ledger's record and stores are in
``broker.schemas.inheritance`` and ``broker.taint.inheritance``; this module
holds the two places the runtime touches them.

  write_inheritance_record   before a declared cause op reaches the Doer, on the
                             inline path and on the approval release path alike
  ingest_inherited           when the runtime mints a turn for its own principal

Fail directions, both toward less authority:

  * A record that cannot be written raises ``InheritanceWriteError``, a
    ``ConnectorExecutionError``. The PEP records it as a failed execution and
    the cause op does not run.
  * A ledger that cannot be read taints the new turn with
    ``INHERITANCE_UNREADABLE_SOURCE``. The turn is still minted: refusing to serve
    would be a forced abstention, whose safety depends on the agent's polarity.

Nothing here reads a declaration from a call. The caller passes the entry from
its own image-baked ``ToolOpTable``.
"""

from __future__ import annotations

import datetime
import logging
import uuid

from safe_agents.broker.delegation.keys import principal_key
from safe_agents.broker.delegation.store import SubGrantStore
from safe_agents.broker.schemas import BrokeredCall, CausesContext, InheritanceRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.taint import TurnContext
from safe_agents.broker.taint.inheritance import (
    InheritanceStore,
    inheritance_target,
    resolve_not_after,
)

from .doer import ConnectorExecutionError

logger = logging.getLogger(__name__)

# The source a turn is tainted with when the ledger could not be read at its mint.
# Not an ``internal:`` source, and ingested under the floor below, so nothing a
# consumer configures trusts it.
INHERITANCE_UNREADABLE_SOURCE = "inheritance:unreadable"

# The source a turn is tainted with when a live record says the causing call was
# tainted but names no source. ``Taint`` permits that shape; a record holding it
# must still taint, and an ingest needs a source id to record.
INHERITED_WITHOUT_SOURCE = "inheritance:unsourced"


class InheritanceWriteError(ConnectorExecutionError):
    """The inheritance record for a cause op could not be written, so the op did not run.

    A ``ConnectorExecutionError`` so both executors record it exactly as they
    record an execution that broke before the connector was reached
    (``outcome="failed"``, the message in the record's ``error``), and the
    enforcement saga settles the write-ahead entry. Never a refusal: no control
    said no about the call itself.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, refused=False)


def _untrusted(_source: str) -> bool:
    """The floor an inherited source is ingested under: nothing lifts it.

    The same floor ``channels.trust_map.ingest_chain`` applies to a sender's
    ``untrusted`` label (PTC §6.2, consequence 2). Neither the receiving
    runtime's trust map nor its ``Envelope.trusted_read_sources`` is consulted.
    """
    return False


def write_inheritance_record(
    *,
    store: InheritanceStore | None,
    decl: CausesContext,
    call: BrokeredCall,
    op: str,
    sub_grant_store: SubGrantStore | None,
    now: datetime.datetime,
) -> InheritanceRecord:
    """Write the record a cause op owes its target, or raise ``InheritanceWriteError``.

    ``decl`` is the declaration from the writing runtime's own ``ToolOpTable``
    for the op about to run, never one a call carried. ``call`` supplies the
    causing principal, the causing turn id and the taint, all frozen on the call:
    a call released from a hold carries the taint its hold froze, so a human's
    approval writes the same record an inline call would.

    ``notAfter`` is the child's sub-grant expiry when the sub-grant store holds
    one for the target, else ``now`` plus the declaration's horizon, and always
    the latter for ``"self"``. Every failure on the way, including a sub-grant
    lookup that finds two rows and a record born expired, is a write failure.
    """
    target = inheritance_target(decl, call.principal)
    try:
        if store is None:
            # The floor makes this unreachable: BrokerRuntime refuses to exist
            # with a cause op and no store. Kept so a bypass fails closed.
            raise RuntimeError("no inheritance store is configured")
        sub_grant = None
        if not isinstance(decl.target, str) and sub_grant_store is not None:
            sub_grant = sub_grant_store.get_by_principal(target)
        not_after = resolve_not_after(decl, issued_at=now, sub_grant=sub_grant)
        record = InheritanceRecord(
            id=str(uuid.uuid4()),
            target=target,
            causingPrincipal=call.principal,
            causingTurnId=call.session.turnId,
            taint=call.taint,
            tool=call.tool,
            op=op,
            issuedAt=now.isoformat(),
            notAfter=not_after.isoformat(),
        )
        store.put_record(record)
    except Exception as exc:  # noqa: BLE001 -- every failure stops the op
        raise InheritanceWriteError(
            f"taint inheritance record for {principal_key(target)} not written, so "
            f"{call.tool}.{op} did not run: {type(exc).__name__}: {exc}"
        ) from None
    return record


def ingest_inherited(
    turn: TurnContext,
    *,
    store: InheritanceStore,
    principal: Principal,
    now: datetime.datetime,
    skew: datetime.timedelta,
) -> None:
    """Ingest every live record owed to ``principal`` into a freshly minted turn.

    Each record's sources go in under their original ids, under a floor the
    runtime's trust map and ``trusted_read_sources`` cannot lift. A record that
    is tainted but names no source taints with ``INHERITED_WITHOUT_SOURCE``. A
    record from a clean causing turn adds nothing.

    ``notAfter`` was stamped by the causing broker's clock. The record is judged
    live at ``now - skew``, so it taints up to the bound LONGER: toward more
    taint, the opposite of ``clock_skew.end_judged_at``, which ends authority
    early.

    A read that raises taints the turn with ``INHERITANCE_UNREADABLE_SOURCE`` and
    returns. It never raises, so the turn is always minted.

    A record whose ``target`` is not ``principal`` is skipped. The partition key
    renders a principal by joining its parts with ``#``, so two principals whose
    parts carry ``#`` can share a partition; the stored target settles whose
    record it is.
    """
    try:
        records = store.live_records(principal, now - skew)
    except Exception as exc:  # noqa: BLE001 -- an unreadable ledger taints, never refuses
        logger.warning(
            "taint inheritance ledger unreadable at turn mint for %s (%s); minting "
            "the turn tainted with %s",
            principal_key(principal),
            type(exc).__name__,
            INHERITANCE_UNREADABLE_SOURCE,
        )
        turn.ingest_source(INHERITANCE_UNREADABLE_SOURCE, _untrusted)
        return
    for record in records:
        if record.target != principal:
            continue
        for source in record.taint.sources:
            turn.ingest_source(source, _untrusted)
        if record.taint.tainted and not record.taint.sources:
            turn.ingest_source(INHERITED_WITHOUT_SOURCE, _untrusted)
