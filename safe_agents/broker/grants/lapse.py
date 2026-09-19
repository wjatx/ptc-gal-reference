"""grants.lapse — write the lapse of an expired certification term (#255).

GAL §6.7.6 / GAL-34. When a grant's term (``certifiedUntil``) passes, the grant
falls to ``lastSafeLevel`` with ``demotionReason = "pending-evidence"`` and a
``lapse``-typed record is appended to the ceremony ledger.

Two halves, deliberately split:

  * READ side — ``grants.term.effective_level``. Per-call enforcement (the
    broker PIP) already treats a term-passed grant as being at lastSafeLevel,
    with no write and no waiting for this module. The agent identity gains no
    grant-store write for it.
  * WRITE side — this module. It makes the stored state and the ledger say what
    enforcement is already doing, so an auditor reading the ledger sees why the
    level fell. It runs under the SAME separate system identity as demotion
    (§6.7.2; ``runner.main`` runs it before the demotion pass) and records
    ``ratifiedBy = DEMOTION_RATIFIER``.

A lapse is NOT a demotion. Its record carries an EMPTY ``triggeredBy``: every
§4.2 trigger asserts that something was observed, and a lapse asserts that
nothing renewed the term. Writing it as a triggered demotion would teach every
auditor to read a demotion record as possibly meaning "nothing happened, on
schedule".

Also by design:

  * A lapse lands on lastSafeLevel and never revokes (§6.7.6: revoking on a
    timer is a self-inflicted forced abstention). The grant is lowered, never
    deleted.
  * Idempotent: the decision is ``term.lapse_pending`` over the STORED grant,
    so a grant this module already lowered has nothing to lapse and a second
    pass appends nothing. A grant already at or below lastSafeLevel likewise.
  * The stored term is carried forward unchanged. It stays as the record of
    which term lapsed; only a ratified re-promotion sets a new one (the store's
    ``refuse_term_extension`` refuses every other path).
  * The evaluation instant ``now`` is an explicit input (see ``grants.term``);
    only ``main`` in ``grants.runner`` reads the wall clock.

Record and grant commit as ONE atomic unit (``write_record_and_grant``, #244),
conditioned on the guarded re-read: both land or neither does, so there is no
ordering in which the grant is lowered without its record or the record exists
without the lowered grant.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.grants.ceremony import PromotionRecordStore
from safe_agents.broker.grants.store import (
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
    RecordAlreadyExistsError,
)
from safe_agents.broker.grants.term import lapse_pending, term_passed
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER

logger = logging.getLogger(__name__)

# The system identity that writes lapses: the demotion evaluator (GAL §6.7.2 —
# the same separate identity; §4.3's lapse row names "the system evaluator").
LAPSE_RATIFIER = DEMOTION_RATIFIER

LapseStatus = Literal[
    "no-grant", "quarantined", "no-term", "not-due", "nothing-to-lapse", "lapsed", "conflict"
]


class LapseConflictError(Exception):
    """The grant changed between the evaluation read and the lapse write.

    Nothing was written. Re-read and re-evaluate; never retried silently.
    """


class LapseNotDueError(ValueError):
    """apply_lapse was called for a grant that owes no lapse at ``now``."""


@dataclass(frozen=True)
class LapseOutcome:
    """Result of one run_lapse pass. Every path returns one; never a silent None.

    status:
        no-grant         — no grant at the coordinate
        quarantined      — stored grant failed verification; NOT evaluated
        no-term          — the grant carries no term; it never lapses
        not-due          — the term has not passed at ``now``
        nothing-to-lapse — the term has passed but the grant is already at or
                           below lastSafeLevel (including: already lapsed)
        lapsed           — grant lowered and lapse record appended
        conflict         — concurrent modification or ledger-key collision;
                           nothing written, operator/caller re-runs
    """

    status: LapseStatus
    reason: str
    updated_grant: Grant | None = None
    record: PromotionRecord | None = None


def _record_ts(now: datetime.datetime) -> str:
    """The ledger's canonical ts form ('+00:00', never 'Z'; validate_record_ts)."""
    return now.astimezone(datetime.UTC).isoformat()


def build_lapse(grant: Grant, now: datetime.datetime) -> tuple[Grant, PromotionRecord]:
    """Pure: the lowered grant and the lapse record for a grant owing a lapse.

    Raises LapseNotDueError when ``term.lapse_pending(grant, now)`` is false —
    this never builds a record for a grant with no term, a term not yet passed,
    or a grant already at/below lastSafeLevel.
    """
    if not lapse_pending(grant, now):
        raise LapseNotDueError(
            f"grant {grant.principal.agentId}/{grant.actionClass} owes no lapse at "
            f"{now.isoformat()} (certifiedUntil={grant.certifiedUntil!r}, level="
            f"{grant.level.value!r}, lastSafeLevel={grant.lastSafeLevel.value!r})"
        )
    ts = _record_ts(now)
    updated = grant.model_copy(
        update={
            "level": grant.lastSafeLevel,
            "demotionReason": "pending-evidence",
            "ts": ts,
            # certifiedUntil and lastSafeLevel carried forward unchanged: the
            # term stays as the record of what lapsed; lastSafeLevel stays the
            # floor it names.
        }
    )
    record = PromotionRecord(
        recordType="lapse",
        actionClass=grant.actionClass,
        principal=grant.principal,
        fromLevel=grant.level,
        toLevel=grant.lastSafeLevel,
        # §5.2: a lapse record's evidence names the expired term — it cites the
        # absence of renewal, not an artifact.
        evidence=f"certification term expired: certifiedUntil={grant.certifiedUntil}",
        predicate=None,
        proposedBy=LAPSE_RATIFIER,
        ratifiedBy=LAPSE_RATIFIER,
        envelopeHash=grant.envelopeHash,
        triggeredBy=[],
        demotionReason="pending-evidence",
        ts=ts,
    )
    return updated, record


def apply_lapse(
    grant: Grant,
    *,
    store: GrantStore,
    record_store: PromotionRecordStore,
    now: datetime.datetime,
    session: object = None,
    record_signer: object = None,
) -> tuple[Grant, PromotionRecord]:
    """Lower ``grant`` to lastSafeLevel and append its lapse record, atomically.

    ``grant`` is the grant as read at evaluation time. A guarded re-read refuses
    quarantine (writing over a tampered grant would launder it) and treats any
    content change as a conflict. ``record_signer`` (an issuer RecordSigner) signs
    the record when supplied; the signature rides the same atomic write.

    Raises LapseNotDueError, QuarantinedGrantError, LapseConflictError, or
    RecordAlreadyExistsError. Every raise writes nothing.
    """
    updated, record = build_lapse(grant, now)

    current = store.get_grant(grant.principal, grant.actionClass)
    if current.quarantined:
        raise QuarantinedGrantError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is quarantined "
            f"({current.quarantine_reason}); it must not be written until the "
            "quarantine is resolved"
        )
    if current.grant is None or current.grant != grant:
        raise LapseConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is missing or was "
            "modified between evaluation and the lapse write; re-read and re-evaluate"
        )

    signature = record_signer.sign_record(record) if record_signer is not None else None
    try:
        store.write_record_and_grant(
            record, updated, record_store, session, signature=signature, expected=current
        )
    except GrantUpdateConflictError as exc:
        raise LapseConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} was modified between "
            "evaluation and the lapse write (conditional write failed); nothing was "
            "written — re-read and re-evaluate"
        ) from exc
    return updated, record


def run_lapse(
    principal: Principal,
    action_class: str,
    *,
    grant_store: GrantStore,
    record_store: PromotionRecordStore,
    now: datetime.datetime,
    session: object = None,
    record_signer: object = None,
) -> LapseOutcome:
    """One lapse evaluation pass for (principal, action_class) at instant ``now``.

    Deterministic: the same stored grant and the same ``now`` give the same
    outcome. No ledger read is involved in the decision — whether a lapse is
    owed is a function of the stored grant and ``now`` alone.
    """
    coordinate = f"{principal.agentId}/{action_class}"
    read = grant_store.get_grant(principal, action_class)
    if read.quarantined:
        reason = (
            f"grant {coordinate} is QUARANTINED ({read.quarantine_reason}); not "
            "evaluating a lapse — quarantined contents are untrusted"
        )
        logger.error(reason)
        return LapseOutcome(status="quarantined", reason=reason)
    grant = read.grant
    if grant is None:
        return LapseOutcome(status="no-grant", reason=f"no grant for {coordinate}")
    if grant.certifiedUntil is None:
        return LapseOutcome(
            status="no-term", reason=f"grant {coordinate} carries no term; it never lapses"
        )
    if not term_passed(grant, now):
        return LapseOutcome(
            status="not-due",
            reason=(
                f"grant {coordinate} is certified until {grant.certifiedUntil}; "
                f"not passed at {now.isoformat()}"
            ),
        )
    if not lapse_pending(grant, now):
        return LapseOutcome(
            status="nothing-to-lapse",
            reason=(
                f"grant {coordinate}'s term passed at {grant.certifiedUntil}, but it "
                f"is already at {grant.level.value!r} (lastSafeLevel "
                f"{grant.lastSafeLevel.value!r}); nothing to lapse"
            ),
        )
    try:
        updated, record = apply_lapse(
            grant,
            store=grant_store,
            record_store=record_store,
            now=now,
            session=session,
            record_signer=record_signer,
        )
    except (LapseConflictError, RecordAlreadyExistsError) as exc:
        logger.error(str(exc))
        return LapseOutcome(status="conflict", reason=str(exc))
    reason = (
        f"grant {coordinate} LAPSED: certification term {grant.certifiedUntil} passed "
        f"at {now.isoformat()}; {record.fromLevel.value} -> {record.toLevel.value}, "
        "demotionReason=pending-evidence"
    )
    logger.info(reason)
    return LapseOutcome(status="lapsed", reason=reason, updated_grant=updated, record=record)
