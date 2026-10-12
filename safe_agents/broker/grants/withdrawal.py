"""grants.withdrawal: record that a grant fell because its issuer key was withdrawn.

GAL §6.10 (GAL-41, #179). Built on the lapse pattern (``grants.lapse``), in two
halves:

  * READ side: ``grants.grant_standing`` and ``grants.term.effective_level``.
    The broker's PIP acts at the lower of a grant's level and lastSafeLevel as
    soon as it has accepted a standing document that withdraws the key behind
    that level, with no write.
  * WRITE side: this module. It makes the stored grant and the ledger say what
    enforcement is already doing, so a reader of the ledger sees why the level
    fell. It runs under the evaluator identity (``grants.runner``, before the
    lapse and demotion passes) and appends a ``withdrawal`` record, signed with
    the evaluator's key when one is configured.

A withdrawal is neither a demotion nor a lapse. No trigger fired, so
``triggeredBy`` stays empty, and no term ran out. Its ``demotionReason`` is
``pending-evidence``: nothing is proven broken about the agent, and the way
back is the promotion ceremony with fresh evidence, under a key in standing.
No command restores a withdrawn key.

Also by design:

  * It lands on the lower of the level and lastSafeLevel, never on revocation,
    for the reason a lapse does (§6.7.6).
  * It writes only for a key the standing document says is WITHDRAWN. Standing
    that is merely not established (no document accepted, or the document past
    its age) recovers by itself when the source answers, so a record would claim
    a transition that did not happen. That fall is the enforcer's alone.
  * Only the issuer's standing is consulted. The key a level rests on signed a
    bootstrap, promotion or reattestation record, and those are issuer-signed;
    an evaluator key's withdrawal is an audit finding and changes no level.
  * Idempotent: a grant at or below lastSafeLevel has nothing to lower, so a
    second pass appends nothing.
  * The key the record accounts for is not a field on the record. A reader
    derives it from the ledger: the verified signer of the last record that
    licensed the grant before the withdrawal record. ``evidence`` names it for a
    person, and no reader in code parses it.

Record and grant commit as ONE atomic unit (``write_record_and_grant``),
conditioned on the guarded re-read.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.grants.ceremony import PromotionRecordStore
from safe_agents.broker.grants.demotion import _rank
from safe_agents.broker.grants.grant_standing import (
    LICENSED_BY_KEY,
    resolve_licensing_key,
)
from safe_agents.broker.grants.key_standing import KeyStandingEntry
from safe_agents.broker.grants.ledger_clock import next_ledger_ts
from safe_agents.broker.grants.record_signing import ISSUER_ROLE, RoleKeyResolvers
from safe_agents.broker.grants.standing_source import (
    IN_STANDING,
    WITHDRAWN,
    StandingSource,
)
from safe_agents.broker.grants.store import (
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
    RecordAlreadyExistsError,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.clock_skew import ZERO_SKEW
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.promotion_record import (
    DEMOTION_RATIFIER,
    WITHDRAWAL_RECORD_TYPE,
)

logger = logging.getLogger(__name__)

# The system identity that writes withdrawals: the evaluator, as for lapse.
WITHDRAWAL_RATIFIER = DEMOTION_RATIFIER

WithdrawalStatus = Literal[
    "no-grant",
    "quarantined",
    "nothing-to-lower",
    "in-standing",
    "not-established",
    "lowered",
    "conflict",
]


class WithdrawalConflictError(Exception):
    """The grant changed between the evaluation read and the write. Nothing was written."""


class WithdrawalNotOwedError(ValueError):
    """build_withdrawal was called for a grant with nothing to lower."""


@dataclass(frozen=True)
class WithdrawalOutcome:
    """Result of one run_withdrawal pass. Every path returns one.

    status:
        no-grant         no grant at the coordinate
        quarantined      the stored grant failed verification; NOT evaluated
        nothing-to-lower the grant is already at or below lastSafeLevel
        in-standing      the key behind the level has standing
        not-established  the key behind the level, or its standing, cannot be
                         established; the enforcer falls, and nothing is written
        lowered          grant lowered and withdrawal record appended
        conflict         concurrent modification or ledger-key collision
    """

    status: WithdrawalStatus
    reason: str
    updated_grant: Grant | None = None
    record: PromotionRecord | None = None


def withdrawal_evidence(key_id: str, entry: KeyStandingEntry) -> str:
    """The record's ``evidence``: which key, for a person reading the ledger."""
    return (
        f"issuer key withdrawn: {key_id} ({entry.withdrawnReason}, withdrawn at "
        f"{entry.withdrawnAt})"
    )


def build_withdrawal(
    grant: Grant, *, key_id: str, entry: KeyStandingEntry, ts: str
) -> tuple[Grant, PromotionRecord]:
    """Pure: the lowered grant and its withdrawal record.

    Lands on lastSafeLevel, which is the lower of the two because a grant at or
    below it has nothing to lower and is refused here.
    """
    if _rank(grant.level) <= _rank(grant.lastSafeLevel):
        raise WithdrawalNotOwedError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is at "
            f"{grant.level.value!r}, not above lastSafeLevel "
            f"{grant.lastSafeLevel.value!r}; a withdrawal never raises"
        )
    updated = grant.model_copy(
        update={"level": grant.lastSafeLevel, "demotionReason": "pending-evidence", "ts": ts}
    )
    record = PromotionRecord(
        recordType=WITHDRAWAL_RECORD_TYPE,
        actionClass=grant.actionClass,
        principal=grant.principal,
        fromLevel=grant.level,
        toLevel=grant.lastSafeLevel,
        evidence=withdrawal_evidence(key_id, entry),
        predicate=None,
        proposedBy=WITHDRAWAL_RATIFIER,
        ratifiedBy=WITHDRAWAL_RATIFIER,
        envelopeHash=grant.envelopeHash,
        triggeredBy=[],
        demotionReason="pending-evidence",
        ts=ts,
    )
    return updated, record


def apply_withdrawal(
    grant: Grant,
    *,
    store: GrantStore,
    record_store: PromotionRecordStore,
    key_id: str,
    entry: KeyStandingEntry,
    now: datetime.datetime,
    session: object = None,
    record_signer: object = None,
) -> tuple[Grant, PromotionRecord]:
    """Lower ``grant`` and append its withdrawal record, atomically.

    A guarded re-read refuses quarantine and treats any change as a conflict.
    Every raise writes nothing.
    """
    ts = next_ledger_ts(record_store, grant.principal, grant.actionClass, now=now, session=session)
    updated, record = build_withdrawal(grant, key_id=key_id, entry=entry, ts=ts)
    current = store.get_grant(grant.principal, grant.actionClass)
    if current.quarantined:
        raise QuarantinedGrantError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is quarantined "
            f"({current.quarantine_reason}); it must not be written until the "
            "quarantine is resolved"
        )
    if current.grant is None or current.grant != grant:
        raise WithdrawalConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} is missing or was "
            "modified between evaluation and the withdrawal write; re-read and re-evaluate"
        )
    signature = record_signer.sign_record(record) if record_signer is not None else None
    try:
        store.write_record_and_grant(
            record, updated, record_store, session, signature=signature, expected=current
        )
    except GrantUpdateConflictError as exc:
        raise WithdrawalConflictError(
            f"grant {grant.principal.agentId}/{grant.actionClass} was modified between "
            "evaluation and the withdrawal write; nothing was written"
        ) from exc
    return updated, record


def run_withdrawal(
    principal: Principal,
    action_class: str,
    *,
    grant_store: GrantStore,
    record_store: PromotionRecordStore,
    standing: StandingSource,
    now: datetime.datetime,
    skew: datetime.timedelta = ZERO_SKEW,
    session: object = None,
    record_signer: object = None,
) -> WithdrawalOutcome:
    """One withdrawal pass for (principal, action_class) at ``now``.

    ``standing`` is the ISSUER's source, already refreshed by the caller.
    ``record_store`` must also read records as stored (``list_stored_records``).
    """
    if standing.role != ISSUER_ROLE:
        raise ValueError("a withdrawal is owed only on the issuer's standing")
    coordinate = f"{principal.agentId}/{action_class}"
    read = grant_store.get_grant(principal, action_class)
    if read.quarantined:
        reason = f"grant {coordinate} is QUARANTINED ({read.quarantine_reason}); not evaluated"
        logger.error(reason)
        return WithdrawalOutcome(status="quarantined", reason=reason)
    grant = read.grant
    if grant is None:
        return WithdrawalOutcome(status="no-grant", reason=f"no grant for {coordinate}")
    if _rank(grant.level) <= _rank(grant.lastSafeLevel):
        return WithdrawalOutcome(
            status="nothing-to-lower",
            reason=(
                f"grant {coordinate} is at {grant.level.value!r}, not above lastSafeLevel "
                f"{grant.lastSafeLevel.value!r}; nothing to lower"
            ),
        )
    stored = record_store.list_stored_records(principal, action_class, session)  # type: ignore[attr-defined]
    resolvers = RoleKeyResolvers(issuer=standing.key_resolver(), standing={ISSUER_ROLE: standing})
    key = resolve_licensing_key(stored, grant, resolvers=resolvers, skew=skew)
    if key.kind != LICENSED_BY_KEY:
        return WithdrawalOutcome(
            status="not-established",
            reason=f"grant {coordinate}: the key behind its level is not established ({key.detail})",
        )
    verdict = standing.standing_of(key.key_id, now, skew=skew)
    if verdict.verdict == IN_STANDING:
        return WithdrawalOutcome(
            status="in-standing",
            reason=f"grant {coordinate}: issuer key {key.key_id!r} is in standing",
        )
    if verdict.verdict != WITHDRAWN:
        return WithdrawalOutcome(
            status="not-established",
            reason=(
                f"grant {coordinate}: the standing of issuer key {key.key_id!r} is not "
                f"established ({verdict.verdict}); nothing is written"
            ),
        )
    try:
        updated, record = apply_withdrawal(
            grant,
            store=grant_store,
            record_store=record_store,
            key_id=key.key_id,
            entry=verdict.entry,
            now=now,
            session=session,
            record_signer=record_signer,
        )
    except (WithdrawalConflictError, RecordAlreadyExistsError) as exc:
        logger.error(str(exc))
        return WithdrawalOutcome(status="conflict", reason=str(exc))
    reason = (
        f"grant {coordinate} LOWERED: issuer key {key.key_id!r} was withdrawn "
        f"({verdict.entry.withdrawnReason}); {record.fromLevel.value} -> {record.toLevel.value}"
    )
    logger.info(reason)
    return WithdrawalOutcome(status="lowered", reason=reason, updated_grant=updated, record=record)
