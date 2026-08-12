"""Autonomy rung state machine (sa#60).

Validates and orchestrates transitions between the three supervision rungs
(in-loop / on-loop / out-of-loop). This module is pure logic with no
DynamoDB dependency. It composes the ceremony (#58) and demotion (#59)
without duplicating their bodies.

Public API
----------
TransitionError              — raised on any structurally-invalid transition
PromotionEligibilityCounters — input type for hysteresis checks
validate_promotion_transition(from_level, to_level)     — pure; raises on illegal
validate_demotion_transition(from_level, to_level)      — pure; raises on illegal
is_eligible_for_promotion(grant, counters, *, min_clean_runs, min_dwell, now=None) -> bool
RungStateMachine             — ties ceremony + demotion into one coordinator

Legal transitions
-----------------
  Promotion (upward, exactly one rung, ceremony required):
    Recommend (None) -> in-loop   (the grant-creating first promotion)
    in-loop  -> on-loop
    on-loop  -> out-of-loop

  Demotion (downward, toward lastSafeLevel, deterministic trigger):
    out-of-loop -> on-loop       (lastSafeLevel=on-loop)
    any         -> in-loop       (lastSafeLevel=in-loop, always permitted)

  Voluntary tightening (downward, any level -> in-loop, no ceremony, no trigger):
    on-loop     -> in-loop
    out-of-loop -> in-loop
    (always permitted — tightening is safety-monotone; writes a
     tightening-typed PromotionRecord to the ledger)

  Lateral (same level, re-ratification for evidence refresh):
    any -> same   (allowed; does not write a PromotionRecord)

  Illegal (raises TransitionError):
    in-loop -> out-of-loop   (level-skipping)
    any demotion path raising the level

Invariants
----------
  - lastSafeLevel is never out-of-loop (enforced by Grant schema; asserted here).
  - Promotion is always exactly one rung — level-skipping is TransitionError.
  - The demotion path never raises the autonomy level.

See broker/grant-lifecycle.md for the full state-machine specification.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Literal

from safe_agents.broker.grants.ceremony import (
    CeremonyResult,
    PromotionCeremony,
    PromotionProposal,
    PromotionRecordStore,
)
from safe_agents.broker.ceremony_identity import attestation_for
from safe_agents.broker.grants.proposals import ProposalStore
from safe_agents.broker.grants.demotion import (
    DemotionMetrics,
    GrantNotFoundError,
    apply_demotion,
    evaluate_demotion_triggers,
)
from safe_agents.broker.grants.store import (
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel


# ---------------------------------------------------------------------------
# Rung ordering
# ---------------------------------------------------------------------------

_RUNG_ORDER: list[AutonomyLevel] = [
    AutonomyLevel.in_loop,
    AutonomyLevel.on_loop,
    AutonomyLevel.out_of_loop,
]

_RUNG_RANK: dict[AutonomyLevel, int] = {
    level: i for i, level in enumerate(_RUNG_ORDER)
}


def _rank(level: AutonomyLevel) -> int:
    return _RUNG_RANK[level]


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class TransitionError(Exception):
    """Raised when a rung transition violates the state machine rules.

    This is a logic error in the caller, not a retriable data error.
    Fix the transition arguments before calling again.
    """


# ---------------------------------------------------------------------------
# Pure transition validators
# ---------------------------------------------------------------------------


def validate_promotion_transition(
    from_level: AutonomyLevel | None,
    to_level: AutonomyLevel,
) -> None:
    """Assert the promotion transition moves exactly one rung upward.

    from_level=None is the Recommend rung (rung 0 — a rung but never a level
    value): its only valid transition is the grant-creating first promotion to
    in-loop (broker/grant-lifecycle.md).

    Raises TransitionError if:
      - from_level is None and to_level is not in-loop (the only valid
        Recommend-origin transition)
      - to_level <= from_level (lateral or downward — not the promotion path)
      - to_level is more than one rung above from_level (level-skipping)

    This is a pure guard; it does not invoke the ceremony or write any state.
    """
    if from_level is None:
        if to_level is not AutonomyLevel.in_loop:
            raise TransitionError(
                f"Promotion from the Recommend rung (from_level=None) must target "
                f"'in-loop' — the grant-creating first promotion — got "
                f"{to_level.value!r}. Level-skipping is not permitted."
            )
        return

    from_rank = _rank(from_level)
    to_rank = _rank(to_level)

    if to_rank <= from_rank:
        direction = "lateral" if to_rank == from_rank else "downward"
        raise TransitionError(
            f"Promotion must move upward: {from_level.value!r} -> {to_level.value!r} "
            f"is {direction}. "
            "Use demote() for downward transitions; "
            "re_ratify() for same-level evidence refresh."
        )

    if to_rank - from_rank != 1:
        raise TransitionError(
            f"Promotion must move exactly one rung: "
            f"{from_level.value!r} -> {to_level.value!r} "
            f"skips {to_rank - from_rank - 1} intermediate rung(s). "
            "Level-skipping is not permitted."
        )


def validate_demotion_transition(
    from_level: AutonomyLevel,
    to_level: AutonomyLevel,
) -> None:
    """Assert the demotion transition does not raise the autonomy level.

    Raises TransitionError if to_level has a strictly higher rank than
    from_level — i.e., if the "demotion" path would increase autonomy.
    Same-rank (already at target) and downward moves are both accepted.

    This is a pure guard; it does not invoke the evaluator or write any state.
    """
    from_rank = _rank(from_level)
    to_rank = _rank(to_level)

    if to_rank > from_rank:
        raise TransitionError(
            f"Demotion must not raise the autonomy level: "
            f"{from_level.value!r} -> {to_level.value!r} would increase autonomy. "
            "Use promote() for upward transitions."
        )


# ---------------------------------------------------------------------------
# Hysteresis — dwell-time eligibility
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromotionEligibilityCounters:
    """Counter state for the promotion hysteresis check.

    Callers pre-fetch this from their counter store (e.g., a DynamoDB counters
    table). This module never reads from any store.

    Attributes:
        clean_runs_since_promotion: consecutive clean runs recorded since the
            grant reached its current level. A run is "clean" when it produced
            no false action and no human override.
        last_transition_ts: ISO-8601 timestamp of the last level transition
            (callers have this from grant.ts — every transition path updates
            it). A naive timestamp is interpreted as UTC.
    """

    clean_runs_since_promotion: int
    last_transition_ts: str


def _parse_ts(ts: str) -> datetime.datetime:
    """Parse an ISO-8601 timestamp; a naive value is interpreted as UTC."""
    parsed = datetime.datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def is_eligible_for_promotion(
    grant: Grant,
    counters: PromotionEligibilityCounters,
    *,
    min_clean_runs: int,
    min_dwell: datetime.timedelta,
    now: datetime.datetime | None = None,
) -> bool:
    """Return True iff the grant has dwelt at its level long enough for promotion.

    Enforces the hysteresis rule from grant-lifecycle.md: a grant promoted to
    a new rung must hold that rung cleanly — both in clean-run count AND in
    wall-clock dwell time — before another upward move is considered. The two
    thresholds are independent and both must pass; keeping them distinct from
    the demotion triggers is what prevents promote/demote flapping.

    Does NOT evaluate the promotion predicate (that is the ceremony's job).
    Combine with evaluate_promotion_predicate and the maker-checker ceremony
    for a complete promotion decision.

    Args:
        grant: the current grant record; only grant.level is inspected.
        counters: pre-fetched dwell-time state (clean-run count + the
            timestamp of the last level transition).
        min_clean_runs: minimum clean runs required. This is per-action-class
            config supplied by the caller; never hardcoded.
        min_dwell: minimum wall-clock time the grant must have held its
            current level. Caller-supplied config, like min_clean_runs. To
            express dwell in counter periods (#212), pass
            ``n * enforcement.period_step(manifest.counter_period)`` — real
            time still elapses; only the bucket size is period-relative.
        now: the evaluation instant; injectable for tests. Defaults to the
            current UTC time. A naive value is interpreted as UTC.

    Returns:
        False if grant.level is already out-of-loop (no upward move possible).
        False if counters.clean_runs_since_promotion < min_clean_runs.
        False if (now - last_transition_ts) < min_dwell.
        True otherwise.
    """
    if grant.level is AutonomyLevel.out_of_loop:
        # Already at the top rung; no further promotion is possible.
        return False
    if counters.clean_runs_since_promotion < min_clean_runs:
        return False
    effective_now = now or datetime.datetime.now(datetime.timezone.utc)
    if effective_now.tzinfo is None:
        effective_now = effective_now.replace(tzinfo=datetime.timezone.utc)
    return effective_now - _parse_ts(counters.last_transition_ts) >= min_dwell


# ---------------------------------------------------------------------------
# Orchestrating state machine
# ---------------------------------------------------------------------------


class RungStateMachine:
    """Ties promotion (ceremony) and demotion (evaluator) into one coordinator.

    Every level change passes through here. The machine enforces:
      - Promotion is exactly one rung upward, via the maker-checker ceremony.
      - Demotion is toward lastSafeLevel, via the deterministic evaluator.
      - No transition that would raise the level can flow through the demotion
        path (TransitionError on misconfigured lastSafeLevel).
      - lastSafeLevel is never out-of-loop (Grant schema invariant; asserted
        here as a defence-in-depth guard before any write).
      - Lateral re-ratification (evidence refresh at the same level) is a
        named, explicit path separate from the promotion path.
      - Voluntary tightening (any level -> in-loop) is always permitted — no
        ceremony, no trigger — and appends a tightening-typed record.

    The machine has no DynamoDB dependency itself: all writes are delegated to
    the injected ceremony and grant_store, which accept InMemoryGrantStore for
    tests and DynamoDBGrantStore for production.
    """

    def __init__(
        self,
        *,
        ceremony: PromotionCeremony,
        grant_store: GrantStore,
        record_store: PromotionRecordStore,
    ) -> None:
        self._ceremony = ceremony
        self._grant_store = grant_store
        self._record_store = record_store

    # ------------------------------------------------------------------
    # Upward path — maker-checker ceremony (exactly one rung)
    # ------------------------------------------------------------------

    def promote(
        self,
        proposal: PromotionProposal,
        ratifier_id: str,
        *,
        session: object = None,
        proposal_store: "ProposalStore | None" = None,
        now: datetime.datetime | None = None,
        ratifier_kind: Literal["human", "predicate"] = "human",
    ) -> CeremonyResult:
        """Validate and execute a one-rung promotion via the maker-checker ceremony.

        Raises TransitionError if the transition is not exactly one rung upward
        (from_level=None is the Recommend rung; its only valid target is
        in-loop). On success, delegates to PromotionCeremony.execute() and
        returns its CeremonyResult (which may still carry status='rejected' if
        the predicate fails — TransitionError only covers structural
        invalidity). proposal_store, now, and ratifier_kind are passed through
        to execute() so the durable-proposal enforcement (single-shot
        consumption, deterministic expiry, high-blast human ratification) flows
        through the state machine unchanged.

        The ceremony is the only path by which a Grant's level can increase.
        Attempting to raise the level through any other path (e.g., calling
        demote() with a target higher than the current level) raises TransitionError.
        """
        validate_promotion_transition(proposal.from_level, proposal.target_level)
        return self._ceremony.execute(
            proposal,
            ratifier_id,
            session=session,
            proposal_store=proposal_store,
            now=now,
            ratifier_kind=ratifier_kind,
        )

    # ------------------------------------------------------------------
    # Lateral path — evidence refresh at the same level
    # ------------------------------------------------------------------

    def re_ratify(
        self,
        grant: Grant,
        evidence_bundle: str,
        ratifier_id: str,
        *,
        session: object = None,
        ts: str | None = None,
    ) -> Grant:
        """Refresh evidence at the current level without changing the rung.

        Lateral re-ratification is permitted when covered-distribution evidence
        needs renewal (e.g., after a distribution shift that resolved without
        triggering demotion). The level is not changed; no PromotionRecord is
        written (no level change occurred).

        Write discipline mirrors tighten_to_in_loop (#190 — the old blind put
        let a re-ratifier silently overwrite a demotion that raced in between
        its read and write, RAISING the level with no ceremony and no record):
        guarded re-read (not-found, quarantined, and concurrently-modified each
        surface as their typed error; a quarantined grant is NEVER written
        over), then the hash-conditioned store.update_grant — the real
        atomicity guard.

        Raises:
            TransitionError: if ratifier_id is empty — accountability requires
                a named ratifier even for lateral moves.
            GrantNotFoundError: if the grant does not exist in the store
                (re-ratification cannot create a grant).
            QuarantinedGrantError: if the re-read found the stored grant
                quarantined; it must not be written until resolved.
            GrantUpdateConflictError: if the grant changed since it was read
                (from the re-read, or from the conditional write losing the
                race); re-read and retry.
        """
        if not ratifier_id:
            raise TransitionError(
                "ratifier_id is required for re-ratification; "
                "accountability requires a named ratifier even for lateral moves."
            )

        # Guarded re-read, mirroring tighten_to_in_loop. Quarantine is checked
        # FIRST: a quarantined read carries grant=None (#246 — tampered bytes
        # are never parsed), so the not-found check would otherwise mislabel a
        # tamper as absence.
        current = self._grant_store.get_grant(grant.principal, grant.actionClass)
        if current.quarantined:
            raise QuarantinedGrantError(
                f"grant {grant.principal.agentId}/{grant.actionClass} is "
                f"quarantined ({current.quarantine_reason}); it must not be "
                "written until the quarantine is resolved"
            )
        if current.grant is None:
            raise GrantNotFoundError(
                f"grant {grant.principal.agentId}/{grant.actionClass} not found "
                "in store; re-ratification cannot create a grant"
            )
        if current.grant != grant:
            # Content equality is the staleness check under the stored-bytes
            # basis (#246): identical fields ⇒ identical canonical bytes.
            raise GrantUpdateConflictError(
                f"grant {grant.principal.agentId}/{grant.actionClass} was "
                "modified since it was read; re-read and retry"
            )

        effective_ts = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
        updated = grant.model_copy(
            update={
                "evidence": evidence_bundle,
                "promotedBy": ratifier_id,
                "ts": effective_ts,
            }
        )
        self._grant_store.update_grant(
            updated, current.stored_hash, session, prev_raw_data=current.raw_data
        )
        return updated

    # ------------------------------------------------------------------
    # Downward path — deterministic demotion evaluator
    # ------------------------------------------------------------------

    def demote(
        self,
        grant: Grant,
        metrics: DemotionMetrics,
        *,
        session: object = None,
        ts: str | None = None,
    ) -> tuple[Grant, PromotionRecord]:
        """Evaluate trigger breach and apply demotion toward lastSafeLevel.

        Evaluates the grant's demotionTriggers against the supplied metrics.
        If at least one trigger fires, validates that the resulting transition
        is strictly downward (never raises the level), then calls apply_demotion().

        Raises:
            TransitionError: if no trigger is currently breached (no demotion
                warranted), or if grant.lastSafeLevel would raise the level
                (defence-in-depth guard; the schema already forbids out-of-loop
                as lastSafeLevel, so this guards against direct-dict construction
                that bypasses the schema validator).
            DemotionConflictError: if the grant changed since this call
                (re-read and re-evaluate before retrying).
            GrantNotFoundError: if the grant does not exist in the store.
            QuarantinedGrantError: if apply_demotion's re-read found the
                stored grant quarantined (never written over).
        """
        demotion_result = evaluate_demotion_triggers(grant, metrics)
        if not demotion_result.should_demote:
            raise TransitionError(
                f"demote() called but no configured trigger is currently breached "
                f"for {grant.principal.agentId}/{grant.actionClass}. "
                f"Reason: {demotion_result.reason}"
            )

        target_level = grant.lastSafeLevel or AutonomyLevel.in_loop

        # Defence-in-depth: the schema forbids lastSafeLevel=out-of-loop,
        # but guard here too in case a record bypassed the validator.
        if target_level is AutonomyLevel.out_of_loop:
            raise TransitionError(
                f"lastSafeLevel is out-of-loop for "
                f"{grant.principal.agentId}/{grant.actionClass}; "
                "demotion must land on a supervised rung. This grant record "
                "is invalid — fix the store entry before retrying."
            )

        # Repeat breach on an already-demoted grant: after a demotion,
        # lastSafeLevel holds the PRIOR level as the re-promotion reference
        # point, which can sit above the current level. That is a record-only
        # demotion (the level stays put, the breach still lands on the ledger —
        # apply_demotion clamps identically), never a raise. Clamp before
        # validating so the guard only rejects genuine level increases.
        if _rank(target_level) > _rank(grant.level):
            target_level = grant.level

        validate_demotion_transition(grant.level, target_level)

        return apply_demotion(
            grant,
            demotion_result,
            store=self._grant_store,
            record_store=self._record_store,
            session=session,
            ts=ts,
        )

    # ------------------------------------------------------------------
    # Voluntary tightening — any level -> in-loop, always permitted
    # ------------------------------------------------------------------

    def tighten_to_in_loop(
        self,
        grant: Grant,
        requested_by: str,
        *,
        session: object = None,
        ts: str | None = None,
        evidence: str = "voluntary tightening",
    ) -> tuple[Grant, PromotionRecord]:
        """Voluntarily lower the grant to in-loop. Always permitted.

        Tightening is safety-monotone: any level -> in-loop needs no ceremony
        and no fired trigger (grant-lifecycle.md; the rule locked 2026-07-11).
        It is NOT a demotion — demotionReason is left untouched and no trigger
        names are recorded. lastSafeLevel is set to in-loop: it is the rung
        demotion falls back to, and once the grant sits at the floor the only
        coherent fall-back is the floor itself (a retained higher value would
        make a later trigger-fired demote() target a rung ABOVE the current
        level). Re-promotion always re-climbs through the full ceremony, so no
        high-water-mark shortcut is lost.

        Write discipline mirrors demotion (apply_demotion's guarded re-read):
        the grant is re-read before writing — not-found, quarantined, and
        concurrently-modified each surface as their typed error before any
        write; in particular a quarantined grant is NEVER written over (that
        would launder the tampered state under a fresh valid hash). The
        lowered grant and its tightening-typed PromotionRecord then commit as
        ONE atomic unit (#244, write_record_and_grant): a failed unit leaves
        the grant at its prior level with no ledger hole, and the error
        surfaces loudly for the caller to retry.

        Args:
            grant: the grant as last read from the store; content equality
                against the guarded re-read is the staleness check (#246).
            requested_by: who asked for the tightening. Recorded as both
                proposedBy and ratifiedBy — maker ≠ checker is not enforced
                for tightening (narrowing autonomy needs no second party).
            session: boto3 Session passed through to the stores.
            ts: ISO-8601 timestamp; defaults to current UTC time.
            evidence: short free-text rationale for the ledger record.

        Returns:
            (updated_grant, tightening_record) — the record is already
            appended to the ledger.

        Raises:
            TransitionError: if the grant is already at in-loop (nothing to
                tighten — do not blindly re-tighten), or if requested_by is
                empty (accountability requires a named requester).
            GrantNotFoundError: if the grant does not exist in the store
                (tightening cannot create a grant).
            QuarantinedGrantError: if the re-read found the stored grant
                quarantined; it must not be written until the quarantine is
                resolved.
            GrantUpdateConflictError: if the grant changed since it was read
                (from the re-read, or from the conditional write losing the
                race); re-read and retry.
        """
        if grant.level is AutonomyLevel.in_loop:
            raise TransitionError(
                f"grant {grant.principal.agentId}/{grant.actionClass} is already "
                "at in-loop; nothing to tighten. Callers should not blindly "
                "re-tighten — re-read the grant before requesting tightening."
            )
        if not requested_by:
            raise TransitionError(
                "requested_by is required for tightening; "
                "accountability requires a named requester even for downward moves."
            )

        # Guarded re-read, mirroring apply_demotion. Quarantine is checked
        # FIRST: a quarantined read carries grant=None (#246 — tampered bytes
        # are never parsed), so the not-found check would otherwise mislabel a
        # tamper as absence.
        current = self._grant_store.get_grant(grant.principal, grant.actionClass)
        if current.quarantined:
            raise QuarantinedGrantError(
                f"grant {grant.principal.agentId}/{grant.actionClass} is "
                f"quarantined ({current.quarantine_reason}); it must not be "
                "written until the quarantine is resolved"
            )
        if current.grant is None:
            raise GrantNotFoundError(
                f"grant {grant.principal.agentId}/{grant.actionClass} not found "
                "in store; tightening cannot create a grant"
            )
        if current.grant != grant:
            # Content equality is the staleness check under the stored-bytes
            # basis (#246): identical fields ⇒ identical canonical bytes.
            raise GrantUpdateConflictError(
                f"grant {grant.principal.agentId}/{grant.actionClass} was "
                "modified since it was read; re-read and retry"
            )

        effective_ts = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
        from_level = grant.level

        updated = grant.model_copy(
            update={
                "level": AutonomyLevel.in_loop,
                "lastSafeLevel": AutonomyLevel.in_loop,
                "ts": effective_ts,
            }
        )
        record = PromotionRecord(
            recordType="tightening",
            actionClass=grant.actionClass,
            principal=grant.principal,
            fromLevel=from_level,
            toLevel=AutonomyLevel.in_loop,
            evidence=evidence,
            predicate=None,
            proposedBy=requested_by,
            ratifiedBy=requested_by,
            envelopeHash=grant.envelopeHash,
            ts=effective_ts,
            attestation=attestation_for(requested_by),
        )
        # Atomic record+grant (#244): the tightening and its ledger record
        # commit together or not at all — a failed unit leaves the grant at
        # its prior level with no ledger hole; the caller retries.
        self._grant_store.write_record_and_grant(
            record, updated, self._record_store, session, expected=current
        )

        return updated, record
