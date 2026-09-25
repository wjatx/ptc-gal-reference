"""Maker-checker promotion ceremony (#123).

The only path by which a Grant's level increases. Three actors:
  - proposer: submits evidence and proposes the promotion
  - ratifier: the distinct identity that ratifies — a human always, at high
              blast; below that threshold a pre-authored signed predicate may
              stand in (broker/grant-lifecycle.md §Promotion)
  - acceptance gate: deterministic — predicate=true plus the identity rules;
              nothing model-judged sits in the accept/reject decision

Flow:
  1. propose_promotion() validates inputs and returns a PromotionProposal
     (persistable between invocations via grants/proposals.py — propose and
     ratify are separate invocations by different identities).
  2. execute() re-validates the proposal's structural claims (it never trusts
     that propose_promotion ran — a proposal is plaintext staging), then runs
     the predicate gate and the deterministic acceptance gate.
  3. On accept: consume the stored proposal (if any), append the
     PromotionRecord, then write the Grant via the promotion-role session —
     create_grant for a Recommend-origin proposal, hash-conditioned
     update_grant from a guarded re-read for an existing grant (#190: never a
     blind put).
  4. On reject: return CeremonyResult(status='rejected'); no write.

The checker seam is where the sa#58 evidence reviewer plugs in later. It ships
OFF (checker=None) and NEVER gates: when present, its findings are RECORDED on
the CeremonyResult and appended into the PromotionRecord's predicate text — it
can raise suspicion and attach findings; it cannot license or veto
(docs/deterministic-gate.md). The checker itself is injected — this module
never selects or calls an LLM directly.

The agent's IAM identity must never reach this code path — that is an
infra-layer invariant enforced by IAM (broker/grant-lifecycle.md). Application-
layer enforcement: proposedBy != ratifiedBy is checked before any write; the
PromotionRecord schema enforces the same constraint as a structural backstop.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from safe_agents.broker.grants.predicate import (
    ActionClassMetrics,
    ProvenanceMaturity,
    evaluate_promotion_predicate,
)
from safe_agents.broker.ceremony_identity import attestation_for, is_same_operator
from safe_agents.broker.grants.ledger_clock import next_ledger_ts
from safe_agents.broker.grants.proposals import ProposalStore, proposal_expired
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.term import lapse_pending
from safe_agents.broker.grants.store import (
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
    RecordAlreadyExistsError,
    validate_record_ts,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.durations import validate_label_latency
from safe_agents.broker.schemas.grant import parse_certified_until
from safe_agents.broker.schemas.evidence import BlastClass, ConfidenceArtifact


# ---------------------------------------------------------------------------
# Rung ordering — promotion moves exactly one step forward
# ---------------------------------------------------------------------------

_RUNG_ORDER: list[AutonomyLevel] = [
    AutonomyLevel.in_loop,
    AutonomyLevel.on_loop,
    AutonomyLevel.out_of_loop,
]


def _one_rung_up(current: AutonomyLevel) -> AutonomyLevel:
    """Return the next autonomy rung above `current`.

    Raises ValueError if already at the top rung (out-of-loop). A promotion
    ceremony must always move exactly one step — no level-skipping.
    """
    idx = _RUNG_ORDER.index(current)
    if idx + 1 >= len(_RUNG_ORDER):
        raise ValueError(
            f"Cannot promote beyond {current.value!r}: already at the top rung."
        )
    return _RUNG_ORDER[idx + 1]


def _one_rung_violation(
    from_level: AutonomyLevel | None, target_level: AutonomyLevel
) -> str | None:
    """Describe the one-rung-rule violation, or None when the transition is valid.

    Shared by propose_promotion (raises ValueError) and execute() (rejects):
    the ceremony never trusts that a proposal came through propose_promotion,
    so execute re-derives the same rule. from_level=None is the Recommend rung,
    whose only valid target is in-loop (broker/grant-lifecycle.md).
    """
    if from_level is None:
        expected_target = AutonomyLevel.in_loop
    else:
        try:
            expected_target = _one_rung_up(from_level)
        except ValueError as exc:  # already at the top rung
            return str(exc)
    if target_level is not expected_target:
        from_label = from_level.value if from_level is not None else "Recommend"
        return (
            f"target_level must be exactly one rung above from_level: "
            f"from {from_label!r} the only valid target is {expected_target.value!r}, "
            f"got {target_level.value!r}. Level-skipping is not permitted."
        )
    return None


# ---------------------------------------------------------------------------
# Checker — the OPTIONAL evidence-reviewer seam (sa#58; ships OFF, never gates)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckerVerdict:
    """Structured findings from the optional evidence reviewer.

    The reviewer can raise suspicion and attach findings; it cannot license or
    veto (docs/deterministic-gate.md). execute() RECORDS this verdict — on the
    CeremonyResult and appended into the PromotionRecord's predicate text — and
    then decides acceptance from the deterministic gate alone.
    """

    findings: str
    suspicious: bool = False


@runtime_checkable
class CheckerProtocol(Protocol):
    """Injectable evidence reviewer — allows tests to stub the LLM call."""

    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        """Review the evidence and ceremony context; return findings.

        Returns a CheckerVerdict that is recorded, never gated on. The
        reviewer should be from a different model family than the proposing
        agent — enforced at construction time by the caller, not here.

        Raising is safe: execute() degrades any exception to a recorded
        ``reviewer_error:<Type>`` finding (suspicious=True) — reviewer failure
        is never a gate flip in either direction.
        """
        ...


# ---------------------------------------------------------------------------
# PromotionRecord store — injectable, parallels GrantStore
# ---------------------------------------------------------------------------


@runtime_checkable
class PromotionRecordStore(Protocol):
    """Injectable store for PromotionRecord persistence.

    Callers supply the boto3 Session (None for in-memory) — same posture as
    GrantStore: which IAM role is appropriate is the caller's job. The durable
    implementation is DynamoDBPromotionRecordStore in grants/store.py.
    """

    def put_record(
        self, record: PromotionRecord, session: object, signature: dict | None = None
    ) -> None:
        """Append one record.

        signature: optional DSSE envelope (grants/record_signing.py) stored
        BESIDE the record — a storage-layer attribute, never a field on the
        PromotionRecord schema (SCHEMAS.md §7 is frozen). None = an unsigned
        append, byte-for-byte the pre-signing behavior.
        """
        ...

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        """A coordinate's records in sk (chronological) order, by partition
        Query. Every writer reads it: the ledger clock (grants/ledger_clock.py)
        stamps each new record's ts from the coordinate's last one (#37)."""
        ...


class InMemoryPromotionRecordStore:
    """Fake PromotionRecord store for unit tests. Not thread-safe.

    Enforces the same append-only key rule as the DynamoDB store: a second
    record under the same (principal#actionClass, ts#recordType) key raises
    RecordAlreadyExistsError. An optional DSSE signature envelope is kept
    beside each record, mirroring the DynamoDB store's `signature` attribute.
    """

    def __init__(self) -> None:
        # (pk-equivalent, sk-equivalent) -> (data, signature) where data is the
        # CANONICAL record payload string — the same bytes the DynamoDB store
        # persists and the DSSE signature binds (#246 re-shape C). Dict
        # preserves insertion order.
        self._records: dict[tuple[str, str], tuple[str, dict | None]] = {}

    @staticmethod
    def _key(record: PromotionRecord) -> tuple[str, str]:
        p = record.principal
        return (
            f"{p.agentId}#{p.skill}#{p.user}#{p.tier}#{record.actionClass}",
            f"{record.ts}#{record.recordType}",
        )

    def put_record(
        self, record: PromotionRecord, session: object = None, signature: dict | None = None
    ) -> None:
        # Same rejection as the DynamoDB store: a non-canonical ts breaks the
        # sk's lexical-chronological ordering (store.validate_record_ts).
        validate_record_ts(record.ts)
        key = self._key(record)
        if key in self._records:
            raise RecordAlreadyExistsError(
                f"ledger record {key[0]}/{key[1]} already exists; "
                "the PromotionRecord ledger is append-only and never overwrites"
            )
        self._records[key] = (canonical_record_payload(record), signature)

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        """Records for (principal, action_class) in sk order (chronological),
        mirroring the DynamoDB Query; ts_prefix narrows to sk beginning with it."""
        pk = f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}#{action_class}"
        matched = [
            (sk, data)
            for (item_pk, sk), (data, _) in self._records.items()
            if item_pk == pk and (ts_prefix is None or sk.startswith(ts_prefix))
        ]
        return [
            PromotionRecord.model_validate_json(data)
            for _, data in sorted(matched, key=lambda pair: pair[0])
        ]

    @property
    def records(self) -> list[PromotionRecord]:
        return [
            PromotionRecord.model_validate_json(data)
            for data, _ in self._records.values()
        ]

    def signature_for(self, record: PromotionRecord) -> dict | None:
        """The DSSE envelope stored beside the record, or None (audit/test seam)."""
        stored = self._records.get(self._key(record))
        return stored[1] if stored is not None else None

    def stored_data_for(self, record: PromotionRecord) -> str | None:
        """The exact stored serialization — the verify basis (#246; audit/test seam)."""
        stored = self._records.get(self._key(record))
        return stored[0] if stored is not None else None


# ---------------------------------------------------------------------------
# Proposal — staging record returned by propose_promotion
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromotionProposal:
    """Pending promotion, returned by propose_promotion() and passed to execute().

    Immutable: once proposed, the inputs are fixed. The predicate config
    (metrics, window_n, min_observations, threshold) is caller-supplied and
    pre-fetched — this module never reads from DynamoDB.

    proposal_id / expires_at exist because propose and ratify are separate
    invocations by different identities (maker ≠ checker is structural):
    the proposal persists in a ProposalStore between them (grants/proposals.py).
    The mutable status ("pending"/"ratified"/"rejected") lives on the STORED
    item, never here — this dataclass is the immutable proposal content.

    from_level=None is the Recommend rung (no grant exists yet): the ceremony
    CREATES the grant, and the only valid target is in-loop
    (broker/grant-lifecycle.md).
    """

    # durable-proposal identity: caller-supplied opaque id + ISO-8601 UTC expiry
    proposal_id: str
    expires_at: str
    principal: Principal
    action_class: str
    from_level: AutonomyLevel | None
    target_level: AutonomyLevel
    evidence_bundle: str
    proposer_id: str
    owner_id: str
    # grant fields passed through to the raised Grant
    envelope_hash: str
    label_latency: str
    demotion_triggers: list[DemotionTrigger]
    last_safe_level: AutonomyLevel
    # pre-fetched predicate inputs
    metrics: ActionClassMetrics
    window_n: int
    min_observations: int
    threshold: float
    # evidence terms threaded to the predicate (sa#57)
    artifact: ConfidenceArtifact | None
    covered: bool
    provenance_maturity: ProvenanceMaturity
    blast_class: BlastClass
    error_budget: ErrorBudget | None
    # Period span the pre-fetched metrics were summed over (#193, periods #212).
    # Provenance only — ratify never re-reads counters, so this is NOT a
    # predicate input; it rides the proposal so the checker can see whether the
    # sample was earned over a few periods or scraped thin across many, and at
    # WHICH period the evidence was bucketed. Defaults (1, "utc-day") make a
    # pre-#193/#212 stored proposal still load and ratify.
    window_periods: int = 1
    period: str = "utc-day"
    # GAL §6.7.6 (#255): the certification term the raised grant will carry,
    # an ISO-8601 UTC instant, or None for no term (the default — terms ship
    # unset). It is part of the proposal content, so it rides the proposal's
    # integrity basis and is what the checker ratifies; the ceremony is the
    # ONLY path that sets a term.
    certified_until: str | None = None


# ---------------------------------------------------------------------------
# Ceremony result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CeremonyResult:
    """Outcome of a promotion ceremony.

    status:
      'ratified' — the deterministic gate passed; grant and PromotionRecord
                   were written.
      'rejected' — the gate failed; no grant was written.

    promotion_record is set iff status == 'ratified'. checker_verdict carries
    the optional reviewer's recorded findings (None when no checker is
    configured or the ceremony rejected before the reviewer ran) — findings
    are attached, never gated on.
    """

    status: Literal["ratified", "rejected"]
    reason: str
    promotion_record: PromotionRecord | None = None
    checker_verdict: CheckerVerdict | None = None


# ---------------------------------------------------------------------------
# The ceremony
# ---------------------------------------------------------------------------


class PromotionCeremony:
    """Maker-checker promotion ceremony.

    Wires together the predicate, grant store write, and PromotionRecord
    persistence under a single deterministic decision rule:

        predicate=True AND the identity rules hold  ->  accept
        anything else                               ->  reject

    The optional checker (the sa#58 evidence reviewer seam, ships OFF) is
    invoked when configured and its findings are RECORDED — it never gates
    (docs/deterministic-gate.md).

    The ceremony enforces proposedBy != ratifiedBy before any write. The
    PromotionRecord schema provides a structural backstop for the same rule.
    """

    def __init__(
        self,
        *,
        grant_store: GrantStore,
        promotion_record_store: PromotionRecordStore,
        checker: CheckerProtocol | None = None,
        record_signer: object = None,
    ) -> None:
        self._grant_store = grant_store
        self._record_store = promotion_record_store
        self._checker = checker
        # The issuer RecordSigner (grants/record_signing.py) or None. Signing
        # is ceremony-side since #244: the record is signed BEFORE the atomic
        # record+grant write, and the signature rides the same transact leg —
        # replacing the old SigningPromotionRecordStore put_record wrapper,
        # which the atomic write path cannot route through.
        self._record_signer = record_signer

    def sign_record(self, record: PromotionRecord) -> dict | None:
        """Sign a record with the configured ISSUER signer, or None if unset.

        Public because the ceremony is not the only issuer-side writer: the
        tightening path (``rung.tighten_to_in_loop``) writes a
        ``tightening``-typed record under the same operator identity and must
        reach the same key rather than growing a second signer of its own.
        """
        return (
            self._record_signer.sign_record(record)
            if self._record_signer is not None
            else None
        )

    # ------------------------------------------------------------------
    # Phase 1 — proposal
    # ------------------------------------------------------------------

    @staticmethod
    def propose_promotion(
        principal: Principal,
        action_class: str,
        target_level: AutonomyLevel,
        evidence_bundle: str,
        proposer_id: str,
        *,
        proposal_id: str,
        expires_at: str,
        owner_id: str,
        from_level: AutonomyLevel | None,
        envelope_hash: str,
        label_latency: str,
        demotion_triggers: list[DemotionTrigger],
        last_safe_level: AutonomyLevel,
        metrics: ActionClassMetrics,
        window_n: int,
        min_observations: int,
        threshold: float,
        artifact: ConfidenceArtifact | None,
        covered: bool,
        provenance_maturity: ProvenanceMaturity,
        blast_class: BlastClass,
        error_budget: ErrorBudget | None,
        window_periods: int = 1,
        period: str = "utc-day",
        certified_until: str | None = None,
    ) -> PromotionProposal:
        """Validate inputs and return a PromotionProposal.

        Rejected immediately (raises ValueError) if:
          - owner_id is empty: a promotion without a named owner is refused
            before any checker is invoked.
          - proposal_id or expires_at is empty: the durable-proposal identity
            and deterministic expiry are both required.
          - target_level is not exactly one rung above from_level: level-
            skipping is never permitted. from_level=None is the Recommend
            rung, whose only valid target is in-loop.
          - label_latency is not a valid nonnegative, calendar-unambiguous
            ISO-8601 duration (sa#214): the maker is refused here, before any
            checker is summoned; the Grant validator backstops the mint path.
          - certified_until is given but is not an explicit UTC ISO-8601
            instant (#255). Whether it is still in the future is judged at
            ratify time against the ratification instant, not here.

        On success the caller should pass the returned proposal to execute().
        """
        validate_label_latency(label_latency)
        if certified_until is not None:
            parse_certified_until(certified_until)
        if not owner_id:
            raise ValueError(
                "owner_id is required; a promotion without a named owner is rejected "
                "before reaching the checker."
            )
        if not proposal_id or not expires_at:
            raise ValueError(
                "proposal_id and expires_at are both required; a proposal without a "
                "durable identity or a deterministic expiry cannot be ratified."
            )

        violation = _one_rung_violation(from_level, target_level)
        if violation is not None:
            raise ValueError(violation)

        return PromotionProposal(
            proposal_id=proposal_id,
            expires_at=expires_at,
            principal=principal,
            action_class=action_class,
            from_level=from_level,
            target_level=target_level,
            evidence_bundle=evidence_bundle,
            proposer_id=proposer_id,
            owner_id=owner_id,
            envelope_hash=envelope_hash,
            label_latency=label_latency,
            demotion_triggers=list(demotion_triggers),
            last_safe_level=last_safe_level,
            metrics=metrics,
            window_n=window_n,
            min_observations=min_observations,
            threshold=threshold,
            # sa#57 evidence terms — stored verbatim; execute() threads them
            # to evaluate_promotion_predicate
            artifact=artifact,
            covered=covered,
            provenance_maturity=provenance_maturity,
            blast_class=blast_class,
            error_budget=error_budget,
            window_periods=window_periods,
            period=period,
            certified_until=certified_until,
        )

    # ------------------------------------------------------------------
    # Phase 2 — execute (predicate gate → checker → acceptance gate → write)
    # ------------------------------------------------------------------

    def execute(
        self,
        proposal: PromotionProposal,
        ratifier_id: str,
        *,
        session: object = None,
        proposal_store: ProposalStore | None = None,
        now: datetime.datetime | None = None,
        ratifier_kind: Literal["human", "predicate"] = "human",
    ) -> CeremonyResult:
        """Run the full maker-checker ceremony for the given proposal.

        execute never trusts the proposal's own claims: the one-rung rule and
        the owner check are re-derived here before anything else runs, because
        a PromotionProposal is plaintext staging — built directly, or a
        PROPOSAL# item edited in the table — and propose_promotion may never
        have seen it. A structural violation rejects; no write.

        Persistence is split by origin (#190 — no blind puts on any ceremony
        path). Recommend-origin (from_level=None) CREATES via create_grant (a
        concurrently-minted grant surfaces as GrantAlreadyExistsError, never
        overwritten). An existing grant gets a guarded re-read — quarantine
        refused loudly; a stored level differing from proposal.from_level is a
        premise change (e.g. a demotion landed between propose and ratify) and
        rejects the ceremony — then a hash-conditioned update_grant whose
        GrantUpdateConflictError propagates, never retried silently: that IS
        the demotion-race protection.

        The record and the grant commit as ONE atomic unit (#244,
        write_record_and_grant): either both legs land or nothing is written.
        This supersedes the old record-first ordering — the per-path
        failure-polarity trade-offs (dangling record vs. unaccounted level)
        existed only because the pair could be interrupted between writes;
        atomically there is no between. A failed unit leaves the ledger and
        the grant exactly as they were — re-read and re-propose.

        Args:
            proposal: returned by propose_promotion() — but re-validated here
                regardless (see above).
            ratifier_id: the ratifier's identity ID (ratifiedBy).
                Must differ from proposal.proposer_id; checked before any write.
            session: boto3 Session carrying the promotion IAM role. Passed
                through to the stores; None is accepted by the in-memory
                fakes (tests). The ceremony never assumes a role.
            proposal_store: when supplied, the stored proposal is consumed
                (status -> 'ratified') BEFORE the ledger append and grant
                write — the single-shot flip kills the double-ratify race
                (ProposalConsumedError propagates). A consumed proposal stays
                burned even if the grant write then conflicts (safe polarity:
                no replay; propose afresh). WITHOUT a store, single-shot
                burning is the CALLER's responsibility — the command surface
                always passes a store; None keeps the in-memory flow for
                embedded/test callers only.
            now: the expiry-evaluation instant (deterministic expiry); defaults
                to current UTC. An expired proposal is ALWAYS rejected,
                storeless or not — expires_at lives on the proposal itself.
            ratifier_kind: whether the ratifier is a human or a pre-authored
                signed predicate standing in below the high-blast threshold.
                High blast (requires_human_ratification on the predicate
                result) is ALWAYS ratified per-instance by a human
                (broker/grant-lifecycle.md §Promotion); a non-human ratifier
                there rejects before any write.

        Returns:
            CeremonyResult with status 'ratified' or 'rejected'.

        Raises:
            QuarantinedGrantError, GrantUpdateConflictError,
            GrantAlreadyExistsError, ProposalConsumedError — see above; all
            propagate, none are retried here.
        """
        # --- structural re-validation (never trust the proposal's claims) ---
        if not proposal.owner_id:
            return CeremonyResult(
                status="rejected",
                reason=(
                    "owner_id is required; a promotion without a named owner is "
                    "rejected before any gate runs."
                ),
            )
        violation = _one_rung_violation(proposal.from_level, proposal.target_level)
        if violation is not None:
            return CeremonyResult(status="rejected", reason=violation)

        # --- deterministic expiry (unconditional: expires_at is ON the proposal) ---
        effective_now = now or datetime.datetime.now(datetime.timezone.utc)
        if proposal_expired(proposal.expires_at, effective_now):
            return CeremonyResult(
                status="rejected",
                reason=(
                    f"proposal {proposal.proposal_id} expired at "
                    f"{proposal.expires_at}; propose afresh from the current state."
                ),
            )

        # Naive instants read as UTC, the same rule proposal_expired applies.
        term_now = (
            effective_now
            if effective_now.tzinfo is not None
            else effective_now.replace(tzinfo=datetime.timezone.utc)
        )

        # --- certification term (#255): must be a UTC instant still ahead of
        # the ratification instant. A term already passed would mint a grant
        # that is lapsed on arrival — refuse rather than write a no-op raise.
        if proposal.certified_until is not None:
            try:
                term_end = parse_certified_until(proposal.certified_until)
            except ValueError as exc:
                return CeremonyResult(status="rejected", reason=str(exc))
            if term_now >= term_end:
                return CeremonyResult(
                    status="rejected",
                    reason=(
                        f"certifiedUntil {proposal.certified_until} is not after the "
                        f"ratification instant {term_now.isoformat()}; the "
                        "grant would be lapsed on arrival. Propose afresh with a "
                        "term in the future, or none."
                    ),
                )

        # --- maker != checker (application layer; schema is the backstop) ---
        # is_same_operator, not ==: on the local (solo) arm two identities that
        # share a ROLE are the same half of the ceremony run twice, even when
        # their derived user@host halves drifted apart (#226).
        if is_same_operator(proposal.proposer_id, ratifier_id):
            return CeremonyResult(
                status="rejected",
                reason=(
                    f"proposedBy and ratifiedBy must differ: got {ratifier_id!r} for both. "
                    "Widening autonomy requires maker != checker."
                ),
            )

        # --- the predicate gate (deterministic, no LLM, no I/O) ---
        predicate_result = evaluate_promotion_predicate(
            proposal.principal,
            proposal.action_class,
            metrics=proposal.metrics,
            window_n=proposal.window_n,
            min_observations=proposal.min_observations,
            threshold=proposal.threshold,
            target_level=proposal.target_level,
            artifact=proposal.artifact,
            covered=proposal.covered,
            provenance_maturity=proposal.provenance_maturity,
            blast_class=proposal.blast_class,
            error_budget=proposal.error_budget,
        )

        if not predicate_result.eligible:
            return CeremonyResult(
                status="rejected",
                reason=f"predicate gate failed: {predicate_result.reason}",
            )

        # --- high blast is ALWAYS ratified per-instance by a human ---
        if predicate_result.requires_human_ratification and ratifier_kind != "human":
            return CeremonyResult(
                status="rejected",
                reason=(
                    f"high-blast promotion requires per-instance human ratification: "
                    f"ratifier_kind={ratifier_kind!r} cannot stand in "
                    "(a pre-authored predicate is only valid below the high-blast "
                    "threshold, broker/grant-lifecycle.md §Promotion)."
                ),
            )

        # --- optional evidence reviewer: findings are RECORDED, never gated on ---
        checker_verdict: CheckerVerdict | None = None
        if self._checker is not None:
            try:
                checker_verdict = self._checker.check(
                    proposal.evidence_bundle,
                    context={
                        "principal": proposal.principal.model_dump(),
                        "action_class": proposal.action_class,
                        # None = the Recommend rung (a rung but never a level value)
                        "from_level": (
                            proposal.from_level.value if proposal.from_level is not None else None
                        ),
                        "target_level": proposal.target_level.value,
                        "predicate_reason": predicate_result.reason,
                    },
                )
            except Exception as exc:  # noqa: BLE001 — ANY reviewer failure degrades
                # A raising reviewer must not abort the ceremony: that would be
                # a de-facto veto, flipping the gate on reviewer availability
                # (sa#58: never a gate flip in either direction). The failure is
                # itself signal — recorded as a suspicious finding for the human
                # ratifier. Only the exception TYPE reaches the record: the
                # predicate text is a trusted, signed surface and an exception
                # message could embed reviewer/evidence-derived content.
                checker_verdict = CheckerVerdict(
                    findings=f"reviewer_error:{type(exc).__name__}", suspicious=True
                )

        # --- acceptance gate passed; write the records ---
        # The ledger clock, not the raw wall clock (#37): strictly after the
        # coordinate's last record, so a same-tick write neither collides nor
        # sorts out of order. Stamped before the record is built and signed.
        ts = next_ledger_ts(
            self._record_store, proposal.principal, proposal.action_class, session=session
        )

        predicate_text = predicate_result.reason
        if checker_verdict is not None:
            suffix = " [suspicion raised]" if checker_verdict.suspicious else ""
            predicate_text += f"; reviewer findings{suffix}: {checker_verdict.findings}"

        # PromotionRecord: proposedBy != ratifiedBy enforced by schema validator
        promotion_record = PromotionRecord(
            recordType="promotion",
            actionClass=proposal.action_class,
            principal=proposal.principal,
            fromLevel=proposal.from_level,
            toLevel=proposal.target_level,
            evidence=proposal.evidence_bundle,
            predicate=predicate_text,
            proposedBy=proposal.proposer_id,
            ratifiedBy=ratifier_id,
            envelopeHash=proposal.envelope_hash,
            ts=ts,
            attestation=attestation_for(ratifier_id),
            # The ratified term (#255), on the SIGNED record: what the checker
            # ratified is non-repudiable, and the audit holds the grant to it
            # (GRANT_TERM_RATIFIED).
            certifiedUntil=proposal.certified_until,
        )

        # Grant: level is raised to target_level; promotedBy and evidence link
        # back to the PromotionRecord (the accountability trail).
        raised_grant = Grant(
            principal=proposal.principal,
            actionClass=proposal.action_class,
            level=proposal.target_level,
            envelopeHash=proposal.envelope_hash,
            promotedBy=ratifier_id,
            evidence=proposal.evidence_bundle,
            ts=ts,
            lastSafeLevel=proposal.last_safe_level,
            demotionTriggers=proposal.demotion_triggers,
            demotionReason=None,
            labelLatency=proposal.label_latency,
            ownerId=proposal.owner_id,
            # The ONE place a term is set (#255): re-promotion carries the
            # newly ratified term, or none — never the old one.
            certifiedUntil=proposal.certified_until,
        )

        if proposal.from_level is None:
            # Recommend-origin: the grant-creating first promotion. The
            # attribute_not_exists condition on the grant leg is the race
            # guard — a concurrently-minted grant surfaces loudly, and the
            # record leg cancels with it (#244: both or nothing).
            self._consume_proposal(proposal, proposal_store, session)
            self._grant_store.write_record_and_grant(
                promotion_record,
                raised_grant,
                self._record_store,
                session,
                signature=self.sign_record(promotion_record),
                expected=None,
            )
        else:
            # Existing grant: guarded re-read (mirrors tighten_to_in_loop).
            # Quarantine is checked before anything else — writing over a
            # tampered grant would launder it under a fresh valid hash.
            current = self._grant_store.get_grant(
                proposal.principal, proposal.action_class
            )
            if current.quarantined:
                # Checked FIRST: a quarantined read carries grant=None (#246),
                # so the not-found check would otherwise mislabel a tamper as
                # absence and invite a re-propose over the evidence.
                raise QuarantinedGrantError(
                    f"grant {proposal.principal.agentId}/{proposal.action_class} is "
                    f"quarantined ({current.quarantine_reason}); it must not be "
                    "promoted until the quarantine is resolved"
                )
            if current.grant is None:
                raise GrantUpdateConflictError(
                    f"grant {proposal.principal.agentId}/{proposal.action_class} not "
                    "found; the proposal was evaluated against a grant that no longer "
                    "exists — re-propose from the current state"
                )
            if lapse_pending(current.grant, term_now):
                # #255: the stored grant's term has passed but its lapse has
                # not been written. Enforcement already treats it as being at
                # lastSafeLevel, so promoting from the STORED level would raise
                # it past its lapsed certification, and promoting from
                # lastSafeLevel would leave the ledger with an unrecorded drop.
                # The lapse is recorded first, by the system evaluator.
                return CeremonyResult(
                    status="rejected",
                    reason=(
                        f"premise changed: the grant's certification term "
                        f"{current.grant.certifiedUntil} has passed, so it acts at "
                        f"{current.grant.lastSafeLevel.value!r}, but its lapse is not "
                        "yet recorded. Run the lapse evaluator "
                        "(python -m safe_agents.broker.grants.runner), then "
                        "re-propose from the lapsed level."
                    ),
                )
            if current.grant.level is not proposal.from_level:
                # Premise changed: a level change (e.g. an automatic demotion)
                # landed between propose and ratify. Ratifying anyway would
                # silently RAISE the level past what the evidence licensed.
                return CeremonyResult(
                    status="rejected",
                    reason=(
                        f"premise changed: the proposal was evaluated at level "
                        f"{proposal.from_level.value!r} but the stored grant is now at "
                        f"{current.grant.level.value!r}; re-propose from the current state."
                    ),
                )
            self._consume_proposal(proposal, proposal_store, session)
            # Atomic record+grant (#244), hash-conditioned from the guarded
            # re-read: a demotion racing in after the re-read surfaces as
            # GrantUpdateConflictError with the record leg canceled — nothing
            # written.
            self._grant_store.write_record_and_grant(
                promotion_record,
                raised_grant,
                self._record_store,
                session,
                signature=self.sign_record(promotion_record),
                expected=current,
            )

        reason = f"predicate passed; ratified by {ratifier_id}"
        if checker_verdict is not None:
            suffix = " [suspicion raised]" if checker_verdict.suspicious else ""
            reason += f"; reviewer findings{suffix}: {checker_verdict.findings}"
        return CeremonyResult(
            status="ratified",
            reason=reason,
            promotion_record=promotion_record,
            checker_verdict=checker_verdict,
        )

    @staticmethod
    def _consume_proposal(
        proposal: PromotionProposal,
        proposal_store: ProposalStore | None,
        session: object,
    ) -> None:
        """Flip the stored proposal to 'ratified' (single-shot) before the grant write."""
        if proposal_store is None:
            return
        proposal_store.consume_proposal(
            proposal.principal,
            proposal.action_class,
            proposal.proposal_id,
            "ratified",
            session=session,
        )
