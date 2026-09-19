"""broker.grants — grant store client, promotion predicate, ceremony,
demotion evaluator, and rung state machine.

Public surfaces:

  audit     — the read-only grant-integrity auditor (#62). Pure rules over a
              loaded AuditDataset → typed AuditReport; the only AWS call in
              the module is load_dataset's paginated Scan. Keyless mode (no
              HMAC key — the CI identity) skips HMAC rules LOUDLY.

  store     — the grant store client: injectable Protocol + InMemory fake for
              tests + DynamoDB implementation for production. Callers supply
              the boto3 Session; this package does NOT manage role assumption.

  proposals — the durable promotion-proposal store (#123). propose and ratify
              are separate invocations by different identities (maker ≠
              checker is structural), so the PromotionProposal persists
              between them; conditional single-shot consumption kills the
              double-ratify race.

  predicate — the deterministic promotion predicate (sa#57). Pure function;
              no I/O, no LLM. Takes pre-fetched metrics, returns a
              PredicateResult with eligible bool + reason string.

  ceremony  — the maker-checker promotion ceremony (#123). The only path by
              which a Grant's level increases. Wires together the predicate
              and the grant store write under a deterministic acceptance
              gate; the optional checker seam (the sa#58 evidence reviewer,
              ships OFF) attaches findings but never gates.

  rung      — the autonomy rung state machine (sa#60). Validates and
              orchestrates all level transitions; enforces hysteresis. Pure
              validation functions + RungStateMachine coordinator. No DynamoDB
              dependency.

  term / lapse — the certification term (#255, GAL §6.7.6). ``term`` is pure:
              whether a term has passed at an EXPLICIT instant, and the
              effective level enforcement acts on. ``lapse`` writes the
              lapse-typed record under the system evaluator identity.

  record_signing — DSSE signing of the PromotionRecord ledger (the #181
              machinery's second statement type). The ISSUER's key, never the
              broker's; the envelope is stored beside the ledger blob, never
              on the schema. Pure and key-injected.

See broker/SCHEMAS.md and broker/grant-lifecycle.md for the broader context.
"""

from .audit import (
    ACKNOWLEDGMENT_NOT_WAIVABLE,
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    GRANT_ENVELOPE_IN_FORCE,
    GRANT_TAMPER,
    GRANT_TERM_RATIFIED,
    HMAC_RULES,
    LEDGER_COUNTERPART,
    LEVEL_DROP_RECORDED,
    LEVEL_LEDGER_CONSISTENT,
    PROPOSAL_LIFECYCLE,
    PROPOSAL_TAMPER,
    QUARANTINED_NO_RAISE,
    RECORD_SIGNATURE_VERIFIES,
    UNPARSEABLE_ITEM,
    AcknowledgedFinding,
    AuditDataset,
    AuditedAcknowledgment,
    AuditedEnvelope,
    AuditedGrant,
    AuditedProposal,
    AuditedRecord,
    AuditReport,
    AuditViolation,
    dataset_from_items,
    load_dataset,
    load_dataset_sqlite,
    run_audit,
)

# NB `audit_command` is deliberately NOT re-exported here, for the same reason
# `commands` is not: both are `python -m` entry points, and importing one from
# the package __init__ makes runpy load it twice and warn on every operator run.

from .ceremony import (
    CeremonyResult,
    CheckerProtocol,
    CheckerVerdict,
    InMemoryPromotionRecordStore,
    PromotionCeremony,
    PromotionProposal,
    PromotionRecordStore,
)
from .lapse import (
    LapseConflictError,
    LapseNotDueError,
    LapseOutcome,
    apply_lapse,
    build_lapse,
    run_lapse,
)
from .predicate import ActionClassMetrics, PredicateResult, evaluate_promotion_predicate
from .record_signing import (
    EVALUATOR_ROLE,
    ISSUER_ROLE,
    RECORD_PREDICATE_TYPE,
    RECORD_ROLE_UNRESOLVED,
    RECORD_SIGNATURE_INVALID,
    RECORD_SIGNATURE_MALFORMED,
    RECORD_SIGNATURE_MISSING,
    RECORD_SIGNER_ROLE_AMBIGUOUS,
    RECORD_SIGNER_UNKNOWN,
    RECORD_SIGNER_WRONG_ROLE,
    RECORD_TYPE_SIGNING_ROLE,
    RecordSigner,
    RecordVerifyResult,
    RoleKeyResolvers,
    build_record_statement,
    canonical_record_bytes,
    canonical_record_payload,
    signer_from_pem,
    signing_role_for_record_type,
    stored_record_digest_hex,
    verify_record,
    verify_record_by_type,
)
from .proposals import (
    DynamoDBProposalStore,
    InMemoryProposalStore,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    ProposalIntegrityError,
    ProposalStore,
    compute_proposal_hash,
    proposal_expired,
    reject_proposal,
)
from .runner import (
    DemotionLedgerStore,
    RunnerOutcome,
    derive_budget_breach,
    metrics_from_signals,
    run_demotion,
)
from .rung import (
    PromotionEligibilityCounters,
    RungStateMachine,
    TransitionError,
    is_eligible_for_promotion,
    validate_demotion_transition,
    validate_promotion_transition,
)
from .store import (
    DynamoDBGrantStore,
    DynamoDBPromotionRecordStore,
    GrantAlreadyExistsError,
    GrantReadResult,
    GrantStore,
    GrantUpdateConflictError,
    InMemoryGrantStore,
    RecordAlreadyExistsError,
    RecordTimestampFormatError,
    TermExtensionRefusedError,
    canonical_grant_payload,
    compute_grant_hash,
    refuse_term_extension,
    validate_record_ts,
)
from .term import effective_level, extends_term, lapse_pending, term_passed

__all__ = [
    # audit
    "ACKNOWLEDGMENT_NOT_WAIVABLE",
    "ACKNOWLEDGMENT_SIGNATURE_VERIFIES",
    "GRANT_ENVELOPE_IN_FORCE",
    "GRANT_TAMPER",
    "GRANT_TERM_RATIFIED",
    "HMAC_RULES",
    "LEDGER_COUNTERPART",
    "LEVEL_DROP_RECORDED",
    "LEVEL_LEDGER_CONSISTENT",
    "PROPOSAL_LIFECYCLE",
    "PROPOSAL_TAMPER",
    "QUARANTINED_NO_RAISE",
    "RECORD_SIGNATURE_VERIFIES",
    "UNPARSEABLE_ITEM",
    "AuditDataset",
    "AcknowledgedFinding",
    "AuditedAcknowledgment",
    "AuditedEnvelope",
    "AuditedGrant",
    "AuditedProposal",
    "AuditedRecord",
    "AuditReport",
    "AuditViolation",
    "dataset_from_items",
    "load_dataset",
    "load_dataset_sqlite",
    "run_audit",
    # record_signing
    "RECORD_PREDICATE_TYPE",
    "RECORD_SIGNATURE_INVALID",
    "RECORD_SIGNATURE_MALFORMED",
    "RECORD_SIGNATURE_MISSING",
    "RECORD_SIGNER_UNKNOWN",
    "EVALUATOR_ROLE",
    "ISSUER_ROLE",
    "RECORD_ROLE_UNRESOLVED",
    "RECORD_SIGNER_ROLE_AMBIGUOUS",
    "RECORD_SIGNER_WRONG_ROLE",
    "RECORD_TYPE_SIGNING_ROLE",
    "RoleKeyResolvers",
    "signing_role_for_record_type",
    "verify_record_by_type",
    "RecordSigner",
    "RecordVerifyResult",
    "build_record_statement",
    "canonical_record_bytes",
    "canonical_record_payload",
    "signer_from_pem",
    "stored_record_digest_hex",
    "verify_record",
    # store
    "GrantStore",
    "GrantReadResult",
    "GrantAlreadyExistsError",
    "GrantUpdateConflictError",
    "InMemoryGrantStore",
    "DynamoDBGrantStore",
    "DynamoDBPromotionRecordStore",
    "RecordAlreadyExistsError",
    "RecordTimestampFormatError",
    "TermExtensionRefusedError",
    "canonical_grant_payload",
    "compute_grant_hash",
    "refuse_term_extension",
    "validate_record_ts",
    # certification term + lapse (#255)
    "effective_level",
    "extends_term",
    "lapse_pending",
    "term_passed",
    "LapseConflictError",
    "LapseNotDueError",
    "LapseOutcome",
    "apply_lapse",
    "build_lapse",
    "run_lapse",
    # proposals
    "ProposalStore",
    "InMemoryProposalStore",
    "DynamoDBProposalStore",
    "ProposalAlreadyExistsError",
    "ProposalConsumedError",
    "ProposalIntegrityError",
    "compute_proposal_hash",
    "proposal_expired",
    "reject_proposal",
    # predicate
    "ActionClassMetrics",
    "PredicateResult",
    "evaluate_promotion_predicate",
    # ceremony
    "CeremonyResult",
    "CheckerProtocol",
    "CheckerVerdict",
    "InMemoryPromotionRecordStore",
    "PromotionCeremony",
    "PromotionProposal",
    "PromotionRecordStore",
    # rung state machine
    "TransitionError",
    "PromotionEligibilityCounters",
    "validate_promotion_transition",
    "validate_demotion_transition",
    "is_eligible_for_promotion",
    "RungStateMachine",
    # demotion runner
    "DemotionLedgerStore",
    "RunnerOutcome",
    "metrics_from_signals",
    "derive_budget_breach",
    "run_demotion",
]
