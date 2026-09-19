"""Grant-ceremony command surface (#123) — the store's only sanctioned mutation path.

    python -m safe_agents.broker.grants.commands {seed,re-seed,propose,ratify,reject,acknowledge,tighten}

seed      the sanctioned bootstrap: manifest-driven floor grants, each paired with
          a bootstrap-typed PromotionRecord from birth (maker != checker is
          deliberately NOT enforced — the single-operator seed is sanctioned).
          Bootstrap records are ISSUER-signed when a signing key is configured.
re-seed   the re-attestation ceremony after a far-jump envelope-hash change:
          re-stamps HMAC-clean grants under the NEW in-force hash at the SAME
          level, under human ratification. An HMAC-tamper quarantine is NEVER
          re-attestable (an incident, not a ceremony).
propose   the maker: builds a PromotionProposal from declared config + durable
          evidence counters, runs the predicate for early feedback, and stores
          it (an ineligible proposal is refused, never stored).
ratify    the checker: loads the integrity-verified proposal and runs the full
          maker-checker ceremony (one-shot proposal burn, one-rung rule,
          high-blast human ratification). On accept the PromotionRecord is
          DSSE-signed by the issuer key when configured (grants/issuer_keys.py;
          unset = REFUSE, unless --allow-unsigned explicitly opts into storing
          an UNSIGNED record with a LOUD warning).
reject    the checker declines: flips the stored proposal to 'rejected' — the
          single-shot burn; a rejected proposal can never be ratified.
acknowledge  disposition a TRUE audit finding (#196): appends a signed waiver
          record bound to the exact finding fingerprint — never edits the
          flagged item; refuses un-waivable rules and refuses unsigned.
tighten   voluntary tightening: any level -> in-loop, always permitted — no
          ceremony, no fired trigger (rung.tighten_to_in_loop). Appends a
          tightening-typed PromotionRecord, ISSUER-signed when a signing key is
          configured (GAL-SPEC §6.10); a quarantined grant is NEVER written over.

Identity is DERIVED, never asserted: proposedBy / ratifiedBy / seededBy come
from STS GetCallerIdentity (the full Arn, which carries the role session name).
There is no --as flag; maker != checker therefore compares actual credential
identities. Self-promotion is structurally impossible: the agent role cannot
assume PromotionRole and holds no grant-table writes (infra/lib/identity-stack.ts),
so the agent's credentials can never reach a ceremony write — the commands run
under whatever credentials the caller holds (PromotionRole in production) and
never assume a role themselves, matching grants/runner.py.

No domain defaults are baked anywhere: every threshold / window / TTL is a
required flag. The consumer declares the ToolOp blast facts
(--effect/--external/--reversible) on the command line for now — joining them
from the manifest's ``tool_ops`` block is a later slice.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import uuid
from pathlib import Path

from pydantic import ValidationError

from safe_agents.broker.enforcement import (
    EnforcementStore,
    current_period_bucket,
    read_counter_window,
    scoped_counter_key,
)
from safe_agents.broker.grants._commands_common import (
    _build_ack_store,
    _build_proposal_store,
    _manifest_context,
    _parse_args,
    _resolve_envelope_hash,
)
from safe_agents.broker.grants.acknowledgments import (
    AcknowledgmentAlreadyExistsError,
    AcknowledgmentRecord,
    WAIVABLE_RULES,
    sign_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.ceremony import (
    CheckerProtocol,
    PromotionCeremony,
    PromotionRecordStore,
)
from safe_agents.broker.grants.issuer_keys import (
    IssuerSigningConfigError,
    resolve_record_signer,
)
from safe_agents.broker.grants.predicate import (
    ActionClassMetrics,
    evaluate_promotion_predicate,
)
from safe_agents.broker.grants.proposals import (
    ProposalConsumedError,
    ProposalIntegrityError,
    ProposalStore,
    reject_proposal,
)
from safe_agents.broker.ceremony_identity import (
    SOLO_ATTESTATION_NOTICE,
    attestation_for,
    is_local_identity,
    resolve_ceremony_identity,
)
from safe_agents.broker.grants.record_signing import RecordSigner
from safe_agents.broker.prototype.boot_config import BrokerConfigError
from safe_agents.broker.grants.runner import (
    RunnerConfigError,
    _build_enforcement_store,
    _build_stores,
)
from safe_agents.broker.grants.demotion import GrantNotFoundError
from safe_agents.broker.grants.rung import RungStateMachine, TransitionError
from safe_agents.broker.grants.term import lapse_pending
from safe_agents.broker.grants.store import (
    GrantAlreadyExistsError,
    GrantStore,
    GrantUpdateConflictError,
    QuarantinedGrantError,
    RecordAlreadyExistsError,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.brokered_call import ToolOp
from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, effective_blast_class

# ---------------------------------------------------------------------------
# Evidence-counter suffixes — the durable scoped counters propose reads (same
# scoped_counter_key derivation as the PEP, so evidence and enforcement can
# never disagree about the coordinate). Since #193 the PEP WRITES the
# observations/human_override labels (pep.py executor closures + reject_intent)
# so the constants live beside scoped_counter_key in enforcement.store; the
# re-export here keeps existing readers working. false_action still has no
# writer (its review surface is a deliberate later design conversation);
# absence reads as 0. ERROR_BUDGET_SUFFIX is the counter the PEP already
# meters (#184; runner.derive_budget_breach reads it).
# ---------------------------------------------------------------------------
from safe_agents.broker.enforcement.store import (
    ERROR_BUDGET_SUFFIX,
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
)


# ---------------------------------------------------------------------------
# Optional evidence reviewer (sa#58) — ships OFF; findings-attach-never-gate.
# The env var selects a kind from the CLOSED image-baked catalog
# (grants/reviewers/REVIEWER_REGISTRY) — it can never name an import path
# (docs/config-provenance.md). Unset = checker None, byte-for-byte the
# reviewer-less ceremony. A MISCONFIGURED reviewer refuses the ceremony loudly
# (config error != runtime failure: a failing reviewer at review time degrades
# to a recorded finding in ceremony.execute(), but a bad config must fail at
# startup, per sa#58's same-family conformance rule).
# ---------------------------------------------------------------------------
REVIEWER_KIND_ENV = "GRANTS_REVIEWER_KIND"
REVIEWER_PARAMS_ENV = "GRANTS_REVIEWER_PARAMS"


def _resolve_reviewer() -> CheckerProtocol | None:
    kind = os.environ.get(REVIEWER_KIND_ENV, "").strip()
    if not kind:
        return None
    # Lazy: the OFF path never imports the reviewers package (or boto3 hints).
    from safe_agents.broker.grants.reviewers import (  # noqa: PLC0415
        REVIEWER_REGISTRY,
    )

    factory = REVIEWER_REGISTRY.get(kind)
    if factory is None:
        raise RunnerConfigError(
            f"{REVIEWER_KIND_ENV}={kind!r} is not in the reviewer catalog "
            f"(known kinds: {sorted(REVIEWER_REGISTRY)}); the catalog is closed — "
            "config selects, it never names code"
        )
    params_raw = os.environ.get(REVIEWER_PARAMS_ENV, "")
    try:
        params = json.loads(params_raw) if params_raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise RunnerConfigError(f"{REVIEWER_PARAMS_ENV} is not valid JSON: {exc}") from exc
    if not isinstance(params, dict):
        raise RunnerConfigError(f"{REVIEWER_PARAMS_ENV} must be a JSON object")
    try:
        return factory(params)
    except (ValidationError, ValueError) as exc:
        raise RunnerConfigError(f"reviewer config invalid for kind {kind!r}: {exc}") from exc


def _caller_identity(session: object = None) -> str:
    """This ceremony's operator identity — the STS Arn, or the local arm (#226).

    A thin delegate to the ONE resolver in ``broker.ceremony_identity``, shared
    with the MCP admission ceremony: extending only one copy would silently
    leave the other ceremony without the local arm. Monkeypatched in tests (no
    real STS).
    """
    return resolve_ceremony_identity(session)


def _principal_from_args(args: argparse.Namespace) -> Principal:
    return Principal(
        agentId=args.principal_agent_id, skill=args.skill, user=args.user, tier=args.tier
    )


def _utc_now(now: datetime.datetime | None) -> datetime.datetime:
    return now or datetime.datetime.now(datetime.UTC)


# ---------------------------------------------------------------------------
# seed — the sanctioned bootstrap (grant + bootstrap ledger record, in pairs)
# ---------------------------------------------------------------------------

def seed_command(
    *,
    grant_store: GrantStore,
    record_store: PromotionRecordStore,
    grants: list[Grant],
    signer: RecordSigner | None = None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Create each floor grant AND its bootstrap-typed PromotionRecord.

    create_grant's attribute_not_exists condition means seed NEVER overwrites:
    an existing grant is a clean per-class skip (no duplicate bootstrap record),
    not a crash. Every grant created here has a ledger counterpart from birth —
    recordType='bootstrap', fromLevel=None (the Recommend rung; the seed creates
    the grant), proposedBy = ratifiedBy = the seeding STS identity (maker !=
    checker deliberately not enforced for the sanctioned bootstrap).

    ``signer`` is the ISSUER's RecordSigner — bootstrap is an operator act on
    the ceremony side. When one is configured, every bootstrap record written
    here is signed (GAL-SPEC §6.10); when none is, they are written unsigned
    exactly as before, so a local floor with no key material still seeds.
    Half-configured signing never reaches this function: ``resolve_record_signer``
    refuses first.
    """
    caller = _caller_identity(session)
    ts = _utc_now(now).isoformat()
    created = skipped = failures = 0
    for template in grants:
        grant = template.model_copy(update={"promotedBy": caller, "ts": ts})
        record = PromotionRecord(
            recordType="bootstrap",
            actionClass=grant.actionClass,
            principal=grant.principal,
            fromLevel=None,
            toLevel=grant.level,
            evidence=grant.evidence,
            predicate=None,
            proposedBy=caller,
            ratifiedBy=caller,
            envelopeHash=grant.envelopeHash,
            ts=ts,
            attestation=attestation_for(caller),
        )
        # Atomic grant+bootstrap-record (#244): every grant has a ledger
        # counterpart FROM BIRTH by construction — the old "grant created but
        # the record collided" reconcile branch cannot occur.
        try:
            grant_store.write_record_and_grant(
                record,
                grant,
                record_store,
                session,
                signature=signer.sign_record(record) if signer is not None else None,
                expected=None,
            )
        except GrantAlreadyExistsError:
            skipped += 1
            print(
                f"[seed] SKIP {grant.actionClass}: grant already exists — seed never "
                "overwrites (use re-seed for envelope-hash re-attestation)"
            )
            continue
        except RecordAlreadyExistsError as exc:
            failures += 1
            print(
                f"[seed] FAIL {grant.actionClass}: the bootstrap record collided "
                f"with an existing ledger entry — nothing written: {exc}",
                file=sys.stderr,
            )
            continue
        readback = grant_store.get_grant(grant.principal, grant.actionClass)
        if readback.grant is not None and not readback.quarantined:
            created += 1
            print(
                f"[seed] OK   {grant.actionClass}: grant + bootstrap record written; "
                "read back un-quarantined"
            )
        else:
            failures += 1
            detail = readback.quarantine_reason or "absent after write"
            print(f"[seed] FAIL {grant.actionClass}: {detail}", file=sys.stderr)
    print(
        f"[seed] seededBy={caller}: {created} created, {skipped} skipped, "
        f"{failures} failed; bootstrap records "
        f"{'signed (issuer DSSE)' if signer is not None else 'UNSIGNED (no issuer signing key configured)'}"
    )
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# re-seed — envelope-hash re-attestation (same level, human-ratified, no record)
# ---------------------------------------------------------------------------

def reseed_command(
    *,
    grant_store: GrantStore,
    principal: Principal,
    granted_classes: list[str],
    envelope_hash: str,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Re-stamp HMAC-clean grants under the NEW in-force envelope hash.

    The two quarantine kinds are deliberately distinguished:
      - A STORE-layer quarantine (grants/store.py: the stored HMAC does not
        match) is tampering, a mis-seeded key, or key rotation drift — NEVER
        re-attestable; refused loudly. That is an incident, not a ceremony.
      - The envelope-hash-mismatch kind (sa#122) is a PIP-level quarantine: the
        store read comes back HMAC-CLEAN but grant.envelopeHash differs from
        the hash now in force (a far-jump broker redeploy). That is the one
        re-attestable case: the grant is rebuilt with the new hash at the SAME
        level (re-attestation carries the prior level under human ratification
        — the caller's STS identity stamps promotedBy/ts), written via the
        hash-conditioned update_grant from this guarded read. No
        PromotionRecord is appended: no level changed (the re_ratify rule).
    """
    caller = _caller_identity(session)
    ts = _utc_now(now).isoformat()
    reattested = skipped = failures = 0
    for action_class in granted_classes:
        read = grant_store.get_grant(principal, action_class)
        if read.quarantined:
            failures += 1
            print(
                f"[re-seed] REFUSED {action_class}: store-layer quarantine "
                f"({read.quarantine_reason}). An HMAC-tamper quarantine is NEVER "
                "re-attestable — this is an incident, not a ceremony; root-cause "
                "the tamper before touching this grant.",
                file=sys.stderr,
            )
            continue
        if read.grant is None:
            failures += 1
            print(
                f"[re-seed] FAIL {action_class}: no grant exists — nothing to "
                "re-attest (bootstrap it with `seed`)",
                file=sys.stderr,
            )
            continue
        if read.grant.envelopeHash == envelope_hash:
            skipped += 1
            print(
                f"[re-seed] SKIP {action_class}: already stamped with the in-force "
                "envelope hash; nothing to re-attest"
            )
            continue
        updated = read.grant.model_copy(
            update={"envelopeHash": envelope_hash, "promotedBy": caller, "ts": ts}
        )
        try:
            grant_store.update_grant(
                updated, read.stored_hash, session, prev_raw_data=read.raw_data
            )
        except GrantUpdateConflictError as exc:
            failures += 1
            print(f"[re-seed] FAIL {action_class}: {exc}", file=sys.stderr)
            continue
        reattested += 1
        print(
            f"[re-seed] OK   {action_class}: re-attested at level "
            f"{updated.level.value!r} under {envelope_hash} "
            f"(was {read.grant.envelopeHash})"
        )
    print(
        f"[re-seed] ratifiedBy={caller}: {reattested} re-attested, "
        f"{skipped} skipped, {failures} failed"
    )
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# propose — the maker
# ---------------------------------------------------------------------------

def propose_command(
    args: argparse.Namespace,
    *,
    grant_store: GrantStore,
    proposal_store: ProposalStore,
    enforcement_store: EnforcementStore,
    envelope_hash: str,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Build, predicate-check, and store a PromotionProposal.

    The predicate runs locally for early feedback and its REASON is printed
    either way; an ineligible proposal is refused, never stored (a checker
    should never be summoned to a proposal that cannot pass the gate).
    """
    principal = _principal_from_args(args)
    caller = _caller_identity(session)

    tool, _, op = args.action_class.partition(".")
    if not tool or not op:
        print(f"REFUSED: --action-class must be 'tool.op', got {args.action_class!r}")
        return 1

    read = grant_store.get_grant(principal, args.action_class)
    if read.quarantined:
        print(
            f"REFUSED: the current grant is quarantined ({read.quarantine_reason}); "
            "a quarantined grant cannot anchor a promotion — resolve the "
            "quarantine first"
        )
        return 1
    # #255: a grant whose term has passed but whose lapse is not yet recorded
    # cannot anchor a promotion — its stored level is no longer certified, and
    # enforcement already acts at lastSafeLevel. The ceremony re-checks this at
    # ratify time; refusing here keeps the maker from staging a doomed proposal.
    if read.grant is not None and lapse_pending(read.grant, _utc_now(now)):
        print(
            f"REFUSED: the grant's certification term {read.grant.certifiedUntil} has "
            f"passed, so it acts at {read.grant.lastSafeLevel.value!r}, but the lapse "
            "is not yet recorded. Run the lapse evaluator "
            "(python -m safe_agents.broker.grants.runner) and re-propose from the "
            "lapsed level."
        )
        return 1
    # No grant = the Recommend rung (from_level=None); propose_promotion
    # enforces that its only valid target is in-loop (the grant-creating first
    # promotion). With a grant, the one-rung rule anchors on the STORED level.
    from_level = read.grant.level if read.grant is not None else None

    try:
        artifact = ConfidenceArtifact.model_validate_json(
            Path(args.artifact_json).read_text()
        )
    except (OSError, ValidationError) as exc:
        print(f"REFUSED: --artifact-json {args.artifact_json} is unusable: {exc}")
        return 1

    # The evidence metrics sum over the declared period window (#193, periods
    # #212): a bare read_counter is a single-period point read, so window_n
    # silently meant "the current period only" until this. read_counter_window
    # validates window_periods per period and raises ValueError out of range —
    # refuse loudly, never a bad-window read. The anchor bucket is derived ONCE
    # and passed to all three reads: without it a period rollover between the
    # reads would sum the three metrics over DIFFERENT windows, baking
    # incoherent (and then DSSE-signed) numbers onto the proposal. The period is
    # operator-NAMED and must match the manifest's counter_period — a mismatch
    # reads disjoint keys and yields zero evidence (fail toward less authority).
    anchor = current_period_bucket(args.period)
    try:
        metrics = ActionClassMetrics(
            false_action_count=int(
                read_counter_window(
                    enforcement_store, principal, tool, op,
                    FALSE_ACTION_SUFFIX, args.window_periods,
                    period=args.period, anchor_bucket=anchor,
                )
            ),
            human_override_count=int(
                read_counter_window(
                    enforcement_store, principal, tool, op,
                    HUMAN_OVERRIDE_SUFFIX, args.window_periods,
                    period=args.period, anchor_bucket=anchor,
                )
            ),
            observation_count=int(
                read_counter_window(
                    enforcement_store, principal, tool, op,
                    OBSERVATIONS_SUFFIX, args.window_periods,
                    period=args.period, anchor_bucket=anchor,
                )
            ),
        )
    except ValueError as exc:
        print(f"REFUSED: {exc}")
        return 1

    error_budget = None
    if args.budget_tolerance is not None:
        # The SAME counter + comparison coordinate as runner.derive_budget_breach
        # and the PIP's error_budget_breached fact — never re-derived differently.
        # Deliberately a single-period point read, NEVER windowed: the error
        # budget is a per-period budget whose tolerance comparison is
        # period-scoped (the same coordinate as derive_budget_breach); windowing
        # it would silently change #184 semantics.
        spent = enforcement_store.read_counter(
            scoped_counter_key(
                principal, tool, op, ERROR_BUDGET_SUFFIX, period=args.period
            )
        )
        error_budget = ErrorBudget(tolerance=args.budget_tolerance, spent=spent)

    # The consumer declares the ToolOp blast facts on the command line for now
    # (the manifest tool_ops join is a later slice); the CLI carries no
    # high-blast overrides, so effective == derived.
    tool_op = ToolOp(
        tool=tool,
        op=op,
        effect=args.effect,
        external=args.external,
        reversible={"true": True, "false": False, None: None}[args.reversible],
    )
    blast_class = effective_blast_class(tool_op, ())

    effective_now = _utc_now(now)
    proposal_id = str(uuid.uuid4())
    expires_at = (
        effective_now + datetime.timedelta(hours=args.ttl_hours)
    ).isoformat()

    try:
        proposal = PromotionCeremony.propose_promotion(
            principal,
            args.action_class,
            AutonomyLevel(args.target_level),
            args.evidence_bundle,
            caller,
            proposal_id=proposal_id,
            expires_at=expires_at,
            owner_id=args.owner_id,
            from_level=from_level,
            envelope_hash=envelope_hash,
            label_latency=args.label_latency,
            demotion_triggers=[DemotionTrigger(t) for t in (args.demotion_trigger or [])],
            last_safe_level=AutonomyLevel(args.last_safe_level),
            metrics=metrics,
            window_n=args.window_n,
            min_observations=args.min_observations,
            threshold=args.threshold,
            artifact=artifact,
            covered=args.covered,
            provenance_maturity=args.provenance_maturity,
            blast_class=blast_class,
            error_budget=error_budget,
            window_periods=args.window_periods,
            period=args.period,
            certified_until=getattr(args, "certified_until", None),
        )
        # Early feedback for the maker — the ceremony re-runs this at ratify
        # time; the two can only diverge if the counters move in between.
        predicate_result = evaluate_promotion_predicate(
            principal,
            args.action_class,
            metrics=metrics,
            window_n=args.window_n,
            min_observations=args.min_observations,
            threshold=args.threshold,
            target_level=proposal.target_level,
            artifact=artifact,
            covered=args.covered,
            provenance_maturity=args.provenance_maturity,
            blast_class=blast_class,
            error_budget=error_budget,
        )
    except ValueError as exc:
        print(f"REFUSED: {exc}")
        return 1

    print(f"predicate: {predicate_result.reason}")
    if not predicate_result.eligible:
        print("REFUSED: ineligible proposal is not stored — fix the evidence and re-propose")
        return 1
    if predicate_result.requires_human_ratification:
        print("note: high blast class — ratification must be per-instance human")

    proposal_store.put_proposal(proposal, session)
    print(
        f"proposal stored: proposal_id={proposal_id} "
        f"target={proposal.target_level.value} expires_at={expires_at}"
    )
    print(f"certifiedUntil={proposal.certified_until or 'none (no term)'}")
    print(f"proposedBy={caller}")
    return 0


# ---------------------------------------------------------------------------
# ratify — the checker
# ---------------------------------------------------------------------------

def ratify_command(
    args: argparse.Namespace,
    *,
    grant_store: GrantStore,
    record_store: PromotionRecordStore,
    proposal_store: ProposalStore,
    signer: RecordSigner | None,
    checker: CheckerProtocol | None = None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Load the stored proposal and run the full maker-checker ceremony.

    checker: the optional sa#58 evidence reviewer (findings recorded, never
    gated on). None — the default, and the state whenever GRANTS_REVIEWER_KIND
    is unset — is byte-for-byte the reviewer-less ceremony.
    """
    principal = _principal_from_args(args)
    caller = _caller_identity(session)

    # A ratified PromotionRecord mints acting authority, so storing it unsigned
    # is minting a weaker artifact than the ceremony claims (#196's polarity,
    # applied to the fully-unconfigured case). Refuse up front — before the
    # proposal is even loaded — unless the operator explicitly opted in, so a
    # refusal provably writes nothing (no record, no grant mutation, the
    # proposal stays pending).
    if signer is None and not getattr(args, "allow_unsigned", False):
        print(
            "REFUSED: issuer signing key not configured — a ratified "
            "PromotionRecord mints authority, so it must be issuer-signed. "
            "Configure ISSUER_SIGNING_KEY_SECRET_ARN/ISSUER_SIGNING_KEY_ID "
            "and a zone (--zone or ISSUER_SIGNING_ZONE), or pass "
            "--allow-unsigned to store the record UNSIGNED (asserted, not "
            "non-repudiable). Nothing was written."
        )
        return 1

    try:
        loaded = proposal_store.get_proposal(
            principal, args.action_class, args.proposal_id, session=session
        )
    except ProposalIntegrityError as exc:
        print(f"REFUSED: {exc}")
        return 1
    if loaded is None:
        print(
            f"REFUSED: no proposal {args.proposal_id} for "
            f"{principal.agentId}/{args.action_class}"
        )
        return 1
    proposal, status = loaded
    if status != "pending":
        print(
            f"REFUSED: proposal {args.proposal_id} is {status!r}, not pending — "
            "a consumed proposal can never be ratified"
        )
        return 1

    # Window provenance for the checker (#193, periods #212): the period-span
    # the evidence was summed over, integrity-bound on the proposal.
    # observation_count=N earned this period reads very differently from N
    # scraped thin across many — the checker judges the sample against the max
    # declared by window_n, at the period the proposal names.
    print(
        f"evidence window: {proposal.metrics.observation_count} observations "
        f"summed over {proposal.window_periods} {proposal.period} period(s); "
        f"window_n={proposal.window_n}"
    )
    # The term is part of what the checker ratifies (#255): show it.
    print(
        "certification term: "
        + (
            f"certifiedUntil={proposal.certified_until} (the grant lapses to "
            f"{proposal.last_safe_level.value!r} then)"
            if proposal.certified_until is not None
            else "none (the grant will carry no term)"
        )
    )

    if signer is None:
        # Reachable only via the explicit --allow-unsigned opt-in above.
        print(
            "WARNING: issuer signing key not configured (ISSUER_SIGNING_KEY_SECRET_ARN"
            "/ISSUER_SIGNING_KEY_ID) and --allow-unsigned was passed — the "
            "PromotionRecord will be stored UNSIGNED (asserted, not non-repudiable).",
            file=sys.stderr,
        )

    # Signing is ceremony-side since #244: the signature rides the atomic
    # record+grant transact leg, so the old put_record signing wrapper is gone.
    ceremony = PromotionCeremony(
        grant_store=grant_store,
        promotion_record_store=record_store,
        checker=checker,
        record_signer=signer,
    )
    machine = RungStateMachine(
        ceremony=ceremony, grant_store=grant_store, record_store=record_store
    )
    try:
        result = machine.promote(
            proposal,
            caller,
            session=session,
            proposal_store=proposal_store,
            now=_utc_now(now),
            ratifier_kind="human",
        )
    except (
        TransitionError,
        ProposalConsumedError,
        QuarantinedGrantError,
        GrantUpdateConflictError,
        GrantAlreadyExistsError,
        RecordAlreadyExistsError,
    ) as exc:
        print(f"REFUSED: {exc}")
        return 1

    if result.status != "ratified":
        print(f"REJECTED: {result.reason}")
        return 1
    record = result.promotion_record
    from_label = record.fromLevel.value if record.fromLevel is not None else "Recommend"
    print(f"RATIFIED: {result.reason}")
    print(
        f"record: recordType={record.recordType} actionClass={record.actionClass} "
        f"{from_label} -> {record.toLevel.value} ts={record.ts} "
        f"ratifiedBy={record.ratifiedBy} "
        f"signed={'yes (issuer DSSE)' if signer is not None else 'NO'}"
    )
    if is_local_identity(record.ratifiedBy):
        print(SOLO_ATTESTATION_NOTICE)
    return 0


# ---------------------------------------------------------------------------
# reject — the checker declines
# ---------------------------------------------------------------------------

def reject_command(
    args: argparse.Namespace,
    *,
    proposal_store: ProposalStore,
    session: object = None,
) -> int:
    """Flip the stored proposal to 'rejected' — the single-shot burn."""
    principal = _principal_from_args(args)
    caller = _caller_identity(session)
    try:
        reject_proposal(
            proposal_store, principal, args.action_class, args.proposal_id, session=session
        )
    except (ProposalConsumedError, ProposalIntegrityError) as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(
        f"rejected: proposal_id={args.proposal_id} for "
        f"{principal.agentId}/{args.action_class} rejectedBy={caller} — "
        "a rejected proposal can never be ratified"
    )
    return 0


# ---------------------------------------------------------------------------
# tighten — voluntary tightening: any level -> in-loop, always permitted
# ---------------------------------------------------------------------------

def tighten_command(
    args: argparse.Namespace,
    *,
    grant_store: GrantStore,
    record_store: PromotionRecordStore,
    signer: RecordSigner | None = None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Voluntarily lower the grant to in-loop (rung.tighten_to_in_loop).

    Tightening is safety-monotone: no ceremony, no fired trigger, maker !=
    checker deliberately not enforced (narrowing autonomy needs no second
    party). The tightening-typed PromotionRecord is ISSUER-signed when a
    signing key is configured (GAL-SPEC §6.10 — tightening is an operator act
    on the ceremony side, so it takes the ceremony key, not the evaluator's);
    with no key configured it is written unsigned, as before. Write discipline
    is the library's guarded re-read: not-found,
    quarantined, and concurrent-modify each refuse with a typed error before
    any write — a quarantined grant is NEVER written over.
    """
    principal = _principal_from_args(args)
    caller = _caller_identity(session)

    read = grant_store.get_grant(principal, args.action_class)
    if read.quarantined:
        print(
            f"REFUSED: the grant is quarantined ({read.quarantine_reason}); "
            "a quarantined grant is never written over — resolve the "
            "quarantine first"
        )
        return 1
    if read.grant is None:
        print(
            f"REFUSED: no grant exists for {principal.agentId}/{args.action_class} — "
            "tightening cannot create a grant (bootstrap it with `seed`)"
        )
        return 1

    ceremony = PromotionCeremony(
        grant_store=grant_store,
        promotion_record_store=record_store,
        record_signer=signer,
    )
    machine = RungStateMachine(
        ceremony=ceremony, grant_store=grant_store, record_store=record_store
    )
    try:
        updated, record = machine.tighten_to_in_loop(
            read.grant,
            caller,
            session=session,
            ts=_utc_now(now).isoformat(),
            evidence=args.evidence,
        )
    except TransitionError as exc:
        if read.grant.level is AutonomyLevel.in_loop:
            print("REFUSED: already at in-loop — nothing to tighten")
        else:
            print(f"REFUSED: {exc}")
        return 1
    except (
        GrantNotFoundError,
        QuarantinedGrantError,
        GrantUpdateConflictError,
        RecordAlreadyExistsError,
    ) as exc:
        print(f"REFUSED: {exc}")
        return 1

    print(
        f"TIGHTENED: {read.grant.level.value} -> {updated.level.value} "
        f"for {principal.agentId}/{args.action_class}"
    )
    print(
        f"record: recordType={record.recordType} actionClass={record.actionClass} "
        f"{read.grant.level.value} -> {record.toLevel.value} ts={record.ts} "
        f"requestedBy={caller} "
        f"signed={'yes (issuer DSSE)' if signer is not None else 'NO (no issuer signing key configured)'}"
    )
    return 0


# ---------------------------------------------------------------------------
# acknowledge — disposition a TRUE audit finding with a signed waiver (#196)
# ---------------------------------------------------------------------------

def acknowledge_command(
    args: argparse.Namespace,
    *,
    ack_store,
    signer: RecordSigner | None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Append a signed acknowledgment record for one specific audit finding.

    The flagged item is NEVER edited or deleted — that is the thing the audit
    exists to catch. Refuses un-waivable rules (closed vocabulary) and refuses
    to run unsigned: a waiver mints "green", which is authority, so it demands
    the same issuer signature a ratified promotion does.
    """
    if args.rule not in WAIVABLE_RULES:
        print(
            f"REFUSED: rule {args.rule!r} is not waivable — the closed waivable "
            f"vocabulary is {sorted(WAIVABLE_RULES)}"
        )
        return 1
    if signer is None:
        print(
            "REFUSED: acknowledgments must be issuer-signed (a waiver mints 'green') — "
            "configure ISSUER_SIGNING_KEY_SECRET_ARN/ISSUER_SIGNING_KEY_ID and a zone"
        )
        return 1

    ack = AcknowledgmentRecord(
        rule=args.rule,
        coordinate=args.coordinate,
        detailDigest=violation_detail_digest(args.detail),
        rationale=args.rationale,
        acknowledgedBy=_caller_identity(session),
        ts=_utc_now(now).isoformat(),
    )
    envelope = sign_acknowledgment(ack, signer)
    try:
        ack_store.append_acknowledgment(ack, envelope, session=session)
    except AcknowledgmentAlreadyExistsError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(
        f"ACKNOWLEDGED: rule={ack.rule} coordinate={ack.coordinate} "
        f"detailDigest={ack.detailDigest} acknowledgedBy={ack.acknowledgedBy} "
        f"ts={ack.ts} signed=yes (issuer DSSE) — the audit reports this finding "
        "as acknowledged, never silently green"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI entry — argparse + store/manifest/envelope resolution live in
# _commands_common.py; the command functions above are store-injected and
# AWS-free for tests
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "seed":
            grant_store, record_store = _build_stores(args.table_name)
            _, _, _, templates = _manifest_context(args.table_name)
            return seed_command(
                grant_store=grant_store,
                record_store=record_store,
                grants=templates,
                signer=resolve_record_signer(zone=args.zone),
            )
        if args.command == "re-seed":
            grant_store, _ = _build_stores(args.table_name)
            principal, classes, envelope_hash, _ = _manifest_context(args.table_name)
            return reseed_command(
                grant_store=grant_store,
                principal=principal,
                granted_classes=classes,
                envelope_hash=envelope_hash,
            )
        if args.command == "propose":
            grant_store, _ = _build_stores(args.table_name)
            return propose_command(
                args,
                grant_store=grant_store,
                proposal_store=_build_proposal_store(args.table_name),
                enforcement_store=_build_enforcement_store(args.counters_table),
                envelope_hash=_resolve_envelope_hash(
                    _principal_from_args(args), args.table_name
                ),
            )
        if args.command == "ratify":
            grant_store, record_store = _build_stores(args.table_name)
            return ratify_command(
                args,
                grant_store=grant_store,
                record_store=record_store,
                proposal_store=_build_proposal_store(args.table_name),
                signer=resolve_record_signer(zone=args.zone),
                checker=_resolve_reviewer(),
            )
        if args.command == "tighten":
            grant_store, record_store = _build_stores(args.table_name)
            return tighten_command(
                args,
                grant_store=grant_store,
                record_store=record_store,
                signer=resolve_record_signer(zone=args.zone),
            )
        if args.command == "acknowledge":
            return acknowledge_command(
                args,
                ack_store=_build_ack_store(args.table_name),
                signer=resolve_record_signer(zone=args.zone),
            )
        # reject
        return reject_command(args, proposal_store=_build_proposal_store(args.table_name))
    except (RunnerConfigError, IssuerSigningConfigError, BrokerConfigError) as exc:
        # BrokerConfigError: #205's named-config refusals (e.g. manifest-mode
        # ceremony on the dynamo arm with BROKER_MANIFEST unset) — same clean
        # operator-facing voice as the other config refusals, never a traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
