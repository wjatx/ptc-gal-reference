"""Out-of-band demotion runner — DemotionSignal → evaluator wiring (sa#59).

The broker process (brokerRole) cannot write the grants table — that invariant is
load-bearing (infra/lib/identity-stack.ts: the broker can neither promote itself
nor the agent). Demotion therefore runs OUT-OF-BAND as its own entrypoint under
the floor demotion role: an ECS one-shot task or Lambda whose ambient credentials
ARE the demotion role (UpdateItem-only IAM — no PutItem API — limits the blast
radius; the lower-never-mint guarantee itself is the store's ConditionExpressions:
attribute_exists for grant updates, attribute_not_exists for ledger appends).
The deployment binding is consumer-side; this module is the entrypoint.

Signal flow:
- The PEP's ``on_demotion_signal`` callback stays advisory (log-only — see
  ``runtime/pep.py`` ``_emit_demotion_signal``). The runner does NOT depend on
  signal delivery: ``budget_breach`` is re-derived deterministically from the
  durable scoped counter via ``derive_budget_breach``, which reuses EXACTLY the
  PIP's derivation (same ``scoped_counter_key``, same ``spent >= tolerance``
  comparison — broker_server.py's error_budget_breached fact), so the runner and
  the PIP can never disagree about what "breached" means.
- Externally-received DemotionSignals (from any delivery channel a consumer
  wires) fold in through ``metrics_from_signals``; the runner composes both.
- A record-only repeat breach (the demotion would not change the level) is
  deduped per UTC day (#191): already recorded today → "deduped", ZERO writes
  (no grant ts/hash churn, no ledger noise). A demotion that WOULD change the
  level is never deduped.

No model is consulted anywhere in this module — demotion is automatic and
deterministic (broker/grant-lifecycle.md §Demotion). Same inputs, same outcome.

Public API:
    RunnerOutcome           — typed result of one runner pass; every path returns one
    DemotionLedgerStore     — the runner's ledger seam (append + same-day dedupe read)
    metrics_from_signals    — pure: matching signals → DemotionMetrics
    derive_budget_breach    — deterministic budget_breach re-derivation from the counter
    derive_false_action     — deterministic false_action re-derivation from the counter
    derive_stale_confidence — deterministic stale_confidence derivation from a typed artifact
    derive_corroboration_failure — deterministic derivation from a typed quorum record
    run_demotion            — the orchestrating entrypoint (pure injection, no boto3)
    main                    — the deployable one-shot CLI entrypoint

Usage (one-shot task / drill):
  BROKER_GRANTS_TABLE=... BROKER_HMAC_KEY=... [BROKER_COUNTERS_TABLE=...] \\
      python -m safe_agents.broker.grants.runner \\
      --principal-agent-id agent-x --skill trade --user alice --tier A \\
      --action-class notify.send \\
      [--tool notify --op send --tolerance 0.5 --check-false-action \\
       --stale-artifact-json artifact.json --corroboration-json quorum.json]
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Protocol, runtime_checkable

from safe_agents.broker.enforcement import (
    ERROR_BUDGET_SUFFIX,
    FALSE_ACTION_SUFFIX,
    EnforcementStore,
    read_counter_window,
    scoped_counter_key,
)
from safe_agents.broker.enforcement.store import period_bucket_of
from safe_agents.broker.grants.ceremony import PromotionRecordStore
from safe_agents.broker.grants.demotion import (
    DemotionConflictError,
    DemotionMetrics,
    GrantNotFoundError,
    _rank,  # the SAME rank ordering apply_demotion clamps with — never duplicated
    apply_demotion,
    demotion_target_level,
    evaluate_demotion_triggers,
)
from safe_agents.broker.grants.store import (
    GrantStore,
    RecordAlreadyExistsError,
    validate_record_ts,
)
from safe_agents.broker.prototype.boot_config import (
    resolve_sqlite_db_path,
    sqlite_grants_open_options,
    resolve_store_arm,
)
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import CounterPeriod, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    CorroborationRecord,
    DemotionSignal,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outcome type — every runner path returns one; no silent None
# ---------------------------------------------------------------------------

RunnerStatus = Literal[
    "no-grant", "quarantined", "no-breach", "deduped", "demoted", "conflict"
]


@dataclass(frozen=True)
class RunnerOutcome:
    """Result of one run_demotion pass.

    Attributes:
        status: which path the run took.
            no-grant    — nothing to demote (not an error; log-worthy)
            quarantined — the stored grant failed hash verification; NOT demoted
                          (its contents are untrusted; the quarantine path owns
                          the loud surfacing)
            no-breach   — evaluator found no configured trigger tripped
            deduped     — a record-only repeat breach already recorded today
                          (same UTC day, same triggers, same level); nothing
                          written — zero grant churn, zero ledger noise (#191)
            demoted     — grant lowered; updated_grant + record carry the result
            conflict    — concurrent grant modification (caller re-reads and
                          retries), or the ledger append hit an existing record
                          key (the grant write already landed — the system is in
                          the safe lowered state; operator attention)
        reason: human-readable, audit-safe explanation (ids + trigger names +
            levels, never payload content).
        triggered_by: names of the triggers that fired (empty unless breached).
        updated_grant: the lowered grant (status == "demoted" only).
        record: the demotion-typed PromotionRecord already appended to the
            ledger (status == "demoted" only).
    """

    status: RunnerStatus
    reason: str
    triggered_by: tuple[str, ...] = ()
    updated_grant: Grant | None = None
    record: PromotionRecord | None = None


# ---------------------------------------------------------------------------
# Pure: signals → DemotionMetrics
# ---------------------------------------------------------------------------

def metrics_from_signals(
    signals: Iterable[DemotionSignal],
    *,
    principal: Principal,
    action_class: str,
) -> DemotionMetrics:
    """Collect the triggers of signals matching (principal, action_class).

    Pure — no I/O. Principal equality is full-tuple (agentId, skill, user, tier):
    a signal for the same agentId under a different user/skill/tier is a
    DIFFERENT grant coordinate and is ignored. Non-matching signals are ignored,
    never an error — one delivery channel may carry signals for many grants.
    """
    tripped = frozenset(
        s.trigger
        for s in signals
        if s.principal == principal and s.action_class == action_class
    )
    return DemotionMetrics(tripped=tripped)


# The default period-span derive_false_action sums the false_action counter over. A
# /flag back-dates the counter to the op's ORIGINAL execution period
# (pep._utc_bucket_of), so a point-read of the current period would miss a flag raised
# against an op that ran a period or two ago. Seven periods is wide enough for a
# realistic after-the-fact review lag and bounded well under
# enforcement.MAX_WINDOW_PERIODS at either period.
FALSE_ACTION_WINDOW_PERIODS = 7

# Back-compat name (pre-#212).
FALSE_ACTION_WINDOW_DAYS = FALSE_ACTION_WINDOW_PERIODS


# ---------------------------------------------------------------------------
# Deterministic re-derivation from the durable counter — the shared assembly
# ---------------------------------------------------------------------------

def _breach_signal(
    spent: float,
    threshold: float,
    *,
    trigger: DemotionTrigger,
    principal: Principal,
    tool: str,
    op: str,
    detail: str,
    now: datetime.datetime | None,
    period: "CounterPeriod" = "utc-day",
) -> DemotionSignal | None:
    """Assemble a DemotionSignal from an already-evaluated input, or None if under threshold.

    The one place all four derivations (budget_breach, false_action, stale_confidence,
    corroboration_failure) build their signal — identical ``spent >= threshold`` gate and
    field population mirroring the PEP's ``_emit_demotion_signal``. The evidence READ
    differs per caller (a counter point-read, a period-window sum, or a typed
    artifact/record predicate collapsed to 1.0-vs-0.0 against threshold 1.0) and stays in
    each caller; only this assembly is shared. ``now`` is injectable for tests and stamps
    period/ts only; ``period`` names the bucket size the stamp renders at (#212).
    """
    if spent < threshold:
        return None
    effective_now = now or datetime.datetime.now(datetime.UTC)
    return DemotionSignal(
        trigger=trigger,
        principal=principal,
        action_class=f"{tool}.{op}",
        period=period_bucket_of(effective_now, period),
        detail=detail,
        ts=effective_now.isoformat(),
    )


def derive_budget_breach(
    principal: Principal,
    tool: str,
    op: str,
    *,
    enforcement_store: EnforcementStore,
    tolerance: float,
    now: datetime.datetime | None = None,
    period: "CounterPeriod" = "utc-day",
) -> DemotionSignal | None:
    """Re-derive the budget_breach signal from the durable scoped counter.

    Reads the SAME ``…:error_budget`` counter the PEP meters, through the SAME
    key derivation (enforcement.scoped_counter_key) and the SAME comparison
    (``spent >= tolerance``) the PIP uses for its error_budget_breached fact —
    deliberately not re-implemented, so the runner and the PIP can never
    disagree about what "breached" means. Because the counter is principal+op+
    period scoped, the derivation is for the CURRENT period only (a new period
    is a new key; the previous period's breach aged out with its key).

    Returns a budget_breach DemotionSignal mirroring the PEP's
    ``_emit_demotion_signal`` field population, or None when under tolerance.
    ``now`` is injectable for tests and stamps period/ts only; the counter key's
    bucket always comes from scoped_counter_key itself (real time). ``period``
    must match the manifest's counter_period (#212) — a mismatch reads a
    disjoint key and sees zero spend (a missed breach is the fail-safe
    direction for a DEMOTION check only because the runner never promotes).
    """
    key = scoped_counter_key(principal, tool, op, ERROR_BUDGET_SUFFIX, period=period)
    spent = enforcement_store.read_counter(key)
    return _breach_signal(
        spent,
        tolerance,
        trigger=DemotionTrigger.budget_breach,
        principal=principal,
        tool=tool,
        op=op,
        detail=(
            f"error budget breached: spent {spent:.4f} >= tolerance {tolerance:.4f}"
        ),
        now=now,
        period=period,
    )


def derive_false_action(
    principal: Principal,
    tool: str,
    op: str,
    *,
    enforcement_store: EnforcementStore,
    window_periods: int = FALSE_ACTION_WINDOW_PERIODS,
    now: datetime.datetime | None = None,
    period: "CounterPeriod" = "utc-day",
) -> DemotionSignal | None:
    """Re-derive the false_action signal from the durable scoped counter.

    Reads the ``…:false_action`` counter the PEP increments on an authenticated owner
    flag (#193). The threshold is ``>= 1``: ONE authenticated flag suffices to demote
    (the maintainer's ease-gradient doctrine — easier to get demoted than to overcome the
    safeguards), and no accumulation of flags can ever promote. Re-deriving from the
    durable counter (never from a message) keeps the runner deterministic — an agent
    cannot forge or replay a flag past what the counter records.

    Unlike ``derive_budget_breach`` (a single-period point read), this SUMS the counter
    over a ``window_periods`` span through the ``read_counter_window`` seam — the same
    seam ``propose --window-periods`` uses. It must: ``flag_intent`` back-dates the
    counter to the op's ORIGINAL execution period (pep._utc_bucket_of), so a flag raised
    now against an op that ran a period ago lands on that period's key; a point-read of
    the current period would miss it. The window's newest period is anchored on ``now``
    (real time by default), so the run period inclusive of the last ``window_periods``
    periods is summed. ``period`` must match the manifest's counter_period (#212).

    Returns a false_action DemotionSignal, or None when no flag falls in the window.
    ``now`` is injectable for tests and stamps period/ts AND pins the window anchor.
    """
    effective_now = now or datetime.datetime.now(datetime.UTC)
    count = read_counter_window(
        enforcement_store,
        principal,
        tool,
        op,
        FALSE_ACTION_SUFFIX,
        window_periods,
        period=period,
        anchor_bucket=period_bucket_of(effective_now, period),
    )
    return _breach_signal(
        count,
        1.0,
        trigger=DemotionTrigger.false_action,
        principal=principal,
        tool=tool,
        op=op,
        detail=(
            f"false-action flag raised: count {count:.0f} >= 1 over "
            f"{window_periods} {period} period(s) "
            "(one authenticated owner flag suffices)"
        ),
        now=now,
        period=period,
    )


def derive_stale_confidence(
    principal: Principal,
    tool: str,
    op: str,
    *,
    artifact: ConfidenceArtifact,
    now: datetime.datetime | None = None,
    period: "CounterPeriod" = "utc-day",
) -> DemotionSignal | None:
    """Derive the stale_confidence signal from a typed ConfidenceArtifact (#192).

    The #184 ``stale`` flag is the label-free drift INPUT (broker/EVIDENCE.md
    §stale_confidence): the drift DETECTOR that sets it is consumer/reference-tier
    and never lives here — this derivation consumes the flag as given, exactly as
    ``derive_false_action`` consumes the counter a /flag wrote. Deterministic: a
    stale artifact yields the signal, a fresh one yields None; no model call, no
    judgment of WHY the artifact went stale.

    The artifact carries no grant coordinate; the CALLER binds it to
    (principal, tool.op) — the same binding discipline ``propose --artifact-json``
    uses. ``now`` is injectable for tests and stamps period/ts only.
    """
    return _breach_signal(
        1.0 if artifact.stale else 0.0,
        1.0,
        trigger=DemotionTrigger.stale_confidence,
        principal=principal,
        tool=tool,
        op=op,
        detail=(
            f"stale confidence artifact: method={artifact.evidence.method} "
            f"computed_at={artifact.computed_at} — drift voids the conformal "
            "threshold (label-free; certification lapsed, not proven failing)"
        ),
        now=now,
        period=period,
    )


def derive_corroboration_failure(
    principal: Principal,
    tool: str,
    op: str,
    *,
    record: CorroborationRecord,
    now: datetime.datetime | None = None,
    period: "CounterPeriod" = "utc-day",
) -> DemotionSignal | None:
    """Derive the corroboration_failure signal from a typed quorum record (#192).

    Consumes a ``CorroborationRecord`` — the k-of-n independent-source quorum
    result a consumer's corroboration pass produced — and applies the ONE
    deterministic predicate (``agreeing < k``). Which sources were consulted and
    how agreement/staleness/provenance were judged is the producer's concern
    (consumer/reference-tier); this derivation never re-litigates it. Failed
    corroboration pushes toward demotion, never toward allow
    (broker/grant-lifecycle.md §Demotion trigger 2).

    The record carries no grant coordinate; the CALLER binds it to
    (principal, tool.op). ``now`` is injectable for tests and stamps period/ts only.
    """
    return _breach_signal(
        1.0 if record.failed else 0.0,
        1.0,
        trigger=DemotionTrigger.corroboration_failure,
        principal=principal,
        tool=tool,
        op=op,
        detail=(
            f"corroboration failed: {record.agreeing}/{record.n} independent sources "
            f"agreeing < quorum k={record.k} "
            f"(stale_sources={record.stale_sources}, computed_at={record.computed_at})"
        ),
        now=now,
        period=period,
    )


# ---------------------------------------------------------------------------
# Ledger seam + record-only same-day dedupe (#191)
# ---------------------------------------------------------------------------

@runtime_checkable
class DemotionLedgerStore(PromotionRecordStore, Protocol):
    """The runner's ledger seam: the append PLUS the same-day dedupe read.

    Extends the ceremony's put_record-only Protocol (the ceremony never reads
    the ledger); both provided implementations satisfy it."""

    def list_records(
        self,
        principal: Principal,
        action_class: str,
        session: object = None,
        *,
        ts_prefix: str | None = None,
    ) -> list[PromotionRecord]:
        ...


def _same_day_demotion_recorded(
    record_store: DemotionLedgerStore,
    grant: Grant,
    triggered_by: list[str],
    *,
    day: str,
    session: object,
) -> bool:
    """True iff today's ledger already carries this record-only breach.

    Dedupe key: same UTC day (the sk's ts prefix) + recordType=="demotion" +
    identical triggeredBy + toLevel == the current grant level. A same-day
    record for a different trigger set or toLevel never suppresses the append —
    a genuinely new breach event must land on the ledger.
    """
    records = record_store.list_records(
        grant.principal, grant.actionClass, session, ts_prefix=day
    )
    return any(
        r.recordType == "demotion"
        and r.triggeredBy == triggered_by
        and r.toLevel == grant.level
        for r in records
    )


# ---------------------------------------------------------------------------
# The orchestrating entrypoint — pure injection, no boto3 construction inside
# ---------------------------------------------------------------------------

def run_demotion(
    principal: Principal,
    action_class: str,
    *,
    grant_store: GrantStore,
    record_store: DemotionLedgerStore,
    signals: Iterable[DemotionSignal] = (),
    session: object = None,
    ts: str | None = None,
) -> RunnerOutcome:
    """Run one demotion evaluation pass for (principal, action_class).

    Composable: callers pass externally-received signals AND/OR any
    derive_budget_breach result, already merged into ``signals``. Deterministic —
    same inputs, same outcome; no model call anywhere.

    Retry policy is the CALLER's: a "conflict" outcome means the grant changed
    between read and write — re-invoke with a fresh read; this function never
    auto-retries internally.
    """
    # Fail fast on a non-canonical caller ts: a parseable-but-non-canonical
    # value (e.g. a 'Z' suffix) would pass the dedupe gate's fromisoformat and
    # only blow up later inside put_record, mid-pass. Same rejection, upfront.
    if ts is not None:
        validate_record_ts(ts)

    read = grant_store.get_grant(principal, action_class)

    if read.quarantined:
        # A quarantined grant's contents are untrusted — evaluating (or lowering)
        # it would treat tampered data as authoritative. Surface loudly; the
        # quarantine path already owns that event.
        reason = (
            f"grant {principal.agentId}/{action_class} is QUARANTINED "
            f"({read.quarantine_reason}); not demoting — quarantined contents "
            "are untrusted"
        )
        logger.error(reason)
        return RunnerOutcome(status="quarantined", reason=reason)

    if read.grant is None:
        reason = (
            f"no grant for {principal.agentId}/{action_class}; nothing to demote"
        )
        logger.info(reason)
        return RunnerOutcome(status="no-grant", reason=reason)

    metrics = metrics_from_signals(
        signals, principal=principal, action_class=action_class
    )
    result = evaluate_demotion_triggers(read.grant, metrics)
    if not result.should_demote:
        return RunnerOutcome(status="no-breach", reason=result.reason)

    # Record-only same-day dedupe (#191): apply_demotion's own target + clamp
    # (shared helpers, never re-derived) — when the level would NOT change,
    # another pass would only churn the grant ts/hash and append ledger noise.
    # A level-CHANGING demotion is never deduped.
    target_level = demotion_target_level(read.grant)
    if _rank(target_level) >= _rank(read.grant.level):
        effective_now = (
            datetime.datetime.fromisoformat(ts)
            if ts is not None
            else datetime.datetime.now(datetime.UTC)
        )
        if _same_day_demotion_recorded(
            record_store,
            read.grant,
            result.triggered_by,
            day=effective_now.date().isoformat(),
            session=session,
        ):
            reason = (
                f"record-only breach for {principal.agentId}/{action_class} "
                f"({result.triggered_by} at level {read.grant.level.value!r}) "
                "already recorded today; skipping — zero writes"
            )
            logger.info(reason)
            return RunnerOutcome(
                status="deduped",
                reason=reason,
                triggered_by=tuple(result.triggered_by),
            )

    try:
        updated, record = apply_demotion(
            read.grant,
            result,
            store=grant_store,
            record_store=record_store,
            session=session,
            ts=ts,
        )
    except DemotionConflictError as exc:
        return RunnerOutcome(
            status="conflict",
            reason=str(exc),
            triggered_by=tuple(result.triggered_by),
        )
    except GrantNotFoundError as exc:
        # The grant vanished between our read and apply's re-read. The end state
        # is safe (no grant = no autonomy); report it as no-grant.
        logger.info(str(exc))
        return RunnerOutcome(status="no-grant", reason=str(exc))
    except RecordAlreadyExistsError as exc:
        # The grant write already landed (grant lowered FIRST, record second) —
        # the system is in the safe state, but the append hit an existing ledger
        # key. Typed outcome, nonzero exit: an operator must reconcile.
        reason = (
            f"grant {principal.agentId}/{action_class} lowered, but the demotion "
            f"record collided with an existing ledger entry: {exc}"
        )
        logger.error(reason)
        return RunnerOutcome(
            status="conflict",
            reason=reason,
            triggered_by=tuple(result.triggered_by),
        )

    return RunnerOutcome(
        status="demoted",
        reason=result.reason,
        triggered_by=tuple(result.triggered_by),
        updated_grant=updated,
        record=record,
    )


# ---------------------------------------------------------------------------
# CLI — the deployable one-shot entrypoint (thin; everything above is injected)
# ---------------------------------------------------------------------------

class RunnerConfigError(Exception):
    """Missing/invalid environment or arguments for the CLI entrypoint."""


def _resolve_table_name(table_name: str | None) -> str:
    """Grants table resolution, mirroring the broker's own order:
    explicit arg, then BROKER_GRANTS_TABLE, then GRANTS_TABLE_NAME."""
    resolved = (
        table_name
        or os.environ.get("BROKER_GRANTS_TABLE")
        or os.environ.get("GRANTS_TABLE_NAME")
    )
    if not resolved:
        raise RunnerConfigError(
            "grants table not set: pass --table-name or set BROKER_GRANTS_TABLE "
            "(or GRANTS_TABLE_NAME)"
        )
    return resolved


def _ceremony_hmac_key() -> bytes:
    """The ceremony's NAMED store-integrity key — never a dev fallback (#205).

    Named on BOTH arms: a durable local store's tamper evidence is only as real
    as its key discipline, and this must NOT route through the broker's
    read-side ``resolve_hmac_key`` (whose dev-key fallback fires off the dynamo
    arm) or the ceremony would write under one key while the broker reads under
    another and quarantine every grant.
    """
    hmac_key = os.environ.get("BROKER_HMAC_KEY", "").encode()
    if not hmac_key:
        raise RunnerConfigError(
            "BROKER_HMAC_KEY is required and must match the key the broker reads "
            "with (else every grant quarantines on read)"
        )
    return hmac_key


def _build_stores(table_name: str | None):
    """Construct the grant + record stores from env, on the selected arm.

    Backend follows the BROKER_STORE profile seam (product-wrapper Phase 1), exactly as
    ``mcp/commands.py::_build_stores`` does: on the sqlite arm the pair is
    sqlite-backed at the boot_config-resolved db path (the ONE db-path seam);
    on every other arm it is DynamoDB at the named table, byte-for-byte the
    pre-sqlite behavior. Store construction stays lazy on both (no AWS call, no
    file touched here); the ambient boto3 credentials at call time must carry
    the ceremony role on the Dynamo arm.
    """
    hmac_key = _ceremony_hmac_key()
    if resolve_store_arm() == "sqlite":
        from safe_agents.broker.grants.sqlite_store import (  # noqa: PLC0415
            SqliteGrantStore,
            SqlitePromotionRecordStore,
        )

        # GRANT# and RECORD# are the CHECKER-writable key space (#203), so both
        # take the grants-store options: their own file when the deployment
        # splits, the co-located broker.db when it does not.
        opts = sqlite_grants_open_options()
        return (
            SqliteGrantStore(hmac_key, **opts),
            SqlitePromotionRecordStore(**opts),
        )

    from safe_agents.broker.grants.store import (  # noqa: PLC0415 — keep module import light
        DynamoDBGrantStore,
        DynamoDBPromotionRecordStore,
    )

    resolved = _resolve_table_name(table_name)
    return (
        DynamoDBGrantStore(hmac_key=hmac_key, table_name=resolved),
        DynamoDBPromotionRecordStore(table_name=resolved),
    )


def _build_enforcement_store(counters_table: str | None) -> EnforcementStore:
    """Construct the counter store for budget/evidence re-derivation, per arm."""
    if resolve_store_arm() == "sqlite":
        from safe_agents.broker.enforcement.sqlite_store import (  # noqa: PLC0415
            SqliteEnforcementStore,
        )

        return SqliteEnforcementStore(resolve_sqlite_db_path())

    from safe_agents.broker.enforcement import DynamoStore  # noqa: PLC0415

    resolved = counters_table or os.environ.get("BROKER_COUNTERS_TABLE")
    if not resolved:
        raise RunnerConfigError(
            "counters table not set: pass --counters-table or set "
            "BROKER_COUNTERS_TABLE (required with --tolerance)"
        )
    return DynamoStore(resolved)


def _load_evidence_json(path: str, model: type, flag: str):
    """Load + validate a typed evidence input file; unusable input REFUSES loudly.

    A demotion input that fails to parse must surface as a config error (exit 2),
    never fall through to a "no breach" outcome — failing toward LESS scrutiny is
    the one polarity this runner must never have.
    """
    try:
        return model.model_validate_json(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise RunnerConfigError(f"{flag} {path} is unusable: {exc}") from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.grants.runner",
        description=(
            "Out-of-band demotion runner: evaluate demotion triggers for one "
            "(principal, action_class) grant and apply the demotion if breached. "
            "Runs under the demotion role (ambient boto3 credentials)."
        ),
    )
    parser.add_argument("--principal-agent-id", required=True)
    parser.add_argument("--skill", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--tier", required=True, choices=["A", "B", "C", "D"])
    parser.add_argument("--action-class", required=True)
    parser.add_argument(
        "--table-name",
        help="grants table (default: BROKER_GRANTS_TABLE / GRANTS_TABLE_NAME env)",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        help="error-budget tolerance; with --tool/--op, re-derives budget_breach "
        "from the durable error_budget counter",
    )
    parser.add_argument(
        "--tool", help="tool of the metered op (with --tolerance / --check-false-action)"
    )
    parser.add_argument(
        "--op", help="op of the metered op (with --tolerance / --check-false-action)"
    )
    parser.add_argument(
        "--check-false-action",
        action="store_true",
        help="with --tool/--op, re-derive false_action from the durable "
        "false_action counter (one authenticated owner flag suffices)",
    )
    parser.add_argument(
        "--period",
        choices=["utc-day", "utc-hour"],
        default="utc-day",
        help="counter period the durable evidence buckets at (#212). MUST match "
        "the manifest's counter_period; a mismatch reads disjoint keys and sees "
        "no evidence (safe only because the runner never promotes).",
    )
    parser.add_argument(
        "--false-action-window-periods",
        "--false-action-window-days",
        dest="false_action_window_periods",
        type=int,
        default=FALSE_ACTION_WINDOW_PERIODS,
        help="period-span the false_action counter is summed over (default: "
        f"{FALSE_ACTION_WINDOW_PERIODS}); a /flag back-dates to the op's "
        "execution period. --false-action-window-days is the pre-#212 spelling.",
    )
    parser.add_argument(
        "--stale-artifact-json",
        help="with --tool/--op, path to a typed ConfidenceArtifact JSON (#184); a "
        "stale artifact derives stale_confidence (the drift detector that sets "
        "the flag is consumer-side — this is the input path only)",
    )
    parser.add_argument(
        "--corroboration-json",
        help="with --tool/--op, path to a typed CorroborationRecord JSON; a failed "
        "k-of-n quorum (agreeing < k) derives corroboration_failure",
    )
    parser.add_argument(
        "--counters-table",
        help="counters table for budget / false_action re-derivation "
        "(default: BROKER_COUNTERS_TABLE env)",
    )
    args = parser.parse_args(argv)

    # --tool/--op are the shared metered-op coordinate for both counter
    # re-derivations; they must be given together, and either derivation flag
    # requires them.
    if (args.tool is not None) != (args.op is not None):
        parser.error("--tool and --op must be given together")
    if args.tolerance is not None and (args.tool is None or args.op is None):
        parser.error("--tolerance requires --tool and --op")
    if args.check_false_action and (args.tool is None or args.op is None):
        parser.error("--check-false-action requires --tool and --op")
    if args.stale_artifact_json is not None and (args.tool is None or args.op is None):
        parser.error("--stale-artifact-json requires --tool and --op")
    if args.corroboration_json is not None and (args.tool is None or args.op is None):
        parser.error("--corroboration-json requires --tool and --op")
    # …and the converse: --tool/--op with NO derivation flag would build stores /
    # read inputs and derive nothing — a silent no-op that looks like "no breach".
    # Require at least one derivation flag when the metered coordinate is given.
    if args.tool is not None and (
        args.tolerance is None
        and not args.check_false_action
        and args.stale_artifact_json is None
        and args.corroboration_json is None
    ):
        parser.error(
            "--tool/--op require a derivation flag: pass --tolerance, "
            "--check-false-action, --stale-artifact-json and/or --corroboration-json"
        )
    return args


# demoted/deduped/no-breach/no-grant are clean completions; conflict (a lost
# write race or a duplicate ledger key) and quarantined (untrusted grant
# contents) need operator attention.
_EXIT_CODES: dict[RunnerStatus, int] = {
    "no-grant": 0,
    "no-breach": 0,
    "deduped": 0,
    "demoted": 0,
    "conflict": 1,
    "quarantined": 1,
}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    principal = Principal(
        agentId=args.principal_agent_id,
        skill=args.skill,
        user=args.user,
        tier=args.tier,
    )

    try:
        grant_store, record_store = _build_stores(args.table_name)
        signals: list[DemotionSignal] = []
        if args.tolerance is not None or args.check_false_action:
            enforcement_store = _build_enforcement_store(args.counters_table)
            if args.tolerance is not None:
                budget = derive_budget_breach(
                    principal,
                    args.tool,
                    args.op,
                    enforcement_store=enforcement_store,
                    tolerance=args.tolerance,
                    period=args.period,
                )
                if budget is not None:
                    signals.append(budget)
            if args.check_false_action:
                flagged = derive_false_action(
                    principal,
                    args.tool,
                    args.op,
                    enforcement_store=enforcement_store,
                    window_periods=args.false_action_window_periods,
                    period=args.period,
                )
                if flagged is not None:
                    signals.append(flagged)
        # The typed-evidence derivations (#192): file inputs, no counter store.
        # An unreadable or malformed input REFUSES loudly (exit 2) — a bad input
        # must never read as "no breach".
        if args.stale_artifact_json is not None:
            stale = derive_stale_confidence(
                principal,
                args.tool,
                args.op,
                artifact=_load_evidence_json(
                    args.stale_artifact_json, ConfidenceArtifact, "--stale-artifact-json"
                ),
                period=args.period,
            )
            if stale is not None:
                signals.append(stale)
        if args.corroboration_json is not None:
            corroboration = derive_corroboration_failure(
                principal,
                args.tool,
                args.op,
                record=_load_evidence_json(
                    args.corroboration_json, CorroborationRecord, "--corroboration-json"
                ),
                period=args.period,
            )
            if corroboration is not None:
                signals.append(corroboration)
    except RunnerConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    outcome = run_demotion(
        principal,
        args.action_class,
        grant_store=grant_store,
        record_store=record_store,
        signals=signals,
    )

    # PII-safe one-line JSON: ids + status + trigger names + the audit-safe
    # reason string — never payload content (the sa#153 log-surface discipline).
    print(
        json.dumps(
            {
                "event": "demotion_runner",
                "status": outcome.status,
                "agentId": principal.agentId,
                "actionClass": args.action_class,
                "triggeredBy": list(outcome.triggered_by),
                "reason": outcome.reason,
            }
        )
    )
    return _EXIT_CODES[outcome.status]


if __name__ == "__main__":
    raise SystemExit(main())
