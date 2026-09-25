"""broker.runtime.pep — Policy Enforcement Point (PEP) and broker orchestrator.

The PEP is the broker's public surface facing the agent. It composes the
built broker modules into one running round-trip:

  1. Serves the capability-scoped tool registry (what the agent may see/request).
  2. Ingests sources into a TurnContext; derives taint deterministically.
  3. Materializes a BrokeredCall from the agent's (tool, op, args).
  4. Fetches Facts from the injected PIP.
  5. Calls decide() → initial Decision.
  6. Calls enforce() — revalidates premise, manages counters/WAL, gates HITL.
     On allow/transform: the executor callback calls the Doer → connector →
     audit.emit().
  7. On require_approval: calls materialize() to freeze the Intent; emits audit;
     the turn ends.
  8. On deny/abstain: emits audit; the turn ends.
  9. Returns a BrokerResponse to the caller.

Agent-facing boundary invariants (documented + test-asserted in test_runtime.py):
  - BrokerResponse contains no credential field.
  - BrokerRuntime exposes no Connector and no Doer reference through its public API.
  - The agent cannot invoke a connector except through handle_request() → Doer.
  - The Doer raises ConfinementError on non-allow/transform decisions.

Exports:
    AgentRequest   — the raw (tool, op, args) from the agent.
    BrokerResponse — the broker's reply; contains no credential.
    BrokerRuntime  — composes all modules; call handle_request() per tool call.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import ValidationError

from safe_agents.broker.approval import (
    ExecutionResult,
    IntentStore,
    IntentView,
    QuarantinedIntentError,
    ReleaseRefusedError,
    approve,
    materialize,
    reject,
)
from safe_agents.broker.approval.engine import REJECTED_BY_OWNER_REASON
from safe_agents.broker.approval.queue_guard import dedup_intent_id, is_flood
from safe_agents.broker.audit import AuditSink, emit, hash_args, hash_stored_call
from safe_agents.broker.enforcement import (
    ACTION_CAP_SUFFIX,
    ERROR_BUDGET_SUFFIX,
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    QUERY_BYTES_SUFFIX,
    UNBOUNDED_COUNTER_CAP,
    EnforcementStore,
    current_period_bucket,
    enforce,
    scoped_counter_key,
)
from safe_agents.broker.delegation.pool import resolve_tree_pool
from safe_agents.broker.delegation.store import SubGrantStore
from safe_agents.broker.enforcement.store import period_bucket_of
from safe_agents.broker.enforcement.types import CounterDraw
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import (
    BrokeredCall,
    ConfidenceArtifact,
    Grant,
    RequireApproval,
    Session,
    ToolOp,
)
from safe_agents.broker.schemas.common import CounterPeriod, DemotionTrigger, Principal
from safe_agents.broker.schemas.decision import Allow, Decision, Deny
from safe_agents.broker.schemas.envelope import ApprovalQueue, Confidence
from safe_agents.broker.schemas.evidence import (
    DemotionSignal,
    effective_blast_class,
    error_budget_draw,
)
from safe_agents.broker.taint import InputTrustMap, TurnContext

from .doer import ConnectorExecutionError, Doer

logger = logging.getLogger(__name__)

# sa#137 — the query-egress-byte counter is a pure per-period accumulator; the budget
# is enforced at the PIP read-gate (read_counter >= query_egress_budget → deny the next
# read), not by this counter's cap. An effectively-unbounded finite cap keeps
# try_increment_counter atomic (and DynamoDB-Number-representable) without ever refusing.
_QUERY_BYTES_COUNTER_CAP = 1e18

# #184 — the error-budget accumulator (Σ error_prob × blast_radius) is a pure
# per-period meter; the BINDING bound is the PDP's tolerance comparison
# (read_counter >= error_budget_tolerance → the next write escalates/denies), not this
# counter's cap. An effectively-unbounded finite cap keeps try_increment_counter atomic
# (and DynamoDB-Number-representable) without ever refusing a draw. Mirrors
# _QUERY_BYTES_COUNTER_CAP.
_ERROR_BUDGET_COUNTER_CAP = 1e18

# #193 — the reject CAS-win sentinel, imported from approval.engine (its source of
# truth): REJECTED_BY_OWNER_REASON is the ONLY reason reject() returns when this
# caller won the compare-and-set; every not-found / expired / not-pending / foreign
# path returns a distinct string.
_REJECT_CAS_WIN_REASON = REJECTED_BY_OWNER_REASON

# #193 Phase 6c — the flag ceremony's success sentinel and idempotency marker.
# flag_intent never executes, so like reject_intent it always returns executed=False;
# FLAGGED_BY_OWNER_REASON is the reason string on a clean flag (a marker-claim win),
# distinct from every unknown / foreign / non-executed / already-flagged refusal.
FLAGGED_BY_OWNER_REASON = "flagged by owner"

# One-shot per-intent marker (a cap-1 counter) that makes flag_intent idempotent
# without an IntentStore-protocol seam: the IntentStore exposes only a pending→X
# transition, and a flagged op is already terminal ("executed"), so there is no
# status transition to compare-and-set against. try_increment_counter(key, 1, 1) is
# the atomic conditional marker instead — the FIRST /flag wins the claim (0→1), a
# SECOND is refused (1+1 > 1), so a re-flag can never double-count the evidence.
_FLAG_MARKER_PREFIX = "flag-marker"
_FLAG_MARKER_CAP = 1.0


def _utc_bucket_of(ts: str, period: CounterPeriod = "utc-day") -> str:
    """Render an ISO-8601 timestamp as the UTC period-bucket key segment (#212).

    Used by flag_intent to back-write false_action on the ORIGINAL op's period
    (from the stored intent's executed/creation ts) rather than the period the
    flag arrives, so a late flag lands on the bucket read_counter_window sums
    for that op.

    A tz-NAIVE timestamp is treated as UTC (``replace(tzinfo=UTC)``), never as broker-
    local: ``.astimezone(UTC)`` on a naive datetime interprets it in the process's local
    zone, which would shift the derived bucket across a UTC boundary near midnight and
    land the flag on the wrong key. Broker timestamps are UTC by construction, so naive
    means "UTC, offset elided".
    """
    parsed = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return period_bucket_of(parsed, period)


@dataclass
class AgentRequest:
    """A raw tool invocation from the agent.

    This is the only input surface the agent has into the broker. The agent
    supplies tool, op, and args; everything else (taint, manifest, facts, decision)
    is derived by the broker.
    """

    tool: str
    op: str
    args: Any
    # #184 — the RAW confidence artifact the agent attached to this proposed action:
    # a dict off the HTTP body, or an already-typed ConfidenceArtifact in tests.
    # Validated by handle_request (never trusted as-shaped); a malformed artifact is
    # a loud deny, not a silent "no artifact". None = the agent supplied none.
    confidence: Any = None
    # Caller-supplied deduplication key ONLY. Replay with the same key returns the
    # stored outcome without re-executing. Pass None to skip deduplication. Since
    # sa#136 this does NOT influence turn identity — the broker owns the turn
    # boundary (see BrokerRuntime._session_turn), so an agent cannot vary this key
    # to shed accumulated taint.
    idempotency_key: str | None = None


@dataclass
class BrokerResponse:
    """The broker's reply to the agent.

    Design invariants (test-asserted in test_runtime.py):
      - No credential field exists on this dataclass.
      - No Connector or Doer reference is reachable from this object.
      - The agent cannot use this object to trigger connector execution directly.
    """

    # The effective decision kind: allow / deny / transform / require_approval / abstain.
    decision_kind: str
    # Set when the decision is deny or abstain.
    reason: str | None = None
    # Set when the decision is require_approval — the pending intent ID.
    intent_id: str | None = None
    # Set when the decision is allow or transform — the connector's opaque result.
    result: Any = None
    # True when the outcome was an idempotent replay (executor not called again).
    idempotent: bool = False
    # Set ONLY when the PDP allowed the call and the connector then did not complete
    # it: "failed" or "refused", the same vocabulary as AuditRecord.outcome. The
    # reply stays deny-shaped (no effect happened), so without this a mouth cannot
    # tell "the gate said no" from "the gate said yes and execution broke" except
    # by string-matching `reason`. None on every gate decision.
    execution_outcome: str | None = None


class BrokerRuntime:
    """The full broker runtime — composes all modules into a running process.

    One BrokerRuntime instance per broker process. The agent's harness calls
    handle_request() for each tool invocation.

    Parameters
    ----------
    principal:
        The agent principal this runtime is serving.
    grants:
        Active grants for this principal (read from the grant store at startup).
    doer:
        The capability-confined Doer. The PEP holds it internally; the agent
        never receives a reference to it.
    pip:
        Callable that resolves the current Facts for a BrokeredCall (reads grant
        state, counters, human reachability, etc.). Injected to keep the PEP testable.
    enforcement_store:
        Persistence backend for enforcement (idempotency records, counters, WAL).
    intent_store:
        Persistence backend for pending Intents (require_approval path).
    audit_sink:
        Append-only audit write surface. InMemorySink for tests; S3ObjectLockSink
        for production. The agent process must never hold a reference to this sink.
    trust_map:
        Per-agent InputTrustMap for taint evaluation. Injected; never baked here —
        the safe-default polarity is per-agent config, not a base invariant.
    envelope_hash:
        The real content-hash (``sha256:...``) of the risk envelope in force for
        this principal — ``compute_envelope_hash(manifest.envelope)`` (sa#122).
        Required (no default): a runtime must know which envelope it is deciding
        under. Stamped into every AuditRecord so each record is attributable to a
        specific envelope, and compared against each grant's ``envelopeHash`` at
        decision time (the PIP quarantines a grant issued under a different one).
    counter_cap:
        Hard budget cap applied by enforce() when decrementing the counter.
    trusted_read_sources:
        The consumer's ``Envelope.trusted_read_sources`` (sa#137) — source ids
        (``connector:{tool}.{op}``) whose external reads are trusted. Consulted
        HERE for the taint-skip half: a trusted external read does NOT self-taint
        the turn. The PIP consults the SAME list for the read rung-gate half; both
        derive from one envelope list, so there is no second source of truth.
        Defaults to empty — every external read untrusted (the safe default).
    confidence_knob:
        The consumer's ``Envelope.confidence`` (#184), extracted at build time (the
        ``approval_queue`` precedent). None = OFF: no below-bar gate, no error-budget
        metering, an attached artifact accepted-but-ignored. When set, its
        ``error_budget_tolerance`` drives the per-op per-UTC-day error-budget draw
        metered here (the PIP only reads that counter).
    on_demotion_signal:
        Advisory seam invoked once when a write crosses the error-budget tolerance —
        where the Phase-3 evaluator subscribes. Default None is log-only (the
        structured breach line still fires). A raising callback never fails the
        request (the broker's own decision already stands).
    counter_period:
        The manifest-named counter period (#212) every scoped_counter_key this
        runtime derives buckets at — caps, egress, error budget, evidence labels,
        flood keys. Default "utc-day" is byte-for-byte the pre-#212 key format.
        Authority-shaping: comes from the image-baked AgentManifest only, never
        a store.
    """

    def __init__(
        self,
        *,
        principal: Principal,
        grants: list[Grant],
        optable: ToolOpTable,
        doer: Doer,
        pip: Callable[[BrokeredCall], Facts],
        enforcement_store: EnforcementStore,
        intent_store: IntentStore,
        audit_sink: AuditSink,
        trust_map: InputTrustMap,
        envelope_hash: str,
        counter_cap: float = 100.0,
        trusted_read_sources: list[str] | None = None,
        approval_queue: ApprovalQueue | None = None,
        confidence_knob: Confidence | None = None,
        on_demotion_signal: Callable[[DemotionSignal], None] | None = None,
        counter_period: CounterPeriod = "utc-day",
        sub_grant_store: "SubGrantStore | None" = None,
    ) -> None:
        self._principal = principal
        self._grants = grants
        # #171 — the per-agent ToolOp table, compiled from the consumer manifest by
        # build_runtime. The PEP resolves every (tool, op) against THIS table, never a
        # base global: a consumer-defined op gates identically regardless of its name.
        self._optable = optable
        self._doer = doer
        self._pip = pip
        self._enforcement_store = enforcement_store
        self._intent_store = intent_store
        self._audit_sink = audit_sink
        self._trust_map = trust_map
        self._envelope_hash = envelope_hash
        self._counter_cap = counter_cap
        # #11 -- delegation-tree pool. None disables every pool draw, so an
        # undelegated deployment is byte-identical in behaviour and pays no extra
        # write per call. The store is broker-owned: nothing about the tree is
        # ever read from a call.
        self._sub_grant_store = sub_grant_store
        self._trusted_read_sources = trusted_read_sources or []
        # sa#160 approval-queue de-amplification knob. None = OFF (byte-identical
        # to the pre-knob hold path — no dedup, no flood cap).
        self._approval_queue = approval_queue
        # #184 calibrated-uncertainty knob — envelope.confidence extracted at build
        # time (the _approval_queue precedent). None = OFF: no below-bar gate, no
        # error-budget metering, an attached artifact is accepted-but-ignored (a
        # byte-identical no-op path). The signal seam is where the Phase-3 evaluator
        # subscribes to breach emissions; default None is log-only.
        self._confidence_knob = confidence_knob
        self._on_demotion_signal = on_demotion_signal
        # #212 — the manifest-named counter period. Every scoped_counter_key this
        # PEP derives (caps, egress, error budget, evidence labels, flood keys)
        # buckets at THIS period; default "utc-day" is byte-for-byte pre-#212.
        self._counter_period: CounterPeriod = counter_period
        # sa#136 — the broker-held turn boundary. One TurnContext per principal,
        # threaded across every /call, lazily created by _session_turn(). The agent
        # supplies neither its id nor its rollover signal (see new_turn()).
        self._current_turn: TurnContext | None = None

    def served_registry(self) -> list[ToolOp]:
        """Return the capability-scoped tool registry for this principal.

        An op absent from the result is absent — removal, not refusal.
        The agent cannot see a tool it was not granted.
        """
        return self._optable.served(self._principal, self._grants)

    def close(self) -> None:
        """Release connector-held OS resources (the Doer's ``close()``).

        The runtime half of graceful shutdown (MCP-HOST.md M20): a service
        catching SIGTERM drives this after its request loop drains, so an MCP
        connector reaps its stdio child before the process exits. Idempotent
        and best-effort per connector; holds no request-path state, so a
        closed runtime simply has connectors that refuse."""
        self._doer.close()

    def new_turn(self) -> None:
        """Roll the broker-held turn boundary — discard accumulated taint so the
        NEXT request starts a fresh turn (sa#136).

        Broker/harness-owned control: it is deliberately wired to NO agent-facing
        HTTP route (broker_server.py serves only /registry and /call), so the agent
        process — which reaches the runtime only across that HTTP surface — cannot
        invoke it. Only the trusted loop driver that owns this runtime object, or a
        human-side reset, may roll a turn. Turn identity is therefore broker-owned
        end-to-end: the agent supplies neither the turn id nor the rollover signal,
        so it cannot launder taint by declaring a fresh turn (memory/TAINT.md Rule 2).
        """
        self._current_turn = None

    def session_turn(self) -> TurnContext:
        """Return the broker-held session TurnContext (trusted-driver surface).

        Public counterpart of ``new_turn()``: only the trusted loop driver that
        owns this runtime object may call it — like ``new_turn()`` it is wired
        to NO agent-facing HTTP route, so the agent process cannot reach it.
        The channels drain worker (channels/DRAIN.md) uses it to feed an
        accepted envelope's provenance chain into the SAME turn the receiver
        will act on (``ingest_chain`` before the first ``handle_request``), so
        ingest and action share one broker-owned turn (sa#136).
        """
        return self._session_turn()

    def _tree_draws(
        self, principal: Principal, tool: str, op: str
    ) -> "tuple[CounterDraw, ...]":
        """The delegation-tree pool draws this call must also satisfy (#11).

        Empty when delegation is not configured, which is what keeps an
        undelegated deployment unchanged. Resolved through the SAME helper the
        PIP reads its cap fact from, so the bound the PDP reports and the bound
        enforce() draws are the same coordinate by construction.
        """
        draw = resolve_tree_pool(
            principal,
            tool,
            op,
            sub_grant_store=self._sub_grant_store,
            own_cap=self._counter_cap,
            period=self._counter_period,
        )
        return () if draw is None else (draw,)

    def _session_turn(self) -> TurnContext:
        """Return the broker-held TurnContext for this principal, lazily creating
        one with a broker-minted turn id (sa#136).

        The load-bearing change: across separate /call requests the runtime threads
        ONE TurnContext (taint accumulates), and its turn id is minted HERE — never
        derived from the agent-supplied idempotency_key. A successful external read
        in one /call self-taints this shared context (the sa#134 hook in _executor),
        so a tainted external write in a LATER /call escalates to require_approval.
        The turn rolls over only via new_turn() (broker/harness-owned), never on
        anything the agent controls.

        Concurrency boundary (NOT thread-safe by design): one runtime serves one
        principal, and this check-then-set — plus the TurnContext mutation over a
        request's lifetime — assumes calls are serialized per principal. Under
        ``ThreadingHTTPServer`` two concurrent /call requests could race here (mint
        two contexts, dropping one's taint) or snapshot taint before a sibling's
        read self-ingests it — a fail-OPEN direction. The prototype's single agent
        issues calls sequentially, so this does not bite today; a production broker
        that multiplexes concurrent or multi-session traffic needs per-session turn
        isolation (or locking), which is the same design surface as the
        harness-authenticated-turn alternative in docs/turn-identity.md. Tracked
        there, not closed here.
        """
        if self._current_turn is None:
            self._current_turn = TurnContext(turn_id=f"turn:{uuid.uuid4()}")
        return self._current_turn

    def _surface_quarantined_intent(self, exc: QuarantinedIntentError, op: str) -> None:
        """Loud, recorded surfacing of a tampered intent row (#349).

        Mirrors the sa#124 grant-quarantine surfacing: one ERROR log + one
        tamper-evident audit record, then the caller refuses. The tampered
        bytes were never parsed, so there are no trusted stored coordinates —
        the record carries the runtime's own principal, the seam that hit the
        quarantine as the op, and the intent id that binds it to the hold
        record already on the tape.
        """
        logger.error(
            "intent quarantined: intent_id=%s op=%s reason=%s",
            exc.intent_id,
            op,
            exc.reason,
        )
        emit(
            self._audit_sink,
            principal=self._principal,
            tool="intent-store",
            op=op,
            args={},
            decision="deny",
            outcome="denied",
            envelope_hash=self._envelope_hash,
            reason=f"intent quarantined: {exc.reason}",
            intent_id=exc.intent_id,
        )

    def _quarantined_intent_result(
        self, exc: QuarantinedIntentError, op: str
    ) -> ExecutionResult:
        """Surface a quarantined intent and return the refusal (#349) — the
        action does NOT run; never silently dropped, never auto-repaired."""
        self._surface_quarantined_intent(exc, op)
        return ExecutionResult(
            intent_id=exc.intent_id,
            executed=False,
            rejection_reason=f"intent quarantined: {exc.reason}",
        )

    def _reject_foreign_intent(self, intent_id: str) -> ExecutionResult | None:
        """Guard an out-of-band action against a DIFFERENT principal's intent (sa#176).

        The intent store is not principal-partitioned (store.py keys only on
        INTENT#{intent_id}), and the owner types an arbitrary intent_id. Without
        this check, at N>1 with a shared intent table a runtime bound to principal
        A could release principal B's frozen call under A's Doer / credentials /
        envelope — a confused deputy. Checked BEFORE any status transition, so a
        foreign intent is never even claimed. Returns an ExecutionResult to
        short-circuit on mismatch, or None to proceed (including when the intent is
        absent — approve()/reject() own the not-found path).
        """
        return self._foreign_intent_result(
            self._intent_store.get_intent(intent_id), intent_id
        )

    def _owns_intent(self, intent) -> bool:
        """True iff ``intent`` was frozen for THIS runtime's principal. The one ownership test.

        Compares the WHOLE principal (agentId, skill, user, tier): the identity
        tuple of GAL §5.1's Grant.principal, authority being per (principal,
        action-class) and never per-agent (§6.1), and the key scoped_counter_key
        and dedup_intent_id already use. Comparing agentId alone left the
        confused-deputy case open: the same agent acting on behalf of a different
        user (or skill, or tier) passed the check, released another user's frozen
        call through its OWN Doer, connector and credentials, and burned that
        user's single-use approval (test_approval_burn.py). Every out-of-band seam
        (approve, reject, describe, flag) must route through here.
        """
        return intent.materializedRequest.principal == self._principal

    def _foreign_intent_result(self, intent, intent_id: str) -> ExecutionResult | None:
        """Pure foreign-principal check over an already-fetched intent (sa#176).

        Split from _reject_foreign_intent so reject_intent can fetch the intent ONCE
        (it also needs the stored coordinates to label its evidence counters) and reuse
        that read here, rather than fetching a second time.
        """
        if intent is not None and not self._owns_intent(intent):
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason="intent belongs to a different principal",
            )
        return None

    def describe_intent(self, intent_id: str) -> IntentView | None:
        """Describe a held Intent so a human can SEE it before releasing it (#301).

        WYSIWYE has two halves and only the execution half was reachable: approve()
        runs the stored bytes, but nothing let an approval surface READ them, so
        every approver was left rendering from whatever the agent had said. This is
        the see half, and it reads the same stored record approve_intent executes.

        Returns None for an unknown intent, and — like the other out-of-band seams —
        for one belonging to a DIFFERENT principal, so this cannot be used to
        enumerate another agent's held calls. Absent and not-yours are deliberately
        the same answer.

        The boundary invariant holds: this returns a frozen IntentView of data, never
        the intent store, the Intent model, or the raw args (see IntentView). It
        executes nothing and transitions nothing — calling it on a pending intent
        leaves it pending.

        A tampered row (#349) surfaces loudly and returns None — the tampered
        bytes are never parsed, so there is nothing trustworthy to show an
        approver, and rendering them would set up exactly the tampered release
        the HMAC exists to refuse.
        """
        try:
            intent = self._intent_store.get_intent(intent_id)
        except QuarantinedIntentError as exc:
            self._surface_quarantined_intent(exc, op="describe")
            return None
        if intent is None:
            return None
        if not self._owns_intent(intent):
            return None
        stored = intent.materializedRequest
        return IntentView(
            intent_id=intent.id,
            status=intent.status,
            tool=stored.tool,
            op=stored.op,
            args_digest=hash_args(stored.args),
            rendered_for_human=intent.renderedForHuman,
            expiry=intent.expiry,
            ts=intent.ts,
            agent_id=stored.principal.agentId,
            approved_by=intent.approvedBy,
        )

    def approve_intent(self, intent_id: str, approved_by: str) -> ExecutionResult:
        """Release a held Intent after an authenticated owner approves it out-of-band (sa#176).

        The sanctioned out-of-band-approval seam: the channels drain worker calls
        this instead of reaching into the runtime's privates, so the boundary
        invariant holds — this method uses self._doer / self._intent_store
        INTERNALLY and returns only an ExecutionResult; it never returns or accepts
        a Doer or a store reference (pep.py header).

        WYSIWYE is preserved: approve() reads the STORED materializedRequest and the
        release runs exactly those bytes, never anything the agent re-sends.

        The release RE-VALIDATES current authority (#9). It routes through the same
        enforce() pipeline an inline call uses, over the stored call, with the
        approval requirement treated as already satisfied: fresh facts are read, the
        PDP is re-run, and a fresh require_approval is folded back to allow so the
        human's ratification cannot loop the call into a second hold. Everything the
        PDP can say that is STRICTER than allow still binds, so a grant revoked or
        demoted between hold and release refuses instead of executing. The release
        also draws the per-op budget counter, and an exhausted cap refuses it. Both
        refusals fail toward less authority: the Doer is never reached, an audit
        record carries the reason, and the intent lands in the terminal "refused"
        state.

        A revalidation that returns transform also refuses. WYSIWYE forbids running
        anything other than the bytes the human saw, and a transform is by
        construction a different op.

        Parameters
        ----------
        intent_id:
            The held intent to release and execute.
        approved_by:
            The authenticated human identity from the approval channel (never
            sourced from the agent). Recorded on the intent's approvedBy field.

        Returns
        -------
        ExecutionResult
            executed=True on success; executed=False with a rejection_reason when
            the intent is missing, expired, already actioned, frozen for a
            different principal, quarantined (#349: the stored bytes failed
            HMAC verification — a store rewrite between hold and release
            refuses instead of executing; the Doer is never reached), or when
            release-time revalidation refused ("release refused: …", #9).
        """
        try:
            foreign = self._reject_foreign_intent(intent_id)
        except QuarantinedIntentError as exc:
            return self._quarantined_intent_result(exc, op="approve")
        if foreign is not None:
            return foreign

        def _approved_decider(call: BrokeredCall, facts: Facts) -> Decision:
            """The release-time PDP wrapper — approval satisfied, authority still checked (#9).

            enforce()'s premise revalidation re-runs the PDP against fresh facts and
            keeps whichever outcome is stricter. Handed the raw decide() that would
            be wrong in one direction only: the call is held BECAUSE the PDP said
            require_approval, so an unchanged world re-decides to require_approval
            and the release would loop back into a second hold. This wrapper answers
            exactly that one requirement and nothing else.

              allow / require_approval → allow. The human ratified this call through
                  an authenticated path; the approval requirement is met.
              transform → deny. A transform substitutes a different op, and the human
                  approved the bytes they were shown (WYSIWYE). The approved call is
                  no longer executable as approved, so the release refuses and a
                  fresh call can be held against the new decision.
              deny / abstain → unchanged. The grant was revoked or demoted, a budget
                  is breached, a bound fired: an approval was never authority.
            """
            decided = decide(call, facts)
            if decided.kind in ("allow", "require_approval"):
                return Allow(kind="allow")
            if decided.kind == "transform":
                return Deny(
                    kind="deny",
                    reason=(
                        "release-time revalidation returned transform "
                        f"(op={getattr(decided, 'op', None)!r}); the approved call is "
                        "no longer executable as approved and a release never runs "
                        "anything other than the bytes the human saw"
                    ),
                )
            return decided

        def _exec(stored_call: BrokeredCall) -> Any:
            """Approved-executor closure — the release path's revalidate-then-execute (#9).

            Runs the STORED call through the same enforce() pipeline an inline call
            uses, so the release gets premise revalidation, the atomic per-op budget
            draw and a write-ahead ledger entry — the three things a direct Doer call
            skipped. _approved_decider supplies the one release-specific adjustment.

            On allow the connector runs and the audit footprint mirrors the inline
            _executor's (outcome "executed" on success, "failed" before re-raising a
            ConnectorExecutionError) plus the #198 receipts: intentId +
            storedCallDigest bind the release to the frozen intent, and approvedBy is
            stamped here (SCHEMAS.md §4 always claimed it was "copied into
            AuditRecord.approvedBy at execution time"; before #198 this path never
            passed it — a latent gap-A sub-bug).

            On anything stricter the release is REFUSED: a deny/abstain audit record
            names the reason beside the approver and the intent, and
            ReleaseRefusedError tells approve() to land the intent in "refused".
            """
            # #198 — recomputed INDEPENDENTLY from the stored bytes (never copied off
            # the hold record): hold-side == release-side proves executed==approved.
            stored_digest = hash_stored_call(stored_call)

            def _release_executor(call: BrokeredCall, effective: Decision) -> Any:
                """Connector execution callback — called by enforce() on allow."""
                try:
                    doer_result = self._doer.execute(call, effective)
                except ConnectorExecutionError as exc:
                    # #198 — a failed attempt still carries its approval binding (no
                    # result_digest: there is no result). An auditor must see WHICH
                    # approval led to a failed attempt.
                    emit(
                        self._audit_sink,
                        principal=call.principal,
                        tool=call.tool,
                        op=call.op,
                        args=call.args,
                        decision=effective.kind,
                        outcome="failed",
                        envelope_hash=self._envelope_hash,
                        approved_by=approved_by,
                        error=str(exc),
                        intent_id=intent_id,
                        stored_call_digest=stored_digest,
                    )
                    raise
                emit(
                    self._audit_sink,
                    principal=call.principal,
                    tool=call.tool,
                    op=doer_result.op,
                    args=call.args,
                    decision=effective.kind,
                    outcome="executed",
                    envelope_hash=self._envelope_hash,
                    approved_by=approved_by,
                    intent_id=intent_id,
                    stored_call_digest=stored_digest,
                    # #198 effect receipt — broker-written digest of what the world returned
                    result_digest=hash_args(doer_result.result),
                )
                # #193 — observations, approve-release path. An in-loop principal's acting
                # ops route require_approval → this release, and the inline executor's
                # observations meter never sees them; without this increment such a
                # principal could never accumulate the evidence that promotes it. Uses the
                # STORED call's coordinates. NOT counted on the ConnectorExecutionError
                # path above. Guarded: the side effect already ran and the intent is being
                # transitioned — a label fault must not escape (friction doctrine: log,
                # never gate), else the approved intent is stranded after its side effect
                # executed.
                try:
                    self._enforcement_store.try_increment_counter(
                        scoped_counter_key(
                            call.principal,
                            call.tool,
                            call.op,
                            OBSERVATIONS_SUFFIX,
                            period=self._counter_period,
                        ),
                        1.0,
                        UNBOUNDED_COUNTER_CAP,
                    )
                except Exception:  # noqa: BLE001 — a label must never gate the op it labels
                    logger.warning(
                        "evidence counter increment failed (observations, approve release) "
                        "for %s.%s — op already executed; continuing",
                        call.tool,
                        call.op,
                        exc_info=True,
                    )
                return doer_result.result

            # The SAME per-op budget key the inline /call path draws (#9): a release
            # spends the op's period budget exactly as an autonomous call would, so an
            # exhausted cap refuses the release instead of slipping past it.
            counter_key = scoped_counter_key(
                stored_call.principal,
                stored_call.tool,
                stored_call.op,
                ACTION_CAP_SUFFIX,
                period=self._counter_period,
            )
            # idempotency_key=None: approve()'s pending→approved CAS is already the
            # release's exactly-once gate, so a second enforcement-level key would add
            # a second, redundant dedup surface over the same event.
            # The release spends the tree's pool exactly as an inline call does
            # (#11). A held call whose SIBLINGS drained the shared pool between
            # hold and release must refuse: an approval was never authority, and
            # the pool is another bound the world can change while a call waits.
            enforced = enforce(
                stored_call,
                Allow(kind="allow"),
                idempotency_key=None,
                counter_key=counter_key,
                counter_delta=1.0,
                counter_cap=self._counter_cap,
                ancestor_draws=self._tree_draws(
                    stored_call.principal, stored_call.tool, stored_call.op
                ),
                decider=_approved_decider,
                fresh_facts=self._pip,
                store=self._enforcement_store,
                executor=_release_executor,
            )
            if enforced.decision.kind == "allow":
                return enforced.result

            # REFUSED. Nothing ran. Put it on the tape before raising: an auditor has
            # to be able to see that a human approved this intent and the broker
            # still refused it, and why.
            reason = getattr(enforced.decision, "reason", None) or "release refused"
            emit(
                self._audit_sink,
                principal=stored_call.principal,
                tool=stored_call.tool,
                op=stored_call.op,
                args=stored_call.args,
                decision=enforced.decision.kind,
                outcome="denied",
                envelope_hash=self._envelope_hash,
                reason=reason,
                approved_by=approved_by,
                intent_id=intent_id,
                stored_call_digest=stored_digest,
            )
            raise ReleaseRefusedError(reason)

        try:
            return approve(intent_id, approved_by, self._intent_store, executor=_exec)
        except QuarantinedIntentError as exc:
            # A rewrite that lands BETWEEN the foreign-check read and the
            # engine's own verify-then-parse read still refuses here (#349).
            return self._quarantined_intent_result(exc, op="approve")

    def reject_intent(self, intent_id: str, rejected_by: str) -> ExecutionResult:
        """Reject a held Intent on an authenticated owner's "no" — executes NOTHING (sa#176).

        The sibling of approve_intent for the /approve <id> no path. It delegates to
        the engine's reject(), which transitions the intent to the terminal
        "rejected" state via a compare-and-set and never constructs an executor — no
        connector is ever reached. Like approve_intent it holds the boundary
        invariant: self._intent_store is used INTERNALLY and only an ExecutionResult
        (always executed=False) is returned.
        """
        # Fetch ONCE: the stored coordinates label the evidence counters below, and the
        # same read feeds the foreign-principal guard (avoids a third store read).
        try:
            intent = self._intent_store.get_intent(intent_id)
            foreign = self._foreign_intent_result(intent, intent_id)
            if foreign is not None:
                return foreign
            result = reject(intent_id, rejected_by, self._intent_store)
        except QuarantinedIntentError as exc:
            # #349 — a tampered row is not transitioned, not labeled, not
            # parsed: refuse loudly and leave the evidence in place.
            return self._quarantined_intent_result(exc, op="reject")
        # Label the evidence counters ONLY when this call actually won the reject CAS
        # (not a missing / expired / already-actioned intent). An owner "no" is a
        # human_override; each terminal labeled outcome is also an observation, so
        # error_rate = overrides / observations stays <= 1.
        if result.rejection_reason == _REJECT_CAS_WIN_REASON:
            # Race: the pre-fetch may have missed an intent that reject()'s own fetch
            # then found and terminally rejected. Re-fetch on a CAS win to recover the
            # coordinates (the intent exists, terminally rejected, materializedRequest
            # intact); an unlabeled real owner "no" would drop evidence and fail toward
            # MORE authority. Only skip labeling if the re-fetch is somehow still None
            # — or quarantined (#349: the rejection stands, but a tampered row's
            # coordinates must not label anything; surface and skip).
            try:
                labeled = intent or self._intent_store.get_intent(intent_id)
            except QuarantinedIntentError as exc:
                self._surface_quarantined_intent(exc, op="reject")
                labeled = None
            if labeled is not None:
                req = labeled.materializedRequest
                # ONE guard around BOTH increments — a label must never gate the
                # rejection (friction doctrine: log, never gate). Ordered
                # HUMAN_OVERRIDE first, then OBSERVATIONS: if a fault splits the pair,
                # override-without-observation makes the predicate's
                # "false + override <= observations" check refuse a later propose —
                # failing toward LESS authority. The reverse order (observation without
                # override) would underestimate the error rate and fail toward MORE.
                try:
                    self._enforcement_store.try_increment_counter(
                        scoped_counter_key(
                            req.principal,
                            req.tool,
                            req.op,
                            HUMAN_OVERRIDE_SUFFIX,
                            period=self._counter_period,
                        ),
                        1.0,
                        UNBOUNDED_COUNTER_CAP,
                    )
                    self._enforcement_store.try_increment_counter(
                        scoped_counter_key(
                            req.principal,
                            req.tool,
                            req.op,
                            OBSERVATIONS_SUFFIX,
                            period=self._counter_period,
                        ),
                        1.0,
                        UNBOUNDED_COUNTER_CAP,
                    )
                except Exception:  # noqa: BLE001 — a label must never gate the rejection
                    logger.warning(
                        "evidence counter increment failed (reject) for %s.%s — "
                        "intent already rejected; continuing",
                        req.tool,
                        req.op,
                        exc_info=True,
                    )
        return result

    def flag_intent(self, intent_id: str, flagged_by: str) -> ExecutionResult:
        """Flag an already-EXECUTED intent as reviewed-wrong — writes false_action (#193 Phase 6c).

        The owner's third out-of-band verb (beside approve/reject): "/flag <intent_id>"
        on an op that already ran but, on review, should not have. It is the FIRST writer
        of the false_action evidence counter — the numerator of the promotion predicate's
        error rate (false_action / observations), so under the maintainer's ease-gradient doctrine a
        flagged op makes the acting grant HARDER to promote (easier to be demoted than to
        overcome the safeguards).

        Unlike the #193 observations/human_override label writes — which guard an execution
        or rejection path and so must log-never-gate — the counter write HERE is the PRIMARY
        effect. A failed write therefore returns a failed result and is NOT swallowed. It
        never touches observations (the op was counted when it executed) and never decrements
        anything.

        Refuses (failed result, writes nothing) — failing toward writing nothing — when the
        intent is unknown, belongs to a different principal (the same confused-deputy guard
        approve/reject use), or has not actually executed. Only a terminal "executed" intent
        is flaggable: false_action labels ops that took effect and were reviewed as wrong, so
        a pending / approved-but-failed / rejected / expired intent is refused.

        Idempotency: a per-intent cap-1 marker counter makes a re-flag a no-op (see
        _FLAG_MARKER_PREFIX). Residual: on the rare store fault where the marker claim
        succeeds but the false_action write then fails, a later /flag is refused as
        already-flagged and the count is lost — an undercount. A durable two-phase flag is
        deferred; the marker is claimed BEFORE the counter write so the common double-/flag
        case can never over- or double-count.

        Parameters
        ----------
        intent_id:
            The executed intent to flag.
        flagged_by:
            The authenticated human identity from the owner channel (never sourced from the
            agent). Not persisted here — flag writes evidence, not intent state.

        Returns
        -------
        ExecutionResult
            Always executed=False (nothing runs). rejection_reason is
            FLAGGED_BY_OWNER_REASON on a clean flag, or the matching
            unknown / foreign / not-executed / already-flagged reason.
        """
        # Fetch ONCE: the stored coordinates key the evidence counter below, and the same
        # read feeds the foreign-principal guard (mirrors reject_intent).
        try:
            intent = self._intent_store.get_intent(intent_id)
        except QuarantinedIntentError as exc:
            # #349 — tampered coordinates must not key a false_action write.
            return self._quarantined_intent_result(exc, op="flag")
        foreign = self._foreign_intent_result(intent, intent_id)
        if foreign is not None:
            return foreign
        if intent is None:
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason="intent not found",
            )
        # Only an op that actually took effect can be reviewed-as-wrong. "executed" is the
        # sole terminal reached via a real connector run (approve_intent's final transition);
        # "approved" means the release attempt FAILED (executor raised before the executed
        # transition), and pending / rejected / expired never ran. Refuse them all.
        if intent.status != "executed":
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason=f"intent not executed (current status: {intent.status})",
            )

        # Atomic idempotency claim BEFORE the primary write: the first /flag wins the cap-1
        # marker, a re-flag is refused — so the evidence counter can never be double-counted.
        marker_key = f"{_FLAG_MARKER_PREFIX}:{intent_id}"
        try:
            claimed = self._enforcement_store.try_increment_counter(
                marker_key, 1.0, _FLAG_MARKER_CAP
            )
        except Exception as exc:  # noqa: BLE001 — surface: the claim is on the primary path
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason=f"flag marker write failed: {exc}",
            )
        if not claimed:
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason="intent already flagged",
            )

        # Back-write false_action on the op's EXECUTION period so a late flag still lands
        # on the bucket read_counter_window sums for that op — not the period the flag
        # arrives. Prefer executedAt (the period the op TOOK EFFECT / was metered as an
        # observation); a hold that spans a period boundary would otherwise back-date the
        # flag to the HOLD period, one bucket off the observation it offsets. Fall back to
        # ts for a pre-executedAt intent.
        req = intent.materializedRequest
        original_bucket = _utc_bucket_of(
            intent.executedAt or intent.ts, self._counter_period
        )
        try:
            self._enforcement_store.try_increment_counter(
                scoped_counter_key(
                    req.principal,
                    req.tool,
                    req.op,
                    FALSE_ACTION_SUFFIX,
                    period=self._counter_period,
                    bucket=original_bucket,
                ),
                1.0,
                UNBOUNDED_COUNTER_CAP,
            )
        except Exception as exc:  # noqa: BLE001 — the counter write IS the flag's effect
            return ExecutionResult(
                intent_id=intent_id,
                executed=False,
                rejection_reason=f"flag counter write failed: {exc}",
            )

        # PII-safe attribution (the sa#153 / drain log discipline): the authenticated
        # flagger is NOT persisted on the intent (a flag writes evidence, not state), so
        # a structured log is the only record of WHO flagged. flagged_by is digested — an
        # owner identity is an email/handle — never emitted in clear; the bucket key
        # locates the evidence write. A full AuditRecord for the reject/flag side is #200.
        logger.info(
            json.dumps(
                {
                    "event": "intent_flagged",
                    "intent_id": intent_id,
                    "flagged_by_digest": "sha256:"
                    + hashlib.sha256(flagged_by.encode("utf-8")).hexdigest(),
                    "bucket": original_bucket,
                }
            )
        )
        return ExecutionResult(
            intent_id=intent_id,
            executed=False,
            rejection_reason=FLAGGED_BY_OWNER_REASON,
        )

    def _emit_demotion_signal(
        self, call: BrokeredCall, spent: float, tolerance: float
    ) -> None:
        """Emit the error-budget-breach DemotionSignal (#184).

        Fires once when a write's draw steps the per-op per-UTC-day error budget
        across its tolerance. The base only EMITS — it never applies a demotion; the
        Phase-3 grant-lifecycle evaluator consumes the signal. Emission is advisory:
        the broker's own decision on this call already stands, so a raising subscriber
        must not kill the request.
        """
        period = current_period_bucket(self._counter_period)
        signal = DemotionSignal(
            trigger=DemotionTrigger.budget_breach,
            principal=call.principal,
            action_class=f"{call.tool}.{call.op}",
            period=period,
            detail=(
                f"error budget breached: spent {spent:.4f} >= tolerance {tolerance:.4f}"
            ),
            ts=datetime.datetime.now(datetime.UTC).isoformat(),
        )
        # sa#153 structured, PII-safe log-metric surface — the approval_queue_flood
        # precedent: principal id + action class + period + a numeric cause, never args
        # or payload content.
        logger.error(
            json.dumps(
                {
                    "event": "demotion_signal",
                    "trigger": signal.trigger.value,
                    "agentId": call.principal.agentId,
                    "actionClass": signal.action_class,
                    "period": signal.period,
                    "detail": signal.detail,
                }
            )
        )
        if self._on_demotion_signal is not None:
            try:
                self._on_demotion_signal(signal)
            except Exception:  # noqa: BLE001 — advisory seam; the decision already stands
                logger.exception("on_demotion_signal callback raised; request unaffected")

    def handle_request(
        self,
        request: AgentRequest,
        *,
        turn_context: TurnContext | None = None,
        ingested_sources: list[str] | None = None,
    ) -> BrokerResponse:
        """Execute one brokered tool call through the full enforcement pipeline.

        Parameters
        ----------
        request:
            The agent's raw tool invocation.
        turn_context:
            Optional explicit TurnContext. When not supplied (the production /call
            path) the runtime threads its own broker-held session turn — see
            _session_turn — so taint accumulates across every /call and the turn id
            is broker-minted, never derived from the request (sa#136). Supply an
            explicit context to drive one turn deterministically (tests); when
            supplied it wins over the session turn.
        ingested_sources:
            Sources to ingest into the turn context before deciding. Used when
            the caller knows untrusted content touched this turn.

        Returns
        -------
        BrokerResponse
            The broker's reply. Contains no credential value.
        """
        # sa#136 — broker-owned turn identity. Production (/call) passes no
        # turn_context, so the runtime threads its OWN broker-held session context
        # across every /call for this principal — taint accumulates, and the turn id
        # is broker-minted (in _session_turn), decoupled from the agent-supplied
        # idempotency_key (which remains ONLY the enforce() dedup/replay key below).
        # Tests thread an explicit turn_context to drive one turn deterministically;
        # when supplied it wins. The agent bypasses neither: over HTTP it supplies no
        # turn_context and no longer influences the turn id, so it cannot mint a
        # fresh turn to shed taint before a write (memory/TAINT.md Rule 2).
        ctx = turn_context if turn_context is not None else self._session_turn()
        turn_id = ctx.turn_id

        # Step 1 — taint: ingest sources into the turn context.
        for source in ingested_sources or []:
            ctx.ingest_source(source, self._trust_map)
        taint = ctx.to_taint()

        # Step 2 — manifest lookup: reject ops absent from the manifest immediately.
        entry = self._optable.entry(request.tool, request.op)
        if entry is None:
            # #281 — RECORD it. This return precedes the PDP, and before the
            # gateway landed it wrote nothing at all: a refusal with no line on
            # the tape. That is the worse half of #281 and it correlates with the
            # SAFEST configuration, because the missileer archetype keeps a
            # dangerous op out of the manifest entirely rather than denying it —
            # so the hardened manifest was the one whose refusals were invisible.
            #
            # Shaped as deny/denied, identical to a classified-but-ungranted
            # refusal, because both are "the broker said no and nothing ran";
            # the reason string carries which. There is no principal-supplied
            # coordinate to validate here, so `op` is recorded as asked.
            reason = f"no manifest entry for {request.tool}.{request.op}"
            emit(
                self._audit_sink,
                principal=self._principal,
                tool=request.tool,
                op=request.op,
                args=request.args,
                decision="deny",
                outcome="denied",
                envelope_hash=self._envelope_hash,
                reason=reason,
            )
            return BrokerResponse(decision_kind="deny", reason=reason)

        # #184 — validate the raw confidence artifact BEFORE it can reach the PDP or
        # the error-budget meter. The broker never trusts the agent-supplied shape.
        # Read via getattr: the duck-typed request contract consumers write against
        # (channels/DRAIN.md receivers) predates #184 and does not carry the
        # attribute — an absent `confidence` is the same declaration as None.
        artifact: ConfidenceArtifact | None = None
        request_confidence = getattr(request, "confidence", None)
        if request_confidence is not None:
            try:
                artifact = (
                    request_confidence
                    if isinstance(request_confidence, ConfidenceArtifact)
                    else ConfidenceArtifact.model_validate(request_confidence)
                )
            except ValidationError:
                # Fail closed and loud: a malformed artifact is a contract violation,
                # not a missing one — do not downgrade it to "no artifact" (that would
                # let a garbage artifact dodge a configured bar's method restriction).
                return BrokerResponse(
                    decision_kind="deny",
                    reason="invalid confidence artifact",
                )

        ts = datetime.datetime.now(datetime.UTC).isoformat()
        session = Session(turnId=turn_id, ingestedSources=taint.sources)

        # Step 3 — materialize the BrokeredCall.
        call = BrokeredCall(
            principal=self._principal,
            tool=request.tool,
            op=request.op,
            args=request.args,
            manifest=entry,
            taint=taint,
            session=session,
            ts=ts,
            confidence=artifact,
        )

        # Step 4 — initial PDP decision (pure, no I/O).
        initial_facts = self._pip(call)

        # sa#124/#122 — a quarantined grant is treated as absent for the decision,
        # but the event must be LOUD: a silent fall-through to a normal deny would
        # be indistinguishable from an un-provisioned capability. Two distinct causes
        # flow through this single point, each carrying its own quarantine_reason:
        #   - HMAC mismatch (sa#124): tampering, mis-seeded key, or key-rotation drift.
        #   - envelope-hash mismatch (sa#122): the grant was issued under a different
        #     risk envelope than the one now in force.
        # Surface it HERE, exactly once, at the single initial read — NOT in
        # enforce()/fresh_facts, whose premise-revalidation re-read must stay silent
        # (quarantine is static within a request, so a second surface would double-log
        # one event). The wording stays cause-agnostic; the specific cause is in the
        # reason.
        if initial_facts.quarantined:
            logger.error(
                "grant quarantined: principal=%s action_class=%s reason=%s",
                call.principal.model_dump(),
                f"{call.tool}.{call.op}",
                initial_facts.quarantine_reason,
            )
            emit(
                self._audit_sink,
                principal=call.principal,
                tool=call.tool,
                op=call.op,
                args=call.args,
                decision="deny",
                outcome="denied",
                envelope_hash=self._envelope_hash,  # real in-force envelope hash (sa#122)
                reason=f"grant quarantined: {initial_facts.quarantine_reason}",
            )

        initial_decision = decide(call, initial_facts)

        # Principal+period scoped (see enforcement.scoped_counter_key for why);
        # the PIP reads the SAME derivation when it builds Facts.
        counter_key = scoped_counter_key(
            self._principal,
            request.tool,
            request.op,
            ACTION_CAP_SUFFIX,
            period=self._counter_period,
        )

        def _executor(brokered_call: BrokeredCall, effective) -> Any:
            """Connector execution callback — called by enforce() on allow/transform.

            The Doer is the only path to the connector; no credential escapes.
            On success audit is emitted immediately after the connector call. On a
            connector FAILURE we honour emit()'s documented invariant: write an
            AuditRecord with outcome="failed" (args stay hashed; the credential was
            already redacted by the Doer's ConnectorExecutionError) BEFORE re-raising,
            so enforce() can run its saga (compensate/escalate the WAL entry) and the
            PEP can turn it into a clean deny.

            Only the Doer's execution step is wrapped: a store/audit fault must still
            surface loudly (chaos invariant) rather than masquerade as a deny. A
            credential that fails to resolve is NOT such a fault: the broker's own
            machinery is intact and the call was allowed, so the Doer raises it as a
            CredentialResolutionError and it is recorded here like any other execution
            failure (#35). Before that it escaped with no audit record at all.
            """
            try:
                doer_result = self._doer.execute(brokered_call, effective)
            except ConnectorExecutionError as exc:
                # #281 — a connector-side control that REFUSED is not a failure.
                # `decision` stays as the PDP returned it (it did allow; saying
                # otherwise would misreport the policy engine), and the outcome
                # carries the distinction. `decision=allow, outcome=refused` is
                # the shape of "two-key admission declined after the PDP said
                # yes", and it cannot be confused with a crashed child.
                emit(
                    self._audit_sink,
                    principal=brokered_call.principal,
                    tool=brokered_call.tool,
                    op=brokered_call.op,
                    args=brokered_call.args,
                    decision=effective.kind,
                    outcome="refused" if getattr(exc, "refused", False) else "failed",
                    envelope_hash=self._envelope_hash,
                    error=str(exc),
                )
                raise
            # Emit audit at the moment of the side effect — never buffered.
            emit(
                self._audit_sink,
                principal=brokered_call.principal,
                tool=brokered_call.tool,
                op=doer_result.op,
                args=brokered_call.args,
                decision=effective.kind,
                outcome="executed",
                envelope_hash=self._envelope_hash,
                # #198 effect receipt — broker-written digest of what the world returned
                result_digest=hash_args(doer_result.result),
            )
            # sa#134 — broker-side taint self-ingestion. An external read pulls untrusted
            # content across a trust boundary; ingest a synthetic connector source into the
            # shared TurnContext so the NEXT op in this turn re-materializes taint at its own
            # handle_request entry (this call's decision is already made — no re-order). Scoped
            # to successful external reads; blanket-untrusted via the base trust_map (connector:
            # is not an internal: prefix, so it always taints). Fail-safe: over-tainting only
            # adds approvals. Cross-/call propagation is inert until broker-owned turn identity
            # (sa#136) — each HTTP /call still gets a fresh ctx.
            if brokered_call.manifest.external and brokered_call.manifest.effect == "read":
                source_id = f"connector:{brokered_call.tool}.{brokered_call.op}"
                # sa#137 — a read from a consumer-declared trusted source does NOT taint
                # the turn: skip the self-ingest for it. Untrusted reads still taint
                # (sa#134/136 preserved). Same envelope list the PIP's rung-gate reads —
                # one trusted_read_sources set consulted in both halves.
                if source_id not in self._trusted_read_sources:
                    ctx.ingest_source(source_id, self._trust_map)
                # sa#137 — meter the egress-arg bytes that actually crossed the wire so
                # the PIP's per-period query_egress_budget gate sees cumulative spend on
                # the NEXT read. Metered regardless of trust (trust gates taint, not
                # egress). This is the SINGLE metered write for query bytes; the PIP only
                # READS this counter, staying side-effect-free across its two invocations.
                egress_arg = brokered_call.manifest.egress_arg
                if egress_arg is not None and isinstance(brokered_call.args, dict):
                    arg_val = brokered_call.args.get(egress_arg)
                    if isinstance(arg_val, str):
                        self._enforcement_store.try_increment_counter(
                            scoped_counter_key(
                                brokered_call.principal,
                                brokered_call.tool,
                                brokered_call.op,
                                QUERY_BYTES_SUFFIX,
                                period=self._counter_period,
                            ),
                            float(len(arg_val.encode("utf-8"))),
                            _QUERY_BYTES_COUNTER_CAP,
                        )
            # #184 — error-budget metering. The SINGLE metered write for the error
            # budget (Σ error_prob × blast_radius), placed here beside the sa#137
            # query-bytes meter under the same discipline: the PEP is the sole writer,
            # the PIP only READS this counter for its breach fact. WRITES only — a read
            # carries no blast radius, so it does not draw the budget (the PDP rules are
            # write-scoped for the same reason).
            knob = self._confidence_knob
            if (
                knob is not None
                and knob.error_budget_tolerance is not None
                and brokered_call.manifest.effect == "write"
            ):
                blast = effective_blast_class(
                    brokered_call.manifest, set(knob.high_blast)
                )
                # A missing artifact draws the worst case (error_prob=1.0 — the
                # probability ceiling, not an invented domain number): omitting the
                # artifact must never be cheaper than supplying an honest one. With an
                # artifact present, error_budget_draw raises loudly on a missing weight;
                # the missing-artifact branch multiplies directly because the knob
                # validator guarantees all three weights exist whenever tolerance is set
                # (so blast_weights[blast] cannot KeyError here).
                if brokered_call.confidence is not None:
                    draw = error_budget_draw(
                        brokered_call.confidence, blast, knob.blast_weights
                    )
                else:
                    draw = 1.0 * knob.blast_weights[blast]
                key = scoped_counter_key(
                    brokered_call.principal,
                    brokered_call.tool,
                    brokered_call.op,
                    ERROR_BUDGET_SUFFIX,
                    period=self._counter_period,
                )
                self._enforcement_store.try_increment_counter(
                    key, draw, _ERROR_BUDGET_COUNTER_CAP
                )
                spent = self._enforcement_store.read_counter(key)
                tolerance = knob.error_budget_tolerance
                # Crossing detection: spent >= tol > (spent - draw) fires the signal
                # exactly ONCE per period under sequential calls (only the draw that
                # steps across the tolerance satisfies both halves). Concurrent racers
                # may double-fire — acceptable: the Phase-3 evaluator is deterministic
                # (same inputs, same outcome), and repeated runner passes on a
                # persistent breach each append a record-only demotion record; dedupe
                # is a caller/scheduler concern, not the evaluator's.
                if spent >= tolerance and (spent - draw) < tolerance:
                    self._emit_demotion_signal(brokered_call, spent, tolerance)
            # #193 — observations: one per successfully executed op, reads and writes
            # both. Placed LAST — after the sa#134 taint self-ingest + sa#137/#184 meters
            # — so its (guarded) failure can never reorder or skip those side effects.
            # A label write must NEVER fail the execution path it labels (friction
            # doctrine: log, never gate). Unguarded, a counter fault here would turn an
            # already-executed op into a reported failure, so enforce()/#148 records no
            # idempotency outcome and the agent retries → double-executes an irreversible
            # side effect. The per-op scoped key keeps the count correct; enforce()'s
            # idempotency short-circuit runs BEFORE this executor, so a replay never
            # double-counts. UNBOUNDED_COUNTER_CAP never refuses.
            try:
                self._enforcement_store.try_increment_counter(
                    scoped_counter_key(
                        brokered_call.principal,
                        brokered_call.tool,
                        brokered_call.op,
                        OBSERVATIONS_SUFFIX,
                        period=self._counter_period,
                    ),
                    1.0,
                    UNBOUNDED_COUNTER_CAP,
                )
            except Exception:  # noqa: BLE001 — a label must never gate the op it labels
                logger.warning(
                    "evidence counter increment failed (observations, inline execute) "
                    "for %s.%s — op already executed; continuing",
                    brokered_call.tool,
                    brokered_call.op,
                    exc_info=True,
                )
            # Return the connector's opaque result (a JSON-serializable dict) so it
            # rides back on EnforcementResult.result — and gets persisted on the
            # idempotency record for replay. The DoerResult wrapper stays internal.
            return doer_result.result

        # Step 5–6 — enforce: revalidate, counter, WAL, optional executor.
        # A connector failure propagates out of enforce() as ConnectorExecutionError
        # (after enforce() has marked the WAL entry compensated/escalated). We catch
        # ONLY that here and return a clean deny-shaped response instead of a 500 — the
        # audit record with outcome="failed" was already written inside _executor. That
        # includes a credential that could not be resolved (CredentialResolutionError,
        # #35). Every other fault (store/audit) still propagates loudly.
        try:
            result = enforce(
                call,
                initial_decision,
                idempotency_key=request.idempotency_key,
                counter_key=counter_key,
                counter_delta=1.0,
                counter_cap=self._counter_cap,
                ancestor_draws=self._tree_draws(call.principal, call.tool, call.op),
                decider=decide,
                fresh_facts=self._pip,
                store=self._enforcement_store,
                executor=_executor,
            )
        except ConnectorExecutionError as exc:
            # Deny-shaped reply — reuse the existing deny shape; no new schema. The
            # reason is generic; the specific error lives only on the broker-private tape.
            # `execution_outcome` carries the one structured bit a mouth needs to say
            # the gate allowed this, mirroring the outcome the audit record just got.
            return BrokerResponse(
                decision_kind="deny",
                reason="connector execution failed",
                idempotent=False,
                execution_outcome="refused" if exc.refused else "failed",
            )

        effective = result.decision

        # Idempotent replay — executor was not called; no new audit record. The
        # cached connector result is replayed from the idempotency record so the
        # caller gets the SAME outcome it got the first time, not None.
        if result.idempotent:
            return BrokerResponse(
                decision_kind=effective.kind,
                reason=getattr(effective, "reason", None),
                result=result.result,
                idempotent=True,
            )

        # Step 7 — handle the effective decision.
        if effective.kind in ("allow", "transform"):
            # The executor already ran and emitted audit; its opaque connector
            # result rode back on EnforcementResult.result.
            return BrokerResponse(
                decision_kind=effective.kind,
                result=result.result,
                idempotent=False,
            )

        if effective.kind == "require_approval":
            # Freeze the BrokeredCall as a pending Intent; the turn ends here.
            # The agent has no tool to approve or release it.
            assert isinstance(effective, RequireApproval)
            aq = self._approval_queue

            # sa#160 dedup: when on, hold under a CONTENT id so an identical
            # re-submission coalesces onto the same pending intent (no second
            # page). None dedup_id = today's ts-based hold, unchanged.
            dedup_id = None
            if aq is not None and aq.dedup:
                dedup_id = dedup_intent_id(
                    call.principal, call.tool, call.op, hash_args(call.args)
                )
            try:
                approval = materialize(
                    call, effective, self._intent_store, dedup_id=dedup_id
                )
            except QuarantinedIntentError as exc:
                # #349 — a tampered row squatting on the dedup id: never
                # coalesce onto it (its content cannot be trusted equal) and
                # never overwrite it (a fresh put would re-mint a valid HMAC
                # over the attacker's slot — an auto-repair). Refuse the hold.
                self._surface_quarantined_intent(exc, op="hold")
                return BrokerResponse(
                    decision_kind="deny",
                    reason=f"intent quarantined: {exc.reason}",
                    idempotent=False,
                )
            coalesced = approval.status == "coalesced"

            # sa#160 flood alarm: count NEW holds per principal+op+UTC-day; past
            # the cap, raise an alarm but STILL hold — never shed (shedding under
            # flood is a polarity decision, kept consumer-side). Coalesced holds
            # are already de-amplified, so they do not draw the counter.
            if (
                aq is not None
                and aq.max_pending_per_op_day is not None
                and not coalesced
            ):
                flood_key = scoped_counter_key(
                    self._principal,
                    call.tool,
                    call.op,
                    "approval",
                    period=self._counter_period,
                )
                within_cap = self._enforcement_store.try_increment_counter(
                    flood_key, 1, float(aq.max_pending_per_op_day)
                )
                if is_flood(within_cap):
                    # Structured, PII-safe alarm line (the sa#153 log-metric
                    # surface). No args, only principal id + op + cap.
                    logger.error(
                        json.dumps(
                            {
                                "event": "approval_queue_flood",
                                "agentId": self._principal.agentId,
                                "op": f"{call.tool}.{call.op}",
                                "cap": aq.max_pending_per_op_day,
                            }
                        )
                    )

            emit(
                self._audit_sink,
                principal=call.principal,
                tool=call.tool,
                op=call.op,
                args=call.args,
                decision=effective.kind,
                outcome="held",
                envelope_hash=self._envelope_hash,
                # Distinguish a de-amplified hold in the tamper-evident log. For a
                # coalesced hold that IS the reason this record exists — the
                # original hold's record carries the PDP's reason and the shared
                # intentId joins them. A fresh hold now carries that reason instead
                # of null, so the tape says what held the call (#300).
                reason=(
                    "approval-queue-coalesced" if coalesced else effective.reason
                ),
                # #198 approval binding: intentId always joins this hold to its
                # release; storedCallDigest only on a FRESH hold — a coalesced
                # hold's frozen call is the EARLIER hold's, so its binding lives on
                # that record and the shared intentId is the join.
                intent_id=approval.intent_id,
                stored_call_digest=None if coalesced else hash_stored_call(call),
            )
            return BrokerResponse(
                decision_kind=effective.kind,
                intent_id=approval.intent_id,
                idempotent=False,
            )

        # deny / abstain — no connector call; emit audit + return.
        reason = getattr(effective, "reason", None)
        # #184 — put the confidence artifact on the tamper-evident tape when an abstain
        # carried one (the audited-artifact DoD clause). PII-safe: the numbers + the
        # method name only, never annotations or payload content.
        if effective.kind == "abstain" and call.confidence is not None:
            a = call.confidence
            reason = (
                f"{reason} [confidence artifact: method={a.evidence.method} "
                f"confidence={a.confidence} error_prob={a.error_prob} stale={a.stale}]"
            )
        emit(
            self._audit_sink,
            principal=call.principal,
            tool=call.tool,
            op=call.op,
            args=call.args,
            decision=effective.kind,
            outcome="denied",
            envelope_hash=self._envelope_hash,
            reason=reason,
        )
        return BrokerResponse(
            decision_kind=effective.kind,
            reason=reason,
            idempotent=False,
        )
