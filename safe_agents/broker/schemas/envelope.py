"""Envelope schema — the typed per-agent risk-configuration artifact (sa#135).

Bridges the manifest-side untyped `envelope:` dict (agents/<name>.yaml) into a
validated Pydantic model, and provides a canonical content-hash over it. This is
the artifact + hash + pipeline-side validation ONLY: the running broker does not
yet load or consume this type at decision time — that is sa#122, which will use
`compute_envelope_hash` below to verify a Grant/AuditRecord's `envelopeHash`
against the envelope actually in force.

Schema fidelity: the four fields every real `agents/*.yaml` manifest exercises
today (`polarity`, `caps`, `allowlists`, `high_stakes`) are modeled with strict
types. The five remaining fields documented in `core/manifest-schema.md` but not
yet exercised by any real manifest (`reversibility_classes`, `fallback_budgets`,
`input_trust_map`, `promotion_predicates`, `autonomy_rungs`) are modeled as
permissive optional dicts — present so the schema is the complete single source of
truth, without over-committing to sub-shapes no manifest has exercised yet. Later
phases firm these up: `input_trust_map` firms into taint types in the follow-on
taint-completeness epic (sa#137); sa#134's broker-side self-ingestion has landed
but reads the base trust map, not this field yet. `autonomy_rungs`/
`promotion_predicates` firm up alongside the Grant lifecycle. The former
`abstention_thresholds` placeholder dict has ALREADY firmed up — into the typed
`Confidence` knob (#184) below — per the friction doctrine's "make it real or
delete it".
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from .evidence import BlastClass, ConfidenceMethod


class Liveness(BaseModel):
    """Typed liveness contract — the deterministic dead-man's-switch (sa#160).

    The availability floor. Prompt injection is not only an integrity/exfil
    attack; forcing an agent *silent* is a denial-of-service, and against the
    taint floor ("tainted → deny/require_approval") a poisoned input becomes the
    attacker's lever to force abstention. Under an act-safe polarity a silenced
    agent causes the exact harm it exists to prevent (see
    `docs/friction-doctrine.md`). This field is the smallest deterministic fix:
    a contract that says "the agent is expected to complete `expected_op` at
    least once every `deadline_seconds`", so a monitor can observe the *absence*
    of life without any model judging *why* the agent went quiet.

    Base ships the MECHANISM only. A missing `Envelope.liveness` (unset) means
    OFF — no monitoring, no silent "monitored" claim. Whether an agent turns
    liveness on, and how tight the deadline is, is DERIVED FROM POLARITY
    consumer-side (see `examples/liveness_policy.py`), never a base default.
    Polarity must not appear here — baking it in is the latent safety bug
    CLAUDE.md forbids.
    """

    model_config = ConfigDict(extra="forbid")

    # The "tool.op" whose successful audit/ledger append counts as a sign of
    # life. Chosen (over a dedicated heartbeat or a domain deliverable) because
    # the broker's AuditRecord is its OWN tamper-evident record, written under a
    # separate identity: the agent cannot forge it, and cannot suppress it
    # without actually failing to act. It is the runtime cousin of
    # assert-the-artifact (sa#25) and reuses the watcher/liveness.py run-record
    # signal (sa#38).
    expected_op: str
    # Max silence, in seconds, before the agent is considered overdue. Must be
    # positive — a zero/negative deadline is a configuration error, not "always
    # overdue". No default: a consumer that opts in must state the window.
    deadline_seconds: int = Field(gt=0)

    def overdue(self, *, last_seen_epoch: Optional[float], now_epoch: float) -> bool:
        """Deterministic monitor predicate: is the agent past its deadline?

        Pure — a timestamp comparison, no model in the path. `last_seen_epoch`
        is the epoch-seconds timestamp of the most recent *successful*
        `expected_op` audit append, or None if it has never been observed.
        Never observes WHY the agent went silent (a forced abstention is
        indistinguishable from a legitimate one and must stay so — judging the
        reason would make this a probabilistic gate, defeating the point). It
        observes only THAT the liveness contract was met within the window.

        None (never seen) → overdue: an opted-in agent that has produced no sign
        of life within its window has, factually, no observation in
        `[now - deadline_seconds, now]`.
        """
        if last_seen_epoch is None:
            return True
        return (now_epoch - last_seen_epoch) > self.deadline_seconds


class Caps(BaseModel):
    """Per-period atomic limits the broker enforces (fills Budgets).

    `actions_per_utc_day` is the only cap every real manifest sets today. Extra keys
    (e.g. `position_usd` in the consumer-agent doc example, core/manifest-schema.md)
    pass through so richer/future caps still carry into the hash without a schema
    change.

    Name history (#163): the field was authored as `actions_per_run`, but it has
    been a per-op per-UTC-day budget since the 2026-07-08 scoping fix
    (`enforcement.scoped_counter_key` keys the counter on principal+op+UTC-day, never
    per-run) — the name now says what it has meant all along. The old spelling is
    still ACCEPTED on load via a validation alias (that back-compat is the point: no
    `agents/*.yaml` churns), but the CANONICAL dumped key is `actions_per_utc_day`.
    Setting more than one spelling at once is rejected — an ambiguous
    double-declaration.

    Period generalization (#212): under a manifest with `counter_period` other
    than "utc-day", the cap scopes to that period (the counter key's bucket
    segment), so `actions_per_period` is the honest input spelling there. All
    three spellings name the SAME cap; the canonical dumped key stays
    `actions_per_utc_day` so no envelope hash churns.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    actions_per_utc_day: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices(
            "actions_per_utc_day", "actions_per_period", "actions_per_run"
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_both_cap_spellings(cls, data: object) -> object:
        """Reject input setting more than one spelling of the action cap.

        `extra="allow"` would otherwise let a non-canonical spelling ALSO survive
        as an extra key alongside the canonical one, silently double-declaring the
        cap. Fail loudly at load instead of guessing which one wins.
        """
        if isinstance(data, dict):
            spellings = [
                k
                for k in ("actions_per_utc_day", "actions_per_period", "actions_per_run")
                if k in data
            ]
            if len(spellings) > 1:
                raise ValueError(
                    f"caps sets {len(spellings)} spellings of the same action cap "
                    f"({', '.join(repr(s) for s in spellings)}); declare exactly one "
                    "(they are the same per-period cap, #163/#212)"
                )
        return data


class Allowlists(BaseModel):
    """Capability-scoped tool/destination set this agent may even see (default-deny).

    Extra keys (e.g. a future `destinations` allowlist) pass through so they still
    carry into the hash without a schema change.
    """

    model_config = ConfigDict(extra="allow")

    tools: list[str] = []


class ApprovalQueue(BaseModel):
    """Approval-queue de-amplification knob (sa#160 sub-item) — ships OFF.

    The availability floor's second half. When injection forces abstention, the
    taint floor escalates to `require_approval`; each poisoned call then holds an
    Intent and pages a human, so an attacker who can trigger many calls floods
    the human's attention — a queue-flooding denial-of-service. This knob
    de-amplifies that flood **without shedding** any distinct decision:

    - `dedup` coalesces truly-identical pending intents (same principal, tool,
      op, and args) into one — killing exact re-submission amplification. It
      never hides a genuinely distinct approval.
    - `max_pending_per_op_day` is a flood-alarm threshold: past it, the broker
      raises an `approval_queue_flood` alarm (the sa#153 log-metric surface) but
      **still holds the intent**. It never denies — shedding under flood is a
      polarity decision (it is the very DoS under act-safe polarity) and stays a
      consumer's call, not a base default.

    Unset on the Envelope = OFF (today's allow-and-audit behavior, byte-identical
    — no dedup, no cap). The base ships mechanism only; whether/how tightly to
    enable it is per-agent config, never polarity-derived in the base.
    """

    model_config = ConfigDict(extra="forbid")

    # Coalesce identical pending intents (de-amplification). Default off.
    dedup: bool = False
    # Per-principal+op+UTC-day count of NEW held intents past which an
    # `approval_queue_flood` alarm fires. None = no cap, no alarm. The intent is
    # ALWAYS still held — this is a signal, never a shed.
    max_pending_per_op_day: Optional[int] = Field(default=None, gt=0)


class Confidence(BaseModel):
    """Typed confidence bar + error budget (#184) — Envelope knob, unset = OFF.

    The calibrated-uncertainty floor. Base ships the MECHANISM — the artifact
    contract (`evidence.ConfidenceArtifact`), the deterministic `meets_bar`
    predicate, and the `error_prob × blast_radius` budget draw — while every number
    here is consumer-declared. A below-bar call routes to the per-agent safe response
    through the existing polarity seam (the abstain verb + the approval queue under
    an abstain-is-safe polarity); the polarity itself is NEVER base, the same rule
    `Liveness` (sa#160) and the safe-default polarity obey. Baking a bar or a
    polarity default in would be the latent safety bug CLAUDE.md forbids.

    This field is the typed firming of the former `abstention_thresholds` placeholder
    dict, per the friction doctrine's "make it real or delete it": an empty knob is a
    control that LOOKS enabled but gates nothing, so the validators reject one.
    """

    model_config = ConfigDict(extra="forbid")

    # the per-call confidence bar; None = no per-call bar
    min_confidence: Optional[float] = Field(default=None, ge=0, le=1)
    # accepted construction methods (selects/tightens WITHIN the closed catalog —
    # it cannot introduce a method); None = any method is accepted
    methods: Optional[list[ConfidenceMethod]] = None
    # per-UTC-day Σ (error_prob × blast_radius) bound, metered on the scoped-counter
    # seam (principal+op+UTC-day); None = no budget. Breach emits a `budget_breach`
    # DemotionSignal the Phase-3 evaluator consumes — the base emits, never applies.
    error_budget_tolerance: Optional[float] = Field(default=None, gt=0)
    # consumer-declared blast_radius weight per class (values must be > 0). REQUIRED
    # when error_budget_tolerance is set — the base never invents a domain weight.
    blast_weights: Optional[dict[BlastClass, float]] = None
    # tighten-only "tool.op" overrides forcing a decision's blast class to high; can
    # never LOWER a derived class (effective_blast_class enforces the one-way rule).
    high_blast: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _knob_is_real(self) -> "Confidence":
        """Reject a knob that looks enabled but gates nothing (friction doctrine).

        Three coupled invariants:
        - at least one of `min_confidence` / `error_budget_tolerance` must be set —
          an all-None knob is an enabled-looking control that bounds nothing.
        - a budget needs weights: `error_budget_tolerance` set ⇒ `blast_weights`
          present and covering ALL three blast classes (a missing class would make
          `error_budget_draw` raise mid-flight; catch it at load).
        - every declared weight is > 0 (a zero/negative blast radius is meaningless).
        """
        if self.min_confidence is None and self.error_budget_tolerance is None:
            raise ValueError(
                "Confidence knob sets neither min_confidence nor "
                "error_budget_tolerance; an empty knob gates nothing (remove it, or "
                "set a bar/budget)"
            )
        if self.blast_weights is not None:
            for cls_name, weight in self.blast_weights.items():
                if weight <= 0:
                    raise ValueError(
                        f"blast_weights[{cls_name!r}] = {weight}; a blast_radius "
                        "weight must be > 0"
                    )
        if self.error_budget_tolerance is not None:
            required = {"low", "medium", "high"}
            have = set(self.blast_weights or {})
            if have != required:
                missing = required - have
                raise ValueError(
                    "error_budget_tolerance is set but blast_weights does not cover "
                    f"every blast class (missing {sorted(missing)}); the base never "
                    "defaults a domain weight"
                )
        return self


class Envelope(BaseModel):
    """The typed risk-envelope artifact (`agents/<name>.yaml` `envelope:` block).

    `polarity` is the one field never defaulted — a missing polarity must be a
    hard validation error, not a silent default (see ARCHITECTURE.md §"The one
    thing that must NEVER be in the base").
    """

    model_config = ConfigDict(extra="forbid")

    # -- Exercised by every real agents/*.yaml manifest today, strict --------
    polarity: Literal["abstain", "act"]
    caps: Optional[Caps] = None
    allowlists: Optional[Allowlists] = None
    high_stakes: bool = False

    # -- Read gating + query-exfil bound (sa#137), consumer-configurable ------
    # trusted_read_sources: source ids (e.g. "connector:market.bars") whose
    # external reads are trusted — they bypass the in-loop read rung-gate AND do
    # not self-taint the turn. Consulted in BOTH halves (the PIP's rung-gate fact
    # and the PEP's taint-skip); empty = every external read is untrusted (the safe
    # default). max_query_bytes / query_egress_budget bound the agent-composed query
    # string that egresses to the provider: per-call byte cap and per-period
    # cumulative byte budget respectively. None = knob unset = no bound (the
    # mechanism is present; the magnitude is the consumer's to set).
    trusted_read_sources: list[str] = Field(default_factory=list)
    max_query_bytes: Optional[int] = None
    query_egress_budget: Optional[float] = None

    # -- Availability floor (sa#160), consumer-configurable -------------------
    # Typed liveness / dead-man's-switch contract. Unset = OFF (the base ships
    # no polarity default, and an unset field must never read as a false
    # "monitored" claim — see the Liveness docstring). A consumer derives its
    # default from polarity CONSUMER-SIDE (examples/liveness_policy.py).
    liveness: Optional[Liveness] = None

    # Approval-queue de-amplification (sa#160 sub-item). Unset = OFF (dedup off,
    # no flood cap) — byte-identical to today's allow-and-audit hold path. Never
    # sheds a distinct decision; see ApprovalQueue.
    approval_queue: Optional[ApprovalQueue] = None

    # -- Calibrated-uncertainty floor (#184), consumer-configurable -----------
    # Typed confidence bar + per-UTC-day error budget. Unset = OFF (no bar, no
    # budget). Supersedes the former permissive `abstention_thresholds` placeholder
    # dict, now firmed up per the friction doctrine's "make it real or delete it".
    # The base ships mechanism only; the below-bar polarity stays consumer-side.
    confidence: Optional[Confidence] = None

    # -- Documented (core/manifest-schema.md) but not yet exercised by any ---
    # -- real manifest; kept permissive until a later phase firms them up. ---
    reversibility_classes: Optional[dict] = None
    fallback_budgets: Optional[dict] = None
    input_trust_map: Optional[dict] = None  # taint-completeness epic (sa#137) firms this into taint types
    promotion_predicates: Optional[dict] = None  # firms up alongside the Grant lifecycle
    autonomy_rungs: Optional[dict] = None  # firms up alongside the Grant lifecycle


def compute_envelope_hash(envelope: Envelope) -> str:
    """Return the deterministic sha256 content-hash of an Envelope.

    Mirrors broker/audit/_hash.py's canonicalization exactly (sorted keys, compact
    separators, `default=str`) so the digest is stable across Python versions and
    field orderings. This is a plain content hash, not an HMAC — no secret key, so
    anyone holding the same envelope can independently recompute it. sa#122 will use
    this to verify a Grant/AuditRecord's `envelopeHash` matches the envelope that was
    actually in force at decision time.
    """
    serialized = json.dumps(
        envelope.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return "sha256:" + hashlib.sha256(serialized).hexdigest()
