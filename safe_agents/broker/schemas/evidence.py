"""Evidence contract — constructed confidence as a typed artifact (#184).

Pillar 4 (calibrated uncertainty). The base does NOT read a raw model logprob and
call it confidence: a logprob is a next-token statistic, not a claim about whether
*this action* is right. Confidence here is **constructed** — self-consistency across
independent samples, ensemble agreement, or a conformal threshold — and packaged as
a typed `ConfidenceArtifact` the deterministic gate can key on. Every function in
this module is pure: there is no model in the decision path (the same discipline as
`Liveness.overdue` — sa#160 — which observes THAT a contract was met, never judges
WHY).

What lives here, and at which tier (`docs/contract-vs-reference.md`):

- the **artifact** (`ConfidenceArtifact`), the **derivation** (`derive_blast_class`
  / `effective_blast_class`), the **below-bar predicate** (`meets_bar`), the
  **budget draw** (`error_budget_draw`), and the **demotion signal**
  (`DemotionSignal`) are CONTRACT surface — the shapes the grant lifecycle's
  promotion/demotion predicates consume, documented in `broker/EVIDENCE.md` and
  pinned by the E1–E10 conformance suite.
- the construction **methods** behind the closed `ConfidenceMethod` catalog are
  REFERENCE tier — pluggable, never model-selected, never an import path.
- the **bars/budgets/weights** are Envelope knobs (`Envelope.confidence`) shipping
  OFF: an unset knob is no gate. The base owns the mechanism; every number is
  consumer-declared, and the below-bar POLARITY (what a below-bar call routes to) is
  re-derived per agent, never in the base — the same rule the safe-default polarity
  and `Liveness` obey.

The base EMITS a `DemotionSignal` at breach detection; it never applies a demotion
itself (that is the Phase-3 evaluator's job — `grants.demotion.DemotionMetrics` maps
emitted signals to the tripped-trigger set).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Collection, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import DemotionTrigger, Principal

if TYPE_CHECKING:
    # ToolOp is a signature-only annotation here (never a model field), so it lives
    # under TYPE_CHECKING: brokered_call.py now imports ConfidenceArtifact from THIS
    # module at runtime (#184), and a runtime ToolOp import here would close that cycle.
    from .brokered_call import ToolOp
    from .envelope import Confidence


# The closed catalog of confidence-construction methods. A Literal, deliberately —
# not an import path (the config-provenance "store cannot inject code" genre): a
# manifest/store selects a method, it can never introduce one. Adding a method is a
# base PR with a conformance test, never a store write.
ConfidenceMethod = Literal["self-consistency", "ensemble", "conformal"]


class SelfConsistencyEvidence(BaseModel):
    """Agreement across independent samples of the same prompt.

    Confidence is the fraction of `samples` that reached the proposed action; more
    agreement, higher confidence. Not a logprob — a repeated-draw statistic.
    """

    model_config = ConfigDict(extra="forbid")

    method: Literal["self-consistency"] = "self-consistency"
    # independent samples drawn — > 1 (one sample cannot agree with itself)
    samples: int = Field(gt=1)
    # fraction of samples agreeing with the proposed action
    agreement: float = Field(ge=0, le=1)


class EnsembleEvidence(BaseModel):
    """Agreement across distinct ensemble members (different models/prompts)."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["ensemble"] = "ensemble"
    members: int = Field(gt=1)
    agreement: float = Field(ge=0, le=1)


class ConformalEvidence(BaseModel):
    """A calibrated conformal threshold in force at construction time.

    `coverage` is the target level (1 - alpha); `threshold` is the calibrated
    cutoff; `calibration_size` is the calibration set behind it. A stale artifact
    (drift) voids this threshold — see `ConfidenceArtifact.stale`.
    """

    model_config = ConfigDict(extra="forbid")

    method: Literal["conformal"] = "conformal"
    # target coverage level (1 - alpha); strictly inside (0, 1)
    coverage: float = Field(gt=0, lt=1)
    # the calibrated conformal threshold in force
    threshold: float
    # size of the calibration set behind the threshold
    calibration_size: int = Field(gt=0)


# Method-discriminated construction evidence. The discriminator makes the wire
# self-describing and rejects an unknown method value at validation (E2).
ConfidenceEvidence = Annotated[
    SelfConsistencyEvidence | EnsembleEvidence | ConformalEvidence,
    Field(discriminator="method"),
]


class ConfidenceArtifact(BaseModel):
    """The typed confidence artifact a gate keys on (#184).

    Constructed confidence packaged as a contract: the value, the error-budget draw
    numerator, the method-discriminated evidence, and a drift flag. Never a raw
    logprob read — `confidence` is the constructed value, and `error_prob` is a
    method-specific error estimate NOT forced to equal `1 - confidence`.
    """

    model_config = ConfigDict(extra="forbid")

    # the constructed confidence value — never a raw logprob
    confidence: float = Field(ge=0, le=1)
    # the error-budget draw numerator; method-specific, NOT forced to equal
    # 1 - confidence (a conformal error estimate and a self-consistency
    # disagreement rate are different numbers)
    error_prob: float = Field(ge=0, le=1)
    # method-discriminated construction evidence
    evidence: ConfidenceEvidence
    # label-free drift flag — voids the conformal threshold; a stale artifact never
    # meets a bar (#65 absorbed: the drift DETECTOR is reference-tier and later; this
    # is the input it sets)
    stale: bool = False
    # ISO-8601 UTC timestamp of construction
    computed_at: str
    # attach-only findings (e.g. the #58 evidence reviewer raises suspicion here).
    # NEVER read by any gate — an annotation cannot license or veto anything; it is
    # a place to record, not a place to decide.
    annotations: list[str] = Field(default_factory=list)


# The blast class a decision falls in — the blast_radius axis of the error-budget
# draw. Derived from the ToolOp classification, never separately declared.
BlastClass = Literal["low", "medium", "high"]


def derive_blast_class(op: ToolOp) -> BlastClass:
    """Derive a decision's blast class from its ToolOp classification (#184).

    Pure derivation — no new declaration invented; the class falls out of the same
    effect/external/reversible facts the PDP already keys on:

    - **high**: an external write whose mistake is not recoverable
      (`reversible is not True`). `reversible is None` counts as not-recoverable —
      the conservative reading, the SAME polarity as `enforce()`'s saga, which
      escalates when reversible is not True.
    - **medium**: any other write (internal, or a reversible external write).
    - **low**: a read.
    """
    if op.effect == "read":
        return "low"
    if op.external and op.reversible is not True:
        return "high"
    return "medium"


def effective_blast_class(op: ToolOp, high_blast_overrides: Collection[str]) -> BlastClass:
    """The blast class after consumer overrides — TIGHTEN-ONLY (#184).

    If `f"{op.tool}.{op.op}"` is in `high_blast_overrides`, the class is forced to
    "high"; otherwise it is `derive_blast_class(op)`. There is deliberately NO input
    that LOWERS a derived class (decided 2026-07-12): an override can only raise the
    blast reading, never let a consumer talk a high-blast op down to medium.
    """
    if f"{op.tool}.{op.op}" in high_blast_overrides:
        return "high"
    return derive_blast_class(op)


def meets_bar(artifact: ConfidenceArtifact | None, knob: Confidence | None) -> bool:
    """The deterministic below-bar predicate the PDP wiring will call (#184).

    Returns True when the artifact clears the configured confidence bar (or no bar
    is configured). The wiring slice routes a False through the per-agent safe
    response (the polarity seam); this predicate is the seam it calls. `knob` is
    duck-typed against `Envelope.confidence` (imported lazily under TYPE_CHECKING —
    `envelope.py` imports FROM this module, so a module-level import here would
    circular-import). Semantics:

    - `knob is None` or `knob.min_confidence is None` → True (no bar = no gate; OFF).
    - `artifact is None` → False (a bar is set but nothing was constructed = below).
    - `artifact.stale` → False (drift voids the threshold).
    - a bar restricts methods and this artifact's method is not among them → False.
    - otherwise → `artifact.confidence >= knob.min_confidence`.
    """
    if knob is None or knob.min_confidence is None:
        return True
    if artifact is None:
        return False
    if artifact.stale:
        return False
    if knob.methods is not None and artifact.evidence.method not in knob.methods:
        return False
    return artifact.confidence >= knob.min_confidence


def error_budget_draw(
    artifact: ConfidenceArtifact,
    blast_class: BlastClass,
    blast_weights: Mapping[str, float],
) -> float:
    """The per-decision error-budget draw: `error_prob × blast_radius` (#184).

    `blast_radius` is the consumer-declared weight for the decision's blast class
    (`Budgets` §6: the error budget is drawn down as `Σ error_prob × blast_radius`).
    A class with no declared weight is a configuration error surfaced LOUDLY — a
    `ValueError`, never a silent default (the base never invents a domain weight).
    """
    try:
        blast_radius = blast_weights[blast_class]
    except KeyError:
        raise ValueError(
            f"no blast_radius weight declared for blast class {blast_class!r}; "
            "declare a weight for every class in Envelope.confidence.blast_weights "
            "(the base never defaults a domain weight)"
        ) from None
    return artifact.error_prob * blast_radius


class DemotionSignal(BaseModel):
    """Typed demotion input emitted by evidence machinery (#184).

    Emitted at breach detection (e.g. an error-budget breach → `budget_breach`), and
    consumed by the Phase-3 evaluator (`grants.demotion.DemotionMetrics` maps emitted
    signals to the tripped-trigger set). The base EMITS this signal; it never applies
    a demotion itself — demotion is deterministic and lives in the grant lifecycle.
    """

    model_config = ConfigDict(extra="forbid")

    # reuses the base DemotionTrigger vocabulary (common.py) — no new trigger names
    trigger: DemotionTrigger
    principal: Principal
    # the (principal, action-class) grant coordinate the signal demotes against
    action_class: str
    # UTC day "YYYYMMDD" — the same period vocabulary as the scoped-counter seam
    # (principal+op+UTC-day), so a breach and its budget window line up
    period: str
    # human-readable cause, audit-safe — no payload content (the audit-surface PII
    # discipline: a reason, never the bytes that triggered it)
    detail: str
    # ISO-8601 UTC emission time
    ts: str


class CorroborationRecord(BaseModel):
    """A k-of-n independent-source quorum result — the corroboration_failure input (#192).

    The typed shape a corroboration pass PRODUCES and the demotion runner CONSUMES
    (`grants.runner.derive_corroboration_failure`): a premise was checked against `n`
    independent sources and `agreeing` of them — non-stale, provenance-valid — agreed;
    the quorum requires `k`. `agreeing < k` is the deterministic failure predicate
    (broker/grant-lifecycle.md §Demotion trigger 2). The corroboration PASS that
    produces this record — which sources, what counts as agreement, how staleness and
    provenance validity are judged — is consumer/reference-tier, exactly as the drift
    detector is for `ConfidenceArtifact.stale`; this contract owns only the shape and
    its consequence. Failed corroboration pushes toward abstain and demotion, never
    toward allow.
    """

    model_config = ConfigDict(extra="forbid")

    # the quorum: agreeing sources required for the premise to stand
    k: int = Field(ge=1)
    # independent sources consulted
    n: int = Field(ge=1)
    # sources that agreed AND were non-stale with valid provenance — the producer
    # excludes stale/invalid sources from this count; they can never carry a quorum
    agreeing: int = Field(ge=0)
    # consulted sources discarded as stale (audit detail; never adds to agreeing)
    stale_sources: int = Field(default=0, ge=0)
    # ISO-8601 UTC timestamp of the corroboration pass
    computed_at: str
    # attach-only findings, same discipline as ConfidenceArtifact.annotations:
    # NEVER read by any gate — a place to record, not a place to decide
    annotations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _coherent_counts(self) -> "CorroborationRecord":
        if self.k > self.n:
            raise ValueError(f"quorum k={self.k} exceeds sources consulted n={self.n}")
        if self.agreeing > self.n:
            raise ValueError(f"agreeing={self.agreeing} exceeds sources consulted n={self.n}")
        if self.stale_sources > self.n:
            raise ValueError(
                f"stale_sources={self.stale_sources} exceeds sources consulted n={self.n}"
            )
        return self

    @property
    def failed(self) -> bool:
        """True iff the premise failed its quorum — the one deterministic predicate."""
        return self.agreeing < self.k
