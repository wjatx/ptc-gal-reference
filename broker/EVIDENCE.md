# EVIDENCE — constructed confidence as a typed contract (#184, Pillar 4)

> **Status: contract (2026-07-12).** Contract-tier per `docs/contract-vs-reference.md`: this document
> is the normative words, `safe_agents/broker/schemas/evidence.py` (`ConfidenceArtifact`,
> `ConfidenceEvidence`, `derive_blast_class`, `effective_blast_class`, `meets_bar`,
> `error_budget_draw`, `DemotionSignal`) is the base-owned shape + deterministic predicates, and
> `safe_agents/broker/tests/test_evidence_contract.py` is the E1–E10 conformance suite. Companion to
> `broker/SCHEMAS.md` (§3 Decision's *constructed confidence* Fact and §6 Budgets' error draw this
> fills, and §1's `DemotionTrigger` this emits) and `docs/friction-doctrine.md` (the knob-ships-OFF
> rule this obeys).

## What this is — and what it is not

Pillar 4 asks a decision to carry a calibrated "how sure am I", so a low-confidence high-blast act
can route to a human instead of firing. The wrong way to get that number is to read a raw model
logprob: a logprob is a next-token statistic, not a claim about whether *this action* is correct, and
a model asserting its own confidence is exactly the self-report the broker exists to not trust.

The evidence contract packages **constructed** confidence — agreement across independent samples
(self-consistency), across ensemble members, or against a calibrated conformal threshold — as a typed
`ConfidenceArtifact` that a **deterministic** predicate gates on. Every function here is pure; there
is no model in any gate (the same discipline as `Liveness.overdue`, sa#160, which observes THAT a
contract was met, never judges WHY).

It is **not** a new decision verb, a new grant, or a taint mechanism. Whether a call is *allowed* is
the PDP's job; this contract only supplies the confidence Fact the PDP keys on and the demotion
signal the grant lifecycle consumes.

## The tiers (what ships as what)

Packaged per `docs/contract-vs-reference.md`:

- **CONTRACT** — the artifact (`ConfidenceArtifact`), the derivation (`derive_blast_class` /
  `effective_blast_class`), the below-bar predicate (`meets_bar`), the budget draw
  (`error_budget_draw`), and the demotion signal (`DemotionSignal`). This doc + the E1–E10 suite.
- **REFERENCE** — the construction *methods* behind the closed `ConfidenceMethod` catalog
  (self-consistency / ensemble / conformal), one honest constructor each in
  `safe_agents/evidence/methods.py` — adoptable as-is, swappable by construction (a third-party
  constructor whose artifact passes the same E1/E2 validation is equally valid), and split-ready
  (imports only the contract surface). A method is *selected*, never *injected* — the catalog is a
  `Literal`, not an import path (the config-provenance "store cannot inject code" genre); adding one is
  a base PR with a conformance test. The worked consumer is `examples/confidence_budget/`.
- **Envelope knob (Layer-2 store config)** — `Envelope.confidence`: the bar, accepted methods, the
  error budget, the blast weights, the tighten-only override list. Select-or-tighten only; mutates via
  ceremony. **Ships OFF** — an unset knob is no gate.

## The contract

```ts
type ConfidenceMethod = "self-consistency" | "ensemble" | "conformal"   // CLOSED catalog

interface ConfidenceArtifact {
  confidence:  number   // constructed value in [0,1] — never a raw logprob
  error_prob:  number   // the error-budget draw numerator; method-specific, NOT forced to 1 - confidence
  evidence:    ConfidenceEvidence   // method-discriminated construction evidence
  stale:       boolean  // label-free drift flag; voids the conformal threshold
  computed_at: string   // ISO-8601 UTC
  annotations: string[] // attach-only; NEVER read by any gate
}

interface DemotionSignal {
  trigger:      "stale_confidence" | "corroboration_failure" | "budget_breach" | "false_action"
  principal:    Principal
  action_class: string
  period:       string  // the counter-period bucket: "YYYYMMDD" (utc-day) or "YYYYMMDDTHH" (utc-hour, #212)
  detail:       string  // audit-safe cause, no payload content
  ts:           string
}

interface CorroborationRecord {          // the corroboration_failure typed input (#192)
  k:             int     // quorum: agreeing sources required (1..n)
  n:             int     // independent sources consulted
  agreeing:      int     // non-stale, provenance-valid agreeing sources (0..n)
  stale_sources: int     // consulted-but-discarded-as-stale (audit detail; never counts)
  computed_at:   string  // ISO-8601 UTC
  annotations:   string[] // attach-only; NEVER read by any gate
}
// failed ⇔ agreeing < k — the one deterministic predicate. The corroboration
// PASS that produces the record (source choice, agreement judgment, staleness/
// provenance vetting) is consumer/reference-tier, like the drift detector.
```

### Blast-class derivation (tighten-only)

`blast_radius` is the second factor of the error draw, and it is **derived** from the ToolOp
classification, never separately declared:

| blast class | condition |
|---|---|
| **high** | `effect == "write"` ∧ `external` ∧ `reversible is not True` (`reversible: null` ⇒ not-recoverable — the conservative reading, same polarity as `enforce()`'s saga) |
| **medium** | any other write (internal, or a reversible external write) |
| **low** | a read |

A consumer `high_blast` list of `"tool.op"` keys can **tighten** a derived class up to `high`; it can
never LOWER one (`effective_blast_class` is one-way — decided 2026-07-12). There is no lowering input.

### The below-bar seam

`meets_bar(artifact, Envelope.confidence)` is the deterministic predicate the PDP wiring will call:

- `knob is None` or `knob.min_confidence is None` → **True** (no bar = no gate; OFF).
- `artifact is None` → **False** (a bar is set but nothing was constructed).
- `artifact.stale` → **False** (drift voids the threshold).
- the bar restricts `methods` and this artifact's method is not among them → **False**.
- otherwise → `artifact.confidence >= knob.min_confidence`.

A `False` (below-bar) routes to the **per-agent safe response** through the existing polarity seam:
under an abstain-is-safe polarity that is the `abstain` verb + the approval queue; the base ships the
**wiring**, never the polarity (baking a polarity default in is the latent safety bug CLAUDE.md
forbids). **The wiring has landed:** a write below the bar routes through the `abstain` verb via the
rule pair `confidence_below_bar_escalate` / `confidence_below_bar_deny`, sitting immediately beside the
error-budget pair in `pdp/engine.py` (below-bar is the PER-CALL gate; the error budget is the
CUMULATIVE one — GAL §7's two mechanisms). The below-bar Fact is set by the PIP calling `meets_bar`;
an abstain carrying an artifact is enriched onto the audit tape (method + numbers only, PII-safe).
A missing artifact is below-bar whenever a bar is configured. Proven by `test_confidence_wiring.py`
(W1–W10, E11–E14 below).

### Error budgets

`error_budget_draw(artifact, blast_class, blast_weights)` returns `error_prob × blast_radius`, drawn
per decision against a **per-period** `Σ error_prob × blast_radius` bound (UTC-day by default; the
manifest's `counter_period`, #212)
(`Envelope.confidence.error_budget_tolerance`), metered on the scoped-counter seam
(principal+op+UTC-day precedent, suffix `error_budget`). A class with no declared weight raises loudly
— a `ValueError`, never a silent default. A breach emits the typed `DemotionSignal` with
`trigger = "budget_breach"`, which the Phase-3 evaluator consumes; **the base emits, never applies** a
demotion. **The metering has landed:** the PEP is the SINGLE writer (drawn in `_executor` after a
successful WRITE, beside the sa#137 query-bytes meter), the PIP only READS the counter to set the
cumulative `error_budget_breached` Fact the now-real rules 2/3 key on, and a missing artifact draws
`error_prob = 1.0` (the probability ceiling) so omission never dodges the budget. Crossing the
tolerance emits the signal on the sa#153 log-metric surface AND the `on_demotion_signal` seam
(a raising subscriber never fails the request).

### stale_confidence (drift)

The artifact's `stale` flag is the **label-free drift input** (#65 absorbed): a stale artifact voids
its conformal threshold and so is always below-bar. The drift **detector** that sets the flag is
reference-tier and lands later; this contract only defines the input and its below-bar consequence.

The demotion runner consumes both typed inputs directly (#192): `derive_stale_confidence`
(a stale artifact → the `stale_confidence` signal) and `derive_corroboration_failure`
(a `CorroborationRecord` with `agreeing < k` → the `corroboration_failure` signal), wired as
`--stale-artifact-json` / `--corroboration-json` on the runner CLI. Both consume the typed
evidence AS GIVEN — deterministic, no model, no re-judgment of why — and an unusable input
file refuses loudly (exit 2), never falling through to "no breach".

### The #58 evidence reviewer

`annotations` is **attach-only**: a reviewer (or any upstream) may record a finding there, but nothing
in this contract reads it. An annotation cannot license or veto anything — it is a place to record, not
a place to decide.

## Conformance clauses

- **E1 — artifact shape.** `ConfidenceArtifact` round-trips; rejects unknown keys and out-of-range
  `confidence`/`error_prob`; per-method evidence discriminates (wrong fields for a method rejected).
- **E2 — closed catalog.** An unknown `method` value is rejected; a dotted import-path string is not a
  selectable method.
- **E3 — blast derivation.** The truth table above holds for every effect/external/reversible combo.
- **E4 — knob ships OFF.** An Envelope without `confidence` validates; `meets_bar` with a `None` knob
  (or a budget-only knob) is True for any artifact and for `artifact = None`.
- **E5 — tighten-only.** An override forces `high`; nothing lowers a derived class (asserted by
  exhaustion over the truth table).
- **E6 — meets_bar.** Stale → False even above bar; method-not-accepted → False; no-artifact-with-bar →
  False; at/above bar → True.
- **E7 — budget draw.** `error_budget_draw` = `error_prob × weight` per class; a missing weight raises
  `ValueError`.
- **E8 — caps rename (#163).** Both `actions_per_run` and `actions_per_utc_day` load to one field; the
  canonical dump key is the new one; setting both at once is rejected; the old spelling does not leak as
  an extra key; the two spellings' envelope hashes are equal.
- **E9 — demotion signal.** `DemotionSignal` round-trips; the trigger vocabulary is exactly the four
  `DemotionTrigger` values; extra keys rejected.
- **E10 — loud legacy rejection.** An Envelope carrying the retired `"abstention_thresholds"` key fails
  validation (`extra="forbid"`); an incoherent `Confidence` knob (budget without weights, or empty) is
  rejected.

- **E15 — corroboration record (#192).** `CorroborationRecord` round-trips; rejects unknown keys and
  incoherent counts (`k > n`, `agreeing > n`, `stale_sources > n`); `failed` is exactly
  `agreeing < k`.

The wiring slice (`test_confidence_wiring.py`, W1–W10) pins four further clauses:

- **E11 — knob OFF is a no-op.** With no `Envelope.confidence`, an attached artifact is
  accepted-but-ignored, a write executes exactly as before, and no `error_budget` counter key is ever
  written (W1). The seam is genuinely OFF, not merely defaulted-permissive.
- **E12 — below-bar routes to abstain.** A write below the bar (or with a missing artifact when a bar is
  set, or a stale artifact above the bar) routes through the `abstain` verb; the executor is not called;
  the abstain's audit reason carries the artifact (method + numbers, PII-safe). Escalation-exhausted
  flips the pair to deny; a read is never gated by the write-scoped pair (W2/W3/W4/W10).
- **E13 — error-budget metering + gating.** A write draws `error_prob × blast_weight` for its effective
  blast class exactly once (missing artifact ⇒ `error_prob = 1.0`); a read draws nothing; once cumulative
  spend reaches tolerance the PIP reports the breach and the next write is gated by rules 2/3 (W4/W5/W8/W6).
- **E14 — breach signal + isolation.** Crossing the tolerance emits the `budget_breach` `DemotionSignal`
  on the log-metric surface and the `on_demotion_signal` seam, exactly once per crossing, with the right
  action-class and period; a malformed artifact is a loud deny; a raising subscriber does not fail the
  request (W6/W7/W9).

## Deployment note

This change churns **every** envelope hash (it retires the `abstention_thresholds` placeholder and
renames the cap), and a pre-#184 stored envelope dump — which carries `"abstention_thresholds": null`
— **fails validation loudly at boot**. That is the intended fail-closed path, not a regression: re-run
seed_envelope → seed_grants per principal to cure it (a far-jump broker redeploy already re-seeds
grants per the cross-version reseed rule). No compat shim.

## Deferred (this contract's edges)

- **The drift detector** — the reference-tier machinery that sets `ConfidenceArtifact.stale` from a
  label-free drift signal (#65). This contract defines only the flag and its consequence.

The construction methods have **landed** (`safe_agents/evidence/methods.py`, the worked consumer
`examples/confidence_budget/`): reference implementations of self-consistency / ensemble / conformal
behind the closed catalog, each a base PR + conformance test, never a store-injected path.
