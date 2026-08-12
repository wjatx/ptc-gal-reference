# confidence_budget — the calibrated-uncertainty knob, worked (#184, Pillar 4)

A **fictional** reference consumer for `Envelope.confidence` — the confidence bar and
per-UTC-day error budget of `broker/EVIDENCE.md`. It is the worked example behind the
E1–E14 conformance clauses, the confidence sibling of `examples/scoped_s3/` (which
works the IAM-scoping knob).

## What it shows

The base ships the confidence **mechanism** — the `ConfidenceArtifact` contract, the
deterministic `meets_bar` predicate, the `error_prob × blast_radius` budget draw, and
the reference constructors under `safe_agents.evidence`. Every **number** is this
consumer's policy, and the below-bar **polarity** (what a below-bar write routes to)
is re-derived per agent in [`reporter_policy.py`](reporter_policy.py), never in the
base. The `confidence-reporter` is a small agent with one external irreversible write
(`report.publish`) and one internal write (`draft.save`).

## Declaration → mechanism → conformance

| declaration (manifest) | mechanism (base code path) | clause |
|---|---|---|
| `tool_ops: report.publish {external, reversible: false}` | `evidence.derive_blast_class` → **high** (external ∧ not-recoverable) | E3 |
| `confidence.high_blast: [draft.save]` | `evidence.effective_blast_class` tightens the internal write's **medium** up to **high** (never lowers) | E5 |
| `confidence.min_confidence: 0.85` | `evidence.meets_bar` — the per-call gate | E6, E12 |
| `confidence.methods: [self-consistency, conformal]` | `meets_bar` rejects an artifact whose method is not accepted | E6 |
| `confidence.error_budget_tolerance: 0.5` | `evidence.error_budget_draw` metered per-UTC-day in the PEP | E7, E13 |
| `confidence.blast_weights: {low, medium, high}` | the `blast_radius` factor of the draw; a missing weight raises loudly | E7 |
| `envelope.polarity: abstain` | a below-bar write routes to the `abstain` verb via the polarity seam | E12 |
| the agent-attached `"confidence"` key | `ConfidenceArtifact` validation (round-trips, method-discriminated) | E1, E2 |

## Four worked calls

The agent attaches a `"confidence"` key (built by `reporter_policy.confidence_payload`)
to its `report.publish` call. `report.publish` is **high** blast (weight `1.0`).

**1. Above-bar publish → allow, budget drawn `0.1 × 1.0`.**
Raw observation: 9 of 10 samples agreed → `confidence 0.9`, `error_prob 0.1`.
`0.9 ≥ 0.85` so `meets_bar` is True → the write executes. The PEP draws
`error_prob × blast_radius = 0.1 × 1.0 = 0.1` against the day's `0.5` budget.

```jsonc
// call body (excerpt)         →  decision: allow; error-budget spend += 0.1
"confidence": { "confidence": 0.9, "error_prob": 0.1,
                "evidence": {"method":"self-consistency","samples":10,"agreement":0.9},
                "stale": false, "computed_at": "…" }
```

**2. Below-bar publish → abstain, artifact on the audit tape.**
Raw observation: 8 of 10 agreed → `confidence 0.8`. `0.8 < 0.85` so `meets_bar` is
False → the executor is never called; the write routes to `abstain` + the approval
queue (this consumer's abstain-is-safe polarity — the safe outcome). The abstain's
audit reason carries the artifact (method + numbers, PII-safe). No budget is drawn (no
write executed).

**3. Missing-artifact publish → below-bar abstain; the budget ceiling is `1.0 × 1.0`.**
A publish with NO `"confidence"` key, while a bar is configured, is below-bar
(`meets_bar(None, knob)` is False) → it abstains, exactly like case 2. The budget's
omission-proofing is the complement: whenever a write WITHOUT an artifact does reach
the executor (i.e. when only the budget knob is set, no `min_confidence`), it draws the
`error_prob = 1.0` ceiling × the high weight `1.0` = **`1.0`** — so omitting the
artifact can never *dodge* the budget. Here the per-call bar catches it first; the
ceiling is why turning the bar off still leaves omission fully charged.

**4. Breach → `demotion_signal` log line.**
The day's spend is cumulative `Σ error_prob × blast_radius`. Once it crosses the `0.5`
tolerance — e.g. one missing-artifact write charges the full `1.0`, or six above-bar
publishes accrue `6 × 0.1` — the PEP emits a typed `DemotionSignal` and stops there:

```
demotion_signal trigger=budget_breach principal=confidence-reporter \
  action_class=report.publish period=20260712 detail="error budget 0.5 exceeded (spend 1.0)"
```

The base **emits** the signal (on the log-metric surface and the `on_demotion_signal`
seam); it never **applies** a demotion — that is the grant lifecycle's deterministic
job (`grants.demotion.DemotionMetrics`). A raising subscriber never fails the request.

## Fictional and deterministic

No real model, no real sampling, no network. `reporter_policy.py` turns
already-obtained sample counts into the typed artifact via
`safe_agents.evidence.construct_self_consistency`; HOW an agent samples its model is
its own business and stays outside the base.
