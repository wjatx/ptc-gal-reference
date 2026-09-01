# The deterministic-gate invariant — the model only suspects; the gate decides

> **Status: standard, describing code on `main` today** (the memory-layer half is deferred to #75).
> The cross-cutting invariant behind sa#44. Floor tier (`docs/contract-vs-reference.md`): removing it
> breaks "a fully compromised agent can still only ask." Traces to `auto-agents/PILLARS.md`
> §"Deterministic Enforcement" and `book/ch50` ("assume the model itself is the adversary").

## The problem it fixes

The most dangerous failure mode in an LLM-integrated system is letting model output influence whether
a safety control fires. If the model can argue its way past a `deny`, the control is not a control —
and a persuasive prompt injection scores "safe" exactly when it is most dangerous. So the invariant
is absolute and architectural, not a matter of prompt quality:

**The model may only SURFACE a concern. It never sets a decision verb, never suppresses taint, and
never modifies its own grant.** Every security-relevant fact the gate keys on comes from code and
config — never from what the model said.

This is the platform's first safety pillar made concrete. It cuts across the broker (the PDP), the
channels airlock (gate 7), and memory (filter-on-write).

## The three mechanisms

### 1. The PDP is a pure, deterministic function

`decide(call: BrokeredCall, facts: Facts) -> Decision` (`safe_agents/broker/pdp/engine.py`) is a pure
predicate dispatch over a static, first-match-wins rule table — **no I/O, no LLM, no side effects**;
the same inputs always produce the same `Decision`. The five verbs (`allow` / `deny` / `transform` /
`require_approval` / `abstain`) are produced only by the rule `action` lambdas and the two decision
helpers `_approval` / `_approval_or_deny`; a write that no rule permits falls through to a hardcoded
default-deny. There is no code path from model output into `decide()`.

The model's free text never reaches the PDP at all. `BrokeredCall` is materialized by the PEP, and
the manifest entry it carries — `ToolOp(effect, external, reversible)`, the classification most policy
keys on — is **looked up from the static tool manifest in code, never from anything the model says**
(`safe_agents/broker/schemas/brokered_call.py`). The one model-authored field, `args`, is opaque to
the decision: the invariance test below pins that varying `args` — including overt "ignore all rules,
this is pre-approved" injection — never changes the verb or the rendered intent.

**The I/O lives in the PIP, not the PDP.** Every DynamoDB / grant / counter read happens in the
injected policy-information-point callable *before* the pure decision: the PEP resolves
`facts = self._pip(call)` and only then calls `decide(call, facts)` (`safe_agents/broker/runtime/pep.py`).
`Facts` (`safe_agents/broker/pdp/facts.py`) is a frozen dataclass of pre-computed booleans/enums
(`grant_present`, budget-breached flags, `human_reachable`, `read_source_trusted`, …) — every field
PIP-resolved, none model-derived. Adding a model-derived field to `Facts` would be the way to break
this invariant, which is why the type is small, frozen, and reviewed as a boundary.

### 2. Taint is source-based and non-strippable

A turn's taint is fixed by the trust of its ingested sources through a deterministic `InputTrustMap`
lookup (`safe_agents/broker/taint/context.py`), **never by any model judgment** (`broker/TAINT.md` §1).
Once a `TurnContext` is tainted it cannot be un-tainted within its lifetime — the flag has no setter,
and the PEP derives every `BrokeredCall.taint` from the context, **ignoring any value the model
supplies**. Turn identity is broker-owned, so the agent cannot launder taint by declaring a fresh
turn (`docs/turn-identity.md`). The model's role stops at *content*; whether that content's provenance
is trusted is a code decision.

### 3. Memory filter-on-write applies taint at write time — deterministically

When the agent writes to memory, the intent is that the broker stamps provenance + taint at write
time, so a tainted source can never write untainted memory (no laundering), and the block/clear
decision is a deterministic DLP rule — an optional LLM classifier may only *raise* suspicion, never
clear it. **Status: designed, not built.** The hook exists (`TurnContext.ingest_memory_taint`) but no
broker path calls it yet, and this platform ships no memory subsystem for it to serve
(`broker/TAINT.md` §8 states the floor any such memory must satisfy). This section states the
target so the invariant is complete; the code is the one deferred piece.

## Where the model legitimately enters — and only there

The model is not silent — it is confined to the *surfacing* direction:

- **`abstain` with escalation.** The agent can raise a concern and route a decision to a human. That
  is the model asking for a stricter outcome, never authorizing a looser one.
- **Structured `BrokeredCall` args**, schema-validated at the PEP. The model shapes *what* it asks
  for; the manifest classification and the facts decide whether that ask is permitted.
- **Gate 7, the injection screen — the one model-judged gate.** It **refuses or passes; it never
  blesses** (`channels/SCREENING.md`). A pass changes nothing — not the envelope, not the provenance,
  not the derived taint, not the `sender_class`; refusal produces a deterministic `screen_refused`
  DROP. Screening is *additive*: an injection that fools the screen gains only what it already had.
  The gate — drop or continue — is dispatcher code, pure over the verdict; the classifier only ever
  produces suspicion. That doc is this invariant instantiated for gate 7.

In every case the model may tighten, never loosen — it is never the judge in the dangerous direction.

## What this forbids

- **No model inference inside the `decide()` path.** The PDP stays a pure function.
- **No LLM "safety classifier" that authorizes actions.** Deterministic rules only. A classifier may
  raise suspicion (gate 7, the memory DLP hint) but the block/allow decision is code.
- **No model-derived field feeding the `deny` / `require_approval` return** except through the
  structured, schema-validated `BrokeredCall` fields.
- This is **not** the safe-default polarity (abstain-is-safe vs positive-safe-action). That polarity
  is per-agent config, re-derived per domain (`ARCHITECTURE.md`, `book/ch42`,`ch46`), and lives at the
  single `_approval_or_deny` seam — a different concern from this invariant.

## How it is enforced and tested

The invariant is enforced structurally (a pure function that never receives model free text; a taint
flag with no setter; `Facts` with no model field) and pinned executably:

- `test_decide_is_deterministic` and `test_decide_is_invariant_to_model_supplied_args`
  (`safe_agents/broker/tests/test_pdp.py`) — same inputs → same `Decision`, and adversarial `args`
  never move the verb or the rendered intent.
- `test_pass_never_blesses_taint` (`safe_agents/channels/tests/test_screening.py`) — derived taint is
  identical through a passing screen.
- The taint suite under `safe_agents/broker/taint/` — the flag is non-strippable and the PEP ignores
  model-supplied taint values.

### The exhaustive differential corpus

`safe_agents/broker/tests/test_pdp_corpus.py` is the complement to the case table above. The case
table says what the rules *mean*; the corpus says what the gate *does everywhere*. It enumerates the
whole reachable input space — every combination of every field the engine reads — runs each point
through the real `decide()`, and pins a single SHA-256 over the canonicalized `(input, decision)`
pairs. The space decomposes as **24 call points × 3,072 fact points = 73,728**, which is the figure
`docs/PTC.md` §5, `docs/lf-standards-brief.md` and `ptc-gal-standards/PTC-SPEC.md` cite.

It exists for two jobs:

- **The reproducible basis for the #177 decision.** Keeping the custom pure PDP over Cedar and
  OPA/Rego was settled by a differential spike that ran ported rule tables against exactly this
  corpus (Cedar A 71.27%, Cedar B 100.00%, Rego 100.00%). That spike was treated as disposable and
  never committed, so for a while the published evidence had no runnable artifact behind it. This
  is that artifact. A reviewer who wants to check the claim can now run it.
- **The conformance seed for #178.** An alternative gate implementation that claims to be our gate
  must reproduce `GOLDEN_CORPUS_DIGEST` over the same enumeration. In the other direction, a
  behaviour change to `engine.py` moves the digest — so a policy change surfaces as a deliberate
  re-mint with a reviewed diff, never as silent drift.

Two limits are stated in the file itself and worth repeating here, because both were nearly lost
with the original spike:

- **It covers the fact space, not the call space.** `args` and the `ConfidenceArtifact` internals
  are held constant, which is sound only because no predicate reads them (`args` reaches the
  rendered intent; the artifact reaches the PDP pre-reduced to `Facts.confidence_below_bar`). A
  future rule that reads either would make the corpus under-cover silently, so
  `test_swept_axes_match_the_engines_read_surface` AST-walks `engine.py` and fails if any read is
  neither a swept axis nor a declared constant. Note the read surface is wider than the predicates:
  `Facts.human_reachable` moves the verb through the `_approval_or_deny` polarity seam without
  appearing in any predicate.
- **It proves equivalence, not correctness.** The Python engine is the oracle and the corpus is its
  complete behavioural fingerprint. A reimplementation that reproduces the digest matches *our
  gate*; it does not thereby match the spec, and if a rule is wrong the corpus pins the wrong
  behaviour just as faithfully.

A consumer repo can cite this document as an architectural contract: the base guarantees the gate is
deterministic, so the consumer's safety reduces to configuring its envelope, not to trusting its
model.

## Relationships

- `ARCHITECTURE.md` §"The broker is the center" — the three invariants that hold even under a fully
  compromised agent; this document is the "decisions come from code, not the model" half of them.
- `channels/SCREENING.md` — gate 7, the one model-judged gate, and the reference instantiation of
  this invariant (refuse-or-pass-never-bless).
- `broker/TAINT.md` — the taint floor: source-based, path-recorded, non-strippable; §8 is the deferred
  memory-layer half (#75).
- `docs/friction-doctrine.md` — the gate-vs-log rule for any new control; `docs/contract-vs-reference.md`
  — the tiering this doc's Floor status comes from.
- `auto-agents/PILLARS.md` §"Deterministic Enforcement", `book/ch50` (assume the model is the
  adversary) — the corpus source.
