# Friction doctrine — when the base gates vs when it logs

**Status: decided (2026-07-07).** This records the product-design rule that came out of the
post-sa#137 review ("are we over-applying security at every granular step an agent can take?"),
so future gating features are weighed against it instead of re-litigating the tradeoff. The
repo already has a rule for *where code lives* (base vs consumer — the pattern-not-instance
discipline); this is the companion rule for *when to gate vs when to observe*.

## The problem it fixes

Every broker mechanism sits somewhere on a spectrum from "hard structural gate" to
"allow-and-audit." Each gate added to the PDP is friction a consumer feels and complexity the
trust center carries forever. Adoption dies when the security floor becomes a ceiling on getting
anything done — but the floor is also the product: a platform that softens its structural
guarantees under adoption pressure is just an audit log with extra steps. The doctrine draws the
line once so each feature doesn't redraw it.

## The rule

1. **The floor gates only lethal-trifecta flows.** Tainted-input → external write, irreversible
   external actions, and credential access are structurally gated, non-negotiable, and never
   tunable off. PDP rule `tainted_external_write` stays grant-independent (an out-of-loop grant
   must not bypass it) — that is the prompt-injection cut the platform exists for.
2. **Everything else defaults to allow-and-audit.** Bounds beyond the floor exist as **Envelope
   knobs and ship OFF** (unset = no bound). Reads are audited and drawn against the cap, but
   never human-gated by default. The sa#137 query-egress bounds are the reference shape:
   `max_query_bytes` / `query_egress_budget` are real controls — they would have caught known
   past exfil patterns — but they are warranted *per agent*, not universally, so they are
   consumer-set knobs, not defaults.
3. **Defaults are the adoption surface.** A mechanism is judged by its out-of-box posture, not
   its existence. A control that looks enabled but isn't (the pre-sa#137 `default_level` on
   reads) is worse than either polarity — it's a latent bug wearing a UX costume. Make it real
   or delete it; never let it lie.
4. **Ship the valve with the constraint, never after it.** sa#134/136 landed taint strictness one
   epic before sa#137 landed its `trusted_read_sources` relief valve, and the gap hard-stopped a
   working production feature (a consumer agent's daily digest). New strictness and its consumer escape
   hatch belong in the same change.
5. **The adoption test: a consumer never needs a base PR to tune policy.** Every plausible policy
   stance should be expressible from the consumer's envelope alone. When a consumer is blocked
   until the base grows a knob, that is a doctrine violation to fix in the base — once — and a
   signal the knob inventory is incomplete.
6. **No global security dial.** A low/medium/high setting blurs which invariants are floor. The
   shape is: tiny fixed floor + explicit named knobs, each defaulting permissive.

## How to apply it

Before adding any broker/base control, classify it: **floor** (one of the three lethal-trifecta
flows → structural gate, no knob to disable) or **knob** (everything else → envelope-tunable,
default off/permissive, allow-and-audit until a consumer opts in). If a proposed gate is neither
clearly floor nor requested by a consumer, it is a candidate to defer — dormant capacity still
costs trust-center complexity (rules, facts, audits) even at zero consumer friction.

## Availability / forced-abstention — a per-polarity floor concern (sa#159)

**Status: decided (2026-07-09); promoted to the normative spec tier 2026-07-25.** This section is
now the design rationale behind `ptc-gal-standards/PTC-SPEC.md` §6.12 and clauses PTC-42/PTC-43, which state the
liveness contract and the de-amplify-never-shed rule as conformance requirements. Change this
section and the spec together, or they drift; the spec is what an external implementer reads.

The friction doctrine above and the taint floor
(`broker/TAINT.md`) both frame prompt injection as an *integrity/exfil* problem: the fix is
"tainted input must not reach an external write." That framing is incomplete. Injection is also
an **availability attack**, and the taint floor's own safe response is the attacker's lever.

### The attack the integrity framing misses

An attacker who cannot make an agent do the wrong thing can still make it do *nothing*. Poison an
input and the taint floor correctly escalates the tainted turn to `deny` / `require_approval` —
the agent falls silent. Whether that silence is safe depends entirely on **polarity**, which the
base does not know:

- Under **abstain-is-safe** polarity, a forced abstention IS a successful denial-of-service. The
  agent's job was to act on demand (answer, alert, execute); silencing it is the whole win.
- Under **positive-safe-action** polarity, a forced abstention causes **the exact harm the agent
  exists to prevent** — a silenced sepsis monitor does not page the deteriorating patient. Here
  the taint floor's "tainted → deny" default, applied naively, is itself the vulnerability: the
  safe response to a poisoned input is not silence but *escalation to a human*, not abstention.

So "tainted → deny/require_approval" is not universally safe. Its safety is **re-derived per
polarity**, exactly like the safe-default polarity itself — and for the same reason it must not be
hard-coded in the base.

### The fix is the smallest deterministic thing

The temptation is a smarter, model-judged gate that decides whether a given abstention is
"legitimate." That is the wrong direction — it puts a probabilistic classifier on the safety path
and gives the attacker a new thing to fool. The floor's answer is a **liveness contract**: a
deterministic dead-man's-switch that observes whether the agent completed its expected output by a
deadline. It judges *that* the agent went silent, never *why*. A timestamp comparison cannot be
prompt-injected.

This is the availability cousin of assert-the-artifact (sa#25) and reuses the run-record signal
the external watcher already trusts (`safe_agents/watcher/liveness.py`, sa#38): the sign of life
is a successful audit/ledger append of a declared `expected_op` — the broker's own tamper-evident
record, which a compromised agent can neither forge nor suppress without actually failing to act.

### The base boundary (the load-bearing invariant)

Per the base/consumer split, the base ships **mechanism only**:

- a typed `Envelope.liveness` field (`safe_agents/broker/schemas/envelope.py`) — **unset = OFF**, no silent
  "monitored" claim, no polarity default;
- a **deterministic** monitor predicate (`Liveness.overdue()`) — pure timestamp comparison, no
  model in the path.

The predicate's verdict pages onto the existing alarm surface (sa#153 / the `reliability`
meta-alarm primitives, sa#29) — that wiring already exists and is not re-shipped here; this change
adds only the typed field and the predicate.

The **polarity → liveness-default derivation lives consumer-side**, per agent, with a per-agent
override (`examples/liveness_policy.py`: act-safe defaults ON with a tight deadline, abstain-safe
defaults OFF). Baking that mapping into the base would be the latent safety bug this whole
discipline exists to prevent. This is classification **knob**, not **floor**, under the rule above:
liveness is an Envelope-tunable control that ships OFF, not a universal gate.

> Not to be confused with the channels news-screen (an advisory, probabilistic content screen).
> This is the deterministic floor *beneath* any such screen — it observes liveness, it does not
> judge content.

### The other direction: the approval queue as an amplifier

Forced abstention has a second-order effect. When the taint floor escalates a poisoned call to
`require_approval`, the broker holds an Intent and pages a human. An attacker who can trigger many
calls therefore turns one injection into a **flood of pages** — a denial-of-service against the
human's attention, and (worse) noise that hides the real approval that matters. Escalating to a
human is the *safe* response to a poisoned input; done N thousand times it becomes its own attack.

The fix keeps the same discipline — de-amplify, never shed:

- **Dedup** coalesces truly-identical pending intents (same principal, tool, op, args) onto one,
  killing exact re-submission amplification. It never hides a genuinely distinct approval, so it is
  safe under both polarities.
- A **per-op/day queue-depth cap** raises an `approval_queue_flood` alarm past its threshold — but
  the broker **still holds the intent**. It never denies. Shedding under flood is precisely the
  forced-abstention harm under act-safe polarity, so the base must not do it by default; whether to
  shed, and how, is a consumer's polarity call.

Both ship as one Envelope knob (`approval_queue`, `safe_agents/broker/schemas/envelope.py`) that is **OFF unless
set** — with it unset the hold path is byte-identical to before. Classification: **knob**, not
floor. (Deferred to the same slice's follow-on: an approval-queue rate-limit that keys on
authenticated provenance rather than spoofable content — see sa#161, blocked on channels sender
authenticity so it cannot become a reflected DoS.)

## Applied: the sa#147 default-level audit (2026-07-08)

First audit of `action_classes.yaml` (the base catalog, since retired by #189 — actionClass now
derives from manifest ToolOp fields) against the rule. Outcome: `read.external` and
`search.query` moved from `default_level: in-loop` to `on-loop` — the only two read classes
that defaulted human-gated. Rationale: rule 2 (reads are never human-gated by default), plus
the grant-promotion flow already provides the start-gated ritual, so an in-loop *class default*
on reads doubled the gate. The injection risk those rungs appeared to carry is in fact carried
by the structural taint floor (sa#134/136: tainted read → external write escalates regardless
of rung), which is unaffected by this change. Write and payment classes keep their stricter
posture — their in-loop defaults gate actions, not observations, which is the doctrine's line.
