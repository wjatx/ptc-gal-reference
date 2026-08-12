# grant-lifecycle — autonomy level is state

The doer's authority for an action class is **not a constant; it is stored state that moves on a
ratchet**, and the broker is where it lives. This file is the state machine behind the `Grant`
schema (`SCHEMAS.md` §1) and `PromotionRecord` (§7). It implements **Pillar 7 — Graduated
Autonomy**. Source: `auto-agents/tool-broker-sketch.md` §"Autonomy level is state".

The asymmetry is the whole point:

> **Promotion is recorded and human-gated. Demotion is automatic, deterministic, and has no model in
> the loop.** The system can narrow its own envelope without a human in the moment; widening it
> requires recorded human approval.

## The ladder — four rungs, three grant levels

```
   in-loop            on-loop                 out-of-loop
   human approves     human supervises,       acts fully within
   each act           can intervene           the envelope
      ^                    ^                       |
      |   demotion (automatic, deterministic)  <---+
      +------------------------------------------- |
      |                                            |
      +----  promotion (recorded, maker-checker) --+--->
```

The canonical level vocabulary is **in-loop / on-loop / out-of-loop** (from `auto-agents/book/ch36`
and `ARCHITECTURE.md`). These are orthogonal to the five Decision verbs (allow / deny / transform /
require_approval / abstain); level is stored state on the grant, the verb is per-call. Mapping from
older disposition terms: `out-of-loop` ≈ autonomous, `on-loop` ≈ autonomous-with-reporting,
`in-loop` ≈ HITL-queued; `blocked` is not a level — it means the action class is not granted (the
Recommend rung, below).

The diagram shows the three **acting** rungs — the grant `level` enum. The full autonomy ladder has
**four**: below them sits **Recommend**, the advise-only baseline where a new agent starts for any
capability. At Recommend the agent holds no grant for the action class at all, so the broker
default-denies; there is nothing for the ratchet to move yet. Recommend is a rung but not a `level`
— the enum is complete at three values and must not grow a fourth. The first promotion
(Recommend → in-loop) is therefore the *creation* of the grant, through the same recorded
maker-checker path as every later climb.

The rung is **per `(principal, action-class)`, never per-agent**. An agent is a vector of rungs —
one per capability, like doors on a badge — so "what rung is the agent on?" is a category error;
the right question is "what rung is *this action class* on for *this agent*?" (`GLOSSARY.md`
§The autonomy ladder.)

`lastSafeLevel` is the rung demotion falls back to — always `in-loop` or `on-loop`, **never**
`out-of-loop`. In abstention-kills domains the safe rung executes a *positive* deterministic action
(a SCRAM / failsafe), not mere inaction; that polarity is per-agent config, never baked into the
base (`ARCHITECTURE.md` §"The one thing that must NEVER be in the base").

## The Recommend → in-loop line — who holds the actuation

The line between Recommend and Act-with-approval (in-loop) is sharp, and the discriminator is
**who holds the actuation**:

- **Recommend.** The agent holds no grant for the class; it cannot stage the action (broker
  default-deny). Its advice is text in its reply, and a human acts in their own system. No staged
  `Intent` ever exists.
- **In-loop.** The agent holds the gated grant. It stages a real brokered call; the broker
  materializes an approval `Intent` and waits; on approval **the broker** executes.

The observable tell is the audit trail: Recommend produces no staged action at all; in-loop
produces a staged `Intent` that a human releases.

## Promotion — the recorded maker-checker path

Promotion is a **recorded, maker-checker decision** (`tool-broker-sketch.md`; the accountable act,
Part 11 of the philosophy doc). It writes a `PromotionRecord` and updates the `Grant`:

1. **A promotion is proposed (maker)** referencing covered-distribution evidence and the in-force
   `envelopeHash`.
2. **It is ratified (checker)** by a different identity (`proposedBy ≠ ratifiedBy`). The approval may
   be a **signed promotion predicate authored in advance** rather than a per-instance act — its
   stringency and ceremony scaling to blast radius. **High-blast action classes are always ratified
   per-instance by a human**; the pre-authored predicate may stand in only below that threshold
   (locked 2026-07-11, epic sa#4; `docs/GAL.md` §5).
3. **The evidence must be sound.** Gathered where deployment conditions are *covered*. A thin
   observed-accuracy count over an irreversible action is an **unsound** predicate and must be
   rejected.
4. **The Grant's `level` rises**, `promotedBy` / `evidence` / `ts` / `envelopeHash` are stamped, and
   the `PromotionRecord` is appended.

An **optional LLM evidence reviewer** (sa#58, shipped 2026-07-12) may review the evidence bundle
during the ceremony — a different model family than the maker's, so the pair shares no blind spot.
It is friction-side instrumentation under the surface-vs-decide rule (`docs/deterministic-gate.md`):
its closed-vocabulary findings are **recorded** on the ceremony result and the PromotionRecord's
predicate text for the human ratifier, and that is all — it cannot license, cannot veto, and a
failing/unreachable reviewer degrades to a recorded `reviewer_error` finding, never a gate flip in
either direction. The seam is `CheckerProtocol` (`grants/ceremony.py`); the reference implementation
is `grants/reviewers/` (Bedrock Converse, forced tool use, same-family config refused at build
time). Ships OFF — enabling is consumer wiring (`GRANTS_REVIEWER_KIND`, a closed catalog per
`docs/config-provenance.md`).

### Re-promotion closes a control loop whose deadtime is `labelLatency`

You have **no labels at action time**, so re-promotion runs on *delayed-label reconciliation*: when
an outcome resolves, pair it with the confidence logged at decision time, accumulate, recompute
calibration, re-validate conformal coverage on the **current** distribution, then ratchet up. Long
`labelLatency` caps how fast you can re-promote — and therefore how much autonomy you can responsibly
hold at all. Two mechanisms keep it honest (high-stakes tier):

- **Randomized allocation doubles as exploration.** Labels are censored (you only see outcomes for
  actions you took), so naive recalibration is biased toward the region you still act in. The same
  seeded randomization that defeats adversarial probing acts occasionally in the abstain region under
  tight caps, generating the off-policy labels recalibration needs. One primitive, three jobs.
- **Active labeling at the boundary.** When you spend a human label, spend it on near-threshold
  cases — the most informative. At maturity the human's role is calibration oracle; approval is the
  transitional arrangement.

## The grant-store write-protection seam

**The grant store is writable only by the maker-checker promotion path (and the deterministic
demotion path). The agent has no write access to it — or the agent promotes itself.**

This is a seam, not a convention: it is enforced structurally. In the AWS reference stack the agent
runs under its own IAM role that has **no `PutItem` / `UpdateItem` / `DeleteItem`** permissions on
the grant table. Only the promotion Lambda (the checker in the maker-checker path) and the demotion
path (running broker-side, deterministically, with no model in the loop) can write grant records.
The agent can read its own grants — so it knows what it is and isn't authorized to ask for — but it
cannot elevate them.

Why this matters: a grant-store write the agent can reach is a promotion bypass. The grant `level`
is stored state that governs the entire broker path; if the agent can write it, every other control
collapses. The IAM separation is the structural backstop that keeps the ratchet honest. This is
listed in the pre-deployment checklist in `ARCHITECTURE.md`:

> *"The grant store is writable only by the maker-checker promotion path — never by the agent (or
> the agent promotes itself)."*

### The input-integrity corollary (normative, locked 2026-07-12)

**When a mutation path is the "only sanctioned path" to a protected object, every durable input
that path consumes needs the same tamper-evidence as the object itself — or the sanctioned path IS
the bypass.** Proven exploitable in the Phase-4 review: the grant carried an HMAC with loud
quarantine, but the durable promotion *proposal* the ceremony ratified did not — a hand-edited
proposal item laundered a one-hop level skip straight through the ceremony onto a grant re-signed
with a fresh, valid HMAC. Tamper the input, not the protected object.

Concretely, for every sanctioned write path, enumerate its durable inputs (stored proposals,
evidence artifacts, config it re-reads at execute time) and give each one of: the object's own
integrity mechanism (the proposal HMAC rides the grant-key discipline), a signature
(`PromotionRecord` DSSE), or re-validation at the trust boundary (`execute()` re-runs everything
`propose` validated — a stored proposal is input, never authority). Same genre as the
config-provenance lattice's "store config only selects/tightens" (`docs/config-provenance.md`),
applied to workflow state.

**And every one of those durable inputs is serialized by the SAME canonical rule** — sorted keys,
no whitespace, ASCII (`broker/SCHEMAS.md` §1, `channels/SIGNING.md`). The grant, the promotion
record, the durable proposal and the acknowledgment record each carry an integrity basis over their
STORED bytes, so a per-callsite serialization is a per-callsite basis: self-consistent inside this
process, and irreconcilable with any second implementation that computes the same HMAC from the
normative spec. `canonical_grant_payload` and `proposal_to_json` diverged this way (sorted and ASCII
but not compact) and were pinned before the spec was filed —
`test_grants_integrity.py::test_canonical_payload_is_sorted_compact_ascii` holds the line.
Moving the canonical form is a **ceremony-bearing migration, never an edit** — but not for the
reason intuition supplies, and the difference decides which command you reach for. A pre-change row
does **not** quarantine: its HMAC covers the bytes as stored and verification digests those bytes
verbatim, so it reads clean forever (that is #246 working). What is wrong with it is narrower — its
stored bytes are not the canonical serialization of the grant they encode, which nothing here checks
and a spec-driven second implementation certainly will. So `re-seed` is the WRONG tool: it re-stamps
only an envelope-hash mismatch, and a serialization change does not move the envelope hash. The
migration is the #246 archive → delete → `seed` shape. `docs/grant-canonicalization-runbook.md` is
the operator's how-to.

## The audit instrument — and dispositioning what it finds (#201 / #196, 2026-07-14)

The read-only grants audit (`grants/audit.py`, #62) is the instrument that tells an operator when
authority state is wrong. Two hardenings came out of the #199 incident (a ceremony minted a grant
under a silently-substituted envelope — quarantine-dead from ratification, green on the audit):

- **`GRANT_ENVELOPE_IN_FORCE` (#201).** Every grant's `envelopeHash` is compared to the stored
  in-force envelope for its principal (recomputed via the same load path the broker uses at boot —
  a plain content hash, so the keyless posture holds). A mismatch is a grant the broker quarantines
  on every call: operationally dead, HMAC-clean, invisible to every other rule. The remedy is
  `re-seed`. The rule fires expectedly after any far-jump redeploy — that is it working, and it is
  why the acknowledgment ceremony ships beside it.
- **The acknowledgment ceremony (#196).** A TRUE finding whose remediation is deferred (honest
  history, a coordinated-window fix) is dispositioned by `acknowledge` — a **ceremony artifact,
  never a config toggle**: a signed record appended to the same append-only table, NEVER a mutation
  of the flagged item (that is the thing the audit exists to catch). It binds the rule, the
  coordinate, and the sha256 of the exact violation detail, so a NEW finding at the same coordinate
  is never auto-waived. Identity is STS-derived; the record is issuer-DSSE-signed and the ceremony
  **refuses to run unsigned** — a waiver mints "green", which is authority. The audit reports the
  matched finding as `acknowledged` (with the waiver ref): green-with-annotations, never silently
  green. Only a **closed waivable vocabulary** (`WAIVABLE_RULES`: LEDGER_COUNTERPART,
  RECORD_SIGNATURE_VERIFIES, GRANT_ENVELOPE_IN_FORCE) can be acknowledged — HMAC-tamper
  quarantines, unaccounted raises, and parse failures stay un-waivable, or the waiver becomes a
  laundering seam. Waivers apply only when their signature VERIFIES; a keyless/no-verify-keys run
  skips acknowledgment verification loudly and applies none (fail toward RED). Two rules police the
  waivers themselves: `ACKNOWLEDGMENT_SIGNATURE_VERIFIES` and `ACKNOWLEDGMENT_NOT_WAIVABLE`.

Relatedly, half-configured issuer signing (`ISSUER_SIGNING_KEY_ID` without the secret ARN) now
**refuses** the ratify/acknowledge ceremony instead of degrading to an unsigned record — the #190
fail-toward-less-authority polarity applied to config. Fully-unconfigured signing gets the same
polarity (#205): `ratify` **refuses** to store an unsigned PromotionRecord — writing nothing (no
record, no grant mutation; the proposal stays pending) — unless the operator passes an explicit
`--allow-unsigned`, which stores the record UNSIGNED with a loud warning. `acknowledge` refuses
unsigned outright, with no override.

## Demotion — automatic, deterministic, no model in the loop

This is the load-bearing safety property. Demotion **must run when the model is confused and the
inputs are suspect** — which is exactly when you cannot ask a model to decide. So it does not.

```
// STUB — illustrative control flow, not an implementation
on each decision / monitoring tick:
    if  stale_confidence            // drift: calibration no longer matches deployment
     or corroboration_failure       // a premise failed its independent-source quorum
     or budget_breach               // an atomic counter (error / cap / escalation / fallback) blew its bound
     or false_action:               // an authenticated owner flagged an executed op as wrong (/flag, ships OFF)
        grant.demotionReason = (stale_confidence and nothing_else ? "pending-evidence"
                                                                   : "failing")
                                              // failing dominates mixed-trigger demotions:
                                              // an actually-blown bound is the stronger claim
        grant.level = grant.lastSafeLevel     // fall to the safe rung
        append PromotionRecord(recordType="demotion", triggeredBy, demotionReason, ...)
                                              // same ledger as promotion (Phase 3, SCHEMAS.md §7)
        emit AuditRecord(outcome="...", reason=demotionReason)
        // NO model call anywhere in this path
```

### The demotion triggers

Exactly four deterministic conditions trip demotion (`Grant.demotionTriggers`):

1. **`stale_confidence` (drift).** The broker watches the *distribution* of constructed confidence
   across runs (no outcome labels needed at action time). A systematic shift, or anomalously high
   confidence on novel inputs, sets `stale`, which **voids the conformal threshold** and trips
   demotion. (`tool-broker-sketch.md` §"Confidence gating".) The runner derives the trigger from
   a stale `ConfidenceArtifact` as given (#192); the drift detector that SETS the flag stays
   consumer/reference-tier (#65).
2. **`corroboration_failure`.** A premise or input failed its quorum of independent sources (k-of-n,
   none stale, provenance valid; physical/market sanity bounds count as the cheapest independent
   source). Failed corroboration pushes toward `abstain` and trips demotion — never toward `allow`.
   (`tool-broker-sketch.md` §"Corroboration".) The quorum result is the typed
   `CorroborationRecord` (broker/EVIDENCE.md, #192); the runner derives the trigger from it
   deterministically (`agreeing < k`) — the corroboration pass that produces the record is
   consumer-side, like the drift detector behind trigger 1.
3. **`budget_breach`.** An atomic durable counter — error, a spend cap, escalation, or fallback —
   blew its bound for the period. (`Budgets`, `SCHEMAS.md` §5.)
4. **`false_action`.** An authenticated owner flagged an executed op as wrong (the `/flag` verb,
   #193): the runner re-derives the trigger from the durable `false_action` counter — never from
   the message — and a single flag suffices. The ease gradient points downward: it should be
   easier to get demoted in this system than to overcome its safeguards. Like every non-floor
   bound this trigger **ships OFF** — it fires only for grants that list it in
   `demotionTriggers`, and no flag (or any accumulation of flags) can ever promote anything.

### Record *why* you demoted — and don't collapse the two reasons

`demotionReason` is `"failing"` **or** `"pending-evidence"`. They look identical from outside and
demand **opposite** responses:

- **`"failing"`** — "the error blew the bound." The model/policy is wrong. Response: *fix it.*
- **`"pending-evidence"`** — "I lack recent labels to certify this rung." Nothing is broken; the
  certification lapsed. Response: *gather data.*

The trigger → reason mapping: `stale_confidence` → `"pending-evidence"` (label-free drift voids the
certification — the model isn't *proven* failing); `corroboration_failure`, `budget_breach`, and
`false_action` → `"failing"` (an owner flag asserts the action *was* wrong — an active breach, not
a lapsed certification). In a mixed-trigger demotion, **failing dominates** — an actually-blown bound is the
stronger claim than a lapsed certification. Collapsing the two reasons sends the wrong team at the
problem. Keep them distinct.

The demotion is recorded, not approved: it appends a **demotion-typed `PromotionRecord`** on the
same ceremony ledger as promotions (ratified by `system:demotion-evaluator`; `SCHEMAS.md` §7),
alongside the `AuditRecord`. This supersedes the earlier no-record exemption (Phase 3,
`docs/GAL.md` §3) — the asymmetry that matters stays: widening requires recorded *human approval*;
narrowing requires no human at all.

### Hysteresis — so it can't flap

Demotion and re-promotion use **different thresholds** and a **dwell time**. Re-promotion requires
fresh recalibration evidence — never just "the alarm stopped." This prevents a noisy signal from
oscillating the rung.

## This must be drilled

Demotion is a safety mechanism, and an untested safety mechanism is a liability. The pre-deployment
checklist (`ARCHITECTURE.md`) requires: **"Demotion path is deterministic, runs with no model in the
loop, and has been drilled."** Treat it like a fire drill — periodically inject each trigger
(`stale_confidence`, `corroboration_failure`, `budget_breach`, `false_action`) against a live grant and confirm the
rung falls to `lastSafeLevel`, the `AuditRecord` is emitted, the demotion-typed `PromotionRecord`
is appended, and no model was called on the path. A
demotion that has never been exercised should not be trusted to fire when it matters.

## Where this sits in adoption

Per `BUILD.md` and `tool-broker-sketch.md` §"Minimum viable vs full", the autonomy ratchet (this
file) is the **fourth** tier — built only once an agent is graduating off "human approves every
write." The drift/corroboration machinery feeding `stale_confidence` and `corroboration_failure` is
the **last** (high-stakes/adversarial-only) tier. A low-risk agent may run indefinitely at `in-loop`
/ `on-loop` with `budget_breach` as its only live demotion trigger, and never need the rest.

## Relationship to the release/rollback loop

This is the same loop as Parts 9–11 of the philosophy doc: the robust policy is the **release
artifact**, drift is the **signal** the adversary (or reality) escaped your model, demotion is the
**rollback**, and delayed-label recalibration is the **re-release**. Promotion ships autonomy;
demotion rolls it back automatically when the evidence stops supporting it.
