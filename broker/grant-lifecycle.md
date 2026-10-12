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
   (locked 2026-07-11, autonomy epic; `docs/GAL.md` §5). The blast class is derived at propose
   from the manifest's `tool_ops` entry for the action class and the in-force envelope's
   `confidence.high_blast`, and derived again at ratify: a stored proposal whose class differs
   from the derivation is refused, as is an action class the manifest does not declare.
3. **The evidence must be sound.** Gathered where deployment conditions are *covered*. A thin
   observed-accuracy count over an irreversible action is an **unsound** predicate and must be
   rejected.
4. **The Grant's `level` rises**, `promotedBy` / `evidence` / `ts` / `envelopeHash` are stamped, and
   the `PromotionRecord` is appended.

An **optional LLM evidence reviewer** (shipped 2026-07-12) may review the evidence bundle
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
verbatim, so it reads clean forever (that is stored-bytes integrity working). What is wrong with it is narrower — its
stored bytes are not the canonical serialization of the grant they encode, which nothing here checks
and a spec-driven second implementation certainly will. So `re-seed` is the WRONG tool: it re-stamps
only an envelope-hash mismatch, and a serialization change does not move the envelope hash. The
migration is the stored-bytes-migration archive → delete → `seed` shape. `docs/grant-canonicalization-runbook.md` is
the operator's how-to.

## The audit instrument — and dispositioning what it finds (2026-07-14)

The read-only grants audit (`grants/audit.py`) is the instrument that tells an operator when
authority state is wrong. Two hardenings came out of the wrong-authority-mint incident (a ceremony minted a grant
under a silently-substituted envelope — quarantine-dead from ratification, green on the audit):

Since the second signing role landed, the audit's signature scope is set by `RECORD_SIGNING_EPOCH`
rather than a per-type exemption list. It names the ISO-8601 UTC instant record signing was adopted
at. With it set, every record must carry a verifying signature of its role, whatever its type and
whatever its `ts`. A record's own timestamp excuses nothing: on an unsigned record that field is
written by whoever wrote the row, so a planted row could date itself into an exemption. Real
ledgers do hold unsigned `demotion`/`tightening`/`bootstrap` records that cannot be re-minted. Each
one is a `RECORD_SIGNATURE_VERIFIES` finding until the acknowledgment ceremony below dispositions
it, one record at a time. The finding's detail carries the sha256 of the record's stored bytes, so
an acknowledgment excuses those bytes and no others: a different record written at the same
coordinate, type and `ts` is a new finding. With the epoch unset the scope stays what it was
(promotion and reattestation required, lapse-if-present) and the report says so in an annotation:
the all-types requirement is not being enforced. The instant the epoch's own validity is judged at is an explicit
input, never derived from the records. An epoch dated after that instant is a violation
(`RECORD_SIGNING_EPOCH_VALID`), and the audit still checks every record as if the epoch were in
force.

- **`EVALUATOR_RECORD_CONTINUOUS`.** A `demotion` or `lapse` record is signed by the evaluator's
  key, and the evaluator may only lower. Two checks hold it to that. The record schema refuses one
  whose `toLevel` is above its `fromLevel`, or a demotion that lands on `out-of-loop`. The audit
  then requires each such record to start from the level the ledger held immediately before it. The
  second check is the one that matters for a planted row: a "demotion" from `out-of-loop` to
  `on-loop` lowers on its own terms, and on a ledger that stood at `in-loop` it would leave the
  derived level raised with no issuer signature. Un-waivable.
- **`LAPSE_TERM_RATIFIED`.** A `lapse` record's `certifiedUntil` is where a reader takes the
  instant enforcement fell (GAL §5.2), and on the sanctioned path the writer copies the grant's term
  and the stores refuse any other. A lapse record appended through a record store alone, by a holder
  of the evaluator's key or by anyone who can write a ledger that has not adopted signing, passes
  through neither. So the audit holds every lapse record that carries a term to the ledger (GAL
  §6.11, GAL-44): the term must equal, as the stored string, the term on the latest `promotion`
  record before it at its coordinate; a lapse record with no promotion before it carries none; and
  the term is not later than the record's own `ts`. "Before" and "latest" are by parsed instant,
  never string or list order, and a `ts` that judgement needs and cannot read is a finding. A lapse
  record carrying no term is not judged, since the field is optional. Judged at every coordinate
  with records, signed or not, in every mode. Un-waivable, as `GRANT_TERM_RATIFIED` is: a misstated
  term misstates how long authority was certified. The third check reads today's writer, which
  applies no clock skew; the skew allowance (#175) has to carry its bound into it.
- **Signing-key standing** (GAL-41): `RECORD_SIGNER_IN_STANDING`, `GRANT_STANDING_WITHDRAWN`,
  `KEY_SIGNED_AFTER_RETIREMENT` and `WITHDRAWAL_RECORD_MATCHES_LEDGER`, all un-waivable, plus the
  annotation that names a role with no standing document. What each judges, and its limits, are in
  §"Key standing" below.
- **`GRANT_ENVELOPE_IN_FORCE`.** Every grant's `envelopeHash` is compared to the stored
  in-force envelope for its principal (recomputed via the same load path the broker uses at boot —
  a plain content hash, so the keyless posture holds). A mismatch is a grant the broker quarantines
  on every call: operationally dead, HMAC-clean, invisible to every other rule. The remedy is
  `re-seed`. The rule fires expectedly after any far-jump redeploy — that is it working, and it is
  why the acknowledgment ceremony ships beside it. A release that adds or removes an `Envelope`
  field is such a redeploy for every principal at once, whether or not the principal's envelope
  ever set the field, because the hash covers the whole dump. Retiring `Envelope.allowlists` was
  one (#135); `SCHEMAS.md` lists what that upgrade requires.
- **`GRANT_TS_RECORDED`.** Every sanctioned write stamps the grant and the record it appends
  with one `ts` (`write_record_and_grant`, `ts` from the ledger clock), so a grant's `ts` must be
  the `ts` of the latest record at its coordinate (GAL §6.11, GAL-40). A grant `ts` later than
  every record is a write the ledger does not explain. A grant `ts` earlier than the latest record
  is a record whose grant write did not land. The level, term and envelope rules each catch a write
  that moved the field they read. This rule catches a write that moved none of them. "Latest" is
  the maximum instant over every record's parsed `ts`, of every type, and equality is on the stored
  string. A `ts` that is not an instant, on the grant or on a record at its coordinate, is a
  finding. A grant with no record at all is `LEDGER_COUNTERPART`'s finding and not also this one.
  That boundary is "no record": a coordinate holding only records that earn nothing (a lone
  demotion, a lone `reattestation`) has a latest record, so a grant whose `ts` is not that record's
  is reported by both rules, as two facts.
  Waivable, for a ledger whose grants were re-attested before re-attestation appended a record:
  each such grant is one finding, dispositioned one at a time by the acknowledgment ceremony below
  (`docs/operator-identities.md` has the steps). The finding's detail carries the sha256 of the
  grant's stored bytes and both timestamps, so an acknowledgment excuses the grant as it stood, and
  a grant rewritten afterwards is a new finding. A record appended afterwards moves the latest `ts`
  and is a new finding too. Where a record's `ts` is not an instant there is no latest `ts` to
  name, and the detail carries one sha256 over the stored bytes of every record at the coordinate
  in its place, so that acknowledgment covers the ledger as it stood and no later state of it.
  Nothing else takes a grant out of scope. The rule
  has no adoption date, and no field on a grant or a record exempts it. Honest limit: the rule
  holds the grant to the ledger as it stands, so a record planted at the grant's `ts` satisfies it.
  Whether a ceremony wrote that record is `RECORD_SIGNATURE_VERIFIES`'s question, and that rule
  asks it of every record type only when `RECORD_SIGNING_EPOCH` is set.
- **Re-attestation is recorded, and readers pass over the record.** `re-seed` re-issues each
  HMAC-clean grant at its level under the new envelope hash and appends one `reattestation`-typed
  record in the same atomic write (`write_record_and_grant`), signed by the issuer key, so no
  failure leaves a re-attested grant without the record that says who rewrote it, when, and under
  which envelope (GAL §6.6, GAL-15). With no issuer signing key configured `re-seed` refuses up
  front and writes nothing, and it has no `--allow-unsigned`: the record returns a quarantined grant
  to acting authority on a human's word, and an unsigned one holds nobody to it. Grant and record
  carry one `ts` from the ledger clock. The write changes the grant's `envelopeHash`, `promotedBy`
  and `ts` and nothing else, and the stores refuse a `reattestation` write that moves anything more.
  The record moves no level, so every rule here that derives a level from the ledger or looks for
  the record that earned it (`LEDGER_COUNTERPART`, `LEVEL_LEDGER_CONSISTENT`, `LEVEL_DROP_RECORDED`,
  `GRANT_TERM_RATIFIED`, `EVALUATOR_RECORD_CONTINUOUS`) reads the ledger as it stood immediately
  before it. `GRANT_TS_RECORDED` is the exception. It reads a timestamp and no level, and the
  grant carries the `reattestation` record's `ts`, so that record is the latest one for it.
  Passing over the type matters for a planted row: a same-level record restating `out-of-loop` on a
  ledger that stood at `in-loop` is not taken as the ledger's level. Dwell is measured from the ledger's
  level-bearing records (`rung.dwell_start_ts`), so an envelope change does not restart it. No other
  write restates a level, and none leaves a level where it was without a record: the old
  `RungStateMachine.re_ratify`, which rewrote a grant's evidence with no record, is removed, and
  fresh evidence enters a grant through the promotion ceremony. (A demotion whose trigger fires on a
  grant already at its floor also leaves the level unchanged; it appends a `demotion` record for the
  breach.) The stores no longer carry a record-less conditional update either: the only way to
  update an existing grant is `write_record_and_grant`, with its record.
- **The acknowledgment ceremony.** A TRUE finding whose remediation is deferred (honest
  history, a coordinated-window fix) is dispositioned by `acknowledge` — a **ceremony artifact,
  never a config toggle**: a signed record appended to the same append-only table, NEVER a mutation
  of the flagged item (that is the thing the audit exists to catch). It binds the rule, the
  coordinate, and the sha256 of the exact violation detail, so a NEW finding at the same coordinate
  is never auto-waived. Identity is STS-derived; the record is issuer-DSSE-signed and the ceremony
  **refuses to run unsigned** — a waiver mints "green", which is authority. The audit reports the
  matched finding as `acknowledged` (with the waiver ref): green-with-annotations, never silently
  green. Only a **closed waivable vocabulary** (`WAIVABLE_RULES`: LEDGER_COUNTERPART,
  RECORD_SIGNATURE_VERIFIES, GRANT_ENVELOPE_IN_FORCE, LEVEL_DROP_RECORDED, GRANT_TS_RECORDED) can be acknowledged — HMAC-tamper
  quarantines, unaccounted raises, and parse failures stay un-waivable, or the waiver becomes a
  laundering seam. Waivers apply only when their signature VERIFIES; a keyless/no-verify-keys run
  skips acknowledgment verification loudly and applies none (fail toward RED). Two rules police the
  waivers themselves: `ACKNOWLEDGMENT_SIGNATURE_VERIFIES` and `ACKNOWLEDGMENT_NOT_WAIVABLE`.

Relatedly, half-configured signing (`ISSUER_SIGNING_KEY_ID` or `EVALUATOR_SIGNING_KEY_ID` without
its role's key source) now **refuses** — the ceremony commands on the issuer side, and the demotion
runner on the evaluator side (exit 2) — instead of degrading to an unsigned record. That is the
fail-toward-less-authority polarity applied to config, and it holds for both roles because
both resolve through one parameterized code path (`grants/issuer_keys.py`), so neither can drift
into a weaker rule than the other. Fully-unconfigured signing gets the same polarity:
`ratify` **refuses** to store an unsigned PromotionRecord — writing nothing (no record, no grant
mutation; the proposal stays pending) — unless the operator passes an explicit `--allow-unsigned`,
which stores the record UNSIGNED with a loud warning. `acknowledge` and `re-seed` refuse unsigned
outright, with no override. The other writers (`seed`, `tighten`, and the runner's demotion, lapse
and withdrawal passes) sign
whenever their role's key is configured and write unsigned when none is, so a local floor with no
key material still works.

### Two signing roles — the ledger is signed by the identity that wrote it

GAL-SPEC §6.10 requires **every** ledger record to be signed, and §6.7.2 requires the demotion
evaluator to be a **separate identity** from the issuer. Satisfying the first by handing the
evaluator the issuer key would break the second: it could then mint `promotion` records, and the
ceremony boundary would exist only on paper. So there are two signing roles, split by the SOURCE of
the key material rather than by a field inside one map — a field is something a store-loaded config
could set, and the authority split would then be a value rather than a boundary
(`docs/config-provenance.md`).

| role | signs | env |
|---|---|---|
| `issuer` | `promotion`, `bootstrap`, `tightening`, `reattestation` (plus acknowledgment waivers and the MCP admission ledger) | `ISSUER_SIGNING_KEY_SECRET_ARN` / `ISSUER_SIGNING_KEY_FILE`, `ISSUER_SIGNING_KEY_ID`, `ISSUER_SIGNING_ZONE`, `ISSUER_VERIFY_KEYS_PARAM` / `ISSUER_VERIFY_KEYS_FILE` |
| `evaluator` | `demotion`, `lapse`, `withdrawal`: the automatic, no-model side, which only ever lowers authority | `EVALUATOR_SIGNING_KEY_SECRET_ARN` / `EVALUATOR_SIGNING_KEY_FILE`, `EVALUATOR_SIGNING_KEY_ID`, `EVALUATOR_SIGNING_ZONE`, `EVALUATOR_VERIFY_KEYS_PARAM` / `EVALUATOR_VERIFY_KEYS_FILE` |
| `standing-authority` | no record; each role's standing document (below) | `STANDING_AUTHORITY_SIGNING_KEY_SECRET_ARN` / `STANDING_AUTHORITY_SIGNING_KEY_FILE`, `STANDING_AUTHORITY_SIGNING_KEY_ID`, `STANDING_AUTHORITY_SIGNING_ZONE`, `STANDING_AUTHORITY_VERIFY_KEYS_PARAM` / `STANDING_AUTHORITY_VERIFY_KEYS_FILE` |

**Verification binds record type to role**, or the second identity is decorative: an
evaluator-signed `promotion` fails (`record_signer_wrong_role`), and so does an issuer-signed
`demotion`. A `reattestation` is the issuer's for the same reason a promotion is: it re-licenses a
grant on a human's authority, and under the evaluator's key the side with no human in it could
re-issue a grant the broker had quarantined. A key_id appearing in BOTH verify maps is a
configuration error that refuses at cold
start — one key with two roles is no split at all. A role whose verify keys are not configured
never passes: a record needing it is `record_role_unresolved`, not an exemption.

### Key standing: a third role and a signed document per role (GAL §6.10, GAL-41, #179)

Whether a record was validly signed and whether its signer still has standing are different
questions. The verify-key map answers the first. It cannot answer the second, because it has no
per-key state: removing a key reads the same whether it was rotated out or withdrawn, and either
way its records turn into `record_signer_unknown` findings while every grant they licensed keeps
its level.

**The source is a signed standing document, one per record-signing role**
(`grants/key_standing.py`). Each entry carries a key's public PEM and a state, with RFC 5280's
reason codes:

| state | fields | what its records keep |
|---|---|---|
| `active` | none | standing |
| `retired` | `retiredAt`, `retiredReason`: `superseded` or `cessationOfOperation` | standing. This is rotation |
| `withdrawn` | `withdrawnAt`, `withdrawnReason`: `keyCompromise` or `privilegeWithdrawn` (and the retirement pair, if it was retired first) | nothing, whatever the record's `ts` |

The document carries its `role`, a `version` that only rises, an `issuedAt` instant and the
`signer` that signed it, and every field dumps whether or not it is null. Transitions run one way:
`active` to `retired`, `active` to `withdrawn`, `retired` to `withdrawn`. There is no hold state and
nothing leaves `withdrawn`. A key that must be trusted again is a new key pair, added under a new
key id. A key id is never reused, and no document lists one public key under two key ids, so a
withdrawn key's bytes cannot come back as `active` under another name. A withdrawal voids records signed before `withdrawnAt` too, for both reasons: a
record's `ts` is part of what the key signed, so whoever held a compromised key can backdate what it
forges, and nothing here can date a record independently.

**The standing authority is a third signing role.** It signs standing documents and nothing else.
It is resolved the way the issuer and evaluator are, from its own names
(`STANDING_AUTHORITY_SIGNING_KEY_SECRET_ARN` / `STANDING_AUTHORITY_SIGNING_KEY_FILE`,
`STANDING_AUTHORITY_SIGNING_KEY_ID`, `STANDING_AUTHORITY_SIGNING_ZONE`, and on every verifier
`STANDING_AUTHORITY_VERIFY_KEYS_PARAM` / `STANDING_AUTHORITY_VERIFY_KEYS_FILE`). No key it holds
may appear in either role's map or document, by key id or by key bytes: one key that both signed
records and decided their standing could restore its own. Who holds it is a deployment fact
(`docs/operator-identities.md`).

**What pins it.** `ISSUER_STANDING_PARAM` / `ISSUER_STANDING_FILE` (and the `EVALUATOR_`
pair) name where the document is, on the same two transports as the flat map, exactly one per role.
The document replaces the map for its role, so setting both refuses. The maximum age,
`ISSUER_STANDING_MAX_AGE_SECONDS` (and the evaluator's), sits beside the pointer, in whole seconds,
with no default: a configured source without one refuses at startup. A per-agent value,
`AgentManifest.input_max_age_seconds["issuer_standing"]`, may only shorten the issuer's; a longer
one refuses at startup, and one given with no source configured refuses too
(`grants/standing_keys.py`). None of these is ever read from a store, a grant or a record.

**What a verifier accepts** (`grants/standing_source.py`). A fetched document is accepted only when
its one DSSE signature verifies, over the payload bytes as carried and before they are parsed,
under a standing-authority key; it is for this role; it lists no standing-authority key; it carries
every withdrawal this process has already accepted, unchanged; its version is greater than the one
accepted; no key in it moves backward or names a different public key; it lists no public key
twice; and no new key id in it names a public key the accepted document, or a withdrawal already
seen, lists under another id. A refusal is a verdict (`signature_invalid`, `signer_unknown`,
`malformed`, `wrong_role`, `rollback`, `withdrawal_dropped`, `transition_refused`, `key_rebound`,
`key_duplicated`, `authority_key_listed`, `unreadable`),
and the document already accepted stays in force until its own age runs out. Its as-of instant is
the earlier of the fetch and its `issuedAt` (GAL-43's rule, #176), so fetching the same document
again never makes it younger. Standing is established up to `as_of + max age`, and a skew bound
moves that end earlier (GAL-42). The standing authority therefore reissues each document at least
once per maximum age. A key seen withdrawn stays withdrawn for the life of the process, however old
the document becomes.

**What the record verifier says.** Where a role's standing document is configured, a record whose
signature verifies under a withdrawn key is `record_signer_withdrawn`, a verdict of its own and not
`record_signer_unknown`. The signature is checked first, so a tampered record still reads as a
signature failure. A retired key's records verify as they always did.

**The ceremony** (`python -m safe_agents.broker.grants.standing_command`): `init`, `add`,
`retire --reason`, `withdraw --reason`, `reissue`, each with `--role`. It runs under the standing
authority's key and refuses without it. It reads the current document, verifies it under the
standing-authority keys before building on it, refuses unless its version is the one named by
`--expect-version` (every command but `init`), applies one transition, signs the next version,
verifies its own output as a verifier would, and writes it back to the role's source or to
`--out`. It has no hold, no reinstate and no backward move. The version check is there because
the command re-signs what it builds on with a fresh `issuedAt`: an older document written back to
the source, or a stale `--from`, would otherwise come out as the next version with a withdrawal
dropped, and a process that had not seen the withdrawal would accept it. The check is only as good
as the holder's record of the last version issued.

**The enforcer's fall** (`grants/grant_standing.py`, the PIP in `prototype/broker_server.py`).
Where `ISSUER_STANDING_PARAM` or `ISSUER_STANDING_FILE` is set on the broker, the PIP asks, for
every grant above its `lastSafeLevel`, whether the issuer key behind its level still has standing.
That key is the signer of the last record that licensed the grant: the latest `bootstrap` or
`promotion` at its coordinate, or a `reattestation` after one, among the records at or before the
grant's own `ts`. It is taken from the record's signature only after the signature verifies over
the stored bytes. Demotion, lapse, tightening and withdrawal records license nothing, so none of
them moves the key, and an evaluator key is never the key behind a level. If the key is
withdrawn, or its standing cannot be established (no document accepted, the document past its age,
a key the document does not list, or a licensing record that is unsigned at or after the
record-signing epoch or does not verify), `effective_level` returns the lower of the level and
`lastSafeLevel`, exactly as a passed term does. That level reaches the PDP through `grant_level`,
so no rule changes and the corpus digest does not move. Nothing is written. Why the level fell
rides up as `Facts.standing_fall_reason`, beginning `issuer key withdrawn` or `issuer standing not
established`, and the PEP logs it once per request at the initial read, as it does a quarantine:
the first calls for acting on a key, the second on the source.

Standing applies from the record-signing epoch (`RECORD_SIGNING_EPOCH`, read by the broker too
where a standing source is configured). An unsigned licensing record dated before the epoch, or a
grant with no licensing record whose own `ts` is before it, is history signed by no key, so there
is no key whose standing could be asked about and the grant keeps its level. With no epoch
declared every unsigned licensing record is treated that way, with one exception that holds with
or without an epoch: an unsigned licensing record that comes after a signed record at its
coordinate, in ledger order, is never history. Signing had begun there before it was written, and
its `ts` is only its own claim (GAL §6.10). Without that rule, a writer that may append records but
holds no issuer key could plant an unsigned `reattestation` at the grant's own `ts`, sorting after
the signed `promotion` beside it, and restore a level a withdrawal took away. The record's `ts` is judged up to
the clock-skew bound later (GAL-42), so the bound only narrows that exemption. The audit still
reports the unsigned record (`RECORD_SIGNATURE_VERIFIES`).

The cost on the hot path: the key behind a coordinate's level is cached against the grant's `ts`,
and every sanctioned write changes that `ts`, so the first call after a ledger write pays one
partition Query on `RECORD#` items and one signature check and every other call pays a lookup. A
verified key stays cached until the grant is written again. A licensing record that did not verify
is cached against the document's version too, since a later version can add the key that signed
it. A ledger read that fails is a fall and is never cached. The document is fetched at boot and
then lazily, at most once per quarter of its maximum age, by the call that finds it due. The
document's as-of joins the decision's inputs as `issuer_standing` (#176), and its age counts toward
the decision's horizon but never refuses the decision: past it the grant falls instead, and a held
call is evaluated again at release. A document not accepted at boot does not refuse the boot; every
grant resting on an issuer key acts lower until one is accepted, and the broker says so.

**The `withdrawal` record and the runner** (`grants/withdrawal.py`). The evaluator's runner
(`grants/runner.py`) runs a withdrawal pass first, before lapse and demotion, when an issuer
standing source is configured for it. For a grant above its `lastSafeLevel` whose licensing key
the document lists as withdrawn, it lowers the stored grant to `lastSafeLevel` and appends a
`withdrawal` record in the same paired write (`write_record_and_grant`), signed with the
evaluator's key where one is configured. The record is neither a demotion nor a lapse: no trigger
fired (`triggeredBy` is empty) and no term ran out; `demotionReason` is `pending-evidence`, since
nothing is proven broken about the agent. The key it accounts for is not a field on the record,
because the published record schema has none for it. A reader derives it from the ledger, and the
record's `evidence` names it for a person. The runner writes nothing when standing is only not
established: that fall recovers by itself when the source answers, and a record would claim a
transition that did not happen. It exits 1 in that case, because the broker is falling for the
same reason. The type is ahead of the published record vocabulary (GAL 0.7.0-draft lists six).

**Recovery** is the promotion ceremony with fresh evidence, under an issuer key in standing. A new
promotion is the grant's new licensing record, so its key is the one asked about from then on. No
command restores a withdrawn key, and a key that must be trusted again is a new key pair under a
new key id.

**No other ceremony builds on a fall** (`grant_standing.ceremony_standing_refusal`, the standing
analog of `term.lapse_pending`). Where an issuer standing source is configured for them,
`propose`, `ratify` and `re-seed` refuse a grant above its `lastSafeLevel` whose issuer standing is
not held, withdrawn or not established. A promotion from the stored level would raise the grant
from a level it no longer acts at. A re-attestation would be worse: it becomes the grant's
licensing record, signed by a key in standing, so re-seed on a routine far-jump redeploy would
restore the withdrawn key's level with no promotion. The order is the withdrawal runner first, which
lowers the stored grant, and then `re-seed` at the lowered level and a new promotion. Standing that
is only not established recovers when the source answers, and the commands proceed then.

**What the audit reports** (`grants/audit_key_standing.py`). Four rules, none waivable:
`RECORD_SIGNER_IN_STANDING` (a record signed by a key its role's document lists as withdrawn,
either role, inside the signing epoch's scope or not; an evaluator key's withdrawal is reported here
and lowers no level, since lowering further would finish an availability attacker's work),
`GRANT_STANDING_WITHDRAWN` (a grant above its `lastSafeLevel` whose licensing key is withdrawn: the
runner has not lowered it), `KEY_SIGNED_AFTER_RETIREMENT` (a record whose `ts`, judged up to the
`--clock-skew-seconds` bound later, is at or after its signer's `retiredAt`) and
`WITHDRAWAL_RECORD_MATCHES_LEDGER` (a `withdrawal` record with no licensing record before it that
verifies under a key the issuer's document lists as withdrawn). A signature by a withdrawn key is
reported under the first rule and not under `RECORD_SIGNATURE_VERIFIES`, which is waivable. An
acknowledgment signed by an issuer key the document withdraws waives nothing
(`ACKNOWLEDGMENT_SIGNATURE_VERIFIES`). With no issuer standing document configured the audit
carries the annotation `gal-41-issuer-standing-unconfigured`, which reports that the deployment
does not conform to GAL-41, a different fact from passing it; with no evaluator document,
`evaluator-standing-unconfigured`.

**What this does not cover.** A grant acting in the window between a withdrawal's publication and
the next fetch, up to the maximum age. Anything a key's holder did before the withdrawal was published. Compromise of the
standing-authority key itself. Across a restart a process remembers no version and no withdrawal,
so a replayed document is stopped there only by its age. That holds only while the standing
authority does not re-sign the replay with a fresh `issuedAt`, which is why its ceremony builds on
no version but the one its holder names. Because standing is not established once
the document passes its age, an outage of the source, or an authority that stops reissuing, past
the maximum age moves every grant resting on an issuer key to the lower of its level and
`lastSafeLevel` at once. That is the clause working, and a deployment tunes it with the age it
declares. The reading is the last licensing record, in the enforcer and in the audit: a ladder
whose lower rung was signed by a withdrawn key and whose upper rung by a key in standing keeps the
upper rung's level. Re-seed cannot build that ladder past a withdrawal it can see, but a
re-attestation written before the withdrawal was published, or by a re-seed run with no standing
source configured, can. The MCP admission ledger's issuer signatures are not checked for standing.

> **Status.** The document, the third role, the loader, the record verdict, the enforcer's fall,
> the withdrawal runner and the audit rules are built. GAL-41 stays marked NOT YET IMPLEMENTED
> (#179) until a specification revision removes the marker and publishes the `withdrawal` record
> type.

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
   a stale `ConfidenceArtifact` as given; the drift detector that SETS the flag stays
   consumer/reference-tier (#59).
2. **`corroboration_failure`.** A premise or input failed its quorum of independent sources (k-of-n,
   none stale, provenance valid; physical/market sanity bounds count as the cheapest independent
   source). Failed corroboration pushes toward `abstain` and trips demotion — never toward `allow`.
   (`tool-broker-sketch.md` §"Corroboration".) The quorum result is the typed
   `CorroborationRecord` (broker/EVIDENCE.md); the runner derives the trigger from it
   deterministically (`agreeing < k`) — the corroboration pass that produces the record is
   consumer-side, like the drift detector behind trigger 1.
3. **`budget_breach`.** An atomic durable counter — error, a spend cap, escalation, or fallback —
   blew its bound for the period. (`Budgets`, `SCHEMAS.md` §5.)
4. **`false_action`.** An authenticated owner flagged an executed op as wrong (the `/flag` verb
   of the evidence-labeling pipeline): the runner re-derives the trigger from the durable `false_action` counter — never from
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

## Lapse — a certification has a term (GAL §6.7.6)

Every demotion trigger asserts that something was *observed*. None fires when nothing happens, so a
grant promoted long ago whose agent has since sat idle has no path down. A **term** is what forces
that authority to be re-justified.

- **The field.** `Grant.certifiedUntil` is an explicit UTC instant, or null for no term. It
  **ships unset**: there is no default term anywhere, and a grant with none never lapses at any
  instant. It is omitted from the canonical payload when null, so every grant written before the
  field existed keeps byte-identical canonical bytes; a set term is inside the payload and so inside
  the item HMAC, and altering it at rest quarantines the grant.
- **Only the ceremony sets it.** `propose --certified-until` carries it on the proposal (inside the
  proposal's integrity basis); `ratify` shows it to the checker, rejects a term that is not after
  the ratification instant, and writes the same value onto the raised grant and onto the signed
  promotion record (`PromotionRecord.certifiedUntil`). Every other write
  path (re-seed, tightening, demotion,
  lapse) carries the stored term forward unchanged: the stores' `refuse_term_extension` refuses any
  non-promotion write that would lengthen or drop a term, on all three backends, before anything is
  written. Nothing auto-renews. Re-promotion sets a new term, or none. A lapse record restates the
  term that expired (below) and sets nothing: the rule is keyed on the record's type, so a lapse
  record carrying the field is no more able to move a term than one without it.
- **Read side: enforcement does not wait for a writer.** The broker PIP hands the PDP
  `grants.term.effective_level(grant, now)`: once `now >= certifiedUntil` the grant acts at the
  lower of its stored level and `lastSafeLevel`. This is pure (no write, and the broker gains no
  grant-store write), so an idle grant nobody sweeps still falls exactly at its boundary.
- **The instant is an input.** Whether a term has passed is judged against an explicit `now`, never
  against the grant's `ts`, a ledger record's `ts`, or the audit tape. Those say when something was
  *written*, and a quiet log writes nothing, which is precisely the case the arc exists for. Only
  the outermost callers read the wall clock: the PIP (its injectable `clock`) and the runner CLI.
- **Skew fails toward less authority (GAL-42).** The term was stamped under the checker's clock and
  is judged under the evaluator's, so every evaluator judges it at `now + skew`, where `skew` is its
  own declared bound: `AgentManifest.clock_skew_seconds` for the PIP and for `propose`/`ratify`
  (read from the same `BROKER_MANIFEST`), and `--clock-skew-seconds` for the lapse runner, which
  reads no manifest and should be given the same value. A term therefore takes effect up to the
  bound early, never late, and a negative bound is refused at load. `ratify` applies the same bound
  to the proposal's expiry, to the proposed term (a term within the bound of the ratification
  instant is lapsed on arrival), and to the stored grant's term. Dwell
  (`rung.is_eligible_for_promotion`) gates a raise, so it is counted from the last transition up to
  the bound late, at `now - skew`; it takes the bound from its caller, and nothing in the ceremony
  calls it yet. Zero, the default everywhere, reproduces the unbounded comparison, and a bound over
  86400 seconds (one day) is refused at load. What it buys: a slow evaluator clock cannot keep a
  lapsed level in force for the width of an allowance. What it does not: it does not detect a clock
  that lies, and it does not bound drift.
- **Write side.** `grants.lapse.run_lapse`, run by `python -m safe_agents.broker.grants.runner`
  before the demotion pass under the same demotion identity, lowers the grant to `lastSafeLevel`,
  sets `demotionReason = "pending-evidence"`, and appends a **`lapse`-typed** record in the same
  atomic unit (`toLevel = lastSafeLevel`, `ratifiedBy = system:demotion-evaluator`, `predicate`
  null, **`triggeredBy` empty**). It is *not* a demotion record: a lapse asserts that nothing renewed
  the term, and naming a trigger would record a condition that never fired. It is idempotent (a
  grant already at or below `lastSafeLevel` has nothing to lapse), and it never revokes: revoking on
  a timer is a self-inflicted forced abstention.
- **The record carries the expired term as a field.** The lapse record's `certifiedUntil` is the
  grant's stored term, copied verbatim, inside the bytes the evaluator signs. So the ledger holds
  two instants for a lapse: `certifiedUntil`, when enforcement fell, and `ts`, when the record was
  written, read from the ledger clock and never set to the term. No reader takes the term from the
  record's `evidence` string, which names it for a person and is opaque to code. The field is
  optional: lapse records written before it was allowed carry none and are read as they are. The
  stores hold the write to it (`refuse_lapse_drift`, all three backends): under a `lapse` record
  the grant's `certifiedUntil` and `lastSafeLevel` do not move, and a term on the record is the
  grant's own.
- **A pending lapse blocks promotion.** While a grant's term has passed but its lapse is unwritten,
  `propose` and `ratify` refuse to anchor on its stored level. Run the runner, then re-propose from
  the lapsed level.
- **Audit.** Lapse records are legitimate ledger transitions. A lapse record must verify under the
  EVALUATOR role (`RECORD_SIGNATURE_VERIFIES`). That is required whenever `RECORD_SIGNING_EPOCH`
  is set, and checked-if-present while it is unset (a `reattestation` record's issuer signature
  is required either way, since `re-seed` never writes one unsigned); one naming a trigger cannot parse and is an
  `UNPARSEABLE_ITEM` finding; a grant that sits below its ledger-derived level with no record for
  the drop is `LEVEL_DROP_RECORDED` (waivable, for pre-atomic-write history where demotion wrote the grant
  first). `GRANT_TERM_RATIFIED` (un-waivable) holds the grant's term to the one on its latest
  promotion record: the term enforced must be the term the checker ratified.
  `LAPSE_TERM_RATIFIED` (un-waivable) holds each lapse record's term to the one on the latest
  promotion record before it, and to no later than the record's own `ts`, so a lapse record that
  reached the ledger outside the paired write cannot misstate how long the grant was certified.

Honest limits. The runner signs the lapse record — and the demotion record beside it — with the
**evaluator** key when one is configured in its environment; otherwise it stores them unsigned with
a warning. The older note here said that handing the issuer key to the demotion identity was a
deployment choice with a cost, because that identity could then sign promotion records: that is no
longer the choice on offer. The evaluator has its own key and its own env names, and the audit
refuses an issuer signature on a demotion or lapse record. What remains a real limit: the auditor
takes no clock, so it cannot report "term passed, lapse not yet written"; enforcement already acts
on it.

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
