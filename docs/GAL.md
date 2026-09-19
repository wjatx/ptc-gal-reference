# GAL — Grant & Autonomy Lifecycle

> **Status: design spine, superseded as normative text.** The reasoning behind the autonomy
> layer, `PTC.md`'s sibling, converged in design discussion and written before the specification
> existed. The normative text is `ptc-gal-standards/GAL-SPEC.md`, and `broker/grant-lifecycle.md`
> stays the contract-tier document for the state machine itself; where either disagrees with this
> document, it wins. Kept for the protocol argument over that state machine: the industry
> position, the conformance roles, and the joins to PTC and the evidence contracts. For what is
> demonstrated against what is asserted, read `docs/lf-reference-implementation.md`.

## 1. What GAL is, in one sentence

**GAL is the autonomy layer: an agent's authority to act is a per-`(principal, action-class)`
grant whose level is stored, signed state — moved upward only by a maker-checker ceremony licensed
by a deterministic predicate over measured evidence, moved downward automatically by deterministic
triggers, and enforced by a broker the agent cannot write past.** It is the ladder as an
enforceable protocol object, not a taxonomy label.

## 2. The industry position (why this is worth naming)

Every ingredient has prior art; the assembled lifecycle does not:

| Prior art | What it gives GAL | What it lacks |
|---|---|---|
| **Sheridan–Verplanck LOA, SAE J3016 levels** | the ladder vocabulary — graduated autonomy is a 40-year-old idea | descriptive taxonomy: a label on a system, not stored state an enforcement point reads per call |
| **FDA PCCP** (Predetermined Change Control Plan) | the regulatory precedent for a **pre-authorized change envelope** — change without per-instance re-approval, inside declared bounds, with declared evidence methods | paperwork reviewed by humans; no runtime object, no automatic rollback when evidence sours |
| **ODD** (Operational Design Domain) | evidence validity bounds — a capability claim holds only inside the declared domain; leaving it voids the claim | no lifecycle attached: ODD-exit detection and response are per-implementation, not protocol |
| **DSSE / in-toto** (via PTC §6, #170) | signed attestations keyed to workload identity | supply-chain scoped; no autonomy semantics |
| **Cedar / OPA** (via PTC §5, #177) | deterministic policy evaluation | no evidence or lifecycle semantics |

- **The seam is the assembly:** *autonomy level as signed, evidence-gated, automatically-demotable
  runtime state* — a grant that must earn its rung through a recorded ceremony and loses it
  deterministically when the evidence stops supporting it. Nobody ships that as a protocol object.
- **Positioning line:** *LOA taxonomies name the rungs; PCCP shows a regulator pre-authorizing
  change inside a declared envelope; GAL makes the rung itself a signed runtime object that must
  earn its level and demotes itself.*
- **Strategy: adopt the standard where one exists; build only the seam** (PTC §2's rule). The
  ladder vocabulary, the change-envelope concept, the domain-bounds concept, the signing format,
  and the policy language are all adopted; the lifecycle machinery that binds them is ours.
  (Standards-contribution path: same LF agent-standards track as PTC; `auto-agents/FEEDBACK-LOOP.md`
  §standards candidates.)

## 3. The GAL objects

- **`Grant`** (`broker/SCHEMAS.md` §1) — the unit of authority: `(principal, action-class)` →
  `level` (`in-loop` / `on-loop` / `out-of-loop`), plus `lastSafeLevel`, `demotionTriggers`,
  `demotionReason`, the in-force `envelopeHash`, an optional certification term
  (`certifiedUntil`, #255, shipping unset), and integrity protection (HMAC + loud quarantine,
  live since sa#122/124).
- **`PromotionRecord`** (`broker/SCHEMAS.md` §7) — the append-only ceremony record: from/to
  level, evidence window, the predicate that licensed it, `proposedBy ≠ ratifiedBy`, timestamp;
  the proposal references the in-force envelope hash, which is stamped onto the record
  (`envelopeHash`) and onto the Grant. Demotions append a demotion-typed record on the same
  ledger — landed in Phase 3's batched schema pass, superseding §7's earlier demotion exemption
  (previously demotion emitted only an `AuditRecord`). The record ships five types
  (`promotion` / `demotion` / `bootstrap` / `tightening` / `lapse`); `stale_confidence` demotions
  carry `demotionReason="pending-evidence"` (label-free drift voids the certification), the other
  triggers `"failing"`. A `lapse` (#255) records an expired certification term: also
  `"pending-evidence"`, but with an empty `triggeredBy`, because it records that nothing renewed
  the term rather than that something fired.
- **The evidence artifact** (#184) — the typed constructed-confidence + counters input the
  promotion predicate and demotion triggers consume (§7).
- **`actionClass` derives from the manifest ToolOp model** — a grant's action class is computed
  from the ToolOp fields consumers already declare (`effect` / `external` / `reversible`), not
  from any base-owned catalog. **There is NO base `action-classes.yaml`** (locked 2026-07-11;
  supersedes #53 as originally written, which would have undone the #171 debaking). Base owns the
  shape, consumer owns the content — the same split as every other manifest block. **High-blast
  derives from the same fields** (`effect=write ∧ external ∧ ¬reversible`); a consumer may
  additionally *declare* a class high-blast but never un-declare a derived one (tighten-only —
  decided 2026-07-12). A "blocked" class is simply the absence of a grant (the Recommend rung),
  not a flag; a never-grantable hard ceiling, if ever wanted, is a future tighten-only Envelope
  knob.

## 4. The ladder (adopted — cite, don't restate)

`broker/grant-lifecycle.md` owns the state machine and is normative for: the **four-rung ladder**
(Recommend → in-loop → on-loop → out-of-loop) with the `level` enum complete at the three acting
rungs; the **actuation discriminator** (Recommend = the agent holds no grant and no staged `Intent`
ever exists; in-loop = the broker stages an `Intent` and executes on approval); rung as
**per-`(principal, action-class)` state, never per-agent**; `lastSafeLevel` never `out-of-loop`;
and the safe-rung **polarity staying per-agent, never base** (abstain-is-safe vs positive-safe-
action — `ARCHITECTURE.md` §"The one thing that must NEVER be in the base"). Level is orthogonal
to the five Decision verbs. One transition rule GAL adds on top: **any level → `in-loop` is always
permitted** — voluntary tightening is safety-monotone and needs no ceremony (locked 2026-07-11;
the state-machine build is #60).

## 5. Promotion — the deterministic gate + maker-checker ceremony

The only upward path. Three locked properties (2026-07-11):

1. **The acceptance gate is deterministic** — a predicate over windowed, scoped counters
   (`principal+op+UTC-day`, the live seam) plus the #184 evidence artifact. No LLM anywhere in
   the licensing path. Human ratification composes with it: high-blast action classes are
   **always** ratified by a human checker (`proposedBy ≠ ratifiedBy`); the pre-authored signed
   predicate (`broker/grant-lifecycle.md` §Promotion) is GAL's PCCP — the change envelope
   authorized in advance, stringency scaling with blast radius. *Why high-blast is **always**
   human and not merely a stringent predicate:* control response time. The after-the-fact
   controls (demotion, the ledger audit, an off-path observer) bound a bad grant's *duration*,
   never the blast of a single exercise of it, so only a human inside the window fits a high-blast
   act — `ptc-gal-standards/GAL-SPEC.md` §6.4.4 is normative; the doctrine underneath it is decision- versus
   effect-divergence, and the rule that an audit trail is only as trustworthy as its writer.
2. **The different-model-family LLM checker (#58) is a configurable evidence reviewer feeding the
   gate, never the gate itself.** It can raise suspicion and attach findings to the evidence
   artifact; it cannot license or veto a level change. Same shape as channels screening gate 7:
   the model may only surface, the gate decides (`docs/deterministic-gate.md`).
3. **Ceremonies ship as SDK-style commands** (`seed` / `re-seed` / `propose` / `ratify`), not
   runbook scripts — they are the grant store's only sanctioned mutation path, sitting under the
   config-provenance lattice (#186). `seed_grants` retires to bootstrap-only; the far-jump
   cross-version re-seed (envelope-hash change → quarantine → re-seed) is re-issued as the
   ceremony's **re-attestation** case, not a side door. Re-attestation **carries the prior level
   under human ratification** (decided 2026-07-12 — formalizing live re-seed practice; a hard
   restart at `lastSafeLevel` was rejected because it turns every far-jump redeploy into an
   autonomy event, and the high-blast always-human rule already backstops the dangerous classes).
   `seed` itself emits a **bootstrap-typed PromotionRecord**, so every grant has a ledger
   counterpart from birth and #62's no-orphan row holds with no exemption.

**Predicate expression — decided with PTC §5 (#177, closed 2026-07-20): stay custom.** The
promotion predicate shares the per-call gate's policy-language decision, and that decision is
settled: the custom pure evaluator stays. The differential spike that decided it (all 73,728
reachable gate inputs ported to Cedar and Rego) found Cedar cannot express the first-match
ordering checkably or the value-producing verbs at all, and Rego — though an exact technical fit —
forfeits the analyzability argument while adding an external binary to a path whose property is
purity. `docs/PTC.md` §5 carries the full record so this is not re-litigated.

## 6. Demotion — automatic, deterministic, no model (adopted)

`broker/grant-lifecycle.md` §Demotion is normative: exactly four triggers (`stale_confidence`,
`corroboration_failure`, `budget_breach`, `false_action` — the owner `/flag` verb's durable
counter, shipping OFF; #193), fall to `lastSafeLevel`, `demotionReason` keeps
`"failing"` and `"pending-evidence"` distinct, hysteresis (different thresholds + dwell time)
prevents flapping, and **the path must be drilled** — it has been: **all four triggers have fired
live on the `development` floor** (budget_breach in the Phase 3 drill, false_action via a real
owner `/flag`, corroboration_failure from a failed 1-of-3 quorum record, stale_confidence last on
2026-07-16). Demotion writes run under a separate identity
from the agent — the grant-store write-protection seam (agent role holds no write permissions on
the grant table) is the structural backstop; a grant-store write the agent can reach is a
promotion bypass.

**Lapse (#255, GAL §6.7.6).** None of the four triggers fires when nothing happens, so an idle
grant had no path down. A grant may now carry a term, `certifiedUntil`, set only by the promotion
ceremony and never extended in place. Once the term passes, the broker PIP enforces the grant at
`lastSafeLevel` immediately, as a pure function of an explicit evaluation instant (never a record's
timestamp), and the demotion runner records a `lapse`-typed ledger entry under the same identity.
A lapse lands on `lastSafeLevel` and never revokes. `broker/grant-lifecycle.md` §Lapse is the
detail.

## 7. Evidence contracts (the #184 half)

GAL's predicates consume typed evidence, and the evidence side is its own epic (#184 — Pillar 4,
calibrated uncertainty), packaged per `docs/contract-vs-reference.md`:

- **Constructed confidence as a contract, not a logprob read** — a typed artifact attached to a
  proposed action; method (self-consistency / ensemble / conformal) pluggable behind the contract.
- **Below-bar → the per-agent safe response, deterministically** — under abstain-is-safe
  polarity, wired to the existing `abstain` verb + approval queue; a positive-safe-action domain
  derives its own below-bar response (§4's polarity rule — the base ships the wiring, never the
  polarity).
- **Error budgets drawn by `error_prob × blast_radius`** — per-period, on the scoped-counter seam;
  breach emits `budget_breach`, a typed demotion input, never a model judgment.
- **Label-free drift** as a typed `stale_confidence` input (#65 absorbed).
- **Evidence soundness is a predicate requirement:** evidence must come from a *covered*
  distribution (`broker/grant-lifecycle.md` §Promotion) — a thin observed-accuracy count over an
  irreversible action class is unsound and the ceremony must reject it.

All bars and budgets are Envelope knobs **shipping OFF** (`docs/friction-doctrine.md`): the floor
is the mechanism and the ratchet's asymmetry, never a domain threshold.

## 8. Signing (adopt, don't invent — reuse PTC Phase 4)

The `PromotionRecord` is signed as a **second DSSE / in-toto-style statement type** on the exact
machinery PTC Phase 4 shipped (#181, `docs/tce-signing-shape.md`, `safe_agents/channels/signing.py`):
same DSSE PAE discipline, same broker-resolved workload identity, same never-in-the-agent-image key
handling. A signed PromotionRecord makes a level change **non-repudiable**: who proposed, who
ratified, over which evidence window, under which in-force envelope hash (`envelopeHash` is a
first-class §7 field since Phase 3's batched schema pass; Phase 4 binds it into the signed
statement). Grant *integrity at rest* is
already live (HMAC + loud quarantine); signing adds provenance of the *change*. Optional Rekor-style
transparency anchor for high-blast promotions stays a knob, OFF — same posture as PTC §6.

**What maker≠checker honestly guarantees (locked 2026-07-14, #202).** The ceremony derives both
identities from STS and compares credential ARNs, so the platform enforces exactly this: **no
single credential can both propose and ratify** — a compromised agent, CI job, or leaked key
cannot self-promote — and it *evidences*, non-repudiably, which credentials did each. It does
**not** and cannot enforce **two humans**: at N=1 operator, maker≠checker is the same judgment
exercised through two ARNs, and the audit trail records that truthfully. Two-human review is an
organizational control (separation of duties), which a platform can only evidence, never enforce
— consumers who need it establish it as a deployment property (distinct credential holders) and
the signed record proves whether it held. The reference stack ships a standing **checker role**
(`identity-stack.ts` `CheckerRole`, context-gated OFF) so the credential separation is
*topological* — a standing trust naming the checker principals — rather than *ceremonial*
(per-ceremony trust-policy surgery, whose revocation is eventually consistent).

**The local (solo) identity arm (#226, 2026-07-25).** A developer with no AWS account has no STS,
so the derivation above is unreachable and no ceremony can run at all. The arm that fixes this
changes the *identity source*, never the invariant: `BROKER_LOCAL_IDENTITY` names a role from a
CLOSED two-value catalog (`maker` / `checker`) and the *who* half stays derived from the OS — there
is still no `--as`, on any arm. Three properties hold it in place. It is an **explicit opt-in**:
absent credentials with the var unset REFUSES with a pointer rather than falling back, because
silently substituting the identity a record is stamped with is the #197/#199 wrong-authority shape.
It is **refused on the DynamoDB arm**, so a solo-attested record can never reach the cloud tables —
the property is structural, not advisory. And it is **honest**: the identity string carries a
`local-solo:` prefix on its face and the ledger record carries a typed `attestation` marker DERIVED
from that string, so a record can never imply a review that did not happen. What survives intact is
the guarantee this section already stated — the proposer cannot ratify in ONE action. Because the
two roles are distinct strings, the `proposedBy != ratifiedBy` schema rule needed no relaxation;
honesty comes from the marker, not from loosening the invariant. NB the comparison is by ROLE, not
string equality: a laptop whose hostname churns between the two invocations must not slip an
identical role past an `==` check.

## 9. The PTC join — rung tracks provenance

**PTC provenance feeds GAL evidence; GAL moves state. `PTC.md` §9 is normative for the ceiling:**
a capability's rung may never exceed what the mesh can currently *prove* about its premises — taint
bit ⇒ trusted-sender autonomy at best, unsigned lineage ⇒ approval-gated, signed lineage ⇒ eligible
for autonomous cross-mesh high-blast. GAL adds the operational half of the join:

- **PTC-verified provenance is a precondition input to the promotion predicate.** A promotion into
  a rung whose PTC §9 row isn't satisfied must be structurally unconstructible — the predicate
  evaluates the provenance maturity as a gate term, not a reviewer's judgment. **Operationalized
  strictly (locked 2026-07-12, Phase 4):** BOTH acting rungs (`on-loop`, `out-of-loop`) require
  `signed-lineage` maturity — unsigned lineage ⇒ approval-gated means no acting-autonomy rung is
  reachable without receiver-verifiable signed provenance (`REQUIRED_PROVENANCE_MATURITY`,
  `safe_agents/broker/grants/predicate.py`). `in-loop` as a target (the Recommend-origin grant-creating first
  promotion) carries no provenance ceiling; every evidence gate still applies. Covered-distribution
  soundness enters the predicate as an explicit proposer assertion recorded on the ceremony record
  (also locked 2026-07-12), plus the artifact's own staleness voiding independently.
- Concretely: a live-brokerage `trade.place` leaves `in-loop` only when **both** this lifecycle's
  evidence predicate passes **and** PTC signing verification is ON for the feeding channels
  (recorded on sa#4 — nobody promotes on vibes). This refreshes PTC §9's pre-#181 "until sa#161"
  prose: the signing machinery now exists (#181); verification ON is the operative condition.

## 10. Open problems (banked)

- **Evidence poisoning.** Two cases, and the mitigation for the first does nothing about the
  second (#342; `ptc-gal-standards/GAL-SPEC.md` §8.1 is normative and was corrected 2026-08-03 in `0.2.2-draft`).
  *Tainted grooming*: an injected input shapes behavior and the turn carries taint. Do tainted-turn
  outcomes count toward the evidence window, at full or discounted weight? Excluding them starves
  evidence (an availability lever, `docs/friction-doctrine.md` §availability); including them lets
  an adversary who can taint a turn shape what the window records. Likely answer: taint-aware
  evidence windows, weight as consumer policy — but this is IFC-hard, like PTC §8's
  declassification. *Untainted grooming*: a patient adversary, or ordinary drift with no adversary,
  produces a clean record the predicate rewards. Nothing is tainted, so there is no signal to
  weight and no weighting scheme closes it. Absence of taint is not evidence of absence of
  grooming. What bounds it is the ceremony, not the predicate — maker≠checker ratification the
  accumulating party cannot supply. The asymmetry to remember: taint is a ratchet and cannot be
  farmed; an evidence window rewarding accumulated clean behavior is a credit mechanism whose
  state the subject improves through its own conduct.
- **Label latency bounds autonomy.** Re-promotion's control loop has deadtime = `labelLatency`
  (`broker/grant-lifecycle.md` §Re-promotion); domains with very slow labels may never soundly
  reach `out-of-loop`. That is a correct result, not a bug — but stating it normatively will be
  contested.
- **Who ratifies the ratifier.** `ownerId` is the root of trust for ratification; at N=1 owner
  this is clean, but the N>1 principal fan (#187 is the tracking issue; its ceremony-side analog) —
  quorum ratification, owner-key rotation mid-window — is unspecified. What #202 locked (§8)
  bounds the claim honestly: the platform enforces two *credentials*, evidences two *humans*.
- ~~Cross-version re-attestation semantics~~ — **resolved 2026-07-12**: re-attestation carries
  the prior level under human ratification (§5). Kept here as a record that it *was* an open
  problem; the finer rule (whether a tighten-only envelope delta could skip ratification) can
  wait for an envelope-diff mechanism that doesn't exist yet.

## 11. Conformance roles & what already exists

Two conformance roles, mirroring PTC's structure:

- **Grant issuer** — hosts the ceremony: evaluates the deterministic predicate, enforces
  `proposedBy ≠ ratifiedBy`, signs the `PromotionRecord`, writes the grant store. The reference
  issuer is the ceremony command set (Phase 4).
- **Grant enforcer** — the broker: reads the grant per call, enforces `level` (the rung's verb
  mapping), runs the demotion triggers, and structurally cannot be written past by the agent.
  The reference enforcer is the safe-agents broker — the one deliberately non-swappable
  implementation (`docs/contract-vs-reference.md`).

**Everything this section once listed as missing is live.** The full stack, all drilled on the
`development` floor and audited green in CI on both floors:

- **Store + enforcement** (pre-epic): grant store + HMAC + loud quarantine (sa#122/124),
  store-mode production operation (ta#13), scoped budget counters; since #212, the counter
  period is a manifest knob (`utc-day` | `utc-hour`, period-in-key so a mismatch reads zero —
  failing toward less authority).
- **State machine + demotion as code** (Phase 3, #60/#59/#55): four-type PromotionRecord ledger,
  conditional UpdateItem demotion writes, the out-of-band demotion runner under the floor
  DemotionRole, the L1–L8 conformance suite.
- **The ceremony command set** (Phase 4, #57/#123/#190/#189): `seed`/`re-seed`/`propose`/
  `ratify`/`reject` as the store's only sanctioned mutation path — STS-derived maker≠checker,
  HMAC'd single-shot expiring proposals, conditional writes end-to-end (every write-order failure
  falls toward less authority), the evidence-wired predicate with the §9 ceiling, DSSE-signed
  PromotionRecords on the issuer's own key. `seed_grants` retired to a deprecation delegate.
- **The evidence reviewer** (Phase 4b, #58/#194): the different-model-family LLM reviewer, ships
  OFF, findings-attach-never-gate — its first real finding (`insufficient_window`) fired in the
  Phase 6 drill and did not gate, exactly as specified.
- **The grant-integrity audit** (Phase 5, #62): the 19-row keyed/keyless auditor in CI on both
  floors, extended by #201 (`GRANT_ENVELOPE_IN_FORCE`) and #196 (the acknowledgment ceremony —
  a waiver is a signed append-only ACK# artifact, never a config toggle).
- **Evidence accumulation + receipts**: the #193 labeling pipeline (observations +
  human_override, log-never-gate), #198 approval receipts (executed==approved byte-provable from
  the audit chain alone), the #212 multi-period evidence windows (day-span/period riding the
  proposal HMAC, #207).
- **The operator identity plane**: every ceremony function under a least-privilege standing role
  (Maker/Checker/Promotion/Demotion/Auditor/Watcher), context-gated OFF, each proven live at
  first use (`docs/operator-identities.md`).
- **The terminal proof** (sa#4 close, 2026-07-15): the full arc — evidence → propose → ratify →
  exercise → induced demotion → re-climb — as one story on a fresh grant, every leg under its
  standing identity, ending with the promoted grant *acting* (the "a promotion is not done until
  the promoted grant acts once" doctrine). Re-run at `utc-hour` period in 24m35s of lifecycle
  time across a real hour boundary (#212, 2026-07-17).

## 12. Roadmap (decomposition — epics sa#4 + #184) — **both epics CLOSED**

All six phases are done; sa#4 closed 2026-07-15 on the terminal proof, #184 closed with Phase 2:

1. **Phase 1 (#185)** ✅ — this doc + sub-issue reconciliation to post-#171 vocabulary.
2. **Phase 2 (#184)** ✅ — evidence contracts (v0.20.0, in production).
3. **Phase 3 (#60, #59, #55)** ✅ 2026-07-12 — state machine + deterministic demotion, live drill.
4. **Phase 4 (#57, #58, #123 + riders)** ✅ 2026-07-12/13 — ceremony commands, predicate + §9
   ceiling, signed records, evidence reviewer.
5. **Phase 5 (#62)** ✅ — grant-integrity audit in CI, both floors.
6. **Phase 6 (+6b/6c/6d)** ✅ 2026-07-14/15 — live promotion on real approve-release evidence,
   receipts, `/flag`, the last two demotion-trigger input paths, then the terminal proof (§11).

Still open beyond the closed epics: **#187** (N>1 principal fan — §10's ratifier question),
**#216** (the re-homed cap-adjust slice), and the normative-spec pass alongside PTC's #178.

Exit condition beyond the epic, refreshed: with the lifecycle machinery proven, a live-brokerage
`trade.place` off `in-loop` is gated on **PTC receiver-side verification ON in production** (§9;
the sa#4 comment is the record) — plus the brokerage MCP credential-delivery slice (#221 Phase 4
follow-on) actually wiring the capability.

## 13. Relationships

- `broker/grant-lifecycle.md` — **owns the state machine**; this doc is the protocol spine over
  it. Where they overlap, that file is normative for mechanism, this one for positioning + joins.
- `broker/SCHEMAS.md` §1 (Grant), §7 (PromotionRecord) — the object contracts.
- `docs/PTC.md` — the sibling spine: §5 shares the parked policy-language decision (#177), §6/#170
  supplies the signing machinery (§8 here), §9 is the normative rung ceiling (§9 here).
- `docs/tce-signing-shape.md` — the DSSE shape this doc's §8 reuses.
- `docs/deterministic-gate.md` — the surface-vs-decide rule the #58 evidence reviewer inherits.
- `docs/friction-doctrine.md`, `docs/contract-vs-reference.md` — the floor-vs-knob and packaging
  lenses (§7's OFF defaults; §11's role tiers).
- `auto-agents/FEEDBACK-LOOP.md` §standards candidates, `auto-agents/PROMOTION-STRATEGY.md` — the
  corpus-side record of candidate #2 and the publication strategy.
