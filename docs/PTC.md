# PTC — Provenance & Trust Context

> **Status: design spine, superseded as normative text.** The reasoning behind the trust layer,
> converged in design discussion and written before the specification existed. The normative text
> is `ptc-gal-standards/PTC-SPEC.md`, and where this document and the specification disagree, the
> specification wins. This one is kept for the argument it carries and for the landscape survey it
> rests on (`docs/references/trust-context-landscape.md`). For what is demonstrated against what is
> asserted, read `docs/lf-reference-implementation.md`.

## 1. What PTC is, in one sentence

**PTC is the connectivity-orthogonal trust layer: a signed trust-context envelope — sender-class +
provenance chain + taint labels on a Biba integrity lattice — consumed by a deterministic gate at
every agent and tool boundary.** It is the *seam* that the primitives around it leave unstandardized.

## 2. The industry position (why this is worth naming)

Three layers exist; the **seam is the white space** (`docs/references/trust-context-landscape.md`):

| Layer | What it does | Mature primitives | safe-agents today |
|---|---|---|---|
| **A — non-repudiation** | cryptographically sign provenance | DSSE/in-toto, SD-JWT-VC, VC 2.0, Sigstore/Rekor | ✅ signed *across* brokers since #181 (Ed25519 DSSE per envelope, v0.18.0); receiver verification a knob shipping OFF |
| **B — deterministic gate** | decide with no model in the path | Cedar, OPA/Rego, CaMeL, Biba lattice | ✅ our PDP (sa#44, `decide()` pure) |
| **C — the seam** | signed trust context *consumed by* the gate at the boundary | **nobody** (AP2 = payments-only precedent) | ✅ **this is us** |

- **MCP and A2A are connectivity standards with no trust model** — MCP tool-poisoning and A2A
  impersonation are open because neither carries taint/provenance. PTC rides *orthogonally* (MCP
  `_meta` field / A2A extension / our own channels), so it composes with both rather than competing.
  The MCP half is no longer only a critique: `broker/MCP-HOST.md` (#174/#221, shipped v0.35.0–v0.42.0)
  is the PTC posture applied to MCP — discovery is untrusted input, a tool is callable only via
  two-key admission (image-baked declaration + an HMAC'd registry row over the signed
  `(server_id, tool_name, input_schema, description)` set), description drift quarantines, and
  per-tool response taint rides the same lattice. Proven against real third-party servers
  (stdio and streamable-HTTP).
- **Positioning line:** *MCP is how agents reach tools; A2A is how agents reach agents; PTC is how
  trust travels across both.*
- **CaMeL** (dual-LLM, capabilities-on-values, deterministic gate) is our in-process design cousin;
  PTC is "CaMeL's pattern **+ a wire format + cryptographic non-repudiation + a production broker**."
- **Strategy: adopt the standard where one exists; build only the seam.** If a primitive is solved
  (signing, identity, policy language), name and adopt it — less work, more credibility, and it
  focuses our novel effort on the seam, which is the publishable part. (Standards-contribution path:
  Linux Foundation agent-standards track.)

## 3. The trust-context envelope (the PTC object)

Rides orthogonally to transport; verifiable independently of it. Carries:

- **sender-class** — `owner` / `peer-agent` / `external` (a floor, never a grant). Maps to a lattice
  level. Binds to a workload/DID identity (candidate substrate: SPIFFE/WIMSE WIT, or DID).
- **provenance chain** — an *ordered, append-only, non-strippable* sequence of
  `{zone, source, transform, label, ts}` entries. The **replayable index**, not a content log.
- **taint labels** — derived deterministically at ingestion from source trust; never model-judged.

Already partially specified in `channels/SCHEMAS.md` (EventTrigger), `channels/TRUST-MAPPING.md`
(sender-class), `broker/TAINT.md` (taint). PTC unifies + generalizes these beyond channels
(broker + channels + memory) and adds the signing envelope.

## 4. The Biba integrity lattice (adopted)

Replace informal taint language with an explicit **Biba integrity lattice** (no write-up: low-integrity
data must not influence a higher-integrity action without a logged endorsement):

- **Levels (draft):** `SYSTEM > USER(owner) > AGENT(peer) > TOOL_OUTPUT > UNTRUSTED_WEB`.
- **Rule:** data at level *L* may not flow into an action requiring level *> L* without an explicit,
  **audited endorsement/declassification** step.
- **Endorsement = `trusted_read_sources` today**, reframed as a first-class, audited declassification
  event (see §8 — this is where the bugs live).
- Adopt into `broker/TAINT.md` + cross-ref sa#44 as an early build step.
  **Adopted (#169):** `broker/TAINT.md` §1.1 — the level vocabulary + no-write-up rule are normative
  (the `tainted_external_write` cut *is* no-write-up; `trusted_read_sources` *is* audited
  declassification); multi-level enforcement stays [deferred] to the signed-provenance work.

## 5. The deterministic gate (Layer B)

- Our PDP (`safe_agents/broker/pdp/engine.py`, sa#44) is the reference gate: pure, no LLM, first-match
  rule table over `(BrokeredCall, Facts)`. This is `docs/deterministic-gate.md` — PTC's gate half.
- **Cedar / OPA — DECIDED 2026-07-20 (#177): keep the custom pure PDP.** Settled by a throwaway
  differential spike, not a trade-off table: the 14-rule table was ported to Cedar and to Rego, and
  all **73,728** reachable `(BrokeredCall, Facts)` combinations were run through each port and the
  real `decide()`. Four findings, in the order that decided it:
  - **Cedar's validator does not check the property we needed.** Cedar *can* express the table
    exactly — but only by hand-flattening the first-match order into mutually-exclusive guards
    (7.3× the policy terms), and `validate_policies` passes a deliberately overlapping policy set
    (`validation_passed=True`). The flattening's correctness was established by differential-testing
    it against `engine.py` — **the Python engine stayed the oracle.** Formal analyzability was the
    reason to consider Cedar; it does not reach the ordering property.
  - **Ordering does not survive a direct port.** One policy per rule agrees on only 71.27% of inputs:
    75.17% match more than one determining policy, and Cedar returns them unordered. A tainted +
    external + irreversible in-loop write matches three forbids; the PDP must return rule 11, and
    that reason string lands on the hash-chained audit record.
  - **Three of the five verbs degrade.** Cedar policy bodies must evaluate to `bool` — there is no
    value channel, so `transform` (which must produce `op` + clamped `args`) is not expressible at
    all, and `abstain` / `require_approval` survive only as a caller-side policy-id → verb table.
  - **Taint fits today but not the declared direction.** The two-level `tainted: bool` projection
    ports fine, as does a PIP-precomputed scalar level. But Cedar has no quantifier — existential
    reasoning over provenance records and over chain hops are both parse errors — and §4's Biba
    direction plus the provenance chain of §3/§9 are exactly that shape.
  - On polarity, precisely: Cedar does **not** bake a safe-default polarity into the base. It cannot
    *represent* the question — a positive-safe-action fallback is a positive action with arguments,
    which is the verb finding again — so it evicts the polarity seam to the caller. Recorded because
    the doctrine concern was expected to be dispositive here and the spike did not support it.
  - **OPA/Rego** matched all 73,728 inputs with no flattening (`else` gives real first-match order),
    in 81 lines vs Cedar's 189, with all five verbs native and both quantifier shapes working. It is
    the better technical fit and was still declined: it forfeits the formal-analyzability argument
    that motivated the question, and adds an external binary to a path whose property is purity.
  - The differential corpus is retained as the shape of a PDP conformance suite for #178.

## 6. Layer A — signing (adopt, don't invent) → #170

> **Shape decided (#170):** `docs/tce-signing-shape.md`. Sign the chain/index with a **DSSE envelope
> over an in-toto-style statement** (best structural fit; native multi-sig for a per-broker hop chain);
> reserve **SD-JWT-VC** for the §7 content drill-down, not the chain signature; key on a broker-resolved
> **workload identity** (SPIFFE/WIMSE → SVID, DID fallback); optional **Rekor** anchor for high-value
> chains (knob, OFF). Build is Phase 4.

- **#170: "wrap the provenance chain in a DSSE / in-toto-style attestation"** (best structural fit for
  a chain predicate) — or **SD-JWT-VC** for a compact, selectively-disclosable token. Sign with
  JWS/COSE keyed to a workload identity; optionally anchor high-value chains in a Sigstore/Rekor-style
  transparency log.
- Signing makes the chain **non-repudiable across brokers** — the prerequisite for autonomous
  cross-mesh high-blast action. **Landed v0.18.0 (#181)**: the sending broker signs per-envelope
  (DSSE PAE, Ed25519 workload identity), the airlock verifies + loud-quarantines forged chains.
  Receiver-side verification is a knob **shipping OFF**; until it's ON in production, such actions
  stay human-in-the-loop (see §9). **sa#161** (the campaign watchdog) was blocked on this, then
  shipped and **closed 2026-07-18**: its live drill was the first verification-ON airlock bring-up
  (on the `development` floor), and it exercised the signing edge adversarially — a signed-chain
  campaign keyed on the verified signer, while 6 forgery events that cryptographically *claimed*
  the signer's key attributed only to a transport token, the claimed signer appearing nowhere in
  the forgery attribution ("authenticity ≠ count trust"; the reflected-DoS negative proof, live).
  Canonicalized sender identity is bound into the signed context (`channels/SIGNING.md` S1b) so
  mutating either dedupe-key half breaks the signature.
- **Message-layer signing is chosen *instead of* transport peer authentication, and that is a
  divergence worth stating** (#260, 2026-07-25). The Five Eyes joint guidance asks for mutual TLS on
  every inter-agent and agent-to-service call; PTC puts non-repudiation on the message instead. The
  properties are not equivalent: a signature survives the relay hops that terminate a TLS session,
  which is what a multi-zone mesh needs, while mTLS authenticates a peer the chain does not
  otherwise identify. A deployment should do both. `ptc-gal-standards/PTC-SPEC.md` §1.2 carries the normative
  wording; claiming conformance to the mTLS clause would be false.

## 7. Content model — replayable index, layered disclosure

The provenance chain propagates as a **contentless index**; content is *layered*, never bundled:

1. **Immediate payload** (e.g. research's reasoning) — delivered in the EventTrigger payload; available
   at approval now. (The contentless discipline only ever governed audit/provenance *metadata*.)
2. **Provenance index** — the chain: foreign keys + labels + digests, PII-safe, propagates everywhere.
3. **Upstream source content** — fetched on drill-down from the owning broker's records via the chain
   ref (`event_id` + source), access-controlled, using **SD-JWT-VC selective disclosure**: least-
   disclosure by default, each reveal cryptographically bound and itself an audited access event.

Replay the *index* to trace; resolve *content* in layers. Full explainability, PII-safe wire/audit.

## 8. Open problems (banked — this is where real bugs live)

- **Declassification/endorsement** is the classic IFC hard problem: *when* may tainted data influence a
  privileged action? That decision is `trusted_read_sources` — treat every exemption as an audited
  declassification, the most-scrutinized knob we ship.
- **Propagation-through-transform is not solved by signing.** A signature proves *who signed*, not that
  taint was *correctly propagated* through a model. The `stamp_outbound` lineage-collapse (a fresh
  origination compresses connector-origin sources into one taint bit) is the concrete instance;
  carrying the turn's ingested sources into the outbound chain is the bounded fix.
- **The mesh is only as trustworthy as its nodes' brokers.** Cross-broker taint is *correct* only if
  the sender also runs a PTC-enforcing broker. safe-agents↔safe-agents is trustworthy;
  safe-agents↔arbitrary-A2A-agent is not. PTC's value compounds when both ends implement it — like TLS.

## 9. The rung tracks the provenance maturity (worked rule)

A capability's autonomy rung is bounded by what the mesh can currently *prove* about its premise:

| Provenance maturity | Enables |
|---|---|
| taint **bit** propagates (today) | correct gating *if you trust the sender* → paper trades autonomous-ish |
| full **lineage** in the chain (§8 fix) | receiver derives its own taint; human sees origin → live trade *with approval* |
| **signed** lineage (#170 / §6) | receiver can't be lied to → autonomous cross-mesh high-blast |

So the live-brokerage `trade.place` rung stays in-loop until receiver-side verification is ON in
production. The other two conditions this section used to carry are now met: the grant-lifecycle
machinery exists and is proven (sa#4 **closed 2026-07-15** with the GAL terminal proof — see
`docs/GAL.md` §11/§12; the §9 ceiling is enforced in code, both acting rungs require
`signed-lineage`), and sa#161's campaign watchdog is live-drilled hardening (closed 2026-07-18).
Not a limitation, the correct expression of what PTC can currently prove.

**Signing moves the ceiling, not the clock.** Tier 3 makes high-blast action *eligible* by lifting
the provenance ceiling, but the response-time bound is independent — no provenance maturity shortens
the window between a high-blast act and its detection, so GAL's always-human rule for high-blast
still holds (signing raises the ceiling; it does not place a human inside the window).
`ptc-gal-standards/PTC-SPEC.md` §7 and `ptc-gal-standards/GAL-SPEC.md` §6.4.4 are normative.

## 10. Conformance & what already exists

Most of PTC is specified already as contract-tier docs with conformance suites:
`channels/SCHEMAS.md`, `channels/TRUST-MAPPING.md`, `channels/SCREENING.md`, `broker/TAINT.md`
(Biba adopted, §4), `docs/deterministic-gate.md`, and — landed since this outline was first
drafted — `channels/SIGNING.md` (the §6 envelope, S-clauses), `channels/PUBLISH.md` (sender-side
stamping), `channels/WATCHDOG.md` (W1–W8, campaign correlation over signed evidence),
`broker/MCP-HOST.md` (M1–M21, the PTC posture applied to MCP discovery), and
`broker/CONNECTOR-AUTH.md`. The remaining work is to **unify them under one normative PTC spec
with the cross-cutting conformance suite** (#178).

## 11. Roadmap (decomposition — epic #167)

**Status 2026-07-21: every build phase is landed; what remains open on #167 is spec-tier.**

Foundations (name-agnostic) — **all landed**:
1. **#168** ✅ — `stamp_outbound` carries ingested sources (§8, the lineage-collapse fix).
2. **#169** ✅ — Biba adopted in `broker/TAINT.md` + sa#44 cross-ref (§4).
3. **#170/#181** ✅ — Layer A signing shape decided + built (v0.18.0; §6). Unblocked #161 (since closed).

Decoupling & connectors — **all landed**:
4. **#171** ✅ — manifest-owned ToolOp classifications (base names no op).
5. **#172/#149** ✅ — `peer.publish` as base connector; domain connectors consumer-owned (v0.17.0, in production).
6. **#173** ✅ — CredentialProvider auth strategies (closed catalog: static / OAuth-refresh / assumed-role).
7. **#174** ✅ — the broker as safe MCP host: two-key admission, signed tool set, drift quarantine
   (`broker/MCP-HOST.md`; buildout completed as epic #221, closed 2026-07-20 — stdio + streamable-HTTP,
   supervised lifecycle, snapshot/diff/bulk-re-vet ceremony tooling, proven against real third-party servers).
8. **#175** ✅ — per-capability IAM scoping (`assumed_role`; out-of-scope denied by IAM, not the broker).

Interaction, standards, consumer:
9. **#176** ✅ — human interaction as an owner-class channel source (Phase 5).
10. **#177** ✅ — **decided 2026-07-20: keep the custom pure PDP** (§5; differential spike over all
    73,728 reachable inputs; recorded so it is not re-litigated).
11. **#179** ✅ — canonical-consumer pattern (`docs/canonical-consumer.md`).
12. **#178** — PTC normative spec + cross-cutting conformance + LF path (**open**; gated on naming
    clearance; the #177 differential corpus is retained as the PDP conformance-suite seed).
13. **#180** — cross-relay per-signer attribution via nested per-hop attestations (**open**; feeder
    into the normative spec — today signing is per-envelope, hops ride as lineage).

## 12. Relationships

- `docs/references/trust-context-landscape.md` — the survey PTC is built against (cite for every
  adopted primitive).
- `docs/deterministic-gate.md` — PTC's Layer-B gate (sa#44).
- `broker/TAINT.md`, `channels/SCHEMAS.md`, `channels/TRUST-MAPPING.md`, `channels/SCREENING.md` — the
  contract-tier pieces PTC unifies.
- `docs/scaling-and-mesh.md` — the mesh doctrine (edge free, mesh not); §8's "only as trustworthy as
  its nodes" extends it.
- `docs/canonical-consumer.md` — the *consumer* pattern; PTC is the *protocol* it rides (§9's rung
  rule is authored there as the consumer-facing knob).
- `docs/friction-doctrine.md`, `docs/contract-vs-reference.md` — the floor-vs-knob and packaging lenses.
