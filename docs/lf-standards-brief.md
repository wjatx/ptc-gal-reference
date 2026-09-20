# PTC & GAL — standards brief for the Linux Foundation discussion

> One/two-pager for the LF agent-standards conversation: what we're building, which existing
> standards we adopt, why two seams remain unstandardized, and how these proposals fill them.
> Names are final (2026-07-24); the normative spec drafts are [`PTC-SPEC.md`](https://github.com/wjatx/ptc-gal-standards/blob/main/PTC-SPEC.md) (`0.2.5-draft`)
> and [`GAL-SPEC.md`](https://github.com/wjatx/ptc-gal-standards/blob/main/GAL-SPEC.md) (`0.2.6-draft`) — they revise independently and their versions differ.
> Internal spines: `docs/PTC.md`, `docs/GAL.md`.

## What we're building

This is a **controls-engineering project** for agentic systems — not another agent framework or
harness. You bring your own harness (the model, the loop, the prompts, the orchestration);
the controls secure it from outside, in ways the harness probably cannot secure itself. A
harness's own guardrails run *inside* the thing being guarded — a system prompt is advice to the
component under attack, and anything the model can be talked out of is not a control. The
controls we are designing are enforced by separate infrastructure holding separate identity,
around one architectural commitment: **the agent holds no credentials, and its only egress is a
deterministic tool broker.** Every tool call crosses a broker that decides per call — allow /
deny / transform / require-approval / abstain — from signed policy state, and writes a
tamper-evident, hash-chained audit under a separate identity the agent cannot reach. A fully
compromised agent can still only *ask*.

That last sentence is the thesis and the thing to attack. It rests on three separate mechanisms —
the agent holding no credentials, the broker being its only egress, and the enforcement point being
unable to grant itself authority — and each is worth attacking separately, since an attack composing
them is worth more to us than one defeating any single one.

Note that the third is enforced by a platform boundary (an IAM deny, a read-only mount) rather than
by broker code, because code cannot meaningfully deny itself. That makes it a property of a
**deployment**, so every claim about it must name a posture: a single-machine run has no boundary
for it to sit on, and correspondingly little for it to buy. We state the postures and what each holds in
[`docs/posture-ladder.md`](https://github.com/wjatx/ptc-gal-reference/blob/main/docs/posture-ladder.md) rather than asserting the property flatly.

**[ptc-gal-reference](https://github.com/wjatx/ptc-gal-reference) is the reference implementation that
demonstrates these controls.** The two proposals below are the control layers extracted from that
build, and neither is a paper design.

**The claim is about the code, not about infrastructure we operate.** Clone the implementation,
clone these specifications into a `spec/` directory at its root, and run its test suite with no
cloud account and no credential: the tests that compare specification text against the shipped
schemas then execute rather than skip, and its continuous integration does exactly that on every
commit. That is the whole of what is offered for checking, and it is deliberately the part made
easiest to check.

Two limits on that claim, stated here because they are the first things worth probing and because
[`docs/lf-reference-implementation.md`](https://github.com/wjatx/ptc-gal-reference/blob/main/docs/lf-reference-implementation.md) states them at length:

- **The conformance suites do not trace to the specifications.** The grant-lifecycle suite certifies
  an internal vocabulary and contains no `GAL-` clause reference at all; across the whole test tree a
  single clause id appears in a single test. So a green suite is evidence about our vocabulary, not
  about the numbered clauses an independent implementer reads. Bidirectional traceability is
  specified and unbuilt.
- **22 of 81 conformance clauses are not supported** — 27%, not a handful. Each is individually
  marked in the draft with the requirement that is missing and an issue tracking it, because a spec
  clause is not a shipped control. The count is generated from the markers, never hand-written
  (`python3 -m safe_agents.contract.spec_clauses --summary`), so a reader can regenerate it rather
  than take it on trust. No clause has been outgrown by the implementation.

## What we adopt

Our working rule is **adopt the standard where one exists; build only the seam**:

- **Connectivity:** MCP (agent↔tool) and A2A (agent↔agent). We ride them — MCP `_meta`, A2A
  extensions, or native channels — and do not compete with them.
- **Signing & attestation:** DSSE envelopes over in-toto-style statements, Ed25519 keys; optional
  Sigstore/Rekor-style transparency anchoring; SD-JWT-VC reserved for selective content
  disclosure on audit drill-down.
- **Identity:** SPIFFE/WIMSE workload identity as the signing-key substrate (DID as fallback).
- **Integrity model:** the Biba lattice — low-integrity data may not influence a higher-integrity
  action without an explicit, audited endorsement.
- **Policy languages:** Cedar and OPA/Rego were evaluated seriously, not dismissed — a
  differential spike ran our 14-rule reference gate over all 73,728 reachable inputs in both.
  Both were declined with a published record: Cedar cannot checkably express first-match ordering
  or value-producing decisions (`transform`); Rego reproduces the gate exactly but forfeits the
  formal-analyzability motivation while adding an external binary to a path whose property is
  purity. We cite this because the adoption posture is evidence-based in both directions.
- **Conceptual ancestry for autonomy:** Sheridan–Verplanck and SAE J3016 levels-of-autonomy
  vocabulary; FDA's PCCP (a regulator pre-authorizing change inside a declared envelope); ODD
  (capability claims bounded by a declared operating domain).

## The gap — two seams nobody standardizes

**1. Trust does not travel.** MCP and A2A move calls and data but carry no trust model — no
provenance, no taint, no sender class. MCP tool-poisoning and A2A impersonation are open problems
precisely because of that. The adjacent standards don't close it: DSSE/in-toto prove *who signed*
something, not how trustworthy it is for a given action; Cedar/OPA evaluate policy, but nothing
standardizes the trust context they evaluate *over*. The seam — a signed trust-context object,
carried with the data across every agent and tool boundary and consumed by a deterministic gate —
is unowned. Our landscape survey found no general standard here; the closest precedent (AP2) is
payments-only.

**2. Autonomy is a label, not state.** Forty years of levels-of-autonomy work produced
descriptive taxonomies — a label on a system, not stored state an enforcement point reads per
call. FDA PCCP is the strongest precedent for pre-authorized change, but it is paperwork: no
runtime object, no automatic rollback when the evidence sours. Nothing in the current agent
stack makes an agent's authority something it must *earn* through measured evidence and *loses*
automatically — enforced by infrastructure the agent cannot write past.

## How PTC and GAL fill it

**PTC (Provenance & Trust Context)** is the trust seam: a signed envelope — sender class
(owner / peer-agent / external, a floor never a grant) + an append-only, non-strippable provenance
chain + taint labels on the Biba lattice — riding orthogonally to transport and consumed by a
deterministic, model-free gate at every boundary. Positioning line: *MCP is how agents reach
tools; A2A is how agents reach agents; PTC is how trust travels across both.* Implemented today:
broker-side taint self-ingestion (an untrusted read taints the turn; a later external write
escalates to human approval); Ed25519/DSSE chain signing with receiver-side verification; an MCP
host contract that treats tool discovery as untrusted input (a tool is callable only via two-key
admission over a signed definition set, and a changed description — the injection surface —
quarantines the tool until re-vetted); and a campaign watchdog whose live drill turned six forged
events claiming a real signer's key into cryptographic attribution that placed the claimed signer
nowhere in the forgery.

**GAL (Grant & Autonomy Lifecycle)** is the autonomy seam: authority is a per-(principal,
action-class) grant whose level (in-loop / on-loop / out-of-loop, with "no grant" as the floor)
is stored, signed state — moved **up** only by a maker≠checker ceremony licensed by a
deterministic predicate over measured evidence (no model in the licensing path; high-blast
classes always human-ratified), moved **down** automatically by four deterministic demotion
triggers (stale confidence, corroboration failure, budget breach, owner-flagged false action),
and enforced by the broker per call. Every state change is a signed, append-only ledger record;
an independent audit re-verifies the whole ledger in CI. Implemented and proven end-to-end: a
real principal was promoted on real approval evidence, demoted by an induced trigger, re-climbed,
and then *exercised* — every leg under a distinct least-privilege identity, all four demotion
triggers fired live.

**The join** is the rule that makes the pair more than the parts: *a capability's autonomy rung
is capped by what the mesh can currently prove about its inputs.* A bare taint bit permits at
most trusted-sender autonomy; unsigned lineage means approval-gated; only signed, receiver-
verified lineage makes high-blast autonomous action eligible. PTC supplies the proof; GAL moves
the state; the ceiling is enforced in the promotion predicate, not left to reviewer judgment.

Both proposals compose with — rather than fork — the ecosystem above, and both come with the
thing a standards process needs most: a running reference implementation, conformance suites,
and the scars of live adversarial drills.
