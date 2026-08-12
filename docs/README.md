# docs — cross-cutting documentation

> **Status: design pending.** This directory is a scaffold for platform-wide docs that do not
> belong to any single subdir.

Per-subdir documentation lives with the subdir (`broker/README.md`, `audit/README.md`, etc.).
This directory holds what spans the whole platform: design documents that cut across components,
runbooks for operating the platform, and the index into the `auto-agents` design corpus that the
platform encodes.

## The auto-agents corpus

The safe-agents codebase is the engineering encoding of a design developed in the `auto-agents`
corpus. The corpus is the authoritative *why*; this repo is the *what* and *how*. Key corpus
documents:

- `base-platform-brief.md` — the platform requirements brief: what the base must provide,
  what belongs in per-agent repos, and the initial epic breakdown.
- `PILLARS.md` — the six safety pillars (Deterministic Enforcement, Least Capability, External
  Audit, Reversibility, Bounded Human Governance, Adversarial Robustness) plus the cross-cuts
  (Proportionality, Non-generalization). Every architectural decision traces back to at least one.
- `ontology.md` — shared vocabulary. When `ARCHITECTURE.md` uses a term, the precise definition
  is here.
- `tool-broker-sketch.md` — the broker design sketch: trust zones, component model, the five
  verbs, taint, audit, the minimum-viable tier table.
- `book/ch16` — the grant lifecycle and autonomy-level-as-state.
- `book/ch36` — the in-loop / on-loop / out-of-loop taxonomy (canonical source of those terms).
- `book/ch42`, `ch46` — safe-default polarity: why abstain vs positive-safe-action is per-agent
  and must never be baked into the base.
- `book/ch48` — the closed learning loop: outcomes → drift → recalibration.
- `book/ch50` — the red-team posture: assume the model itself is the adversary.

## Pre-deployment checklist

The platform's pre-deployment checklist lives in `ARCHITECTURE.md` §"Pre-deployment checklist".
It is the canonical checklist — not duplicated here. Runbooks in this directory should point to
it rather than copy it.

## Design documents

- `environments.md` — environment ownership rules (sa#111): `development` is the platform's
  ephemeral iteration floor; `production` is durable and claimed by a real consumer agent —
  coordinate before touching it.
- `consumer-image-contract.md` — the contract between the Fargate arm's task definition and
  any consumer-built agent image (sa#116): injected env, entrypoint obligations, run record,
  packaging. The smoke image is the reference implementation; this doc is normative.
- `model-egress.md` — how an autonomous agent reaches its model (`api.anthropic.com`) while
  everything else stays broker-only: the netns + broker-proxy confinement design. Specifies the
  mechanic `ARCHITECTURE.md` invariant #2 names but leaves open. Read before building agent-arm
  confinement (sa#35) or the broker's model-proxy surface (sa#12).
- `turn-identity.md` — why the broker owns the turn boundary (sa#136): the fork between a
  broker-held session and a harness-authenticated turn header, why single-principal runtimes take
  the former, and how decoupling turn identity from `idempotency_key` makes sa#134's taint
  self-ingestion hold across `/call` (an agent cannot launder taint by declaring a fresh turn).
- `paperclip-contribution.md` — assessment (2026-07-08) of Paperclip (paperclipai/paperclip) as
  a future contribution/integration target: the gap map vs our schemas, why a broker layer is
  not a plugin there (their platform-module registries `registerSecretProvider()` /
  `registerAgentAdapter()` are the real seam), their conversation-first contribution norms, and
  the sequencing (SDK #106 first, run-a-consumer-on-Paperclip before any upstream PR).
- `contract-vs-reference.md` — the packaging doctrine (2026-07-08): for each part of an agent
  harness, whether the base ships a floor invariant, a contract + conformance tests, a reference
  implementation, or nothing (product/consumer layer). Companion axis to `friction-doctrine.md`;
  the default lens for scoping roadmap issues, and the tier map the SDK boundary (sa#106) reads
  from. First applied in `memory/README.md` §"Contract vs reference".
- `config-provenance.md` — the third doctrine lens (#186, sibling to `friction-doctrine.md` and
  `contract-vs-reference.md`): config stratifies by injection power — code-provenance (image-baked
  only) > store (ceremonied, integrity-protected) > deploy (topology) > secrets (leaves) — a Biba
  no-write-up lattice where "where config lives" is itself the enforcement mechanism; includes the
  which-layer decision test and the unified-config-store anti-pattern.
- `posture-ladder.md` — the honesty lens (2026-07-26, vocabulary ruled 2026-07-24), beside
  `friction-doctrine.md` and `contract-vs-reference.md`. Those decide what to build; this decides
  what you may *say* about what you built. Three rungs by where the boundary is (a plain wrapper,
  same OS user · a wrapper plus a sandbox, agent inside and gateway outside · the cloud floor with
  IAM), the rule that every posture claim names its rung or is an overclaim, the per-harness
  wrap-durability table with its coverage-artifact caveat, and #165's cheap half (the agent asks,
  the broker performs). Executable form: a wrapper's `posture` command.
- `canonical-consumer.md` — the reusable *consumer* pattern (sa#179, PTC Phase 6): the invariant
  five-seam anatomy every consumer has (envelope · ToolOp classifications · connector classes · auth
  strategy + IAM · image + grants), the base/agent line ("Unix ships what a database needs, not a
  database"), capability-vs-provider, classification-travels-with-the-agent, and the rung-tracks-
  provenance rule. The *why-shape* companion to `adopting-safe-agents.md`'s *how-to*; direct input to
  the Phase 7 normative spec.
- **The lockfile projection** (contract frozen 2026-07-25) — the format a wrapper commits to a
  user's repo, the one wrapper artifact that becomes public API: read by teammates, diffed in
  review. Load-bearing distinction: the lock is a signed, human-reviewable **projection**, never
  the runtime admission authority (it lives in a directory the wrapped agent can write, and the
  harness's protected-path list cannot be extended to cover it). Reuses `compute_tool_def_hash` as
  the one drift primitive; pins definitions verbatim so verify-against-lock can render the M5 diff
  rather than only report "mismatch".
- `threat-model.md`: the top-level referent for "our threat model" (#268). The four adversaries
  (A1 compromised mind, A2 hostile content on a legitimate channel, A3 the vendor behind a remote
  tool, A4 an attacker with store write access) and what is explicitly out of scope; the trust
  boundaries; the register of base-owned untrusted-input channels with per-row entry points,
  defenses, and pinning tests; the limit statements (including the #125 model-channel carve-out);
  and the row contract a consumer's own register fills (hybrid scope, ruling 2026-08-04).
- `deterministic-gate.md` — the cross-cutting invariant (sa#44): the model may only SURFACE a
  concern; the gate is deterministic — `decide(call, facts)` is pure (no I/O, no LLM), taint is
  source-based and non-strippable, and the one model-judged gate (channels screen 7) can only refuse,
  never bless. Floor tier; spans broker + channels + memory (`#75` filter-on-write deferred). The
  contract a consumer repo cites for "the gate can't be argued past."
- `scaling-and-mesh.md` — what multiplies from one agent to fifty (shared mechanism vs. per-agent
  config/namespaces vs. the per-agent inbound queue+drain), the isolated-vs-multiplexed drain
  topology choice (sa#82), and which parts of an A2A mesh come free (the bilateral edge) versus the
  named mesh backlog (multi-hop provenance authenticity, N×N trust-map governance, cross-node
  cascade, discovery — sa#161/sa#82). Extends `ARCHITECTURE.md` §"Compositional opacity".
- `tce-signing-shape.md` — the #170 design note (decide, don't build): sign the outbound
  provenance chain with a **DSSE / in-toto** statement keyed to a broker workload identity, reserve
  **SD-JWT-VC** for the `PTC.md` §7 content drill-down, optional Rekor anchor. Settles the Phase-4
  signing shape and unblocks the campaign watchdog (sa#161). Companion to `PTC.md` §6.
- `PTC.md` — the spine spec for the trust layer (standards candidate #1, epic #167): the signed
  trust-context envelope (sender-class + provenance chain + taint on a Biba lattice) consumed by
  the deterministic gate at every boundary; adopt-the-standard strategy, conformance inventory,
  and the rung-tracks-provenance rule (§9).
- `GAL.md` — the spine spec for the autonomy layer (standards candidate #2, #185; PTC's sibling):
  autonomy level as signed, evidence-gated, automatically-demotable grant state — the
  deterministic promotion gate + maker-checker ceremony, the #184 evidence contracts, and the PTC
  join (PTC §9 as the normative rung ceiling). `broker/grant-lifecycle.md` stays normative for
  the state machine; this doc is the protocol spine over it.
- `subagent-identity.md` — companion doctrine to `turn-identity.md`: the boxes are trust zones,
  not processes, so in-zone sub-agents need no broker/airlock of their own and share the zone's
  principal non-negotiably (one turn, one taint state, one budget pool); enforced downscoping
  means a new zone + principal (same broker service), and spawning that leaves the zone or the
  present is brokered egress whose spawned context inherits taint.
- `sci-fi-failures.md` — **explanatory, not normative.** Nineteen fictional AI failures mapped to the
  control that changes the outcome, each carrying an honest status (shipped / knob shipping off /
  roadmap / not solved). Useful for explaining what a control is *for* to someone who has not read
  the specs, and useful internally because the entries that come back ROADMAP or NOT SOLVED are the
  real gaps: obligation (#344), authority magnitude bounds (#318), memory taint (#3/#75), and the
  fact that nothing independent has attacked any of it (#320).
- `sci-fi-primer.md` — the **outward-facing** companion, written for someone reading the PTC/GAL
  proposals with no background at all. Same stories, no clause IDs, paragraphs labelled PTC or GAL,
  framed as what the architecture makes possible rather than as compliance claims. Carries the
  aviation authority-envelope framing (see `authority-change-safety.md`) and keeps the four gaps
  visible. **Published 2026-08-06** at the root of `wjatx/ptc-gal-standards`, alongside
  `lf-standards-brief.md`; this file stays canonical, so edit here and re-copy. Keep
  `sci-fi-failures.md` internal.

## References (design inputs)

`references/` holds external material we **design from** — standards, primitives and published
guidance — as distinct from `research/`, which holds market awareness under the firewall rule.

- `references/five-eyes-agentic-guidance.md` — the six-agency joint guidance *Careful adoption of
  agentic AI services* (2026-05-01), mapped clause-by-clause onto what we implement, plus the gap
  analysis in both directions: where we are weaker than the guidance (FE-1…FE-9) and where the
  guidance is silent on something we have a mechanism and a live proof for (the contribution list).
  Also records that the widely-cited "82% shadow agents" / "68% cannot distinguish agent from user"
  statistics are **not** from the guidance — they are vendor-sponsored CSA surveys.
- `references/trust-context-landscape.md` — the trust-context prior art PTC is positioned against.
- `references/PACT-TCE-naming-brief.md` — the naming brief behind the PTC/TCE vocabulary.
- `references/harnesses/` — per-harness authority descriptors (the wrapper's harness catalog).

## Known gotchas

- `rhel-host-gotchas.md` — RHEL/EL host scars that bite any agent arm: the SELinux
  exec-from-`/home` (`203/EXEC`) rule for systemd units, and the `/usr/local/bin` service-user PATH
  gotcha. Read before standing up an EC2/Fargate arm.

## What belongs here (guidelines)

A document belongs here if it is platform-wide and architectural (not per-component), or if it
is a runbook for operating the platform as a whole (incident response, key rotation, environment
promotion). Component runbooks (how to redeploy the airlock, how to rotate a specific secret)
belong with the component.

If a document ends up cross-referencing more than two subdirs' internals, it probably belongs
here rather than in any one subdir.

## Relationships

- `ARCHITECTURE.md` (repo root) — the shared vocabulary and pre-deployment checklist; docs here
  extend it, do not duplicate it.
- Every subdir — design docs here cross-reference subdir READMEs as the detailed specs.
