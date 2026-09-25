# docs — cross-cutting documentation

What spans the whole platform: the doctrine that decides what gets built and what may be claimed
about it, the runbooks for operating it, the guides for consuming it, and the external material
the design draws on. Per-component documentation lives with the component
(`broker/README.md`, `audit/README.md`, and so on).

The specifications themselves are not here. They are maintained in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards) and licensed separately.
`PTC.md` and `GAL.md` in this directory are the earlier design spines those specifications grew
from, kept for the reasoning they carry.

## Start here

- `evaluating.md`: the evaluator's guide, picking up where the root `README.md`'s laptop setup
  stops: which path to take (laptop, AWS, OpenShift) against what each can show, the laptop tour
  in order (suite, conformance statement, the gateway demo, your own search key and the taint
  hold, connecting a real MCP client, the embedded agent), an AWS tour from a CDK-bootstrapped
  account to one allowed and one refused call decided on Fargate, and the OpenShift path.
- `lf-reference-implementation.md`: the claim and where to attack it (listed again below with
  the other outward-facing documents).

## What is in this repository

| Path | What it holds |
|---|---|
| `safe_agents/broker/` | The broker: the gate, the grant store, the ceremonies, the audit tape, the MCP host |
| `safe_agents/channels/` | The inbound airlock: validate, verify, trust-map, deduplicate, screen, stamp |
| `safe_agents/arms/` | Substrate arms, including the OpenShift deployment |
| `safe_agents/` (rest) | Contract types, connectors, watcher, evidence, pipeline |
| `broker/` `channels/` `core/` `audit/` `registry/` | The normative contract documents |
| `docs/` | Doctrine, threat model, posture ladder, and the operator runbooks |
| `infra/` | AWS CDK for a deployed environment. See `cdk-context-contract.md` first |
| `examples/` | Worked consumers, including a drill against a real third-party MCP server |

Start with `lf-notional-architecture.md` for how the pieces fit, and the root `ARCHITECTURE.md`
for the technical floor.

## The auto-agents corpus

This codebase is the engineering encoding of a design developed in a separate corpus,
`auto-agents`, which is a private repository. The entries below are lineage rather than links:
they record where a decision was reasoned out, and they are cited the same way throughout this
tree. The public statement of the reasoning is the specifications themselves. Key corpus
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

- `environments.md` — environment ownership rules: `development` is the platform's
  ephemeral iteration floor; `production` is durable and belongs to consumers, so coordinate
  before touching it once one depends on it.
- `consumer-image-contract.md` — the contract between the Fargate arm's task definition and
  any consumer-built agent image: injected env, entrypoint obligations, run record,
  packaging. The smoke image is the reference implementation; this doc is normative.
- `model-egress.md` — how an autonomous agent reaches its model (`api.anthropic.com`) while
  everything else stays broker-only: the netns + broker-proxy confinement design. Specifies the
  mechanic `ARCHITECTURE.md` invariant #2 names but leaves open. Read before building agent-arm
  confinement or the broker's model-proxy surface.
- `turn-identity.md` — why the broker owns the turn boundary: the fork between a
  broker-held session and a harness-authenticated turn header, why single-principal runtimes take
  the former, and how decoupling turn identity from `idempotency_key` makes taint
  self-ingestion hold across `/call` (an agent cannot launder taint by declaring a fresh turn).
- `friction-doctrine.md` — the gate-versus-log rule, and the first of the doctrine lenses: only
  lethal-trifecta flows are structurally gated, and every other bound is an envelope knob that
  ships off. Includes the availability and forced-abstention analysis. Read before adding any new
  broker control.
- `contract-vs-reference.md` — the packaging doctrine (2026-07-08): for each part of an agent
  harness, whether the base ships a floor invariant, a contract + conformance tests, a reference
  implementation, or nothing (product/consumer layer). Companion axis to `friction-doctrine.md`;
  and the tier map the SDK boundary reads from.
- `config-provenance.md` — the third doctrine lens (sibling to `friction-doctrine.md` and
  `contract-vs-reference.md`): config stratifies by injection power — code-provenance (image-baked
  only) > store (ceremonied, integrity-protected) > deploy (topology) > secrets (leaves) — a Biba
  no-write-up lattice where "where config lives" is itself the enforcement mechanism; includes the
  which-layer decision test and the unified-config-store anti-pattern.
- `posture-ladder.md` — the honesty lens (2026-07-26, vocabulary ruled 2026-07-24), beside
  `friction-doctrine.md` and `contract-vs-reference.md`. Those decide what to build; this decides
  what you may *say* about what you built. Three postures by where the boundary is (a plain wrapper,
  same OS user · a wrapper plus a sandbox, agent inside and gateway outside · the cloud floor with
  IAM), the rule that every posture claim names its posture or is an overclaim, the per-harness
  wrap-durability table with its coverage-artifact caveat, and the cheap half of the wrap story
  (the agent asks, the broker performs). Executable form: a wrapper's `posture` command.
- `self-application.md` — the scope lens, written for the coding agents that read this repo as
  often as people do: these controls govern a running agent's authority at run time, and are not a
  development methodology. Carries the symptom list, the two cases where transferring a control to
  the development loop is legitimate (credentials, and letting someone other than the author attack
  a claim), the schema-freeze defect the failure actually cost us, and the block a consuming repo
  pastes into its own agent instructions. Root `WARNING-TO-AI-AGENTS.md` and `CLAUDE.md` are the
  loud pointers at it.
- `canonical-consumer.md` — the reusable *consumer* pattern: the invariant
  five-seam anatomy every consumer has (envelope · ToolOp classifications · connector classes · auth
  strategy + IAM · image + grants), the base/agent line ("Unix ships what a database needs, not a
  database"), capability-vs-provider, classification-travels-with-the-agent, and the rung-tracks-
  provenance rule. The *why-shape* companion to `adopting-safe-agents.md`'s *how-to*; direct input to
  the normative specifications.
- `threat-model.md` — the top-level referent for "our threat model". The four adversaries
  (A1 compromised mind, A2 hostile content on a legitimate channel, A3 the vendor behind a remote
  tool, A4 an attacker with store write access) and what is explicitly out of scope; the trust
  boundaries; the register of base-owned untrusted-input channels with per-row entry points,
  defenses, and pinning tests; the limit statements (including the model-channel carve-out);
  and the row contract a consumer's own register fills (hybrid scope, ruling 2026-08-04).
- `deterministic-gate.md` — the cross-cutting invariant: the model may only SURFACE a
  concern; the gate is deterministic — `decide(call, facts)` is pure (no I/O, no LLM), taint is
  source-based and non-strippable, and the one model-judged gate (channels screen 7) can only refuse,
  never bless. Floor tier; spans broker + channels + memory (filter-on-write deferred). The
  contract a consumer repo cites for "the gate can't be argued past."
- `scaling-and-mesh.md` — what multiplies from one agent to fifty (shared mechanism vs. per-agent
  config/namespaces vs. the per-agent inbound queue+drain), the isolated-vs-multiplexed drain
  topology choice, and which parts of an A2A mesh come free (the bilateral edge) versus the
  named mesh backlog (multi-hop provenance authenticity, N×N trust-map governance, cross-node
  cascade, discovery). Extends `ARCHITECTURE.md` §"Compositional opacity".
- `tce-signing-shape.md` — the design note (decide, don't build): sign the outbound
  provenance chain with a **DSSE / in-toto** statement keyed to a broker workload identity, reserve
  **SD-JWT-VC** for the `PTC.md` §7 content drill-down, optional Rekor anchor. Settles the Phase-4
  signing shape and unblocks the campaign watchdog. Companion to `PTC.md` §6.
- `PTC.md` — the design spine the PTC specification grew from: the signed
  trust-context envelope (sender-class + provenance chain + taint on a Biba lattice) consumed by
  the deterministic gate at every boundary; adopt-the-standard strategy, conformance inventory,
  and the rung-tracks-provenance rule (§9).
- `GAL.md` — the design spine the GAL specification grew from, PTC's sibling:
  autonomy level as signed, evidence-gated, automatically-demotable grant state — the
  deterministic promotion gate + maker-checker ceremony, the evidence contracts, and the PTC
  join (PTC §9 as the normative rung ceiling). `broker/grant-lifecycle.md` stays normative for
  the state machine; this doc is the protocol spine over it.
- `subagent-identity.md` — companion doctrine to `turn-identity.md`: the boxes are trust zones,
  not processes, so in-zone sub-agents need no broker/airlock of their own and share the zone's
  principal non-negotiably (one turn, one taint state, one budget pool); enforced downscoping
  means a new zone + principal (same broker service), and spawning that leaves the zone or the
  present is brokered egress whose spawned context inherits taint.
- `authority-change-safety.md` — open design analysis of changing an agent's authority while it
  runs. Argues the risk tracks safe-default polarity rather than the direction of the change, with
  revocation as the unguarded dangerous case. Carries the aviation and driving-automation prior
  art. Framing for a decision not yet taken, so nothing in it is built.
- `egress-drift.md` — what counts as egress-policy drift across both the security-group and the
  network-namespace layer, a severity per drift category, and the alarm routing each severity
  earns. The auditor that would implement it is out of scope here.
- `network-security-layer.md` — the topological half of the egress invariant: the three subnet
  tiers, the interface endpoints and security-group shape, the CDK traps that each cost real
  debugging, the cost profile that made it ship off by default, and exactly what open mode gives
  up.
- `sci-fi-failures.md` — **explanatory, not normative.** Nineteen fictional AI failures mapped to the
  control that changes the outcome, each carrying an honest status (shipped / knob shipping off /
  roadmap / not solved). Useful for explaining what a control is *for* to someone who has not read
  the specs, and useful internally because the entries that come back ROADMAP or NOT SOLVED are the
  real gaps: obligation, authority magnitude bounds, memory taint, and the fact that nothing
  independent has attacked any of it.
- `sci-fi-primer.md` — the **outward-facing** companion, written for someone reading the PTC/GAL
  proposals with no background at all. Same stories, no clause IDs, paragraphs labelled PTC or GAL,
  framed as what the architecture makes possible rather than as compliance claims. Carries the
  aviation authority-envelope framing (see `authority-change-safety.md`) and keeps the four gaps
  visible. **Published 2026-08-06** at the root of `wjatx/ptc-gal-standards`, alongside
  `lf-standards-brief.md`; this file stays canonical, so edit here and re-copy.

## The proposals, for an outside reader

- `lf-notional-architecture.md` — the descriptive shape of a system implementing the two
  specifications: each component and what it holds, the trust-envelope and grant objects, the
  ordered path of a single tool call, the inbound airlock, the two ceremonies, and the stated
  non-goals. Start here for how the pieces fit.
- `lf-reference-implementation.md` — what this implementation supports and where its evidence
  stops: generated conformance counts, what is demonstrated on live infrastructure against what is
  asserted from tests, and the named limits including the unkeyed audit chain. Written to be
  probed, and the first thing to read before attacking the claim.
- `lf-standards-brief.md` — the short external brief: the controls-engineering framing, which
  existing standards are adopted, the two seams nobody standardizes, and how the two proposals
  fill them. The summary to hand an outside reviewer.

## Consumer guides

- `adopting-safe-agents.md` — the refactor guide for an existing agent joining the platform: strip
  its connector credentials, route every side effect through the broker, write a manifest and an
  envelope, choose a substrate arm. Open it when onboarding a new consuming agent.
- `consuming-the-sdk.md` — install-and-invoke mechanics for a separate repo depending on this one
  as a package: pinning the distribution, what the import surface exposes and deliberately
  withholds, repo layout, and driving the pipeline against your own manifest.

## Runbooks

- `cdk-context-contract.md` — the twenty-five CDK context keys a deploy can take, sorted by
  whether omitting one fails loudly, degrades silently, or lands a harmless default. Twelve
  degrade silently, which is the reason to read this before any deploy or redeploy.
- `broker-service-bringup.md` — ordered bringup of the persistent broker service from a torn-down
  floor: compute at zero tasks first, build and push the image, seed envelope then grants then
  secrets, then scale up. Plus the gotchas that cost a debug cycle each.
- `channels-airlock-bringup.md` — the two-phase deploy of the inbound airlock: substrate before
  function, the consumer image layer, the webhook secret seed, the post-deploy binding assertion,
  and the optional classifier screen. Ends with the airlock's deliberate operational boundaries.
- `channels-drain-bringup.md` — bringup for the drain workers consuming the airlock's accepted
  queue: image layering, per-consumer envelope, grant and connector-secret seeding, tag-gated
  deploys, and why each drain needs its own queue and audit prefix.
- `operator-identities.md` — the least-privilege ceremony roles: which command runs under which
  identity, the assume-with-guard idiom, why every identity deploy must re-pass all five trust
  contexts or the gated roles are dropped, and the checklist for adding a role.
- `grant-canonicalization-runbook.md` — an unexecuted migration plan for normalizing grant
  serialization to compact canonical bytes. Explains why pre-change rows read clean rather than
  quarantining, and gives the archive, delete and re-mint sequence with its identity constraints.

## References (design inputs)

`references/` holds external material the design is built on: standards, primitives and
published guidance, read for what they specify rather than for what they claim.

- `references/five-eyes-agentic-guidance.md` — the six-agency joint guidance *Careful adoption of
  agentic AI services* (2026-05-01), mapped clause-by-clause onto what we implement, plus the gap
  analysis in both directions: where we are weaker than the guidance (FE-1…FE-9) and where the
  guidance is silent on something we have a mechanism and a live proof for (the contribution list).
  Also records that the widely-cited "82% shadow agents" / "68% cannot distinguish agent from user"
  statistics are **not** from the guidance — they are vendor-sponsored CSA surveys.
- `references/role-confusion-icml.md` — a reading of the ICML role-confusion paper, which measures
  that models infer a span's role from style rather than from tags, mapped claim by claim onto the
  deterministic gate and the taint model. Cite it for the premise, never for the remedy.
- `references/trust-context-landscape.md` — the trust-context prior art PTC is positioned against.

## Known gotchas

- `rhel-gotchas.md` — RHEL 9 and systemd traps found in live deploys: SELinux refusing execs
  under `/home` and mislabeled unit files, missing PATH entries, cgroup delegation ordering,
  rootless podman linger, and a shell exit-code leak. Overlaps `rhel-host-gotchas.md`.
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
