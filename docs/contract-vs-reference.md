# Contract vs reference — what the base owes each part of the harness

> **Status: doctrine (2026-07-08).** Companion to `friction-doctrine.md` (which governs *gates vs
> logs*); this doc governs *packaging* — for each part of an agent harness, does the base ship the
> **rules**, an **implementation**, or nothing? It generalizes a split the repo already practices in
> its best places (`consumer-image-contract.md` is normative, the smoke image is its reference
> implementation; `RUNNER-CONTRACT.md` is the contract, the five arms are instantiations) and turns
> it into the default lens for scoping any roadmap issue.

## The four tiers

Every capability the platform touches lands in exactly one tier:

1. **Floor (invariant).** Present in every deployment, not opt-out-able. The test: *removing it
   breaks "a fully compromised agent can still only ask."* Examples: agent holds no connector
   credentials; only egress is the broker; audit written under a separate identity; taint is
   source-based and non-strippable. Per `friction-doctrine.md`, the floor is deliberately tiny.
2. **Contract (normative words + conformance tests).** Rules any implementation must obey. The base
   owns the vocabulary (a schema, an interface, a normative doc) **and the test suite that certifies
   an implementation** — the conformance tests are the contract's teeth; a contract without them is
   a suggestion. The test: *consumers will legitimately bring their own implementation of this part.*
3. **Reference implementation.** One honest, working instantiation the base ships — adoptable
   as-is, swappable by construction, always sitting *behind* the contract's seam. The test: *our
   instance choices show up here* (AWS service bindings, storage engines, a specific harness's
   lifecycle hooks). Reference code must pass the same conformance tests a third-party
   implementation would.
4. **Out of scope (product).** Differentiating quality — retrieval relevance, consolidation
   strategy, UX, hosting. Belongs to a consumer or a SaaS built *on* the base, never to the base.
   Pulling tier-4 features into the base because a future SaaS will want them is the sprawl failure
   mode this doc exists to prevent; the SaaS is a consumer.

Two standing rules interact with the tiers. The **safe-default polarity** is never in the base at
any tier — it is re-derived per agent. And the **broker is the one deliberate exception** to
"contract implies swappable": the seven base schemas are its contract, but the base ships *the* broker
rather than inviting alternatives, because the deterministic enforcement point is the trust anchor —
outsource it and the platform's claims are no longer the platform's to make.

## The sweep — harness parts by tier

| Harness part | Floor | Contract | Reference | Roadmap |
|---|---|---|---|---|
| **Capability mediation (broker)** | broker-only egress; per-call decisions; separate audit identity | the seven base schemas (`broker/SCHEMAS.md`); connector interface + injection seam | the broker service itself (deliberate exception, above); shipped connectors | #141 |
| **OS confinement / sandbox** | egress confined to broker at the network layer (runner contract) | the sandbox-provider seam: generate-policy / create / exec / teardown | netns + SG scripts (autonomous); OpenShell policy generator (interactive) | #86, #87, #95 |
| **Substrate / compute (arms)** | — | `core/RUNNER-CONTRACT.md`, machine-verifiable via the conformance harness | the five arms (`ec2`, `ec2-woken`, `fargate`, `local`, `rhel-openshell`) | #31, #143 |
| **Model access** | model channel named as an accepted-uninspected egress boundary | `docs/model-egress.md` (the confinement obligation) | per-arm netns + broker-proxy mechanics | #125 |
| **Identity & turns** | broker-owned turn boundary; zone = principal | `docs/turn-identity.md`, `docs/subagent-identity.md`; principal fields in the schemas | broker session mechanics (sa#136, landed) | — |
| **Grants & graduated autonomy** | grants gate every call; quarantine on hash mismatch | Grant + PromotionRecord schemas; rung state-machine semantics; actionClass derivation from ToolOp fields (no base catalog — #189) | promotion/demotion predicates; the seed→ceremony path | #53, #55, #57–#60, #123 |
| **Memory** | memory is a taint source; labels ride write → storage → read-back, non-strippably (`memory/TAINT.md`) | record schema; the three-op interface (resolve/search/write) + gate routing; DLP gate semantics; quarantine-not-delete; the memory-provider seam | OKF vault + loader; DynamoDB/pgvector stores; trace retention; async memory-builder | #3, #69, #71, #73, #75, #77, #79 |
| **Audit** | written broker-side under a separate identity | AuditRecord schema; completeness + retention standard | off-substrate chain verifier; digest sink | #26, #66, #67 |
| **Channels & airlock** | inbound content is untrusted until mapped | channel-adapter interface; trust-mapping framework; injection-screening standard | specific adapters (Telegram today); dispatch/routing | #43, #80, #81, #82 |
| **Event-driven work** | — | EventTrigger envelope schema; ephemeral-worker lifecycle contract; maker≠checker gate semantics | the event-driven example agents | #74, #76, #78 |
| **Observability / liveness** | loud failure over silent degradation | meta-alarm / page-semantics standard; loud-failure pattern library | GH Actions watcher (already being converted to an importable pattern) | #25, #29, #38, #145 |
| **Scaling** | budgets enforced broker-side | scale-trigger policy shape; queue semantics (once decided) | any concrete autoscaler wiring | #70, #72 |
| **Secrets** | agent holds no connector credentials | inventory + rotation standard; naming conventions | Secrets Manager provisioning pattern | #50, #126 |
| **Registry & governance** | envelope hash pins what was approved | manifest schema (`AgentManifest`); catalog lifecycle states | catalog index; cost rollup | #61, #63, #64 |
| **Lifecycle / pipeline** | complete teardown must exist | `consumer-image-contract.md`; manifest-driven provisioning obligations | the pipeline + CDK stacks | #32, #117 |

Blank floor cells mean the part has no non-negotiable slice of its own — its obligations come from
the contracts it participates in.

## How to apply this when scoping an issue

An issue is well-scoped under this doctrine when it answers four questions:

1. **Which tier is each deliverable in?** If one issue mixes tiers (a schema *and* the DynamoDB
   binding), split the text into a contract section and a reference section — or split the issue.
2. **Where are the conformance tests?** A contract-tier deliverable names the test table that a
   third-party implementation would run. If no such tests are conceivable, it isn't a contract —
   it's a reference implementation being described abstractly.
3. **What is the seam called?** A reference-tier deliverable names the interface it sits behind
   (`VaultSource`, the sandbox-provider verbs, the channel adapter). Instance bindings (a table
   name, a model id, a Fargate schedule) appear *only* on the reference side of that seam.
4. **What does the "Do NOT" guard?** The strongest guard is the seam itself: "do NOT let the
   contract reference the binding" (e.g. sa#69's "the schema is a data contract, not a file
   format" is the genre done right).

The practical payoff is the SDK (#106): the installable package is, almost by definition, *the
floor + the contracts + whichever reference implementations a consumer opts into*. Anything that
can't say which tier it's in doesn't know whether it ships in the package, ships as an example, or
doesn't ship at all.

## Repo topology — when the tiers become repos

Decided 2026-07-08 (recorded on sa#106 and sa#3). The tiers eventually become the org layout:
this repo stays the core — floor + contracts + conformance harness + **the** broker (which never
moves out, per the exception above) — and reference implementations live in sibling repos that
depend on the published SDK and pass its conformance suite, each doubling as the worked example
of a compliant implementation.

**The split is gated on the SDK (#106), not before.** Three reasons a split today costs instead
of pays: there is no installable artifact yet, so a satellite would have to vendor the base or
path-depend on a sibling checkout — violating the decoupling discipline the split exists to
enforce; the contracts are pre-1.0 and actively churning, and a monorepo makes a schema change one
atomic commit where a polyrepo makes it N coordinated PRs; and the adoption-signal payoff of a
small public core is nil while the repos are private.

**Interim discipline:** reference-tier code is built *split-ready* — packaged so it imports only
the contract surface, with the consumer-boundary CI guard extended so "this directory could be
extracted without edits" is a checked property. The eventual split is then a `git filter-repo`
with history preserved, not a refactor.

**Extraction order:** memory's reference implementation first (design-only today, so it can be
born in its own repo against the published contract with zero migration); the arms second (they
are reference implementations of the runner contract but operationally entangled with `infra/`
today); a live consumer agent already models the consumer-repo side.

## Relationships

- `friction-doctrine.md` — the sibling axis: this doc decides *what we ship*, that one decides
  *whether a shipped control gates or logs*. A contract can mandate a gate exists while the
  envelope knob decides its strictness.
- `consumer-image-contract.md`, `core/RUNNER-CONTRACT.md` — the in-repo exemplars of the genre.
- `memory/README.md` §"Contract vs reference" — the first subsystem restated under this lens.
- `broker/TAINT.md`, `memory/TAINT.md` — floor standards referenced by the sweep.
- sa#106 (installable SDK) — the packaging boundary this taxonomy feeds.
