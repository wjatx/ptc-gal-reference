# Architecture — the trusted-autonomy floor

The shared vocabulary every subdir builds against. The deeper *why* is in the `auto-agents` corpus
(`base-platform-brief.md`, `tool-broker-sketch.md`, `PILLARS.md`, `ontology.md`); this states *what*
safe-agents encodes once.

## The organizing idea

**The base provides the domain-invariant floor; each per-agent repo re-derives and configures the
domain-specific envelope.** A feature belongs in the base if it would be identical for a high-risk
trading agent and a low-risk dashboard agent; it belongs in a per-agent repo if it changes with risk
level or domain.

## The broker is the center

The **deterministic tool broker** is the architectural center — not the agent, not a "doer." Three
invariants the substrate enforces in **every** compute mode, holding even if the agent process is
fully compromised ("a compromised agent can still only ask"):

1. **The agent holds no connector credentials** — they live only in the broker's secret store.
2. **The agent's only egress is the broker**, enforced at the network layer — a confined network
   namespace whose only route is the broker, *not* a security-group rule (`docs/model-egress.md`
   §"Why a single box cannot SG-confine its agent") — never in code the agent runs. "Call the API
   directly" must not be a path that exists.
   (The agent's own model inference — `api.anthropic.com` — is not a connector; the broker mediates
   *tools/actions*, not the model's brain.) The **network-layer** half of this is now flag-gated
   (`secureNetwork`, default off — the topology ships OFF for the current experiment floor); the
   **code/credential** half (agent holds no creds, broker is a separate identity, every call routes
   through the broker) is always on. See `docs/network-security-layer.md` for the two modes and the
   trade.
3. **The broker runs under a separate IAM identity** from the agent (different role; ideally a
   different process / container / task).

Underpinning all three: **the model may only surface a concern; the gate is deterministic** — the
PDP `decide()` is a pure function, taint is source-based and non-strippable, and the one model-judged
gate can only refuse, never bless. The cross-cutting invariant is `docs/deterministic-gate.md`.

## Compositional opacity: bound the composed system at the boundary

Composed systems (delegated sub-agents, persistent memory, multi-step plans) lose global
inspectability even when each component is individually transparent, and harm composes across
permitted steps. The platform enforces at the boundary (the broker), not by inspecting components,
through three mechanisms: (1) path-based taint recorded in audit state rather than a strippable
label, so untrusted provenance cannot be laundered out of a flow; (2) cumulative blast-radius
budgets across the session and the delegation tree, so the composed cost is bounded even when each
step is individually permitted; and (3) a trajectory-capturing audit recording the lineage of each
composed action. See auto-agents Chapter 31. How these mechanisms scale to many agents and to an
A2A mesh — what multiplies, and which mesh properties are free versus deliberately unbuilt — is
`docs/scaling-and-mesh.md`.

## The seven base schemas (encoded once; per-agent repos fill in values)

| Schema | Purpose |
|---|---|
| **Grant** | Per (principal × action-class): level, envelopeHash, promotedBy, evidence, lastSafeLevel, demotionTriggers, demotionReason, labelLatency, ownerId. Integrity is **not** a schema field: the stored bytes are HMAC'd into the item-level `grantHash` attribute (`#246`), so the basis is what was stored, never a re-serialization. |
| **BrokeredCall** | The typed request: principal, tool, op, args, the **static** manifest entry (effect/external/reversible — from code, never from the model), taint, session, ts. |
| **Decision** | The five verbs under default-deny: `allow` · `deny` · `transform` · `require_approval` · `abstain`. |
| **Intent** | Durable state for a held action (out-of-band approval): id, materializedRequest (the exact BrokeredCall to execute), renderedForHuman (what-you-see), status, expiry, approvedBy, ts. Makes "draft and hold" physically true — the approved artifact is executed verbatim, not re-derived. |
| **AuditRecord** | Hash-chained: seq, ts, principal, tool, op, argsDigest, decision, reason, envelopeHash, approvedBy, outcome, error, seed, prevHash, hash — plus the optional approval receipts `intentId` / `storedCallDigest` / `resultDigest` (`#198`), hash-covered only when present so pre-receipts chains still verify byte-for-byte. `storedCallDigest` is recomputed independently at release, which is what makes executed==approved provable after the intent expires. Broker-emitted, append-only, external; the writing role cannot delete it. |
| **Budgets** | Per period: error / attention / escalation / fallback (atomic counters). |
| **PromotionRecord** | Maker-checker: actionClass, principal, fromLevel, toLevel, evidence, predicate, proposedBy, ratifiedBy, ts. |

**The grant `level` is the human-oversight rung — `in-loop` / `on-loop` / `out-of-loop`** (the
canonical vocabulary from `auto-agents/book/ch36`): *in-loop* = a human approves each action of the
class; *on-loop* = the agent acts but a human monitors and can veto; *out-of-loop* = fully
autonomous. This is **orthogonal to the Decision verb** (what happens to one specific call —
allow/deny/transform/require_approval/abstain) and to the audited disposition. Level is *state on the
grant*; the verb is *per call*. Don't conflate them.

## The base / per-agent split

**Base (invariant — build once, here):** the broker · egress confinement · the agent-external
tamper-evident audit · the grant lifecycle (recorded maker-checker promotion + automatic
deterministic demotion, no model in the loop) · capability-scoped tool registry (an agent cannot
see a tool it wasn't granted) · premise revalidation, idempotency, atomic counters · out-of-band
approval with what-you-see-is-what-executes · **strictly-attenuating sub-grants** (a delegated
sub-agent gets a computed, short-lived sub-grant that can only narrow authority, and its actions
attribute up the chain to the human) · the shared vocabulary + pillar contract.

**Per-agent repo (configured — re-derived per domain):** the envelope (caps, allowlists,
reversibility classes, abstention thresholds, fallback budgets, corroboration config) · the
input-trust map · the policy ruleset + its CI test-table · the promotion predicates + the autonomy
rungs the agent may occupy · whether the high-stakes/adversarial machinery is enabled.

### The one thing that must NEVER be in the base

**The safe-default polarity** — abstain-is-safe vs a positive safe action. It is **re-derived per
agent**: the trading agent *abstains* (silence is safe); an operations agent *acts* (inaction is the
hazard). Baking a polarity into the base is a latent safety bug. (`auto-agents/book/ch35`,`ch42`,`ch46`.)

### One architecture, four agents

The same data flow + the same broker, configured differently — *not* four different systems
(`auto-agents/book/ch48`). The canonical examples that double as our per-agent roadmap:

| Agent | Polarity | What its envelope turns up |
|---|---|---|
| **trading** | abstain (silence is safe) | corroboration + the error budget + a medium-latency learning loop; all order classes start `blocked` |
| **communications** | (mixed) | the human-approval path for high-blast sends; promotes on the envelope |
| **build-fixer** | act-within-CI | the **pull request is the approval artifact**; a tight loop behind green CI |
| **operations** | act (inaction is the hazard) | routes `abstain` to a **positive safe action**, not silence |

The architecture is the constant; the configuration is the per-domain re-derivation. A live trading
consumer is the first; comms / build-fixer / ops are the "2–3 more agents" with genuinely different envelopes.

#### That table is cut by domain; `examples/` is cut by polarity

The four above answer *"what does a real agent in this business look like."* `examples/` answers a
different question — *"what must the base be blind to, and what proves it."* **Domain is flavor;
polarity is what actually varies the design**, and polarity is the one thing the base must never
assume (above). The two cuts are not separate roadmaps and do **not** multiply into eight agents.

The polarity archetypes are `missileer` (abstain-safe) · `sepsis-detection` (act-safe) ·
`flood-gate` (state-dependent, isolated; deferred) · `home-security` (per-action **and**
state-dependent composite — the hardest case; deferred). Their domains are
chosen for **rhetorical clarity of the polarity** and assert **no correspondence** to the four
domains above or to any real consumer — a launch-watch observer and a bedside monitor share no
domain vocabulary and are nonetheless the same manifest with one field flipped. Reading `missileer`
as a stand-in for `trading` gets it backwards.

Where the four domains actually land:

- **trading** is the one with *real* consumers, and they are not fictional examples: a live consumer
  agent's own repo, `examples/alpaca_paper_drill/`, and the brokerage MCP work under #221.
- **communications** and **operations** have their polarity interest discharged by the archetypes
  (per-action and act-safe respectively).
- **build-fixer** has no polarity archetype **on purpose** — its contribution is the *approval
  artifact* (the pull request standing in for a human gate), orthogonal to polarity and demonstrated
  by `examples/owner_channel/`. A domain whose interest sits on a different axis belongs with the
  seam consumers, not the archetypes.

See [`examples/README.md`](examples/README.md) for the per-example proof obligations. The two
deferred archetypes are blocked on
[`docs/authority-change-safety.md`](docs/authority-change-safety.md) findings 1 and 2 — the scalar
`envelope.polarity` cannot express either shape.

## Broker placement across the cloud arms

The compute mode changes *where the broker process sits*, never the invariant. The durable state
(grant, counters, intents, audit) always lives **outside** the compute (DynamoDB / S3 Object Lock)
so it survives restart and the audit can't die with an ephemeral host.

**Egress is enforced at the network layer, not by an OS sandbox.** On the production agent arms the
agent runs in a confined network namespace whose only outbound route is the broker — arm-agnostic,
and the broker is the single enforcement point. **The netns is the floor, not a box-level security
group**: the agent and the broker co-host, the broker needs broad egress to reach connectors, and an
SG cannot tell the two apart — so agent-confinement is process-level isolation, and the box SG only
governs what the *box* may reach (`docs/model-egress.md`). OS-level sandboxing
(OpenShell) is **reserved for the interactive dev-box arm**, where a human drives the box and there's
no separate broker process; it is not the enforcement mechanism for the autonomous arms.

- **Always-on EC2** — broker as a separate local process / sidecar under its own IAM role; agent in
  a confined netns whose only outbound route is the broker.
- **Lambda-woken / scheduled EC2** — same while running; the waking Lambda is itself a scoped
  principal and carries no connector creds to the agent.
- **Fargate** — broker as a separate task / sidecar; per-container task-role; agent container egress
  restricted by the task networking.

## Pre-deployment checklist (any agent on the base)

- [ ] Agent holds no connector credentials; the broker holds them.
- [ ] Agent egress is the broker only, enforced at the network layer, in this compute mode.
- [ ] Broker runs under a separate IAM role/identity from the agent.
- [ ] Writes are default-deny; the served tool registry is capability-scoped to this agent.
- [ ] Audit is broker-emitted, append-only, external; the writing role cannot delete it.
- [ ] Grant state, counters, intents are durable + external (survive an ephemeral host).
- [ ] Caps are atomic counters; idempotency keys enforced.
- [ ] High-blast actions hold for out-of-band approval with what-you-see-is-what-executes.
- [ ] **Safe-default polarity re-derived for this domain** (abstain vs positive safe action).
- [ ] Memory taint propagation is on; no memory-laundered premise drives a high-blast action.
- [ ] Demotion path is deterministic, runs with no model in the loop, and has been drilled.
- [ ] Policy test-table passes in CI; a red-team reached no unauthorized action.
- [ ] Each grant has a named owner and a signed promotion record.
- [ ] The grant store is writable **only by the maker-checker promotion path** — never by the agent
  (or the agent promotes itself).
- [ ] Every durable input a sanctioned write path consumes (stored proposals, evidence artifacts,
  re-read config) carries the same tamper-evidence as the object it mutates — or is re-validated
  at the trust boundary (an unprotected input is the bypass; `broker/grant-lifecycle.md`
  §input-integrity corollary).
- [ ] Sub-grants strictly attenuate (delegation can only narrow authority); sub-agent actions
  attribute up the chain to the human.
