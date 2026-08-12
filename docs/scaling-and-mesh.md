# Scaling to many agents, and the A2A mesh

What multiplies as you go from one agent to fifty, what stays shared, and which parts of an
"agents talking to agents" mesh you get from the current design versus which parts are deliberately
unbuilt. Companion to `ARCHITECTURE.md` §"The base / per-agent split" and §"Compositional opacity",
and to the channels docs (`channels/TRUST-MAPPING.md`, `channels/PUBLISH.md`, `docs/channels-*.md`).

## Per-agent vs. shared: the cost classes

The design intent (the broker invariants) is that an agent is *configuration on shared mechanism*,
not re-implemented mechanism. Fifty agents is **not** fifty brokers, airlocks, or drain handlers —
the code is shared. What is genuinely per-agent falls into three cost classes, and conflating them
is what makes people say "a full stack per agent" (an overstatement):

| Class | Examples | Cost of one more agent |
|---|---|---|
| **Shared mechanism** | broker/airlock/drain *code*, the seven schemas, KMS keys, network, the audit + ledger *buckets* | zero |
| **Config + isolation namespaces** | principal identity, Envelope (polarity/caps/allowlists), AgentManifest (grants/connectors), connector-credential leaves, the audit/ledger *prefix*, the grants/counters/intents *rows* (already principal-scoped — the sa#146 scoped counters key on principal) | a row and a namespace |
| **Per-agent runtime AWS resources** | the inbound **queue** + the **drain** Lambda | one queue + one Lambda + one prefix |

The honest one-liner is therefore **shared substrate + per-agent config + a small fixed set of
per-agent runtime resources** — not a cloned platform. At 40–50 agents that is 40–50 queues and
drains: real and bounded, not 50× the whole floor.

## Why the drain is the part that multiplies

The drain is **single-principal by construction** (channels/DRAIN.md D5): it builds one
`BrokerRuntime` from one image-baked AgentManifest and terminal-drops any envelope whose
`principal` does not match. It also runs at `reservedConcurrentExecutions: 1`, because its S3 audit
sink *resumes a tamper-evident hash chain* under one prefix — two runtimes resuming one prefix fork
the chain. Those two facts together mean two listening agents need **separate queues** (a second ESM
on one queue would let the drains compete, each terminal-dropping the other's principal) and
**separate audit prefixes**. That is exactly why standing up a second listening consumer (sa#166)
adds a queue + a drain rather than a second event-source mapping.

## The topology choice: isolated drains vs. a multiplexed drain

Per-agent drains are one topology, not a law. Because the agent is config, the base admits both:

- **Isolated drains (today).** One runtime, one principal, one un-forkable audit chain, independent
  concurrency and blast radius per agent. Cost: N queues + N Lambdas.
- **Multiplexed drain (unbuilt).** One drain that routes by `principal` to a per-principal runtime
  it builds/caches on demand. Cost: far fewer resources — but you trade away exactly those
  isolation guarantees (shared concurrency, shared process, per-principal chain separation now an
  in-Lambda discipline rather than an AWS boundary).

Which one you pick is a per-deployment risk call — strong isolation vs. resource count — and it is
the deferred sa#82 "routing" territory. Nothing in the base forecloses either.

## The A2A mesh: the edge is free, the mesh is not

A **bilateral A2A edge is fully specified and isolated by the current design.** For any two agents:
the sender's `peer.publish` is gated by the *sender's own* broker (a tainted turn's publish hits its
standing external-write cut — channels/PUBLISH.md); the listener's airlock `trust_map` is the only
place that sender becomes known (exact-match; unmapped → dropped at gate 5); the listener's own
`input_trust_map` + polarity decide what the admitted content may *do*; and the provenance chain is
append-only and non-strippable. Wire up any two agents and the edge is correct. A mesh is N of those
edges, so at the *link* level, yes — free.

Two properties of the edge are worth stating precisely, because they are the usual confusions:

1. **Admission ≠ content trust.** Being in a listener's `trust_map` gets your envelope *in* and
   authenticates *who* you are (`sender_class` is a floor, never a grant). It does not bless *what*
   you said — the listener's `input_trust_map` still derives taint and its polarity still governs a
   tainted turn. "Approved peer" and "believed peer" are separate axes, on purpose
   (channels/TRUST-MAPPING.md §"Two maps").
2. **One-way, independently configured, no shared store.** The sender gates its own egress; the
   listener admits on its own map; neither reaches into the other. No mutual registration. In an
   N-agent mesh that is an N×N web of *per-listener* allowlists, each agent owning its own trust
   boundary — decentralized by design.

**What is NOT free — the mesh backlog.** Everything that only exists at N>2 is unbuilt, and this is
the emergent-composition territory `ARCHITECTURE.md` §"Compositional opacity" (auto-agents ch31)
already flags. Named so "mesh for free" stays honestly scoped:

- **Multi-hop provenance authenticity (the biggest gap).** A→B→C: the airlock authenticates the
  *immediate* sender (shared-secret token → `sender_class`). The chain records that the signal
  passed through B, but C cannot cryptographically verify the *origin* was A and not something B
  minted. Taint rides the chain; taint ≠ authenticated origin. This is the substrate under sa#161.
- **N×N trust-map governance.** Each listener curates its own allowlist — no mesh-level curator.
  Who approves a new edge at 50 agents is an operational surface, not a mechanism gap.
- **Cycles / cascade amplification.** A mesh can loop; one injection can fan out across edges. The
  availability epic de-amplifies an approval-queue *flood at one node* (sa#159/160); a *campaign
  across nodes* watchdog is the deferred sa#161.
- **Discovery / routing.** How B addresses C is static config today (sa#82).

**Recommendation.** Do not build a mesh *subsystem* now. At the current agent count it is YAGNI, and
mesh machinery ahead of a real second consumer would violate the repo's own floor-first doctrine
(`docs/friction-doctrine.md`). Keep taking the free bilateral edge; treat the four items above as the
known backlog (two already have issues — sa#82, sa#161 — and multi-hop provenance authenticity is
the substrate to state explicitly under sa#161) so we do not sleepwalk past the multi-hop-authenticity
cliff.
