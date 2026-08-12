# The canonical consumer — the reusable pattern for an agent on the base

> **Status: doctrine (2026-07-11).** The *consumer* pattern; `docs/PTC.md` is the *protocol* it rides.
> Where `docs/adopting-safe-agents.md` is the **how-to** (refactor this agent, pick an arm, run the
> pipeline), this doc is the **what-shape** — the invariant anatomy every consumer has once the
> broker-debaking (sa#139) and PTC connector work (#171/#172/#173/#175) landed, and the line that
> decides what is *base* and what is *the consumer's*. It is the direct input to the Phase 7 normative
> spec (`docs/PTC.md` §11 #178): the spec standardizes the wire; this doc standardizes the consumer.

## 1. The one idea

> **A consumer is a risk envelope on a trusted floor — configuration, not re-implemented mechanism.**
> The base ships the broker, the schemas, the arms, the gate, the taint model, and the connector
> *seam*. A consumer brings a manifest (its envelope), its ToolOp classifications, its domain
> connector classes, and its image — and nothing else. If a consumer has to re-implement a *mechanism*
> to stand up, the base has a hole; if the base has to learn a *domain fact* to serve it, the base has
> a leak. This doc is the boundary that keeps both from happening.

Everything the base does is domain-invariant: it is *identical* for a high-risk trading agent that
must never act on doubt and a low-risk dashboard agent that should always refresh. Everything a
consumer does is where risk and domain live. The whole platform thesis is that the second set is
small, typed, and declarative — a consumer is *authored*, not *built*.

## 2. The base/agent line (load-bearing)

The organizing rule of the whole repo, stated as a test:

> **A capability belongs in the base if it is byte-for-byte the same for a high-risk trading agent and
> a low-risk dashboard agent. It belongs in the consumer if it changes with risk level or domain.**

The analogy that keeps the line honest:

> **Unix ships what a database needs, not a database.** It ships the filesystem, processes, sockets,
> permissions, `fsync` — the domain-invariant floor every database (and every non-database) stands on.
> It does not ship Postgres, a schema, or a query planner. safe-agents ships what an *agent* needs —
> mediated egress, a deterministic gate, tamper-evident audit, taint propagation, a connector seam —
> not an agent, not a strategy, not a connector to any one API, and above all not a *safe-default
> polarity*. The consumer is the database.

Two things sit so far on the consumer side of this line that the base may **never** hold them at any
tier (`docs/contract-vs-reference.md`):

- **The safe-default polarity** (`abstain`-is-safe vs `act`-is-safe). Baking it in is a latent safety
  bug — it inverts between agents (missileer abstains, sepsis acts; `examples/README.md`). It is
  re-derived per agent, always.
- **Any op *name* or *classification*.** The base owns the ToolOp *schema* and the PDP *rules*; the
  fact that `alpaca.news` is a tainting external read is the consumer's, and travels with the agent
  (§5).

## 3. The anatomy of a consumer — the five seams it fills

A consumer is exactly these five declarations against base-owned shapes. Each names a base seam, a
consumer fill, and the guard that keeps the fill from becoming a mechanism the consumer re-implements.

| # | Seam (base owns the *shape*) | Consumer fills (its *config*/*domain*) | Guard |
|---|---|---|---|
| 1 | `Envelope` (`safe_agents/broker/schemas/envelope.py`) | its risk envelope: polarity, rungs, caps, trust map | polarity never in base; envelope hash pins what was approved |
| 2 | `ToolOp` schema + PDP rules (#171) | its `tool_ops` table — every granted op's effect/external/reversibility | base names **no** op; the table travels in the manifest |
| 3 | the `Connector` protocol + `connector_providers` injection seam (#141) | its domain connector *classes* (`AlpacaConnector`) | the broker holds the instance; the agent never gets a reference |
| 4 | the closed `AuthStrategy` catalog + `capability_iam` (#173/#175) | *which* strategy each connector uses + the minimal IAM per capability | catalog is an enum, not an import path; nothing store-loaded injects a strategy |
| 5 | the consumer-image contract (`docs/consumer-image-contract.md`) + the promotion flow | its image (agent code + prompts + pinned SDK) + its grants | the agent holds no connector credential; grants are maker-checker, broker-read-only |

Seams 1–4 are the `AgentManifest` (`safe_agents/broker/schemas/manifest.py`) — `build_runtime(manifest)`
constructs the entire broker runtime from it, with no agent-specific constant baked into the base.
Seam 5 is the deployment: the image the broker runs and the grants it reads.

`build_runtime` is imported from **`safe_agents.broker.api`**, the base's public embedding surface
[ruling: maintainer, 2026-07-26, #266] — the one entry point this document had named as the pattern's
centerpiece for months while the consumer-boundary guard forbade importing it. The rule the ruling
settled: *a consumer may import what it fills (`broker.schemas`) and what it runs (`broker.api`),
never what decides.* See `docs/consuming-the-sdk.md` §2, and `examples/embedded_agent/` for the
smallest consumer that exercises seams 1–4 without seam 5 — no image, no deployment, one process.

## 4. Capability vs provider — the distinction the epic sharpened

The connector work (#171–#175) forced a split that was previously blurred. Keep them separate:

- A **capability** is *what the agent may do*: a `(tool, op)` pair, its ToolOp classification, its
  grant, and its envelope rung. It is a **policy** object — it decides whether a call is allowed and at
  what oversight rung. The base owns its *shape*; the consumer owns its *content* (seams 1–2).
- A **provider** is *who executes it*: the connector class that speaks the real API, plus how its
  credential resolves (the auth strategy) and what identity it runs under (`capability_iam`). It is a
  **transport/identity** object. The base owns the *seam*; the consumer owns the *class* (seams 3–4).

The payoff of the split: the same capability can change provider without touching policy, and the same
provider can serve capabilities at different rungs. A live brokerage and paper-Alpaca are the same
`trade.place` capability with different providers and different rungs — *one code path, config-only
difference* (§7). And the base can ship the `peer.publish` transport as a base connector (#172) while
the *classification* of a peer publish stays whatever the consumer's `tool_ops` says — provider base,
capability consumer.

## 5. Classification travels with the agent

The base runtime names no operation. A consumer's `tool_ops` table (seam 2, #171) is the sole source
of every op's effect/external/reversibility/egress classification, and it lives **in the consumer's
manifest**, not in a base global. Two consequences:

- **Rename-invariance.** A consumer-defined op gates identically regardless of its name — the base has
  no `if op == "trade.place"` anywhere to drift out of sync with a renamed op. The base ships a
  *copyable* `CATALOG` of domain-neutral ops (`safe_agents.broker.manifest.CATALOG`) an author may copy
  in, but it is **never consulted at request time**; copying is authorship, not a base dependency.
- **The model cannot re-classify.** Classifications are code/manifest-resident facts. The model cannot
  assert its `send` is really a `draft` to dodge a gate — the verdict was fixed at load, before any
  turn ran. This is why classification is a *declaration*, not a runtime judgment.

The sharpest instance: a consumer may **split one API into two ops** to give them different taint
behavior. The live consumer agent splits `alpaca.read` (structured market data — trusted) from `alpaca.news`
(free-text news — the injection carrier that must taint the turn). Same connector, two ops, two
classifications, two trust postures — and the base learned nothing about news to make that split.

## 6. The broker owns the connector — the credential floor

The single non-negotiable across every provider seam: **the agent holds no connector credential, ever;
its only path to an external effect is `agent → broker → Doer → connector`.** "Call the API directly"
is not a path that exists from anything the agent can reach (`safe_agents/connectors/README.md`).

- The Doer is the *sole* holder of connector instances; it fetches the credential at call time, passes
  it into `execute(...)`, and the credential never reaches the audit record (args are hashed) or the
  agent.
- A connector's credential is a broker-resolved **strategy**, not a static string (#173): `StaticSecret`
  (a secret leaf), `OAuthRefresh` (mint a short-lived access token from a broker-held refresh token),
  or `assumed_role` (STS-assume a per-capability scoped role and hand the connector only the short-lived
  bundle — #175). The catalog is base-owned and **closed** (an enum discriminator, never an import
  path), so nothing store-loaded can inject a strategy, role, or scope.
- When the credential is an *identity* (`assumed_role`), the provider's blast radius is bounded by IAM,
  not by the broker: `capability_iam` declares the minimal actions/resources, the CDK provisions one
  role scoped to exactly that (assumable only by the broker), and an out-of-scope action is
  `AccessDenied` by **IAM** (proven live, 2026-07-11). A fully compromised agent that somehow reached
  the connector still cannot exceed the one declared capability.

The consumer supplies the *class* and the *config*; the base supplies the *seam and the enforcement*.

## 7. The rung tracks provenance maturity (the config knob that moves with proof)

A capability's autonomy rung is a consumer config value, but it is **bounded by what the mesh can
currently prove about the call's premise** (`docs/PTC.md` §9). This is the rule that makes "one code
path, config-only difference" safe rather than reckless:

| Provenance maturity | Rung it licenses |
|---|---|
| taint **bit** propagates (today) | correct gating *if you trust the sender* → paper trades autonomous-ish |
| full **lineage** in the chain | receiver derives its own taint; human sees origin → live trade *with approval* |
| **signed** lineage (#181, verify OFF) | receiver can't be lied to → autonomous cross-mesh high-blast |

So a live-brokerage `trade.place` stays pinned to `in-loop` in its envelope until signed-provenance
verification runs ON — not as a limitation of the code, but as the honest expression of what the trust
layer can prove. The consumer *authors* the rung; the doctrine tells it how high it may honestly set it.

## 8. The complete pattern, proven

The pattern is provable end-to-end today: **a consumer owns its ToolOps end-to-end.** The live proof is
a consumer agent's own pair of broker manifests — one for the agent, one for its digest sender — which
live in that consumer's repo rather than here. Do not re-prove the pattern in the base; point at it:

- It declares its own `tool_ops` (seam 2) covering exactly its four granted classes — the base holds no
  `alpaca` op.
- It **splits** `alpaca.read` from `alpaca.news` for taint (seam 2, §5) — a domain decision the base
  never saw.
- It **injects** a consumer-owned `AlpacaConnector` via `connector_providers` (seam 3) — the class
  travels in *its* broker image; the base has no alpaca dependency (`safe_agents/connectors/README.md`).
- It **re-derives** its envelope (seam 1) — `polarity: abstain` ("silence is safe"), `order.place:
  [blocked]` structural, `trusted_read_sources: [connector:alpaca.read]` trusting structured reads but
  *not* news.
- It splits `notify.send` onto a **separate one-shot runtime** (the digest-sender) because turn identity
  is broker-owned and a tainting news read would escalate a same-runtime send — a consumer *using* the
  base's turn/taint mechanism to shape its own safety, exactly the intended grain.

Every one of those is configuration against a base shape. The base learned no trading fact to serve any
of it. That is the pattern working.

## 9. What a consumer must NOT do (the guards, restated)

- **Never hold a connector credential** or reach a connector directly — seam 3/6.
- **Never bake the safe-default polarity** into anything shared — §2.
- **Never expect the base to name its ops** — the `tool_ops` table travels with the agent — §5.
- **Never inject a strategy/role via an import path** — the auth catalog is closed — §6.
- **Never let a `require_approval`/`deny`/`abstain` be retried around** — a non-`allow` decision is a
  hard stop, not a transient error (`docs/consumer-image-contract.md` obligation 3).
- **Never port base mechanism into the consumer repo, or consumer domain into the base** — re-derive
  clean in each direction (the decoupling discipline; CLAUDE.md).

## 10. Relationships

- `docs/adopting-safe-agents.md` — the how-to companion (refactor, arm choice, pipeline run); this doc
  is its *why-shape*.
- `docs/PTC.md` — the trust *protocol* this consumer pattern rides (§9 is the rung rule; #178 the spec).
- `docs/contract-vs-reference.md` — the packaging lens (which tier each seam is); `docs/friction-doctrine.md`
  — the floor-vs-knob lens (why an envelope value ships OFF).
- `broker/SCHEMAS.md`, `safe_agents/broker/schemas/manifest.py` — the `AgentManifest` the five seams fill.
- `broker/CONNECTOR-AUTH.md` — the auth-strategy + `capability_iam` contract (seam 4).
- `safe_agents/connectors/README.md` — the shared-vs-agent-owned connector line (seam 3).
- `docs/consumer-image-contract.md` — the image obligations (seam 5).
- `examples/` — fictional consumers proving the base is polarity-blind (missileer/sepsis) and each
  provider seam (`oauth_api`, `scoped_s3`, `emailer`); a live consumer agent's own repo is the first
  *real* one.
