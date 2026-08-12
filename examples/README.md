# examples — fictional consumers, each proving one claim by construction

These are **fictional** example consumers of the safe-agents base — not deployable agents.
Each is a broker-facing `AgentManifest` (`safe_agents/broker/schemas/manifest.py`): a
`principal`, granted action-classes, connector names (base names, or consumer-supplied via
`connector_providers`), and a risk `envelope`. A real deployment supplies its own manifest
via `BROKER_MANIFEST` and lives in its own repo.

**Every example here exists to discharge one proof obligation.** If you cannot say what an
example proves that no other example proves, it should not be here. The gallery has three
buckets, and they are not a cross-product — see "How this relates to the domain four" below.

## 1. Polarity archetypes — the base is polarity-blind

The base — broker, connector registry, schemas — makes **no assumption** about an agent's
safe-default polarity. Polarity (`abstain`-is-safe vs `act`-is-safe) lives entirely in
per-consumer config; baking it into the base is a latent safety bug (`CLAUDE.md`,
`ARCHITECTURE.md` §"The one thing that must NEVER be in the base").

**The domain of each archetype is chosen for rhetorical clarity of the polarity, and
asserts no correspondence to any real consumer or business domain.** Nobody argues about
whether not-launching a missile is safe — that is the entire reason missileer is a
missileer. A launch-watch observer and a bedside monitor share no domain vocabulary and are
nonetheless the *same manifest with one field flipped*, which is the polarity-blind claim
stated as construction rather than prose.

| Example | Polarity shape | Status | What it proves that nothing else does |
|---|---|---|---|
| [`missileer/`](missileer/) | `abstain` is safe | **built** | Pole 1. Silence is always the safe outcome. Also the **restrict-by-construction** move: the hazardous op is *absent* from the registry, not merely denied — an agent cannot be argued into an op it was never given. |
| [`sepsis-detection/`](sepsis-detection/) | `act` is safe | **built** | Pole 2, and the polarity-blindness proof itself: identical connectors and `grant_classes` to missileer, differing **only** in `envelope.polarity`. Inaction is the hazard, so `abstain` must route to a *positive safe action*, never silence. |
| [`flood-gate/`](flood-gate/) | **state-dependent**, isolated | deferred | Polarity is *evaluated*, not declared. One op (`open_spillway`) inverts with world state — act-safe in flood, abstain-safe in drought. A single-op agent, so the state axis is visible with no per-action complexity confounding it. |
| [`home-security/`](home-security/) | **per-action + state-dependent** (composite) | deferred | The realistic, hardest case: `sound_alarm` (act-safe) vs `unlock_door` (abstain-safe) needs a per-action map — *and* `unlock_door` itself flips act-safe during a fire, which a map cannot express. Expressible only as a function of `(action, state)`, so it is the example arguing the two schema findings may be one. |

The two deferred archetypes are blocked on
[`../docs/authority-change-safety.md`](../docs/authority-change-safety.md) findings 1 and 2;
the current scalar `envelope.polarity` cannot express either shape. They are deliberately
pitched at different difficulty: `flood-gate` **isolates** state-dependence so the shape can
be named cleanly, while `home-security` **composes** both shifts the way a real agent would.
The composite is the one carrying the open design question — if polarity is evaluated over
`(action, state)`, that subsumes a per-action map, and findings 1 and 2 may be one mechanism
at two levels of generality rather than two independent calls.

## 2. Seam consumers — one mechanism each

| Example | Proof obligation |
|---|---|
| [`embedded_agent/`](embedded_agent/) | The broker as a **library** — a plain Python program embeds it through the public `safe_agents.broker.api` surface (#266). Every other example configures the broker *as a service*; this one imports it, which is the demonstrable half of "agents you build can use the broker directly". |
| [`oauth_api/`](oauth_api/) | `OAuthRefresh` credential strategy — the broker mints a short-lived access token from a broker-held refresh token; the agent sees neither. |
| [`oauth_remote_mcp/`](oauth_remote_mcp/) | The same credential, delivered to a **vendor-hosted** MCP server as a per-connect header (`header_map`, the remote dual of `env_map`). Resolution per *connect* is the point: an expired token dies as a transport failure, so the reconnect is the re-auth path. |
| [`scoped_s3/`](scoped_s3/) | `assumed_role` + `capability_iam` — an out-of-scope action is denied **by IAM, not by the broker**, so blast radius survives a fully compromised broker decision. |
| [`confidence_budget/`](confidence_budget/) | `Envelope.confidence` bar + per-period error budget (`error_prob × blast_radius`) on the scoped-counter seam. |
| [`restricted_mcp_server/`](restricted_mcp_server/) | Restrict-by-construction applied to a *tool server* — the missileer move at the MCP layer; the dangerous tool is absent, not denied. |
| [`alpaca_paper_drill/`](alpaca_paper_drill/) | Two-key MCP admission against a **real third-party server** at volume (69 tools discovered, 3 admitted, M5 finding-flood discipline). Drill scope, not production. |
| [`emailer/`](emailer/) | Outbound A2A — `peer.publish` provenance is **broker-stamped** from the sending turn, so a sender cannot launder taint out of its own chain. |
| [`webhook_peer/`](webhook_peer/) | Inbound A2A — the airlock and drain: untrusted peer input gated in fixed order, sender labels a floor never a grant. |
| [`owner_channel/`](owner_channel/) | Human-as-owner — `/approve` and `/flag` keyed on the unforgeable gate-8 `sender_class`. |
| [`liveness_policy.py`](liveness_policy.py) | The availability floor — a dead-man's-switch whose *default* is itself polarity-dependent, which is why the derivation lives consumer-side. |

## 3. How this relates to the "domain four"

`ARCHITECTURE.md` §"One architecture, four agents" carries a different cut of the same
concern, from `auto-agents/book/ch48`: trading / communications / build-fixer / operations.
That table is cut by **domain** — "what does a real agent in this business look like." This
directory is cut by **polarity and seam** — "what does the base have to be blind to, and
what mechanism proves it."

**These are not two roadmaps and do not multiply into eight agents.** Domain is flavor;
polarity is what actually varies the design. Concretely:

- **trading** is the one domain with *real* consumers, and they are not in this directory —
  a consumer agent in its own repo (live), [`alpaca_paper_drill/`](alpaca_paper_drill/), and the
  brokerage work under #221. No fictional archetype here stands in for them.
- **communications** and **operations** are domains whose polarity interest is already
  discharged by the archetypes above (per-action and act-safe respectively).
- **build-fixer** has no polarity archetype **on purpose** — its distinctive contribution is
  the *approval artifact* (a pull request standing in for a human gate), which is orthogonal
  to polarity and is demonstrated by [`owner_channel/`](owner_channel/). When a domain's
  interest sits on a different axis, it belongs with the seam consumers.

## Relationships

- `ARCHITECTURE.md` §"One architecture, four agents" — the domain cut, with its `ch48` citation.
- `core/manifest-schema.md` — the manifest schema these conform to.
- `safe_agents/broker/schemas/{manifest,envelope}.py` — the typed `AgentManifest` / `Envelope`
  a manifest is validated against.
- `docs/authority-change-safety.md` — why polarity must be re-derived per agent, and the
  per-action / state-dependent cases the deferred archetypes wait on.
- `docs/canonical-consumer.md` — the five-seam anatomy of a real consumer.
