# Config provenance — the injection-power lattice for config surfaces

> **Status: doctrine (2026-07-12, #186).** The third doctrine lens, alongside
> `friction-doctrine.md` (when the base gates vs logs) and `contract-vs-reference.md` (what the
> base owes each part). This one answers *where a setting is allowed to live*. The rule was
> extracted from the 2026-07-11 config audit — it governed every placement decision we had made,
> but only as tribal knowledge; an SDK consumer (#106) would scatter config wrong on day one
> without it. The corpus carries the ported prose in `auto-agents/tool-broker-sketch.md`
> §request-envelope (auto-agents@0f72c49); this doc is the platform-side operational form.

## The rule

**Config stratifies by injection power; "where config lives" is an enforcement mechanism, not a
housekeeping choice.** A config surface's required provenance is set by the worst thing a
malicious value on that surface could do. Four layers, strictly ordered:

| Layer | What may live here | Provenance required | Mutation path |
|---|---|---|---|
| **1. Code-provenance** | anything that can name *code to run*: provider import paths, connector classes, strategy implementations | image-baked, code-reviewed artifact (`AgentManifest` in the consumer broker image) | a reviewed commit + image rebuild |
| **2. Store** | anything that can only *select or tighten among pre-approved behaviors*: Envelope knobs, grant levels, caps | integrity-protected runtime store (hash/HMAC + loud quarantine) | ceremonies only (GAL §5's SDK-style commands); safe-by-construction where possible |
| **3. Deploy** | topology and wiring that names no behavior: CDK context, env-var pointers, queue/table bindings | deploy-time IaC, versioned | a deploy |
| **4. Secrets** | credentials — bare leaves, scoped by the deploying topology (see "Secret naming" below) | broker-resolved at runtime; never in an image, store, or template | rotation, out-of-band |

The order is a **Biba integrity lattice, the same no-write-up shape as taint**
(`broker/TAINT.md` §1.1): a lower layer must never be able to write up into a higher one. Store
config can never cause new code to load; deploy context can point at a store but not inject into
it; secrets appear in the other layers only as *pointers* (an ARN env var), never as values.

## The decision test — "which layer does my setting go in?"

Ask in order; first yes wins:

1. **Can the value name code to run** — an import path, a class, a URL something fetches code
   from, a template that gets evaluated? → **Layer 1.** It is honored only from the image-baked
   manifest. If you need it runtime-selectable, you don't move the setting down — you **close the
   catalog**: the base owns an enum/registry of reviewed implementations, and only the *key* into
   it becomes selectable (which is a Layer-2 value, because now it can only select).
2. **Can the value only select or tighten among behaviors already reviewed into the image** — a
   level, a cap, a bound, an on/off knob for a shipped mechanism? → **Layer 2.** It lives in the
   integrity-protected store and moves only through a ceremony.
3. **Does it bind topology with no behavior content** — which queue, which table, which model
   ARN, which manifest path the image reads? → **Layer 3.**
4. **Is it a credential?** → **Layer 4.** Bare leaf; every other layer holds at most its name.

When genuinely unsure, place **higher** (more restrictive). Moving a setting down later is a
deliberate declassification and usually requires the catalog-closing step from test 1; moving up
after an incident is a redesign.

## Worked examples (the existing surfaces, and why each sits where it does)

- **`connector_providers` / `connector_secrets` (sa#141)** — provider import paths are honored
  ONLY from the image-baked `AgentManifest`, never from anything store-loaded. The canonical
  Layer-1 example: a store-injected import path would be arbitrary code execution inside the
  broker.
- **`AgentManifest.connector_auth` (#173)** — the `AuthStrategy` catalog is deliberately a
  **closed enum discriminator, not an import path**: nothing store-loaded can inject a strategy.
  The catalog-closing move from test 1, executed.
- **`ADAPTER_REGISTRY` (#176)** — adapters are selected by registry key with a shipped default;
  the selection selects, the implementations are image-baked. Same move.
- **The grant + Envelope stores (sa#122/124)** — Layer 2 as designed, with two distinct integrity
  mechanisms: **grants are HMAC'd with loud quarantine** on mismatch, while the stored envelope
  deliberately carries a plain content hash and *no* HMAC — its integrity is enforced downstream
  by grant hash-binding, so a tampered stored envelope can only produce a deny/quarantine, never
  mint authority. "An edit can only tighten" is a property of that binding plus the seed script
  (from reviewed YAML) being the only sanctioned write path today; the GAL ceremonies (#123) are
  this layer's real mutation path going forward, which is why they must ship as SDK-style
  commands rather than ad-hoc scripts — a ceremony is a provenance event, not a convenience.
- **The channels screen enable (#152)** — a Layer-2-*eligible* knob deliberately placed higher
  (image-baked `channels-manifest.yaml` + deploy context). Placing above your layer is always
  allowed: the lattice sets a floor, not an address.
- **CDK context (`brokerManifestPath`, `capabilityRoles`, `channelsScreenModelArns`,
  `secureNetwork`)** — pure Layer 3: each names *which* reviewed artifact or topology binds,
  never new behavior.
- **`BROKER_SIGNING_KEY_SECRET_ARN` (#181)** — the layering in one setting: the env var (Layer 3)
  carries only a pointer; the key material (Layer 4) resolves broker-side at cold start and never
  enters the agent image. Connector secrets are bare leaves under `<prefix>/connectors/` (NB #164).
- **The YAML-vs-Python authoring split** encodes the lattice at authoring time: YAML seeds are
  data (Layers 2–3 content), Python manifests are code (Layer 1). The format hints the layer, but
  **provenance is what counts** — `channels-manifest.yaml` is YAML that ships image-baked, riding
  Layer-1 provenance.

## Secret naming — the leaf rule (#126)

Layer 4 says "bare leaves". This is what that means operationally. It is a **ruling**
[ruling: maintainer, 2026-07-27, on #126] rather than a house style, because one shipped arm cannot
represent the alternative at all.

**The rule: a manifest names a bare LEAF; the environment/tenant scope is supplied by the
deployment topology, never by the manifest.**

| Arm | What supplies the scope | leaf `github-token` resolves to |
|---|---|---|
| `secretsmanager` | `BROKER_SECRET_PREFIX` (a Layer-3 pointer) | `<prefix>/connectors/github-token` |
| `dir` (#248) | the mount root | `<root>/github-token` |
| `file` (a local wrapper) | the containing directory | key `github-token` in that directory's `secrets.json` |

A leaf therefore contains **no path separator**. That is enforced rather than merely documented:
`DirSecretsProvider._resolve` refuses a name containing `/` or `\` (or equal to `.`/`..`), and
raises `ValueError` specifically so the refusal cannot be read as "no such secret" and fall
through to a dev-stub credential [read: `safe_agents/broker/runtime/secrets.py:166-178`].

**Why the rule is forced, not preferred.** The leaf-only constraint *is* the traversal guard. Any
convention that encodes scope *inside* the name requires loosening that guard — trading a
directory-confinement property for a naming preference. Note this indicts **both** historical
Lane-1 spellings equally: `safe-agents/{env}/agents/{agent}/oauth-token` and
`{agent}/claude-oauth-token` are each unusable as a `dir` filename as written. The rule above is
not "the other one of the two"; it is the only one of the three shapes that survives all the arms.

Enforcement is uneven, and the weak spot is worth naming: `LocalFileSecretsProvider` is a flat
JSON map with no separator check [read: `safe_agents/broker/runtime/secrets.py:110-114`], so on
the `file` arm the rule is upheld by whoever **writes** the map — the wrapper — not by the provider. A
leaf-shaped name is what keeps the same map portable to the two arms that do enforce it.

**The IAM wildcards survive this ruling, and that is not a coincidence.** The broker's connector
grant is `secret:*/connectors/*` [read: `infra/lib/identity-stack.ts:88`], the issuer grants
are `secret:*/issuer/*` [read: `infra/lib/identity-stack.ts:291`, `:446`] and the demotion
evaluator's is `secret:*/evaluator/*` [read: `infra/lib/identity-stack.ts:380`]; the channels drain adds
`secret:safe-agents/${env}/connectors/*` [read: `infra/lib/channels-stack.ts:693`]. Every one of
them keys on a **path segment the deploying topology supplies**, never on anything the manifest
spells — which is exactly what the leaf rule guarantees stays true. A convention that let a
manifest name its own full path would put the author in a position to write a name outside the
grant, and the failure mode is a runtime `AccessDenied` no schema check catches.

**Two lanes; only one was ever contested.**

- **Connector credentials — converged.** `connector_secrets` values are bare leaves, and declaring
  a pre-prefixed path is explicitly called out as wrong [read:
  `safe_agents/broker/schemas/manifest.py:78-85`]; resolution prefixes them (sa#164). This lane
  was already at the rule above before #126 was decided.
- **Agent-runner secrets — outstanding.** The pipeline manifest's `secrets:` block takes **full
  secret ids** typed by the author (`my-agent/deploy-key`) [read:
  `safe_agents/pipeline/manifest.py:32-68`], while the Fargate arm *constructs* an env-prefixed
  path for the same logical secret [read: `safe_agents/arms/fargate/provision.py:201`]. That
  divergence is #126's problem 1, and it lives entirely here. This lane **migrates to the leaf
  rule**; the cloud-side rename and env-prefixing (#126's problem 2) is deliberately deferred and
  still tracked on #126.

**Consequence for a local wrapper.** Credential relocation (#253) operates in the *converged* lane,
so the local secret format publishes no new convention: the leaf is the bare `server_id`, and the
per-project directory under the wrapper's home plays the prefix's role — the same move the `dir` arm
makes with its mount root. The wrapper's lockfile still records no secret location at all, so this
resolution remains changeable store-side.

## The anti-pattern — the unified config store

The tempting consolidation — "put all configuration in one table / one YAML / one admin UI for
DX" — is precisely the thing this doctrine forbids. **Never consolidate config surfaces for
convenience: the split IS the control.** One unified surface means one injection point whose
compromise reaches every layer at once — a store write becomes code execution, an admin-UI XSS
becomes a grant promotion. The friction of "why do I have to edit three places?" is the same
friction as the broker itself: the separation is the mechanism. (An SDK may *present* the layers
coherently — one CLI with `manifest` / `envelope` / `deploy` / `secrets` subcommands — as long as
each subcommand writes only its own surface with its own provenance; presentation may unify,
storage and mutation paths must not.)

## Conformance angle

Part of this is already CI-enforced: the sa#139 grep-guard + AST consumer-boundary guard keep
consumer identity out of base source, and the sa#141 rule (providers honored only from the
image-baked manifest) is enforced in the loader itself. A config-provenance conformance check
would add, in the same core CI stage:

1. **No import-path-shaped strings in store-loaded schemas** — partially enforced today:
   `TestStoreCannotInject` (`test_connector_providers.py`) proves the Envelope schema carries no
   provider/import-shaped field and that a provider-carrying store document fails validation. The
   generalization: every selector field in *any* store schema must be a closed enum or registry
   key, checked structurally rather than by known-bad names.
2. **Store schemas provably closed-vocabulary** — every store field an enum, bounded numeric, or
   typed reference — with a named exception to encode: `Caps`/`Allowlists` are deliberately
   `extra="allow"` (future caps ride into the hash without a schema change) and the Envelope
   carries typed-dict placeholder fields. Those extras cannot name code and are inert until base
   code consumes them, but a conformance check must either encode that exception explicitly or
   force the migration to typed sub-models.
3. **Loud rejection of unknown store keys** — enforced at the Envelope top level today
   (`extra="forbid"` + validate-on-load in both store implementations); the remaining gap is the
   sub-model carve-outs above, where an uncatalogued field could accrete unnoticed.

## Relationships

- `docs/friction-doctrine.md`, `docs/contract-vs-reference.md` — the sibling lenses: gate-vs-log,
  packaging tier, and (this doc) placement. A new mechanism should pass all three.
- `docs/GAL.md` §5 / #123 — the ceremonies are Layer 2's mutation path; `seed`/`re-seed`/
  `propose`/`ratify` are provenance events on the store.
- `broker/TAINT.md` §1.1 — the Biba lattice this doctrine reuses; store-config-never-writes-up is
  no-write-up applied to configuration.
- `broker/SCHEMAS.md` (AgentManifest, Envelope) — the Layer-1 and Layer-2 contracts.
- #106 (SDK extraction) — the consumer-facing reason this doc exists; the SDK boundary must
  preserve the surface split (see the anti-pattern's presentation-vs-storage rule).
- `auto-agents/tool-broker-sketch.md` §request-envelope (auto-agents@0f72c49) — the corpus prose
  for the lattice.
- Standalone essay / short-paper (standards-adjacent artifact #3) — stays tracked on #186.
