# registry — capability-scoped tool registry and agent catalog

> **Status: design pending.** This directory is a scaffold. Epic: registry & governance (sa#10).

The broker serves each agent a capability-scoped tool list — the agent cannot see a tool it was
not granted. This directory owns the mechanism that makes that true: the registry that maps
principals to their allowed tools, the agent catalog that declares each agent's manifest, and the
governance layer that detects when declared intent and runtime behavior have drifted apart.

## The registry

The PEP (in `broker/`) consults the registry at every tool call to decide what tool surface to
serve. The registry is **not** a runtime lookup — it is **policy-as-code**, reviewed like any
other code, so adding a capability to an agent requires a code change and review, not a runtime
API call. This is the difference between "the model chose not to use it" and "the model could not
reach it."

The registry is keyed by `(principal, action-class)`. The PEP serves only the slice of the tool
list the principal's active grants cover. A capability that does not appear in the slice does not
exist in the agent's world — no prose, injection, or model error can reach it.

See `broker/README.md` §"Capability-scoped registry" and `ARCHITECTURE.md` §"The base/per-agent
split" for the design rationale.

## The agent catalog

Each agent is declared by a manifest (`core/agents/<name>.yaml`, schema in
`core/manifest-schema.md`). The catalog here is the **reconciliation layer** on top of those
manifests: a machine-readable index of every declared agent, its granted action-classes, its
current autonomy level (`in-loop` / `on-loop` / `out-of-loop`), and its named grant owners.

The catalog exists so governance tooling has a single authoritative view — "what is every agent
allowed to do, and who is responsible" — without grepping manifests.

## Declared-vs-actual governance and drift detection

A manifest declares what an agent is supposed to do. The runtime rollup (cost, activity, broker
decisions, audit records) shows what it actually did. The gap between the two is **capability
drift** — an agent steadily using action-classes near the edge of its grants, or never using a
capability that was granted months ago.

The drift detector reconciles the declared manifest against the runtime rollup from the audit log
and DynamoDB counters, and surfaces:

- **Creep alerts:** actual activity approaching envelope boundaries (error budget, blast limits)
  before a hard breach.
- **Dead-grant reports:** capabilities granted but never exercised over a rolling window — prune
  candidates.
- **Undeclared-use alerts:** broker approved a tool the manifest didn't list as an expected
  action-class — triggers a manifest review.

Drift feeds back into the promotion/demotion loop: a persistent creep pattern is evidence for
re-evaluation of the grant level. See `audit/README.md` for the learning loop that consumes these
signals.

## Relationships

- `broker/` — the PEP consults this registry; the broker does not own the catalog.
- `audit/` — drift detection reads the runtime rollup from the audit log and counters.
- `core/manifest-schema.md` — the per-agent manifest this catalog indexes.
- `infra/` — the DynamoDB tables that back the grant store and activity counters.
