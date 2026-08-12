# restricted_mcp_server — restrict-by-construction (the missileer archetype, #174)

A **fictional** example MCP server that makes the strongest MCP control visible: a
bespoke server exposing **only** safe tools, so the dangerous op is **absent, not
denied**. It is the worked instantiation of `broker/MCP-HOST.md`
§"Restrict-by-construction — the missileer archetype".

## Why absence beats denial

MCP discovery carries no trust model: a server names its own tools and can change
them between connections, so the broker treats discovery as untrusted input and
admits a tool only through a two-key ceremony a human ran. That machinery governs
the tools that *exist*. For a **high-blast** surface, the cheaper and stronger move
is to remove the hazardous capability from existence entirely.

The missileer does not decide whether to launch — the launch capability is not on
their console. A consumer that needs an agent to read a ledger but never post to it
ships a server whose tool set has no append and no delete: there is nothing to
admit, nothing to quarantine, nothing to deny, because the capability was never
advertised. A denied tool still exists (a gate can be misconfigured, a drift can
slip, a store row can be tampered); an absent tool cannot be reached by any of
those paths, because it isn't there.

## What this server exposes

`server.py` is a small FastMCP server (`ledger`) with **exactly two** read-only
tools, both returning **structured** (typed) data:

| tool | signature | returns |
|---|---|---|
| `get_entry` | `get_entry(entry_id: str)` | one typed `LedgerEntry` |
| `list_entries` | `list_entries(limit: int)` | a bounded `LedgerPage` of entry ids |

There is **no** `append_entry`, `delete_entry`, `post_adjustment`, or admin tool.
Adding one is a code-reviewed change to the server source — not something a
compromised agent or a swapped store row can reach.

## What it composes with

Absence removes a capability; the registry governs the ones that remain. The two
tools this server *does* expose are ordinary MCP tools and ride the full base
machinery unchanged:

- **Declared** — `manifest.yaml` pre-declares the `(ledger, get_entry)` /
  `(ledger, list_entries)` namespace under `mcp_servers` (key #1, image-baked), and
  gives each its external-read `ToolOp` in `tool_ops`. The manifest half must be
  complete: a declared tool with no matching `ToolOp` refuses at load.
- **Admitted + hashed** — each tool becomes callable only when a human-admitted
  registry row's discovery-hash matches what the server advertises now; a changed
  schema or description is drift and fails closed (key #2, `broker/MCP-HOST.md`).
- **Taint-tracked** — a tool response is an external read that taints the turn, so
  a later external write rides the standing lethal-trifecta cut.
- **Structured-only trust** — because both tools return structured output, either
  may be named in `envelope.trusted_read_sources` to suppress its response taint.
  This manifest trusts `connector:ledger.get_entry`. Naming a **free-text** tool
  there is refused at manifest load — free-text output is injection surface.

## How you'd run it

```bash
# Serve the restricted tool surface over stdio:
python -m examples.restricted_mcp_server.server

# Validate the example manifest is honest (no mcp SDK needed for this):
python -m pytest examples/restricted_mcp_server/ -q
```

A real deployment supplies its own manifest via `BROKER_MANIFEST` and lives in its
own repo; this exists to demonstrate the archetype by construction.

## Running as a consumer of the broker (#219)

The example is deployable end-to-end, not just declarative:

- **Native construction (#221)** — the manifest's `mcp_servers.ledger` block
  declares the spawn config (`command: python3`, `-m` the server module), and
  `build_runtime` composes the base `McpConnector` + `stdio_host_factory` +
  the admitted-tool registry itself — no consumer provider class at all. The
  server runs as a stdio **child process of the broker task** — no separate
  service — behind the two-key admission gate, reading the registry named by
  `MCP_REGISTRY_TABLE_NAME` under the broker's own HMAC key. (The pre-#221
  `provider.py` that hand-rolled this wiring is retired; a consumer today
  ships only its server, manifest, and image layer.)
- **`Containerfile.broker`** — the consumer image layer (base broker image +
  the `mcp` SDK + this package), mirroring a consumer's own `Containerfile.broker`;
  the task definition injects `BROKER_MANIFEST` pointing at this manifest.
- **`peer.publish`** — the manifest's one outbound capability, which gives the
  taint floor live teeth on this principal: an untrusted `list_entries` read
  taints the turn so a same-turn publish escalates on the standing
  `tainted_external_write` cut, while the trusted `get_entry` read leaves the
  same publish flowing. Both branches of M9/M10 on one small surface.

One provisioning note: the broker's Doer resolves a credential for **every**
connector before dispatch, so even this credential-less local server needs its
declared secret leaf to exist — provision `ledger-mcp-placeholder` under the
broker secret prefix (`<prefix>/connectors/ledger-mcp-placeholder`) with an
empty-string value before first dispatch (and `peer-mcp-example` with a peer
descriptor before exercising the publish leg).

## Honest, not decorative

`safe_agents/broker/tests/test_example_restricted_mcp_server.py` proves the manifest
validates as written **and** that
each invariant refuses a mutated copy: adding an undeclared tool (no `ToolOp`)
refuses, and flipping the trusted tool's `structured_output` to `false` refuses. A
fourth check asserts the running server's tool set is exactly the two safe tools —
the absence claim is machine-checked, not just asserted. The safety is in the
schema and the server surface, not the prose.

## Relationships

- `broker/MCP-HOST.md` — the two-key admission contract and the
  restrict-by-construction doctrine this instantiates.
- `safe_agents/broker/schemas/{manifest,mcp_registry}.py` — the `AgentManifest` /
  `McpServerDecl` the manifest validates against.
- `examples/scoped_s3/` — the sibling confinement example (per-capability IAM
  scoping): scope what a capability *can do*; here we remove it from existence.
