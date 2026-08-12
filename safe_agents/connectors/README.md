# safe_agents.connectors — the connector boundary

A **connector** is the only component that touches a real external API. The broker's
Doer is the *sole* holder of connector instances; the agent process never receives a
connector reference — its only path to an external effect is through the broker
(`agent → broker → Doer → connector`). "Call the API directly" is not a path that
exists from anything the agent can reach.

This package draws the **shared-vs-agent-owned** line.

## What lives here (shipped in the SDK)

| Symbol | Purpose |
|---|---|
| `Connector` | The Protocol the Doer dispatches to (`execute(tool, op, args, credential)`). Re-exported from its canonical home `safe_agents.broker.runtime.connector`, where the Doer imports it. |
| `ConnectorCall`, `StubConnector` | Deterministic test doubles (no network, no real credentials). |
| `GitHubConnector` | Read-only `github.whoami` (`GET /user`) with a broker-injected token. |
| `TelegramConnector` | `notify.send` — outbound notification with a broker-injected bot token. |
| `LedgerConnector` | `ledger.append` — durable, append-only brief/ledger-delta sink (S3); the destination bucket/prefix come from the broker-injected credential, never from args. |
| `SearchConnector` | `search.query` — external web search (Tavily-backed) for groundedness verification; the source endpoint comes from a code-resident table keyed by the credential's provider, never from args. **Results are untrusted free-text web content** — the broker self-ingests every successful external read into the TurnContext (sa#134), so the turn is tainted and a subsequent external write escalates to require_approval. |
| `PeerConnector` | `peer.publish` — A2A transport: POSTs a broker-stamped `EventTrigger` to a peer agent's airlock with a shared secret-token header (#172). It speaks our own protocol to our own airlock, so its transport is platform mechanism; shipping the canonical connector makes `stamp_outbound` non-bypassable. Its endpoint + secret stay consumer-supplied via `connector_secrets`. |

These are **genuinely shared**: domain-invariant connectors that more than one agent
can reuse. Import them from one place:

```python
from safe_agents.connectors import Connector, GitHubConnector, TelegramConnector
```

## What does NOT live here (agent-owned)

**Single-agent connectors are owned by the agent that needs them, not the base
platform.** The canonical example is a consumer agent's `ExampleConnector` (`example.read`):
it is specific to one agent's domain, so it belongs in that agent's repo.

The base platform therefore has **no hard dependency on any single-agent connector** —
importing `safe_agents.connectors` (or `safe_agents.broker`, or `safe_agents.pipeline`)
pulls in no agent-owned connector code. An agent ships its own connector class in its image layer and
declares it in the AgentManifest (the sa#141 injection seam) — the broker loads it,
protocol-checks it, and maps its secret name; the agent process still never touches it:

```yaml
# the consumer's image-baked manifest (the ONLY source providers are honored from)
connectors: ["github", "example"]
connector_providers:
  example: "my_agent.connectors.example_connector:ExampleConnector"  # agent-owned class
connector_secrets:
  example: "my-agent/example-keys"   # secret NAME (default: the tool name)
```

Direct `Doer(connectors={...})` construction remains the low-level seam for tests and
embedders; production composition goes through `build_runtime(manifest)`. The honest
worked example is `examples/missileer/trackfeed_connector.py`.

### Transitional note

`ExampleConnector` is now **fully removed from the base** (#172): it no longer sits
under `safe_agents.broker.prototype`. A consumer that needs it injects it via
`connector_providers` (the consumer's broker image carries the class). That boundary
is what guarantees the SDK core does not depend on any single-agent connector.
