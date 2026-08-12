# oauth_remote_mcp — reference REMOTE MCP credential-delivery consumer (#237)

Proves the last unwired seam in the MCP host: a **vendor-hosted** MCP server that
requires bearer auth, reached through the broker with the credential resolved
broker-side and never visible to the agent (`broker/MCP-HOST.md` M25,
`broker/CONNECTOR-AUTH.md` C10).

Before this, a hosted server needing auth was *not wireable through the
sanctioned path at all*: `env_map` is spawn-time delivery and a remote server has
no child to spawn, so a remote decl carrying one refused at manifest load. The
gap was delivery, not strategy — `oauth_refresh` already minted a short-lived
access token from a broker-held refresh token, and it is used here **unmodified**.

## What a consumer actually writes

`manifest.yaml`, and nothing else. There is no connector class, no
`connector_providers` path, and no new `AuthStrategy` — the strategy catalog is
base-owned and closed, so a manifest *selects and configures* a strategy and can
never inject one. Three declarations do the work:

| block | says |
|---|---|
| `mcp_servers.vendor_mcp` | the namespace + the remote `url` (image-baked-only) |
| `connector_auth.…strategy` + `params` | how the credential is **obtained** |
| `connector_auth.…header_map` | where the resolved credential **goes** |

`header_map: {Authorization: {scheme: Bearer}}` is the whole delivery
declaration. It names a header, never a credential. The `Bearer` framing lives on
the delivery side rather than inside the strategy because it is transport
framing, not credential material — which is precisely why no new strategy was
needed.

## The one thing worth copying deliberately

**`respawn` is declared, and here it is a credential decision.** Resolution
happens once per *connect*. An expired access token surfaces as a
transport-family death, so the reconnect is what re-mints it — the M18 clause
("a reconnect is a new discovery") re-runs the credential resolver in the same
re-entered context. `respawn` ships **OFF**; without it the M19 fork leaves the
session dead and the token is never renewed. A remote server on an expiring
credential wants this block, and a static header set would replay a dead token
forever.

## Fictional, and what proves the real thing

The URLs here resolve to nothing. The wire-level proof lives in
`safe_agents/broker/tests/test_mcp_remote_oauth.py`, against a toy server that
**genuinely 401s** an unauthenticated request and mints tokens from a real
refresh-grant endpoint — so "the call succeeded" can only mean the credential was
delivered. That suite also pins the properties this example depends on: the
bearer the *server* received is the one the broker minted, a reconnect re-mints
rather than replays (tokens carry the server's pid, so a restart invalidates
them), and neither the refresh token nor the minted bearer reaches the logs.

## Siblings

- `examples/oauth_api/` — the `oauth_refresh` strategy itself, on a plain
  consumer-owned connector.
- `examples/alpaca_paper_drill/` — the same credential seam delivered the *other*
  way, as `env_map` into a spawned stdio MCP child.
- `examples/restricted_mcp_server/` — restrict-by-construction, where the
  dangerous op is absent rather than denied.
