# oauth_api — reference `oauth_refresh` credential-strategy consumer (#173)

Proves the connector-auth-strategy seam (PTC Phase 3a): the broker mints a
short-lived OAuth **access token** from a broker-held **refresh token**, and hands
only the access token to the connector — the agent and the connector never see the
refresh token, and the connector never sees or emits the access token it was given
either.

- `manifest.yaml` — declares `connector_auth: {api: {strategy: oauth_refresh, ...}}`
  alongside the consumer-owned `api` connector (via the sa#141 `connector_providers`
  seam) and its `api.query` `tool_ops` classification.
- `oauth_api_connector.py` — the consumer-owned connector; treats its `credential`
  argument as an opaque bearer token, requires it non-empty, never logs/echoes/
  returns it.

Fictional and deterministic — no real network call, no real OAuth provider.

See `broker/CONNECTOR-AUTH.md` for the full contract this example instantiates,
and `examples/missileer/` for the sibling `connector_providers` example this one
mirrors in structure.
