# emailer — a fictional A2A *sender* (the outbound half of the driving case)

A **fictional** example consumer demonstrating the outbound channels seam,
`peer.publish` (`channels/PUBLISH.md`, sa#156). Where `webhook-peer/` supplies the
**receiver** airlock (a `ChannelsManifest`), this one supplies the **sender**: a broker
`AgentManifest` granting exactly one outbound capability, `peer.publish`, and the
consumer-owned `peer` connector that transports it. Together they are the sa#8 driving
case end to end — email-agent → example-agent — with the boundary the platform exists to
enforce running between them.

## What it shows

An email-watching agent reads inbound email (untrusted content), and when it recognizes a
trade confirmation, publishes a normalized signal to a peer agent's airlock. Three
properties, none of which the agent can subvert:

- **It holds no peer credential.** The only outbound op is the brokered `peer.publish`;
  the peer endpoint URL and shared secret live in the broker-held connector credential, so
  a fully compromised agent can still only *ask* the broker to publish
  (`channels/PUBLISH.md` P1).
- **Its provenance is broker-stamped.** The outbound `EventTrigger` is built by
  `stamp_outbound` (`safe_agents/channels/publish.py`) from the sending turn's taint state
  — the agent authors the *intent* (target principal, event_id, payload), never the
  provenance or the taint label (P3/P4). The `peer` connector
  (`safe_agents.connectors.PeerConnector`, shipped in the base SDK) is pure transport: it
  validates and POSTs the stamped envelope, and never touches provenance.
- **A tainted publish cannot go out autonomously.** Because the agent read untrusted email
  upstream, the turn is tainted, and `peer.publish` (`external=True, effect="write"`) hits
  the standing `tainted_external_write` cut → `require_approval`. The abstain-safe polarity
  makes that gate the *safe* outcome (P2).

## The `peer` connector (now a base builtin, #172)

The `peer` connector ships in the base SDK as `safe_agents.connectors.PeerConnector`:
`peer.publish` speaks our own protocol to our own airlock (EventTrigger, `/inbound`, the
provenance chain — all base), so its transport is platform mechanism, not domain code, and
shipping the canonical connector makes `stamp_outbound` non-bypassable by construction.
This example just *names* it — it resolves from the base registry, no provider path needed:

```yaml
connectors:
  - peer
connector_secrets:
  peer: "peer-example-agent"     # a LEAF (sa#164): resolves under <prefix>/connectors/
```

Its class is base, but the secret + endpoint stay consumer-supplied (they vary per
deployment). The secret VALUE is the JSON peer descriptor `{url, token_header, token}` the
connector authenticates with — the sending mirror of the receiver's `SignedWebhookAdapter`
secret-token gate.

## Files

- [`manifest.yaml`](manifest.yaml) — the broker `AgentManifest` granting `peer.publish`.

The `peer` connector itself is shipped in the base SDK
(`safe_agents.connectors.PeerConnector`); this example only names it.

## Relationships

- `channels/PUBLISH.md` — the outbound-seam contract this example instantiates.
- `channels/TRUST-MAPPING.md` §"The one-way rule — sender side" — why the provenance is
  broker-stamped.
- `examples/webhook_peer/` — the complementary *receiver* airlock; publish here, receive
  there.
