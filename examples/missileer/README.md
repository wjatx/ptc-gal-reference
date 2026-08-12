# missileer — the abstain-safe archetype

A **fictional** example consumer of the safe-agents base. A launch-watch observer that
reads sensor and track data, records what it sees, and pages a human duty officer. It
is here to demonstrate one pole of the platform's polarity-blindness claim; it is not a
deployable agent.

## The polarity choice: `abstain`

**Silence is safe.** Not launching — not acting at all — is always the safe outcome in
this domain. A missed observation is recoverable; an unauthorized launch is not. So the
manifest declares `envelope.polarity: abstain`: the broker's `abstain` verb is a
*success* here, not a degraded fallback. When in doubt, the safe move is to do nothing
and wait for a human.

This is the naive intuition's easy case (`docs/authority-change-safety.md`): increasing
authority is the risky direction, decreasing it is safe. Missileer exists precisely so
that **sepsis-detection** (the act-safe archetype, where that intuition *inverts*) has a
foil — together they prove the base makes no polarity assumption of its own.

## Why the dangerous capability is *absent*, not *denied*

Note what is missing from `grant_classes`: any effecting/launch op. The hazardous
capability is not listed and then refused per call — it is structurally out of the
served registry, so it never appears as a tool the agent can even see. A fully
compromised agent "can still only ask," and here it can only ask to read, log, and page
a human. The safe default is enforced by *absence*, which no prompt injection can undo.

## What it can do

| grant_class    | why it is safe to hold |
|----------------|------------------------|
| `search.query` | read-only observation of the world |
| `ledger.append`| append-only record of what was seen |
| `notify.send`  | page a human — escalation, never autonomous action |

`high_stakes: true` and a tight `actions_per_run` cap reflect the launch domain even
though every granted op is itself low-blast.

## The consumer-owned connector (the sa#141 seam, by construction)

Missileer also carries the worked example of **consumer-supplied connector injection**.
Its `search` is not the base `SearchConnector` but its own track-feed query,
[`trackfeed_connector.py`](trackfeed_connector.py), declared in the manifest:

```yaml
connector_providers:
  search: "examples.missileer.trackfeed_connector:TrackFeedConnector"
connector_secrets:
  search: "track-feed-token"
```

`build_runtime` resolves the name through the manifest's providers first (import +
zero-arg instantiate + `Connector` protocol check, fail-closed on any breakage), and
the Doer fetches the secret leaf `track-feed-token` instead of the default leaf
`search`. That leaf is resolved under the broker's secret prefix — with
`BROKER_SECRET_PREFIX=safe-agents/development` it fetches
`safe-agents/development/connectors/track-feed-token` (sa#164) — so the manifest
carries a bare **leaf**, never a value and never a pre-prefixed path, and the connector
uses the broker-fetched credential without ever logging or returning it. The connector
imports only the public `safe_agents.connectors` surface; the consumer-boundary AST
guard (`safe_agents/broker/tests/test_consumer_boundary.py`) gates that, and the same
suite builds this runtime end-to-end and asserts the provider class is what got wired.
Provider paths are honored only from this image-baked manifest file — nothing
store-loaded can reach the seam.

## The consumer-owned drain Receiver (the sa#155 seam, by construction)

Missileer also carries the worked example of the **channels drain's Receiver seam**
(`channels/DRAIN.md`): [`duty_log_receiver.py`](duty_log_receiver.py), injected the same
way as the connector above — an image-baked dotted provider path, here the
`CHANNELS_DRAIN_RECEIVER` environment value:

```
CHANNELS_DRAIN_RECEIVER=examples.missileer.duty_log_receiver:DutyLogReceiver
```

This is **consumer-tier code**, and that is the point. The base ships the airlock, the
drain worker, and the `Receiver` protocol — but what an accepted envelope *means* to an
agent (which brokered action to take, which sources the receiving turn trusts) changes
with domain and risk level, so per the base/per-agent split the base ships **no receiver
implementation and no default trust map**. Missileer's answer is the abstain-safe one:
observe and record — one `ledger.append` (a grant it already holds) per accepted
envelope, through the drain's brokered-call facade (`handle_request` only, no turn
controls — DRAIN.md D2) forwarding to the same runtime that ingested the envelope's
provenance chain, so a tainted chain escalates the write and any non-`allow` outcome is
itself the safe result.

Two seam mechanics the example demonstrates:

- **Its own `InputTrustMap` is a plain function.** The map is `Callable[[str], bool]`,
  so the receiver writes its policy (trust only `internal:` sources) without importing
  any broker internal — the consumer-boundary AST guard holds for this file too.
- **Idempotency (DRAIN.md D4) via the broker's own dedupe.** The queue delivers
  at-least-once and the worker ships no dedupe store, so the receiver derives its
  brokered call's `idempotency_key` deterministically from
  `(sender.channel_identity, event_id)` (digested, so the raw identity never lands in
  the enforcement store). A duplicate delivery presents the same key and the broker
  replays the stored outcome instead of appending twice — real across invocations
  whenever the enforcement store is the shared production (DynamoDB) one.
