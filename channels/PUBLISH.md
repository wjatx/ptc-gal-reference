# PUBLISH — the outbound seam (agent-to-agent `peer.publish`) (sa#156)

> **Status: contract (2026-07-09).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, the base `peer.publish` manifest entry
> (`safe_agents/broker/manifest/__init__.py`) plus the `stamp_outbound` helper
> (`safe_agents/channels/publish.py`) are the typed encoding, and
> `safe_agents/channels/tests/test_publish.py` is the conformance suite. The reference `peer`
> connector — the one wire binding — is **reference-tier** and lives in `examples/` (a consumer
> owns the endpoint and shared secret; the base names neither). The driving use case is the A2A
> agreement on sa#8 (email-agent → a consumer agent, 2026-07-08): the sender's broker publishes; the
> receiver treats it as an ordinary sender at its airlock (`channels/TRUST-MAPPING.md`).

## What `peer.publish` is — and what it is not

`peer.publish` is the outbound half of the channels seam: a sending agent emitting an
`EventTrigger` (`channels/SCHEMAS.md`) **to a peer agent's airlock**. It is the publish seam named
in the envelope contract ("A sending agent's outbound path emits an EventTrigger through its own
broker"). One record type crosses the zone boundary; the receiver re-validates and re-gates it as
an ordinary inbound signal.

It is **not** the notifier. The notifier (`channels/README.md` §Outbound, the `notify.send` op /
`OutboundAdapter.deliver`) delivers *this agent's rendered reply* back to the human on the
originating channel, and carries the out-of-band approval path. `peer.publish` is a **new signal
addressed to a different agent's principal**, not a reply on an open conversation. The two are
distinct ops with distinct connectors; do not conflate them.

Three properties define the seam, each a contract clause below:

1. **Brokered — the agent holds no peer credential.** Exactly the floor every connector stands on:
   the shared secret / endpoint that authenticates to the peer's airlock is held by the broker's
   Doer, never by the agent process. A fully compromised agent can still only *ask* its broker to
   publish; it cannot forge the transport authenticity the peer will verify.
2. **The sending zone's provenance is broker-stamped, never agent-authored.** The outbound chain's
   sending-zone entry — and therefore the taint the receiver will derive — is set by the broker from
   the sending turn's ingested taint state, not from anything the agent supplies. This is the
   sender-side of the one-way rule (`channels/TRUST-MAPPING.md` §"The one-way rule — sender side").
3. **No shared store.** The two zones share exactly two things: the `EventTrigger` on the wire and
   the `event_id` audit-join key (SCHEMAS C7). No database, queue, or memory is shared; the receiver
   trusts nothing but what the envelope carries and what its own gates re-verify.

## `peer.publish` is a brokered op — the base manifest entry

`peer.publish` is a domain-invariant op and lives in the base tool/op registry, the same tier as
`notify.send`:

```python
ToolOp(tool="peer", op="publish", effect="write", external=True, reversible=True)
```

- **`effect="write", external=True`** — a publish crosses a trust boundary to an external party.
  This is the *entire* trigger for taint enforcement: on a tainted turn the existing
  `tainted_external_write` floor cut (`broker/pdp/engine.py`, `broker/TAINT.md` §5) routes the
  publish to `require_approval`. No new PDP rule exists or is needed; the sender-side one-way rule is
  the broker's standing external-write floor applied to this op.
- **`reversible=True`** — a published signal is bounded-blast, not irreversible: the receiver
  re-gates everything it carries at *its* airlock, so a single publish cannot itself effect an
  irreversible action in the receiving zone. It therefore does not fire the `external_irreversible`
  cut, and an **untainted** publish is allowed autonomously (the base default). A consumer that
  wants a stricter floor tightens it in its `Envelope` — the base never forces approval on every
  publish, which would make autonomous A2A impossible.
- The **`peer` connector** that actually POSTs to a peer's airlock is consumer-supplied via the
  sa#141 injection seam (`connector_providers` / `connector_secrets`), because its endpoint URL and
  shared secret vary per deployment. The base names no peer, no URL, no secret. The reference
  implementation is `examples/…/peer_connector.py`.

## Constructing the outbound EventTrigger

The agent supplies the *intent* of a publish; the broker constructs the *envelope*. The split is
deliberate and load-bearing — the agent authors what it is entitled to author, and nothing that
could launder taint or forge provenance:

| Field | Set by | Notes |
|---|---|---|
| `event_id` | agent | the sender-chosen idempotency key (SCHEMAS: the confirmation # in the driving case). The receiver dedupes on `(sender.channel_identity, event_id)`. |
| `principal` | agent | the **target** principal at the peer the signal addresses. The receiver drops on a principal it does not serve — addressing is not routing. |
| `payload` | agent | the parsed, bounded normalization (`MAX_PAYLOAD_BYTES`). The raw original is never embedded (SCHEMAS C2). |
| `sender` | broker | `channel_type` = the **transport** the sender uses (e.g. `"webhook"`, matching the receiver adapter's own type, which its `normalize` gate enforces), `channel_identity` = the identity the receiver's trust map keys on (e.g. `"peer:example"`) — also the identity `dedupe_key()` keys on. This is transport identity, **not** a sender class — the receiver *derives* `sender_class="peer-agent"` from its own map. The agent does not get to name who it is. When a `ChainSigner` is supplied, `channel_identity` (canonicalized) is additionally bound into the signature (`channels/SIGNING.md` S1b), so the dedupe key's sender half cannot be mutated in a captured envelope without invalidating the signature. `evidence` = the transport proofs the connector will stamp. |
| `provenance` | **broker** | the sending-zone entry (and any preserved inbound chain) — **broker-stamped from the turn's taint state**. See below. |
| `sender_class` | — | absent on the wire; the *receiver* derives it (SCHEMAS C4). A sender never asserts its own class. |
| `ts` / `expiry` | broker | deterministic, caller-supplied time; `expiry` is the hard TTL the receiver checks before any budget-spending gate (SCHEMAS C6). |

### The broker-stamped provenance entry

The one clause that makes "sender cannot launder" real on the sending side:

> The sending broker sets the outbound provenance from the sending turn's taint state via
> `stamp_outbound`. If the turn is tainted, the outbound chain carries an `untrusted` entry the
> agent can neither remove nor relabel. The agent supplies no provenance and no label.

Two cases:

- **Originating a fresh signal.** The agent read the world (feeds, files, its own reasoning) and
  emits a new signal. `stamp_outbound` starts the chain with this zone's entry:
  `source = "peer:<this-agent-id>"`, `label = untrusted` iff the sending `TurnContext` is tainted,
  else `trusted`. A turn that ingested an untrusted source (an inbound brokerage email upstream) publishes
  an `untrusted` chain — non-strippable, exactly as inbound. **The real ingested sources ride the
  chain, not a collapsed bit** (P8 below): each source that tainted the turn
  (`TurnContext.to_taint().sources`, e.g. `connector:mcp-news`) is carried as its own `untrusted`
  origin hop ahead of the `peer:<this-agent-id>` hop, so the receiver derives taint from the true
  origin under its own trust map rather than seeing only `peer:*`.
- **Relaying / forwarding.** The agent is acting on an inbound `EventTrigger` it received and
  publishes onward to a further peer. `stamp_outbound` **appends** this zone's hop entry to the
  received chain and never edits prior entries (`EventTrigger.stamped`, the frozen additive path).
  The upstream `untrusted` origin rides through unchanged.

Because the label is a deterministic function of the broker-held turn — never a model judgment and
never an agent argument — a compromised agent has no path to publish a `trusted` chain over content
it read from an untrusted source. Its only escalation path is the honest one: a tainted publish is
an external write on a tainted turn, so the broker gates it to `require_approval`.

## Addressing a peer's airlock

- `principal` names the **target principal** inside the receiving zone. It is an addressing label,
  not a route: the receiver MUST verify it serves that principal and drops (never re-routes) on a
  mismatch (SCHEMAS §principal).
- The **transport binding** — the peer airlock's URL and the shared-secret / signature scheme that
  authenticates the hop — is held entirely by the `peer` connector's broker-fetched secret. It is
  reference-tier: the contract says only that the connector authenticates to the peer at the
  transport layer and stamps its `sender.evidence` accordingly.
- The receiver's trust map is authoritative for what the publish earns. The peer must be
  **pre-declared** in the receiver's `ChannelTrustMap` (as `peer-agent`) to be delivered at all; an
  undeclared sender — however well it authenticates — is dropped silently toward the sender
  (`channels/TRUST-MAPPING.md`). Authentic delivery is not content trust: a `peer-agent` hop is a
  `trusted` *hop* over a chain whose derived taint persists untouched.

## Contract clauses

- **P1 — brokered credential.** The agent process never holds the peer transport secret; the
  broker's Doer fetches it at execute time and the connector uses it without returning or logging it
  (the connector floor, `broker/runtime/doer.py`).
- **P2 — `peer.publish` is an external write.** The base manifest entry is
  `effect="write", external=True`; a tainted turn's publish escalates through the standing
  `tainted_external_write` cut. No publish-specific PDP rule exists.
- **P3 — provenance is broker-stamped and taint-preserving.** The outbound chain is set by
  `stamp_outbound` from the sending turn; the agent supplies no provenance and no label; a tainted
  turn yields a non-strippable `untrusted` entry; relaying appends and never edits.
- **P4 — the agent authors intent, not identity.** The agent supplies `event_id`, target
  `principal`, and `payload`; the broker sets `sender`, `provenance`, `ts`, `expiry`; `sender_class`
  is absent on the wire.
- **P5 — no shared store.** The only cross-zone state is the `EventTrigger` on the wire and the
  `event_id` audit-join key; nothing else is shared.
- **P6 — the receiver re-gates everything.** A publish earns delivery to a pre-declared peer only;
  authenticity raises the action surface but never cleans taint, and every downstream gate at the
  receiver runs unchanged (`channels/TRUST-MAPPING.md`, `channels/ADAPTERS.md`).
- **P7 — transport-neutral.** No clause here closes over a wire technology; the endpoint and
  signature scheme are the connector's own business and live only in reference-tier text.
- **P8 — lineage, not a collapsed taint bit** (#168, PTC §8). A fresh origination carries the turn's
  ingested taint sources (`TurnContext.to_taint().sources`) into the outbound chain as `untrusted`
  origin hops — the receiver re-derives taint from the actual source under its own map, and a human
  sees the origin. Sources already carried by a preserved inbound chain are not duplicated. This is
  *lineage fidelity* only: whether a model faithfully propagated taint through a transform is the
  banked §8 problem, unsolved by carrying sources (or by signing).

## Conformance

| Clause | Test (`test_publish.py`) |
|---|---|
| P2 | `test_peer_publish_is_external_write` · `test_tainted_turn_publish_escalates` |
| P3 | `test_outbound_provenance_is_broker_stamped` · `test_tainted_turn_yields_untrusted_chain` · `test_relay_appends_and_preserves_upstream` · `test_agent_supplied_label_is_ignored` |
| P4 | `TestAgentAuthorsIntentNotIdentity` — `test_sender_is_broker_set_transport_identity` · `test_sender_class_absent_on_the_wire` |
| P6 | `test_undeclared_peer_publish_is_dropped_at_receiver` (bridges to the trust-map suite) |
| P8 | `TestOutboundCarriesIngestedSources` — `test_fresh_origination_carries_real_source_as_origin_hop` · `test_relay_does_not_duplicate_sources_already_in_chain` · `test_receiver_rederives_taint_from_real_source` |
| P7 | the absence of any transport field is the contract text itself |

<!-- assumption-tested 2026-08-06 — P2 HOLDS (rule-11 disable → allow, absence of a publish rule confirmed); P4 HOLDS at the stamp layer (both tests mutation-verified); sender-side wiring is caller contract until #315 -->


## Relationships

- `channels/SCHEMAS.md` (sa#74) — the `EventTrigger` this seam constructs; the publish seam is named
  there. `stamp_outbound` is the sender-side mirror of `stamp_inbound`.
- `channels/TRUST-MAPPING.md` (sa#81) — §"The one-way rule — sender side" is the sender-side clause
  P3 encodes; the receiver-side derivation is unchanged.
- `broker/TAINT.md` §5 — the `tainted_external_write` floor P2 rides on; no new rule.
- `broker/SCHEMAS.md` — `peer.publish` is a `ToolOp`; the broker schemas the outbound call fills.
- `examples/` — the reference `peer` connector (the one wire binding), consumer-owned via sa#141.
