# owner-channel — a fictional human-as-owner airlock + drain consumer

A **fictional** example consumer for the sa#176 owner channel, standing on BOTH channels
seams: the inbound airlock (a `ChannelsManifest`) that admits its one mapped human owner,
and the drain (a broker `AgentManifest` + `Receiver`) that lets an airlock-accepted owner
command drain end-to-end to a ledger. It is the human-as-owner complement to
`webhook_peer/` (the peer-agent case): where a peer POSTs a full `EventTrigger`, here a
**human owner sends a raw command** over an authenticated transport and the airlock
CONSTRUCTS the envelope. (`Telegram`, a chat app, or an SMS gateway are plausible
transports — but the transport is a consumer-side illustration, never a base literal.)

## Airlock

Like `webhook_peer/`, this consumer supplies a **`ChannelsManifest`**
(`safe_agents/channels/manifest.py`): the entire inbound airlock as config, with no base
source changed. What differs is `adapter.kind: owner`, which selects `OwnerInboundAdapter`
via `ADAPTER_REGISTRY` (the default — kind absent — stays the signed-webhook adapter, so
the owner adapter is an explicit opt-in).

The owner adapter's `normalize` is the heart of the difference: the owner sends a raw
command, not an envelope, and `normalize` builds a **fresh-chain `EventTrigger`** from it
with a single seed provenance hop. The consumer's transport shim wraps the raw command in
a small JSON body the adapter parses:

```json
{
  "sender": {"channel_type": "owner", "channel_identity": "owner@example.com"},
  "event_id": "evt-2026-07-11-0001",
  "text": "/observer note the morning digest looked healthy",
  "ts": "2026-07-11T14:00:00Z",
  "expiry": "2026-07-11T14:05:00Z"
}
```

The shared secret token rides in the `x-airlock-token` header (verified constant-time at
gate 1, before the body is parsed); the token lives in Secrets Manager, never in the
manifest.

## What it shows

The sa#176 driving case — a human owner reaching this agent as the OWNER sender class. The
airlock verifies the token, reads the sender identity, `normalize`s the command, maps the
owner identity to a principal, dedupes, and stamps its own provenance hop before the
envelope reaches a worker. The airlock loop itself is channel-agnostic — everything
owner-shaped lives in `channels-manifest.yaml`:

- **`routing`** is friendly-name → principal indirection consumed ONLY by the owner
  adapter's `normalize`. The leading whitespace token of the raw command is the address; a
  HIT maps the friendly token (`/observer`) to the deployment principal, a MISS passes the
  raw token through as the *claimed* principal so gate 5 rejects it `principal_mismatch`.
  This is ergonomic indirection, NOT a second allow-list — the **trust map is the sole
  authorization authority** (gate 5 never sees the token). An address-less message raises
  → gate-3 `malformed`; NO default principal is ever synthesized. At N=1 every address
  maps to the one example principal.
- **one trust-map row** admits `owner@example.com` (as `channel_type: owner`) as principal
  `owner-example-agent`, sender class `owner`. An empty trust map (the base default) drops
  every sender; this row is the single deliberate admission.
- **`sender_class: owner` is a FLOOR, never a grant.** It is stamped at gate 8 from the
  trust map and RAISES the owner's action surface, but it does NOT map owner → auto-allow
  or shortcut any gate. The broker still decides every call; there is no owner bypass.
- **the screen is OFF** (no `screen:` block) — the friction-doctrine default
  (`docs/friction-doctrine.md`). Authenticity is not content trust.

### The `/approve <intent_id> yes|no` flow

The owner channel carries approvals on the SAME transport. When the owner replies
`/approve <intent_id> yes` (or `no`), `normalize` classifies it into an **approval-kind**
payload (`{"kind": "approval", "intent_id": ..., "decision": ...}`) rather than a command.
The **base drain handler** (`channels/drain/handler.py`) forks this envelope BEFORE any
receiver runs: on `sender_class == "owner"` AND `payload.kind == "approval"` it calls the
broker's `approve_intent` / `reject_intent` seam, actioning the STORED materializedRequest
(WYSIWYE). The fork REQUIRES the airlock-stamped `owner` class (unforgeable on the wire),
so a non-owner envelope carrying an approval-shaped payload does NOT fork — it falls
through to the normal turn where the broker decides every call. `approved_by` is the
AUTHENTICATED owner identity (`owner:<channel_identity>`), never read from the payload.

The consumer-owned `Receiver` in this example therefore handles only the COMMAND path.

Every value is obviously-example and lives ONLY here — never in `safe_agents/` (the CI
consumer-boundary guard enforces that).

## Drain

`owner_command_receiver.py`'s `OwnerCommandReceiver` is the drain's `Receiver`
(`channels/DRAIN.md`) for the owner COMMAND path. Its own trust map extends the trust the
airlock already granted the owner, trusting sources prefixed `"owner:"` or `"channel:"` —
an envelope the airlock accepted (carrying an `owner:` origin hop and a `channel:` stamp
hop) drains UNTAINTED. That "trusted" label is still a floor, never a grant: a source
outside those prefixes taints the turn regardless. It is abstain-safe: the only op granted
(`drain-manifest.yaml`'s sole `grant_classes` entry) is an observation (`ledger.append`);
there is no effecting op to escalate to, so any non-allow broker outcome is itself the
safe, complete handling of the command.

## Files

- [`channels-manifest.yaml`](channels-manifest.yaml) — the `ChannelsManifest` the airlock
  is built from (`build_airlock`); selects the owner adapter and carries the `routing`
  and `trust_map` blocks.
- [`Containerfile.airlock`](Containerfile.airlock) — FROMs the base channels-airlock image
  and COPYs the manifest to `/var/task/channels-manifest.yaml`, pointing `CHANNELS_MANIFEST`
  at it.
- [`drain-manifest.yaml`](drain-manifest.yaml) — the broker-facing `AgentManifest` the
  drain worker builds its runtime from (`build_runtime`); distinct schema from the
  `ChannelsManifest` above.
- [`owner_command_receiver.py`](owner_command_receiver.py) — the `Receiver` the drain
  worker loads by dotted path (`CHANNELS_DRAIN_RECEIVER`) for the owner COMMAND path
  (approvals fork in the base handler before it).
- [`Containerfile.drain`](Containerfile.drain) — FROMs the base channels-drain image and
  COPYs this package, pointing `CHANNELS_DRAIN_MANIFEST` / `CHANNELS_DRAIN_RECEIVER` at it.

## Relationships

- `channels/ADAPTERS.md` §"Reference bindings" / §"The two named inbound cases" — the owner
  channel this manifest instantiates.
- `channels/TRUST-MAPPING.md` — the one-way rule the `sender_class` here rides; owner is a
  floor, never a grant.
- `safe_agents/channels/{manifest,owner,trust_map}.py` — the typed config, the owner
  adapter (raw command → fresh-chain envelope), and the trust-mapping seam.
- `examples/webhook_peer/` — the peer-agent inbound complement to this human-as-owner one.
