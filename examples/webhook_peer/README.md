# webhook-peer — a fictional A2A peer airlock + drain consumer

A **fictional** example consumer, now standing on BOTH channels seams: the inbound
airlock (a `ChannelsManifest`) that admits its one mapped peer, and — since the webhook drain landed —
the drain (a broker `AgentManifest` + `Receiver`) that lets an airlock-accepted
envelope drain end-to-end to a ledger. Together they are the A2A driving case
worked all the way through: a peer POSTs, the airlock admits and stamps it, and the
drain records it, exactly once.

## Airlock

Where the other examples here (`missileer/`, `sepsis-detection/`) supply only a broker
`AgentManifest`, this one ALSO supplies a **`ChannelsManifest`**
(`safe_agents/channels/manifest.py`): the entire inbound airlock as config, with no base
source changed.

## What it shows

The A2A driving case — a peer agent reaching this agent over A2A. The peer POSTs an
`EventTrigger` envelope to a signed webhook; the airlock verifies the shared token, maps
the peer identity to a principal, dedupes, (optionally) screens, and stamps its own
provenance hop before the envelope reaches a worker. The airlock loop itself is
channel-agnostic — everything peer-shaped lives in `channels-manifest.yaml`:

- **one trust-map row** admits `peer:example` as principal `example-agent`, sender class
  `peer-agent`. An empty trust map (the base default) drops every sender; this row is the
  single deliberate admission.
- **`zone`** is this airlock's id (`webhook-peer-example`), and the `audience` a peer
  must write on an envelope meant for it. An envelope addressed to any other zone is
  dropped `audience_mismatch` at gate 3, before its signature is looked at
  (`channels/SIGNING.md` S9). The field is required and has no default. The check tells
  receivers apart only by zone id, so each deployed airlock needs its own, and so does
  each environment of the same agent; nothing verifies that across deployments. The
  screened variant (`channels-manifest-screened.yaml`) declares
  `webhook-peer-screened-example`, so a peer addressing an airlock built from it writes
  that id.
- **the screen is OFF** (no `screen:` block) — the friction-doctrine default
  (`docs/friction-doctrine.md`). Authenticity is not content trust: an admitted peer's
  payload still rides through as `peer-agent` provenance, tainting exactly as its chain says.

Every value is obviously-example and lives ONLY here — never in `safe_agents/` (the CI
consumer-boundary guard enforces that).

## Drain

`inbound_log_receiver.py`'s `InboundLogReceiver` is the drain's `Receiver`
(`channels/DRAIN.md`) for this consumer, the deliberate CONTRAST to missileer's
`duty_log_receiver.py`. Missileer is the always-tainted internal-observer
archetype — it trusts nothing, so every drained envelope taints the turn.
webhook-peer is the peer-agent INBOUND archetype: its airlock already admits its
one mapped peer, so this receiver's own trust map extends that same trust to the
drain side, trusting sources prefixed `"peer:"` or `"channel:"` — an envelope the
airlock accepted (carrying a `peer` origin hop and a `channel:webhook` stamp hop)
drains UNTAINTED. It is still abstain-safe: the only op granted
(`drain-manifest.yaml`'s sole `grant_classes` entry) is an observation
(`ledger.append`); there is no effecting op to escalate to, so any non-allow
broker outcome is itself the safe, complete handling of the envelope.

## Files

- [`channels-manifest.yaml`](channels-manifest.yaml) — the `ChannelsManifest` the airlock
  is built from (`build_airlock`).
- [`Containerfile.airlock`](Containerfile.airlock) — FROMs the base channels-airlock image
  and COPYs the manifest to `/var/task/channels-manifest.yaml`, pointing `CHANNELS_MANIFEST`
  at it.
- [`drain-manifest.yaml`](drain-manifest.yaml) — the broker-facing `AgentManifest` the
  drain worker builds its runtime from (`build_runtime`); distinct schema from the
  `ChannelsManifest` above.
- [`inbound_log_receiver.py`](inbound_log_receiver.py) — the `Receiver` the drain worker
  loads by dotted path (`CHANNELS_DRAIN_RECEIVER`).
- [`Containerfile.drain`](Containerfile.drain) — FROMs the base channels-drain image and
  COPYs this package, pointing `CHANNELS_DRAIN_MANIFEST` / `CHANNELS_DRAIN_RECEIVER` at it.

## Relationships

- `channels/ADAPTERS.md` §"Reference bindings" / §"The two named inbound cases" — the peer
  channel this manifest instantiates.
- `channels/TRUST-MAPPING.md` — the one-way rule the `sender_class` here rides.
- `safe_agents/channels/{manifest,webhook,stores}.py` — the typed config, the signed-webhook
  adapter, and the DynamoDB/S3 seams the Lambda handler binds.
