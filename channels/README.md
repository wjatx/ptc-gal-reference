# channels — inbound airlock and outbound notifier

> **Status: contracts landed (2026-07-08); production binding deployed (sa#152, 2026-07-08).**
> The four channel contracts are normative, each with a typed encoding and a conformance suite
> under `safe_agents/channels/`:
>
> - `SCHEMAS.md` (sa#74) — the **EventTrigger envelope**: one record type at both seams, with an
>   append-only provenance chain and derived, non-strippable taint.
> - `TRUST-MAPPING.md` (sa#81) — the **inbound trust-mapping framework**: sender classes
>   (owner / peer-agent / external), authenticity ≠ content trust, the one-way rule.
> - `ADAPTERS.md` (sa#80) — the **channel-adapter interface** and the fixed airlock gate ordering;
>   wire bindings are reference-tier there.
> - `SCREENING.md` (sa#43) — the **injection-screening standard**: gate 7's semantics — a typed
>   verdict that may refuse or pass, never bless; fails closed; ships OFF.
> - `DRAIN.md` (sa#155) — the **accepted-queue drain worker**: ingest-before-act on one
>   broker-owned turn, trust-the-stamp, consumer Receiver injected image-baked.
> - `PUBLISH.md` (sa#156) — the **outbound A2A seam** (`peer.publish`): a brokered external write
>   whose provenance is broker-stamped from the turn, so the sender cannot launder taint.
>
> The driving use case is A2A (sa#8, 2026-07-08): a peer agent is just another sender at the
> airlock. The binding is the `SafeAgents-Channels` stack (`infra/lib/channels-stack.ts`): the
> reference dispatcher behind API Gateway + Lambda, every seam wired from a consumer
> `ChannelsManifest`, none from base source — the clean, agent-agnostic re-derivation of the
> proven consumer-agent SAM airlock pattern, depending on nothing in that repo. Bringup runbook:
> `docs/channels-airlock-bringup.md`.

Every agent run has two channel concerns: something that wakes it (inbound) and something that
delivers its output (outbound). This directory owns the shared platform implementations of both,
so each per-agent repo configures channels rather than reimplements them.

## Inbound — the airlock

The airlock is the structural gate between the public network and an agent arm. It enforces four
properties before anything reaches an agent (the normative gate ordering lives in `ADAPTERS.md`):

1. **Sender allow-list (trust-mapping).** Only identities the consumer's `ChannelTrustMap` names —
   as `owner`, `peer-agent`, or `external` — pass; unmapped senders are dropped silently toward the
   sender, with a PII-safe `DropRecord` logged (`TRUST-MAPPING.md`). The owner `chat_id` case is
   one row of that map, not a special path.
2. **Secret-token verification.** The transport-layer token (Telegram secret-token header, or
   equivalent per channel) is verified before the message body is read.
3. **Deduplication.** Idempotency on the transport message id (`update_id` in the Telegram case)
   against a DynamoDB table, so retries and webhook replays are no-ops.
4. **Injection screening.** The one model-judged gate (`SCREENING.md`): an injected screen may
   refuse a message — a hard drop, recorded PII-safely with a machine-code reason — or pass it. A
   pass changes nothing. The screen ships OFF; wiring one (the proven pattern uses a Bedrock
   classifier) and its strictness are consumer policy.

**Supersession (2026-07-08).** The proven pattern's "classification result is a taint signal"
model is retired by the contracts: a refusal produces no turn at all, a passing screen blesses
nothing, and turn taint derives from the provenance chain alone at ingestion
(`TRUST-MAPPING.md` §"The one-way rule", `broker/TAINT.md`) — never from classification. The
broker still enforces that a tainted turn cannot trigger an autonomous external write.

### The deployed binding (sa#152)

The `SafeAgents-Channels-{env}` stack fronts the reference dispatcher
(`safe_agents/channels/dispatch.py`, unchanged — it remains the semantic subject) with one
`POST /inbound` HTTP route and a container-image Lambda
(`safe_agents/channels/airlock/handler.py`). Every seam is bound, not baked:

- **`ChannelsManifest`** (`safe_agents/channels/manifest.py`) is the consumer's whole airlock as
  config — trust map, adapter shape, screen knob (OFF by default), verdict sink, dedupe TTL. It
  rides the consumer image layer (`examples/webhook_peer/` is the honest example); the base image
  alone carries an empty trust map and drops everything.
- The **dedupe store** is the State-stack `channel-dedupe` table; **drop records** (and, when the
  valve is on, **verdict records**) land PII-safe on the audit surface under `channels/`.
- An **accepted envelope** is enqueued (SQS) for the broker path and consumed by the **drain
  worker** (`DRAIN.md`, sa#155): per message an ephemeral in-process `BrokerRuntime` is built from
  the image-baked `AgentManifest`, the provenance chain reaches its broker-held turn via
  `ingest_chain` BEFORE any action, and a consumer-injected Receiver
  (`safe_agents/channels/drain/`, the sa#141 provider-path discipline) acts through a
  brokered-call facade over that same runtime (`handle_request` only — no turn controls, so the
  receiver cannot roll the ingested taint). The drain adds no second trust surface — it trusts
  the airlock's stamp; receiver idempotency is a contract obligation; permanently-bad records
  drop terminally (structured-logged, never redelivered).
- The **reference Bedrock classifier screen** (`safe_agents/channels/screens/`, reference-tier —
  no contract doc names it) maps classifier output deterministically onto the declared codes and
  fails closed at the seam; enabling it is a manifest + deploy-context change only.

Waking a compute arm from the accepted queue differs per arm (`core/arms.md`) and stays out of
the airlock. Conformance: the in-memory suite under `safe_agents/channels/tests/`, plus two
opt-in live smokes (`test_airlock_live.py`, `test_airlock_live_screened.py`) that drive the
deployed endpoint through the same gate matrix.

**Reference pattern:** a consumer agent's SAM inbound-airlock stack (`responsive-agent-airlock-production`,
us-east-1) — the proven implementation this binding was re-derived from, learned from and importing
nothing: manifest-driven principal config instead of Telegram/owner hardcoding, the generic adapter
interface, no dependency on the consumer's repo.

## Outbound — the notifier

The notifier is the reply seam. An agent arm calls `notify.sh` (or the platform equivalent) to
deliver a response to the originating channel. It is also the delivery mechanism for the
**out-of-band approval path**: when the broker issues `require_approval`, the materialized Intent
(`renderedForHuman`) is pushed to the human via the notifier.

The human-authenticated approval response (approve/deny) comes back through the inbound airlock,
is classified as an approval action, and is routed to the broker's Intent resolver — never to the
agent. This keeps the approval authenticated to the human, not to the agent.

Future channels (email, SMS, iMessage) extend this pattern: each channel gets an inbound adapter
(airlock plugin) and an outbound adapter (notifier plugin). The screening and taint logic is
shared across adapters — the screen is injected once, at gate 7, never per-adapter.

## Outbound — the A2A publish seam (`peer.publish`)

Distinct from the notifier reply above is **`peer.publish`** (`channels/PUBLISH.md`, sa#156): a
sending agent emitting a *new* `EventTrigger` addressed to a **peer agent's** principal, not a reply
on an open conversation. It is the sending half of the same one-record-two-seams contract — the
receiver re-validates and re-gates the envelope at its airlock as an ordinary inbound signal
(`SCHEMAS.md`, `TRUST-MAPPING.md`).

It stands on the same floor as every other outbound op: **brokered** (the agent holds no peer
transport credential — the base `peer.publish` op is `external=True, effect="write"`, its `peer`
connector consumer-supplied via sa#141), **broker-stamped provenance** (the sending zone's chain
entry and its taint are set by the broker from the turn, never authored by the agent —
`TRUST-MAPPING.md` §"The one-way rule — sender side"), and **no shared store** (only the envelope
and its `event_id` cross the boundary). A tainted turn's publish escalates through the standing
`tainted_external_write` cut; no publish-specific gate exists.

## Relationships

- `broker/` — the emitted envelope's provenance chain feeds the broker-held turn at ingestion
  (`TurnContext.ingest_source`); classification never sets taint. `require_approval` outcomes
  route back through the notifier.
- `infra/` — the deduplication DynamoDB table and the Lambda/API Gateway IaC.
- `core/arms.md` — the waking mechanism differs per compute arm; the airlock abstracts over it.
- A consumer agent's SAM stack — reference pattern for the Telegram airlock implementation; re-derived clean here, depending on nothing in that repo.
