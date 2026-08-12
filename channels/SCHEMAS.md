# SCHEMAS — the EventTrigger envelope (sa#74)

> **Status: contract (2026-07-08).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, `safe_agents/channels/schemas/event_trigger.py` is the typed
> encoding, and `safe_agents/channels/tests/test_event_trigger.py` is the conformance suite. The
> driving use case is recorded on sa#8 (email-agent → a consumer agent's trade signals, 2026-07-08); the
> contract is designed against that case, not against a running instance. **The contract names no
> transport** — SQS/EventBridge and every other wire binding are reference-tier
> (`channels/ADAPTERS.md` §"Reference bindings").

## What the EventTrigger is

The EventTrigger is the normalized, typed envelope **any inbound signal becomes**, and the platform
uses **one record type at two seams**:

- **Publish seam.** A sending agent's outbound path emits an EventTrigger through its own broker
  (a gated `peer.publish`-class op). The envelope is what crosses the zone boundary.
- **Consume seam.** The receiving agent's airlock re-validates the envelope (its schema-check gate
  is exactly this schema), runs its gates (`channels/ADAPTERS.md` §"Gate ordering"), appends its own
  provenance entry, and hands the stamped envelope to the worker. It is the contract between the
  airlock layer and the ephemeral worker.

Human-channel messages (Telegram today) take the same shape: the receiving adapter *normalizes* the
raw message into an EventTrigger whose provenance chain starts at that airlock. There is no separate
"internal" record type — cross-zone taint transit works because the same chain rides the same record
end to end.

**Supersessions (2026-07-08).** The original sa#74 sketch carried `trigger_source: webhook |
schedule | queue` and `taint: boolean`. Both are superseded by the sa#8 A2A decision: the source
enum named transports, so it is replaced by the open `sender.channel_type` vocabulary; the boolean
is replaced by the derived label over the provenance chain (§"Taint").

## The schema

```ts
// STUB — illustrative; the canonical encoding is event_trigger.py
interface EventTrigger {
  schema_version: 1                // wire versioning; two zones deploy independently
  event_id: string                 // stable, sender-chosen idempotency key (= confirmation # in the driving case)
  principal: string                // the target principal the event addresses
  sender: SenderIdentity           // WHO, at the transport layer, plus verification evidence
  payload: object                  // the PARSED, normalized payload — bounded, never the raw original
  payload_digest?: string          // "sha256:<hex>" over the raw original artifact
  payload_ref?: string             // opaque pointer to the stored raw original (binding is reference-tier)
  provenance: ProvenanceEntry[]    // append-only chain, min length 1 — taint derives from this
  chain_signatures: ChainSignature[]   // per-hop signatures over the chain prefix each broker committed to (channels/SIGNING.md); [] on an unsigned chain
  sender_class?: "owner" | "peer-agent" | "external"   // RECEIVER-owned (#81); null on the wire
  ts: string                       // ISO-8601 UTC, creation
  expiry: string                   // hard TTL; expired envelopes drop before any budget-spending gate
}

interface ChainSignature {         // channels/SIGNING.md — authenticates lineage, does NOT replace taint
  key_id: string                   // the signing broker's workload-identity key a receiver resolves to verify
  zone: string                     // the zone that signed (attribution)
  covers: number                   // prefix length this signature commits to: provenance[:covers]
  payload_type: string             // DSSE payloadType bound into the signed PAE
  sig: string                      // base64 Ed25519 signature over the DSSE PAE of the in-toto statement
}

interface SenderIdentity {
  channel_type: string             // open vocabulary ("telegram", "peer-agent", …) — never a closed enum here
  channel_identity: string         // transport-level identity: chat id, From domain, publisher id — opaque
  evidence: string[]               // "{scheme}:{result}" checks stamped by the VERIFYING adapter ("dkim:pass")
}

interface ProvenanceEntry {
  zone: string                     // the agent/airlock that appended this entry
  source: string                   // namespaced source id: "email:example-vendor.com", "channel:telegram", "peer:email-agent"
  evidence: string[]               // authenticity checks this zone performed for this hop
  label: "trusted" | "untrusted"   // this zone's judgment of ITS source under ITS trust map
  ts: string
}
```

Per-field notes:

- **event_id** — the dedupe key. Scope is `(sender.channel_identity, event_id)`: the receiving
  airlock produces **exactly one** stamped EventTrigger per deduplicated inbound message; replays
  are no-ops. It is also the cross-chain audit join key (sa#8 decision 4): both zones' AuditRecords
  reference it, so the off-substrate verifier (#26/#67) can replay end-to-end from register entry
  back to the originating email.
- **principal** — the receiver MUST verify the target names a principal it serves; a mismatch is a
  drop, not a re-route. The broker session the worker opens runs under this principal
  (`docs/turn-identity.md`).
- **sender.evidence** — stamped by the adapter that *performed* the verification. A receiver MUST
  NOT treat sender-asserted evidence as its own: it re-verifies what it can at its transport
  (signature, token) and records its own checks in its own provenance entry.
- **payload / payload_ref / payload_digest** — the payload is the parsed normalization and is
  size-bounded (`MAX_PAYLOAD_BYTES`, 64 KiB serialized — a contract ceiling; consumers may bound
  lower). The **raw original is never embedded**: it lives behind `payload_ref`, bound by
  `payload_digest`, and a worker fetches it only via a brokered read so the fetch itself is
  taint-tracked (`broker/TAINT.md` §2). `payload_ref` set ⇒ `payload_digest` set.
- **provenance** — append-only. A hop appends via the `stamped()` helper (the model is frozen;
  there is no mutation path); no operation edits or removes prior entries. `source` values are
  namespaced `{scheme}:{value}` strings — same genre as the broker's `connector:{tool}.{op}`.
- **chain_signatures** — per-hop signatures authenticating the provenance chain (`channels/SIGNING.md`).
  Each commits to the chain prefix as it left the signing broker's zone (`covers`); empty on an
  unsigned chain. Receiver verification is a knob shipping OFF, and it authenticates *who asserted a
  hop* — it never replaces the derived taint, which is still recomputed from the chain regardless.
- **sender_class** — the *output* of the receiver's trust-map gate (#81), never a sender claim.
  It is absent on the wire; the trust-map gate sets it from the receiver's own map, unconditionally
  overwriting any inbound value (enforced at the gate — `channels/TRUST-MAPPING.md`).
- **expiry** — hard TTL, checked with caller-supplied time (deterministic, testable). An expired
  envelope drops before the injection screen so replays cannot drain the screening budget.

## Taint — derived, non-strippable, cross-zone

There is deliberately **no writable taint field** on the envelope. The envelope-level label is a
derived property: *tainted iff any provenance entry carries `label: "untrusted"`*. This is
`TurnContext`'s non-strippable discipline (`broker/TAINT.md` §1) extended across zones:

1. **Sender cannot launder.** A sending zone that read untrusted content (an inbound vendor email)
   carries `email:example-vendor.com · untrusted` in the chain. Nothing it does downstream — parsing,
   DKIM-verifying, re-publishing — removes that entry.
2. **Receiver derives locally, floor not ceiling.** The receiving airlock applies its **own** trust
   map and appends its **own** entry. It may judge a hop *worse* than the sender claimed; it never
   edits prior entries and no gate output lowers the derived label. Because chain labels are
   sender-asserted, they act only as a **floor, never a grant**: an entry labeled `untrusted` taints
   the receiving turn even where the receiver's map would trust that source, and a `trusted` label
   earns nothing the receiver's map does not independently grant — so a compromised peer stamping
   `trusted` on its origin launders nothing (`channels/TRUST-MAPPING.md` §"The one-way rule").
3. **The chain feeds the turn.** At ingestion the airlock feeds each provenance `source` into the
   broker-held turn via `TurnContext.ingest_source` (the existing hook, `broker/taint/context.py`),
   so an inbound tainted envelope deterministically taints the receiving turn — and a subsequent
   external write escalates per the floor rule (`broker/TAINT.md` §5), with zero model judgment
   anywhere on the path.

Authenticity and content trust stay separate by construction: `dkim:pass` lives in `evidence`
(what the receiver may *do* — #81's axis); `untrusted` lives in `label` (what the content *is*).
Verified authenticity never cleans a payload's taint.

## Contract clauses

- **C1 — one envelope per deduplicated message.** Dedupe key = `(sender.channel_identity,
  event_id)`; the receiving airlock emits exactly one stamped EventTrigger per key; replays are
  no-ops.
- **C2 — the raw original is never embedded.** `payload` is parsed and bounded; the raw original
  sits behind `payload_ref` + `payload_digest` and is fetched only via a brokered read.
- **C3 — provenance is append-only and taint is derived.** No writable taint field exists; hops
  append and never edit; envelope taint = any untrusted entry.
- **C4 — receiver-owned fields are receiver-derived.** `sender_class` is absent on the wire and
  set only by the receiver's trust-map gate, ignoring any inbound value.
- **C5 — the chain feeds the receiving turn.** Every provenance source is ingested through
  `TurnContext.ingest_source` before the worker acts.
- **C6 — expiry is a hard TTL,** checked deterministically before budget-spending gates.
- **C7 — `event_id` joins the audit chains** of both zones for end-to-end replay.
- **C8 — transport-neutral.** No field closes over a wire technology; `channel_type` and `source`
  are open, namespaced vocabularies; bindings live only in reference-tier text.

## Conformance

A third-party implementation of the envelope (any language) must pass the equivalents of:

| Clause | Test (`test_event_trigger.py`) |
|---|---|
| C1 | `test_dedupe_key_is_stable_and_sender_scoped` — replay no-op behavior lands with the #80 dispatch suite |
| C2 | `test_payload_over_cap_is_rejected` · `test_payload_ref_requires_digest` · `test_digest_format_is_sha256_hex` |
| C3 | `test_no_writable_taint_field` · `test_taint_derives_from_chain` · `test_stamped_appends_and_originals_are_frozen` · `test_empty_provenance_is_rejected` |
| C4 | `test_sender_class_defaults_none_on_the_wire` — overwrite enforcement lands with #81's `stamp_inbound` suite |
| C5 | `test_provenance_sources_feed_turn_ingestion` (bridges to the live `TurnContext`) |
| C6 | `test_expired_envelope_is_detected_deterministically` |
| C7 | documented here; executable with the off-substrate verifier (#26/#67) |
| C8 | `test_provenance_source_must_be_namespaced`; the absence of any transport enum is the contract text itself |
| fixtures | `test_driving_use_case_fixture_roundtrips` — the sa#8 trade-signal envelope, JSON round-trip |

## Relationships

- `broker/TAINT.md` — the floor this contract extends across zones; §2 is the ingestion hook.
- `channels/PUBLISH.md` (sa#156) — the outbound seam that *constructs* this envelope (`peer.publish`);
  `stamp_outbound` is the sender-side mirror of the airlock's `stamp_inbound`.
- `channels/TRUST-MAPPING.md` (#81) — consumes the envelope; owns `sender_class` derivation and the
  one-way rule (receiver and sender sides).
- `channels/ADAPTERS.md` (#80) — the gate ordering that produces a stamped envelope; reference
  bindings live there.
- `channels/SCREENING.md` (sa#43) — the injection-screening standard; the screen is a gate over
  this envelope, not a field in it.
- `broker/SCHEMAS.md` — the eight broker schemas this record feeds (`BrokeredCall.taint` via the
  turn; `AuditRecord` via `event_id`).
