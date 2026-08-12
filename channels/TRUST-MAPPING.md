# TRUST-MAPPING — the inbound trust-mapping framework (sa#81)

> **Status: contract (2026-07-08).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, `safe_agents/channels/trust_map.py` is the typed encoding, and
> `safe_agents/channels/tests/test_trust_map.py` is the conformance suite. It consumes the
> EventTrigger envelope (`channels/SCHEMAS.md`, sa#74) and is consumed by the airlock gate ordering
> (`channels/ADAPTERS.md`, sa#80). Where the map's *values* live (YAML in a consumer repo, a config
> store) is reference-tier — the base defines only the shape and the lookup semantics.

## What trust-mapping is — and the axis it never touches

Trust-mapping answers exactly one question at the airlock: **a transport-verified channel identity
has addressed this agent — who is that, and what may the receiver *do* about it?** It maps
`(channel_type, channel_identity)` → `(principal, sender_class)` by deterministic config lookup —
never by model judgment, never by content inspection.

It deliberately does **not** answer "is the content safe?". Authenticity and content trust are
orthogonal axes, and the driving use case (sa#8) exercises both at once: a consumer agent's airlock
can be *certain* the signal came from the email-agent (authenticity: verified) while the payload
*remains* untrusted content that originated in an inbound email (taint: inherited from the
provenance chain). Verified authenticity raises the action surface; it never cleans the payload.

## Sender classes

Three classes, closed vocabulary. "Unmapped" is not a fourth class — it is the absence of a mapping,
and it short-circuits the pipeline.

| Class | Who | What verified authenticity raises | Receiver hop label |
|---|---|---|---|
| `owner` | the declared principal's accountable human | the full command surface: commands, questions, and approval responses (approvals route to the broker's Intent resolver, never to the agent — `channels/README.md` §Outbound) | `trusted` |
| `peer-agent` | an authenticated peer agent this receiver has declared | may wake the worker and deliver signals addressed to the mapped principal | `trusted` — the *hop* is authentic; chain-inherited taint persists untouched |
| `external` | a verified-but-external sender (e.g. an HMAC-verified vendor webhook) | the minimum: delivery to the mapped principal, subject to every downstream gate | `untrusted` — always taints |
| *(unmapped)* | anyone else, however well-authenticated at the transport | nothing: **drop** — no EventTrigger, no injection-screen call (no budget spend), no reply to the sender | — |

The hop label is a deterministic function of the class (`CLASS_HOP_LABEL` in `trust_map.py`), not a
per-entry config knob: `owner`/`peer-agent` → `trusted`, `external` → `untrusted`. What varies per
consumer is *membership* (which identities map to which class), never the label semantics.

"Drop silently" means silent **toward the sender** — no acknowledgement, no error detail an
adversary could probe. It never means unrecorded: every drop emits a `DropRecord` (below).

## The one-way rule

The single most load-bearing clause in this framework:

> **No output of trust-mapping — or of any airlock gate — may lower the taint derived from the
> provenance chain.** Mapping may only *add* the receiver's own entry and set the receiver-owned
> `sender_class`. It never edits or removes prior entries, and there is no resolution result that
> renders a tainted envelope clean.

Three consequences, each a conformance test:

1. **Authenticity never cleans.** An `owner` or `peer-agent` resolution over a chain containing an
   `untrusted` origin (the inbound brokerage email) appends a `trusted` hop — and the envelope *stays
   tainted*, because derived taint is any-untrusted over the whole chain.
2. **Sender-asserted labels are a floor, never a grant.** Chain labels arrive from the sending zone
   and could be forged by a compromised peer. The receiver's own trust map is therefore
   authoritative for the receiving turn: at ingestion, a source taints the turn if *either* its
   chain label is `untrusted` *or* the receiver's `InputTrustMap` does not trust it. A peer that
   stamps `trusted` on its origin launders nothing; a peer that honestly stamps `untrusted` taints
   the turn even for sources the receiver would otherwise trust.
3. **Screens refuse or pass — never bless.** The injection screen (`channels/SCREENING.md`, a
   later gate) may refuse a message or let it through; a passing screen changes nothing about
   taint. Model judgment may only tighten, never loosen — the model is never the judge in the
   dangerous direction (`broker/TAINT.md` §1).

## The one-way rule — sender side

Everything above governs the receiving airlock. The rule is symmetric, and its sending-side mirror
is what makes cross-zone taint honest: **a zone that publishes to a peer (`peer.publish`,
`channels/PUBLISH.md`) cannot strip or downgrade the taint it carries into the envelope it emits.**

The sending side has two structural protections, neither of which the agent can subvert:

1. **Provenance is broker-stamped, not agent-authored.** The outbound chain's sending-zone entry is
   set by the broker from the sending `TurnContext`'s taint state (`stamp_outbound`), exactly as the
   receiver's entry is set from *its* trust map by `stamp_inbound` — never by the party being
   judged. A turn that ingested an untrusted source publishes an `untrusted` entry the agent can
   neither remove nor relabel, and a relaying agent appends its hop without editing the upstream
   chain. The label is a deterministic function of the turn, never a model judgment and never an
   agent argument.
2. **A tainted publish is an external write.** `peer.publish` is `external=True, effect="write"`, so
   a tainted turn's publish hits the standing `tainted_external_write` floor cut and escalates to
   `require_approval` (`broker/TAINT.md` §5). The sender's only path to emit tainted content to a
   peer is the honest, human-gated one — there is no autonomous laundering path.

So the guarantee is end-to-end: a compromised sender can neither forge a `trusted` chain over
untrusted content (protection 1) nor autonomously push that content across the boundary (protection
2), and the receiver independently re-derives taint from the chain regardless (the receiver-side
rule above). Authenticity of the *hop* — a `peer-agent` sender — is orthogonal to and never cleans
the *content*.

## Two maps, two boundaries

This framework and the broker's `InputTrustMap` (`broker/taint/propagation.py`) are different
instruments and must not be conflated:

- **`ChannelTrustMap`** governs the airlock seam: *who may address this agent at all*, under which
  principal, with which action surface. Keyed by channel identity.
- **`InputTrustMap`** governs turn ingestion: *which content sources taint a turn*
  (`broker/TAINT.md` §2). Keyed by source id.

They meet at the taint stamp: the airlock feeds every provenance `source` into the broker-held turn
via `TurnContext.ingest_source` under the receiver's `InputTrustMap`, combined with the label floor
(consequence 2 above). The `ChannelTrustMap` result never substitutes for that per-source judgment.

## The map shape

```ts
// STUB — illustrative; the canonical encoding is trust_map.py
interface ChannelTrustMap {
  entries: TrustMapEntry[]         // uniqueness enforced on (channel_type, channel_identity)
}
interface TrustMapEntry {
  channel_type: string             // matches EventTrigger.sender.channel_type
  channel_identity: string         // the NORMALIZED transport identity (normalization is the adapter's job, #80)
  principal: string                // the principal this identity may address
  sender_class: "owner" | "peer-agent" | "external"
}
// resolve(channel_type, channel_identity) -> { principal, sender_class } | null   — null = drop
// stamp_inbound(envelope, resolution, zone, source, evidence, ts) -> EventTrigger — appends the
//   receiver's hop entry (label from CLASS_HOP_LABEL), sets sender_class, overwrites any wire value
// ingest_chain(envelope, turn_context, receiver_map) — feeds every provenance source into the
//   broker-held turn: a source counts as trusted only when its chain label is "trusted" AND the
//   receiver's InputTrustMap trusts it (the label floor, consequence 2 — the canonical bridge the
//   dispatcher uses; #74's C5 clause is satisfied through this seam)
```

- **`resolve` is a deterministic, config-derived, exact-match lookup.** No wildcards, no regex, no
  model call in the contract; identity normalization (lower-casing an email domain, canonicalizing
  a chat id) happens in the adapter's `extract_identity`, before this seam.
- **The base ships no identity values.** All membership comes from consumer config; the base defines
  the shape only (the consumer-boundary CI guard already polices literals in base source). A
  resolution whose `principal` differs from `EventTrigger.principal` is a drop
  (`principal_mismatch`), not a re-route.
- **`stamp_inbound` is the only sanctioned path** from a wire envelope to a worker-ready envelope:
  it appends exactly one receiver entry via the envelope's `stamped()` helper and sets
  `sender_class` from the resolution, unconditionally overwriting any inbound value (closes
  `channels/SCHEMAS.md` C4).

## DropRecord

Every drop is recorded, PII-safely: the record carries a `sha256:` digest of the channel identity,
never the raw value (the same discipline as `AuditRecord.argsDigest`).

```ts
interface DropRecord {
  channel_type: string
  identity_digest: string          // "sha256:<hex>" of channel_identity — never the raw identity
  reason: "authenticity_failed" | "malformed" | "expired" | "unmapped" | "principal_mismatch"
        | "screen_refused"
  detail: string | null            // gate-specific machine code, ^[a-z][a-z0-9_]{0,63}$ — never free
                                   // text (channels/SCREENING.md; today only the screen gate sets it)
  ts: string
}
```

Only `unmapped` and `principal_mismatch` drops are emitted by this framework's gate; the other
reasons belong to sibling gates in the fixed ordering (`channels/ADAPTERS.md` §"Gate ordering") —
the record type is defined once, here. The optional `detail` field is `channels/SCREENING.md`'s
addition (sa#43): a validator-enforced closed-vocabulary code so the drop log can say *why* a gate
refused without ever carrying content-derived prose. A deduplicated replay is a silent no-op, not a drop: replays
are expected transport behavior, and recording each one would let a replaying adversary flood the
drop log.

## Conformance

| Clause | Test (`test_trust_map.py`) |
|---|---|
| resolve maps all three classes deterministically | `test_resolve_maps_each_sender_class` |
| unmapped → `None`, no downstream call | `test_unmapped_identity_resolves_none` — the no-screen-call ordering assertion lands with the #80 dispatch suite |
| map config validates; duplicate keys rejected | `test_trust_map_config_validates` · `test_duplicate_identity_keys_rejected` |
| stamp appends exactly one receiver entry | `test_stamp_inbound_appends_receiver_entry` |
| receiver owns `sender_class` (SCHEMAS C4) | `test_stamp_inbound_overwrites_wire_sender_class` |
| one-way rule 1: authenticity never cleans | `test_authenticity_never_lowers_taint` |
| one-way rule 1: external hop taints | `test_external_sender_stamp_taints` |
| one-way rule 2: labels are a floor, receiver map authoritative | `test_sender_asserted_trusted_label_is_only_a_floor` (the anti-laundering test) + its untainted control |
| drops are recorded, PII-safe | `test_drop_record_digests_identity` |

## Relationships

- `channels/SCHEMAS.md` (sa#74) — the envelope this framework stamps; §Taint carries the shared
  one-way language.
- `channels/ADAPTERS.md` (sa#80) — where this gate sits in the fixed ordering (after transport
  verification and schema check, before the injection screen).
- **`channels/SCREENING.md` (sa#43) — the injection-screening standard — stays the sibling gate,
  not part of this framework.** #81 owns *identity → authorization* (provenance-based,
  deterministic); #43 owns the *content screen* and the provenance-category reconciliation. The
  boundary rule they share is consequence 3 above: a screen refuses or passes, never blesses.
- `broker/TAINT.md` — the floor; `TurnContext.ingest_source` is where both maps' judgments land.
