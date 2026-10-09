# ADAPTERS — the channel-adapter interface and the airlock gate ordering

> **Status: contract (2026-07-08), with one named reference component.** Contract-tier per
> `docs/contract-vs-reference.md`: this document and `safe_agents/channels/adapters.py` (the
> abstract interfaces) are the normative surface; `safe_agents/channels/tests/test_adapters.py` is
> the conformance suite. `safe_agents/channels/dispatch.py` — the in-memory airlock dispatcher — is
> **reference-tier**: it exists so the ordering clauses below are executable, and it passes the same
> suite a third-party dispatcher would. All wire bindings live in §"Reference bindings" and nowhere
> else.

## What an adapter is

An adapter is the channel-specific edge of the airlock. The airlock dispatch loop is
channel-agnostic — it contains **no channel conditionals**; everything Telegram-shaped,
email-shaped, or peer-shaped lives behind the two interfaces below. Each channel contributes one
inbound adapter (airlock plugin) and, where the channel can carry replies, one outbound adapter
(notifier plugin). Adapters receive their configuration by injection or environment — the
interfaces carry **no config fields** (an adapter's secrets and endpoints are its own business, and
instance values never enter contract surface).

## The adapter-selection seam

Which inbound adapter the airlock runs is consumer config, not a base constant. A `ChannelsManifest`
names `adapter.kind`; `build_airlock` looks that kind up in **`ADAPTER_REGISTRY`** (the adapter
mirror of `SCREEN_REGISTRY`) and builds the concrete adapter from its typed config, the injected
token secret, the manifest `routing` table, and the manifest `zone`. Every factory takes all four; the
webhook factory ignores the last two. The token secret arrives as stored and each factory reads it
in its own kind's shape: the webhook factory parses it as a map from channel identity to that
peer's own token (`webhook.parse_token_map`), refusing a bare string, an empty map, an identity
named twice once canonicalized, a token that is empty or not a string, and one token under two
identities, each by name and without echoing any value from the secret; the owner factory takes
the bot's one token as a bare string. Three invariants hold this seam:

- **A kind-less adapter block keeps its meaning.** `adapter.kind` defaults to `signed-webhook`,
  so an adapter block written before kinds existed resolves to the webhook adapter.
- **`zone` has no default.** It is the id of this one airlock deployment: the provenance zone
  the airlock stamps at gate 8 and the `audience` an envelope must name at gate 3. A manifest that
  omits it, leaves it empty, or pads it with whitespace fails to load. Two deployments must not
  share an id, including two environments of the same agent, whenever they enrol any of the same
  signer keys; the audience check is only as strong as that distinctness, and the base cannot
  verify it across deployments (`channels/SIGNING.md` S9). An airlock deployed with no manifest
  runs as the placeholder zone `unconfigured` with an empty trust map and drops every sender.
- **An unregistered kind fails loudly.** A named kind with no registered factory raises at build
  time rather than silently degrading to pass-through or dropping all traffic — the friction
  doctrine's rule for any configured-but-unbuildable seam (`docs/friction-doctrine.md`), identical
  to the screen registry's.

The registry is populated eagerly at import (adapters are pure stdlib, unlike screens whose vendor
SDKs force a lazy path). Reference-tier bindings register their own kind there; the contract is the
seam, not the set of kinds registered in it.

## InboundAdapter

```ts
// STUB — illustrative; the canonical encoding is adapters.py
interface InboundAdapter {
  channel_type: string                          // the adapter IS a channel type ("telegram", "peer-agent", …)
  credential_per_sender: boolean                // true when the gate-1 credential names one sender; default false
  verify_token(request): boolean                // transport authenticity — BEFORE the body is read
  extract_identity(request): string             // the NORMALIZED channel identity of the sender
  normalize(request): EventTrigger              // the wire request as a typed envelope (schema check)
}
```

- **`verify_token`** verifies the transport-layer authenticity proof (a secret-token header, an
  HMAC signature, a message signature) **without parsing the message body** — unauthenticated bytes
  never reach a parser. Failure is a drop (`authenticity_failed`), recorded PII-safely
  (`channels/TRUST-MAPPING.md` §DropRecord), with nothing revealed to the sender.
- **`credential_per_sender`** is true when the gate-1 credential is bound to one sender identity,
  so that a sender authenticated at gate 1 is authenticated *as* the identity `extract_identity`
  returns. It defaults to false, and only when an adapter declares it true are its senders told a
  refusal class (§"What the sender is told"). The webhook adapter declares it: each peer holds its own
  token, and `extract_identity` returns the identity that token is bound to. The owner adapter does
  not: its token is one per bot by the transport's design.
- **`extract_identity`** returns the sender's transport identity, **normalized** (canonical chat
  id, lower-cased domain) — the trust map's `resolve` is an exact-match lookup and does no
  normalization of its own.
- **`normalize`** produces the typed `EventTrigger` (`channels/SCHEMAS.md`) and *is* the schema
  check. For a human channel the chain starts here: the adapter constructs the envelope with one
  origin provenance entry stamped by this airlock, and sets `audience` to this airlock's own zone.
  For the peer channel the wire *already is* an
  EventTrigger: normalize parses and validates it, provenance arriving non-empty from the sending
  zone. Where a raw original exists (a full webhook body, a raw email), the implementation stores
  it out-of-band and sets `payload_ref` + `payload_digest` — the raw original is never embedded
  (SCHEMAS C2); the storage binding is reference-tier.

**Sender-transport binding (an adapter contract obligation).** An adapter's `normalize` MUST
produce an envelope whose `sender.channel_identity` equals its OWN `extract_identity` result for
the SAME request. `EventTrigger.dedupe_key()` keys on `sender.channel_identity`; when chain
verification is ON, gate 3.5 also binds this same field into the signed statement
(`channels/SIGNING.md`), so a divergent claim surfaces as a forged/invalid chain there. This
adapter-level check is what covers the gap when verification is OFF, hasn't run yet for this
envelope, or the adapter's own gate-2/gate-3 identity extraction diverges independently of anything
cryptographic. Dispatch enforces it structurally, right after gate 3 and before gate 3.5: a
divergence drops `malformed` with `detail="sender_identity_mismatch"` and carries no verification
evidence (the divergence is untrusted input at the moment it's caught). The owner adapter
satisfies this by construction: `extract_identity` and `normalize` both derive `channel_identity`
from the identical wire field via the identical canonicalization (`_canonical_identity`). The
webhook adapter does not, on purpose: its `extract_identity` returns the identity the presented
token is bound to, its `normalize` reads the identity the body claims, and both canonicalize by
the same rule. So for the webhook adapter this check is what binds the body to the token: a peer
whose body claims another peer's identity drops here, before gate 3.5 and before the trust map is
asked about the claimed identity.

**Supersession (2026-07-08).** `normalize` replaces the earlier sketch's `extract_payload(request)
-> bytes`: with the EventTrigger contract in place, handing raw bytes forward would re-open
the unparsed-payload seam the envelope exists to close.

## OutboundAdapter

```ts
interface OutboundAdapter {
  channel_type: string
  deliver(principal, rendered_output, channel_metadata): delivery_ref   // returns a reference for the audit trail
}
```

The outbound adapter is the **notifier seam**: agent replies, and the out-of-band approval path —
when the broker issues `require_approval`, the Intent's `renderedForHuman` is pushed through
`deliver`, and the human's response comes back through the *inbound* airlock, authenticated to the
human, routed to the broker's Intent resolver, never to the agent (`channels/README.md`).

**The approval-return contract.** The inbound leg of that out-of-band path is the owner
`/approve <intent_id> yes|no` reply. The owner adapter's `normalize` classifies it into an
approval-kind payload — `{"kind": "approval", "intent_id": …, "decision": "yes"|"no"}` — and the
drain worker forks on `sender_class == "owner" AND payload.kind == "approval"` to the broker's
sanctioned `approve_intent()` / `reject_intent()` seam. That path is **WYSIWYE**: it executes the
**stored** `materializedRequest`, so the human message's own taint cannot change what executes. The
release **re-validates current authority** (#9): the broker re-reads facts, re-runs the PDP over the
stored call with the approval requirement treated as satisfied, and draws the op's period budget, so
a grant revoked or demoted between the hold and the release refuses instead of executing. A refused
release reaches no connector and lands the intent in the terminal `refused` state. The fork keys on
the **unforgeable**
gate-8 `sender_class` (set only at the airlock from the trust map), so a non-owner envelope carrying
an approval-shaped payload does **not** fork — it falls through to the normal agent-turn path where
the broker decides every call. Approvals are **addressed like any command** (`/approve` is the
reserved leading token); the consumer's outbound prompt templates the full reply string, since a
reply must carry its own address for `normalize` to admit it.

The owner's third verb is `/flag <intent_id>` — `normalize` classifies it into a `{"kind": "flag", …}` payload and the drain forks the same unforgeable-`sender_class` way to the broker's `flag_intent()` seam, which writes the `false_action` evidence label on an already-executed op (the demotion coupling ships OFF).

**Floor note — peer publication is not an adapter bypass.** An agent publishing to a peer does so
through a brokered `peer.publish`-class op, because the agent's only egress is the broker (the
floor invariant). The OutboundAdapter is where the *broker-side connector* (or the notifier)
touches the channel; it is never an agent-side path around the broker.

## Gate ordering — fixed by contract

The airlock dispatch runs these gates in this order, short-circuiting on the first failure. The
relative order of the four load-bearing gates — **schema check → trust-map → injection screen →
taint stamp** — is contract; the interleaved deterministic gates sit where they are for stated
reasons.

| # | Gate | On failure | Why here |
|---|---|---|---|
| 1 | `verify_token` | drop: `authenticity_failed` | unauthenticated bytes never reach a parser |
| 2 | `extract_identity` | drop: `malformed` | the identity keys every later gate |
| 3 | **schema check** (`normalize`), then discard any wire `sender_class` and refuse an envelope that is not forwardable (`EventTrigger.to_wire`: within the size ceiling and reading back unchanged from the wire form the worker parses) | drop: `malformed` (`detail` `not_forwardable` for the last) | nothing downstream handles untyped bytes, reads a class the sender asserted, or claims a dedupe key for a message it cannot forward |
| 3 (audience) | audience check: `envelope.audience` must equal this airlock's zone id exactly, with no trimming and no case folding (`channels/SIGNING.md` S9) | drop: `audience_mismatch` | an envelope addressed to another receiver is refused before its signature is verified, so the drop record names no signer, and before dedupe, so it claims no key |
| 3.5 | chain verification (`channels/SIGNING.md`), when the airlock is configured with verification keys; not run for an adapter that builds the envelope itself (`originates_envelope`, the owner adapter), which has no sending broker and no signature | drop: `chain_signature_missing` / `chain_signature_invalid` / `chain_signer_unknown`; keys configured but unavailable: `not_evaluated` (`detail` `key_source`) | a forged chain is refused before any budget is spent, and before dedupe, so it cannot shadow the genuine message |
| 4 | expiry check (`is_expired`, caller-supplied time) | drop: `expired` | expired replays must not spend any budget |
| 5 | **trust-map** (`resolve`; principal match) | drop: `unmapped` / `principal_mismatch` | unmapped senders get no further processing at all |
| 6 | dedupe on `(sender.channel_identity, event_id)` | silent no-op; store unavailable: drop `not_evaluated` (`detail` `dedupe_store`) | after trust-map so only mapped senders can write the dedupe store; before the screen so replays cannot drain the screening budget |
| 7 | **injection screen** (`channels/SCREENING.md`, injected) | drop: `screen_refused` | the one model-judged gate — it may refuse or pass, never bless (one-way rule 3) |
| 8 | **taint stamp** (`stamp_inbound`) | — (cannot fail) | appends the receiver's provenance entry, sets `sender_class` overwriting any wire value |
| 9 | emit — exactly one stamped EventTrigger per dedupe key | — | SCHEMAS C1 |

Two clauses ride the ordering:

- **The screen is injected, not owned.** The dispatcher takes the screen as an injected callable;
  its semantics are `channels/SCREENING.md`. A dispatcher must function with a null screen
  (pass-through) — screening strictness is consumer policy per `docs/friction-doctrine.md`; the
  *position* of the gate is contract.
- **The stamped envelope must reach the turn.** Whoever dispatches the emitted EventTrigger to a
  worker — the trusted loop driver, which already holds the runtime and is the only caller of
  `new_turn()` (`docs/turn-identity.md`) — feeds every provenance source into the broker-held turn
  (`TurnContext.ingest_source`, combined with the label floor per `channels/TRUST-MAPPING.md`
  §"The one-way rule") before the worker's first call is decided. The bridging mechanism is
  reference-tier; any mechanism may only **add** taint.

## What the sender is told

The gate order decides what is refused. This section decides what the sender learns about it
(PTC §6.1, clause PTC-44). The answer is carried in the response body, and the transport status is
the same on every path: the reference binding answers 200 to every request, an unexpected
exception included. The status never carries the class, for two reasons. A provider that retries
on any non-2xx status would re-deliver a message the airlock has already handled. And a party
probing the ingress sees one status whatever it sends.

The body is one of three, and carries exactly these keys:

| Body | Told to | When |
|---|---|---|
| `{"ok": true}` | every sender | an accepted envelope; a screen refusal, `screen_error` included; a deduplicated replay; every refusal toward a sender that is not both authenticated and mapped; or the airlock failed while handling the request |
| `{"ok": false, "refusal": "permanent"}` | an authenticated, mapped sender | a refusal before the screen that the airlock evaluated: `malformed` (any gate-3 variant), `audience_mismatch`, the three chain failures, `expired`, `principal_mismatch` |
| `{"ok": false, "refusal": "transient"}` | an authenticated, mapped sender | the airlock could not evaluate because a fetched input was unavailable: its verification keys (gate 3.5) or its dedupe store (gate 6) |

A sender is **authenticated and mapped** when its gate-1 credential names it
(`credential_per_sender`), it passed gate 1, and the identity that credential names resolves in the
trust map for `(adapter.channel_type, identity)`. The dispatcher makes that lookup right after
gate 2, and only for an adapter whose credential is per sender. It moves no gate and writes no
record, and gate 5 still decides admission. A sender that fails gate 1 or gate 2, or whose identity
is not in the trust map, gets `{"ok": true}` for everything. A party that fails gate 1 learns
nothing from the answers. A token holder is authenticated as the one identity its token names, so
it learns about that identity and nothing about any other: a body claiming another identity is
refused at gate 3 as the holder's own malformed envelope, and the answer is the same whether the
claimed identity is mapped or not. An adapter whose gate-1 credential is shared across senders,
such as the owner adapter, tells its senders nothing on every path, because there the identity is
whatever the holder claims and a differing answer would tell it which identities the trust map
holds. A screen refusal reads as an acceptance to everyone, so a compromised peer gets no feedback
on content.

A permanent refusal is recorded with the drop reason the gate always wrote. A transient refusal is
recorded as a `not_evaluated` drop whose `detail` names the input, `key_source` or `dedupe_store`.
Both inputs are consulted before the dedupe key is claimed, so a sender that retries after a
transient answer is evaluated afresh and no record strands. One edge remains: a write to the dedupe
store that succeeded but whose response was lost leaves the key claimed behind a transient answer,
and the retry dedupes silently. The `not_evaluated` record is what lets an operator see it; the
reference build does not undo the claim. While the keys are unavailable, every envelope that
reaches gate 3.5 is recorded `not_evaluated`, an unmapped sender's included, because gate 3.5 runs
before gate 5; that sender is still told nothing. An adapter that builds its envelope itself
(`originates_envelope`) never consults the keys and is unaffected.

The reference airlock fetches its verification keys at cold start and, when the fetch fails, keeps
serving: the next request that reaches gate 3.5 fetches again, and the keys are cached once a fetch
succeeds. A request that fails gate 1 never triggers a fetch.

A sending transport must read the body to act on the class. Whether to send again after a
transient answer is the sender's decision; the reference peer connector reports the class and does
not retry (`channels/PUBLISH.md`).

## Addressing — a `normalize` responsibility, not a router

Addressing is an adapter-`normalize` responsibility. There is **no component in front of the
airlock** that makes admission decisions; every rejection is a gate rejection carrying a
`DropRecord`. The "router" is a *responsibility, not a component* — no standalone pre-airlock router
is built at any N. `normalize` writes the addressing claim (it sets `EventTrigger.principal`) and
gate 5 judges it: there is one flow, not a router reconciled against a gate.

**Altitude — why the trust layer never routes.** Legitimate routing lives at two altitudes, both
outside this layer: *above* it — a higher-level app deciding which bounded agent gets a request,
before any airlock — and *inside* the bounded agent — internal orchestration after the drain. The
trust layer in between **verifies addressing claims; it never routes.** The base ships what routing
needs — a principal claim on the envelope, per-principal admission config, single-principal drains —
not routing itself. (This restates the base/per-agent split: deciding where work goes is policy;
verifying the claim is floor.)

Three consequences fall out of "`normalize` writes, gate 5 judges" and are made contract by the
owner case below: a friendly address token is resolved to a principal in `normalize` and never seen
by gate 5; an unresolved token passes through as the *claimed* principal and is dropped at gate 5,
not at `normalize`; and an address-less message is a gate-3 `malformed` drop with **no default
principal ever synthesized**.

## The named inbound cases

- **Peer-agent (the new case).** `verify_token` verifies the sending zone's transport
  credential, which is per peer: each peer holds its own token, so one peer's token can be revoked
  or rotated without touching another's; `extract_identity` returns the peer identity that
  credential is bound to; `normalize` validates the wire EventTrigger as-is, and its claimed sender
  must be that identity. The payload is already parsed — the sending zone did that work — and its
  provenance (e.g. `email:example-vendor.com · untrusted`) rides through untouched until the receiver
  stamps its own entry at gate 8.
- **Telegram (the existing case, restated agent-agnostically).** Secret-token header verification;
  chat-id identity; `normalize` wraps the message into a fresh envelope whose chain starts at this
  airlock. The owner mapping lives in consumer config (`ChannelTrustMap`), never in base source —
  this is the re-derivation of the proven consumer-agent airlock pattern without its owner/Telegram
  hardcoding (`channels/README.md` §Inbound).
- **Owner (the human-as-owner case).** The owner sends a **raw command**
  (e.g. `/trader buy AAPL`, or an approval reply `/approve <intent_id> yes|no`) over an authenticated
  transport — not a full envelope like a peer — so `normalize` **constructs** a fresh-chain
  `EventTrigger`, stamping one seed provenance hop. The envelope's `audience` is the airlock's own
  zone, which `build_airlock` hands the adapter from the manifest. The request body carries no
  `audience` and cannot set one. The command's leading whitespace token is the
  **address**: `normalize` resolves it through the manifest `routing` block (friendly-name → principal
  indirection *only*) and sets `EventTrigger.principal`. The trust map stays the **sole authorization
  authority** — gate 5 keys on `(channel_type, identity)` and never sees the address token. A routing
  **miss** passes the raw token through as the claimed principal, and gate 5 drops it
  `principal_mismatch` (no new drop vocabulary): an owner who types a raw principal id is admitted iff
  the trust map already authorizes them for it — an undocumented alias, not a trust hole. An
  **address-less** message raises in `normalize` → gate-3 `malformed`; **no default principal is ever
  synthesized** (defaulting is the misroute hazard at N>1).

  *Floor discipline.* `sender_class="owner"` (stamped at gate 8 from the trust map) is a trust label /
  **floor**, never a grant: it widens the owner's action surface, but the broker still decides every
  call an admitted owner *command* drives — there is no owner auto-allow anywhere. The owner mapping
  lives in consumer config (`ChannelTrustMap` + the `routing` block), never in base source. The seed
  hop's `label="trusted"` is **earned** by gate-1 authentication, not asserted — and it too is only a
  floor: the receiver's `InputTrustMap` may still fail it under the one-way rule
  (`channels/TRUST-MAPPING.md`), so a trusted seed does not auto-un-taint the turn. (An `untrusted`
  seed would instead taint every owner turn, collapsing owner≈external and tripping the
  lethal-trifecta cut on the owner's own explicit command.) `owner` is the base adapter's channel_type;
  a chat transport such as Telegram is a consumer-side label wrapping the raw command into this
  adapter's body.

## Reference bindings

Everything in this section is **reference-tier** — named here and only here, never in contract
clauses:

- **Peer transit:** SQS or EventBridge between zones (the agent-to-agent channels decision's binding). The queue is
  dumb transport; every property that matters — authenticity, dedupe, taint — is enforced at the
  receiving airlock, so a substituted transport changes nothing above.
- **Webhook channels:** API Gateway + Lambda in front of the dispatcher; the DynamoDB dedupe table
  (`infra/` State stack).
- **The proven pattern:** a consumer agent's SAM inbound-airlock stack — learned from,
  never imported (decoupling discipline, `CLAUDE.md`).
- **The in-memory dispatcher** (`dispatch.py`): pure, transport-free, injected seams for the trust
  map, screen, dedupe store, drop sink, and the optional verdict sink (`channels/SCREENING.md`).
  It is the conformance harness's subject and an honest starting point, not the production binding.

## Conformance

| Clause | Test (`test_adapters.py`) |
|---|---|
| gate 1 fails → nothing else called, PII-safe drop | `test_verify_failure_short_circuits_before_body_read` |
| malformed → drop before trust-map | `test_malformed_payload_drops_before_trust_map` |
| expired → drop before screen (no budget spend) | `test_expired_envelope_drops_before_screen` |
| unmapped → no screen call, no emit | `test_unmapped_sender_never_reaches_screen` |
| principal mismatch → drop | `test_principal_mismatch_drops` |
| replay → no second emit, no second screen call (SCHEMAS C1) | `test_replay_is_a_noop` |
| screen refuses → no emit, recorded; passes → envelope unchanged | `test_screen_refusal_blocks_emission` · `test_screen_pass_changes_nothing` |
| emitted envelope is stamped: receiver entry + `sender_class` overwritten (SCHEMAS C4) | `test_emitted_envelope_is_stamped` |
| emitted chain feeds the turn, label floor honored | `test_dispatch_result_feeds_turn_ingestion` |
| stub adapters satisfy both interfaces | `test_stub_adapters_satisfy_interfaces` |
| outbound stub returns a delivery reference | `test_outbound_stub_delivers` |
| sender-transport binding: mismatch drops `malformed`/`sender_identity_mismatch` before gate 3.5, no evidence; match unaffected | `test_sender_identity_mismatch_drops_malformed_before_verify_chain` · `test_sender_identity_match_is_unaffected` |
| an envelope addressed to another zone drops `audience_mismatch` before gate 3.5: verification, the screen and dedupe never run, the record carries no evidence, and zone ids are compared exactly | `test_an_envelope_addressed_to_another_zone_drops_before_verification` · `test_audience_is_checked_ahead_of_expiry_and_the_trust_map` · `test_signing.py::test_audience_is_checked_with_verification_off` · `test_airlock_handler.py::test_a_request_addressed_to_another_airlock_enqueues_nothing` |
| a body claiming its own token's identity, or for the owner adapter its own identity, satisfies sender-transport binding across identity spellings | `test_webhook_adapter.py::test_normalize_sender_identity_matches_extract_identity` · `test_owner_adapter.py::test_normalize_sender_identity_matches_extract_identity` |
| the webhook token is per peer: gate 1 compares every entry with no early exit and reads no body; gate 2 returns the identity the token names, never the body's; a wrong token is `authenticity_failed` whatever the body claims; each peer is accepted under its own token | `test_webhook_adapter.py::test_verify_token_accepts_each_peers_own_token` · `::test_gates_1_and_2_never_read_the_body` · `::test_verify_token_compares_every_entry_whichever_matches` · `::test_extract_identity_ignores_the_identity_the_body_claims` · `::test_a_wrong_token_is_authenticity_failed_whatever_the_body_claims` · `::test_each_peer_is_accepted_under_its_own_token` |
| a body claiming another identity under a peer's token drops `malformed`/`sender_identity_mismatch` before gate 3.5 and before the trust map is asked about the claimed identity, and the answer does not depend on whether that identity is mapped | `test_webhook_adapter.py::test_a_body_claiming_another_peer_drops_before_verification_and_tells_nothing_of_it` · `test_airlock_handler.py::test_a_token_holder_learns_nothing_about_an_identity_it_claims` |
| the webhook token secret is refused at load, by name, giving the expected shape and no value from the secret, when it is a bare string, not an object, empty, names an identity twice (before or after canonicalization), gives one token to two identities, or holds an empty or non-string token, an empty identity, or a token or identity not encodable as UTF-8; the refusal fails the cold start | `test_webhook_adapter.py::test_a_token_secret_that_is_not_a_usable_map_is_refused_by_name` · `test_manifest.py::test_a_webhook_airlock_refuses_a_bare_token_secret` · `test_airlock_handler.py::test_a_webhook_secret_that_is_not_a_token_map_fails_the_cold_start` |
| a refusal class is told only behind an adapter that declares `credential_per_sender` exactly true: a mapped sender behind a shared credential, the owner adapter's included, is told nothing on every path, and the trust-map lookup that decides it is not made | `test_dispatch_outcome.py::test_a_mapped_sender_behind_a_shared_credential_is_told_nothing` · `::test_a_dedupe_store_failure_behind_a_shared_credential_is_told_nothing` · `::test_only_an_adapter_that_says_true_is_told_anything` · `::test_the_mapped_lookup_is_made_only_for_a_per_sender_credential` · `test_adapters.py::test_an_inbound_adapter_claims_a_per_sender_credential_only_by_saying_so` · `test_owner_adapter.py::test_a_mapped_owner_is_told_nothing_of_a_refusal` · `test_airlock_handler.py::test_a_mapped_owner_is_told_nothing_of_a_refusal` |
| toward an authenticated, mapped sender each pre-screen refusal is classed permanent; toward any other sender the same refusal is classed nothing; a screen refusal, `screen_error` and a replay are classed nothing (`dispatch_outcome`) | `test_dispatch_outcome.py::test_a_mapped_sender_is_told_a_pre_screen_refusal_is_permanent` · `::test_an_unmapped_sender_is_told_nothing_about_the_same_refusal` · `::test_a_sender_that_never_reached_the_trust_map_lookup_is_told_nothing` · `::test_a_screen_refusal_reads_as_an_acceptance_and_is_dedupe_marked` · `::test_a_replay_is_told_nothing` |
| an unavailable key source or dedupe store is classed transient toward a mapped sender, recorded `not_evaluated`, and claims no dedupe key | `test_dispatch_outcome.py::test_keys_unavailable_is_transient_toward_a_mapped_sender_and_claims_nothing` · `::test_keys_unavailable_tells_an_unmapped_sender_nothing_and_records_what_happened` · `::test_a_dedupe_store_failure_is_transient_and_claims_nothing` |
| the response body: status 200 on every path; the uniform body is the same bytes for every path that tells nothing; a retry after a transient answer is evaluated afresh; the keys are fetched again until a fetch succeeds | `test_airlock_handler.py::test_every_path_that_tells_nothing_answers_the_same_bytes` · `::test_a_pre_screen_refusal_is_permanent_toward_a_mapped_sender_only` · `::test_an_unavailable_key_source_is_transient_and_retried_until_it_answers` · `::test_an_unavailable_dedupe_store_is_transient_and_claims_nothing` |
| a mutated-sender replay never accrues an attributed record, whichever gate sees it first: a divergent sender claim (an adapter whose gate-2/gate-3 identities diverge) drops at gate 3 before gate 3.5 runs, carrying no verification evidence; an internally-consistent mutation of a still-validly-signed envelope — which gate 3 cannot see — is caught at gate 3.5 as a forgery, with no second attributed record and no second screen spend | `test_adapters.py::test_sender_identity_mismatch_drops_malformed_before_verify_chain` · `test_signing.py::test_mutated_sender_replay_fails_verification_no_second_attributed_record` |

<!-- assumption-tested 2026-08-06 — gate-3-before-3.5 ordering HOLDS (reorder mutation red, no masking); by-construction binding HOLDS for the two reference adapters (normalize mutation red); both dead citations in this table re-pointed same run; 2026-10-09: the webhook half is superseded by #188, the body-to-identity binding is now enforced by the dispatcher's gate-3 check rather than by construction -->

The owner cases are proven across three suites — the owner adapter +
dispatch (`test_owner_adapter.py`), the drain fork (`test_drain_owner.py`), and
the out-of-band release seam (`safe_agents/broker/tests/test_out_of_band_approval.py`,
`safe_agents/broker/tests/test_release_revalidation.py`):

| Clause | Test |
|---|---|
| mapped address + trusted identity → all 9 gates run, stamped `sender_class == "owner"` | `test_owner_adapter.py::test_owner_mapped_trusted_runs_all_gates_and_stamps` |
| unknown/unmapped address → one `DropRecord`, `principal_mismatch`, at gate 5 | `test_owner_adapter.py::test_owner_unmapped_address_drops_principal_mismatch` |
| unknown *identity* on the owner channel → `unmapped` (gate 5's other arm) | `test_owner_adapter.py::test_owner_unknown_identity_drops_unmapped` |
| address-less message → gate-3 `malformed`, no default principal synthesized | `test_owner_adapter.py::test_normalize_raises_on_address_less_message` |
| admitted owner command still routes every call through the broker (no auto-allow) | `test_drain_owner.py::test_owner_command_takes_normal_turn_not_approval_fork` |
| owner `/approve` forks to `approve_intent`/`reject_intent`; non-owner approval payload does NOT fork | `test_drain_owner.py::test_owner_approval_yes_forks_to_approve_intent` · `::test_non_owner_approval_shaped_payload_does_not_fork` |
| an owner may not release another principal's held intent (confused-deputy guard) | `test_out_of_band_approval.py::TestForeignIntentGuard` |
| an owner approval does not overcome authority withdrawn since the hold (grant revoked, cap exhausted) | `test_release_revalidation.py::test_grant_revoked_between_hold_and_release_refuses` · `::test_action_cap_exhausted_between_hold_and_release_refuses` |
| the owner adapter addresses its envelope to the airlock that built it, with verification on or off, and nothing in the request sets the audience | `test_owner_adapter.py::test_owner_envelope_is_addressed_to_the_airlock_that_built_it` · `::test_nothing_in_the_request_sets_the_owner_envelopes_audience` · `::test_an_owner_adapter_built_for_another_zone_is_refused_like_any_sender` |
| every registered adapter factory takes the airlock's zone | `test_manifest.py::test_every_registered_adapter_factory_takes_the_airlock_zone` |
| `zone` is required with no default; a missing, empty or padded zone fails the load; a manifestless airlock runs as `unconfigured` and drops everything | `test_manifest.py::test_zone_is_required_and_has_no_default` · `::test_a_manifest_without_a_zone_is_refused_and_told_why` · `::test_a_manifest_file_without_a_zone_does_not_load` · `::test_a_zone_that_could_never_match_is_refused` · `test_airlock_handler.py::test_an_airlock_with_no_manifest_drops_everything` · `::test_a_configured_manifest_that_names_no_zone_accepts_nothing` |
| every shipped example manifest names a different zone, and an envelope addressed to one is dropped `audience_mismatch` at each of the others | `test_manifest.py::test_every_shipped_manifest_is_listed_and_names_its_own_zone` · `::test_a_shipped_airlock_accepts_an_envelope_addressed_to_it` · `::test_an_envelope_addressed_to_one_shipped_airlock_is_refused_at_every_other` |
| unknown adapter kind rejected loudly at manifest validation (discriminated union) | `test_manifest.py::test_unknown_adapter_kind_fails_validation_loudly` |
| `routing` set on a non-owner adapter fails loudly | `test_manifest.py::test_routing_on_non_owner_adapter_fails_loudly` |

## Relationships

- `channels/SCHEMAS.md` — the envelope every gate operates on.
- `channels/TRUST-MAPPING.md` — gates 5 and 8; the DropRecord type.
- `channels/SCREENING.md` — gate 7's standard; injected here, owned there.
- Multi-channel routing — deferred until a second live channel exists, and deliberately not
  designed here.
- The owner channel — the owner inbound case, the adapter-selection seam, and the addressing doctrine above;
  the N-principal admission fan (per-principal config selection inside the one handler, keyed by the
  normalized principal) stays a follow-up, unbuilt until a second live consumer agent exists.
- `core/arms.md` — the wake mechanism the emitted EventTrigger triggers differs per arm; the
  airlock abstracts over it.
