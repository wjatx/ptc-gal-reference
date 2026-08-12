# DRAIN — the accepted-queue drain worker contract (sa#155)

> **Status: contract (2026-07-09), with one named reference component.** Contract-tier per
> `docs/contract-vs-reference.md`: this document is the normative words and
> `safe_agents/channels/tests/test_drain_handler.py` is the conformance suite.
> `safe_agents/channels/drain/handler.py` — the SQS-triggered Lambda handler — is
> **reference-tier**: it exists so the clauses below are executable, and any third-party drain (any
> queue, any compute) must satisfy the same suite. The **Receiver is consumer code**, injected per
> D6 — the base ships the protocol (`safe_agents/channels/drain/receiver.py`), never an
> implementation. The transport (SQS, `safe-agents-{env}-channel-accepted`) is named only in
> §"Reference binding".

## What the drain is

The airlock (sa#152) ends at gate 9: exactly one stamped `EventTrigger` per deduplicated inbound
message, enqueued for the worker side. The drain is that worker side — the bridge
`channels/ADAPTERS.md` §"Gate ordering" left reference-tier ("the stamped envelope must reach the
turn"). Per message it opens an **ephemeral, in-process brokered turn**: build the receiving
principal's `BrokerRuntime` from the image-baked `AgentManifest`, feed the envelope's provenance
chain into that runtime's broker-held session turn (`ingest_chain`, closing `channels/SCHEMAS.md`
C5), and only then hand the envelope to the consumer's Receiver — which acts **through that same
runtime**, so every action it takes is decided under the taint the chain carried in (sa#136: one
turn spans ingest and action; the receiver cannot act on a cleaner turn than it ingested).

The drain adds **no second trust surface**. Screening, trust-mapping, dedupe, and stamping happened
at the airlock; the worker trusts the stamp. What the drain does add is the three checks only the
worker can make — the envelope parses as the contract schema, it has not passed its hard TTL
(`channels/SCHEMAS.md` C6, re-checked here because queue latency post-dates the airlock's gate 4),
and it addresses the principal this runtime serves — plus the ordering guarantee above.

## The Receiver seam

```ts
// STUB — illustrative; the canonical encoding is drain/receiver.py
interface Receiver {
  input_trust_map(): InputTrustMap      // the receiver's OWN per-source trust policy (TRUST-MAPPING.md §"Two maps")
  receive(envelope, brokered_calls)     // the action hook — called AFTER ingestion, acts only through the facade
}
```

- **The receiver owns its map.** `ingest_chain` combines the chain's label floor with the
  receiver's `InputTrustMap` (`channels/TRUST-MAPPING.md` §"The one-way rule", consequence 2); the
  base supplies no default map, and no drain mechanism may lower the derived taint.
- **The facade is the only egress — and carries no turn controls.** `receive` gets a minimal
  brokered-call facade exposing ONLY `handle_request`, never connectors, credentials, or the
  runtime's turn surface (`new_turn()`/`session_turn()`): a receiver handed the raw
  `BrokerRuntime` could roll the ingested taint away before acting, which D2 forbids. A receiver
  that needs its own connector classes injects them the sa#141 way, through the manifest's
  `connector_providers`.
- **Injection mirrors sa#141 exactly.** The receiver class is named by an image-baked dotted
  provider path (`"pkg.module:ClassName"`), importlib-loaded, zero-arg instantiated, and
  protocol-checked — fail-closed with a typed `ReceiverProviderError` on any failure.

## Contract clauses

- **D1 — ingest before act.** Every provenance source of the envelope is fed into the broker-held
  turn (`ingest_chain`: chain label floor AND the receiver's `InputTrustMap`) **before** the
  Receiver's action hook runs. No drain path reaches `receive` with an un-ingested chain.
- **D2 — one turn, and the receiver cannot roll it.** Ingestion and the Receiver's actions share
  the **same** broker-owned session turn of the **same** runtime, per message and fresh per
  message. The receiver neither supplies nor rolls the turn (sa#136) — enforced structurally: the
  object handed to `receive` is a facade exposing only `handle_request`, with no
  `new_turn()`/`session_turn()` reachable. A tainted chain therefore escalates the receiver's
  external writes exactly as `broker/TAINT.md` §5 requires.
- **D3 — trust the stamp.** The drain performs no re-screening, no re-stamping, no trust-map
  re-resolution, and no dedupe. The airlock is the sole gate surface; a drain that re-judges
  content would be a second, divergent policy engine (and a drain that re-stamped would violate
  the one-way rule's append-only discipline).
- **D4 — receiver idempotency is a contract obligation.** The airlock→drain handoff is
  at-most-once *per dedupe key* but the queue delivers at-least-once: duplicates — including
  concurrent ones — can reach `receive` (see `docs/channels-airlock-bringup.md` §Operational
  boundaries). `receive` MUST be idempotent on `(sender.channel_identity, event_id)`. The drain
  deliberately ships no second dedupe store: the broker's own idempotency and approval mechanisms
  already gate the actions that matter, and a worker-side store would be a second trust surface
  (D3) that masks non-idempotent receivers instead of fixing them.
- **D5 — principal match.** The constructed runtime is single-principal from the manifest. An
  envelope whose `principal` does not name that principal is a hard, structured-logged per-record
  failure **before any runtime is built** — never a re-route (the airlock-side rule of
  `channels/TRUST-MAPPING.md` restated at the worker, for defense in depth across the queue hop).
- **D6 — the receiver is image-baked.** The provider path is honored ONLY from the image-baked
  environment (`CHANNELS_DRAIN_RECEIVER`), the manifest ONLY from the image-baked path
  (`CHANNELS_DRAIN_MANIFEST`) — never from anything store-loaded and never from the message.
  Missing or invalid config fails the whole invocation loudly (typed error + structured log);
  a bad provider raises `ReceiverProviderError`, never degrades to a silent drop.
- **D7 — per-record disposition: terminal vs transient.** A failing record never kills its batch
  siblings, and its disposition depends on whether redelivery can help. **Terminal** failures —
  malformed body, principal mismatch (D5), expired envelope (D9) — are permanently bad: they are
  logged with a structured `drain_terminal_drop` event (machine `reason` field) and treated as
  handled, NOT reported for redelivery. The queue deliberately has no DLQ, so redelivering them
  would poison-loop for the retention period and then vanish silently; the structured log is the
  observable surface (alarm-able the sa#153 way). **Transient** failures — a receiver exception,
  a runtime build failure — are reported for redelivery (`reportBatchItemFailures` semantics).
  Config failures (D6) are the deliberate exception: the whole invocation errors.
- **D8 — PII-safe observability.** Structured log lines carry machine fields only — event ids,
  `sha256:` identity digests, exception type names — never payload content, raw identities, or
  validation messages (which embed input values). The airlock's drop-log discipline, worker-side.
- **D9 — expiry is re-checked at the worker.** `channels/SCHEMAS.md` C6's hard TTL is enforced
  again here, because queue latency post-dates the airlock's expiry gate: an envelope whose
  `expiry` has passed is dropped (structured `drain_expired` log, D8-safe) **before** ingest,
  runtime construction, or any other budget-spending step, and is terminal per D7 — never
  redelivered, never handed to the receiver.

## Conformance

| Clause | Test (`test_drain_handler.py`) |
|---|---|
| D1 | `test_ingest_precedes_receive` |
| D1 label floor | `test_trusted_label_and_trusted_map_leave_turn_clean` · `test_untrusted_label_taints_despite_trusting_map` · `test_trusted_label_earns_nothing_receiver_map_denies` |
| D2 | `test_ingest_and_action_share_one_turn` · `test_receiver_gets_facade_without_turn_controls` |
| D3/D4 | `test_duplicate_records_both_delivered_receiver_owns_idempotency` |
| D5 | `test_principal_mismatch_drops_terminally_without_receive` |
| D6 | `test_missing_receiver_env_fails_whole_invocation` · `test_missing_manifest_env_fails_whole_invocation` · `test_bad_receiver_provider_path_fails_closed_typed` · `test_load_receiver_rejects_bad_providers` |
| D7 | `test_terminal_records_never_reported_transient_siblings_unaffected` · `test_malformed_body_drops_terminally_without_killing_batch` · `test_receiver_exception_is_transient_fails_its_record_only` · `test_terminal_drop_log_carries_machine_reason` |
| D8 | `test_malformed_record_logs_no_payload` · `test_structured_logs_carry_digest_never_identity` · `test_expired_drop_log_is_pii_safe` |
| D9 | `test_expired_envelope_drops_terminally_before_ingest` |

## Reference binding

Everything here is **reference-tier** — named here and only here:

- **Transport:** the sa#152 accepted queue (`safe-agents-{env}-channel-accepted`, SQS) triggering
  the container-image Lambda `safe_agents/channels/drain/handler.py` (entrypoint
  `safe_agents.channels.drain.handler.handler`) with `batchSize: 1` and
  `reportBatchItemFailures` enabled — D7 is implemented batch-correctly regardless.
- **Runtime construction:** `build_runtime(manifest)` (`broker/prototype/broker_server.py`),
  backends selected by its existing env contract (`BROKER_STORE`, `BROKER_AUDIT_*`,
  `BROKER_SECRETS`, `BROKER_ENVELOPE_LOAD`). The session turn is reached through
  `BrokerRuntime.session_turn()` — the trusted-driver surface, sibling of `new_turn()`.
- **Env contract:** `CHANNELS_DRAIN_MANIFEST` (in-image `AgentManifest` yaml/json path) and
  `CHANNELS_DRAIN_RECEIVER` (dotted receiver provider path), both baked into the consumer image
  layer like the airlock's `CHANNELS_MANIFEST`. The deployment MUST also set
  `BROKER_AUDIT_PREFIX` (infra binds `audit-drain/`) so the drain's audit records land under a
  distinct S3 key prefix: `S3ObjectLockSink.resuming` continues the max-seq chain under its
  prefix, and two writers sharing `audit/` would fork the broker service's hash chain. The grant
  HMAC key arrives via `BROKER_HMAC_KEY_SECRET_ARN` (Secrets Manager ARN): the handler fetches it
  once at cold start and exports it as `BROKER_HMAC_KEY` for `build_runtime`'s grant store, so
  the key plaintext never sits in Lambda env config; an ARN that is set but unfetchable fails
  the invocation closed, and the key value is never logged.

## Relationships

- `channels/SCHEMAS.md` (sa#74) — the envelope; C5 ("the chain feeds the receiving turn") is
  closed at this seam; the "ephemeral worker" of §"What the EventTrigger is" is this worker.
- `channels/ADAPTERS.md` (sa#80) — the gate ordering that produced the stamped envelope; its
  "stamped envelope must reach the turn" clause is D1/D2 made contract.
- `channels/TRUST-MAPPING.md` (sa#81) — the label floor `ingest_chain` enforces; the two-maps
  distinction the Receiver's `input_trust_map()` lives on.
- `broker/TAINT.md` — the floor: source-based, path-recorded, non-strippable; §5 is what D2 buys.
- `docs/turn-identity.md` (sa#136) — why the turn is broker-owned and per-message here.
- `docs/contract-vs-reference.md` — the packaging rule this doc follows: contract = base,
  worker = reference, receiver = consumer.
