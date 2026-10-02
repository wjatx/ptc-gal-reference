# SIGNING — authenticating the outbound provenance chain (PTC Phase 4)

> **Status: contract (2026-07-10).** Contract-tier per `docs/contract-vs-reference.md`: this document
> is the normative words, `safe_agents/channels/signing.py` (the DSSE statement, PAE, `ChainSigner`,
> `verify_chain`) plus the `ChainSignature` model (`safe_agents/channels/schemas/event_trigger.py`)
> are the typed encoding, and `safe_agents/channels/tests/test_signing.py` is the conformance suite.
> The boto3 cold-start key resolution (`safe_agents/channels/keys.py`) and the airlock deploy binding
> are **reference-tier** — one instantiation of the verify seam, not the contract. The **taint floor
> is unchanged** (`broker/TAINT.md`): signing authenticates *who asserted a hop*, it does not replace
> source-based taint. Implements the shape decided in `docs/tce-signing-shape.md`; companion to
> `channels/PUBLISH.md` (the unsigned outbound seam this signs).

## What signing is — and what it is not

`channels/PUBLISH.md` today emits an **unsigned** provenance chain: a receiving broker trusts the
chain only because it trusts the transport (a shared secret to a pre-declared peer). That is enough
for `safe-agents ↔ safe-agents` over a private wire, but it does not survive a hostile intermediary,
does not compose across a wider mesh, and is not *non-repudiable* — a receiver cannot later prove
which broker asserted a hop (`docs/tce-signing-shape.md`, PTC §9). Signing turns the chain from
*asserted* into *authenticated*.

It is **not** a taint mechanism and **not** a correctness proof. A signature is non-repudiation of
*who asserted a hop*, never a proof that taint was correctly propagated through a transform (the
banked §8 problem, `docs/tce-signing-shape.md`) and never a substitute for the receiver's own trust
map. An authenticated chain is still re-derived and re-gated at the receiver's airlock exactly as an
unsigned one is (`broker/TAINT.md`, `channels/TRUST-MAPPING.md`).

**Name-agnostic.** The "PTC" / "TCE" names of `docs/PTC.md` are provisional pending the maintainer's
standards-body naming pass and appear in **no code, schema, or wire constant** here. The DSSE `payloadType`, in-toto
`_type`, and versioned `predicateType` URIs (`safe_agents/channels/signing.py`) are the only stable
identifiers; the predicate type is versioned so the normative wire schema can bump it.

## The signing shape

The shape is `docs/tce-signing-shape.md`'s Decision, built:

- **Ed25519** signatures — asymmetric, so a receiver holds only the public key and cannot forge a
  sender's chain (the non-repudiation §9 needs). The private key is the **broker's** workload
  identity; the agent holds no key and cannot sign.
- The signature is over a **DSSE pre-authentication encoding (PAE)** of an **in-toto-style
  statement** binding, together: `subject` = a canonical hash of the actual inline `payload`,
  always, so a swapped payload breaks the signature, plus a second subject binding `payload_digest`
  and `payload_ref` when the envelope names a raw original (S1c), `predicate.hops` = the ordered
  provenance hops,
  `predicate.signer` = this signature's own `key_id`/`zone` (so attribution is non-malleable), and
  `predicate.envelope` = every other field of the envelope except the two that are unsigned by
  design (S1d), with `sender.channel_identity` in canonical form (`signing.canonical_identity`,
  byte-identical to the adapters' own `_canonical_identity`). Canonical JSON (sorted keys, no whitespace, ASCII) so sign
  and verify agree byte-for-byte; DSSE PAE binds the `payloadType` so a signature cannot be replayed
  under a different type.
  **Why `sender.channel_identity` is bound (campaign-watchdog residual, 2026-07-18).** `EventTrigger
  .dedupe_key()` is `(sender.channel_identity, event_id)`, and `sender.channel_identity` is
  agent/wire-authored. Before this field joined the bound set, a captured signed envelope could be
  replayed with a mutated sender claim — landing a fresh dedupe key, and, pre-dedupe, a fresh
  watchdog attribution bucket (`channels/WATCHDOG.md` §"Replay soundness") — without ever
  invalidating the signature. Binding it means the dedupe key's sender half is now
  signature-bound exactly like its `event_id` half already was: an exact replay dedupes, and ANY
  mutation — to `event_id` or to `sender.channel_identity` — breaks the signature and lands in the
  `FORGERY_REASONS` class, attributed to transport only, never to the impersonated signer.
- **Per-envelope signing.** The sending broker signs the **full chain as it leaves** —
  `ChainSignature.covers = len(provenance)` — including any preserved upstream hops. Attribution
  *within* the envelope is real: `predicate.signer` is bound into the signed bytes and the verifier
  requires a signature's `zone` to equal the top hop it covers. Inbound signatures are **not** carried
  onward: a relay re-packages a fresh payload/`event_id`/`principal`, so an upstream broker's
  signature (over its own envelope) could never verify against the downstream one. The upstream *hops*
  still ride as lineage; attributing each intermediate signer *across* a relay needs nested
  per-hop attestations and is **deferred to the normative spec**.

## Signing clauses

- **S1 — DSSE-over-in-toto, Ed25519, name-agnostic.** The signed bytes are the DSSE PAE
  (`DSSEv1 <len> <type> <len> <payload>`) of a canonical in-toto statement binding the payload hash
  (`subject`), the ordered hops, the signer identity, and the rest of the envelope
  (`predicate`); the algorithm is Ed25519; no PTC/TCE name appears in code, schema, or wire constant
  (`build_statement`, `pae`, `DSSE_PAYLOAD_TYPE` / `STATEMENT_TYPE` / `PREDICATE_TYPE`). The first
  subject always binds a hash of the *actual* inline `payload`, so a swap breaks verification whatever
  `payload_digest` or `payload_ref` the envelope carries; `event_id`, `principal`, `expiry` and the
  canonical `sender.channel_identity` are all bound too, so a signed envelope cannot be replayed
  under a fresh dedupe key (`(sender.channel_identity, event_id)`), an extended TTL, or a mutated
  `sender.channel_identity`.
- **S1c — the raw-original reference is bound, and so is its presence.** When the envelope carries a
  `payload_digest`, the statement has a second subject, `raw_original`, binding that digest and, when
  set, the `payload_ref` as its `uri`. An envelope that carries neither has one subject. A reference
  or digest therefore cannot be attached to, changed on, or stripped from a signed envelope. A
  reference with no digest, or a digest that is not exactly `sha256:` followed by 64 lowercase hex
  digits, is refused at signing and fails verification as `SIGNATURE_INVALID`. That the bytes behind
  the reference match the digest remains the dereferencing zone's check (reference-tier,
  `channels/SCHEMAS.md`).
- **S1d — the whole envelope is signed by default.** `predicate.envelope` is the envelope itself
  with a short, named list of fields left out (`bound_envelope`), where v1 signed a short list of
  fields put in. Two fields are unsigned, each for a reason: `sender_class` is the receiver's to set,
  and the receiver discards whatever arrived before any gate reads it (`channels/ADAPTERS.md`, gate
  3); `chain_signatures` are the signatures themselves. `payload`, `payload_digest` and `payload_ref`
  are bound as subjects and `provenance` as hops. Everything else is in the predicate: today
  `schema_version`, `event_id`, `principal`, the whole `sender` claim, `ts` and `expiry`. A field
  added to the envelope later is signed without anyone adding it to a list, and
  `test_every_envelope_field_is_signed_or_named_as_unsigned` fails if the partition stops covering
  the model. The signer is handed the finished envelope (`ChainSigner.sign_envelope`), never a set
  of values beside it, so what is signed and what is sent cannot differ. Signing refuses a payload
  JSON cannot carry as given (NaN, Infinity, a non-string key), because serializing it would change
  it after the signature was made.
  **Why the predicate type is v2 (2026-10-01).** The v1 statement had two faults with one cause, an
  enumerated list of what to sign. It bound the declared digest *in place of* the inline payload
  whenever a `payload_ref` was present and did not bind the reference, so a signed inline envelope
  verified with its payload swapped, a `payload_ref` attached, and `payload_digest` set to the hash
  of the original payload (GHSA-wfrf-hcqh-pw8x). It also left `ts`, `sender.channel_type`,
  `sender.evidence` and `schema_version` outside the signature, so a party with no key could change
  them, and receivers record `ts`. The statement changed shape, so `PREDICATE_TYPE` moved to
  `provenance-chain/v2` and was not redefined in place. The verifier rebuilds the statement and the
  wire does not carry its type, so a v2 verifier reports a v1 signature as `SIGNATURE_INVALID`.
- **S2 — per-envelope signing, non-malleable attribution.** The sending broker signs the full chain as
  it leaves (`ChainSigner.sign_envelope`, `covers = len(provenance)`), including preserved upstream hops.
  The signature's own `key_id`/`zone` are bound into the signed bytes and the verifier requires the
  `zone` to equal the top hop it covers, so attribution within the envelope cannot be forged or
  relabelled. Inbound signatures are not carried across a relay (it re-packages the envelope);
  cross-relay per-signer attribution is deferred to the normative spec.
- **S3 — broker-keyed, the agent never signs.** The private key is the broker's workload identity,
  resolved at cold start from Secrets Manager (`keys.resolve_signer`, `BROKER_SIGNING_KEY_SECRET_ARN`
  → PEM, `BROKER_SIGNING_KEY_ID` → `key_id`) and injected into `stamp_outbound` as the `signer`
  param. It is never in the agent image and never a caller/agent assertion — the same floor
  `channels/PUBLISH.md` P1/P3 stands on.
- **S4 — receiver verification & quarantine, fail-closed.** `verify_chain` rejects a chain with no
  signatures (`SIGNATURE_MISSING`), an unknown signer (`SIGNER_UNKNOWN`), a `covers` outside
  `[1, len(provenance)]` or a bad signature (`SIGNATURE_INVALID`), or no signature covering the full
  chain (the sending broker did not commit to the hop it just added → `SIGNATURE_INVALID`). Every
  present signature must verify — a valid full-cover signature does not excuse a forged prefix
  signature riding alongside it. A failure drops and quarantines, mirroring the grant-HMAC loud
  quarantine; it authenticates lineage but does **not** clean taint — the receiver still
  applies its own trust map and re-derives taint from the chain (`broker/TAINT.md`,
  `channels/TRUST-MAPPING.md`).
- **S8 — a key verifies only for the zone and sender it is enrolled for.** Being known to the
  receiver does not let a key speak for every peer. Each verification key is enrolled with one
  `zone` and a non-empty list of `sender_identities` (`signing.PeerKey`). A signature whose `zone`
  is not its key's zone fails, and a full-cover signature fails unless its key is enrolled for the
  envelope's canonical `sender.channel_identity`. Both are `SIGNATURE_INVALID`, with the drop
  record's `detail` set to `signer_zone_mismatch` or `signer_identity_out_of_scope`. The scope comes
  from the receiver's own configuration and never from the envelope. Without it, any enrolled broker
  could sign an envelope naming another broker's zone and identity, and the receiver's trust map
  would resolve the impersonated identity and record `sig:pass`. The verification-keys secret is
  JSON of the form `{key_id: {"public_key": PEM, "zone": ..., "sender_identities": [...]}}`
  (`keys.peer_key_resolver_from_map`). An entry with a missing, empty or unrecognized field is a
  `SigningConfigError` naming the key, including a bare PEM string, which was the format before keys
  had a scope: an unscoped key would be trusted for every zone and sender.
- **S5 — ships OFF (friction doctrine).** With no verification-keys ARN configured
  (`BROKER_VERIFY_KEYS_SECRET_ARN` unset → `resolve_verification_keys()` returns `None` →
  `make_gate(None)` returns `None`), the airlock skips the verify gate (Gate 3.5) and unsigned peers
  pass — today's trust-by-transport behavior. Enabling verification is a deploy-config knob, exactly
  as every non-floor bound is (`docs/friction-doctrine.md`). A set-but-unfetchable or malformed ARN
  fails **closed** loudly (`SigningConfigError`) rather than silently degrading to no verification.
- **S6 — what signing does NOT do.** A signature is non-repudiation of *who asserted a hop* — never
  correctness-of-propagation. Whether a model faithfully carried taint through a transform is the
  banked §8 problem (`docs/tce-signing-shape.md`, `channels/PUBLISH.md` P8), unsolved by signing.
  Carrying lineage (`channels/PUBLISH.md` P8) and signing it are orthogonal: signing makes the
  asserted lineage attributable, not correct.
- **S7 — tiering.** The signature format and verification semantics (`signing.py`, the
  `ChainSignature` schema) are **contract-tier** with the `test_signing.py` conformance suite as its
  teeth. The boto3 key resolution (`keys.py`) and the airlock deploy binding are **reference-tier** —
  one instantiation of the sender's `signer` seam and the receiver's `verify_chain` seam, both
  key-injected so the crypto module stays pure. The **taint floor is unchanged** — signing adds an
  authentication layer over the chain, it does not touch source-based non-strippable taint.

## Where the seam binds

- **Sender.** `stamp_outbound(..., signer=...)` (`safe_agents/channels/publish.py`) — when a
  `ChainSigner` is supplied the outbound chain is signed (this zone's signature covers the full
  chain as it leaves, preserved upstream hops included); `signer=None` emits an unsigned chain.
  `keys.resolve_signer(zone)` builds the `ChainSigner` at cold start. **Inbound signatures are NOT
  carried onward** (PTC-13, S2): a relay re-packages the envelope under its own `event_id`, `expiry`
  and sender claim, and an upstream signature binds the whole envelope it was made
  for, so it could not verify against the new one. The upstream *hops* still ride as lineage,
  covered by this zone's signature. An earlier revision of this line said inbound signatures were
  preserved, which contradicted PTC-13 and `publish.py`; it never described the code.
- **Receiver.** Gate 3.5 in `safe_agents/channels/dispatch.py` — the injected `verify_chain` seam,
  placed **after `normalize` (Gate 3) and before `expiry` (Gate 4)** so a forged chain is rejected
  before any trust-map, dedupe, or screen budget is spent (the same reasoning that puts expiry ahead
  of the budget gates). A drop uses the verification reason verbatim (a closed `DropReason`
  vocabulary). On success, Gate 8 records `sig:pass` in the receiver's provenance evidence **only when
  the gate actually ran** — evidence of a check performed, never asserted for an unverified chain
  (the same discipline as `sender.evidence`). `resolve_verification_keys()` builds the scoped
  resolver (S8), or `None` to ship the gate OFF.

## Conformance

| Clause | Test (`test_signing.py`) |
|---|---|
| S1 (shape) | `test_valid_signed_chain_verifies` · `test_tampered_payload_fails_closed` · `test_payload_swap_with_pinned_digest_fails_closed` · `test_replay_with_fresh_event_id_or_extended_expiry_fails_closed` |
| S1b (`sender.channel_identity` bound — campaign-watchdog residual closure) | `test_mutated_sender_after_signing_fails_verify_chain` · `test_mutated_sender_replay_fails_verification_no_second_attributed_record` · `test_sign_verify_round_trip_with_non_canonical_sender_spelling` · `test_relay_resign_binds_the_relays_own_sender_not_the_inbounds` |
| S1c (inline payload always bound; raw-original reference and its presence bound) | `test_payload_swap_behind_an_added_payload_ref_fails_closed` · `test_inline_payload_and_raw_original_reference_are_bound` · `test_forged_payload_ref_envelope_drops_at_the_webhook_gate` · `test_nested_payload_content_is_bound` · `test_statement_subjects` · `test_statement_and_payload_hash_are_canonical_json` · `test_statement_refuses_a_raw_original_it_cannot_bind` |
| S1d (whole envelope signed by default) | `test_every_envelope_field_is_signed_or_named_as_unsigned` · `test_the_mutation_table_covers_every_signed_field` · `test_no_signed_field_can_change_after_signing` · `test_the_receiver_owned_class_is_outside_the_signature` · `test_signing_refuses_a_payload_json_cannot_carry` |
| S2 (per-envelope signing, non-malleable attribution) | `test_relay_signs_full_chain_over_preserved_hops` · `test_tampered_hop_fails_closed` · `test_signature_attribution_is_not_malleable` |
| S3 (broker-keyed, agent never signs) | `test_broker_signs_agent_has_no_key` · `test_signing_key_resolved_at_cold_start_from_secret` |
| S4 (verify & quarantine, fail-closed) | `test_tampered_hop_fails_closed` · `test_tampered_payload_fails_closed` · `test_unknown_signer_quarantines` · `test_unsigned_chain_missing` · `test_covers_out_of_range_invalid` · `test_no_full_cover_signature_invalid` · `test_forged_chain_drops_before_trust_map` |
| S8 (a key verifies only within its enrolled zone and sender identities) | `test_an_enrolled_key_cannot_sign_for_another_zone` · `test_an_enrolled_key_cannot_sign_for_another_sender` · `test_each_peer_still_verifies_within_its_own_scope` · `test_a_verification_key_without_a_full_scope_is_refused` · `test_verification_keys_resolve_and_fail_closed` |
| S5 (ships OFF) | `test_verification_ships_off_unsigned_passes` |
| S4/S5 (gate placement + evidence) | `test_verify_gate_runs_after_normalize_before_expiry` · `test_sig_pass_evidence_recorded` |
| S6 (non-repudiation ≠ correctness) | the absence of any propagation-correctness claim is the contract text itself (the banked §8 problem) |
| S7 (tiering) | tiering is doctrine (`docs/contract-vs-reference.md`), asserted by the suite existing as the contract's teeth, not a single test |

<!-- assumption-tested 2026-08-06 — S1b HOLDS: all four cited test names exist, and zeroing sender_channel_identity in the signed statement turned exactly the three mutation-detection tests red (verification succeeded where a refusal was demanded) -->


## Relationships

- `docs/tce-signing-shape.md` — the design note this implements; the shape (DSSE + in-toto,
  broker-keyed, per-hop) is decided there, built here. Sub-decisions still open (SPIFFE vs DID,
  Rekor anchoring) stay in that note.
- `channels/PUBLISH.md` — the unsigned outbound seam this signs; `stamp_outbound`'s `signer`
  param is the sender-side binding. P8 (lineage, not a collapsed taint bit) is what signing
  authenticates — orthogonal to correctness-of-propagation.
- `broker/TAINT.md` — source-based, non-strippable taint. Signing authenticates lineage; it does
  **not** replace taint. The receiver re-derives taint from the chain regardless of signature status.
- `channels/TRUST-MAPPING.md` — the receiver's trust map is authoritative for what a verified
  hop earns; authenticity raises the action surface but never cleans taint.
- `channels/SCHEMAS.md` — `ChainSignature` and `EventTrigger.chain_signatures`, the wire
  fields the signature travels in.
- `docs/friction-doctrine.md` — verification is a knob shipping OFF (S5); the floor stays tiny.
- `docs/contract-vs-reference.md` — the tiering S7 records: contract (signing semantics + conformance)
  vs reference (key resolution, airlock binding).
- `channels/WATCHDOG.md` §"Replay soundness" — the reflected-DoS reasoning `sender.channel_identity`
  binding (S1b) closes: signer attribution is sound only when the dedupe key's sender half is
  itself signature-bound, or a captured envelope could be replayed under a fresh attribution bucket
  without forging anything.
- `channels/ADAPTERS.md` §"Sender-transport binding" — the dispatch-gate-3 backstop for the same
  `sender.channel_identity` field, covering the cases signing does not (verification OFF, not yet
  run, or an adapter whose own gate-2/gate-3 identity extraction diverges independently).
