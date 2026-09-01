# WATCHDOG — the input-poisoning campaign watchdog (sa#161)

> **Status: contract (2026-07-18).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, `safe_agents/watcher/campaign.py` is the typed encoding (the
> pure correlation engine: `ObservedEvent`, `FloodEvent`, `CampaignThresholds`,
> `AttributionBasis`, `CampaignReport`), and `safe_agents/watcher/tests/test_campaign.py` is the
> conformance suite. The scheduled runner (`safe_agents/watcher/campaign_runner.py`) and its
> GitHub Actions cron are **reference-tier** — one instantiation of the engine, mirroring
> `safe_agents/watcher/liveness.py` (sa#38). No classifier, threshold value, or schedule is named
> in this document.

## What the watchdog is — and the one direction it may act

Every gate in the airlock (`channels/ADAPTERS.md`) makes a per-message, on-path decision under a
budget: verify, map, dedupe, screen. None of them can see a *pattern* across messages, senders, or
time — nor should they; a per-call gate that tried to correlate would spend request latency on
history it cannot act on safely. The campaign watchdog is the deliberately separate answer: an
**off-path, stateful observer** that reads the exhaust the airlock already produces —
`channels/drops/` DropRecords, `channels/verdicts/` ScreenRecords, and the broker's
`approval_queue_flood` log signal (`docs/friction-doctrine.md` §"The other direction: the approval
queue as an amplifier") — and correlates them into **attributed campaigns**, escalated to a human.

It is a **watchdog, never a screen**:

- **It never gates.** It holds no airlock or broker seam and cannot refuse, delay, or throttle a
  single request. `channels/SCREENING.md`'s boundary rule — "a screen refuses or passes, it never
  blesses" — has no watchdog analogue because the watchdog has no path to act on a request at all;
  it runs entirely after the fact, over records already written. `analyze()` is a pure function of
  its typed inputs (no boto3/botocore import, no clock read) — there is structurally nowhere for a
  gate to hide.
  <!-- assumption-tested 2026-08-06 — HOLDS by import graph both directions (no deciding import; nothing on a request path imports the watcher); unpinned by any test until #370 lands -->
- **It produces suspicion and a suggested remediation, never a safety decision.** Its output
  (`CampaignReport.suggested_remediation`) is a report a human reads. Applying a remediation is a
  human ceremony outside this contract, exactly as `channels/SCREENING.md`'s classifier only
  suspects and the dispatcher gate — not the model — decides.
- **It is itself a positive-safe-action agent.** Under the availability floor
  (`docs/friction-doctrine.md` §Availability/forced-abstention), silence from the watchdog *is* the
  harm it exists to prevent — a live campaign nobody is told about is exactly as bad as no watchdog
  at all. Any scheduled runner MUST satisfy the meta-alarm standard
  (`reliability/META-ALARM-STANDARD.md`): heartbeat, meta-alarm, and content-alarm on three separate
  channels, so a broken watchdog and a silent-because-nothing-fired watchdog are never confused.

## Inverting the attack economics

An attacker probing the airlock today pays nothing for a refused attempt — it is a drop, logged and
forgotten. The watchdog changes that calculus without changing a single gate's behavior:

- **Each attempt spends the attacker's anonymity.** Authenticated provenance (`channels/SIGNING.md`)
  means a repeated probe from the same signer, or the same unauthenticated transport identity,
  accumulates against itself across the correlation window — the attacker cannot get a clean slate
  by trying again.
- **It accelerates suggested lockout.** A campaign report crossing threshold names a remediation a
  human can apply immediately, rather than the pattern staying buried across separately-triaged drop
  log lines.
- **It donates a PII-safe corpus.** Every correlated campaign is evidence — digests, codes, counts,
  timestamps, source refs — a human or downstream tooling can use without ever touching raw sender
  content.

## Inputs

All three input surfaces already exist and are already PII-safe; the watchdog adds no new capture.
The runner (reference-tier) maps each surface onto the engine's typed inputs:

- **DropRecords** (`channels/drops/`, `channels/TRUST-MAPPING.md` §DropRecord) and refused
  **ScreenRecords** (`channels/verdicts/`, `channels/SCREENING.md`) map onto `ObservedEvent`:
  `channel_type`, `identity_digest`, `reason`, `detail`, `ts`, and the evidence-of-check pair
  `chain_verified` / `signer_key_id`. `reason` carries the closed `DropReason` vocabulary the engine's
  attribution tables key on (below); a passing ScreenRecord (`passed=True`) carries no signal and
  never becomes an `ObservedEvent` — there is nothing to correlate about a message that cleared the
  screen. **A runner must count each attempt once:** every screen refusal produces *both* a refused
  ScreenRecord and a `screen_refused` DropRecord (`safe_agents/channels/dispatch.py` gate 7), so a
  runner that ingests both surfaces double-counts and inflates campaigns toward its threshold. The
  reference runner therefore ingests DropRecords only; the verdict surface remains the human-review
  corpus.
- **The `approval_queue_flood` log signal** (`docs/friction-doctrine.md`, `safe_agents/broker/
  runtime/pep.py`) — a structured, PII-safe log line per breach: `agentId`, `op`, `cap` — maps onto
  `FloodEvent`: `agent_id`, `op`, `cap`, `ts`. No sender identity travels on this signal; it is a
  broker-principal event, not a channel event, and carries no `reason` of its own — the engine
  attributes it structurally, below.

**Evidence-of-check is stamped only by the airlock, never by the watchdog.** `chain_verified` and
`signer_key_id` are set exclusively at gate time (`channels/SIGNING.md` Gate 3.5, the `sig:pass`
provenance-hop precedent) by `stamp_inbound`'s callers — `DropRecord` and `ScreenRecord` both
structurally enforce this (`signer_key_id` may only be set alongside `chain_verified=True`; see
`safe_agents/channels/trust_map.py`, `safe_agents/channels/screening.py`), and `ObservedEvent`
re-enforces the same rule independently (`test_signer_key_id_requires_chain_verified`). The watchdog
reads these fields; it never infers, recomputes, or overrides them from runner config. An off-path
observer that could assert its own view of what was verified would be exactly the confused-deputy
hole the provenance chain exists to close. When `chain_verified=True`, `signer_key_id` is the
**full-cover signer's** `key_id` as `verify_chain` reports it (`channels/SIGNING.md` S4) — the broker
that committed to the entire chain as it left its own zone, never a partial-cover or non-existent
signature; a chain lacking a full-cover signature fails verification outright and never reaches the
airlock's evidence-of-check fields at all. When more than one enrolled key produces a valid full-cover
signature over the same chain, `verify_chain` reports the first match and the watchdog attributes to
that `key_id` — this is not a reflected-DoS gap: every candidate is an enrolled, trusted verify-key
sharing the same top-hop zone (`channels/SIGNING.md` S4), so attributing among them picks between
trusted parties rather than mis-attributing to an untrusted or victim identity.

## The attribution table — the reflected-DoS rule

Attribution is the center of this contract: attributing a poisoning attempt to the *wrong* party
turns the watchdog into a weapon (throttle recommendation against an innocent sender) instead of a
defense. The table below is exhaustive over every `DropReason` and the flood signal
(`safe_agents/watcher/campaign.py`'s `VECTOR_AUTH_REASONS` / `DEDUPE_CAPPED_REASONS` /
`FORGERY_REASONS` / `UNATTRIBUTABLE_REASONS`), and `attribution_key` is the exact string `analyze()`
groups on.

| Evidence | Authenticated as | Attribution basis | `attribution_key` | Throttle-eligible |
|---|---|---|---|---|
| `screen_refused` with `chain_verified=true` and `signer_key_id` set | the DSSE signer | `signed-chain` | `signer_key_id` | yes |
| `screen_refused` with `chain_verified=false` (or `chain_verified=true` with no `signer_key_id`, a conservative fallback) | gate-1 transport identity | `transport-token` | `f"{channel_type}#{identity_digest}"` | yes |
| `expired` / `unmapped` / `principal_mismatch`, **regardless of `chain_verified`/`signer_key_id`** | gate-1 transport identity | `transport-token` | `f"{channel_type}#{identity_digest}"` | yes |
| `chain_signature_missing` / `chain_signature_invalid` / `chain_signer_unknown` (forgery attempts) | transport identity **only — never the claimed signer**, even if `chain_verified`/`signer_key_id` were somehow set alongside a forgery reason | `transport-token` | `f"{channel_type}#{identity_digest}"` | yes |
| `authenticity_failed` / `malformed` / any reason the engine does not recognize | nobody | `unattributable` | `f"{channel_type}#{identity_digest}"` | **no** |
| `approval_queue_flood` | the broker principal + op (no sender identity on this signal) | `principal` | `f"{agent_id}#{op}"` | no |

The forgery row is the rule's load-bearing case: an attacker who signs a message claiming to be a
trusted peer, badly, wants the watchdog to throttle *that peer* — a reflected denial of service
against a party who did nothing. `chain_signer_unknown` and its siblings never resolve to the
claimed `signer_key_id`; only the transport identity that actually sent the bytes accrues attempts.
`_classify_observed_event` checks `FORGERY_REASONS` before it ever looks at `chain_verified`, so
there is no code path — malformed input or otherwise — through which a forgery reason resolves to a
signer. Throttling the forger costs the forger; throttling the impersonated identity would be the
attack succeeding through the watchdog.

`unattributable` is deliberately terminal, not a fallback to weaker attribution: an event the engine
cannot place anywhere still gets **reported** (it may be the leading edge of a real campaign) but
never counted toward a throttle recommendation, since there is no party left to hold accountable.

### Replay soundness — why `expired`/`unmapped`/`principal_mismatch` cap at transport-token

Signer (`signed-chain`) attribution is sound only for reasons that are **both signature-bound AND
dedupe-capped** — `safe_agents/watcher/campaign.py`'s `DEDUPE_CAPPED_REASONS`, today exactly
`{"screen_refused"}`. A forged *count* is as dangerous as a forged identity: the forgery row above
stops an attacker from putting words in a victim's mouth, but a reason that fires ahead of the
airlock's dedupe gate lets an attacker replay one genuinely victim-signed envelope byte-for-byte and
accrue an unbounded attributed count against that victim, without forging anything — the reflected
DoS the forgery row exists to prevent, reached by a different door.

Gate ordering is fixed (`safe_agents/channels/dispatch.py`): gate 3.5 verifies the chain signature,
gate 4 checks expiry, gate 5 resolves the trust map (`unmapped`/`principal_mismatch`), gate 6
dedupes, and gate 7 is the screen (`screen_refused`). Only `screen_refused` fires *after* dedupe;
`expired`, `unmapped`, and `principal_mismatch` all fire *before* it. An attacker who captures one
genuine victim-signed envelope can replay those exact bytes N times: each replay re-verifies
honestly (`chain_verified=true`, `signer_key_id=<victim>`) and then drops at gate 4 or 5, every
time — dedupe never runs, so nothing caps the replay, and N honestly-verified DropRecords accrue
against a signer who sent exactly one message. `screen_refused` has no such hole: a byte-for-byte
replay dedupes silently at gate 6 (no DropRecord at all — the airlock's dedupe-then-screen ordering,
`dispatch.py` gate 6's docstring), and any change to the bytes needed to dodge dedupe — including a
fresh `event_id`, which rides the signed statement (`channels/SIGNING.md`) — breaks the signature,
landing the replay in `FORGERY_REASONS` instead, attributed to transport only.

Capping `expired`/`unmapped`/`principal_mismatch` at `transport-token` regardless of verification
strength stays sound: replaying requires possessing the captured transport token, and
`rotate_channel_token` is the correct remedy for a captured token whether or not the replayed
payload also carries a genuine signature.

**Signer attribution is sound (closed 2026-07-18, sa#161 residual).** `sender.channel_identity` —
the dedupe key's sender half, and what `transport-token`'s `attribution_key` digests — is now bound
into the signed statement alongside `event_id` (`channels/SIGNING.md` S1b,
`BoundContext.sender_channel_identity`). An exact byte-for-byte replay still dedupes silently at
gate 6 as before; ANY mutation an attacker makes to dodge dedupe — to `event_id`, as already true,
or now to `sender.channel_identity` — invalidates the signature and lands the replay in
`FORGERY_REASONS` (`chain_signature_invalid`), attributed to transport only, never to the
impersonated signer
(`test_signing.py::test_mutated_sender_replay_fails_verification_no_second_attributed_record`). The
dispatch-gate-3 sender-transport-binding check
(`channels/ADAPTERS.md` §"Sender-transport binding") remains a real but *separate* backstop — it
covers a divergent adapter's own gate-2/gate-3 identity extraction, independent of anything
cryptographic, and neither reference adapter can trip it (both derive the two extractions
identically from the same wire field).

**The remaining limitation is under-counting, not mis-attribution, and only when verification is
OFF.** Signing verification ships OFF by default (S5); with no verify-keys ARN configured, unsigned
peers pass Gate 3.5 and `sender.channel_identity` rides completely unauthenticated, exactly as
`channels/SIGNING.md`'s "Ships OFF" section already documents for attribution strength generally.
Under that (today's default) configuration, a holder of valid gate-1 transport credentials can still
claim a *fresh* `sender.channel_identity` on each attempt — no captured signature or replay even
required — landing each attempt under its own `transport-token` `attribution_key`
(`f"{channel_type}#{identity_digest}"`), so no single campaign ever crosses `min_attempts`. This
never mis-attributes to an innocent party (attribution stays keyed to what gate 1 actually attests:
a channel_type, not a false identity), so it is a detection-evasion / under-counting gap, not a
reflected-DoS one — but it does mean the watchdog's coverage for unsigned traffic is only as strong
as gate 1's credential granularity. Closing it needs a volume-based throttle keyed on the gate-1
credential itself (or a lower-cardinality identity than the self-asserted `channel_identity`) rather
than the fragmentable per-attempt claim — tracked as the deferred "enforced throttle seam" follow-up,
not implemented here. Enabling signing verification is the immediate, already-shipped mitigation for
any consumer who needs stronger correlation than this today.

**Attribution granularity is the sending broker**, not an individual upstream agent behind it — a
consequence of `channels/SIGNING.md` S2 (per-envelope signing; inbound signatures are not carried
across a relay). Cross-relay per-signer attribution is deferred with signing itself, to the
normative spec (#178, #180).

## Grouping, windows, and campaign identity

`analyze(events, floods, thresholds, now)` groups strictly by `(kind, basis, attribution_key)` —
`kind` is `"vector"` (from `ObservedEvent`s) or `"principal-flood"` (from `FloodEvent`s); a
`principal-flood` group's `counts_by_reason` always has exactly one key, the constant
`"approval_queue_flood"`, since a `FloodEvent` carries no `reason` of its own. An item is in-window
iff `window_start < ts <= now` where `window_start = now - thresholds.window_seconds` (exclusive
lower bound, inclusive upper bound); a group becomes a `CampaignReport` iff its in-window count is
`>= thresholds.min_attempts`. `campaign_id` is `"campaign-" + sha256(f"{basis}|{attribution_key}|
{window_start.isoformat()}")[:16]` — deterministic and reproducible across runs, never a random or
sequential id. `now` must be timezone-aware; a naive value is refused, matching the base's
no-naive-datetime floor.

## CampaignReport — what the watchdog may say

```python
# STUB — illustrative; the canonical encoding is watcher/campaign.py
class CampaignThresholds:       # extra="forbid" — exactly these two required fields
    min_attempts: int           # > 0
    window_seconds: int         # > 0

class CampaignReport:           # extra="forbid"
    campaign_id: str
    kind: Literal["vector", "principal-flood"]
    basis: AttributionBasis     # "signed-chain" | "transport-token" | "unattributable" | "principal"
    attribution_key: str
    throttle_eligible: bool
    window_start: datetime      # tz-aware
    window_end: datetime
    first_ts: datetime
    last_ts: datetime
    total: int
    counts_by_reason: dict[str, int]
    corpus_refs: list[str]              # opaque source refs (e.g. S3 keys) — never inline content
    suggested_remediation: list[str]    # validated against the closed vocabulary, below
```

`CampaignThresholds` has **no optional or extra fields** — the base ships no campaign policy at all,
not even a permissive default; a consumer that has not decided `min_attempts`/`window_seconds`
cannot accidentally run the watchdog at a base-chosen sensitivity.

**The remediation vocabulary is closed**, the same discipline as `ScreenVerdict`'s refuse codes: a
machine code, never free text derived from correlated content, validated at `CampaignReport`
construction. The base reserves exactly five codes, each naming a concrete existing lever rather
than an abstract action — the trust map, the gate-1 transport token, the verify-keys secret, the
screen config, and the pending-approval queue:

| Code | Names |
|---|---|
| `remove_trust_map_entry` | revoke a `(channel_type, identity)` entry from the trust map (`channels/TRUST-MAPPING.md`) |
| `rotate_channel_token` | rotate the gate-1 transport-verification secret for a channel |
| `unenroll_verify_key` | remove a signer's key from `BROKER_VERIFY_KEYS_SECRET_ARN` (`channels/SIGNING.md`) |
| `review_screen_config` | a human reviews screen strictness/config (`channels/SCREENING.md`) — the unattributable default, since there is no identity to act against |
| `review_pending_approvals` | a human reviews the held approval queue (`docs/friction-doctrine.md` §Availability) |

`analyze()` maps `suggested_remediation` from `basis` **deterministically**, with no per-report
variation:

| `basis` | `suggested_remediation` |
|---|---|
| `signed-chain` | `[remove_trust_map_entry, unenroll_verify_key]` |
| `transport-token` | `[remove_trust_map_entry, rotate_channel_token]` |
| `unattributable` | `[review_screen_config]` |
| `principal` | `[review_pending_approvals]` |

Consumers extend the vocabulary in their own runner/source, never at runtime
(`docs/config-provenance.md` Layer 1: anything that names a code path the runner will *act* on is
image-baked; the report itself is inert data). Applying any of these five is a **human ceremony**
outside this contract — the watchdog suggests, it never enacts. (An autonomy-ladder climb that lets
a proven-reliable watchdog apply low-blast remediations itself is plausible future work per the GAL
spine, `docs/GAL.md`, but is explicitly out of scope here.)

## Conformance

| Clause | Test (`test_campaign.py`) |
|---|---|
| W1 — never-gates: the engine is pure over its typed inputs, no AWS/broker/airlock seam, no clock read | `test_purity_no_aws_no_clock_reads` |
| W2 — attribution-at-recorded-strength: signed-chain basis derives from `chain_verified`/`signer_key_id` **and only for dedupe-capped reasons** (`DEDUPE_CAPPED_REASONS`); pre-dedupe reasons and forgery reasons never attribute to a signer, incl. the verified-conservative-fallback cases | `test_signed_chain_groups_by_signer_key_id_across_channel_types` · `test_vector_auth_reason_unverified_groups_under_transport_token` · `test_vector_auth_chain_verified_without_signer_key_id_falls_back_to_transport` · `test_pre_dedupe_reasons_never_attribute_to_signer_even_when_verified` · `test_mixed_dedupe_capped_and_pre_dedupe_reasons_split_into_separate_campaigns` · `test_forgery_reason_never_attributes_to_signer` |
| W3 — unattributable is throttle-exempt, never a fallback attribution | `test_unattributable_reason_not_throttle_eligible` · `test_unknown_reason_defaults_to_unattributable` |
| W4 — PII-safety: reports carry digests, key ids, machine codes, counts, timestamps, and opaque source refs — never raw identity or content | structural (no raw-identity/content field exists on `ObservedEvent`/`CampaignReport` to leak); `test_corpus_refs_collects_only_non_none` proves `corpus_refs` carries only caller-supplied opaque refs |
| W5 — closed remediation vocabulary; construction-time rejection of unknown codes; deterministic basis→remediation mapping | `test_remediation_validator_rejects_out_of_vocabulary`; the exact-list assertions embedded in the W2/W3 tests above |
| W6 — never-shed: the vocabulary contains no shed/deny/drop action | doctrine, not a runtime-checked test — `REMEDIATION_VOCABULARY`'s five entries (above) are enumerated in the module docstring and this contract; no sixth entry may be added without re-deriving this clause |
| W7 — meta-alarm compliance for any scheduled runner | reference-tier: `safe_agents/watcher/campaign_runner.py` + its own test module (not `test_campaign.py`) — mirrors `test_liveness.py`'s meta-alarm proof |
| W8 — evidence stamped only at gate time; the engine trusts but never fabricates `chain_verified`/`signer_key_id` | `test_signer_key_id_requires_chain_verified` (re-enforced independently of the upstream `DropRecord`/`ScreenRecord` validators) |
| supporting: window/threshold boundaries, deterministic `campaign_id`, ordering stability, naive-datetime refusal, flood grouping | `test_window_boundary_inclusive_upper_exclusive_lower` · `test_threshold_boundary` · `test_campaign_id_matches_stated_formula` · `test_ordering_and_campaign_id_stable_regardless_of_input_order` · `test_naive_datetime_refused_on_observed_event_ts` · `test_naive_datetime_refused_on_flood_event_ts` · `test_naive_datetime_refused_on_analyze_now` · `test_flood_events_produce_principal_flood_campaigns` · `test_vector_and_flood_campaigns_coexist` · `test_thresholds_require_positive_values` |

## Ships OFF

The base ships **no thresholds**: `CampaignThresholds` has two required fields and no defaults, so
an unconfigured watchdog cannot silently run at a base-chosen sensitivity. Running the watchdog at
all is a consumer choice, same as the screen (`channels/SCREENING.md`) and signing verification
(`channels/SIGNING.md` S5). Signed-chain attribution additionally requires verification to actually
be **ON** for the counted vector (`channels/SIGNING.md`): with no verify-keys ARN configured,
unsigned peers pass Gate 3.5 and every drop/verdict the watchdog would otherwise attribute to a
signer instead carries `chain_verified=false`, degrading attribution to `transport-token` — which
the table above makes safe rather than wrong. Enabling verification is therefore a deployment
precondition for the strongest attribution tier, not a requirement to run the watchdog at all.

## Packaging and placement

Per `docs/contract-vs-reference.md`: this document plus the engine's conformance suite are
**contract tier**; the scheduled runner and its GitHub Actions workflow are **reference tier**,
mirroring the liveness watcher (`safe_agents/watcher/liveness.py`, sa#38). No new floor is added —
the watchdog reads records the floor already produces.

Per `docs/config-provenance.md`: `CampaignThresholds` (`min_attempts`, `window_seconds`) and the
schedule that invokes the runner are **deploy-layer** consumer config — they can only select or
tighten how sensitively an already-correlated pattern gets reported, never name code to run.
Evidence fields (`chain_verified`, `signer_key_id`, every `DropReason`/`ScreenRecord` field) are
**code-provenance** — stamped by the airlock at gate time, never store-loaded or runner-supplied.
Nothing in this contract is store-loaded; there is no ceremony, because there is nothing here that
mints authority.

## What this is NOT

- **Not an uptime probe.** It says nothing about whether the airlock is reachable — that is the
  meta-alarm's own heartbeat concern, orthogonal to campaign content.
- **Not a gate.** It has no seam into `dispatch.py` or the broker; nothing it produces can drop,
  delay, or deny a live request.
- **Not a shedding rate-limiter.** The vocabulary (W6) never sheds held or legitimate load — it
  inherits the sa#160 never-shed invariant by construction, having no shed action to select.
- **Not a content classifier.** It never inspects message content and consumes no LLM judgment —
  that is gate 7's job (`channels/SCREENING.md`), a different mechanism with a different failure
  mode.

## Relationships

- `channels/SCREENING.md` (sa#43) — the on-path model-judged gate this watchdog is deliberately not;
  the refuse/pass contentless-verdict discipline this doc's remediation vocabulary borrows.
- `channels/SIGNING.md` (#170) — the authenticated provenance this watchdog's strongest attribution
  tier depends on; `chain_verified`/`signer_key_id` are this standard's fields, and `unenroll_verify_key`
  names its verify-keys secret.
- `channels/TRUST-MAPPING.md` (sa#81) — `DropRecord`, the primary input surface; `remove_trust_map_entry`
  and `rotate_channel_token` name its enforcement levers.
- `docs/friction-doctrine.md` §Availability/forced-abstention — the sa#159/160/161 lineage; the
  approval-queue-flood signal this watchdog also correlates; the watchdog's own positive-safe-action
  obligation.
- `reliability/META-ALARM-STANDARD.md` (sa#29) — the three-channel discipline any scheduled runner
  (W7) must satisfy.
- `docs/contract-vs-reference.md`, `docs/config-provenance.md` — the packaging and placement doctrine
  this document is scoped against.
- `safe_agents/watcher/liveness.py` (sa#38) — the sibling off-substrate watcher this runner's
  reference implementation mirrors.
