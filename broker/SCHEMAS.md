# SCHEMAS — the seven base schemas

The canonical contract other subdirs reference. These are the **base** schemas (encoded once);
per-agent repos fill in *values* (caps, allowlists, thresholds), never the shapes. Field lists match
`ARCHITECTURE.md` §"The seven base schemas" exactly, expanded here with per-field notes from
`auto-agents/tool-broker-sketch.md`.

The TypeScript-ish interfaces below are **illustrative stubs**, not an implementation — they pin the
field names and types. The wire/storage encoding (JSON over MCP; DynamoDB items; S3 objects) is
`BUILD.md`'s concern.

| Schema | Purpose |
|---|---|
| **Grant** | Per (principal × action-class): level, envelope, promotedBy, evidence, lastSafeLevel, demotionTriggers, ownerId (integrity HMAC lives at the store's item level, #246). |
| **BrokeredCall** | The typed request the PDP decides on. |
| **Decision** | The five verbs under default-deny. |
| **Intent** | Durable "draft and hold" record: materializedRequest, renderedForHuman, status, expiry, approvedBy. |
| **AuditRecord** | Hash-chained, broker-emitted, append-only, external. |
| **Budgets** | Per-period atomic counters: error / attention / escalation / fallback. |
| **PromotionRecord** | The maker-checker promotion act. |

> **Per-agent Envelope (fills these, isn't one of them).** The *values* a per-agent repo supplies —
> polarity, caps, allowlists, reversibility classes, thresholds — are themselves typed: the canonical
> `Envelope` schema lives at `safe_agents/broker/schemas/envelope.py`, with `compute_envelope_hash`
> (a plain `sha256:` content hash) tying a Grant/AuditRecord to the exact envelope in force. The
> Envelope is per-agent config that *fills* the seven base schemas above — not an eighth base contract.
> See `core/manifest-schema.md` for the field-by-field prose.
>
> **Read-gating knobs (sa#137), consumer-configurable.** Three Envelope fields tune how external
> reads are gated; all are safe-by-default (an unset knob adds no bound):
> - `trusted_read_sources: string[]` (default `[]`) — source ids (`connector:{tool}.{op}`) whose
>   external reads are trusted. Consulted in BOTH halves of the read seam from one list: the PIP's
>   in-loop read rung-gate (a trusted read needs no per-read approval) and the PEP's taint-skip (a
>   trusted read does not self-taint the turn). Empty = every external read is untrusted.
> - `max_query_bytes: int | null` (default `null`) — per-call UTF-8 byte cap on the `egress_arg`
>   value; an over-cap read is denied before it egresses.
> - `query_egress_budget: float | null` (default `null`) — per-period cumulative byte budget on the
>   same egress arg; once cumulative spend reaches it, the next such read is denied. The PEP meters
>   spend after each successful read; the PIP only reads the counter.
>
> **Availability / liveness knob (sa#160), consumer-configurable.** One Envelope field, the typed
> dead-man's-switch, safe-by-default (unset = OFF):
> - `liveness: {expected_op: string, deadline_seconds: int>0} | null` (default `null`) — the typed
>   liveness contract. `expected_op` is the `tool.op` whose successful audit/ledger append counts
>   as a sign of life; `deadline_seconds` is the max silence before the agent is overdue.
>   `Liveness.overdue(last_seen_epoch, now_epoch)` is the base's **deterministic** monitor predicate
>   — a pure timestamp comparison, never a model judging *why* the agent went silent. Unset = no
>   monitoring (no silent "monitored" claim). The base ships this MECHANISM only; the
>   polarity→default derivation lives consumer-side (`examples/liveness_policy.py`), never in the
>   base — see `docs/friction-doctrine.md` §"Availability / forced-abstention".
> - `approval_queue: {dedup: bool, max_pending_per_op_day: int>0} | null` (default `null`) — the
>   approval-queue de-amplification knob. `dedup` coalesces truly-identical pending intents (same
>   principal+tool+op+args) so an injection-driven flood of identical `require_approval` holds pages
>   the human once, not N times. `max_pending_per_op_day` raises an `approval_queue_flood` alarm
>   (the sa#153 log-metric surface) past that many NEW held intents per principal+op+UTC-day — but
>   the broker **still holds the intent**; it never sheds (shedding under flood is the
>   forced-abstention harm under act-safe polarity, kept consumer-side). Unset = OFF: the hold path
>   is byte-identical to today's. Mechanism only; no polarity in the base.
>
> **AgentManifest (`safe_agents/broker/schemas/manifest.py`)** is the typed broker-facing
> deployment-manifest block `build_runtime(manifest)` consumes: `envelope` (required) plus
> `principal`, `grant_classes`, `budgets`, `connectors`, and — sa#141 — two consumer-connector
> fields:
> - `connector_providers: {name: "pkg.module:ClassName"}` (default `{}`) — consumer-supplied
>   connector implementations, resolved provider-first through the registry's one sanctioned
>   injection seam (`connector_registry.resolve_connectors`). **Image-baked-only invariant:**
>   provider paths are honored solely from the manifest file baked into the broker image;
>   `BROKER_ENVELOPE_LOAD=store` loads an `Envelope`, which has no provider/import-path field,
>   so nothing store-loaded can ever inject code (test-asserted in
>   `broker/tests/test_connector_providers.py`).
> - `connector_secrets: {name: secret_leaf}` (default `{}`) — overrides the default
>   leaf == tool-name mapping the Doer uses at execute time. Bare **leaves** only, never
>   values and never a pre-prefixed path: when the broker runs with a secret prefix the
>   value is resolved under `<prefix>/connectors/<leaf>` (sa#164), so a pre-prefixed value
>   would double the prefix and miss the IAM grant.
> - `tool_ops: list[ToolOp]` (default `[]`, #171) — the consumer-owned ToolOp table. Each op's
>   `effect/external/reversible/egress_arg` classification travels WITH the agent here, not in a
>   base global; `build_runtime` compiles it into the runtime's `ToolOpTable` and the broker
>   resolves every `(tool, op)` against it — so a consumer-defined op gates identically regardless
>   of its name (the base owns the ToolOp *schema* + the PDP rules that key on it, never the op
>   *names*). A grant for a class with no matching `tool_ops` entry is inert (no entry ⇒ the PEP
>   denies). Duplicate `(tool, op)` keys are rejected at load. The base ships a copy-only `CATALOG`
>   of domain-neutral ops (`safe_agents.broker.manifest.CATALOG`) an author may copy in; it is
>   **never** consulted at request time. `tool_ops` rides inside `AgentManifest` — it is not an
>   eighth base schema.
> - Later phases added further manifest blocks documented in their own contracts:
>   `connector_auth` + `capability_iam` (#173/#175, `broker/CONNECTOR-AUTH.md`), `counter_period`
>   (#212, §Budgets note below), and `mcp_servers` (#174, `broker/MCP-HOST.md`) — the image-baked
>   half of two-key MCP admission: the declared `(server_id, tool_name)` namespace +
>   per-tool `structured_output` trust eligibility, validated at load against `tool_ops` and
>   `envelope.trusted_read_sources`.

---

## 1. Grant

Per `(principal, action-class)` authority. **Autonomy level is stored state**, not a constant; this
record is where it lives and what the grant lifecycle moves on a ratchet (`grant-lifecycle.md`).
**Pillar 7 — Graduated Autonomy.**

```ts
// STUB — illustrative, not an implementation
interface Grant {
  principal:   Principal           // the (agentId, skill, user, tier) this grant is for
  actionClass: string              // the class of action it authorizes (e.g. "email.send", "payments.transfer")
  level: "in-loop" | "on-loop" | "out-of-loop"  // current autonomy rung — STORED STATE, moves on the ratchet
  envelopeHash: string             // hash of the signed envelope in force (caps, thresholds, quorum, fallback budgets)
  promotedBy:  string              // accountable identity that ratified the current level (maker-checker)
  evidence:    string              // ref to the covered-distribution evidence the promotion cited
  ts:          string              // when this level took effect
  lastSafeLevel: "in-loop" | "on-loop"          // the rung automatic demotion falls back to (never "out-of-loop")
  demotionTriggers: DemotionTrigger[]           // the deterministic conditions that trip demotion (see below)
  demotionReason: null | "failing" | "pending-evidence"  // why currently demoted; null if at full level
  labelLatency: string             // how long until an action of this class yields ground truth (caps re-promotion speed)
  ownerId:     string              // the NAMED human owner accountable for this grant
  certifiedUntil?: string | null   // the certification TERM (#255): an explicit UTC instant; null/absent = no term
}
// Integrity lives at the STORE's item level, not on the schema (#246): the grant
// is serialized once in the CANONICAL form (below), the stored bytes are the HMAC
// basis (grantHash beside the data attribute), and reads verify the stored bytes
// verbatim before parsing — so additive Grant schema growth can never read an
// intact stored grant as tampered (integrity indicts tampering, never evolution).

type DemotionTrigger = "stale_confidence" | "corroboration_failure" | "budget_breach" | "false_action"
```

> **Canonical serialization (normative, one rule for the whole platform).** Every stored-bytes
> integrity basis — `Grant`, `PromotionRecord`, the durable promotion proposal, the acknowledgment
> record — is **JSON with sorted keys, NO whitespace, ASCII**: in Python,
> `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. Same rule, same
> words, as `channels/SIGNING.md` §"How a chain is signed". The bytes are a wire format the moment
> a second implementation recomputes an HMAC or digest from this document instead of from our code,
> and until that moment a divergence is undetectable — each writer HMACs bytes its own process just
> wrote and reads back verbatim, so a non-canonical serializer is perfectly self-consistent and
> perfectly wrong. `canonical_grant_payload` and `proposal_to_json` were exactly that (sorted and
> ASCII but not compact) until it was pinned; the regression test is
> `test_grants_integrity.py::test_canonical_payload_is_sorted_compact_ascii`. Changing the canonical
> form is a **ceremony-bearing migration**, never an edit — and note that pre-change rows keep
> verifying (the basis is the stored bytes), so the migration normalizes rather than recovers, and
> `re-seed` is not the command for it. See `docs/grant-canonicalization-runbook.md`.

> **DemotionTrigger is emitted as a typed `DemotionSignal` (#184).** The evidence
> machinery emits a `DemotionSignal { trigger, principal, action_class, period,
> detail, ts }` at breach detection; the Phase-3 evaluator maps signals to the
> tripped-trigger set. The base emits, never applies. See §"Evidence contract" below.

Per-field notes:

- **level** — `in-loop` (human approves each act) · `on-loop` (human supervises, can intervene) ·
  `out-of-loop` (acts fully within the envelope). The exchange rate between machine error-budget and
  human attention-budget is *set* by choosing this per action class. This is **orthogonal to the
  Decision verb** (allow/deny/transform/require_approval/abstain); level is state on the grant, the
  verb is per-call. Mapping from older disposition terminology: `out-of-loop` ≈ autonomous,
  `on-loop` ≈ autonomous-with-reporting, `in-loop` ≈ HITL-queued; `blocked` is **not** a level —
  it means the action class is simply not granted to this principal. That no-grant state is itself
  a rung of the autonomy ladder: **Recommend**, the advise-only baseline below the enum — the agent
  holds no acting grant for the class, the broker default-denies, and its advice is only text in
  its reply. Recommend is a rung but not a `level`; the enum is complete at three values. The rung
  is per `(principal, action-class)`, never per-agent (`grant-lifecycle.md`).
- **envelopeHash** — the envelope is the deterministic bounded region (caps, allowlists,
  reversibility classes, fallback budgets). The agent **cannot widen its own envelope**; hashing it
  makes the in-force bundle verifiable and ties each AuditRecord to the exact envelope that decided.
- **lastSafeLevel** — demotion target. Never `autonomous`. In abstention-kills domains the safe rung
  must execute a *positive* deterministic action (a SCRAM/failsafe), not mere inaction — that
  polarity is per-agent config, not baked here.
- **demotionReason** — `"pending-evidence"` ("I lack recent labels to certify this rung") and
  `"failing"` ("the error blew the bound") look identical from outside but demand opposite responses
  (gather data vs. fix the model). **Do not collapse them.**
- **labelLatency** — re-promotion closes a control loop whose deadtime equals this. Long latency
  caps how fast you can re-promote, and therefore how much autonomy you can responsibly hold.
- **ownerId** — every grant has a named owner (pre-deployment checklist).
- **certifiedUntil** — the term of the current certification (GAL §6.7.6, #255). Once
  `now >= certifiedUntil`, per-call enforcement treats the grant as being at `lastSafeLevel` (never
  higher than its stored level), and the demotion runner records a `lapse` (§7). `null` means no
  term and never lapses; terms **ship unset**. It must be an explicit UTC instant (`Z` or `+00:00`;
  naive and non-UTC values are refused) and is stored verbatim. **Omitted from the canonical payload
  when null**, so every pre-#255 grant keeps byte-identical canonical bytes; when set it is inside
  the HMAC'd payload. Set only by a ratified promotion; no other write may lengthen or drop it
  (`grants/store.py::refuse_term_extension`). Whether a term has passed is judged against an
  explicit evaluation instant, never a record's `ts` (`grants/term.py`).

---

## 2. BrokeredCall

The typed envelope the PEP materializes from a tool call. **The PDP never sees free text.**
`manifest` is looked up from the agent's `ToolOpTable` (compiled from `AgentManifest.tool_ops`,
#171) — a classified, code/manifest-resident fact, never model-supplied. **Pillar 1.**

```ts
// STUB — illustrative, not an implementation
interface BrokeredCall {
  principal: { agentId: string; skill: string; user: string; tier: "A"|"B"|"C"|"D" }
  tool: string                     // e.g. "email"
  op:   string                     // e.g. "send"          — what the model asked for
  args: unknown                    //                       — what the model asked for
  manifest: ToolOp                 // LOOKED UP from the agent's ToolOpTable, NOT model-supplied
  taint:   { tainted: boolean; sources: string[] }   // source-based, deterministic; rides the turn
  session: { turnId: string; ingestedSources: string[] }
  ts: string
}

// ToolOpTable — classifies each operation once; entries travel in AgentManifest.tool_ops
// (#171), never a base global. Illustrative consumer classifications:
//   { tool:"email",    op:"send",         effect:"write", external:true,  reversible:false }
//   { tool:"email",    op:"draft",        effect:"write", external:false, reversible:true  }
//   { tool:"calendar", op:"create_event", effect:"write", external:false, reversible:true  }
//   { tool:"crm",      op:"list_deals",   effect:"read",  external:false                   }
//   { tool:"payments", op:"transfer",     effect:"write", external:true,  reversible:false }
interface ToolOp {
  tool: string; op: string
  effect: "read" | "write"         // default-deny applies to write
  external: boolean                // does it cross a trust boundary to an external party
  reversible?: boolean             // can a wrong action be undone (deletes a bad event) vs not (a wire)
  egress_arg?: string              // sa#137: name of the arg that egresses to the provider (e.g. "query")
}
```

Per-field notes:

- **principal.tier** — coarse trust tier (A–D) used by capability-scoping and policy; a recruiter
  (Tier C) is served only resume-screening read tools.
- **manifest.effect/external/reversible** — the three static facts that drive most policy. They are
  classified in the consumer's `AgentManifest.tool_ops` (#171), not model-supplied, so the model
  can't assert its `send` is really a `draft`. `effect:"write"` is
  default-deny; `external && !reversible` is the high-blast/irreversible boundary where the heavy
  machinery belongs.
- **taint** — set at ingestion from the *source*, propagated through any derived result; the model
  never judges maliciousness. The PDP keys an external write in a tainted turn to
  `require_approval`/`deny`.
- **session.ingestedSources** — what untrusted sources this turn touched; feeds taint and audit.
- **manifest.egress_arg** (sa#137) — the name of the single arg whose value egresses to an external
  provider (the covert-exfil channel; `"query"` for `search.query`). Code-resident, never
  model-supplied. When set, the PIP bounds that arg's UTF-8 byte length against
  `Envelope.max_query_bytes` (per call) and its cumulative spend against `Envelope.query_egress_budget`
  (per period), and the PEP meters the bytes that actually cross the wire. `null` = the op egresses no
  agent-composed argument.

---

## 3. Decision

The five verbs, default-deny. Output of the pure `decide(call, facts)`. **Pillar 1 / Pillar 4** (the
`abstain` verb).

```ts
// STUB — illustrative, not an implementation
type Decision =
  | { kind: "allow" }
  | { kind: "deny";      reason: string }
  | { kind: "transform"; op: string; args: unknown }     // downgrade send->draft; op only, args verbatim
  | { kind: "require_approval"; renderedIntent: RenderedIntent; reason?: string }  // materialized; turn ends
  | { kind: "abstain";   escalate: boolean; reason: string }       // out of competence / inputs suspect

function decide(call: BrokeredCall, facts: Facts): Decision   // PURE + DETERMINISTIC, no LLM
```

Per-field notes:

- **transform** — the broker substitutes a safer **op** and executes *that*: `send → draft`. The
  agent does not get to re-issue the original.

  **As built, op substitution is the whole of the verb.** `args` are carried through byte-for-byte
  (`safe_agents/broker/pdp/engine.py:261`), so the base redacts no field and clamps no value; the
  `args` field specifies the substituted call rather than offering a rewriting seam. Pinned by
  `test_pdp.py::test_transform_passes_args_through_byte_for_byte`.

  **Specified and not yet built:** `ptc-gal-standards/PTC-SPEC.md` §PTC-25 requires `transform` to produce a
  substituted operation *plus* clamped arguments, and carries the implementation-status marker
  saying the argument half is unbuilt here (tracking **#358**). So this is a design requirement the
  code has not reached, not a verb that was never meant to clamp — the spec states the blueprint and
  marks what is unbuilt, while this document describes what exists. Do not cite #228 as the tracker:
  it owns magnitude bounds through accumulating counters, which is what a clamp would clamp *to*,
  not the per-call narrowing itself.
- **require_approval.renderedIntent** — the **materialized** bytes that will execute, persisted as an
  `Intent` record (§4; fields: id, materializedRequest, renderedForHuman, status, expiry, approvedBy,
  ts). What-you-see-is-what-executes: the human approves the stored `materializedRequest`, not an
  agent-written summary. The turn ends; the agent cannot self-release.
- **require_approval.reason** — WHY the call was held, as the PDP rule that fired phrased it, copied
  onto the `AuditRecord.reason` of the hold. `deny` and `abstain` always carried a reason and
  `require_approval` did not, so a held record read `reason: null`: the tape could show that a call
  was held and never say what held it (#300). Optional because the field post-dates the verb —
  a record written before it exists is not missing anything, and omitting it keeps those records
  hashing byte-for-byte.
- **abstain.escalate** — escalation spends the **attention/escalation budget** (Budgets §5), so
  `abstain → escalate:true` is itself rationed; an adversary DoSes this channel. `abstain` is a
  first-class outcome, not a failure.
- **Facts** — supplied by the PIP: counter balances, allowlist membership, human reachability, and
  *constructed* confidence (self-consistency / ensemble / conformal / stale — high-stakes tier
  only). Confidence is computed deterministically, never read off a raw model logprob. The
  constructed value is packaged as a typed `ConfidenceArtifact` and gated by the deterministic
  `meets_bar` predicate against the `Envelope.confidence` knob (#184); a below-bar call routes to
  the per-agent safe response through the polarity seam (the base ships the wiring, never the
  polarity). See §"Evidence contract" below.

---

## 4. Intent

The durable record of a `require_approval` decision — the artifact that makes "draft and hold"
physically true. When the PDP returns `require_approval`, the broker immediately materializes and
persists this record; the agent's turn ends. Execution happens only if a human approves through a
path authenticated to *them*, not the agent. **Pillar 5 — Bounded Human Governance.**

```ts
// STUB — illustrative, not an implementation
interface Intent {
  id:                  string            // stable identifier; referenced by the approval flow and AuditRecord
  materializedRequest: BrokeredCall      // the FROZEN BrokeredCall the broker executes verbatim on approval — never re-derived
  renderedForHuman:    string            // what-you-see: human-readable render pushed to the approval channel
  status:              "pending" | "approved" | "rejected" | "expired" | "executed" | "refused"
  expiry:              string            // hard TTL; unapproved intents auto-deny at this timestamp (ISO-8601 UTC)
  approvedBy?:         string            // the human identity that approved; absent until approval
  ts:                  string            // when this intent was created
}
```

Per-field notes:

- **materializedRequest** — the load-bearing field. Written once at intent creation and **never
  re-derived** from anything the agent says after that point. The human approves these bytes. A
  compromised agent could stage a benign `renderedForHuman` summary over a malicious payload; the
  broker ignores the render at execution time and runs the stored call verbatim.
- **renderedForHuman** — what the approval channel shows the human ("Send this email to alice@…
  with subject '…'"). Separate from `materializedRequest` so the render can be human-friendly
  prose while execution stays typed and frozen.
- **status** — `pending` (awaiting human decision) · `approved` (broker may execute) · `rejected`
  (human declined) · `expired` (TTL passed, auto-deny) · `executed` (broker ran it) · `refused`
  (a human approved, and release-time revalidation then refused: the grant was revoked or demoted,
  or the op's period budget was exhausted, between the hold and the release; nothing ran, #9).
  Terminal states: `rejected`, `expired`, `executed`, `refused`.
- **expiry** — a hard TTL. An intent the human does not act on auto-denies; it never hangs open
  indefinitely. The agent cannot extend or re-issue.
- **approvedBy** — the authenticated human identity, set by the approval path (not the agent).
  Copied into `AuditRecord.approvedBy` at execution time, and onto the refusal record when
  release-time revalidation refuses, so the tape shows who approved a release the broker declined.

Intent is stored in **DynamoDB** (the same on-demand table as grants and counters). `AuditRecord.outcome = "held"` means an intent is pending; `"executed"` / `"denied"` are terminal.

---

## 5. AuditRecord

Hash-chained, broker-emitted, append-only, external. The writing role cannot delete it. **Pillar 3.**

```ts
// STUB — illustrative, not an implementation
interface AuditRecord {
  seq: number                      // monotonic sequence; a gap is detectable
  ts:  string
  principal: Principal
  tool: string; op: string
  argsDigest: string               // HASH of args, not raw args (PII discipline)
  decision: Decision["kind"]       // allow | deny | transform | require_approval | abstain
  reason?: string
  envelopeHash: string             // the exact envelope in force when this was decided
  approvedBy?: string              // the human identity, for approved intents
  outcome: "executed" | "denied" | "held" | "failed"
  error?: string
  seed?: string                    // committed randomization seed, where allocation was randomized (auditable randomness)
  intentId?: string                // #198 — held + release records: joins a hold to its release across the intent TTL
  storedCallDigest?: string        // #198 — digest of the frozen materializedRequest; hold-side == release-side ⇒ executed==approved is byte-provable post-TTL
  resultDigest?: string            // #198 — broker-written digest of the connector response (the effect receipt)
  prevHash: string                 // chains to the previous record
  hash: string                     // hash over this record incl. prevHash -> tamper-evident
}
```

Per-field notes:

- **argsDigest** — hash, not raw args, so the audit doesn't itself become a PII store.
- **envelopeHash** — ties the decision to the exact signed envelope, so "under what authority?"
  reconstructs.
- **outcome** — `held` is an intent awaiting approval; `executed`/`denied`/`failed` are terminal.
- **seed** — when scarcity allocation was randomized (high-stakes tier), the committed seed is logged
  (commit-reveal / VRF): unpredictable in advance, fully reconstructable after. "Why not engage that
  one?" has an answer in the log.
- **intentId / storedCallDigest / resultDigest** — the #198 receipts: broker-stamped at the moment
  of effect, agent-unforgeable; digests only, never raw content (the `argsDigest` discipline).
  OPTIONAL — absent == a pre-receipts record, and receipt fields are hash-covered only when
  present, so existing chains verify unchanged while stripping a present receipt breaks the chain.
- **prevHash / hash** — the chain. Any later edit or deletion breaks it; any gap in `seq` shows.

---

## 6. Budgets

Per-period typed budgets, decremented **atomically** (a durable counter, so two concurrent runs
can't both slip under a cap). **Pillar 4** (error budget) **and Pillar 5/6** (attention, escalation,
fallback). Two are foundational and non-fungible: **error** and **attention**.

```ts
// STUB — illustrative, not an implementation
interface Budgets {                 // per period
  error:      { tolerance: number; spent: number }   // Σ error_prob × blast_radius
  attention:  { capacity: number; spent: number }    // Σ cognitive_cost, time-decaying
  escalation: { capacity: number; spent: number }    // asks are rationed (adversary DoSes this)
  fallback:   { capacity: number; spent: number }    // the safe action is NOT free
}
```

Per-field notes:

- **error** — bounded cumulative tolerable error per period (alpha-spending / SRE error budget),
  drawn down by each decision as `error_prob × blast_radius` (the typed draw is
  `evidence.error_budget_draw`, #184; `blast_radius` is the consumer-declared weight per blast
  class). Decision *volume* inflates aggregate error, so scaling volume forces higher per-decision
  confidence to hold the bound fixed.
- **attention** — the human's finite quality-decisions per period, drawn by each escalation's
  *cognitive cost* (multi-dimensional; degrades across a session). Different currency from error;
  the binding one switches by action class, so "decisions per period" is a vector per class, never a
  scalar.
- **escalation** — asks are rationed; this is the channel an adversary tries to drain with decoys.
- **fallback** — "abstain to safe action" is itself capped; you cannot be chopped to death by a
  thousand safe actions.
- **Autonomy level is the exchange rate** between `error` and `attention`: graduating a class to
  autonomous spends machine error-budget to save human attention; keeping it HITL spends attention to
  conserve error-budget. The hard cap (envelope) stays deterministic; only allocation *within* it is
  randomized (high-stakes tier).

---

## 7. PromotionRecord

The append-only ceremony-ledger record of every grant level change. The accountable record (Part 11
of the philosophy doc). Five record types share one ledger; the maker-checker act that raises a
Grant's level is the `promotion` type. **Demotions append a `demotion`-typed record on the same
ledger** — this supersedes the earlier "demotion needs no such record" exemption (Phase 3,
`docs/GAL.md` §3); demotion itself stays automatic and deterministic (`grant-lifecycle.md`).
**Pillar 7.**

```ts
// STUB — illustrative, not an implementation
interface PromotionRecord {
  recordType:  "promotion" | "demotion" | "bootstrap" | "tightening" | "lapse"   // default "promotion"
  actionClass: string              // the class whose level changed
  principal:   Principal           // for whom
  fromLevel:   "in-loop" | "on-loop" | "out-of-loop" | null   // null = the Recommend rung (no-grant baseline; the record creates the grant)
  toLevel:     "in-loop" | "on-loop" | "out-of-loop"
  evidence:    string              // ref to covered-distribution evidence (delayed-label recalibration result)
  predicate:   string | null       // the signed promotion PREDICATE authored in advance; promotion-typed only
  proposedBy:  string              // maker
  ratifiedBy:  string              // checker (promotion: must differ from maker)
  envelopeHash: string             // the envelope hash in force when the record was written
  triggeredBy: string[]            // demotion-typed only: the DemotionTrigger values that fired
  demotionReason: "failing" | "pending-evidence" | null      // demotion-typed; "pending-evidence" on lapse
  ts:          string
  certifiedUntil?: string | null   // promotion-typed only (#255): the certification term the checker RATIFIED
}
```

Record types and their shape rules (the schema enforces field **shape** only; transition validity —
one-rung-up, level ordering — is the state machine's job, `grant-lifecycle.md`):

| recordType | what it records | shape rules |
|---|---|---|
| `promotion` | the maker-checker ceremony that raises the level | maker ≠ checker; `predicate` required non-empty; `triggeredBy` empty; `demotionReason` null |
| `demotion` | automatic deterministic demotion | `ratifiedBy` = `"system:demotion-evaluator"`; `triggeredBy` non-empty; `demotionReason` set; `predicate` null |
| `bootstrap` | the sanctioned seed record — first creation of a grant outside the ceremony (`seed_grants` retires to bootstrap-only, Phase 4) | `fromLevel` null; maker ≠ checker NOT enforced (single-operator seed is sanctioned); `predicate` null; `triggeredBy` empty; `demotionReason` null |
| `tightening` | voluntary any-level → in-loop move (always permitted, no ceremony, no trigger — `docs/GAL.md` §4) | `toLevel` = `"in-loop"`; maker ≠ checker NOT enforced; `predicate` null; `triggeredBy` empty; `demotionReason` null |
| `lapse` | a certification term expired (GAL §6.7.6, #255; `grant-lifecycle.md` §Lapse) | `ratifiedBy` = `"system:demotion-evaluator"`; `triggeredBy` EMPTY (a lapse is an absence, not a fired condition); `demotionReason` = `"pending-evidence"`; `predicate` null; `fromLevel` non-null; `toLevel` = the grant's `lastSafeLevel` (never `"out-of-loop"`); `evidence` names the expired term |

Per-field notes:

- **fromLevel** — `null` means the Recommend rung: the agent held no grant for the class, and this
  record's write is the grant's creation (first promotion or bootstrap seed). Recommend is a rung
  but NOT a level — it can never be an enum value.
- **envelopeHash** — the in-force envelope hash at write time, binding each ledger record to the
  exact bounded region it was written under (the same binding the Grant carries; the signed-record
  statement in `docs/GAL.md` §8 signs over it).
- **evidence** — must reference evidence gathered where the deployment conditions are *covered*. A
  thin observed-accuracy count over an irreversible action is an **unsound** predicate.
- **predicate** — approval can be a signed predicate authored in advance rather than a per-instance
  act; its stringency and ceremony scale to blast radius. Promotion-typed records only.
- **proposedBy / ratifiedBy** — maker ≠ checker on the promotion path. Widening autonomy requires
  recorded human approval; narrowing (demotion) requires none — it is ratified by
  `system:demotion-evaluator` and recorded, not approved.
- **certifiedUntil** — promotion-typed only (#255, GAL §6.7.6): the term the checker ratified,
  written by the ceremony onto both this record and the raised `Grant.certifiedUntil`. Same format
  and parser as the Grant field (explicit UTC instant, stored verbatim). Every other record type
  refuses a non-null value. **Omitted from the canonical, stored and signed bytes when null**, so
  every record written before the field existed keeps byte-identical bytes and a still-valid DSSE
  signature (pinned in `test_grant_term_lapse.py`); when set it is inside the signed subject digest.
  The audit rule `GRANT_TERM_RATIFIED` holds each grant to it: a grant's `certifiedUntil` must
  equal the term on the chronologically-latest promotion record at its coordinate (a later
  demotion, tightening or lapse moves the level, never the term), and a grant whose ledger holds
  no promotion must carry no term. Un-waivable.
- **triggeredBy / demotionReason** — demotion-typed only. `stale_confidence` maps to
  `"pending-evidence"` (label-free drift voids the certification — gather labels/recalibrate);
  `corroboration_failure` and `budget_breach` map to `"failing"` (fix the model/policy). Never
  collapse the two (§1's demotionReason note).
- Re-promotion runs on **delayed-label reconciliation**: pair a resolved outcome with the confidence
  logged at decision time, recompute calibration, re-validate conformal coverage on the *current*
  distribution, then ratchet up — with hysteresis (different thresholds + dwell time; fresh
  recalibration evidence, never just "the alarm stopped").

**Signing.** Every record type is signed (GAL-SPEC §6.10), by the identity that wrote it: the
**issuer** key signs `promotion`, `bootstrap` and `tightening` (the ceremony/operator side); the
**evaluator** key — GAL §6.7.2's separate system identity — signs `demotion` and `lapse`. The two
are distinct keys with distinct env contracts, because an evaluator holding the issuer key could
mint promotion records. Verification selects the key map by `recordType`, so a signature from the
wrong role fails closed (`grant-lifecycle.md` §"Two signing roles").

**Storage.** Records live in the grants table as append-only `RECORD#…` items
(`pk = RECORD#<principal>#<actionClass>`, `sk = <ts>#<recordType>`), written via a
conditioned UpdateItem so an existing record is never overwritten (`grants/store.py`). The stored
`data` string is the canonical serialization from §1 (sorted keys, no whitespace, ASCII) — the exact
bytes the DSSE signature's subject digest binds, verified verbatim on read.

---

## Evidence contract (#184)

Pillar 4's constructed confidence, packaged as base contract surface. It is **not an eighth base
schema** — the same rule as the Envelope: the artifact and signal *fill* the seven above (a
`ConfidenceArtifact` supplies §3's *constructed confidence* Fact; a `DemotionSignal` carries §1's
`DemotionTrigger`), they are not a new contract in the table. The normative words are
`broker/EVIDENCE.md`; the shapes live in `safe_agents/broker/schemas/evidence.py` and are pinned by
the E1–E10 conformance suite (`safe_agents/broker/tests/test_evidence_contract.py`). The
construction *methods* (self-consistency / ensemble / conformal) are **reference tier**, pluggable
behind a closed `ConfidenceMethod` catalog (a `Literal`, never an import path); the bars/budgets are
an **Envelope knob** shipping OFF.

Constructed confidence is a contract, not a logprob read — every function here is pure and
deterministic; there is no model in any gate.

```ts
// STUB — illustrative, not an implementation
type ConfidenceMethod = "self-consistency" | "ensemble" | "conformal"   // CLOSED catalog

interface ConfidenceArtifact {
  confidence:  number            // constructed value in [0,1] — never a raw logprob
  error_prob:  number            // the error-budget draw numerator; method-specific, NOT 1 - confidence
  evidence:    | { method: "self-consistency"; samples: number; agreement: number }
               | { method: "ensemble";         members: number; agreement: number }
               | { method: "conformal"; coverage: number; threshold: number; calibration_size: number }
  stale:       boolean           // label-free drift flag; voids the conformal threshold — a stale artifact never meets a bar
  computed_at: string            // ISO-8601 UTC
  annotations: string[]          // attach-only (e.g. the #58 reviewer); NEVER read by any gate
}

interface DemotionSignal {       // emitted at breach; consumed by the Phase-3 evaluator (base emits, never applies)
  trigger:      DemotionTrigger  // §1's vocabulary — "stale_confidence" | "corroboration_failure" | "budget_breach"
  principal:    Principal
  action_class: string           // the (principal, action-class) grant coordinate
  period:       string           // the counter-period bucket — "YYYYMMDD" (utc-day) or "YYYYMMDDTHH" (utc-hour, #212)
  detail:       string           // audit-safe cause, no payload content
  ts:           string           // ISO-8601 UTC
}
```

**BlastClass derivation.** The `blast_radius` axis of the error draw is *derived*, never separately
declared: `high` = write ∧ external ∧ ¬reversible (`reversible: null` counts as not-recoverable —
the conservative reading, same polarity as `enforce()`'s saga); `medium` = any other write; `low` =
read. A consumer `high_blast` list of `"tool.op"` keys can **tighten** a derived class up to `high`,
never lower it (`effective_blast_class`, one-way).

**The `Envelope.confidence` knob (ships OFF).** Supersedes the retired `abstention_thresholds`
placeholder dict (firmed up per the friction doctrine's "make it real or delete it"). Unset = no bar,
no budget. Fields: `min_confidence` (the per-call bar, gated by the deterministic `meets_bar`
predicate — a below-bar call routes to the per-agent safe response through the polarity seam; the
base ships the wiring, never the polarity), `methods` (accepted subset of the closed catalog),
`error_budget_tolerance` (a per-UTC-day `Σ error_prob × blast_radius` bound metered on the
scoped-counter seam; a breach emits the `budget_breach` `DemotionSignal`), `blast_weights` (the
per-class `blast_radius` weight, **required** when a budget is set — the base never invents a domain
weight), and `high_blast` (the tighten-only override list). An empty knob is rejected: a control that
looks enabled but gates nothing violates the friction doctrine.

> **Caps rename (#163).** `caps.actions_per_run` is renamed `caps.actions_per_utc_day` — the field
> has been a per-op per-UTC-day budget since the 2026-07-08 scoping fix
> (`enforcement.scoped_counter_key`), and the name now says so. The old spelling is still accepted on
> load (a validation alias, so no `agents/*.yaml` churns); the canonical dumped key is the new one.
>
> **Counter period (#212).** The bucket every cap and evidence counter scopes to is the
> manifest-named `AgentManifest.counter_period` — default `utc-day` (byte-for-byte the pre-#212 key),
> `utc-hour` for development-speed lifecycle runs. It is authority-shaping, so it lives on the
> image-baked manifest and deliberately OUTSIDE `Envelope` (declaring it never churns the envelope
> hash; nothing store-loaded can change it). Under a non-day period, `caps.actions_per_period` is the
> honest input spelling of the same cap (validation alias; canonical dump key unchanged). Ceremony
> readers name the same period on the CLI (`--period`); a writer/reader period mismatch reads
> disjoint keys and yields zero evidence — failing toward less authority, never a wrong sum. There is
> deliberately NO clock-injection seam: real time always elapses, only the bucket size changes
> (the 2026-07-15 triggers-vs-effects doctrine — calendar *triggers* are validated once at real
> granularity; period-relative *effects* run at any bucket size).
>
> **Deployment consequence.** Retiring `abstention_thresholds` and renaming the cap churns every
> envelope hash, and a pre-#184 stored envelope dump (carrying `"abstention_thresholds": null`) fails
> validation loudly at boot — the intended fail-closed path, cured by re-running
> seed_envelope → seed_grants (the consumer's own broker-image cutover runbook). No compat shim.
