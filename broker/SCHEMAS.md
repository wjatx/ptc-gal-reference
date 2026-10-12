# SCHEMAS — the seven base schemas

The canonical contract other subdirs reference. These are the **base** schemas (encoded once);
per-agent repos fill in *values* (caps, thresholds), never the shapes. Field lists match
`ARCHITECTURE.md` §"The seven base schemas" exactly, expanded here with per-field notes from
`auto-agents/tool-broker-sketch.md`.

The TypeScript-ish interfaces below are **illustrative stubs**, not an implementation — they pin the
field names and types. The wire/storage encoding (JSON over MCP; DynamoDB items; S3 objects) is
`BUILD.md`'s concern.

| Schema | Purpose |
|---|---|
| **Grant** | Per (principal × action-class): level, envelope, promotedBy, evidence, lastSafeLevel, demotionTriggers, ownerId (integrity HMAC lives at the store's item level). |
| **BrokeredCall** | The typed request the PDP decides on. |
| **Decision** | The five verbs under default-deny. |
| **Intent** | Durable "draft and hold" record: materializedRequest, renderedForHuman, status, expiry, approvedBy. |
| **AuditRecord** | Hash-chained, broker-emitted, append-only, external. |
| **Budgets** | Per-period atomic counters: error / attention / escalation / fallback. |
| **PromotionRecord** | The maker-checker promotion act. |

> **Per-agent Envelope (fills these, isn't one of them).** The *values* a per-agent repo supplies —
> polarity, caps, reversibility classes, thresholds — are themselves typed: the canonical
> `Envelope` schema lives at `safe_agents/broker/schemas/envelope.py`, with `compute_envelope_hash`
> (a plain `sha256:` content hash) tying a Grant/AuditRecord to the exact envelope in force. The
> Envelope is per-agent config that *fills* the seven base schemas above — not an eighth base contract.
> See `core/manifest-schema.md` for the field-by-field prose.
>
> **Read-gating knobs, consumer-configurable.** Four Envelope fields tune how external
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
> - `escalate_composed_destinations: bool` (default `false`) — PTC-52. On a tainted turn, a call
>   that supplies its op's declared `destination_arg` (§2), a read or an internal write alike, is
>   decided as an external write: held through the polarity seam with the reason `tainted
>   composed destination: decided as an external write` (`broker/TAINT.md` §6.1). It does not stop request forgery inside a tool
>   server; containment is the closure. While it is off no decision moves. It dumps like every
>   other knob, so adding the field moved the hash of every envelope once (#178: a grant stamped
>   under the old hash is re-attested by `re-seed`), and turning it on changes the hash as any
>   policy change does. A manifest that turns it on with no `destination_arg` declared is refused
>   at load.
>
> **Harness-tool hold, consumer-configurable (#168).** One Envelope field, safe-by-default:
> - `tainted_harness_hold: ToolClass[]` (default `[]`) — the harness tool classes (`file-read`,
>   `file-write`, `file-edit`, `shell`, `web-fetch`, `web-search`, `other`) whose decision request is
>   held on a tainted turn: a request at the reserved coordinate `harness-tool`, op
>   `<tool_class>/<locality>` (§2), of a listed class at any locality, is routed through the
>   polarity seam with the reason `tainted harness hold: the envelope holds this tool class on a
>   tainted turn`, whatever effect and external the consumer declared there (`broker/TAINT.md` §5).
>   Empty is off, and no decision moves. A class listed twice, or not a member of the set, is
>   refused; a manifest that lists a class no `harness-tool` entry declares is refused at load. It
>   holds only a call the harness's hook carries to the broker, and it adds no taint itself. It
>   dumps like every other knob, so adding it moved the hash of every envelope once (#168).
>
> **Availability / liveness knob, consumer-configurable.** One Envelope field, the typed
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
>   (the log-metric alarm surface) past that many NEW held intents per principal+op+UTC-day — but
>   the broker **still holds the intent**; it never sheds (shedding under flood is the
>   forced-abstention harm under act-safe polarity, kept consumer-side). With the cap set the alarm
>   also has state (#163): it is **raised** once per op and counter period (an `approval_queue_alarm`
>   log line plus a delivery to the approver seam `build_runtime(on_approval_alarm=...)`), each hold
>   that **expires undecided** while it is raised is counted and delivered by count (one delivery per
>   op per sweep), and it is **cleared** once every hold made in the flooded period has been decided
>   or has expired. With no seam wired, those deliveries are the log line only. Unset = OFF: the
>   hold path is byte-identical to today's. Mechanism only; no polarity in the base.
>
> **AgentManifest (`safe_agents/broker/schemas/manifest.py`)** is the typed broker-facing
> deployment-manifest block `build_runtime(manifest)` consumes: `envelope` (required) plus
> `principal`, `grant_classes`, `budgets`, `connectors`, and two consumer-connector
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
>   value is resolved under `<prefix>/connectors/<leaf>`, so a pre-prefixed value
>   would double the prefix and miss the IAM grant.
> - `tool_ops: list[ToolOp]` (default `[]`) — the consumer-owned ToolOp table. Each op's
>   `effect/external/reversible/egress_arg/destination_arg/causes_context` classification travels WITH the agent here, not in a
>   base global; `build_runtime` compiles it into the runtime's `ToolOpTable` and the broker
>   resolves every `(tool, op)` against it — so a consumer-defined op gates identically regardless
>   of its name (the base owns the ToolOp *schema* + the PDP rules that key on it, never the op
>   *names*). A grant for a class with no matching `tool_ops` entry is inert (no entry ⇒ the PEP
>   denies). Duplicate `(tool, op)` keys are rejected at load. The reserved tool `harness-tool` is
>   where a consumer classifies a harness's own tool calls, one entry per `<tool_class>/<locality>`
>   op (§2); an entry there whose op is not such a pair is refused at load. The base ships a copy-only `CATALOG`
>   of domain-neutral ops (`safe_agents.broker.manifest.CATALOG`) an author may copy in; it is
>   **never** consulted at request time. `tool_ops` rides inside `AgentManifest` — it is not an
>   eighth base schema.
> - Later phases added further manifest blocks documented in their own contracts:
>   `connector_auth` + `capability_iam` (#79, `broker/CONNECTOR-AUTH.md`), `counter_period`
>   (§Budgets note below), `clock_skew_seconds` (#175: the bound in whole seconds, default 0, at
>   most 86400, applied toward less authority where the broker's PIP and approval release, the
>   drain, `propose`/`ratify`, and the MCP `bulk-propose`/`bulk-ratify` commands compare their
>   instant with a time another party's clock stamped; `broker/grant-lifecycle.md` §Lapse). Two
>   commands read no manifest and take `--clock-skew-seconds` instead, defaulting to 0: the lapse
>   runner and MCP `admit-ratify`. They apply this bound only when given the same value. The
>   delegation checks and the dwell check take the bound as a parameter from their caller, and no
>   runtime path in this tree calls them yet. And `mcp_servers`
>   (`broker/MCP-HOST.md`) — the image-baked
>   half of two-key MCP admission: the declared `(server_id, tool_name)` namespace +
>   per-tool `structured_output` trust eligibility, validated at load against `tool_ops` and
>   `envelope.trusted_read_sources`.
> - `input_max_age_seconds: {input: seconds}` (default `{}`, #176; PTC §6.13, GAL §6.15): the
>   longest a decision may rely on each fetched input, in positive whole seconds no larger than one
>   hundred years (a larger value is refused at load), counted from the instant the broker
>   established it. The input names are a closed vocabulary: `manifest`, `envelope`, `hmac_key`
>   (read once at startup), `grant`, `counters`, `sub_grants` (read per call), `intent` (the frozen
>   call, read at release), `mcp_admission` (an MCP server's two-key admission snapshot, read at
>   spawn and again past its age, `broker/MCP-HOST.md`) and `issuer_standing` (the issuer's signed
>   standing document, #179). The last differs twice. Its maximum age is bound at deploy
>   (`ISSUER_STANDING_MAX_AGE_SECONDS`, no default), a value here may only shorten it, and a longer
>   one refuses at startup. And past its age it refuses nothing: the grants whose level rests on an
>   issuer key act at the lower of their level and `lastSafeLevel`, while the age still counts
>   toward the decision's horizon, so a held call is evaluated again past it
>   (`broker/grant-lifecycle.md` §"Key standing"). A decision depending on any other
>   input past its age is refused (`deny`, reason `input past maximum age: <input> …`) before
>   any counter is drawn or connector reached, and a held call released past it is refused at release. The age is
>   checked at the initial decision and again at `enforce()`'s premise revalidation. An error while
>   checking refuses too (`deny`, reason `input age check failed: <error type>`), never reading the
>   inputs as fresh. Nothing re-reads an
>   input because it aged: a startup input is fetched again only by a restart, so an age declared
>   for one is a deadline by which the broker must be restarted, after which it refuses every call
>   until it is. Empty declares no age and refuses nothing; the as-of instants are recorded on the
>   audit record either way (§5). Image-baked like `counter_period`, and outside `Envelope` so
>   declaring it never changes the envelope hash.

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
  ts:          string              // instant of the last write to this grant; equal to the ts of the record that write appended
  lastSafeLevel: "in-loop" | "on-loop"          // the rung automatic demotion falls back to (never "out-of-loop")
  demotionTriggers: DemotionTrigger[]           // the deterministic conditions that trip demotion (see below)
  demotionReason: null | "failing" | "pending-evidence"  // why currently demoted; null if at full level
  labelLatency: string             // how long until an action of this class yields ground truth (caps re-promotion speed)
  ownerId:     string              // the NAMED human owner accountable for this grant
  certifiedUntil?: string | null   // the certification TERM: an explicit UTC instant; null/absent = no term
}
// Integrity lives at the STORE's item level, not on the schema: the grant
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

> **DemotionTrigger is emitted as a typed `DemotionSignal`.** The evidence
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
- **envelopeHash** — the envelope is the deterministic bounded region (caps,
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
- **certifiedUntil** — the term of the current certification (GAL §6.7.6). Once
  `now + skew >= certifiedUntil` (`skew` = the manifest's `clock_skew_seconds`, default 0; GAL-42),
  per-call enforcement treats the grant as being at `lastSafeLevel` (never
  higher than its stored level), and the demotion runner records a `lapse` (§7). `null` means no
  term and never lapses; terms **ship unset**. It must be an explicit UTC instant (`Z` or `+00:00`;
  naive and non-UTC values are refused) and is stored verbatim. **Omitted from the canonical payload
  when null**, so every grant predating terms keeps byte-identical canonical bytes; when set it is inside
  the HMAC'd payload. Set only by a ratified promotion; no other write may lengthen or drop it
  (`grants/store.py::refuse_term_extension`). Whether a term has passed is judged against an
  explicit evaluation instant, never a record's `ts` (`grants/term.py`).

---

## 2. BrokeredCall

The typed envelope the PEP materializes from a tool call. **The PDP never sees free text.**
`manifest` is looked up from the agent's `ToolOpTable` (compiled from `AgentManifest.tool_ops`)
— a classified, code/manifest-resident fact, never model-supplied. **Pillar 1.**

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
//, never a base global. Illustrative consumer classifications:
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
  egress_arg?: string              // read-gating: name of the arg that egresses to the provider (e.g. "query")
  destination_arg?: string         // PTC-52: name of the arg that says where the request goes (e.g. "url")
  causes_context?: {               // PTC-51: running this op creates a context that acts later
    target: "self" | Principal     //   a deferred run of this principal, or a child spelled in full
    horizon_seconds: number        //   the record's lifetime when no sub-grant to the target exists
  }
}
// A harness's own tool call is decided at the reserved tool "harness-tool", op "<tool_class>/<locality>":
//   { tool:"harness-tool", op:"shell/project", effect:"write", external:false, reversible:true }
```

Per-field notes:

- **principal.tier** — coarse trust tier (A–D) used by capability-scoping and policy; a recruiter
  (Tier C) is served only resume-screening read tools.
- **manifest.effect/external/reversible** — the three static facts that drive most policy. They are
  classified in the consumer's `AgentManifest.tool_ops`, not model-supplied, so the model
  can't assert its `send` is really a `draft`. `effect:"write"` is
  default-deny; `external && !reversible` is the high-blast/irreversible boundary where the heavy
  machinery belongs.
- **taint** — set at ingestion from the *source*, propagated through any derived result; the model
  never judges maliciousness. The PDP keys an external write in a tainted turn to
  `require_approval`/`deny`.
- **session.ingestedSources** — what untrusted sources this turn touched; feeds taint and audit.
- **manifest.egress_arg** — the name of the single arg whose value egresses to an external
  provider (the covert-exfil channel; `"query"` for `search.query`). Code-resident, never
  model-supplied. When set, the PIP bounds that arg's UTF-8 byte length against
  `Envelope.max_query_bytes` (per call) and its cumulative spend against `Envelope.query_egress_budget`
  (per period), and the PEP meters the bytes that actually cross the wire. `null` = the op egresses no
  agent-composed argument.
- **manifest.destination_arg** — the name of the top-level arg whose value says where the request
  goes (an address, a host, a path on another system). Declared in the image-baked manifest, never
  model-supplied, and read only by the composed-destination control: with
  `Envelope.escalate_composed_destinations` on, a tainted-turn call whose args carry this key (or
  are present but not a mapping the broker can read by name) is decided as an external write
  (`broker/TAINT.md` §6.1). The match is the exact key, so the declaration has to name the key the
  connector actually reads; a case variant or alias the connector also accepts is not seen. Absent
  = the op takes no destination the agent can choose. It dumps as `null` when unset, as
  `egress_arg` does. A declaration is in the runtime's table and in a stored call's bytes (and so
  in its `storedCallDigest`) whether or not the knob is on; only the control reads it, and only
  while the knob is on.
- **The reserved coordinate `harness-tool` (#168).** A harness's own tool call (its shell, its file
  reads and writes, its web fetch) is decided at tool `harness-tool`, op `<tool_class>/<locality>`,
  spelled as the tail of the source id `harness:<harness>/<tool_class>/<locality>`; both sides come
  from closed sets (`schemas/harness_tool.py`). Its `ToolOp` facts are the consumer's declaration in
  `tool_ops`, activated by an ordinary grant on that action class; the base declares no facts for
  any class and no polarity. A class with no entry has no connectable op and is refused. The facts
  are the consumer's classification of what the adapter reports, never an observation of the call.
  The coordinate is never in the served registry and never a connector op: an agent-facing call
  (`/call`, MCP `tools/call`) that names `harness-tool` is refused and recorded as `deny`/`denied`
  before the manifest is consulted.
- **manifest.causes_context** (PTC-51, #177): the op's declaration that running it creates a
  context that will act later, and whose principal that context runs as. `target` is the literal
  `"self"` (a deferred run of the principal whose manifest declares the op) or a child principal
  with all four parts spelled, non-empty and unpadded. `horizon_seconds` is a positive whole number
  of seconds, at most 3,162,240,000 (one hundred years of 366 days, the bound
  `input_max_age_seconds` uses), and is required on every declaration. It is honoured only
  from the image-baked manifest's `tool_ops`; the broker reads it from its own `ToolOpTable`, never
  from a call or from the copy of the ToolOp a held intent froze. Refused at load, each with a
  message naming the `tool.op` entry: any other target shape, a missing or non-positive horizon, a
  child target equal to the manifest's own `principal`, and any declaration in a manifest that
  names no `principal`. A manifest that declares one builds no runtime without an inheritance
  store (below). Absent, the op creates no context the broker is told about and nothing is
  written. It dumps as `null` when unset, so it is in a stored call's bytes like the other ToolOp
  fields; adding it moved no pinned hash.

### The inheritance record (a store row, not a base schema)

When an op that declares `causes_context` runs, the broker writes one `InheritanceRecord`
(`safe_agents/broker/schemas/inheritance.py`) before it calls the connector, and every runtime
reads the unexpired records for its own principal when it mints a turn. `broker/TAINT.md` §4.1 owns
that behaviour and its fail directions; this is the shape.

```ts
// Illustrative stub, not an implementation
interface InheritanceRecord {
  id: string                 // broker-minted, unique per record
  target: Principal          // whose turns inherit: the causing principal for "self", else the child
  causingPrincipal: Principal
  causingTurnId: string      // the broker-minted turn the cause op ran in
  taint: { tainted: boolean; sources: string[] }   // the causing call's own frozen taint, whole
  tool: string; op: string   // the op coordinate that caused the context
  issuedAt: string           // ISO-8601 with an offset
  notAfter: string           // ISO-8601 with an offset, later than issuedAt; fixed at write
}
```

- **taint** is copied from the causing call. A call released from an approval hold carries the
  taint the hold froze into its intent, so a released call writes the same record an inline call
  would. Source ids keep their original spelling; no lineage prefix is added.
- **notAfter** is resolved by `taint.inheritance.resolve_not_after`: the expiry of the child's
  sub-grant when the broker's sub-grant store holds one for the target, otherwise `issuedAt` plus
  the declaration's `horizon_seconds`, and always the latter for `"self"`. A record whose
  `notAfter` is not after its `issuedAt` is refused, so the write fails and the op does not run.
  A record taints while the reader's instant, less the reader's `clock_skew_seconds`, is before
  `notAfter`, so another broker's clock can only keep it tainting longer.
- **No hash or signature.** Like every other broker-written row, a record's integrity rests on who
  may write the store. The agent holds no store credential. A record grants nothing. The
  broker code writes create-only, but a holder of the store write could rewrite or delete a live
  record and so lower the taint it carries; the ledger is only as sound as that write is held.
- **Key layout**, the same on every durable store so a row pump moves rows verbatim:
  `pk = "INHERIT#<agentId>#<skill>#<user>#<tier>"` (the target) and
  `sk = "<notAfter as fixed-width UTC>#<id>"`, with the record as JSON in `data`. A read asks for
  one partition from the current instant onward, then re-checks each record's `notAfter`.
- **Stores** (`safe_agents/broker/taint/inheritance.py`, `inheritance_sqlite.py`), behind one
  protocol, `put_record(record)` (create-only) and `live_records(target, now)`. In memory, for
  tests and one process. SQLite, in the broker-writable database `BROKER_SQLITE_PATH` names and
  never in the grant space's own file, which a cluster mounts read-only into the broker. DynamoDB,
  in the grants table under `INHERIT#`, read by a strongly consistent Query on the target's
  partition and never a Scan, and written by a conditional create through `UpdateItem` that the
  broker role may issue only for `INHERIT#` keys (`dynamodb:LeadingKeys`,
  `infra/lib/identity-stack.ts`). The grants table has no time-to-live, so an expired row stays
  stored until something removes it; it taints nothing.
- **The floor.** `BrokerRuntime` refuses to construct when its ToolOp table declares any
  `causes_context` and it was given no store. `build_runtime` builds the SQLite or DynamoDB store
  on those arms whether or not the manifest declares a cause op, because a child that declares
  nothing still reads its records; on the in-memory arm there is none unless one is passed.

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
  saying the argument half is unbuilt here (tracking **#16**). So this is a design requirement the
  code has not reached, not a verb that was never meant to clamp — the spec states the blueprint and
  marks what is unbuilt, while this document describes what exists. Do not cite #93 as the tracker:
  it owns magnitude bounds through accumulating counters, which is what a clamp would clamp *to*,
  not the per-call narrowing itself.
- **require_approval.renderedIntent** — the **materialized** bytes that will execute, persisted as an
  `Intent` record (§4; fields: id, materializedRequest, renderedForHuman, status, expiry, approvedBy,
  ts). What-you-see-is-what-executes: the human approves the stored `materializedRequest`, not an
  agent-written summary. The turn ends; the agent cannot self-release.
- **require_approval.reason** — WHY the call was held, as the PDP rule that fired phrased it, copied
  onto the `AuditRecord.reason` of the hold. `deny` and `abstain` always carried a reason and
  `require_approval` did not, so a held record read `reason: null`: the tape could show that a call
  was held and never say what held it. Optional because the field post-dates the verb —
  a record written before it exists is not missing anything, and omitting it keeps those records
  hashing byte-for-byte.
- **abstain.escalate** — escalation spends the **attention/escalation budget** (Budgets §5), so
  `abstain → escalate:true` is itself rationed; an adversary DoSes this channel. `abstain` is a
  first-class outcome, not a failure.
- **Facts** — supplied by the PIP: grant presence and level, counter balances, human reachability,
  `destination_composed` (the composed-destination knob, the op's `destination_arg` and the call's
  args folded into one boolean, so the PDP never reads args), `harness_class_held` (the
  `tainted_harness_hold` knob and the reserved coordinate's op folded into one boolean, so the PDP
  parses no op string), and
  *constructed* confidence (self-consistency / ensemble / conformal / stale — high-stakes tier
  only). Confidence is computed deterministically, never read off a raw model logprob. The
  constructed value is packaged as a typed `ConfidenceArtifact` and gated by the deterministic
  `meets_bar` predicate against the `Envelope.confidence` knob; a below-bar call routes to
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
  status:              "pending" | "approved" | "rejected" | "expired" | "executed" | "refused" | "permitted"
  expiry:              string            // hard TTL; an undecided intent expires at this timestamp (ISO-8601 UTC), recorded as an event
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
- **status** — `pending` (awaiting human decision) · `approved` (broker may execute; for a held
  harness tool call, the harness's next request for the same call may be permitted once) · `rejected`
  (human declined) · `expired` (TTL passed with no human decision) · `executed` (broker ran it) · `refused`
  (a human approved, and release-time revalidation then refused: the grant was revoked or demoted,
  or the op's period budget was exhausted, between the hold and the release, or an input the
  release depends on was past its declared maximum age at the release instant; nothing ran, #9,
  #176) · `permitted` (a held harness tool call, at `harness-tool`: a human approved it, and a later
  request for the same call was evaluated again and permitted once, so the harness performed it;
  the broker ran nothing, so it is never `executed`, #168). A release is a decision of its own: it
  re-reads the frozen call, the grant and the counters, and never relies on the hold's inputs or
  horizon.
  Terminal states: `rejected`, `expired`, `executed`, `refused`, `permitted`.
  A held harness tool call (#168, `broker/GATEWAY.md` G36) moves differently once approved, because
  the broker never runs it. Approving it moves `pending` to `approved` and nothing else: no
  connector, no `enforce()`, no record. `approved` then waits for the harness to ask again. The next
  request from the same principal at the same coordinate with the same input digest, inside the
  expiry, is evaluated again; on `allow` the intent moves `approved` to `permitted` before the
  `permitted` record is written, and on anything stricter to `refused`. An approval found past its
  expiry moves `approved` to `expired`. Such an intent is held under an id derived from the
  principal, the op and the input digest, so the broker finds it with a get by key, and a later
  hold of the same call reuses the id once the earlier one has resolved.
- **expiry** — a hard TTL. An intent the human does not act on expires; it never hangs open
  indefinitely, and an expired intent never executes. The agent cannot extend or re-issue. It is stamped
  under the clock of the process that held the call, so a release (`approve`) judges it at
  `now + AgentManifest.clock_skew_seconds` and refuses up to that bound early (PTC-49); a
  rejection applies no bound, since both outcomes refuse and the owner's "no" stays recorded
  as a rejection rather than an expiry. The
  period is ONE fixed value (`DEFAULT_APPROVAL_EXPIRY_SECONDS`, an hour): it does not shorten as
  the queue grows (PTC §6.12). Expiry is an **event**, found by the runtime's sweep
  (`BrokerRuntime.sweep_expired_intents`), which a long-lived host runs on a schedule (the broker
  server between requests, the gateway beside its mouths, and once at boot on the sqlite arm), and
  which reads each backend's pending index attributes and never issues a DynamoDB Scan (on
  DynamoDB it is a Query on the sparse `pending-by-principal` index; the sqlite and in-memory
  backends read every intent row's attributes and filter in process). Whoever moves the intent from `pending` to `expired` (the sweep,
  or a late approve or reject that finds it past its expiry) writes its one `expired` audit
  record; the transition is a compare-and-set, so there is exactly one. A pending row's DynamoDB
  time-to-live sits a grace period (seven days) past its expiry, and the sqlite privacy sweep keeps
  a pending row for the same grace, so the record is written before the row can go. Limits of what
  this buys (#163): a hold outlasting the grace with no broker of its principal running is deleted
  unrecorded; so is a hold written before the pending index existed, which carries no index
  attributes and is never a sweep candidate (on DynamoDB it keeps its old time-to-live, its expiry;
  on sqlite it goes after the grace); and if the audit sink fails after the compare-and-set, the
  intent is already `expired` and nothing writes its record again, the same as a rejection whose
  emit fails. "Exactly one" is per hold: with dedup on, an identical call held again after an
  expiry reuses the content-derived id, so a reader keyed on `intentId` can see two `expired`
  records for one id, told apart by `expiredAt`, as it can already see two `held` records.
- **approvedBy** — the authenticated human identity, set by the approval path (not the agent).
  Copied into `AuditRecord.approvedBy` at execution time, and onto the refusal record when
  release-time revalidation refuses, so the tape shows who approved a release the broker declined.

Intent is stored in **DynamoDB** (the same on-demand table as grants and counters). `AuditRecord.outcome = "held"` means an intent is pending; `"executed"` / `"denied"` / `"refused"` / `"failed"` are terminal, an owner's "no" writes a `"rejected"` record, an intent that expires with no human decision writes an `"expired"` record, and a held harness tool call that is released writes a `"permitted"` record.

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
  outcome: "executed" | "denied" | "held" | "refused" | "failed" | "rejected" | "flagged" | "observed" | "expired" | "permitted"
  error?: string
  seed?: string                    // committed randomization seed, where allocation was randomized (auditable randomness)
  intentId?: string                // approval receipt — held + release records: joins a hold to its release across the intent TTL
  storedCallDigest?: string        // approval receipt — digest of the frozen materializedRequest; hold-side == release-side ⇒ executed==approved is byte-provable post-TTL
  resultDigest?: string            // approval receipt — broker-written digest of the connector response (the effect receipt)
  actorDigest?: string             // owner-verdict receipt: "sha256:" digest of the human who rejected or flagged; never the identity in clear
  evidenceBucket?: string          // owner-verdict receipt: the counter period bucket the verdict's evidence write landed on
  expiredAt?: string               // expiry receipt: the expired intent's verified expiry instant (ISO-8601 UTC)
  inputsAsOf?: {[input: string]: string} // per fetched input the decision depended on: the ISO-8601 instant as of which the broker established it (#176)
  horizon?: string                 // the earliest instant any input in inputsAsOf passes its declared maximum age; absent = no bound
  prevHash: string                 // chains to the previous record
  hash: string                     // hash over this record incl. prevHash -> tamper-evident
}
```

Per-field notes:

- **argsDigest** — hash, not raw args, so the audit doesn't itself become a PII store.
- **envelopeHash** — ties the decision to the exact signed envelope, so "under what authority?"
  reconstructs.
- **outcome** — `held` is an intent awaiting approval; `executed`/`denied`/`refused`/`failed` are terminal.
  `refused` means a control refused the call after the PDP decided (two-key MCP admission is the
  first), so nothing was attempted; `failed` means the execution step broke.
  `rejected` and `flagged` record an owner's verdict on an intent rather than a call's fate (#34,
  #134). `rejected` is an owner's "no" to a held intent, so nothing ran. `flagged` is an owner
  reviewing an executed intent as wrong, which writes the `false_action` evidence counter. Both
  records carry the stored call's coordinates, `decision: "require_approval"` (the verb the intent
  was held under), `intentId`, `storedCallDigest` and `actorDigest`.
  `observed` means the broker made no decision on the call at all: a harness ran it with a tool of
  its own and reported it after it ran (`broker/GATEWAY.md` G21 to G29). Its record carries
  `decision: "abstain"`, the reserved coordinate `tool: "harness-tool"` with the reported tool
  class as `op`, a digest of the reported subject inside `argsDigest`, and the result digest, when
  one was reported, as `resultDigest`. It is terminal, and nothing was decided or attempted by the
  broker.
  `permitted` means the broker decided a harness's own tool call before it ran and allowed it, so
  the harness performs it (#168). Its record carries `decision: "allow"` and the reserved coordinate
  `tool: "harness-tool"` with `op` `<tool_class>/<locality>`; one that releases an approved hold also
  carries `intentId`, `storedCallDigest` and `approvedBy`. It is never `executed`, which says the
  broker ran the effect: here the broker ran nothing, and only the harness's own report afterwards
  (`observed`) is evidence that the call ran. Its args are `{"call", "harness", "input",
  "locality", "subject"}`, all codes or digests, so `argsDigest` binds the input digest; on a release
  they are the re-issued request's, and `storedCallDigest` binds the held call. Its `reason` cites the
  coordinate as the manifest's declaration (`permitted at harness-tool.<op> as declared by the
  manifest; performed by the harness`, or `permitted once at ... on the approval of intent <id>`).
  `expired` means a held intent reached its expiry with no human decision (#163, PTC §6.12). It is
  its own outcome, never `rejected` or `denied`, so a timer never reads as a person having said no.
  Its record carries the stored call's coordinates, `decision: "require_approval"`, `reason:
  "approval expired undecided"`, `intentId`, `storedCallDigest` and `expiredAt`, and no
  `actorDigest`, `approvedBy` or `evidenceBucket`: nobody acted, and an expiry writes none of the
  counters the promotion predicate reads (`observations`, `human_override`, `false_action`). Its
  `ts` is when the broker recorded the expiry, which a sweep interval can put after `expiredAt`.
  When the approval-queue alarm's count write fails the record is still written, with `error` set.
  One variant: an approved harness tool call the harness did not ask for again before its expiry
  (#168) is recorded `expired` with `reason: "approval lapsed unused: the harness did not ask again
  before the intent expired"` and `approvedBy` set, since a human did decide. It is written when a
  later request for the same call finds it, not by the sweep, and never once retention has removed
  the row first (`GATEWAY.md`, Known limits).
- **seed** — when scarcity allocation was randomized (high-stakes tier), the committed seed is logged
  (commit-reveal / VRF): unpredictable in advance, fully reconstructable after. "Why not engage that
  one?" has an answer in the log.
- **intentId / storedCallDigest / resultDigest** — the approval receipts: broker-stamped at the moment
  of effect, agent-unforgeable; digests only, never raw content (the `argsDigest` discipline).
  OPTIONAL — absent == a pre-receipts record, and receipt fields are hash-covered only when
  present, so existing chains verify unchanged while stripping a present receipt breaks the chain.
- **actorDigest / evidenceBucket**: the owner-verdict receipts, on `rejected` and `flagged`
  records. `actorDigest` is `"sha256:"` plus the SHA-256 of the authenticated identity that acted,
  so the tape names who acted without becoming a store of owner emails or handles.
  `evidenceBucket` is the counter period-bucket key the verdict's evidence write landed on: the
  current period for a rejection's `human_override` and `observations` labels, and the executed
  op's own period for a flag's `false_action` back-write. A rejection whose label write failed
  still gets its record, with `evidenceBucket` absent and `error` set, so the tape never claims a
  write that did not land. Optional and hash-covered only when present, like the approval receipts.
- **expiredAt**: the expiry receipt, on `expired` records only: the intent's expiry instant, read
  from its HMAC-verified stored bytes. Optional and hash-covered only when present (#163).
- **inputsAsOf / horizon** (#176; PTC §6.13, GAL §6.15): on every record of a decision the broker
  makes on a call (`handle_request` and an approval's release, including their refusals),
  `inputsAsOf` maps each fetched input the decision depended on to the instant as of which the
  broker established it. That instant is the earlier of the fetch and any time the source stated
  for its answer, and the fetch instant is read before the read it stamps, so a recorded instant
  is never later than a fetch the broker makes. One input arrives fetched by something else: on
  the Fargate service the platform injects `BROKER_HMAC_KEY` from Secrets Manager before the process
  starts, and the broker can stamp it only when it first reads it, later than the real fetch by the
  process's start-up time. The drain worker stamps its key once per cold start, whether it fetched
  it or found it in its environment, so a declared `hmac_key` age fires there too. No source on the decision path states a time today; the manifest
  is a file and the rest are store reads that answer as of the read. The startup inputs carry
  their startup instants on every record for the life of the process, which is what lets an
  auditor tell a decision on current inputs from one on inputs read long ago. An input read twice
  in one decision (initial decision and premise revalidation) records the earlier read. `horizon`
  is the earliest instant at which any of those inputs passes the maximum age the manifest
  declares for it (`AgentManifest.input_max_age_seconds`); it is absent when none of them has a
  declared age. A hold's horizon says how long the hold decision was good for; the release is
  evaluated again and carries its own. An idempotent replay of a call that already executed is not
  a decision carried on from the earlier one: it returns that call's settled outcome and cached
  result, starts no new effect, reaches no connector and writes no record, so it is not evaluated
  again whatever the horizon says. Records that carry no broker decision on fetched inputs
  carry neither field: an owner's `rejected` or `flagged` verdict and the quarantine record either
  of those seams writes, an `observed` event, and a mouth's refusal count. Optional and hash-covered only when present, like the receipts.
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
  `evidence.error_budget_draw`; `blast_radius` is the consumer-declared weight per blast
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

The append-only ceremony-ledger record of every write to a grant. The accountable record (Part 11
of the philosophy doc). Seven record types share one ledger. Six record a level change, and the
maker-checker act that raises a Grant's level is the `promotion` type. `reattestation` records a
write that changes none (GAL §4.3, §6.6). `withdrawal` (GAL §6.10, GAL-41, #179) records a grant
lowered because the issuer key its level rested on was withdrawn; GAL 0.8.0-draft publishes it as
the seventh type (§4.3, §5.2). **Demotions append a
`demotion`-typed record on the same
ledger** — this supersedes the earlier "demotion needs no such record" exemption (Phase 3,
`docs/GAL.md` §3); demotion itself stays automatic and deterministic (`grant-lifecycle.md`).
**Pillar 7.**

```ts
// STUB — illustrative, not an implementation
interface PromotionRecord {
  recordType:  "promotion" | "demotion" | "bootstrap" | "tightening" | "lapse" | "reattestation" | "withdrawal"   // default "promotion"
  actionClass: string              // the class of the grant the record accounts for
  principal:   Principal           // for whom
  fromLevel:   "in-loop" | "on-loop" | "out-of-loop" | null   // null = the Recommend rung (no-grant baseline; the record creates the grant)
  toLevel:     "in-loop" | "on-loop" | "out-of-loop"   // equal to fromLevel on a reattestation record
  evidence:    string              // ref to covered-distribution evidence (delayed-label recalibration result)
  predicate:   string | null       // the signed promotion PREDICATE authored in advance; promotion-typed only
  proposedBy:  string              // maker
  ratifiedBy:  string              // checker (promotion: must differ from maker)
  envelopeHash: string             // the envelope hash in force when the record was written; on a reattestation, the NEW hash
  triggeredBy: string[]            // demotion-typed only: the DemotionTrigger values that fired
  demotionReason: "failing" | "pending-evidence" | null      // demotion-typed; "pending-evidence" on lapse and withdrawal
  ts:          string
  certifiedUntil?: string | null   // promotion: the certification term the checker RATIFIED; lapse: the term that expired; null on every other type
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
| `lapse` | a certification term expired (GAL §6.7.6; `grant-lifecycle.md` §Lapse) | `ratifiedBy` = `"system:demotion-evaluator"`; `triggeredBy` EMPTY (a lapse is an absence, not a fired condition); `demotionReason` = `"pending-evidence"`; `predicate` null; `fromLevel` non-null; `toLevel` = the grant's `lastSafeLevel` (never `"out-of-loop"`); `certifiedUntil` is the term that expired, where present (absent on records written before the field was allowed here); `evidence` names the expired term for a human reader and is never parsed |
| `withdrawal` | the issuer key behind the grant's level was withdrawn (GAL §6.10, GAL-41; `grant-lifecycle.md` §"Key standing") | `ratifiedBy` = `"system:demotion-evaluator"`; `triggeredBy` EMPTY (no condition fired); `demotionReason` = `"pending-evidence"` (nothing is proven broken about the agent); `predicate` null; `fromLevel` non-null; `toLevel` never above `fromLevel` and never `"out-of-loop"` (it is the grant's `lastSafeLevel`); `certifiedUntil` null. The key it accounts for is not a field: a reader derives it from the ledger, as the verified signer of the last licensing record before it, and `evidence` names it for a person and is never parsed |
| `reattestation` | a grant re-issued at its level under a changed envelope (`re-seed`; GAL §6.6) | `fromLevel` = `toLevel` = the grant's level (non-null); `ratifiedBy` is the identity that re-attested; maker ≠ checker NOT enforced; `predicate` null; `triggeredBy` empty; `demotionReason` null; `certifiedUntil` null; `envelopeHash` is the hash the grant was re-issued under |

A `reattestation` record neither earns a level nor lowers one. Every reader that derives a
coordinate's level from its ledger, or looks for the record that raised a grant to its current
level, passes over it (`PromotionRecord.bears_level`): the level and the earning record are the ones
the ledger held immediately before it. The schema refuses one whose `fromLevel` and `toLevel`
differ, at construction, so the writer and every reader that parses one hold the same rule. The
stores hold the other half (`refuse_reattestation_drift`, all three backends): a write under this
record type may change the grant's `envelopeHash`, `promotedBy` and `ts` and nothing else, cannot
create a grant, and its record must carry the grant's level, new hash, re-attesting identity and
`ts`.

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
- **certifiedUntil** — promotion- and lapse-typed only (GAL §5.2, §6.7.6), and the two types
  carry different things. On a `promotion` record it is the term the checker ratified,
  written by the ceremony onto both this record and the raised `Grant.certifiedUntil`. On a
  `lapse` record it is the term that expired, copied by the lapse writer from the grant that
  lapsed as the exact stored string. That is the instant enforcement fell, and it sits beside `ts`,
  the instant the record was written, which is never set to the term. The interval between the two
  is how long the grant sat lapsed and unrecorded. The field is optional on a lapse record: one
  written before it was allowed there carries none, still parses and verifies, and is not an audit
  finding for lacking it. Same format and parser as the Grant field (explicit UTC instant, stored
  verbatim). Every other record type refuses a non-null value, at construction, so the writer and
  every reader that parses a record hold the same rule. **Omitted from the canonical, stored and
  signed bytes when null**, so every record written without it keeps byte-identical bytes and a
  still-valid DSSE signature (pinned in `test_grant_term_lapse.py` for a promotion record and
  `test_grants_lapse_term_bytes.py` for a lapse record); when set it is inside the signed subject
  digest, under the issuer's key on a promotion and the evaluator's on a lapse.
  A lapse record carrying the field sets nothing. The stores refuse a lapse write whose record
  names a term other than the grant's, or that moves the grant's `certifiedUntil` or
  `lastSafeLevel` (`refuse_lapse_drift`, all three backends), and `refuse_term_extension` still
  exempts a `promotion` record only. That guard sits on the paired grant-and-record write, so it
  holds the honest writer and no record appended outside that write. The audit rule
  `LAPSE_TERM_RATIFIED` (GAL §6.11, GAL-44) re-derives the term from the ledger for every lapse
  record that carries one, however it got there: the term must equal, as the stored string, the
  term on the latest `promotion` record before it at its coordinate (by parsed `ts`); with no
  promotion before it the record must carry none; and the term must not be later than the record's
  own `ts`, since a lapse is written at or after the instant its term passed. A `ts` that judgement
  needs and cannot read is a finding too. Un-waivable, and it runs with no key. What it buys: the
  ledger cannot state a lapse term its own promotion records do not account for. It does not say
  the promotion record is genuine, which is `RECORD_SIGNATURE_VERIFIES`'s question, and it does not
  say the lapse was owed.
  The audit rule `GRANT_TERM_RATIFIED` holds each grant to the ratified term: a grant's
  `certifiedUntil` must equal the term on the chronologically-latest **promotion** record at its
  coordinate (a later demotion, tightening or lapse moves the level, never the term), and a grant
  whose ledger holds no promotion must carry no term. The rule reads promotion records only and
  never takes a lapse record's `certifiedUntil` as the ratified term. Un-waivable.
- **triggeredBy / demotionReason** — demotion-typed only. `stale_confidence` maps to
  `"pending-evidence"` (label-free drift voids the certification — gather labels/recalibrate);
  `corroboration_failure` and `budget_breach` map to `"failing"` (fix the model/policy). Never
  collapse the two (§1's demotionReason note).
- Re-promotion runs on **delayed-label reconciliation**: pair a resolved outcome with the confidence
  logged at decision time, recompute calibration, re-validate conformal coverage on the *current*
  distribution, then ratchet up — with hysteresis (different thresholds + dwell time; fresh
  recalibration evidence, never just "the alarm stopped").

**Signing.** Every record type is signed (GAL-SPEC §6.10), by the identity that wrote it: the
**issuer** key signs `promotion`, `bootstrap`, `tightening` and `reattestation` (the
ceremony/operator side); the
**evaluator** key, GAL §6.7.2's separate system identity, signs `demotion`, `lapse` and
`withdrawal`. The two
are distinct keys with distinct env contracts, because an evaluator holding the issuer key could
mint promotion records. Verification selects the key map by `recordType`, so a signature from the
wrong role fails closed (`grant-lifecycle.md` §"Two signing roles").

**Signing-key standing (GAL §6.10, GAL-41, #179).** Which keys of a role still have standing is
carried by a signed standing document per record-signing role, signed by a third role, the
standing authority. Like the Envelope, it is not an eighth base schema: it fills nothing in the
seven, and it describes the keys that sign one of them. Shapes in `grants/key_standing.py`; the
loader, the age and the verdicts in `broker/grant-lifecycle.md` §"Key standing".

```ts
// STUB: illustrative, not an implementation
interface KeyStandingDocument {
  role:     "issuer" | "evaluator"
  version:  number                  // integer >= 1; a verifier refuses one not above what it accepted
  issuedAt: string                  // explicit UTC instant; the as-of is the earlier of this and the fetch
  signer:   { keyId: string; zone: string }   // the standing-authority key; must equal the DSSE keyid
  keys:     { [keyId: string]: KeyStandingEntry }
}

interface KeyStandingEntry {
  publicKey:       string           // Ed25519 SubjectPublicKeyInfo PEM; never rebound, and never listed under two key ids
  state:           "active" | "retired" | "withdrawn"           // one way; no hold state
  retiredAt:       string | null    // set iff retired, or withdrawn after retirement
  retiredReason:   "superseded" | "cessationOfOperation" | null
  withdrawnAt:     string | null    // set iff withdrawn
  withdrawnReason: "keyCompromise" | "privilegeWithdrawn" | null
}
```

Every field dumps, null or not. The carried form is a DSSE envelope with payload type
`application/vnd.safe-agents.key-standing.v1+json` whose payload is the canonical document bytes
(sorted keys, no whitespace, ASCII) and whose one signature is over those bytes; a verifier checks
it before parsing them. Where a role's document is configured, a record signed by a key it lists as
`withdrawn` verifies as `record_signer_withdrawn`, whatever the record's `ts`.

Where the ISSUER's document is configured, the broker's PIP asks it about the key behind each
grant's level: the verified signer of the last record that licensed the grant (the latest
`bootstrap` or `promotion`, or a `reattestation` after it; an unsigned one that comes after a
signed record at its coordinate leaves the key not established). Withdrawn, or not established
within the document's maximum age, and the grant acts at the lower of its level and
`lastSafeLevel`. `propose`, `ratify` and `re-seed` refuse such a grant while it sits above
`lastSafeLevel`, so no `reattestation` re-licenses a level a withdrawal took. The
lower level reaches the PDP as `Facts.grant_level`, so no rule changes and the corpus digest does
not move. Why it fell rides on `Facts.standing_fall_reason`, which no rule reads, for the PEP to
log once at the initial read, as it does `quarantine_reason`. The runner records the fall with a
`withdrawal` record, and four un-waivable audit rules report what neither can see
(`grant-lifecycle.md` §"Key standing").

**Storage.** Records live in the grants table as append-only `RECORD#…` items
(`pk = RECORD#<principal>#<actionClass>`, `sk = <ts>#<recordType>`), written via a
conditioned UpdateItem so an existing record is never overwritten (`grants/store.py`). A record's
`ts` comes from a hybrid logical clock per coordinate (`grants/ledger_clock.py`, #37): the wall
clock, or one microsecond past the coordinate's last recorded `ts` when that is later, so `ts`
stays near wall time and the sk order is the write order even for two records in one clock tick.
The same value is written to the grant in the same write, and the audit rule `GRANT_TS_RECORDED`
holds each grant to it: a grant's `ts` must be the `ts` of the latest record at its coordinate.
The stored
`data` string is the canonical serialization from §1 (sorted keys, no whitespace, ASCII) — the exact
bytes the DSSE signature's subject digest binds, verified verbatim on read.

---

## Evidence contract

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
  annotations: string[]          // attach-only (e.g. the evidence reviewer); NEVER read by any gate
}

interface DemotionSignal {       // emitted at breach; consumed by the Phase-3 evaluator (base emits, never applies)
  trigger:      DemotionTrigger  // §1's vocabulary — "stale_confidence" | "corroboration_failure" | "budget_breach"
  principal:    Principal
  action_class: string           // the (principal, action-class) grant coordinate
  period:       string           // the counter-period bucket — "YYYYMMDD" (utc-day) or "YYYYMMDDTHH" (utc-hour)
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

> **Caps rename.** `caps.actions_per_run` is renamed `caps.actions_per_utc_day` — the field
> has been a per-op per-UTC-day budget since the 2026-07-08 scoping fix
> (`enforcement.scoped_counter_key`), and the name now says so. The old spelling is still accepted on
> load (a validation alias, so no `agents/*.yaml` churns); the canonical dumped key is the new one.
>
> **Counter period.** The bucket every cap and evidence counter scopes to is the
> manifest-named `AgentManifest.counter_period` — default `utc-day` (byte-for-byte the original key),
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
> envelope hash, and an older stored envelope dump (carrying `"abstention_thresholds": null`) fails
> validation loudly at boot — the intended fail-closed path, cured by re-running
> seed_envelope → seed_grants (the consumer's own broker-image cutover runbook). No compat shim.
>
> **The tool allowlist is retired, and retiring it changed every envelope hash (#135).**
> `Envelope.allowlists` was declared as a default-deny scope of the tools an agent may see. No
> decision read it. An agent was served, and could call, whatever its grants covered, so a
> deployment that narrowed the list believed in a restriction that did not exist. The field and its
> model are removed. What an agent may call comes from its grants and from nothing else in the
> envelope. An envelope or manifest that still carries the key is refused at load with a message
> naming the retirement. It is never dropped silently, whatever its value.
>
> The consequence reaches every deployment, including one that never set the block. The envelope
> hash covers the whole dump, and the old dump wrote `"allowlists": null` for an envelope that left
> the field unset. So the hash of every envelope is different after this change. An upgrade across
> it requires three things, in this order:
>
> 1. Remove the `allowlists:` block from the authored manifest. If the list was meant to narrow what
>    the agent can reach, narrow the grants instead.
> 2. In store mode, seed the envelope again. Every envelope row written before the change carries
>    the key, as null when it was never set, and the broker refuses the row at startup until it is
>    replaced. A ceremony command refuses it too, and says the seeded row was refused. Until the
>    row is replaced, the ledger audit reports it as an `UNPARSEABLE_ITEM`. That finding cannot be
>    acknowledged: the remedy is the seed.
> 3. Re-attest the grants with `re-seed`, once per principal. Every grant stamped under an old hash
>    is quarantined on every call until then, and the audit reports each one as
>    `GRANT_ENVELOPE_IN_FORCE`. `re-seed` needs the issuer signing key and has no unsigned
>    override, so an operator without that key cannot complete the upgrade.
>
> No compat shim, for the same reason as the retirement above: a shim that kept old hashes valid
> would have to keep hashing a field that means nothing.
