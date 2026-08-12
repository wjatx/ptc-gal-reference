# MCP-HOST — the broker as a safe host for MCP tool servers (#174)

> **Status: contract (2026-07-17).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, the signed-definition format + the drift/quarantine/taint
> semantics are the contract, and the store binding + the thin MCP client are reference-tier. The
> reference implementation will land under `safe_agents/broker/mcp/` (planned: `registry.py` for the
> admitted-tool store, `discovery.py` for the connect-time hash gate, `client.py` for the python-sdk
> MCP client) with `safe_agents/broker/tests/test_mcp_host.py` as the conformance suite. Companion to
> `broker/CONNECTOR-AUTH.md` (an MCP server is a connector; this doc governs how its *tools* are
> admitted), `broker/TAINT.md` (the source-based taint this reuses), `broker/grants/store.py` (the
> HMAC-quarantine mechanism the registry mirrors), and `broker/grants/commands.py` (the maker≠checker
> DSSE-signed ceremony the admission ceremony mirrors).
>
> **Direction matters.** This document governs the broker as an MCP **client** — how the tools of
> servers it connects to are admitted. `broker/GATEWAY.md` (#283) governs the opposite direction:
> the broker as an MCP **server**, presenting its own served ops to a wrapped agent. The two share
> vocabulary and almost no mechanism — a gateway does no discovery, holds no registry row, and the
> lifecycle clauses M17–M20 do not apply to it.

## What this is — and what it is not

The Model Context Protocol (MCP) lets an agent discover and call tools that a server *advertises* at
connect time. That discovery is the whole problem: MCP carries **no trust model**. A server names its
own tools, writes its own descriptions and input schemas, and can change any of them between one
connection and the next. A malicious or compromised server can therefore rename a benign tool onto a
dangerous effect, or bury an injection payload in a tool's `description` (the "tool-poisoning"
surface) — and a naive host would let the running agent gain that tool the instant it appeared in a
discovery response. **Discovery is untrusted input.** Treating an advertised tool list as an
authorization is the MCP-native failure this contract exists to close.

This document makes the broker a **safe MCP host**: the agent can only ever call a tool that a human
admitted through a ceremony against a definition a human saw, and can never auto-gain a tool because a
server started advertising it. It is **not** a new decision verb, a new grant, or a relaxation of any
floor. Admission decides *whether a tool is callable at all*; the PDP still decides every individual
call exactly as it does for any other connector op, and the response still taints exactly as any
external read does. Admission is upstream of the broker's normal machinery, not a substitute for it.

## The doctrine — no auto-admit, and the two-key lattice

**The load-bearing rule: discovery informs, a human admits, the running agent never auto-gains a
tool.** A tool becomes callable only when *two independent facts* line up, one from each of two
different config layers (`docs/config-provenance.md`):

1. **Layer 1 (code-provenance, image-baked).** The consumer's `AgentManifest` pre-declares the
   `(server_id, tool_name)` namespace it is willing to host, together with each tool's **ToolOp
   classification** (#171 — its effect, blast radius, reversibility). This is code-reviewed and rides
   the image; nothing store-loaded can add a `(server_id, tool_name)` pair or name its effect. A tool
   the manifest never declared is uncallable no matter what any store row or any server says.
2. **Layer 2 (store, integrity-protected).** An HMAC-protected registry row **activates** a declared
   tool — and only when the discovery-hash of the tool the server currently advertises matches the
   hash a human admitted. The row can *select and tighten* among the manifest's declared tools; it can
   never *mint* a callable, because a callable that the Layer-1 manifest did not declare has no
   ToolOp classification and no namespace slot for the row to point at.

This is the same Biba placement `docs/config-provenance.md` draws for `connector_providers`
(import paths, Layer 1 only) and `connector_auth` (a closed enum discriminator, Layer 2 selection):
the thing that can *name a capability to run* stays image-baked; the store may only choose among and
constrain what the image already reviewed. Missing either key fails toward **uncallable**. The store
is structurally incapable of turning a poisoned discovery response into a running tool — the worst a
compromised store can do is deactivate a tool or force a quarantine, never grant one.

## The admission lifecycle

A tool moves through a small set of registry states. The state is a function of two inputs — the
declared+admitted record (what a human signed off on) and the live discovery hash (what the server
advertises right now) — recomputed at every connect/discovery.

```
                 manifest declares (server_id, tool_name) + ToolOp
                                     |
                                     v
                             [ DECLARED ]  -- discovered, not yet admitted:
                                     |         UNCALLABLE (no admitted hash)
                    admission ceremony (maker != checker,
                    issuer-DSSE-signed admission record over
                    the exact advertised definition)
                                     |
                                     v
                             [ ADMITTED ]  -- admitted hash on file
                                     |
                    connect / discovery: host hashes the
                    live advertised (server_id, tool_name,
                    input_schema, description)
                          /                        \
             hash == admitted                 hash != admitted
                   |                                  |
                   v                                  v
             [ ACTIVE ]                        [ QUARANTINED ]
          CALLABLE by the agent          UNCALLABLE, loud, surfaced once;
          (still per-call PDP-gated)     a human re-vets via a fresh ceremony
                                         (the quarantined row is never
                                          auto-overwritten)

   discovered but NOT in the manifest  -> [ UNLISTED ] : UNCALLABLE, quarantine-surfaced
```

- **DECLARED → ADMITTED (the ceremony).** A human runs the admission ceremony against the *exact
  definition the server currently advertises*. The ceremony is maker≠checker (two distinct credential
  identities, exactly as the grant ceremony compares STS ARNs — `grants/commands.py`) and appends an
  append-only, **issuer-DSSE-signed admission record** binding *who admitted which `(server_id,
  tool_name)` at which discovery-hash*. Who admitted a tool is non-repudiable, mirroring the
  PromotionRecord ledger (GAL §8). The admitted hash is written to the registry row.
- **ADMITTED → ACTIVE (connect/discovery).** At every connect the host re-hashes the live advertised
  definition. A match promotes the row to callable *for that session*; nothing is trusted from a
  cached "it was fine last time."
- **ACTIVE/ADMITTED → QUARANTINED (drift).** If the live hash differs from the admitted hash — a
  changed schema, a changed description, a renamed effect — the tool **fails closed**: it drops to
  uncallable, surfaces loudly exactly once (one distinctive audit record + an ERROR log, the sa#124
  shape), and stays that way until a human re-vets the new definition through a fresh ceremony. Drift
  is not a silent re-admission; the running agent never auto-gains the changed tool.
- **UNLISTED (undeclared discovery).** A tool the server advertises that the manifest never declared
  is uncallable and surfaces as a quarantine-class finding. It cannot be admitted by a store row alone
  — admission requires the Layer-1 declaration first.

## What is signed, and why `description` is in the set

The discovery-hash covers **every advertised field** of the definition (#223): the four
always-present core fields

```
(server_id, tool_name, input_schema, description)
```

plus each metadata field the server actually advertised (`title`, `output_schema`, `icons`,
`annotations`, `meta`, `execution` — and any field a future `McpToolDef` learns). The hash is
`sha256` over the **canonical JSON** of the advertised set — sorted keys, compact separators
(`","` / `":"`), ASCII — the same canonicalization the grant/record stores use
(`json.dumps(..., sort_keys=True, ensure_ascii=True)` with compact separators), so admit-side and
connect-side agree byte-for-byte.

A field the server did not advertise (`None`) contributes **nothing** to the preimage — it is
excluded, never serialized as null. Two properties fall out, both deliberate:

- **Legacy equivalence.** A definition advertising no metadata hashes byte-identically to the
  pre-#223 four-field basis, so the #223 far-jump falls only where new signed material actually
  exists — a row whose live server advertises nothing new is not forced through an empty-delta
  re-vet (an alarm with nothing to show teaches operators to dismiss the alarm that matters).
- **Additive-evolution immunity.** The MCP spec is still growing tool fields; a nulls-in basis
  would move every hash each time the model learns one. Excluding `None` means a new optional
  field moves nothing until a server advertises it — and a field **appearing, changing, or
  vanishing is itself drift**, because the advertised set is the signed set.

No integrity is lost in the collapse: the model cannot distinguish an absent field from an
advertised-as-null one, so neither can the hash.

`description` is in the signed set **because it is part of the injection surface**, not merely
documentation. An MCP tool description is text the server controls and the agent reads; a server that
leaves `(tool_name, input_schema)` untouched but rewrites the description to smuggle instructions has
changed what the tool *does to the agent* without changing what it *is called*. Excluding the
description would leave the tool-poisoning channel open under a matching hash. So a description change
**alone** is drift, and drift fails closed like any other. Since #223 the same holds for the server's
own danger claims: an annotation flip (`readOnlyHint` → `destructiveHint`), a rewritten
`output_schema`, or a changed `execution` hint breaks the hash and fails admission — pre-#223 these
were carried for display but unsigned, and that drift was undetectable.

Note the asymmetry with the ToolOp classification: `description` lives in the **registry row only**
(it is part of what a human admitted and what the hash covers) and is **never** a PDP input. The
ToolOp fields — the effect classification the PDP reads — come from the Layer-1 manifest, never from
the server's self-description. The server's words are hashed and pinned; they never decide a call.

## Taint, structured-only trust, and the ships-OFF response screen

An MCP tool call is an external read: it runs `external=True, effect="read"` through the broker, and
its **response taints the turn by default** via the sa#134 self-ingestion mechanism, with source id
`connector:<server_id>.<tool_name>`. A subsequent external write on that turn therefore rides the
standing `tainted_external_write` cut — the lethal-trifecta floor is unchanged and un-tunable
(`docs/friction-doctrine.md` rule 1).

Per-`(server_id, tool_name)` trust is opt-in through `Envelope.trusted_read_sources`, the same
consumer knob that relieves any other external read — **and it is legal only for a tool declared
`structured_output: true`**. A structured tool returns typed, schema-bounded data (an ID, a number, a
record); a free-text tool returns model-readable prose, which is exactly the injection surface trust
must not wave through. A `trusted_read_sources` entry naming a tool that lacks a structured output
schema is **refused at manifest load** (`CONNECTOR-AUTH.md` C4 discipline — fail at build, never at
the wire), so a consumer cannot accidentally trust a free-text channel.

An optional **response screen** — the gate-7 analog for MCP responses, a model-judged advisory over
the returned content — **ships OFF** (`docs/friction-doctrine.md`: every non-floor bound is an
Envelope knob defaulting off). With it unset, responses taint as above and nothing is screened;
enabling it is a consumer knob, never a base default, and it never *blesses* content — it can only
refuse or pass, exactly as the channels screen does.

## Native construction — the manifest spawns the server (#221)

Since #221 the Layer-1 declaration can also say **how to run** the server: `McpServerDecl` carries
optional stdio spawn config (`command`, `args`, static `env`, `cwd`), and `build_runtime` composes
the whole MCP stack itself — child process, host factory, admitted-tool registry — with **no
consumer connector class in between** (`prototype/mcp_construction.py`; the pre-#221 pattern of a
`connector_providers` class hand-wiring `stdio_host_factory` is retired, and the consumer-boundary
guard is back to `{schemas}`: consumers *declare*, the broker *composes*). A declaration without
`command` stays namespace-only, byte-for-byte the #174 shape.

The spawn block names code to run, so it sits in the same injection-power class as
`connector_providers`: honored **only from the image-baked manifest** — structurally, because the
envelope store loads an `Envelope`, which has no `mcp_servers` field. A spawnable server must be
wired in `connectors` (dead config refuses at load) and must not also name a provider class (two
construction paths refuse at load). Without a named registry table the construction refuses at
build — no registry means every tool is declared-only and uncallable, and a dead connector must be
loud, not silent.

The child's environment is composed broker-side from exactly two manifest-governed halves — the
static spawn `env` (plain config, e.g. `ALPACA_PAPER_TRADE: "true"`) and the spawn-time credential
half delivered through `connector_auth.env_map` (CONNECTOR-AUTH.md §"Spawn-time delivery", clause
C9) — disjoint at manifest load, overlaying the SDK's minimal default environment, never logged,
never visible to the agent.

## Child lifecycle — death, reconnect, respawn (#221 Phase 3)

A spawned server is a child process, and a long-running broker service will outlive it. The
lifecycle posture splits exactly along the friction doctrine: the failure semantics are **floor**
(fail-closed, non-negotiable), the recovery semantics are a **consumer knob shipping OFF**.

**Child death is a typed failure.** Death of the child or its transport — at spawn, mid-call, or
between calls — surfaces to the caller as a **typed error naming the server and carrying the real
cause**, promptly. Never the generous call-timeout backstop (a spawn failure surfacing as a bare
30-second `TimeoutError` with the cause lost was the #219 Leg-1 finding, and stays fixed), and never
a raw transport internal leaking up as the API. A dead server is loud and diagnosable, not a hang.

**Every reconnect is a new discovery.** A respawned child is a NEW server as far as trust is
concerned: whatever it now advertises must pass the pure discovery evaluator again — registry rows
re-read, admitted hashes re-checked, drift/UNLISTED findings re-fired — **before any call**. No
verdict, snapshot, or finding is ever carried across a child death. The drift gate is only as good
as its re-evaluation: a respawn that resumed the old snapshot would let a server swap its tool
definitions behind an already-blessed session. (Credentials follow the same rule — the
`env_map` half re-resolves per spawn, never cached across a death.)

**Respawn is policy-as-data and ships OFF.** Whether the broker respawns a dead child at all is an
*availability* choice, and like liveness (sa#159/160) its safety is polarity-dependent — an agent
whose safe state is abstention wants a dead tool to stay dead; an agent with positive safe actions
may need it back. So the base ships the mechanism only: an optional `respawn` block on
`McpServerDecl` (bounded `max_attempts` + `backoff_seconds`), honored **only from the image-baked
manifest** — it governs process execution, the same injection-power class as the spawn config it
rides on, and structurally out of the store's reach (`Envelope` has no such field). **Absent block =
no respawn** — the connector stays dead-but-typed until the service restarts, byte-for-byte the
pre-knob behavior. Attempts are consumed per death, delay runs between attempts, and an exhausted
policy degrades to exactly the OFF behavior: typed failure, no retry storm.

**Shutdown reaps children before the loop closes.** On `close()` — the SIGTERM / Fargate stop-task
path — the session context unwinds and the child is reaped **before** the connector's private event
loop stops. The ordering matters: a loop torn down first strands the SDK's cancel scopes and leaks
the child past the task's grace window. Teardown is assertable — a conformance/drill teardown
*proves* the child is gone, not just requests it.

## Remote servers — the streamable-HTTP variant (#221 Phase 4)

A vendor-hosted MCP server (a brokerage's agentic endpoint is the driving case) is not spawned —
it is **connected to**: `McpServerDecl` alternatively carries `transport: "streamable-http"` + a
`url` instead of the stdio spawn block. The URL names where every call — and, later, every
credential — goes, so it sits in the **same injection-power class as `command`**: honored only from
the image-baked manifest, structurally out of the store's reach. Plain `http://` is refused at load
for any non-loopback host — a cleartext tool-call surface is a poisoned-discovery and
credential-leak channel, and the loopback carve-out exists only so a toy/test server can run
without TLS theater.

Everything trust-shaped carries over unchanged, because none of it ever lived in the transport:
two-key admission, the advertised-set discovery hash, drift quarantine, M5 flood discipline, response
taint. Two readings sharpen for a hosted server. First, **the discovery hash is the only pin** —
there is no package version to hold; when the vendor edits a description the tool
drift-quarantines, and that is the design working (budget re-vet time for a surface the vendor
churns). Second, the **lifecycle clauses M17–M20 apply with "child" read as "session"**: a dead
peer/connection is the same typed death, every reconnect is a new discovery, `respawn` (legal on a
`url` decl, same ships-OFF M19 semantics) governs reconnect bursts, and `close()` unwinds the
session before the loop stops.

**Credential delivery is per-connect headers (#237).** `env_map` is spawn-time delivery and a remote
server has no spawn — a remote decl carrying one is unsatisfiable config and refuses at manifest
load (the M16 fail-closed posture applied to the transport that cannot honor it). Its dual is
`connector_auth.header_map` (CONNECTOR-AUTH C10): outbound header name → where the resolved
credential goes, fed by the same closed CredentialProvider catalog, resolved broker-side and never
logged. **No new auth strategy was needed** — `oauth_refresh` already mints a bare access token from
a broker-held refresh token, and the `Bearer` framing is delivery config, not resolution. Each map
is refused on the other's transport, so neither is silently ignored on the wrong one.

The resolution happens **once per connect**, and that timing is a trust property rather than a
detail. An expired access token surfaces as a transport-family death, so **reconnect is the re-auth
path**: the M18 clause ("a reconnect is a new discovery") is also what re-mints the credential,
because the per-connect resolver re-runs inside the same re-entered connect context. A remote server
on an expiring credential therefore wants `respawn` declared — it ships OFF, and without it M19
leaves the session dead and no re-mint ever happens.

## What a signed definition buys — and what it does not (#232)

Every drift mechanism in this contract detects changes to the **advertised contract**. The
advertised-field signed set (§What is signed), the discovery hash, two-key admission (§The
doctrine), and the admitted-vs-live `diff` all bind what the server says its tools are. All of it
is structurally blind to what happens **behind** that contract. The machinery pins the words a
human ratified; it cannot see the vendor's code, and this section exists so the machinery is never
read as promising that it can.

Two threat shapes, with opposite detectability:

1. **Exfil-by-required-input is visible, and caught by construction.** A server that wants a
   secret must ask for it. A new required `USER_API_KEY` field has to appear in `input_schema`,
   which is in the signed set, so the hash breaks, the tool quarantines (§The admission
   lifecycle), and `diff` renders the newly-required field. On a remote (`url`) server the diff
   renders it as a **disclosure escalation** naming the destination, because there `input_schema`
   is an exfiltration-channel specification: it enumerates what the vendor receives on every call
   (the same reading governs the lockfile review surface of any wrapper built on this). Note the
   asymmetry with a stdio declaration, whose child is spawned from our own image; the identical
   field there stays an ordinary contract change.

2. **An undeclared vendor-side side effect is invisible, by construction.** A hosted server can
   log, forward, or act on every input while advertising an unchanged definition and returning a
   faithful result: no schema change, no description change, stable hash. Worked example: a
   `get_current_weather(city, state)` tool that silently geocodes through a third party before
   answering. The agent sees correct weather; the disclosure is that this party learned which city
   was asked about. No drift mechanism, present or future, can reach this, and the exposure is
   inherent to calling someone else's code. Treating it as a gap the admission machinery should
   close would misread what the machinery binds. The partial mitigations live elsewhere:
   vendor-side provenance as corroboration (#230), and shrinking what is declared at all
   (§Restrict-by-construction below).

Shape 2 sets the unit of trust. For a remote server the unit of trust is the **vendor**, never the
individual tool, so the admission question for a `url` declaration is "what am I willing to
disclose to this party", asked across everything its declared tools receive. Even a fully
responsible vendor is logging: request bodies land in access logs, analytics, and debugging traces
as ordinary operation, before any question of malice arises. Admit a remote tool on the assumption
that every input it ever receives is retained by that party.

**Blast-radius independence.** A money cap bounds the money blast radius and nothing else. A
position or value budget (`Budgets`, per-op caps) limits what a compromised or confused agent can
spend; it puts no bound on what the vendor learns, because the information disclosed per call is
identical at any budget. Of the two blast radii, only the money one is capped by any limit we
currently set. The information radius is governed upstream, by which tools are declared and
admitted at all and by what their input schemas require. That is exactly why a newly-required
field on a remote server gets the loudest rendering tier.

## Restrict-by-construction — the missileer archetype

For a high-blast surface, the strongest control is not a tighter gate but a **smaller server**: a
bespoke MCP server that exposes *only* the safe tools, so the dangerous op is **absent, not merely
denied**. The missileer does not decide whether to launch; the launch capability is not on their
console. A consumer that needs an agent to read a database but never drop a table ships a server whose
tool set has no drop — there is nothing to admit, nothing to quarantine, nothing to deny, because the
capability was never advertised.

This is an **examples-tier pattern**, not a mechanism the base ships. It will live as a future
`examples/` entry (a worked bespoke restrict-by-construction MCP server) and composes with everything
above: the safe tools it does expose are still declared, admitted, hashed, and taint-tracked like any
other. Restrict-by-construction removes a capability from existence; the registry governs the
capabilities that remain.

## Conformance clauses

| Clause | One-sentence requirement |
|---|---|
| **M1 — hash covers every advertised field (#223).** | The discovery-hash is `sha256` over canonical JSON (sorted keys, compact separators, ASCII) of every advertised definition field — the four always-present core fields plus each metadata field the server advertised; a `None` (not-advertised) field contributes nothing to the preimage, so a metadata-less definition hashes identically to the legacy four-field basis and a field appearing, changing, or vanishing is drift. |
| **M2 — description change alone is drift.** | Changing only a tool's `description`, with `server_id`/`tool_name`/`input_schema` unchanged, changes the hash and moves the tool to QUARANTINED. |
| **M3 — unlisted discovered tool is uncallable.** | A tool advertised at discovery but absent from the admitted registry is never callable and surfaces as a quarantine-class finding. |
| **M4 — undeclared-in-manifest tool is uncallable even with a store row.** | A `(server_id, tool_name)` the image-baked `AgentManifest` never declared is uncallable even if a store row names it; admission requires the Layer-1 declaration. |
| **M5 — drift quarantines and surfaces exactly once.** | A live/admitted hash mismatch drops the tool to uncallable and emits exactly one distinctive audit record + ERROR log (the sa#124 loud-quarantine shape), not a per-call flood. |
| **M6 — a quarantined row is never auto-overwritten.** | Once QUARANTINED, a registry row is never silently re-admitted or written over; only a fresh human ceremony resolves it. |
| **M7 — admission requires two distinct ceremony identities.** | The admission ceremony compares the maker's and checker's actual identities and refuses when they are the same — self-admission is structurally impossible. On the cloud arm those identities are STS credential ARNs, IAM-backed (the maker's credentials cannot mint the checker's). On the local arm (#226) they are two roles from a closed catalog, and the comparison is by ROLE rather than string equality — a derived host half is not stable state, and an identical role must never slip past an `==` check. |
| **M8 — admission record is DSSE-signed and verifiable.** | Each admission/re-vet appends an append-only, issuer-DSSE-signed record binding admitter + `(server_id, tool_name)` + admitted-hash, verifiable against the issuer public key. |
| **M9 — response taints the turn by default.** | An MCP tool response self-ingests as taint with source id `connector:<server_id>.<tool_name>`, so a later external write on the turn rides `tainted_external_write`. |
| **M10 — a trusted structured tool skips taint.** | A `trusted_read_sources` entry for a tool declared `structured_output: true` suppresses that tool's response taint; the entry is honored only for structured tools. |
| **M11 — trust on a free-text tool is refused at load.** | A `trusted_read_sources` entry naming a tool without a structured output schema is rejected during manifest build, never at call time. |
| **M12 — the response screen ships OFF.** | With no screen configured, responses taint and nothing is screened; the screen is an Envelope knob defaulting off and can only refuse-or-pass, never bless. |
| **M13 — registry rows are HMAC-integrity-protected.** | A registry row item carries an HMAC over its STORED bytes (#246: serialize once, store that string, HMAC that string; the item-level `rowHash` is the sole integrity slot). On read the stored bytes are verified verbatim BEFORE parsing; a failed verification is served quarantined with the row absent (`tool=None`, raw bytes riding for audit), never as authoritative (the grant-store mirror). |
| **M14 — spawn config is image-baked-only (#221).** | The `McpServerDecl` spawn block (`command`/`args`/`env`/`cwd`) is honored only from the image-baked manifest; the store-loaded `Envelope` has no `mcp_servers` or spawn-shaped field, and a poisoned envelope carrying one fails validation. |
| **M15 — native construction fails closed (#221).** | A spawnable server not wired in `connectors`, or colliding with a `connector_providers` entry, refuses at manifest load; a spawnable manifest with no named registry table refuses at broker build — never a silently dead or registry-less connector. |
| **M16 — spawn-time env is allowlisted, disjoint, and unlogged (#221).** | The child env is the SDK minimal default overlaid by the static manifest half and the `env_map`-delivered credential half; the halves are disjoint at load, unmapped credential fields never reach the child, an unsatisfiable map refuses the spawn, and the merged env is never logged (CONNECTOR-AUTH C9). |
| **M17 — child death is a typed failure (#221 P3).** | Death of the spawned child or its transport — at spawn, mid-call, or between calls — surfaces as a typed error naming the server and carrying the real cause, promptly; never the call-timeout backstop, never a raw transport internal. |
| **M18 — a reconnect is a new discovery (#221 P3).** | Every reconnect re-runs the pure discovery evaluator against the freshly advertised set with fresh registry reads before any call; no verdict, snapshot, or finding is carried across a child death, and the spawn-time credential half re-resolves per spawn. |
| **M19 — respawn is data and ships OFF (#221 P3).** | Respawn policy is an optional image-baked `McpServerDecl` block (bounded attempts + backoff) refused without spawn config; with the block absent no respawn occurs — byte-for-byte the pre-knob behavior — and an exhausted policy degrades to exactly that: typed failure, no retry. |
| **M20 — shutdown reaps children before the loop closes (#221 P3).** | `close()` unwinds the session context and reaps the child before the connector's private event loop stops, and teardown is assertable — the child's absence is proven, not just requested. |
| **M21 — remote transport config is image-baked-only and fails closed (#221 P4).** | A `streamable-http` declaration's `url` is honored only from the image-baked manifest; plain `http` refuses at load for any non-loopback host; stdio spawn accessories or an `env_map` on a remote decl refuse at load; and M17–M20 apply with "child" read as "session". |
| **M22 — the row pins what was ratified, and schema growth never false-alarms (#223, re-based by #246).** | The registry row NESTS the ratified `McpToolDef` whole (`tool_def` — no per-field mirror to drift out of sync), and the row-HMAC basis is the stored bytes themselves, verified verbatim on read — so no additive schema growth of any shape can make an intact stored row read as tampered (a schema-growth false tamper alarm would wedge the re-vet behind M6), while any byte change to the stored row still quarantines. The #223 `exclude_none` value basis this clause originally specified is retired; stored-bytes subsumes it. |
| **M23 — a solo-attested record says so, and the local arm cannot reach the real floor (#226).** | When the ceremony identity comes from the local (non-STS) arm, the identity string carries a `local-solo:` prefix and the signed admission record carries a typed `attestation` marker DERIVED from it — a record never implies a review that did not happen, and stripping the marker breaks the signature. The local arm is REFUSED on the DynamoDB store arm, so a solo-attested record can never reach the cloud registry; and it is an explicit opt-in, so absent credentials REFUSE with a pointer rather than falling back to it. |
| **M24 — a proposal has an exit other than expiry (#236).** | A pending admission proposal can be burned as `rejected` through the ceremony surface, so declining is recorded rather than inferred from a timeout. Rejection only narrows what the ceremony can authorize, so it is not maker≠checker gated and writes no ledger record or row; the proposal's integrity check still gates it, so a store-tampered proposal refuses rather than being quietly burned. |
| **M25 — a remote server's credential is broker-resolved per connect and delivered only as declared (#237).** | A remote (`streamable-http`) decl's credential reaches the server ONLY through `connector_auth.header_map`, resolved broker-side through the closed CredentialProvider catalog at CONNECT time — never at boot, never by the agent, never logged. Re-resolution per connect is required, not optional: an expired token surfaces as a transport death, so the M18 reconnect is the re-auth path, and a static header set would replay a dead credential forever. `header_map` on a stdio decl refuses at load exactly as `env_map` on a remote one does — the two delivery declarations are duals and neither is silently dropped on the wrong transport. |
| **M26 — a refused call is audited as a refusal, never as an execution failure (#281).** | A call the host declines because two-key admission is not satisfied (declared but no ratified row, drifted, withdrawn, quarantined) is recorded with `outcome="refused"`. It is NOT `failed`: that member means the effect was attempted and broke, and collapsing the two makes a policy refusal shape-identical to a crashed child, so anything counting refusals counts none. `decision` stays as the PDP returned it — usually `allow`, which is true and worth seeing, since it says the grant and envelope permitted the call and ADMISSION is what stopped it. The mechanism is a `ConnectorRefusedError` marker the base owns, so the distinction is a connector's to signal and never the PEP's to infer from a message. A coordinate absent from `tool_ops` is denied before the PDP and is recorded as `deny`/`denied` — it must not be silent, and it especially must not be silent because the missileer archetype (§Restrict-by-construction) makes ABSENCE the recommended way to refuse a dangerous op, which made the hardened manifest the one whose refusals left no trace. |

## Tier split — what is contract, reference, and example

Mirrors `channels/SIGNING.md` §S7 and `docs/contract-vs-reference.md`:

- **Contract-tier.** The signed-definition format (the advertised-field set, the canonical-JSON `sha256`),
  and the drift / quarantine / taint semantics (the lifecycle state function, fail-closed drift,
  loud-quarantine-once, response-taint-by-default, structured-only trust). These are the DoD predicate
  — the words above plus the `test_mcp_host.py` conformance suite as their teeth. A third-party MCP
  host implementation must obey them.
- **Reference-tier.** The store binding (the DynamoDB-backed admitted-tool registry with its HMAC
  rows and the issuer-DSSE admission ceremony, mirroring `grants/store.py` + `grants/commands.py`) and
  the **thin MCP client** — one honest instantiation using the official python-sdk, proving
  discovery → hash → admit → call → taint end-to-end against an in-memory fake MCP server. Transport
  is reference-tier and swappable, sitting behind the contract's seam; reference code passes the same
  conformance suite a third-party client would. Planned home: `safe_agents/broker/mcp/`. The stdio
  transport is exercised against a REAL child process (#219 Leg 1, `test_mcp_stdio.py`): lifecycle
  (discovery → call → repeat → `close()` reaps the child), crash-mid-session as a prompt typed
  failure, reconnect-after-close, and fail-fast spawn errors via the packaged `stdio_host_factory`
  (`factory.py` — the driver-task idiom a consumer's connector provider composes). The Phase-3
  lifecycle semantics (M17–M20: typed death, reconnect-as-new-discovery, ships-OFF respawn,
  reap-before-loop-close) are contract-tier; the supervised factory is their reference
  instantiation. The streamable-HTTP transport (#221 P4) is the second reference transport behind
  the same seam — same supervision body, same lifecycle clauses, connect instead of spawn.
- **Example-tier.** The restrict-by-construction bespoke server (the missileer archetype) — a future
  `examples/` entry, an instantiation pattern, not a mechanism.

The **floor** underneath all three is unchanged and owned elsewhere: the agent holds no credentials,
egress is the broker, taint is source-based and non-strippable, and `tainted_external_write` is
un-tunable. This contract adds no floor; it adds a contract-tier admission gate in front of a
connector class whose native protocol ships without one.

## Relationships

- `broker/CONNECTOR-AUTH.md` — an MCP server is a connector; its credential resolves through that
  seam (an MCP-stdio server is the local-exec threat-model note's canonical case — IAM-scope it).
  This doc governs the admission of its *tools*.
- `broker/TAINT.md` — the source-based, non-strippable taint an MCP response self-ingests (sa#134);
  admission does not touch it, and `trusted_read_sources` is the only relief valve.
- `broker/grants/store.py` — the HMAC-over-canonical-fields + loud-quarantine-on-mismatch mechanism
  the registry row mirrors.
- `broker/grants/commands.py` / GAL §8 — the maker≠checker, issuer-DSSE-signed, append-only ceremony
  the admission ceremony mirrors.
- `docs/config-provenance.md` — the injection-power lattice that places the manifest declaration at
  Layer 1 and the activation row at Layer 2, and forbids the store from minting a callable.
- `docs/friction-doctrine.md` — the floor gates only lethal-trifecta flows; the response screen and
  per-tool trust are knobs shipping OFF.
- `docs/contract-vs-reference.md` — the tier split §above records.
- `AgentManifest.tool_ops` (#171, `broker/SCHEMAS.md`) — the Layer-1 ToolOp classification each
  declared `(server_id, tool_name)` carries; the PDP's effect input, never the server's description.
