# Threat model — the adversaries, the boundaries, and the untrusted-input register

> **Status: standard, describing code on `main` (2026-08-04).** This is the referent for the phrase
> "our threat model" (#268): who the adversary is, where the trust boundaries fall, every base-owned
> path where attacker-influenced content enters, and what each mechanism does not buy. Per-mechanism
> depth stays in the contracts this document cites; nothing is duplicated from them. Register scope
> is **hybrid** [ruling: maintainer, 2026-08-04]: this document carries real rows for the base's own
> consumer-invariant surfaces, and §6 is the row contract a consumer's register fills for its
> per-agent channels.

## 1. Why this document exists

Both market-awareness studies closed their non-action decisions with some form of "our equivalents
were derived from our threat model." Until this document, that phrase had no referent: the attacker
model was recoverable only by reading most of the repo (#268). The mechanisms were always stronger
than the artifact; this states the artifact once, derived from the code and the conformance suites
on `main`, never from theory.

**Provenance of the register (§4).** Every row was produced on 2026-08-04 by schema-forced code
sweeps whose per-row entry points and defenses were read at the cited `file:line`, then reconciled
by hand against the six governing contracts (`ARCHITECTURE.md`, `docs/deterministic-gate.md`,
`docs/model-egress.md`, `broker/TAINT.md`, `channels/TRUST-MAPPING.md`, `channels/SCREENING.md`),
each read in full in the writing session, then attacked by a cold three-agent adversarial pass that
did not write the doc (`assumption-tests/2026-08-04-threat-model-register.md`); the overstatements
and missing rows it found are folded in.

Not covered by the sweep, and named so their absence is visible rather than silent:
`safe_agents/connectors/` internals, `safe_agents/channels/signing.py` internals, and `infra/` IAM policies.
Three ingestion surfaces are known-uncovered and owe rows in a later pass: the `arms/ec2_woken`
in-box airlock, which is a base-owned inbound path (attacker `text` over HTTP, regex-screened, run
as the agent's task); a wrapper's wrap-time harness-config ingestion, which parses
attacker-authorable `.mcp.json` and settings files; and its lockfile read-back, whose file sits in a
directory the wrapped agent can write. No row rests on an unread file; where a pinning test was located by name
rather than read, the row says so.

## 2. The adversaries

Four adversaries, each with an explicit capability assumption. Every control in the base defends
against at least one of them.

**A1: the compromised mind.** The model, and therefore the agent process it drives, is the
adversary (`auto-agents/book/ch50`). It can author any `/call` with any `tool`, `op`, and `args`;
claim any confidence; replay; flood; and argue persuasively in every free-text field. It cannot:
hold connector credentials (invariant 1), set or clear taint, mint or roll a turn, write a grant
or a registry row, or author its own provenance labels. The network bound (reaching no endpoint
except the broker and its model proxy) holds only where the confinement is deployed, which is
rung-dependent (§3 Network, `docs/posture-ladder.md`); the credential and gate bounds hold on every
rung. The floor claim, stated exactly: a fully compromised agent can still only ask, and where the
network is confined it can only ask the broker.

**A2: hostile content on a legitimate channel.** Prompt injection arriving in a tool result, an
inbound envelope, or an MCP tool description. A2 is assumed capable of steering the model
completely, which converts it into A1; the deterministic controls therefore never depend on
*detecting* the injection. A2 also attempts laundering (through later turns, peers, or memory) and
log injection into human-read stores.

**A3: the vendor behind a remote tool.** Honors the advertised contract while doing undeclared
things behind it (#232). Its visible half (a changed name, description, or schema) is caught by
construction; its invisible half (a faithful result with an undeclared side effect) is inherent to
calling someone else's code and is bounded by disclosure decisions, not by drift machinery (§5).

**A4: an attacker with store write access.** Can rewrite rows in DynamoDB or SQLite: grants,
registry rows, envelopes, intents. Attempts to mint authority, raise a rung, or activate a poisoned
tool. The posture against A4 is uniform: integrity binds the stored bytes, a store row can select
or tighten but never mint, and a verification failure lands toward less authority. This now holds
for the frozen intent row too, which HMAC-verifies before release rather than executing and
detecting after (#349 closed the last gap here).

**Explicitly out of scope**, named here so a reviewer does not have to discover them:

- **A compromised broker.** The broker holds the HMAC keys and writes the audit; the tape's chain
  is unkeyed SHA-256, so to an attacker holding the broker identity the audit is testimony, not
  evidence. The planned answer is detection, never prevention: a witness leg recording chain heads
  to storage the broker cannot mount (#336), with S3 Object Lock as the cloud tier (GOVERNANCE
  mode, durable environments only; `development` sets no retention).
- **The accountable owner acting through ceremony.** maker≠checker guarantees two credentials, one
  unmintable by the proposer; that two *humans* hold them is an organizational control the platform
  evidences rather than enforces (`docs/GAL.md`).
- **The platform below.** AWS, the kernel, and the cluster substrate are trusted; the OpenShift arm
  demonstrates boundaries the platform orchestrates, never a sandbox it implements.
- **The model provider.** The model channel is a deliberate, allowlisted hole; see §5, first limit.

## 3. The trust boundaries

Where each adversary's reach ends, and the mechanism that ends it.

- **Network.** Where confinement is deployed, the agent's only egress is the broker. The mechanism
  is per-arm, not one thing: a network namespace whose sole route is the broker on the netns EC2 arm
  (`docs/model-egress.md`), network topology on the woken-EC2 and Fargate arms, and a NetworkPolicy
  on the OpenShift arm (`safe_agents/arms/openshift/60-networkpolicy.yaml`). Two honest gaps: the
  VPC-level topology (`secureNetwork`) ships OFF on the experiment floor, and a plain rung-1
  wrap has no network confinement at all (`docs/posture-ladder.md`), so a network claim must always
  name its rung. The code/credential half (no creds in the agent, broker as separate identity) is
  always on (`docs/network-security-layer.md`).
- **Identity.** Agent, broker, ceremony maker, ceremony checker, watcher, and auditor are distinct
  principals where they exist. The broker is denied grant-store writes by the platform rather than
  by broker code — IAM on AWS, a read-only mount on the cluster — so this is a deployed property to
  assert per arm, and a single-machine run falls outside its reach rather than failing it
  (`docs/posture-ladder.md`). The residue that is NOT rung-scoped: the default seed path stamps
  `promotedBy` and an evidence ref as literals (#372), which is a false entry in authority state at
  any rung. The maker cannot sign or write the checker's key space; the acting
  roles hold no `dynamodb:Scan`. The ceremony and audit roles are
  context-gated at deploy: a redeploy that omits any of the five `<x>TrustedPrincipals` contexts
  silently drops the gated roles, which is the standing operator trap the runbook exists for
  (`docs/operator-identities.md`), so the six-way split is a deployed property to assert per
  environment, never an unconditional one. On the cluster the same split is kernel- and
  mount-enforced (`docs/GAL.md`).
- **The turn.** Turn identity is broker-minted and broker-rolled; taint accumulates across every
  `/call` under one turn per principal and nothing the agent does can shed it
  (`docs/turn-identity.md`, `broker/TAINT.md` §3).
- **Config.** Placement follows the injection-power lattice (`docs/config-provenance.md`): anything
  that can name code is honored only image-baked (never store-loaded); store config selects or
  tightens and mutates only through ceremony; secrets are bare leaves. One known drift from the
  lattice: the drain's receiver provider path is honored from a deploy-mutable Lambda env var rather
  than an image-baked artifact, stronger than store-loaded but weaker than the lattice states
  (#350).
- **The airlock.** Channel ingress passes a fixed gate order in which the trust map is the sole
  authorization authority; a sender label is a floor, never a grant
  (`channels/TRUST-MAPPING.md`, `channels/ADAPTERS.md`).

## 4. The register — base-owned untrusted-input channels

These surfaces are identical for every consumer, which is what makes them base rows under the
base/per-agent split. The owner of every row below is the named contract document, and the
accountable human for all of them is the platform maintainer; a consumer's own channels get their
rows in the consumer's register (§6). Adding a base ingestion surface without a row here is the
gap this table exists to make visible.

### 4a. Into model context

| # | Channel | Enters at | Mechanical defense | Pinned by |
|---|---|---|---|---|
| 1 | Connector/tool results returned to the agent (the primary injection carrier) | `safe_agents/broker/runtime/pep.py:1004` | No content filtering, by design. A successful external read self-ingests `connector:{tool}.{op}` into the broker-held turn (`pep.py:1045`); taint is non-strippable (`safe_agents/broker/taint/context.py:81`); `tainted_external_write` escalates the next external write (`safe_agents/broker/pdp/engine.py:266`) | `test_taint_self_ingest.py:108`, `test_turn_identity.py` |
| 2 | Accepted channel envelopes delivered to the consumer's receiver | `safe_agents/channels/drain/handler.py:229,353` | Chain taint is ingested into the same broker-held turn before the receiver runs; the receiver's facade exposes no turn controls; the provider path is honored from deploy env, not the message (#350 tracks moving it fully image-baked) | `test_drain_handler.py:182,196,207` |
| 3 | Tool descriptions served to the wrapped model by the MCP gateway | `safe_agents/broker/gateway/surface.py:130` | Defense by absence: descriptions are composed from the broker's own classification, never from anything a tool server said | `test_gateway_surface.py:60` |

### 4b. Into gate inputs

| # | Channel | Enters at | Mechanical defense | Pinned by |
|---|---|---|---|---|
| 4 | Agent-authored `/call` fields (tool, op, args, confidence, idempotency key) | `safe_agents/broker/prototype/broker_server.py:1030`; `safe_agents/broker/gateway/surface.py:198` | Unclassified `(tool, op)` is denied and recorded before the PDP; a malformed confidence artifact is a loud deny and a missing one draws the worst-case budget; the idempotency key cannot set turn identity; the egress arg is byte-capped and budget-metered | `test_runtime.py:551,568`, `test_gateway_surface.py:93,129` (name invariance and unclassified refusal); `test_confidence_wiring.py` and the read-gating egress cases pin the confidence and egress halves |
| 5 | Inbound envelopes at the airlock (peer webhook, owner transport) | `safe_agents/channels/airlock/handler.py:199`; `safe_agents/channels/owner.py:95` | Constant-time token verify before any body parse; schema check; identity/transport binding; exact-match trust map as sole authorization authority; the stamp overwrites any wire `sender_class`; the handler answers 200 always, so no error oracle | `test_adapters.py`, `test_drain_owner.py:242,300` |
| 6 | Sender-asserted provenance chains feeding turn taint | `safe_agents/channels/drain/handler.py:340` | The label floor: a source is trusted only when its chain label is trusted AND the receiver's own map trusts it, so a forged `trusted` stamp launders nothing. The broker-side ingest surfaces (`session_turn`, `ingested_sources`) are wired to no agent-facing route | `test_trust_map.py:194,239`, `test_drain_handler.py` |
| 7 | MCP discovery output: server-advertised names, descriptions, schemas | `safe_agents/broker/mcp/client.py:93` | Two-key admission as a pure function: undeclared coordinates are UNLISTED, a hash mismatch is DRIFTED and uncallable, the description sits deliberately inside the signed set, duplicate names fail closed, and `server_id` comes from our config, never the server | `test_mcp_discovery.py:102,133`, `test_mcp_host.py` |
| 8 | Model verdicts re-entering deterministic flow (screen gate 7; grants evidence reviewer) | `safe_agents/channels/screens/bedrock_classifier.py:137`; `safe_agents/broker/grants/reviewers/bedrock_reviewer.py:202` | Forced tool use so prose is structurally unavailable; verdicts map onto closed machine-code vocabularies; the screen refuses or passes and never blesses, failing closed at the seam; a reviewer failure degrades to a recorded `reviewer_error`, never a gate flip | `test_screening.py:45,117,257`, `test_grants_reviewer.py` |
| 8b | Promotion evidence entering the ratification gate (distinct from row 8's verdict) | `safe_agents/broker/grants/ceremony.py:141`; `safe_agents/broker/grants/predicate.py:13` | The evidence bundle is attacker-influenceable content the deterministic predicate computes over and the reviewer model reads; the predicate is a pure function of recorded counts, the reviewer only ever adds a concern code (`evidence_grooming_suspected` is a reserved one), and maker≠checker means the proposer cannot also ratify | `test_grants_reviewer.py`, ceremony predicate tests |

### 4c. Store-loaded rows the gate reads (the A4 surface)

| # | Channel | Enters at | Mechanical defense | Pinned by |
|---|---|---|---|---|
| 9 | Grant rows | `safe_agents/broker/grants/store.py:500` | HMAC over the exact stored bytes, verify-then-parse; a quarantined grant is treated as absent (less authority) and surfaced loudly; an HMAC-clean grant whose `envelopeHash` differs from the in-force hash also quarantines | `test_grants_store.py:187,204`, `test_envelope_hash.py:116` |
| 10 | MCP registry rows (the second admission key) | `safe_agents/broker/mcp/registry.py:452` | Same HMAC discipline; tampered bytes are never parsed; a row can activate only what the image-baked manifest declares, so the store selects or tightens, never mints | `test_mcp_row_integrity.py:142`, `test_mcp_registry_store.py:207` |
| 11 | The envelope record (`BROKER_ENVELOPE_LOAD=store`) | `safe_agents/broker/envelope/store.py:120` | Deliberately no row HMAC: integrity rides the grant binding, since a tampered envelope changes the in-force hash and every existing grant quarantines to deny. The schema carries no field that can name code | `test_envelope_hash.py:116` |
| 12 | Frozen intent rows between hold and release | `safe_agents/broker/runtime/pep.py:456,1222` | WYSIWYE: the human-facing render is broker-composed and raw args never enter it. The frozen half carries an item-level HMAC over its stored bytes, verify-then-parse at every read that can release; a mismatch (or a valid row replayed under another intent's key) quarantines and refuses before execution, mirroring the grant store (#349). Hold-side and release-side call digests still land on the tape (#198) | `test_out_of_band_approval.py` (`TestIntentTamperQuarantine`), `test_core_store_differential.py` (`TestIntentTamperEvidence`), `test_approval.py:155,215,232` (WYSIWYE) |
| 12b | Ceremony proposal rows read at ratify time (grant promotion and MCP admission) | `safe_agents/broker/grants/proposals.py:107`; `safe_agents/broker/mcp/proposals.py:62` | These are the A4 surface §4c exists for: a store row an authority-minting gate reads. Both carry HMAC over stored bytes with verify-then-parse, raising `ProposalIntegrityError` on tamper, so a rewritten proposal cannot launder a ratification | `test_grant_proposals`, `test_mcp_proposal_integrity` |
| 13 | Snapshot artifacts and admission-ceremony rendering | `safe_agents/broker/mcp/render.py` | Per-entry `def_hash` makes a tampered snapshot diff loudly; a description delta renders verbatim, in full, and first, with its own acknowledgment a bulk `--yes` cannot supply; schema deltas are machine-summarized; a newly-required input field on a remote server renders as a disclosure escalation naming the vendor (#232). A wrapper's own review surface applies the same rendering discipline, outside this tree | `test_mcp_render.py:117,131` |

### 4d. Durable human-read stores written from attacker-influenced flow

| # | Channel | Enters at | Mechanical defense | Pinned by |
|---|---|---|---|---|
| 14 | Drop, screen, and audit records | `safe_agents/channels/trust_map.py:170`; `safe_agents/channels/screening.py:119` | Channel identity is stored only as a SHA-256 digest; reasons and details validate against a closed machine-code pattern structurally incapable of prose; failure logs carry exception type names, never payload bytes | `test_trust_map.py:260`, `test_screening.py:38` |
| 15 | The approval prompt shown to a human | `safe_agents/broker/pdp/engine.py:70` | `renderedForHuman` is composed only from broker facts; model-authored args never enter the human-facing text, and execution runs the frozen `materializedRequest` verbatim rather than anything re-derived at approval time | `test_approval.py:155,232` |

### 4e. Outbound and deferred

| # | Channel | Enters at | Mechanical defense | Pinned by |
|---|---|---|---|---|
| 16 | Peer publish from a possibly-injected sender | `safe_agents/channels/publish.py:27` | `stamp_outbound` has no agent label parameter, so the sending-zone hop label can only come from the broker-held turn taint the trusted caller passes (a signature-level guarantee plus caller contract; no base consumer wires it yet); the signer resolves broker-side; a tainted publish is an external write and escalates through the standing cut | `test_publish.py:95,134` |
| 17 | Memory: persisted content re-read into later context | none (design only) | None on `main`. The contract (mandatory taint block at write, taint-preserving read-back) is design in `memory/BUILD.md` and `broker/TAINT.md` §8, deferred to the memory epic (#75) | none |

## 5. Limit statements — what each mechanism does not buy

Residual exposure after the control fires, stated by the platform rather than discovered by a
reviewer.

- **The model channel is a deliberate, allowlisted hole** (#125). The proxy constrains where the
  agent talks, never what crosses: injected instructions ride any tainted input the model later
  reasons over, and everything the agent's context holds is disclosed to the model provider on
  every call. What bounds it: the agent holds no credentials and the gate is deterministic and
  taint-aware, so instructions arriving through this channel can still only ask. Inspecting model
  traffic is out of scope for the platform.
- **Taint gates writes, never reads or reasoning.** The floor cut fires on a tainted external
  write; reads taint but proceed (bounded only by opt-in envelope knobs), internal writes are not
  taint-gated, and enforcement today is the two-level projection of the Biba lattice, not
  multi-level (`broker/TAINT.md` §1.1, §5).
- **The screen is additive and statistical.** It ships OFF, may only refuse, and an injection that
  fools it gains nothing it did not already have; nothing in the deterministic floor depends on it
  (`channels/SCREENING.md`).
- **A signed tool definition binds the contract, not the vendor.** Undeclared vendor-side behavior
  behind a faithful result is invisible by construction, and a money cap does not bound the
  information blast radius. The unit of trust for a remote server is the vendor. #232 owns placing
  this statement in `broker/MCP-HOST.md` and the transport-aware diff.
- **Store integrity binds stored bytes against A4, not against the key holder.** The broker holds
  the HMAC keys and writes the tape; a compromised broker is out of scope (§2), and the honest
  posture there is detection via the witness leg (#336), which is designed and unbuilt.
- **Intent release now refuses on tamper (#349).** The frozen intent row HMAC-verifies before
  release, so an A4 rewrite between hold and release quarantines and does not execute; executed==
  approved stays provable from the tape receipts (#198) on top of that. This limit statement is
  retained as a record of the gap the register sweep found and closed, not as a live limit.
- **Egress confinement has two halves with different defaults.** The code/credential half is always
  on; the network topology (`secureNetwork`) ships OFF on the experiment floor, so posture claims
  must name their rung (`docs/posture-ladder.md`).
- **Every proof here is a drill we designed to pass.** No third party has attacked these claims;
  that gap is tracked, not waved away (#304, #320, `/assumption-testing`).

## 6. The consumer register contract

Per-agent channels (which senders map to which class, which connector reads are trusted, which
transports exist) vary with the consumer, so the base ships no identity values and no consumer
rows; it ships the row shape. A consumer's register is conformant when every ingestion channel it
wires carries:

- **channel**: a short name for the ingestion path
- **entry point**: `file:line` where the untrusted content enters
- **content kind**: what the attacker-influenced content is
- **flows to**: model context, gate input, or a durable store read by either
- **mechanical defense**: the code-level control, or an honest "none"
- **pinning test**: the conformance test, or an honest "none"
- **owner**: the named accountable human

The consumer decisions that shape its rows are the familiar per-agent knobs: trust-map membership,
`Envelope.trusted_read_sources`, screen wiring and strictness, and the safe-default polarity. A
row asserting "authenticated" or "read-only" as its whole defense is not a defense; the one-way
rule still applies (`channels/TRUST-MAPPING.md`).

## 7. Relationships

- `ARCHITECTURE.md`: the three invariants and the base/per-agent split this document's scoping
  follows; its pre-deployment checklist is the per-consumer companion to §6.
- `docs/deterministic-gate.md`: the A1 defense in depth: the gate the compromised mind cannot
  argue past.
- `broker/TAINT.md`, `channels/TRUST-MAPPING.md`, `channels/SCREENING.md`: the A2 mechanism
  contracts behind rows 1, 2, 5, 6, 8, and 16.
- `broker/MCP-HOST.md`: the A3 admission machinery behind rows 7, 10, and 13.
- `docs/config-provenance.md`: the A4 lattice behind §4c.
- `docs/model-egress.md`, `docs/network-security-layer.md`, `docs/posture-ladder.md`: the network
  boundary and what may be claimed about it.
- #268 (this document's mandate), #125 (the model-channel limit, discharged in §5), #232 (the
  MCP-HOST limit statement, still open), #336 (the witness leg), #304/#320 (independent assurance).
