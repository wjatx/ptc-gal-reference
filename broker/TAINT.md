# TAINT — the broker-side taint-propagation standard

**Status: standard, describing code on `main` today.** The bookend of
the taint-completeness epic: the normative floor every consumer inherits. Where a clause
describes behavior not yet built it is marked **[deferred]** and names the epic that owns it — never
presented as current. Schemas are referenced, never duplicated (`broker/SCHEMAS.md`); per-agent
thresholds are out of scope (consumer envelope policy — `docs/friction-doctrine.md`). The
platform ships no memory subsystem, so the memory-side application of this floor is stated
directly in §8 rather than deferred to a separate standard. Code paths below are under
`safe_agents/broker/`. §1.1 adopts the **Biba integrity
lattice** as the model behind taint — the vocabulary and no-write-up rule are normative; the
full multi-level enforcement is marked **[deferred]** there.

## The problem it fixes

First-order injection: malicious content in a tool result steers the model. Second-order injection —
the target here — is that result being written to memory or passed as an argument to a *later* call
that was not itself from a tainted source, **laundering** the taint and defeating the airlock by
going around it in time. The standard closes the laundering path by making taint a property of
**where content came from**, recorded on the turn, that the agent cannot strip.

## 1. What taint is here

- **Source-based, never model-judged.** A turn's taint is fixed by the trust of its ingested sources
  through a deterministic `InputTrustMap` lookup (`taint/context.py::TurnContext.ingest_source`),
  never by any model judgment of whether content "looks malicious" (`pdp/engine.py`, rule
  `tainted_external_write`). A persuasive injection scores "safe" exactly when it is most dangerous,
  so the model is never the judge.
- **Non-strippable.** Once a `TurnContext` is tainted it cannot be un-tainted within its lifetime
  (`TurnContext._mark_tainted`; the flag has no setter, and the PEP derives every `BrokeredCall.taint`
  from `context.to_taint()`, ignoring any value the model supplies).
- **Two source families reach the turn from outside the agent.** `connector:{tool}.{op}` is a
  read the broker made itself, through a connector (§2). `harness:{harness}/{tool_class}/{locality}`
  is a read a harness made with a tool of its own (a file read, a web fetch, a web search) and
  reported to the gateway's tool-event mouth after it ran (`broker/GATEWAY.md` G21 to G29). Neither
  is an `internal:` prefix, so the base trust map treats both as untrusted, and only the consumer's
  `trusted_read_sources` can trust either.
- **Path-recorded.** The tainting sources ride on the live call (`BrokeredCall.taint.sources` /
  `session.ingestedSources`); every decision lands on the hash-chained, append-only `AuditRecord`,
  whose `argsDigest` keeps the tape PII-safe. Both fields are defined in `broker/SCHEMAS.md` (§2, §5)
  — see there, not here.

### 1.1 The integrity model — a Biba lattice (adopted)

Taint is not an ad-hoc flag: it is the enforcement projection of a classic **Biba integrity
lattice**. Naming it as one replaces informal "tainted/clean" language with a model that has a
literature, a rule, and a named hard problem — and it is deterministic all the way down (levels and
endorsements are code and config, never a model judgment; `docs/deterministic-gate.md`).

**The levels** (higher = more trusted; the confirmed vocabulary, `docs/PTC.md` §4):

```
SYSTEM  >  USER(owner)  >  AGENT(peer)  >  TOOL_OUTPUT  >  UNTRUSTED_WEB
```

These are the same tiers the rest of the platform already speaks: the channels sender classes map
onto them (`owner` → `USER`, `peer-agent` → `AGENT`, `external` → `UNTRUSTED_WEB`;
`channels/TRUST-MAPPING.md`), and a `connector:{tool}.{op}` read enters at `TOOL_OUTPUT` (untrusted
unless the consumer endorses it — below). A `harness:` read enters at the same level: it is tool
output, which the harness's own tool fetched instead of a connector.

**The rule — no write-up.** Data at integrity level *L* must not flow into an action that requires a
level *> L* without an explicit, **audited endorsement** (a logged declassification). This *is* the
`tainted_external_write` cut (§5) stated in lattice terms: content read from below the integrity
floor an external write demands cannot influence that write until a human endorses it (the escalation
to `require_approval`). The cut being grant-independent is exactly no-write-up being non-bypassable
by autonomy rung.

**Endorsement = `trusted_read_sources`, reframed as first-class audited declassification.** A
consumer placing `connector:{tool}.{op}` in `Envelope.trusted_read_sources` (§2) is asserting a
**declassification**: "raise this source's ingest above the integrity floor for this agent." This is
the classic IFC hard problem — *when* may lower-integrity data influence a privileged action — and it
is **where the bugs live** (`docs/PTC.md` §8). So it is the most-scrutinized knob we ship: every
exemption is a deterministic, per-connector-op, envelope-declared (never model- or agent-declared)
event, and it lands on the audit tape like any other decision. It endorses a *source*, never
individual content, and it can only ever *raise* an ingest's level — the lattice has no operator that
lowers `SYSTEM`/`USER` content to launder a write the other direction.

**What is built vs. the direction.** Enforcement on `main` today is the lattice's **two-level
projection**: a turn is either at-or-above the external-write integrity floor (`tainted = false`) or
below it (`tainted = true`), and the single floor is the external trust boundary (§5). The full
multi-level lattice — distinguishing `USER` from `AGENT` from `TOOL_OUTPUT` as separate rungs, and
letting an *action* declare its own minimum required level — is **[deferred]**: the adopted
*vocabulary and rule*, not yet multi-level *enforcement*. Its natural home is the signed-provenance
work (a receiver derives a hop's level from the chain; `docs/PTC.md` §9, the rung-tracks-provenance
rule) and per-action level requirements in the manifest. Named here so the model is fixed before the
spec; do not read the five levels as five enforced gates today.

## 2. How taint enters (as-built)

A **successful external `effect=read` connector call self-ingests** a synthetic source
`connector:{tool}.{op}` into the broker-held turn (`runtime/pep.py::_executor`). Because
`connector:` is not an `internal:` prefix, the base trust map always treats it as untrusted, so the
read taints the turn — with **zero** harness- or agent-supplied taint hint.

**Exception: a consumer-declared trusted source neither gates nor taints.** If
`connector:{tool}.{op}` is in the consumer's `Envelope.trusted_read_sources` (`schemas/envelope.py`),
the PEP skips the self-ingest (`if source_id not in self._trusted_read_sources`) and the PIP sets
`read_source_trusted` so the read also bypasses the rung-gate. It is **per connector-op,
consumer-declared in the envelope — never model- or agent-declared**, and one list drives both halves
(no second source of truth).

**A harness's own read, reported.** A coding harness's built-in tools never become broker calls,
so the self-ingest above never sees them. When a harness's hook reports a completed `file-read`,
`web-fetch` or `web-search` to the gateway's tool-event mouth, the runtime ingests
`harness:{harness}/{tool_class}/{locality}` into the same broker-held turn
(`runtime/pep.py::record_observed_event`), BEFORE it writes the report's record, so a failed write
leaves the turn tainted rather than clean. The same `trusted_read_sources` skip applies, by the
same exact-match lookup. The report is a claim made by a process running as the agent's user; it
can only add taint, so a forged one costs approvals and nothing else, and a report never sent
leaves the turn as it was (`broker/GATEWAY.md` G22, and its Known limits).

**A harness's own read, permitted.** When the harness's hook asks before the call runs, the broker
decides it at the reserved coordinate `harness-tool` (`broker/GATEWAY.md` G30 to G38). A permit of
`file-read`, `web-fetch` or `web-search` ingests the same `harness:{harness}/{tool_class}/{locality}`
source at the permit: after the decision is `allow`, before the `permitted` record is written, and
so before the harness runs the read (`runtime/pep.py::_harness_executor`). The same
`trusted_read_sources` skip applies. A failed record leaves the turn tainted and the answer
`refuse`. For a call the hook carries, the read taints the turn before its content can reach the
agent; a call the hook does not carry is covered only by its report, as above. A refused call
ingests nothing: the harness is not to run it.

## 3. How taint propagates — the agent cannot launder it

Taint accumulates within **one broker-held `TurnContext` per principal**, threaded across every
`/call` (`runtime/pep.py::_session_turn` / `_current_turn`). The load-bearing property:
**turn identity is broker-owned.** The turn id is broker-minted (`turn:{uuid}`), never derived from
the agent-supplied `idempotency_key` (which stays only the `enforce()` dedup/replay key). The agent
supplies **neither the turn id nor the rollover signal** — `new_turn()` is wired to no HTTP route
(the prototype serves only `/registry` and `/call`; `broker_server.py::do_POST` passes no
`turn_context`), so an agent cannot declare a fresh turn to shed taint before a write. Full rationale:
`docs/turn-identity.md`.

`connector:` and `harness:` taint land on that one turn alike, so a read the harness made with its
own tool escalates the next external write the agent asks for through the gateway exactly as a
connector read does. The tool-event mouth reaches only the add half: `record_observed_event`
ingests and never calls `new_turn()`. The turn lives in the gateway process, so a report taints
the turn of the process it reaches and no other.

## 4. What clears taint — and what cannot

**Clears (broker/harness-owned only):** a turn rollover (`new_turn()`, callable only by the trusted
loop driver that owns the runtime object), or session expiry / process restart.

**Cannot clear:** model output, a later clean read in the same turn, or anything the agent does.
There is **deliberately no taint-clearing broker API** (clearing is a human/harness action, not
a code path the agent can reach). This is the memory-side Rule 2 of §8, enforced at the turn boundary.

## 5. The escalation floor by action class

The base floor. Per-agent thresholds (which classes escalate under taint) are consumer envelope
policy layered on top, out of scope here (`docs/friction-doctrine.md`).

- **Tainted turn + external write → the structural cut.** Rule `tainted_external_write`
  (`pdp/engine.py`, predicate `taint.tainted and manifest.external and effect == "write"`) routes
  through the single polarity seam `_approval_or_deny` → `require_approval` when a human is reachable,
  **deny** when none is. It is **grant-independent**: the rule sits above the grant-level write rules
  (`in_loop_write`, `supervised_write_allow`), so **no autonomy rung — including out-of-loop — routes
  a tainted external write around it.** Per the friction doctrine this cut is floor: never tunable off.
- **No silent downgrade.** `transform_to_safer_op` is explicitly blocked on a tainted write
  (`... and not c.taint.tainted`) — a tainted write escalates; it is not quietly turned into a draft.
- **Tainted reads are allowed and audited** — they are what *taints*. Taint gates writes, not the
  read that produced it. Two exceptions a deployment opts into: with
  `Envelope.escalate_composed_destinations` on, a call that supplies its op's declared destination
  is decided as an external write (§6.1); and with `Envelope.tainted_harness_hold` listing a
  harness tool class, a harness's own call of that class is held (below).
- **Internal writes (`external=False`) are not taint-gated.** The cut is the external trust boundary;
  an internal, reversible write on a tainted turn is governed by the grant-level rules alone, under
  the same two opt-in exceptions.
- **A harness's own tool call, of a held class (opt-in, #168).** A harness's call is decided at the
  reserved coordinate `harness-tool`, op `<tool_class>/<locality>`, whose `ToolOp` facts are the
  consumer's declaration in the image-baked manifest. With `Envelope.tainted_harness_hold` listing
  the class (`shell`, say), a decision request at that class, at any locality, on a tainted turn is
  routed through the same `_approval_or_deny` seam by rule `tainted_harness_hold`, with the reason
  `tainted harness hold: the envelope holds this tool class on a tainted turn`, whatever effect and
  external the consumer declared at the coordinate. The PIP folds the knob and the coordinate into
  one fact, `Facts.harness_class_held`, so the PDP parses no op string. The rule comes after the
  rules that decide first (no grant; for a write, the error-budget and confidence rules; for a read,
  the query-egress bound; a breached capacity budget) and ahead of every rule that would allow the
  call, and ahead of the composed-destination hold and the standing cut, so its reason is the one
  on the record. Empty, the default, it is off and no decision moves; a manifest that lists a class
  no `harness-tool` entry declares is refused at load. What it does not do: it holds only a call
  the harness's hook carries to the broker, it adds no taint of its own, and a read made through
  the shell still does not taint (§2), so a turn the shell alone read from is not held by it. A
  harness's network tool needs no class-specific rule: its coordinate declares `destination_arg`
  and the composed-destination hold (§6.1) applies to it as to any op.

## 6. Read-side bounds

All knobs per the friction doctrine — real controls that **ship OFF** (unset = no bound); a consumer
opts in per agent.

- Reads **draw the shared capacity budget** (rule `cap_budget_breached`).
- **In-loop external reads rung-gate** (rule `read_rung_gate`) through the same `_approval_or_deny`
  seam, unless the source is trusted.
- **Query-egress bounds** (rule `read_query_exfil_deny`): the agent-composed egress arg
  (`ToolOp.egress_arg`, e.g. `query`) is bounded per-call (`Envelope.max_query_bytes`) and
  per-period cumulative (`Envelope.query_egress_budget`); the PEP meters the bytes that actually cross
  the wire, the PIP only reads the counter.
- **Composed-destination hold** (rule `tainted_composed_destination`, §6.1):
  `Envelope.escalate_composed_destinations` over the declared `ToolOp.destination_arg`.

Read-path order: exfil-deny → harness-tool hold and then composed-destination hold (each only with
its knob on, and never past a breached cap) → rung-gate → cap → `read_allow`.

### 6.1 What an attacker can still do through a read: request forgery

The query-egress bounds above meter how many bytes an agent sends, not where a request goes. With
the composed-destination control off, which is the default, a read on a tainted turn whose address
came from planted text is allowed like any other read (§5). The attack is this: the agent reads
text an attacker wrote, the text supplies an address, and a tool that holds network position the
attacker lacks fetches it.

**The broker does not stop request forgery inside a tool server.** A server that follows a
redirect, or resolves a name to an internal address, does so after the broker has decided. An
attacker who can steer one read can reach whatever that server can reach.

**No list of approved destinations is offered at the broker.** The broker sees an argument and
never the connection. A list checked against the argument passes the address the agent wrote and
learns nothing about the redirect or the name resolution that follows, so it would read as a
control and fail as one. The retired `Envelope.allowlists` block left room for such a list, and
that room went with it (#135).

**Containment at a boundary around the server closes the gap.** Only the component that opens the
connection, or a network boundary around it, can check where a request lands. A deployment that
needs this closed puts the tool server behind an egress boundary that names what it may reach. The
broker cannot supply that from where it sits.

**The composed-destination hold (PTC §6.4, PTC-52; #178).** A deployment that turns on
`Envelope.escalate_composed_destinations` (`schemas/envelope.py`, default off) gets this: on a
tainted turn, a call that supplies its op's declared destination argument is decided as an external
write. It routes through the same `_approval_or_deny` seam as the §5 cut, so it is held as
`require_approval` where a human is reachable and denied where none is, and the hold's
`AuditRecord.reason` reads `tainted composed destination: decided as an external write`.

- **Which argument is the destination** is declared per op as `ToolOp.destination_arg`, beside
  `egress_arg`, in the image-baked manifest's `tool_ops`. Nothing store-loaded can declare one; an
  envelope loaded from the store can only switch the control on or off. An op that declares no
  destination is never touched.
- **What "the agent composed" means here.** Every argument on a brokered call came from the agent's
  request, so on a tainted turn any destination the call supplies is one an attacker could have
  chosen. Operationally (`prototype/broker_server.py::supplies_destination`): the call composed its
  destination when its args are a mapping that contains the declared key, whatever its value, or
  are not a mapping at all (the broker cannot read them by name, so it cannot rule the destination
  out). A call with no args, or whose args omit the key, leaves the connector's own default, which
  the agent did not choose. The declaration names a top-level argument, matched as that exact key;
  one nested inside another argument is not seen, and neither is a case variant or alias the
  connector also accepts, so the declaration has to name the key the connector actually reads.
- **Where it sits.** The PIP folds the knob, the declaration and the args into one fact,
  `Facts.destination_composed`, so the PDP never reads args. Rule `tainted_composed_destination`
  comes after the rules that refuse first (no grant; for a write, the error-budget and
  confidence rules; for a read, the query-egress bound; a breached capacity budget) and before
  the in-loop rung-gate, `read_allow` and the grant-level write rules, as
  `tainted_external_write` sits before `in_loop_write`. An external write is left to the standing cut, which already holds it and keeps
  its own reason. A source in `trusted_read_sources` is held the same way: trust endorses what
  the source returns, not a destination an attacker-steered call sends it to. A held call is
  released by a human like any other hold.
- **Off, no decision moves.** With the knob off the fact is always false, so every decision, and
  every audit record's decision, reason and outcome, is what it would be without the field. The
  bytes do move, and say so. A declaration is in the runtime's table and in a stored call's bytes
  (and so in its `storedCallDigest`) whether or not the knob is on; only the control reads it. The
  knob dumps like every other envelope field, so adding it moved the hash of every envelope once
  (#178), and a grant stamped under the old hash is re-attested by `re-seed`; turning it on moves
  the hash again, as any policy change does. A manifest that switches the knob on without
  declaring any destination is refused at load, since it would hold nothing; an envelope loaded
  from the store is not checked against the table that way.
- **Why it ships off.** Switched on, it holds every step in which an agent reads a page and then
  follows a link from it.

It narrows the gap and does not close it: a planted address is held for a human, but the hold
decides on the argument. A destination a human approved can still redirect, and a name the server
resolves to an internal address is resolved after the broker has decided. Containment around the
server, above, remains the closure.

## 7. Executable acceptance

The broker-side half of the memory-taint acceptance exists as tests today (`safe_agents/broker/tests/`):

- **In-turn self-ingest** — `test_taint_self_ingest.py`:
  `test_external_read_self_taints_turn_and_escalates_next_write`, control
  `test_control_lone_notify_send_on_untainted_turn_is_allowed`.
- **Cross-`/call`, no laundering** — `test_turn_identity.py`:
  `test_external_read_taints_a_later_call_write`, `test_distinct_idempotency_keys_do_not_launder_taint`,
  `test_new_turn_clears_taint_and_only_the_broker_can_roll_it`,
  `test_multiple_reads_then_write_matches_automated_run`, control
  `test_control_untainted_cross_call_write_is_allowed`.
- **A harness's own read, reported** — `test_runtime_observed.py`:
  `test_a_read_from_outside_taints_the_turn_and_the_next_external_write_escalates`, the trusted
  pair `test_a_source_the_consumer_trusts_records_and_does_not_taint`, ingest-before-record
  `test_taint_lands_even_when_the_record_cannot_be_written`; and through a launched gateway,
  `test_gateway_events_e2e.py::test_a_reported_read_holds_the_next_external_write_over_stdio`.
- **A harness's own read, permitted**: `test_harness_decision.py::TestTaintAtThePermit`: the
  turn is tainted before the `permitted` record is appended
  (`test_a_tainting_permit_taints_the_turn_before_its_record`), a sink failure leaves it tainted and
  refuses, and a trusted source is permitted without taint.
- **Composed-destination hold (opt-in)** — `test_composed_destination.py`: what "composed" means
  (`test_supplies_destination`), the PIP fact, the decision table including precedence and the
  external writes left to the standing cut (`test_rule_decisions`), the declaration in a dump and
  the envelope hash that moves with the knob (`test_envelope_hash_off_differs_from_on`), the
  refused empty knob, the hold and its release through `build_runtime`
  (`test_on_holds_the_composed_destination_and_names_the_rule`), and
  `test_off_decides_and_records_as_without_the_field`. The exhaustive corpus pins the ON
  slice and keeps the OFF digest (`test_pdp_corpus.py::test_on_slice_moves_only_tainted_composed_points`).
- **Harness-tool hold (opt-in)** — `test_harness_tool.py`: the reserved coordinate's vocabulary
  and its refusal at load, the coordinate never served and refused before the manifest when an
  agent calls it, the PIP fact (`TestThePipFact`), the rule's decisions including its precedence
  over the other taint holds (`TestTheRule`), and the hold through `build_runtime`
  (`test_a_held_class_on_a_tainted_turn_is_held_and_names_the_rule`); through the decision mouth,
  the hold, its approval and its one release (`test_harness_decision.py::TestHoldAndRelease`). The
  exhaustive corpus pins
  its ON slice and keeps the OFF digest
  (`test_pdp_corpus.py::test_harness_on_slice_moves_only_tainted_points`).
- **Trusted-read relief + regression pair** — `test_read_gating.py`:
  `test_untrusted_read_taints_and_escalates_next_write` vs
  `test_trusted_read_does_not_taint_and_next_write_is_not_escalated` (the only difference is
  `trusted_read_sources`); the rung-gate, cap, and query-egress cases; and the seam guard
  `test_all_fallback_rules_route_through_the_single_polarity_seam`.

## 8. Deferred — memory-layer taint (memory epic)

**[deferred]** This standard **requires**, but `main` does **not yet implement**, memory as a taint
source across the write/read boundary:

1. The memory module **MUST tag every written item with taint provenance** at write time, and a read
   that surfaces a tainted item **MUST set `taint: true` on the resulting `BrokeredCall`.** The broker
   already exposes the propagation hook (`taint/context.py::TurnContext.ingest_memory_taint`); nothing
   in the broker path calls it yet — the memory layer must.
2. The memory acceptance scenario (turn 2 reads a memory item written in turn 1; turn 2's call
   carries `taint: true` with no external call of its own) **rides with the memory epic**, not this
   phase.

This platform ships no memory subsystem, and an agent standing on it brings whatever memory its
own harness provides. So the memory-side floor is stated here rather than in a standard of its
own, as **two rules** any such memory must satisfy: no high-blast action rests on a
memory-derived premise alone, and memory must never launder untrusted content into a trusted
premise.
