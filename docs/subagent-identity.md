# Sub-agent identity — zones, not processes

**Status: doctrine.** This records why an agent spawning sub-agents requires no new mechanism from
the base platform — no per-sub-agent broker, no per-sub-agent airlock — and the one rule that makes
that safe: **everything inside the agent zone is the same principal.** Companion doctrine to
`turn-identity.md` (which owns *when* a turn is; this owns *who* is calling), and the precondition
for `broker/sub-grants.md` (which owns *what a second zone may hold*).

## The boxes are trust zones, not processes

The pattern is Client → Airlock → Agent → Broker → Effect. Each box is a *trust zone*, not a
process. "Agent" means *the untrusted compute zone whose only egress is the broker* — however many
processes, threads, or harness-spawned sub-agents run inside it.

Two consequences fall out immediately:

- **No per-sub-agent broker.** Egress pinning is enforced at the network layer (invariant 2), not
  per-process. A sub-agent spawned inside the zone shares the zone's host, network position, and
  sandbox, so its only egress is already the broker without anyone doing anything.
- **No per-sub-agent airlock.** The airlock is the client↔agent boundary. Sub-agents do not face
  the client; there is nothing for a second airlock to mediate.

This is also why the floor works with off-the-shelf harnesses (Claude Code's Agent tool, LangGraph,
anything): the design asks nothing of the harness. Children are spawned however the harness likes,
and the floor holds because it was never enforced in agent code to begin with. "A fully compromised
agent can still only ask" must cover a fully compromised *swarm* — and it does, because the swarm
shares the asker's identity.

## The rule: in-zone sub-agents are the parent principal, non-negotiably

The question that matters is not topology but principal identity: when a sub-agent calls the
broker, who is it? For in-zone sub-agents the answer is **the same principal as the parent**, for
two reasons:

1. **Nothing else is believable.** The broker authenticates the *zone* — its network identity (IAM
   role, mTLS cert, source subnet). Everything inside the zone shares that identity, so a claim
   like "I'm sub-agent-7, a restricted researcher" is self-reported by untrusted compute. A
   compromised parent would simply claim whichever identity has the most convenient grants.
2. **Distinct principals would reopen the turn-identity laundering hole.** Turn identity is broker-owned
   *per principal* precisely so taint cannot be shed by declaring a fresh turn
   (`turn-identity.md`). If a tainted parent could spawn a "clean" sub-agent principal to perform
   the external write, that is the same laundering with an extra step.

Sharing the principal gives the conservative merge for free: one turn, one taint state, one set of
budget counters. A sub-agent's untrusted read taints the parent's subsequent write; a fleet of
sub-agents cannot multiply a daily cap by fanning out.

## Different grants require a different zone — and the asymmetry

A sub-agent that genuinely needs *different* grants is where a new area begins, and the two
directions are not symmetric:

- **Less privilege** (e.g. a read-only researcher child). Advisory downscoping inside the zone —
  the harness passes fewer tools, the child's registry view is narrower — is worth doing as
  defense-in-depth, but it is not enforced: the broker still sees the parent's principal, so the
  child *could* ask for anything the parent can. If the downscope must hold against compromise,
  the child needs a network identity the parent cannot forge: its own sandbox, its own principal,
  its own grants. Its own *zone* — but the **same broker service**. The broker is already
  multi-principal (grants are keyed per principal × action-class); a new principal is a row, never
  a second broker instance. What that second zone's grants may then contain is
  `broker/sub-grants.md`: its strict attenuation applies once the boundary exists, and never to an
  in-zone child, where there is nothing for it to bind.
- **More privilege** than the parent: never grantable from inside the zone at all. That is a
  promotion — the human / `PromotionRecord` path — not a spawn-time argument.

## The escape hatch: spawning that leaves the zone is egress

Spawning *within* the zone is unbrokered compute — fine. Anything that creates agent execution
**outside the zone or in the future** is an effect on the world and goes through the broker as an
action-class with a grant, a rung, a budget draw, and an audit record:

- launching a cloud worker or remote job,
- scheduling a cron / deferred run,
- enqueueing work another agent will pick up.

And the spawned context **inherits the spawning turn's taint** rather than starting clean —
otherwise "spawn my future self after the read, let it do the write" launders taint through time
exactly as declaring a fresh turn once did across calls.

**How it inherits (PTC-51, #177).** The consumer marks each op that creates such a context with an
image-baked `causes_context` declaration on its `ToolOp`, naming the target: `"self"` for a
deferred run of the same principal, or the child principal spelled in full. The target comes from
that declaration and never from the call's arguments, so the agent cannot choose where its taint
goes. When the op runs, the broker writes an inheritance record keyed by the target before it
calls the connector. The record holds the causing turn's sources, the op's own source when the op
is itself an external read, the causing principal and turn, the op, and a `notAfter` fixed at
write time. Every runtime reads the live records for its own
principal whenever it mints a turn, including after a turn rollover, and ingests the sources
under a floor its own trust map cannot lift. The child presents nothing, which fits the per-zone
model above: the broker already knows which principal it serves. A held cause op that a human
releases writes the same record from the taint its hold froze, so approval does not clean the
child. A record that cannot be written stops the op; a ledger that cannot be read mints the turn
tainted. The record's shape and stores are in `broker/SCHEMAS.md`; the reading, the floor and the
fail directions are in `broker/TAINT.md` §4.1.

A sub-grant is issued only to a declared child. `compute_sub_grant` takes the causing op from the
issuing runtime's table and refuses a requested child that is not that op's declared target
(`broker/sub-grants.md`).

This covers a context the broker itself creates on the agent's behalf. It does not cover one the
broker never sees: a shell that writes a crontab, or a cloud API called with ambient credentials.
Containment closes that. Nor does it catch a declaration that names the wrong child: the record
goes where the declaration points, and a context the connector starts under a different principal
reads nothing and begins clean. A hand-off to an agent in another deployment is a channel publish, which already
carries the turn's sources in its signed chain; the ledger is shared within one deployment. Two
nearer cases are open gaps rather than covered ones: a same-zone child that starts its own broker
process begins with a clean turn (#190), and a process restart clears the live turn's own taint
(#191), though not taint it inherited from a live record.

## Base / consumer split

Base (invariant): zone = principal; in-zone identity claims are never trusted; out-of-zone /
future spawning is a brokered action-class; spawned contexts inherit taint through the
inheritance ledger, which a runtime declaring any cause op cannot run without. Consumer
(manifest and envelope): whether to run multiple enforced zones at all, which ops cover its
spawn/schedule surfaces and the `causes_context` target each one names, and any advisory in-zone
downscoping policy. Per `friction-doctrine.md`, the enforced
floor here is small — everything else is topology the consumer chooses.
