# Sub-agent identity — zones, not processes

**Status: doctrine.** This records why an agent spawning sub-agents requires no new mechanism from
the base platform — no per-sub-agent broker, no per-sub-agent airlock — and the one rule that makes
that safe: **everything inside the agent zone is the same principal.** Companion doctrine to
`turn-identity.md` (which owns *when* a turn is; this owns *who* is calling).

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
2. **Distinct principals would reopen the sa#136 laundering hole.** Turn identity is broker-owned
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
  a second broker instance.
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

## Base / consumer split

Base (invariant): zone = principal; in-zone identity claims are never trusted; out-of-zone /
future spawning is a brokered action-class; spawned contexts inherit taint. Consumer (envelope):
whether to run multiple enforced zones at all, which action-classes cover its spawn/schedule
surfaces, and any advisory in-zone downscoping policy. Per `friction-doctrine.md`, the enforced
floor here is small — everything else is topology the consumer chooses.
