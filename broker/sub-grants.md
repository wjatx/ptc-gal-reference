# sub-grants — strictly-attenuating delegation

When an agent delegates work to a sub-agent, authority does not flow automatically. The broker
issues a **computed, strictly-attenuating, short-lived sub-grant**: a derived grant that can only
*narrow* the parent's authority — never widen it. This is the structural guarantee that prevents
delegation from becoming a privilege-escalation path. Source: `auto-agents/book/ch41`; see also
the seam note in `auto-agents/book/ch48` §"The seams, restated for the whole."

> **The seam:** *The sub-grant computation must strictly attenuate, or delegation leaks authority.*

## Precondition: a sub-grant needs a second zone

Attenuation is enforceable only across a trust-zone boundary, and most spawning does not cross one.
The broker authenticates the *zone* (workload identity, mTLS, network position), so a
harness-spawned child inside the parent's zone is the same principal as its parent: one turn, one
taint state, one budget pool. Any finer identity claim it makes is self-reported by the compute the
broker exists not to trust, so a sub-grant presented from inside the zone would be a promise rather
than a control.

An *enforced* narrower child is therefore a second zone, with an identity the parent cannot forge
and grants of its own, served by the same multi-principal broker. A second broker instance is never
the answer. Handing a harness child a narrower tool registry is still worth doing, but name it
honestly: advisory defense in depth, real friction against an honest mistake, no barrier to a
subverted child.

The asymmetry is not symmetric. Less privilege can be enforced only across a zone boundary; more
privilege can never be granted from inside one, because that is promotion rather than a spawn-time
argument.

See `docs/subagent-identity.md` for the doctrine, `auto-agents/ontology.md` §"One principal per
zone" for the compressed form, and `auto-agents/book/ch41` §"The zone question comes first" for the
full treatment.

## Status

The computation is built and tested: `safe_agents/broker/delegation/compute.py` derives a
`SubGrant` from a parent, refuses any widening, and `test_delegation.py` covers each attenuating
dimension.

**The aggregate bound is built** (#11, first half). A delegation tree shares one budget pool per
(root grant, op, period), keyed by `enforcement.store.tree_counter_key` on the root grant ID that
`delegation.keys.root_grant_id` derives. Both draw sites take it -- the inline `/call` path and the
out-of-band approval release -- and the PIP reads the same coordinate through the one helper
(`delegation/pool.py`) the PEP draws with, so the cap fact and the draw cannot key different
counters. A root charges the pool too, or "what the tree spent" would omit the root's own calls.
Depth cannot move the bound: `treePoolCap` is stamped at issuance and propagated unchanged, never
re-declared by a descendant. `test_delegation_pool.py` carries the case the review asked for --
siblings each inside their own cap, collectively over the ancestor's -- and removing the draw turns
it red while all 42 attenuation tests stay green, which is the shape the defect had.

It **ships off**: with no sub-grant store configured no pool is drawn and behaviour is unchanged,
so this is opt-in per deployment.

**Issuance is still not built** (#11, second half), and the rest of this document should be read
with that in mind. No execution path issues a sub-grant: nothing in the runtime receives a
delegation request. A sub-grant reaches the store out of band today. Note that under the per-zone
runtime model there is nothing for a sub-agent to *present* -- the broker resolves the child's
sub-grant from its own store by the principal it already authenticated, exactly as it resolves a
Grant -- so the "presents its sub-grant ID" language elsewhere in this document describes a
multi-principal runtime we do not have.

A third thing is unsettled, and it bears on who the mechanism is for. The trading agent's daily run
and responsive Q&A flow both spawn helpers (groundedness checker, grader, Q&A responder), but they
spawn them *inside* the agent's zone, where the precondition above says a sub-grant cannot be
enforced. Giving those helpers enforced sub-grants means giving each its own zone and identity
first, which is a deployment change rather than a delegation-wiring one.

---

## What attenuation means

A sub-grant is computed from a parent grant along three attenuating dimensions. All three apply
simultaneously; the computation may not widen any of them.

**1. Level — can only be equal or lower on the oversight rung.**

The sub-agent's level is set to the parent's level or a more supervised rung. A parent running
`out-of-loop` may issue a sub-grant at `out-of-loop`, `on-loop`, or `in-loop`. A parent running
`in-loop` can only issue an `in-loop` sub-grant — it cannot grant more autonomy than it holds.

**2. Tool set — can only be a subset.**

The sub-agent receives a capability-scoped tool list that is a strict subset of the parent's
granted tools. If the parent holds `email.*` and `calendar.read`, the sub-grant may carry
`calendar.read` alone — but not `payments.*` or any tool the parent doesn't hold. The
capability-scoped registry (`broker/README.md` §"Capability-scoped registry") enforces this: the
sub-agent's broker session is initialized with only the sub-granted tools; the rest do not exist
in its world.

**3. Envelope — caps, allowlists, and expiry are tighter.**

The sub-grant's envelope is computed as the intersection (tightest bound) of the parent's envelope
and any further constraints the spawning agent specifies. The spend caps in the sub-grant can only
be ≤ the parent's remaining caps. The expiry is always shorter than the parent grant's remaining
TTL. The sub-grant cannot carry a higher blast-radius limit than the parent.

---

## The delegation chain and attribution

Every `BrokeredCall` emitted by a sub-agent carries a **delegation chain**, recorded by the broker
in the `AuditRecord` so that a sub-agent action attributes up to the human who authorized the root
rather than stopping at the leaf that acted:

```
human principal
  └── parent agent (root grant G)
        └── sub-agent (sub-grant SG, derived from G)
              └── BrokeredCall → AuditRecord { delegationChain: [G, ..., SG] }
```

**The chain holds grant identifiers, not principals.** `delegation/types.py` is explicit: the
lineage runs "from the root human-owned grant ID outward through each delegation to the sub-grant
that directly authorized the call", `[root_grant_id, ..., parent_grant_id, sub_grant_id]`. An
earlier version of this document described it as a list of principal identities, which the sketch
below still shows; the Python type wins.

The distinction is load-bearing at a boundary. Grant IDs resolve to principals only for a holder of
the grant store, so a receiver outside it sees opaque strings and cannot recover on whose behalf
the action was taken. That is the single-log assumption that RFC 8693 separates with its `sub` and
`act` claims, and it is the same shape PTC answers for a single envelope by binding `principal`
into the signed statement. The chain has not had equivalent treatment. The open design question is
an attribution model that distinguishes the five roles a brokered call actually has — subject,
requester, decider, performer, recorder — rather than collapsing them into one `principal`, and
serializes the chain so a receiver can read on whose behalf an action was taken without holding the
grant store.

---

## The schema

The implemented record is `SubGrant` in `safe_agents/broker/delegation/types.py`; the shape below
is the illustrative sketch it was built from and differs in places (the implementation carries
`id`, a list `actionClasses`, a single `spendCap`, and `allowFurtherDelegation`, and has no
`toolSet` or `AttenuatedEnvelope`). Where the two disagree the Python type wins.

```ts
// Illustrative sketch; the implemented shape is types.py::SubGrant
interface SubGrant {
  // Provenance
  parentGrantId:    string              // the grant this was derived from
  delegationChain:  string[]            // [humanPrincipalId, ..., parentAgentId] — ordered, outermost first

  // Attenuated authority (all dimensions must be ≤ parent's at time of issuance)
  principal:        Principal           // the sub-agent's principal identity
  actionClass:      string              // the action class this sub-grant covers (subset of parent's)
  level:            "in-loop" | "on-loop" | "out-of-loop"  // ≤ parent's level on the oversight rung
  toolSet:          string[]            // strict subset of parent's granted tools
  envelope:         AttenuatedEnvelope  // caps and allowlists — all bounds tighter than or equal to parent's remaining
  expiry:           string              // ISO-8601 UTC; always < parent grant's remaining expiry

  // Broker bookkeeping
  issuedAt:         string              // when the broker computed this sub-grant
  issuedBy:         string              // broker identity that issued it (not the agent)
  hash:             string              // integrity hash over this record
}

interface AttenuatedEnvelope {
  spendCaps:        Record<string, number>   // per-action-class spend cap; each ≤ parent's remaining cap
  allowlists:       Record<string, string[]> // intersection of parent's allowlists with any additional narrowing
  maxBlastRadius:   number                   // ≤ parent's envelope blast-radius bound
}
```

The computation that produces a `SubGrant` from a parent `Grant` is **deterministic and
broker-side** — the spawning agent proposes a delegation scope (which tools, what level), the
broker validates and enforces the attenuation invariant, and issues the sub-grant. The agent cannot
issue a sub-grant directly; it can only request one, and the broker refuses any request that would
widen authority.

---

## Enforcement

Sub-grant attenuation is enforced at issuance, not on trust. The broker's sub-grant computation
path, as designed (steps 1 and 5, and the audit write in step 4, are the unwired parts; see
Status):

1. Receives the parent agent's delegation request (desired tool set, desired level, desired caps).
2. Intersects the requested scope against the parent grant's current authority (remaining caps,
   granted tools, current level).
3. Clamps the expiry to be shorter than the parent's remaining TTL.
4. Rejects the request if *any* attenuating dimension would widen. The rejection is logged as an
   `AuditRecord` with `outcome:"denied"` and `reason:"sub-grant-would-widen"`.
5. Issues the sub-grant and records it. The sub-agent's broker session is initialized with this
   sub-grant only.

The sub-agent's `BrokeredCall`s carry `delegationChain` automatically; the broker populates it
from the sub-grant record, not from anything the sub-agent asserts.

---

## Why this matters on this platform

The motivating case is a helper that runs in a zone of its own: an ephemeral worker provisioned for
one task, with an identity the spawning agent cannot forge. ch41's worked example is a build-fixer
orchestrator that provisions a worker to reproduce and fix a failing test, scoped to one repository
and a scratch branch, with no authority to merge. Without sub-grant attenuation:

- A worker running with the parent's full tool set could, if compromised or injected, attempt
  anything the parent is authorized for, and depth would buy it trust it has not earned.
- The delegation chain would be lost, so the audit could not trace the worker's action back to the
  human owner.

With strict attenuation the worker receives only what its task needs, and every action is audited
against the full lineage.

The in-zone helpers this platform runs today are deliberately **not** this case. They share the
agent's principal, so what bounds them is the parent's own grant plus the advisory narrowing of
their tool registry. Treating them as sub-grant holders would claim an enforcement boundary that is
not there.

---

## Where this fits in the build order

Sub-grant enforcement is part of the **autonomy ratchet** tier (`broker/README.md`
§"Minimum viable vs full") — built once an agent is graduating off "human approves every write"
and begins to spawn sub-agents with meaningful authority. For a low-risk agent where all
sub-agents are read-only and `in-loop`, the enforcement is simple (tool-set subset + expiry); the
full attenuation machinery is proportional to the blast radius of the delegated scope.

Cross-references: `SCHEMAS.md` §1 (Grant), §2 (BrokeredCall), §5 (AuditRecord);
`grant-lifecycle.md` §"The grant-store write-protection seam"; `ARCHITECTURE.md`
§"The base / per-agent split" (strictly-attenuating sub-grants listed as a base invariant).
