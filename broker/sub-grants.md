# sub-grants — strictly-attenuating delegation

When an agent delegates work to a sub-agent, authority does not flow automatically. The broker
issues a **computed, strictly-attenuating, short-lived sub-grant**: a derived grant that can only
*narrow* the parent's authority — never widen it. This is the structural guarantee that prevents
delegation from becoming a privilege-escalation path. Source: `auto-agents/book/ch41`; see also
the seam note in `auto-agents/book/ch48` §"The seams, restated for the whole."

> **The seam:** *The sub-grant computation must strictly attenuate, or delegation leaks authority.*

## Status

The computation is built and tested: `safe_agents/broker/delegation/compute.py` derives a
`SubGrant` from a parent, refuses any widening, and `test_delegation.py` covers each attenuating
dimension. Two things are not built, and the rest of this document should be read with that in
mind (#11). No execution path issues a sub-grant: nothing in the runtime receives a delegation
request or presents a sub-grant to the broker on a call. And nothing charges a child's actions
against an ancestor's remaining budget, so siblings that each fit their own cap can jointly exceed
the parent's. Individually bounded children do not bound the set.

This is directly relevant to agents on this platform: the trading agent's daily run and responsive
Q&A flow both spawn sub-agents (groundedness checker, grader, Q&A responder). Each sub-agent must
receive a sub-grant computed from, and strictly narrower than, the parent's grant.

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

Every `BrokeredCall` emitted by a sub-agent carries a **delegation chain** — the ordered list of
principal identities from the human at the top down through each spawning agent to the current
sub-agent. The broker records this chain in the `AuditRecord` so that every sub-agent action
**attributes up the chain to the human principal**:

```
human principal
  └── parent agent (grant G)
        └── sub-agent (sub-grant SG, derived from G)
              └── BrokeredCall → AuditRecord { delegationChain: [human, parent, sub-agent] }
```

This means the audit answers "who authorized this?" with the full principal chain, not just the
immediate caller. A sub-agent action is attributed to its human principal, not laundered through
the sub-agent boundary.

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

Agents on this platform routinely spawn sub-agents: the daily advisory run delegates to a
groundedness-check sub-agent; the responsive Q&A flow delegates to a read-only Q&A worker. Without
sub-grant attenuation:

- A groundedness-check sub-agent running with the parent's full tool set could, if compromised or
  injected, attempt writes the parent is authorized for — bypassing the intent that the sub-agent
  is read-only.
- The delegation chain would be lost, so the audit couldn't trace a sub-agent action back to the
  human owner.

With strict attenuation, the sub-agent receives only what it needs for its task, and every action
it takes is audited against the full principal chain.

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
