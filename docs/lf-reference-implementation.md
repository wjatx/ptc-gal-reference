# PTC & GAL: the reference implementation

> For anyone evaluating the `PTC` and `GAL` specifications who wants to know what stands behind
> them. This document states what the reference implementation supports, what it does not, and
> where its evidence stops. It is written to be probed.
>
> Specifications: `ptc-gal-standards/PTC-SPEC.md` and `ptc-gal-standards/GAL-SPEC.md`, licensed
> `Community-Spec-1.0`. The reference implementation is licensed Apache-2.0.

## What it is

`safe-agents` is a working implementation of both specifications: a deterministic tool broker, an
inbound airlock, a grant store with an append-only ceremony ledger, a hash-chained audit tape, an
MCP tool host, and the operator ceremonies that mutate authority. It runs on cloud infrastructure
and on an OpenShift cluster, and it is exercised by a live consumer agent.

The specifications were derived from it rather than drafted ahead of it. That direction has one
consequence worth stating plainly: **the specifications describe a design, not this codebase.** Where
the two diverge, the specification is the thing to build to, and the divergence is recorded rather
than smoothed over. The rest of this document is mostly a description of those divergences.

## Conformance status

**55 of 78 conformance clauses are supported. 23 are not.**

That statement is generated, never written by hand:

```
python3 -m safe_agents.contract.spec_clauses --pics-ri    # our completed statement
python3 -m safe_agents.contract.spec_clauses --pics       # the blank proforma
```

The generator extracts every clause from the specifications, reads each clause's
implementation-status marker, and derives the support answer. Deriving rather than authoring is the
control: a hand-written conformance claim drifts from the document it describes, and this one cannot,
because the answers, the markers, and the clause list all come out of the same extraction. A CI check
fails if the marked set changes without the pinned set changing with it.

The statement follows ISO/IEC 9646-7. Every clause is mandatory within its role; neither
specification defines optional clauses, so `N-A` is available only where a clause carries a
conditional predicate an implementation does not meet, and never because a capability was not built.

## How to read a marked clause

A marker is scoped to the specific requirement that is unbuilt, not to the clause. `PTC-24` reads:

> The decision function is pure, deterministic, and model-free; facts are pre-resolved into a closed
> fact set with no model-derived field; evaluation is first-match over an ordered rule set; the
> matched rule is recorded (recording the matched rule: not yet implemented — #365); unmatched
> writes default-deny.

Four of those five requirements ship. The fifth does not, and the marker names it and points at the
issue tracking the work. Marking the whole row would understate the implementation as badly as
silence overstated it.

This matters when reading the 23. Almost none is a clause where nothing was built. The dominant
shape is a compound clause conjoining several requirements where most ship and one does not, which is
precisely the shape that reads as implemented when nothing distinguishes the halves.

## What is demonstrated, and what is asserted

Demonstrated on live infrastructure, with records: a principal promoted on real approval evidence,
demoted by an induced trigger, re-climbed, and then exercised, each leg under a distinct
least-privilege identity. All four demotion triggers fired against live grants. Tool admission run
against a third-party MCP server, including the drift path where a changed description drops a tool
to uncallable. A campaign watchdog drill in which six forged events claiming a real signer's key
produced attribution placing the claimed signer nowhere in the forgery.

Asserted from code and tests, not from a live exercise: everything else, including most of the
airlock's gate ordering and the taint derivation, which are covered by unit and contract tests rather
than by drills.

## Honest limits

These are the places where a careful reader would find less than a summary implies. They are listed
because finding them yourself and finding them here should produce the same result.

**The audit chain is unkeyed.** `hash_record` is a bare SHA-256 over the record's fields, with no
key. Write access to the tape is therefore sufficient to rewrite a record and re-chain everything
after it, and the result verifies clean. What the chain detects is edits by a party who cannot
rewrite the rest of the file. The actual control is that the tape is mounted read-only to every
component except the broker's own identity, and that off-device durability is a separate mechanism.
An unkeyed chain and a chain nobody can forge look identical in a diagram, so this is worth checking
rather than assuming in any implementation.

**Write-once storage is weaker than it sounds.** Object Lock in the cloud deployment is GOVERNANCE
mode, not COMPLIANCE, and it is configured only for durable environments. The development environment
sets no default retention at all. No drill has yet attempted a delete against a locked object, so the
retention is asserted by configuration assertions rather than by an observed refusal.

**maker≠checker guarantees two credentials, not two humans.** The property provided is that the
proposer cannot mint the ratifier's credential. Whether two people stand behind those credentials is
an organizational control that the platform evidences and does not enforce. Records carry an
attestation field stating when a single operator held both roles, so the weaker case is visible
rather than hidden.

**The conformance suite does not trace to the specification.** The grant-lifecycle suite certifies an
`L1`–`L8` vocabulary drawn from an internal design document. The string `GAL-` does not appear in it.
So a green suite is evidence about that vocabulary and says nothing directly about the numbered
clauses an independent implementer reads. Bidirectional traceability, in which every conformance test
names the clause it exercises, is specified and not yet built.

**No independent party has run any of it.** Everything above was produced by the same project that
wrote the specifications. Drills are designed by the people whose work they test, which makes a green
drill evidence that the drill ran rather than evidence that the control holds. Independent execution
is tracked and open.

**The backlog is not small.** Roughly 190 issues are open, including the 23 clause gaps above. The
conformance statement is the accurate summary of what works; the issue count is the accurate summary
of what is known to be incomplete.

## Reproducing the claims

The conformance statement, the clause inventory, and the extraction self-checks run from a clean
checkout with no cloud account:

```
python3 -m safe_agents.contract.spec_clauses --summary   # 81 rows, marker state, self-checks
python3 -m pytest                                        # the full suite
```

Run `pytest` from the repository root rather than `pytest safe_agents/`: the broker packages are
4068 of the tests, and the reliability library the watcher depends on carries another 154 that the
narrower path silently skips.

The live demonstrations require deployed infrastructure and are not reproducible from a checkout
alone. That asymmetry is deliberate to note: the parts you can check yourself are the parts we make
easiest to check.

## What we would most like challenged

The claim that a fully compromised agent can still only ask. It rests on the agent holding no
credentials, on the broker being its only egress, and on the enforcement point being unable to grant
itself authority. Each of those is a separate mechanism with its own failure mode, and an attack that
composes them is worth more to us than one that defeats any single one.

Read the third leg carefully, because it is scoped in a way the sentence does not show. "The
enforcement point cannot grant itself authority" is enforced by a *platform boundary*, never by
broker code — an IAM policy denying the write on the cloud deployment, a read-only mount on the
cluster. That is not an implementation shortcut; code cannot meaningfully deny itself, so a boundary
is the only place the property can live. It follows that the leg is a property of a **deployment**,
and a single-machine run has no boundary for it to sit on. `docs/posture-ladder.md` is where each
posture states what it holds and what it does not: at the bottom posture the agent and the thing
controlling it are the same OS user, so an adversary who could exploit the broker writing grants
could equally edit the grant store directly. The control has little to buy there. Attack it at a
posture where the boundary exists, or attack the boundary.

One thing on that path is **not** posture-scoped, and we would rather you heard it from us. The default
local seed mode writes grants from inside the broker process, and the grant it writes carries
`promotedBy: "human-reviewer"` and an evidence reference as hardcoded literals, with no demotion
triggers armed (#372, open). Skipping a ceremony that has no boundary to enforce it is a posture
statement; *asserting in authority state that a human reviewed something* is a false record, and a
false record does not get cheaper at a lower posture. The fix is a posture decision we have not yet
taken; the misattribution is a defect at every posture.
