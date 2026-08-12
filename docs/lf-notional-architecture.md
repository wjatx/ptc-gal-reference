# PTC & GAL: notional architecture

> For collaborators working against the `PTC` and `GAL` specifications. This document describes the
> shape of a system that implements them: the components, the boundaries between them, the two
> objects that cross those boundaries, and what happens on a single tool call. It is descriptive
> rather than normative. Where this document and a specification disagree, the specification wins.
>
> Specifications: `PTC-SPEC.md` (Provenance & Trust Context) and `GAL-SPEC.md` (Grant & Autonomy
> Lifecycle). Licensed `Community-Spec-1.0`.

## The one commitment everything else follows from

**An agent holds no credentials, and its only egress is a deterministic broker.**

Every other element here is a consequence. If the agent cannot reach a network, a filesystem, or a
credential except through a component that decides per call, then a fully compromised agent can
still only *ask*. The architecture's job is to make that sentence true and to leave evidence that it
was true.

This is a controls layer, not an agent framework. It assumes you bring your own harness: the model,
the loop, the prompts, the orchestration. Controls that live inside the harness are advice to the
component under attack, and anything a model can be talked out of is not a control. So the controls
sit outside it, under a separate identity.

## Components

| Component | Holds | Responsibility |
|---|---|---|
| **Agent** | nothing | Proposes actions. Assumed compromisable. |
| **Broker** | connector credentials, signing key | The only egress. Decides every call, stamps outbound provenance, writes audit. |
| **Gate (PDP)** | nothing durable | The pure decision function inside the broker. No model on the path. |
| **Airlock** | nothing durable | The inbound pipeline: validate, verify, trust-map, deduplicate, screen, stamp. |
| **Grant store + ledger** | authority state | Per-`(principal, action-class)` grants and the append-only record of every level change. |
| **Audit tape** | evidence | Hash-chained record of every decision, written under an identity the agent cannot reach. |
| **Tool host** | admitted tool definitions | Treats discovery as untrusted input; admits a tool only through a two-key ceremony. |
| **Ceremony CLI** | operator credentials | The only sanctioned mutation path for grants and admissions. |

The **broker cannot write the grant store** wherever a platform boundary enforces that. It is a
deliberate inversion: the component that reads authority per call is denied the ability to grant
itself any. Enforcement is by the platform (IAM policy, or a read-only mount) rather than by broker
code, so a bug in the broker does not reach it.

State the corollary plainly, because it decides how the requirement should be read: code cannot
meaningfully deny itself, so this property can only live on a boundary, which makes it a requirement
the specification places on a **conforming deployment** rather than a behaviour of broker code. A
deployment with no such boundary — a single-machine run, where the controlling process and the
controlled one are the same OS user — does not fail the requirement so much as fall outside its
reach, and has correspondingly less for it to protect. Say which rung a claim is about;
`docs/posture-ladder.md` states what each one holds.

The reference implementation's default local seed path is that case, with one part that is not
excused by rung: the grant it writes carries `promotedBy` and an evidence reference as hardcoded
literals (#372, open). Bypassing a boundary that is not there is a posture statement; recording that
a human reviewed something is a false entry in authority state at any rung.

## The two objects

**A PTC envelope** carries trust context alongside data across any boundary. It holds a **sender
class** (`owner`, `peer-agent`, `external`), an append-only **provenance chain** of hop entries, and
**taint** derived from those hops on a Biba integrity lattice. Sender class is a floor on treatment
and never a grant of content trust. Taint is derived from sources rather than judged from content,
and cannot be stripped within a turn. The chain is signed as a DSSE envelope over an in-toto-style
statement.

**A GAL grant** is authority as stored, signed state, scoped to one `(principal, action-class)` pair.
Its `level` is `in-loop`, `on-loop`, or `out-of-loop`, with the absence of a grant as the floor. The
level moves **up** only through a maker≠checker ceremony licensed by a deterministic predicate over
measured evidence, and **down** automatically on any of four deterministic triggers: stale
confidence, corroboration failure, budget breach, and an owner-flagged false action.

The level is orthogonal to the per-call decision. A gate returns one of `allow`, `deny`,
`transform`, `require_approval`, or `abstain`; the level says how much supervision the principal is
operating under. Neither is derivable from the other.

## What happens on one call

1. The agent asks the broker to perform a tool operation.
2. The broker resolves the grant for `(principal, action-class)`. No grant is a denial.
3. Facts are pre-resolved into a closed set: grant level, taint state of the current turn, budget
   counters, provenance maturity. No fact is model-derived.
4. The gate evaluates a fixed, ordered rule set over those facts, first match wins, and an unmatched
   write defaults to deny.
5. The intent is journaled to a write-ahead ledger as `uncommitted` **before** any effect. An entry
   still uncommitted at restart triggers saga compensation, so a crash mid-effect is detectable
   rather than lost.
6. On `allow`, the broker executes the call with a credential the agent never sees. On
   `require_approval`, the call is held and an approval is solicited out of band.
7. The audit record is written under the broker's identity **after** the effect, carrying a
   broker-computed digest of what the world returned, and the write-ahead entry is committed.

That ordering is worth reading twice, because "the decision is recorded before the effect" is the
intuitive design and is not this one. There are two durable records, not one. The pre-effect marker
is the write-ahead entry, whose job is that nothing can happen unobserved. The audit record is
written afterwards precisely so that it can bind a digest of the actual result — a record written
before the effect has no result to bind, and would attest to an intention rather than to what
occurred. An implementation that collapses these into a single pre-effect write gives up the effect
receipt; one that keeps only the post-effect write gives up crash detection.

8. A successful external read taints the turn. A later external write from that same turn escalates,
   because the taint rode between the two calls without the agent being able to clear it.

Turn identity is minted and owned by the broker. An agent declaring a fresh turn buys nothing.

## Inbound: the airlock

Anything arriving from outside is untrusted until mapped. The airlock runs a fixed gate order, and
the order is part of the contract rather than an implementation detail: expiry is checked before any
budget-spending gate, signature verification precedes trust mapping, deduplication precedes
screening, and the receiver **overwrites** any inbound-asserted sender class rather than trusting it.

Content screening is the one place a model may participate, and its power is deliberately shaped: it
may refuse or pass, never bless. A pass is contentless and changes nothing. A refusal carries a
closed-vocabulary machine code. It ships off by default.

## The two ceremonies

**Promotion** raises a grant's level. A proposer evaluates a deterministic predicate over measured
evidence and submits a proposal; a distinct ratifier approves it. The two must be credentials a
single operator cannot both satisfy. High-blast action classes are always human-ratified regardless
of what the predicate returns. Every level change appends a signed record to an append-only ledger.

**Admission** makes a discovered tool callable. Discovery output is untrusted input, so a tool is
callable only when the image-baked manifest declares its namespace *and* a signed registry row
activates it at a matching discovery hash. The tool's `description` is inside the signed set, because
description is model-facing injection surface: changing it alone is drift, and drift drops the tool to
uncallable.

Both ceremonies are maker≠checker. The property the platform provides is **two credentials, one of
which the proposer cannot mint**, an organizational control that the platform evidences rather than
enforces. It is not a guarantee of two humans, and no implementation should claim otherwise.

## The join between the two specifications

The pair is more than its halves because of one rule: **a capability's autonomy rung is capped by
what can currently be proven about its inputs.**

A bare taint bit permits at most trusted-sender autonomy. Unsigned lineage means approval-gated.
Only signed, receiver-verified lineage makes high-blast autonomous action eligible. PTC supplies the
proof, GAL moves the state, and the ceiling is enforced inside the promotion predicate rather than
left to a reviewer's judgment.

## Packaging: what an implementation owes

Each part of the system lands in exactly one tier, and the tier decides what a specification can
demand of it.

- **Floor.** Present in every deployment, not optional. The test is whether removing it breaks "a
  compromised agent can still only ask." The floor is deliberately small.
- **Contract.** Normative words plus conformance tests. Conformance tests are a contract's teeth; a
  contract without them is a suggestion.
- **Reference implementation.** One honest working instantiation, sitting behind the contract's seam,
  passing the same conformance tests a third party would.
- **Out of scope.** Differentiating quality that belongs to a product built on the platform.

Two consequences worth stating to anyone building against this. The **safe-default polarity**,
whether abstaining is the safe act or the harmful one, is never in the platform at any tier, because
it inverts between domains and baking it in is a latent safety bug. And the **broker is a deliberate
exception** to "contract implies swappable": the specifications define its obligations, but a
deployment that outsources the enforcement point can no longer make the platform's claims on its own
behalf.

## Deliberate non-goals

- **Transport.** MCP and A2A are adopted, not competed with. Neither specification defines a wire
  binding; the trust object rides as an MCP `_meta` field, an A2A extension, or a native channel.
- **Policy language.** The gate must be pure, deterministic, and model-free. Which language expresses
  it is an implementation choice.
- **Session-layer authentication.** Non-repudiation is placed at the message layer, because a
  signature survives relay hops that terminate a TLS session. A deployment should do both; only the
  message layer is constrained here.
- **Model quality.** Nothing here makes a model more accurate. The controls bound what a wrong or
  compromised model can cause.
