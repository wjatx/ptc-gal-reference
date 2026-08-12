# The posture ladder — naming the posture you are on

**Status:** doctrine, written 2026-07-26. The vocabulary was ruled 2026-07-24 [ruling: maintainer]; until
now it existed only in plan files and a CLAUDE.md summary, which meant every module that deferred
to it was citing something unwritten. This document is the referent.

**A word this ladder deliberately does not use.** Its positions were called "rungs" until
2026-08-11, when that word was reserved for the *autonomy* ladder, which is normative in
`spec/GAL-SPEC.md` §4.1 and implemented in `safe_agents/broker/grants/rung.py`. Two ladders sharing
one word is a homonym a reader has no way to resolve, and the autonomy sense is the filed one, so
the posture sense moved. A position here is a **posture**: posture 1, posture 2, posture 3. See
`GLOSSARY.md` for the reservation and both ladders side by side.

It is the third doctrine lens beside [friction-doctrine.md](friction-doctrine.md) (gate-vs-log) and
[contract-vs-reference.md](contract-vs-reference.md) (what ships as what). Those two decide *what to
build*. This one decides *what you are allowed to say about what you built*.

## The problem it solves

A control that is real in one deployment is decorative in another, and the difference is usually
invisible from inside the code. The same lockfile, the same signed ledger, the same deterministic
gate: on a cloud floor with IAM identities they are separated authority; on a laptop where the agent
runs as the same OS user as the thing controlling it, several of them are conventions the agent
could step around if it tried.

Both are worth shipping. Neither is worth *misdescribing*. The failure mode is not building the
weak version — it is building the weak version and describing it in the strong version's vocabulary,
because a user who believes they have a boundary stops looking for one.

So: **every posture claim names its posture, or it is an overclaim.** The posture is the honest unit
of "how much does this actually hold".

## The three postures

The postures are about **where the boundary is**, not about how many controls are switched on.
Adding another Envelope knob does not move you up the ladder; putting the controlled thing and the
controlling thing on opposite sides of a boundary the controlled thing cannot cross does.

### Posture 1 — a local wrapper

The agent and the thing controlling it run as the **same OS user on one machine**. The controlling
thing is a wrapper: it interposes on the agent's tool calls by rewriting the harness's own
configuration to point at a gateway it owns.

**What holds.** Deterministic gating: a call is decided by a rule table, not by a model's opinion,
and the decision is the same every time for the same inputs. Taint: a turn that read something
external carries that fact forward and cannot declare it away. Audit honesty: what happened is
recorded under a separate identity from the thing that did it, and the chain is tamper-evident.
Two-key admission: a tool is callable only if a namespace declaration and a ceremony-written
activation row agree, and the agent writes neither.

**What does not hold, and must be said out loud.** *Same-user process separation is not privilege
separation.* A wrapper's authority should live outside the project tree, so that an ordinary
injected-agent edit cannot reach it: the agent writes where it normally writes, and the authority is
not there. That defeats the agent following a poisoned instruction. It does not defeat a determined
same-user adversary, who can read and write that directory, and the key files in it, exactly as
easily as the wrapper can. The distinction is the whole content of this posture.

Note what that implies about the wrapper's own protection: it depends on the *harness* refusing to
write to certain paths, and a harness's protected-path list is vendor-controlled. The wrapper cannot
extend it. So the boundary at posture 1 is one the wrapper borrows rather than one it owns.

The agent's **built-in** tools are also outside the boundary. A wrapper of this shape interposes on
tool servers; a harness's own shell, file-write and network tools are not tool servers and are not
gated by anything the wrapper does.

**What would move you up.** Not another rule. A boundary.

### Posture 2 — a local wrapper plus a sandbox

The agent runs **inside** a sandbox; the gateway runs **outside** it; the sandbox's egress allows
the gateway and the model provider and nothing else.

This is the first posture where the word "boundary" is literal. Two things change, and they are the
two that posture 1 cannot fix from the inside:

- **Built-ins are confined.** The agent's shell can still run, but it runs in a place whose reach is
  bounded by the sandbox rather than by the agent's good behaviour. The ungated-built-ins gap does
  not close by gating them; it closes by containing them.
- **Credentials are across a real boundary.** Connector credentials, the wrapper's own state, the
  issuer key and the lockfile sit outside the container. A compromised agent cannot read them
  because it is not in the same place as them, rather than because it was asked not to.

The wrapper's role here is to **orchestrate an existing boundary** (a container runtime, a
per-harness containment profile), never to implement a sandbox. The composition depends on the
gateway being reachable over HTTP as well as stdio, which is why that transport is first-class
rather than an extra.

### Posture 3 — the cloud floor

The broker runs as its **own cloud identity**, with per-capability IAM scoping, and the agent has no
credentials at all.

The distinguishing property is that an out-of-scope action is refused by the **infrastructure**
rather than by the broker: a capability's role grants exactly its declared actions on its declared
resources, so a broker bug or a broker compromise still cannot reach past the role — "the
enforcement point gets an enforcement point", proven live on `development` with out-of-scope actions
AccessDenied by IAM rather than by broker policy [#175].

This posture also gets the operator identity plane: maker≠checker on ceremonies is enforced by
comparing credential ARNs rather than by convention, and no single identity can both propose and
ratify.

## The postures are not a maturity model

You do not "graduate" from posture 1. Posture 1 is the correct posture for a developer wrapping
their own coding agent on their own laptop, and saying so plainly is the point — the alternative is
not a better posture, it is the same posture described dishonestly. Posture 2 is the recommended
hardening for anyone whose agent handles anything they would mind losing. Posture 3 is for a
deployment that already has a cloud account and an operator.

What the ladder forbids is the *unmarked* claim. "This controls which tools your agent can call" is
true at every posture and means something different at each.

## Wrap durability — a posture-1 sub-property

At posture 1 there is a second honest question, separate from what a control does when it fires: **can
the wrapped agent undo the wrap?**

A wrapper of this shape interposes by rewriting the harness's own configuration. That
configuration is a file, and the agent generally has a file-writing tool. So the durability of a
wrap is a property of the **harness**, not of the wrapper, and it differs sharply between harnesses.
It belongs in posture because a user wrapping harness A and a user wrapping harness B do not have
the same protection, and nothing else will tell them.

Four things govern any claim made on this axis. They are stated as constraints rather than as a
table of vendors, because a per-vendor ranking is exactly the artifact this section warns against:

**Every durability claim is a documentation claim until someone runs it.** Harness behaviour on this
axis is generally established by reading vendor documentation, not by observing a running binary
against an adversarial agent. A claim sourced that way should say so.

**An apparent ranking is usually a coverage artifact.** The question that decides durability is
whether the agent's **shell** can reach the configuration, routing around whatever protects it from
the file-editing tool. Some vendor docs ask that question and answer honestly; others never ask it.
A harness that looks strongest is often the one whose documentation never took the test the weakest
one failed. Publishing a flat order implies a comparison that was never made.

**It is two axes, not one.** "Does the harness protect its configuration from its own agent" and
"does the harness offer a blocking pre-tool seam" rank roughly *inversely* in practice, and a seam
whose own configuration lives in a file the agent's shell can rewrite does not protect itself. A
single ordering hides both facts.

**A co-installed harness is an escape route none of this covers.** An agent need not undo a wrap if
it can run under a second harness that reads the first one's pre-wrap tool definitions. Wrapping one
harness on a machine says nothing about the others installed beside it.

A related gap worth naming: whether an agent can edit its **own system-prompt file** is rarely
addressed by any vendor's documentation, so a claim in that direction is usually unsourced.

These are vendor behaviours in a fast-moving space. Establish the line for the harness you actually
wrap, cite what you established it from, and re-verify at integration time rather than trusting a
summary's memory.

## Audit durability — what the tape is worth, per posture

The audit tape is the architecture's payoff: "a fully compromised agent can still only ask",
demonstrated rather than asserted. So how much the tape can be *trusted* is a posture property, and
it differs by posture in a way nothing else states. `tape_cli` prints a caveat pointing here with every
verify verdict, which is why this section exists.

**The one fact that governs all three postures: the chain is unkeyed SHA-256**
[`safe_agents/broker/audit/_hash.py` — `hash_record` is a bare digest over the canonical field JSON]. An intact
chain therefore proves **self-consistency**: no record edited in place, dropped, or reordered. It is
**not** tamper-evidence, because anyone who can write the file can rewrite every record and recompute
every hash, and the result verifies clean. A test pins that limit deliberately
(`test_a_wholesale_rewrite_verifies_clean`) — its *passing* is the point.

Since the chain is unkeyed, the whole question at each posture is **who can write the tape.**

- **Posture 1 — anyone who can write the file.** `FileAuditSink` only ever appends and has no delete or
  overwrite path, but that is a property of the *writer*, not of the file. Same-user process
  separation is not privilege separation, so the agent's own file-writing tool reaches the tape. The
  honest claim is "self-consistent", never "tamper-evident".
- **Posture 2 — the broker identity alone, one pod at a time.** On a cluster the tape gets its own
  volume, read-write under the broker's ServiceAccount and **read-only in every ceremony leg**, with
  the kernel enforcing it. What that buys, exactly: **a ceremony leg cannot forge or erase another
  leg's records** — attempted and refused four ways, against a tape holding real records. What it
  does **not** buy: the broker must write the tape, so a compromised broker can still rewrite it and
  re-chain. The read-only mount *is* the control; the chain only catches an edit by someone who could
  not rewrite the rest of the file.
- **Posture 3 — off-device, and weaker than it sounds.** The cloud floor writes one S3 object per record
  under a bucket with Object Lock. Three limits must ride with that claim: it is **GOVERNANCE** mode,
  not COMPLIANCE, so an administrator holding `s3:BypassGovernanceRetention` can still delete (no role
  in this repo is granted it); the retention applies in **durable environments only** — `development`
  sets no default retention and the sink sets none per object, so nothing is locked there; and **no
  drill has ever attempted the delete**, so this is a configuration read from CDK rather than an
  observed refusal. See #333 and #334.

**Nothing here yet survives a compromised broker.** That needs an anchor the writer cannot reach —
either an in-cluster witness holding periodic chain heads on a volume the broker cannot mount, or
off-device custody — and it is **not built** (#250 Phase 7). When it is, it will buy *detection*: a
verifier holding the anchor sees that a rewrite happened. Preventing one is a different and stronger
claim, and the distinction must travel with the wording.

## Who the actor is (#165, the cheap half)

Posture and the audit surface must not say "the agent did X". The agent **asked**; the broker
**performed**, under its own identity, which is the whole point of the architecture — an agent that
holds no credentials cannot itself be the performer of anything.

The full attribution model is #165's deliverable and names five roles (subject / requester /
decider / performer / recorder). Posture's obligation is the cheap half: never collapse *requester*
into *performer* in user-facing text, because that collapse erases exactly the evidence for "a fully
compromised agent can still only ask".

## How this doc gets used

A **posture report** is the executable form: it reports which properties hold in one concrete
configuration, names the posture, and cites a code path or a vendor doc for every line. A posture line
that cannot cite is an overclaim and should be weakened to what is actually known — including all
the way down to "unknown".

The discipline is worth more than the report format: any module making a posture claim should defer
to a document like this one rather than restating the claim locally, so that the posture and the
claim cannot drift apart.
