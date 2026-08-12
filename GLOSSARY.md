# Glossary

A plain-language guide to the vocabulary of this project. It's written for a reader who is
**not** an engineer — a founder or executive deciding whether to trust an AI agent with real
work — and who is tired of security that's just a well-written paragraph. Each term gives a
plain explanation first; where an engineer needs the exact meaning, a short *Precisely:* line
follows. The architecture docs (`ARCHITECTURE.md`, `broker/SCHEMAS.md`) are the technical floor
beneath this.

## The one idea, first

Most "safe AI agent" pitches are **prose-as-policy**: a document says the agent won't do
anything dangerous, and you're asked to believe it. The moment the agent is tricked — and AI
agents *can* be tricked by the very content they read — the prose is worth nothing.

This project replaces the prose with a **structure**. The agent is deliberately kept
powerless: it holds none of the keys to your real systems, and the only way it can *do*
anything in the outside world is to ask a separate, dumb, rule-following gatekeeper — the
**broker** — which decides yes or no on every single request and writes down what happened in
a tamper-evident log kept under a different lock than the agent's.

The design promise, in one line: **a completely compromised agent can still only ask.** It
never holds the ability to act; it holds the ability to request. That is the difference
between a policy you hope holds and a wall that does.

---

## Core terms

### Broker
The gatekeeper at the center of everything. The agent cannot touch your bank, your email, or
your files directly — it can only send requests to the broker, and the broker decides, one
request at a time, whether to allow it, and records the decision. Crucially the broker makes
its decisions with fixed rules, **not** with AI — so it can't be sweet-talked, confused, or
prompt-injected the way the agent can. It's the one piece of this platform we intend never to
let anyone swap out for something weaker.

*Precisely:* the deterministic tool broker. Three always-true invariants: the agent holds no
connector credentials, the agent's only egress is the broker, and the broker runs under a
separate identity than the agent. Internally: a policy-enforcement point (builds and runs the
call), a pure `decide(call, facts)` policy-decision point (no LLM), and a facts provider. See
`ARCHITECTURE.md`, `broker/README.md`.

### The broker's four jobs (PEP / PDP / PIP / PAP)
The broker isn't one blob — it's the standard, decades-old shape for "a gatekeeper that enforces
rules," borrowed from the access-control world so we're using proven vocabulary rather than
inventing our own. Four named jobs:

- **PEP — Policy Enforcement Point.** The bouncer at the door. It takes the agent's messy request
  and turns it into one clean, typed request card, then carries out whatever the decision says.
  It's the only part that actually *touches* the outside tool.
- **PDP — Policy Decision Point.** The rulebook reader. Handed the request card, it returns one of
  the five decisions. It is a **pure, deterministic function with no AI and no side effects** —
  the same request always gets the same answer — which is exactly why it can't be sweet-talked or
  prompt-injected, and why every rule it follows can be exhaustively tested.
- **PIP — Policy Information Point.** The fact-checker. It supplies the facts a decision needs that
  aren't in the request itself — is this turn tainted? how much of the budget is already spent? —
  so the PDP can decide on facts, not guesses.
- **PAP — Policy Administration Point.** Where the rules themselves are written and changed — the
  envelopes, grants, and budgets an agent is deployed with. Kept deliberately separate from the
  agent, so the thing being policed never edits its own policy.

*Precisely:* the broker's internal PEP/PDP/PIP/PAP decomposition, the standard XACML
policy-enforcement roles. `decide(call, facts)` is the pure PDP, unit-tested against a data-driven
policy table. See `broker/README.md`, `tests/README.md`.

### Floor
"The floor" is our word for **the minimum guarantees that are always on and can never be
turned off.** A building code is a floor: you may build a fancier house, but you may never go
below the code. In this project the base platform *is* a floor — the safety machinery every
agent stands on, no matter how risky or tame that agent is. You'll see the word specialized a
few ways: the **security floor** (the small set of protections that are structurally impossible
to disable), the **taint floor** and **label floor** (see *Taint* and *Trust map*), and the
infrastructure senses — the **development floor** (our experimentation environment) and the
**production floor** (a real customer's durable, hands-off environment). Same root idea each
time: the solid ground you're not allowed to dig below.

### Agent
The AI worker itself — e.g. a "Chief of Staff" agent that reads your mail, drafts replies, and
schedules things. In this project the agent is treated as **untrusted by design**: not because
it's malicious, but because it reads outside content that could trick it, so we never give it
the power to cause harm even if it's fooled. It asks; the broker acts.

---

## How the agent gets its instructions safely

### Airlock
The guarded front door for anything arriving from the outside world (an email, a message from
another system). Before a single word reaches the agent, the airlock checks: is this sender on
the allow-list? is the security token valid? have we already seen this message? does it look
like an attempt to hijack the agent? Only messages that pass every check are let through — and
even then, they're let through **marked**, not blessed (see *Taint*).

*Precisely:* the inbound channels airlock (`SafeAgents-Channels-{env}` stack), one `POST
/inbound` route in front of the reference dispatcher; every check bound from a consumer's
`ChannelsManifest`. See `channels/README.md`, `docs/channels-airlock-bringup.md`.

### Gate
One check in the airlock's fixed sequence of checks. There are **nine gates**, run in a fixed
order, and the message is dropped the instant any gate fails: verify the token, identify the
sender, check the message's shape, check it hasn't expired, check the sender is trusted, check
we haven't already handled it, **screen it for hijacking attempts** (that's gate 7, the only
gate that uses AI judgment — and it may only *refuse* or *pass a message along*, never declare
it safe), stamp it with its trust level, and hand off exactly one clean, stamped message. The
*order* is fixed by contract; how strict each gate is can be tuned per agent.

### Drain
The delivery step that carries an approved outside message the last mile to the agent — after
the airlock has cleared it. Its one important discipline: it **trusts the airlock's stamp and
adds no second opinion**, and it feeds the message's origin trail into the agent's session
*before* the agent is allowed to act on it, so the agent can never act on outside content while
"forgetting" where that content came from. (Newly built; see `channels/DRAIN.md`.)

---

## How trust and contamination are tracked

### Taint
A mark that says "this came from outside and might not be trustworthy." When the agent reads
external content, its current work session is **tainted**, and that mark has three stubborn
properties: it's decided by *where the content came from*, never by an AI guessing whether the
content "looks bad"; it **cannot be scrubbed off** once applied; and it's **written into the
permanent record**. The payoff: if a tainted session then tries to do something irreversible in
the outside world — send money, email a stranger — the broker forces a human into the loop or
refuses outright. This is the specific defense against an agent being fed poisoned instructions
and laundering them into a harmful action. No level of autonomy, not even "fully autonomous,"
lets a tainted action skip this cut.

*Precisely:* source-based, non-strippable, path-recorded taint; enforcement floor = tainted
turn + external write → `require_approval` (human reachable) or `deny`. Grant-independent. See
`broker/TAINT.md`.

### Turn
One continuous work session of the agent, within which taint accumulates. The important design
choice: the **broker** owns where a turn begins and ends — the agent can't declare itself a
"fresh, clean turn" to shake off contamination it picked up. Whoever controls the turn boundary
controls whether taint can be laundered, and we deliberately keep that control away from the
agent. See `docs/turn-identity.md`.

### Trust map
Each receiving agent's own list of which sources it considers trustworthy. Combined with the
sender's stamp, it forms a **floor**: a source is treated as untrusted if *either* the stamp
says so *or* the agent's own map doesn't vouch for it. A sender can never talk its way up in
trust by labeling its own message "trusted" — that label is a floor, never a grant.

### Lethal trifecta
The dangerous combination this whole platform exists to prevent: **hostile input + access to
secrets + an open path to the outside world**, all present at once. Any one alone is
survivable; together they're how a tricked agent does real damage. The security floor
structurally blocks that combination and this block can never be tuned off.

---

## How permission and autonomy work

### Grant
A written permission slip: "this agent may perform this *class* of action, at this level of
human oversight, and here is the named human accountable for it." Permissions live here, not in
the agent's head, and they can be tightened automatically if the agent misbehaves. A grant is
one **door on the badge** — an agent's authority is the whole set of its grants, never
all-or-nothing (see *The autonomy ladder*).

*Precisely:* per `(principal, action-class)` authority; carries the autonomy level as stored
state, the envelope hash it was granted against, the accountable owner, and demotion triggers.
See `broker/SCHEMAS.md` §Grant.

### The autonomy ladder (rungs)
How much a given agent is trusted to act on its own, pictured as a **ladder** an agent climbs
one rung at a time. There are **four rungs**:

- **Recommend** — the agent only advises; it proposes, a human does. It holds no permission to
  act in the world at all. (This is where a brand-new agent starts for any given capability, and
  where a live trading agent sits *for placing trades* today.)
- **Act with approval** *(in-loop)* — the agent may act, but a human approves each action of
  this kind before it happens.
- **Act and notify, with recall** *(on-loop)* — the agent acts on its own; a human is watching,
  is told, and can pull an action back.
- **Act within caps** *(out-of-loop)* — fully autonomous inside its envelope, no human in the
  moment.

An agent **earns** its way up the ladder through a recorded, human-approved promotion, and gets
knocked back down **automatically and without discussion** the instant something goes wrong —
"fall fast, climb slow." Two things are worth keeping straight: this ladder is about *oversight*
("how closely is a human watching"), which is **separate** from the broker's yes/no decision on
any single request; and the top three rungs are the ones written into a permission as its
autonomy **level**, while *Recommend* is a rung on the ladder but not an acting permission — an
agent there simply hasn't been granted the authority to act.

**Crucially, an agent doesn't sit on one rung — each *capability* has its own rung.** This works
exactly like an employee's building access. A datacenter worker's badge always opens the front
door, opens the server floor only after trading hours, and — most employees' badges don't open
that floor at all; once inside, they still have logins for only some of the machines; and
everyone, no matter their access, can pull the fire alarm. Nobody holds "all the keys" or "no
keys." An agent is the same: it is a bundle of per-capability grants, each on its own rung. A
live trading agent is the worked example — its market-data reads and its notifications to the owner
have climbed to autonomous, while *placing a trade* stays on the bottom rung. Asking "what rung
is the agent on?" is the wrong question; the right one is "what rung is *this action* on for
*this agent*?"

The line between *Recommend* and *Act with approval* is worth stating precisely, because it's
easy to blur: the difference is **who holds the ability to act.** At Recommend the agent holds
no grant for that action — it can't even stage it, so its advice is just text in its reply and a
human goes and does the thing. At Act-with-approval the agent *holds* the (gated) grant: it
stages a real request, the broker pauses it for a human's yes, and on approval **the broker**
carries it out. The observable tell is the audit trail — Recommend never produces a staged
action at all; Act-with-approval produces one that a human releases.

*Precisely:* the three acting rungs are the grant `level` enum (`in-loop` / `on-loop` /
`out-of-loop`); *Recommend* is the advise-only baseline below them (no acting grant; broker
default-deny). Level moves on a ratchet via recorded maker-checker promotion and deterministic
automatic demotion, with a `lastSafeLevel` floor that is never `out-of-loop`. See
`broker/grant-lifecycle.md`.

### The five decisions
Every request to the broker ends in exactly one of five outcomes: **allow** (do it), **deny**
(refuse, with a reason), **transform** (do a *safer version* instead — e.g. turn "send this
email" into "save it as a draft" — and the agent can't undo the substitution), **require
approval** (pause and wait for a human), or **abstain** (decline because the request is outside
the agent's competence or its inputs look suspect — treated as a legitimate, safe answer, not a
failure). Everything defaults to deny unless a rule says otherwise.

### Envelope
An agent's **risk boundaries, written as configuration rather than prose**: its spending caps,
its allow-lists, which actions count as reversible, how much it may read. This is where one
agent differs from another — a trading agent's envelope is tight and paranoid, a read-only
dashboard agent's is loose. The load-bearing rule: **an agent can never widen its own
envelope.** It can only ever operate inside the box it was handed.

*Precisely:* the typed per-agent risk envelope (`safe_agents/broker/schemas/envelope.py`), tied
to grants and audit records by a content hash (`compute_envelope_hash`). See `broker/SCHEMAS.md`.

### Manifest
The deployment blueprint for a specific agent — its identity, its envelope, its permitted
action classes, its budgets, and which real-world connectors it's wired to. The broker builds
an entire agent runtime from this one document, with no agent-specific assumptions baked into
the platform itself. (Note: "manifest" also refers to a separate internal catalog that
classifies each tool operation once, in code, so the agent can't misrepresent what an action
really does.)

### Connector
The broker-held wiring to a real external tool or service — Stripe, GitHub, a search API, a
notification channel. The agent never holds a connector's credentials; the broker does, and the
broker mediates every use. (An agent's own AI "brain" is not a connector — the broker guards
*actions in the world*, not the model's thinking.)

---

## The seven-plus-one contracts

The platform is held together by a fixed set of **contracts** — precise, shared shapes that
every part must fill in. There are **seven base contracts** (the shapes that are identical for
every agent, risky or tame): *Grant, BrokeredCall, Decision, Intent, AuditRecord, Budgets,* and
*PromotionRecord*. Then there's the **Envelope**, which is the per-agent configuration that
*fills in* those seven with a specific agent's risk settings. So the canonical count is **seven
base schemas plus the Envelope** — seven invariant shapes, plus the one per-agent thing that
populates them.

### Audit record
The permanent, tamper-evident log entry for every brokered decision, written under a **separate
identity** from the agent — so even a fully compromised agent cannot rewrite the record of what
it did and what it was refused. For a non-technical owner, this is the deliverable that matters
most: it's how someone you trust can answer, after the fact, "what did the agent actually do,
and what did it *try* to do that we stopped?"

---

## How the codebase is organized (for context)

### Base vs. consumer (the "per-agent split")
The **base** is this platform: the safety machinery that is *identical* whether the agent is a
high-risk trading bot or a low-risk dashboard. A **consumer** (or per-agent repo) is one actual
agent, which supplies only its *configuration* — its envelope, its trust map, its risk
settings. The rule of thumb: if a feature is the same for every agent, it belongs in the base;
if it changes with the agent's risk or domain, it belongs to the consumer. A deliberate
consequence: no single agent's business logic ever lives in the base.

### Contract-tier / reference-tier / floor / knob
Four words for *how firmly* a piece is fixed. A **floor** can never be turned off. A **knob** is
tunable per agent and usually ships off by default. A **contract** is the normative shape a part
must satisfy, with conformance tests that prove it does. A **reference** implementation is one
working example of a contract that others may replace — as long as their replacement passes the
same tests. This is what keeps "runs on my laptop" and "runs in production" honestly identical:
both are reference implementations gated on the same contract.

### The four repos
- **safe-agents** (this repo) — the independent base platform; where the safety machinery is
  built.
- **auto-agents** — the design corpus and theory (the "why"): the book, the pillars, the
  ontology.
- **A consumer agent** — a live agent; the first real example of an agent consuming this base.
- **A development harness** — a separate interactive coding environment; not a home for autonomous
  agents.

---

*This glossary is a living document; terms are added as the platform grows. For the precise,
authoritative definitions an engineer needs, follow the `Precisely:` source pointers into
`ARCHITECTURE.md`, `broker/SCHEMAS.md`, `broker/TAINT.md`, and the `channels/` and `docs/`
contract files. For the deeper "why" behind these terms — the theory, the seven pillars, and
the industry anchors each idea borrows from (the reference monitor, ABAC/XACML, the operational
design domain) — see the design corpus in the sibling **auto-agents** repository (`PILLARS.md`,
`ontology.md`).*
