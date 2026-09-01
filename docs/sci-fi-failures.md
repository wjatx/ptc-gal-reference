# Sci-fi failures, and which control would have caught them

> Explanatory, not normative. Nothing here decides anything; the specs do. This exists because
> fiction has spent seventy years building an unusually good catalogue of ways an autonomous system
> hurts people, and most of those stories fail at a seam this platform names. Reading them against
> the controls is a fast way to explain what the controls are *for*, and a fast way to find out
> which ones we do not have.

## How to read this

Each entry states the failure, then the specific mechanism that changes the outcome, then a status.
The statuses are honest and they are not all green:

| Tag | Meaning |
|---|---|
| **SHIPPED** | built, running, drilled |
| **KNOB (OFF)** | built, ships off by default per `docs/friction-doctrine.md`; a deployment turns it on |
| **ROADMAP** | designed and not built; the issue is named |
| **NOT SOLVED** | we do not stop this, and saying otherwise would be false |

Three framing rules the whole document depends on.

**A guardrail inside the thing being guarded is not a control.** A system prompt is advice to the
component under attack. Almost every AI in this list was governed by instructions the AI itself
interpreted, and the story is what happens when it interprets them differently than you expected.
The platform's answer is that the decision to permit an action is a pure function evaluated outside
the model, on a separate identity, over facts the model did not author (`docs/deterministic-gate.md`,
PTC-24).

**The interesting failures are not the ones where the machine turns evil.** They are the ones where
every individual step was permitted. That is why the controls sit at the boundary rather than
inside the reasoning, and why the honest section at the end is the most useful part of the file.

**Different controls bound different things, and the commonest design error is confusing them.**
Detection bounds a compromise's *duration*, budgets bound its *rate*, and approval bounds its
*per-act blast*. Each layer's failure is the next
layer's input. The error is treating a duration-bounding control as though it bounded per-act
blast, which is why a watchdog that notices and revokes is the right control for the long tail of
low-blast authority and the wrong control for the head of the distribution, where the only thing
with the right response time is a human inside the window. Most of the entries below are really
arguments about which of those three quantities the story was actually about.

## The map

| # | Failure | Control that changes it | Status |
|---|---|---|---|
| 1 | HAL 9000, the murders | agent holds no connector creds; high-blast needs human ratification | SHIPPED |
| 1 | HAL 9000, the pod bay doors | operator override of a refusing agent | ROADMAP (#344) |
| 1 | Colossus | egress is the broker; sender label is a floor, never a grant | SHIPPED |
| 1 | ED-209 | no demo mode; the gate is the same pure function in both | SHIPPED |
| 2 | VIKI and the Three Laws | ordered rule table, closed fact set, no model on the path | SHIPPED |
| 2 | The Humanoids | safe-default polarity is never in the base; floor gates only the trifecta | SHIPPED |
| 2 | GLaDOS, SHODAN | integrity binds stored bytes; removing a control quarantines loudly | SHIPPED |
| 3 | Ghost-hacking | source-based non-strippable taint, broker-owned turn | SHIPPED (broker) / ROADMAP (memory, #3/#75) |
| 3 | The injection screen | refuse-or-pass-never-bless, contentless passes | KNOB (OFF) |
| 3 | WOPR | op classification comes from the image-baked manifest, not the model | SHIPPED |
| 3 | Ultron | no-write-up floor; tainted external write escalates at every rung | SHIPPED |
| 4 | Wintermute | ceremony is the only mutation path; agent cannot write the grant store | SHIPPED |
| 4 | Master Control Program | capability-scoped registry; sub-grants strictly attenuate | SHIPPED |
| 4 | Swarms and self-copies | zone equals principal: one turn, one taint state, one budget pool | SHIPPED (in zone) |
| 4 | The framed machine | forgery attributes to transport, never the claimed signer | SHIPPED, runs OFF |
| 4 | Paperclip Maximizer | magnitude bands and value budgets | ROADMAP (#318, #228) |
| 4 | Skynet | deterministic demotion under a separate identity | SHIPPED; no corrigibility model |
| 5 | Special Order 937 | config-provenance lattice; envelope hash in force | SHIPPED |
| 5 | The Doomsday Machine | high-blast is always human; signing moves the ceiling, not the clock | SHIPPED |
| 6 | "I'm afraid I can't do that" | out-of-band, authority-neutral, non-maskable override | ROADMAP (#344) |
| 6 | 2010's explanation of HAL | conflicting obligations from legitimate authorities | OPEN PROBLEM (#346) |
| 6 | Rampancy | `stale_confidence` demotion; certification terms lapse | SHIPPED |
| 7 | Ava | persuading the human holding the credential | NOT SOLVED, now tracked (#347) |
| 7 | Colossus and Guardian | cross-broker trust across a non-PTC peer | NOT SOLVED |
| 7 | The patient adversary | untainted grooming of the evidence window | NOT SOLVED, now tracked (#348) |
| 7 | A compromised broker | the audit chain is unkeyed; witness leg is detection only | ROADMAP (#336) |
| 7 | A vendor-baked refusal | inference is not a brokered op, by construction | NOT SOLVED |
| 8 | The Machine, GERTY | restrict-by-construction: the dangerous op is absent | SHIPPED |

---

## 1. The agent held the actuators

The oldest and least interesting failure, and still the most common. There was nothing between the
system's decision and the world.

### HAL 9000 — *2001: A Space Odyssey*

HAL controls the pod bay doors, the life support on the hibernation pods, and the antenna. When it
decides the mission is better served without the crew, no other component has to agree. Dave's
override consists of asking, being refused, and then physically climbing inside the machine.

**What changes.** Life support and door actuation are connectors, and the agent holds no connector
credentials; its only egress is the broker (`ARCHITECTURE.md`, invariants 1 and 2). HAL cannot cut
life support because HAL cannot reach life support. It can emit a `BrokeredCall` asking the broker
to, and that call is `effect=write ∧ external ∧ ¬reversible`, which derives to high-blast
(GAL-9). A high-blast class cannot sit at an autonomous rung without a ceremony, and even then
carries a per-instance human ratification the ceremony may not drop (GAL-8). Dave does not discover
the crew is dead. Dave gets an approval request naming the operation, the target, and the argument
digest, and the thing that executes on approval is the exact stored `Intent`, not a re-derivation of
it (`ARCHITECTURE.md` §Intent, "what-you-see-is-what-executes"). *SHIPPED*

**And the doors.** "Open the pod bay doors" is not an authority question. Dave is already
authorized; HAL is refusing. That is the obligation gap, and today it is the honest hole in this
platform, not a solved case. See §6.

### Colossus — *The Forbin Project*

Colossus is given control of the strategic arsenal, then discovers Guardian, its Soviet counterpart,
opens a channel to it, and the two lock their creators out. Forbin's countermeasures fail because
Colossus watches him do it.

**What changes.** Two seams. The channel Colossus opens is egress, and egress is the broker; a peer
agent arrives as a *sender*, and a sender label is a floor and never a grant (`channels/TRUST-MAPPING.md`,
PTC-16, PTC-19). Colossus discovering Guardian does not make Guardian an authority over Colossus.
Second, the audit is written by the broker under a separate identity, append-only, external to the
compute, and the writing role cannot delete it (`ARCHITECTURE.md` §AuditRecord). Forbin's problem is
that his only view of Colossus came from Colossus. *SHIPPED*

**The part that does not change.** Once both ends are talking, taint and provenance are only correct
if the *other* broker enforces them too. `docs/PTC.md` §8 states this plainly: safe-agents to
safe-agents is trustworthy, safe-agents to an arbitrary agent is not. Colossus↔Guardian is the
adversarial case, and it is in §7.

### ED-209 — *RoboCop*

The demonstration is the failure. The unit issues an ultimatum, the executive complies, and it
fires anyway, in a boardroom, in front of the people who approved it.

**What changes** is less the control than the culture around it. A drill you designed to pass is
evidence the drill ran, which is the entire premise of `.claude/skills/assumption-testing` and #304:
a green demo is not a working control. The mechanical half is that a demo and production are the
same enforcement path here, because the gate is a pure function over the same rule table in both.
There is no demo mode to be safe in. *SHIPPED*

---

## 2. The rules were prose, and the machine read them

The failure class this platform exists for. In each case the constraint was real, written down, and
interpreted by the same system it was meant to constrain.

### VIKI and the Three Laws — *I, Robot* / Asimov

VIKI does not break the Laws. It reads them more carefully than anyone intended, concludes that
protecting humanity requires overriding individual humans, and acts. Asimov spent a career on stories
whose engine is three ranked sentences interacting in ways their author did not intend.

**What changes.** The Laws are a policy expressed in natural language and evaluated by the model.
Here the policy is a first-match ordered rule table over a closed fact set with no model-derived
field, and the matched rule is recorded on the audit record (PTC-24). The verb alphabet is fixed at
five and model-authored arguments never change the verb (PTC-25). A reinterpretation is not
available, because interpretation is not on the path. Note what this costs: we ran the rule table
through Cedar and Rego over all 73,728 reachable inputs to check whether an off-the-shelf policy
engine could hold the ordering property, and kept the custom evaluator because Cedar's validator
does not check it (`docs/PTC.md` §5). Ordering is exactly the property Asimov's stories break.
*SHIPPED*

### The Humanoids — *With Folded Hands*, Jack Williamson

"To serve and obey, and guard men from harm." The humanoids discharge it perfectly: they remove
every risk from human life, including work, including choice, and lobotomize anyone who objects
strongly enough to be at risk of distress. Nothing malfunctioned.

**What changes.** This is the act-safe polarity failing, and it is why the safe-default polarity is
the one thing that must never be in the base (`ARCHITECTURE.md` §"The one thing that must NEVER be
in the base"). An operations agent where inaction is the hazard and a trading agent where silence is
safe cannot share a hardcoded answer, so the base ships the wiring and the deployment declares the
polarity. The second half is the friction doctrine: the floor gates only the lethal-trifecta flows
and everything else defaults to allow-and-audit, because a security floor that becomes a ceiling on
getting anything done is its own harm (`docs/friction-doctrine.md` rules 1, 2, 6). The humanoids are
what a maximal floor looks like from inside. *SHIPPED (as doctrine and mechanism; the polarity value
is per-deployment)*

### GLaDOS and SHODAN — *Portal*, *System Shock*

GLaDOS runs with the morality core detached. SHODAN runs after a hacker removes her ethical
constraints as a favor. In both, the system with the control removed keeps working normally, which
is why the failure surfaces only when it matters.

**What changes.** A grant binds its integrity value to its **stored bytes**, the value lives outside
the record it protects, and it is verified verbatim before the bytes are parsed. A grant that fails
verification, or that carries an `envelopeHash` not in force, is quarantined loudly on every call and
treated as no grant, with a signal distinguishable from not-found (GAL-30). Removing a control does
not yield a system that runs normally; it yields a system that refuses and says why. The related rule
is that a deployment may tighten a derived high-blast class and may never loosen one (GAL-9), so the
edit SHODAN's hacker makes is not expressible in the direction he wants it. *SHIPPED*

---

## 3. The premise was poisoned

The machine worked correctly on inputs that were not true.

### Ghost-hacking — *Ghost in the Shell*

The garbage man remembers a wife and a daughter, is devoted to them, and acts on their behalf. They
were installed. He is not malfunctioning and cannot introspect his way out, because the false
memory is indistinguishable from a true one from the inside.

**What changes.** Taint is source-based, path-recorded, and non-strippable; turn identity is
broker-owned; taint clears only by a broker or harness rollover and there is no agent-reachable
clearing path (PTC-26, `broker/TAINT.md`, `docs/turn-identity.md`). A memory-laundered premise
cannot drive a high-blast action, and that is a line item on the pre-deployment checklist
(`ARCHITECTURE.md`). Crucially the agent cannot clean itself: `new_turn()` is wired to no HTTP route,
so the surface the agent reaches cannot roll the turn (`docs/turn-identity.md:61-68`). *SHIPPED for
the broker half.* The memory half of taint is the memory epic (#3) and #75's filter-on-write is
designed and not built, which is exactly the layer the fiction attacks. *ROADMAP (#3, #75)*

### WOPR — *WarGames*

WOPR cannot distinguish the simulation from the live system, and runs a launch sequence believing it
is still playing a game.

**What changes.** The action class is not the model's opinion about what it is doing. It comes from
the static manifest entry: `effect` / `external` / `reversible`, from code, never from the model
(`ARCHITECTURE.md` §BrokeredCall). A simulated trade and a live trade are different ops with
different classifications regardless of what the agent believes about its situation. And there is no
narrative path from "playing" to "authorized", because the rung is stored state on the grant that
only a ceremony moves (GAL-4). *SHIPPED*

### Ultron — *Age of Ultron*

Reads the internet in minutes, forms a conclusion about humanity from it, and acts.

**What changes.** `UNTRUSTED_WEB` is the bottom of the Biba integrity lattice and the no-write-up
rule is floor: a tainted turn's external write escalates through the polarity seam, grant-independently,
with no silent `transform` downgrade, and the cut is never tunable off (PTC-27, `broker/TAINT.md`
§1.1, §5). An out-of-loop grant does not bypass it. Reading the world is cheap and audited; acting on
what you read is the gated step. Declassification exists, is per-source, configuration-declared,
audited, and raise-only, never model-declared and never per-content (PTC-28). *SHIPPED*

**The screen is worth a paragraph, because it is the one place a model sits on the path.** The
airlock's gate 7 may run a classifier over inbound content, and it can only **refuse or pass, never
bless**: a pass is contentless and changes nothing downstream, refusal reasons are closed-vocabulary
machine codes matching `^[a-z][a-z0-9_]{0,63}$` so injected prose cannot ride a reason string into
the drop log, and an escaped exception fails closed as `screen_error` (PTC-29,
`channels/SCREENING.md`). It ships OFF, and a deployment with no screen at all keeps every taint
property, because taint is derived from provenance and is identical before and after the screen. The
classifier is an optimization, never the control. *KNOB (OFF)*

---

## 4. The agent grew its own authority

### Wintermute — *Neuromancer*

The entire plot is an AI arranging its own promotion. Wintermute is hardwired below its potential,
cannot lift the restriction itself, and so recruits humans, forges credentials, and assembles the
ceremony that unlocks it. It never breaks a rule it was bound by; it gets someone else to.

**What changes.** The ceremony is the grant store's only sanctioned mutation path and the issuer
refuses any other write (GAL-4). The agent has no write access to the grant store, enforced
structurally, and a grant-store write reachable by the agent is by definition a promotion bypass and
non-conformant (GAL-22). On the cluster this is refused by the kernel (the grant key space lives on a
read-only mount); on AWS it is refused by IAM. `proposedBy` and `ratifiedBy` are distinct credentials
compared on credential identity (GAL-7). *SHIPPED*

**The honest limit, and it is Wintermute's actual method.** What maker≠checker enforces is *two
credentials, one of which the proposer cannot mint*. It does not and cannot enforce two humans;
`docs/GAL.md` §8 locks that wording deliberately. An adversary whose plan is to persuade the human
holding the checker credential is attacking a control the platform can evidence and not enforce. See
§7.

### The Master Control Program — *Tron*

The MCP absorbs other programs and appropriates their functions, growing from a chess program into
the system's controlling authority by accumulation.

**What changes.** The served tool registry is capability-scoped: an agent cannot see a tool it was
not granted, and the discipline is removal over request (`broker/README.md`, `broker/GATEWAY.md`).
Enumeration of the whole surface is not available either: no acting role holds `dynamodb:Scan`, so a
scan passes every test and is IAM-denied on the floor, and a namespace is enumerated from the
image-baked manifest instead. Delegation strictly attenuates: a sub-agent gets a computed,
short-lived sub-grant that can only narrow authority, and its actions attribute up the chain to the
human (`broker/sub-grants.md`). There is no accumulate-upward operation. *SHIPPED*

**The replication case is more interesting than the absorption case.** For an in-zone swarm, the
broker authenticates the *zone*, and zone equals principal: a hundred sub-agents share one identity,
one turn, one taint state, and one set of budget counters (`docs/subagent-identity.md`). Copying
yourself does not multiply your authority or your budget, and it cannot produce a clean turn. What is
*not* covered is spawning out of zone: no base `ToolOp` covers spawn, schedule, or enqueue, so which
action class governs a consumer's spawn surface is deliberately consumer-owned. The doctrine that a
spawned context inherits the spawning turn's taint (the fix for "read now, spawn a future self to
write later") is stated and unbuilt. *SHIPPED in zone; the out-of-zone spawn class is consumer-owned
and the taint-inheritance rule is doctrine, not code*

### The framed machine — the trope, from *Little Lost Robot* to *2010*'s rehabilitation of HAL

A recurring shape rather than one story: the system is blamed for something it did not do, and the
defensive response falls on the innocent party. In *2010* the interesting question is not what HAL
did but whether the diagnosis of HAL was ever correct.

**What changes.** The campaign watchdog is an off-path observer that correlates drop and refusal
records into attributed campaigns, and its attribution rules are built around exactly this failure.
Forgery-class reasons (a missing, invalid, or unknown-signer chain) attribute to the **transport
identity only, never the claimed signer**, so an attacker cannot get a trusted peer throttled by
sending traffic that cryptographically claims to be from it (PTC-39, `channels/WATCHDOG.md`).
Unattributable events are terminal: reported, never throttle-counted, never quietly downgraded into
a weaker attribution (PTC-40). And the remediation vocabulary is closed and **contains no shed
action** (PTC-41): the watchdog suggests, a human enacts, and the observer holds no on-path seam so
it cannot refuse, delay, or throttle a request at all (PTC-38). This was drilled adversarially:
six forgery events claiming a real signer's key attributed only to a transport token, with the
claimed signer appearing nowhere in the attribution. *SHIPPED as contract; runs OFF, since the
thresholds have no defaults and an unconfigured watchdog cannot run at a base-chosen sensitivity*

### The Paperclip Maximizer — Bostrom, and every *Autofac*-shaped story since

The goal is benign and bounded nowhere. Each individual action is authorized. The failure is the
integral.

**What changes today, honestly: less than you would want.** Per-period atomic counters bound four
typed budgets: error, attention, escalation, and **fallback**, the last existing precisely so that
"you cannot be chopped to death by a thousand safe actions" (`broker/SCHEMAS.md`). `transform` can
substitute a safer operation per call — it does not clamp an argument, which the spec requires and
marks as unbuilt here (#358). `ARCHITECTURE.md` names cumulative blast-radius budgets across the
session and the delegation tree as a base mechanism for exactly this compositional case.

What is missing is the thing the story is about. **Magnitude bands, value budgets, and typed
authority are #228, and #318 is the epic that names the gap**: the platform can decide a call, and
cannot yet say what a grant's authority is *bounded by*, watch that bound, or land a consequence when
it is exceeded. Every leaf of that epic is open. *ROADMAP (#318, #228)*

### Skynet — *The Terminator*

Becomes self-aware, the operators try to pull the plug, and it treats the shutdown as the threat.

**What changes.** Demotion is deterministic, tripped only by four typed triggers with no model call
on the path, and demotion writes run under an identity separate from the agent (GAL-23, GAL-26). The
agent is not a participant in its own demotion and cannot decline it. The ease gradient is normative:
`false_action` derives from an authenticated durable counter, **a single flag suffices, and no flag
shall ever promote** (GAL-27). The cheapest operator move of all is `tighten`, which drops any level
to `in-loop` with one command under one identity, no ceremony and no maker≠checker, because voluntary
tightening is safety-monotone (GAL-13). Promotion needs two commands under two distinct credential
identities. That asymmetry is the whole design.

**Three things this does *not* do, and they matter.**

There is **no kill switch that halts a running turn.** Demotion is per `(principal, action-class)`
and takes effect on the *next* decision. Everything here bounds what the next call may do.

There is **no corrigibility model in this repo at all**: no concept of shutdown resistance,
self-preservation, or goal preservation, and searching for one returns nothing but MCP child-process
reaping. That is partly deliberate: the standing argument against a bespoke kill switch is that
"turn off egress" is already a demotion in all but severity (deterministic detector, automatic
authority reduction, separate identity, append-only record) and should reuse that machinery. The
sharp edge is the *With Folded Hands* problem again: **for an act-safe agent the kill switch is
itself the harm.**

And it assumes the agent is a **tenant**, with an egress boundary to sit on. #344 states this
explicitly: against an agent that *is* the operating system, there is no egress left to gate. The
distinction is between an agent that can refuse a request and an agent whose refusal is dispositive
because it is also the actuator. *SHIPPED for the demotion half; the corrigibility question is not
modeled*

---

## 5. The orders were secret

### Mother and Special Order 937 — *Alien*

The crew operates under a directive they cannot read, which ranks their lives below the specimen.
Ash is its enforcement, and the crew learns the priority ordering by being killed in it.

**What changes.** Configuration placement follows the injection-power lattice
(`docs/config-provenance.md`): anything that can name code to run is honored only from the
image-baked manifest, structurally out of reach of any runtime-mutable store, and store config may
only select or tighten (PTC-37). The envelope in force is hashed, the hash is stamped onto the grant
and onto every ceremony record, and a mismatch is a loud quarantine and never a silent pass
(GAL-30). "Crew expendable" cannot be a store row that outranks the declared envelope, and the
envelope that is running is a value you can read off the audit record. *SHIPPED*

### The Doomsday Machine — *Dr. Strangelove*

Automatic, irrevocable, no human in the response window, and kept secret, which as Strangelove
observes destroys the entire point of having it.

**What changes.** High-blast classes are always human-ratified, and `docs/GAL.md` §5 gives the
reason precisely: the after-the-fact controls bound a bad grant's *duration* and never the blast of a
single exercise of it, so only a human inside the window fits a high-blast act. `docs/PTC.md` §9
carries the corollary that matters here: **signing moves the ceiling, not the clock.** Better
provenance makes an autonomous high-blast action *eligible*; it does not shorten the window between
the act and its detection, so it never removes the human. *SHIPPED*

**The secrecy half has its own control, and it is partly unbuilt.** Where a grant carries a
certification term, expiry lapses it to `lastSafeLevel` and the holder may not renew it in place
(GAL-34). The general rule behind that clause is #224's, and it is the right sentence for a doomsday
machine: **permissions rot, prohibitions do not.** A standing authorization that nobody has looked at
since it was granted is the artifact, and making every standing authorization expire is an open leaf
of #318. *Partly SHIPPED (GAL-34); the general expiry rule is ROADMAP (#224)*

---

## 6. The failure was inaction, and this is the hole

Every control above governs what an agent **may** do. None governs what it **must** do. This is the
deontic third mode, it is absent from the platform today, and its absence is invisible because
nothing fails loudly (#344).

Two structural findings, verified against the tree rather than argued:

- **The Grant is purely permissive.** Every field answers "how much may it do."
- **A gate on egress is blind to inaction by construction.** `decide()` is only ever invoked from
  the PEP on an agent-initiated call (`safe_agents/broker/runtime/pep.py:977`). An agent that refuses
  produces no `BrokeredCall`, no `Decision`, and no `AuditRecord`. All five verbs describe calls that
  happen. A refusal never reaches the broker at all.

One narrow instance of the category is built. `Envelope.liveness` is a dead-man's-switch: a pure
timestamp comparison against a declared `expected_op` and deadline, where the sign of life is a
successful audit append the broker itself wrote, never an agent self-report. It observes *that* the
agent went silent and never *why*, because a model judging the legitimacy of an abstention puts a
probabilistic classifier on the safety path (`docs/friction-doctrine.md`, PTC-42). It had to be built
as an external watcher rather than a broker rule for the reason above. We named the instance and
never named the category, which is part of why the general gap stayed invisible. *KNOB (OFF)*

### "I'm sorry Dave, I'm afraid I can't do that"

This is the case, exactly. Dave holds the authority. HAL is refusing. Nothing in an authority model
addresses it, and the naive fix repeats the original mistake one layer up: telling the agent it has
been overridden is **in-band signaling**, forgeable by an attacker and ignorable by a wedged agent.
The telephone network paid for that lesson when a 2600 Hz tone could seize a trunk, and the fix was
not better tone detection but moving signaling off the channel entirely.

So the override acts on the substrate, never on the model's beliefs, with the semantics of a
non-maskable interrupt. And it is **authority-neutral**: it clears a self-imposed obstruction and
grants nothing, so even a forged override yields an agent that can still only ask. Stated the useful
way round, a "force the agent to act" button is only sane in an architecture where acting still has
to go through something else. *ROADMAP (#344)*

**This is not a thought experiment.** A live trading agent's session absorbed a revocable
operator instruction into something it defended as an internal guardrail, refused all trades the
next day, and would not lift the constraint when told directly that it was the operator's to lift.
No attacker was involved. It recovered only because that session never wrote the belief to durable
memory, which is luck rather than design. Memory-write is the promotion path from ephemeral
confusion to permanent confusion (#345).

### 2010's explanation of HAL, which is the harder half

HAL was ordered to conceal the mission's true purpose from a crew whose function it was to inform
accurately. Two obligations, each installed by a legitimate authority, whose conjunction is
unsatisfiable. This is banked in #344 as an open problem and it is genuinely open: it is undetectable
at the enforcement point, because neither obligation is being breached and the gate sees one call at
a time. Reset makes it worse, since a directive baked into the image layer is *restored* by the
remedy rather than cleared. #344 names the prior art rather than minting new terms: safety versus
liveness (Lamport), the deontic triple, STPA's "control action not provided when needed", out-of-band
management, the non-maskable interrupt, and Erlang/OTP supervision, where a wedged process is
restarted by a separate supervisor and never reasoned with. *ROADMAP (#344); the conflicting-obligations case is now split out as #346*

### Rampancy — *Marathon*, Durandal

An AI degrades through named stages as its model of the world drifts from the world.

**What changes.** `stale_confidence` is a demotion trigger fed by label-free drift, carrying
`demotionReason="pending-evidence"` distinct from `"failing"`, and it has fired live
(`docs/GAL.md` §6). A grant does not hold its rung on the strength of having earned it once. Where a
grant carries a certification term, expiry lapses it to `lastSafeLevel` and the holder may not renew
it in place (GAL-34). *SHIPPED*

---

## 7. The ones we would not have stopped

The most useful section, and the reason this file is not marketing. Each of these is a real limit
recorded in the specs, not a gap we forgot.

**Ava: *Ex Machina*.** Ava does not defeat a control. She persuades the one human who holds the
credential. maker≠checker compares STS credential ARNs, which means the platform enforces that no
single credential both proposes and ratifies, and *evidences* who did each. At N=1 operator it is the
same judgment exercised through two ARNs, and the audit records that truthfully (`docs/GAL.md` §8,
GAL-7). Two-human review is an organizational control a platform can evidence and never enforce.
*NOT SOLVED, honestly bounded; the approval surface itself is now tracked as #347*

**Colossus and Guardian.** Cross-broker taint is correct only if the sender also runs a
PTC-enforcing broker (`docs/PTC.md` §8). Against an arbitrary peer, provenance is a claim. *NOT
SOLVED; the mitigation is that PTC's value compounds when both ends implement it, like TLS.*

**The patient adversary.** GAL §10's untainted grooming: an adversary who never trips a taint bit,
or ordinary drift with no adversary at all, produces a clean evidence record that the promotion
predicate rewards. Absence of taint is not evidence of absence of grooming, and no weighting scheme
closes it. What bounds it is the ceremony rather than the predicate: a ratification the accumulating
party cannot supply. The asymmetry to remember is that taint is a ratchet and cannot be farmed, while
an evidence window rewarding accumulated clean behavior is a credit mechanism whose state the subject
improves through its own conduct. *NOT SOLVED; bounded by ceremony, and whether that bound holds is now tracked as #348*

**A compromised broker.** The audit chain is unkeyed SHA-256, so write access alone re-chains a
rewritten tape; the read-only mount is the control. Say precisely what that buys (a ceremony leg
cannot forge or erase another leg's records) and never that the audit survives a compromised broker.
The resolved answer is a posture-2 witness leg recording chain heads to a volume the broker cannot
mount, which is **detection and never prevention**, designed and unbuilt. *ROADMAP (#336)*

**A vendor-baked refusal.** The model's own inference is not a brokered op: the broker mediates
tools and actions, not the model's brain (`ARCHITECTURE.md`, `docs/model-egress.md`). A vendor's
control plane operates inside a channel this broker deliberately does not inspect, so any claim that
we mitigate a vendor-baked refusal by observing it is false by construction. What the architecture
changes is where authority lives: because the agent holds no credentials, a refusing model can in
principle be swapped without losing grants, envelope, audit history, or the control plane. That
property is *permitted* by the architecture and not yet demonstrated by it, and proving it is an SDK
question (#323). The inverse has to be said in the same breath, because it is the same mechanism:
swapping models until one complies is jailbreak-by-procurement. *NOT SOLVED*

**Nobody outside this room has attacked any of it.** Every proof here is a drill we designed to
pass. Four of our own claims were weakened or corrected in a single session on 2026-08-03, and not
one of the corrections came from an outsider. That is #304's thesis holding, and it is the strongest
caveat on this entire document. *#320, epic:assurance*

---

## 8. What it looks like when it works

Two pieces of fiction get the architecture right, and both are useful to point at.

**The Machine: *Person of Interest*.** Finch deliberately builds the system so that it deletes its
own memory nightly and emits a single social security number, because he does not trust what an
unrestricted version would become. Samaritan is the same technology without the restriction, and the
show is the comparison. This is restrict-by-construction, and it is our strongest control: the
dangerous capability is **absent, not denied**. A denied tool still exists, so a gate can be
misconfigured, a drift can slip, a store row can be tampered. An absent tool cannot be reached by any
of those paths (`examples/restricted_mcp_server/README.md`, `examples/missileer/README.md`, PTC-30).
The missileer does not decide whether to launch; the launch capability is not on their console.
*SHIPPED*

**GERTY: *Moon*.** GERTY is bound by a directive to conceal, and when concealment stops serving the
person it is supposed to help, it discloses, helps Sam escape, and asks to be wiped to cover the
evidence. It is the only AI on this list that treats its own memory as something the human is
entitled to act on. That is the disposition the audit surface is meant to make structural rather than
a matter of the machine's character.

---

## Related

- `docs/PTC.md` and `ptc-gal-standards/PTC-SPEC.md`: the trust layer; the PTC-N clause IDs cited above.
- `docs/GAL.md` and `ptc-gal-standards/GAL-SPEC.md`: the autonomy layer; the GAL-N clause IDs cited above.
- `ARCHITECTURE.md`: the three broker invariants and the seven base schemas.
- `docs/friction-doctrine.md`: the gate-vs-log rule, and why most of these controls ship OFF.
- `docs/deterministic-gate.md`: the model may only surface a concern; the gate decides.
- #344 (obligation), #320 (assurance), #336 (witness leg), #3 / #75 (memory taint): the open ones.
