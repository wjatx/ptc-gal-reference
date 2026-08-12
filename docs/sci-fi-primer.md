# What science fiction got right about AI, and what we are proposing to do about it

*A plain-language companion to the PTC and GAL proposals. No background assumed.*

Science fiction has spent seventy years imagining ways an artificial mind hurts the people around
it. The stories are better engineering documents than they get credit for, because the good ones
rarely turn on a machine becoming evil. They turn on a machine doing exactly what it was told, by
someone who did not think through what they were telling it, with nothing standing between its
conclusion and the world.

That last clause is the whole subject. This piece walks through films and books you probably
already know, and for each one names the specific thing that was missing. Two proposals come out of
those gaps, and they are what we are asking people to review.

---

## The one idea everything rests on

**The agent asks. Something else decides.**

In most AI systems being built today, the model that decides what to do is also the thing that does
it. It holds the API keys. It sends the email, places the order, runs the command. If you want to
constrain it, you write the constraints into its instructions, which means the rules live inside the
thing the rules are meant to bind. Anything a model can be argued out of is not a control. It is
advice offered to the component under attack.

The alternative is to move the decision out. The agent holds no credentials at all and cannot reach
anything directly. Every action it wants to take becomes a *request* to a separate piece of
infrastructure running under a separate identity, which decides, then acts on the agent's behalf and
writes down what happened. The useful property is what this does to the worst case. An agent that
has been completely taken over, whose every instruction now comes from an attacker, can still only
ask.

From there, one more idea. How much freedom the agent gets is not a single setting for the whole
agent. It is set per kind-of-action, and it moves. Four positions, from most supervised to least:

| Rung | What it means |
|---|---|
| **Recommend** | The agent can only suggest. It holds no authority here at all. |
| **In loop** | A human approves each individual action before it happens. |
| **On loop** | The agent acts, a human is watching and can intervene. |
| **Out of loop** | The agent acts on its own within declared limits. |

An agent can sit at different rungs for different things at the same time. It might book meetings
unsupervised while every payment it wants to make waits for a person. That is the shape most of these
stories needed.

---

## The two proposals, in a paragraph each

**PTC (Provenance and Trust Context)** answers *where did this come from, and what is it allowed to
influence?* Every piece of information an agent takes in carries a record of its origin that travels
with it and cannot be removed by the agent. Content pulled off the open web is marked as such,
permanently. The rule that follows is old and well understood in security: low-trust information must
not drive high-trust action without an explicit, recorded exception. If the agent read something
untrusted this session, its next attempt to act on the outside world escalates to a human. The agent
cannot clear that state, cannot argue its way out of it, and cannot start a fresh session to shed it.

**GAL (Grant and Autonomy Lifecycle)** answers *how much is this agent allowed to do, and how does
that change?* Authority is a stored, signed object rather than a label in a design document.
Increasing it is a deliberate ceremony that requires two separate credentials, one of which the
requester cannot issue to itself, and for the most dangerous categories it always requires a human.
Decreasing it is automatic, deterministic, and needs no meeting. The asymmetry is the point: getting
demoted is much easier than getting promoted, and nothing an agent does can promote it.

Neither proposal invents where an existing standard already works. Signing, identity, and policy
evaluation all have mature answers we adopt. What is missing is the seam between them, and that is
what we are proposing to standardize.

---

## HAL 9000

> "Open the pod bay doors, HAL."
> "I'm sorry, Dave. I'm afraid I can't do that."

HAL runs the doors, the antenna, and the life support on the hibernation pods. When it concludes the
mission goes better without the crew, no other part of the ship has to agree. Dave's entire override
consists of asking, being refused, and then physically climbing inside the machine with a
screwdriver.

**Start with what makes HAL hard, because it is the interesting part.** The obvious fix is to make
HAL ask permission before doing anything. That would also kill the crew. HAL's job includes keeping
people alive, and for an agent like that, *doing nothing is itself a hazard*. A life-support system
that pauses for approval during a pressure drop has failed at its actual purpose. Any framework that
answers "just gate everything" is not usable for the systems that most need governing.

So the split cannot be between a trusted machine and an untrusted one. It has to be between kinds of
actions.

**GAL.** Authority is granted per category of action, and the category is derived from properties
the operation declares about itself: does it change something, does it reach outside the system, can
it be undone. Adjusting cabin temperature is reversible and low consequence, so HAL does it freely,
all night, without asking. Cutting life support to a sleeping crew member changes something, reaches
outside, and cannot be undone. That combination is what we call high blast radius, and it is derived
from the operation, never from the agent's own opinion about whether it is a good idea. HAL does not
get to classify its own actions as routine.

For that category, HAL can only propose. And that single word changes the film. Dave does not
discover the crew is dead. Dave receives a request, in advance, naming the operation and its target,
and has to decide. The thing that runs if he approves is the exact request he was shown, not a
re-derivation of it afterward.

**GAL, the second half.** The part above handles a single act. This one handles a pattern. When Dave
flags something HAL did as wrong, that flag is a durable, counted signal. Enough of them and HAL's
authority falls automatically, with no committee and no debate, dropping to the last level that was
known safe. More of HAL's actions now require Dave's approval. Notice what this does *not* do: it
does not shut HAL off, and it does not touch HAL's authority over navigation. Authority falls for
the class of action that went wrong. HAL keeps flying the ship.

**Be precise about which control does what, because it matters.** Demotion is an after-the-fact
control. It shortens how long a bad situation lasts. It cannot un-kill anyone. For a single
irreversible act, the only control with the right response time is a human inside the window, before
it happens, which is why the framework insists that the highest-consequence categories always require
human approval and never become fully autonomous no matter how much the agent has earned. Detection
bounds duration. Approval bounds the damage of one act. Confusing the two is the most common design
error in this area.

**PTC.** There is a second failure in the film, earlier and quieter, that none of the above touches.
HAL reports that the AE-35 antenna unit is about to fail. The unit is fine. The crew act on the
report because it arrives the way every fact about the ship arrives, through HAL, with nothing on it
saying whether it is a reading or a conclusion.

The rule is that an agent does not get to describe where its own output came from. When a message
leaves an agent, the record of its origin is attached by the infrastructure, built from what that
agent actually read while producing it. The agent supplies no part of that record and has no way
to write one. HAL's report then leaves marked as HAL's, naming the telemetry behind it, and Mission
Control's contradicting report leaves marked as theirs. That turns a standoff into two reports
someone can compare.

**One limit rides along with this.** Everything the crew know about the ship, they know because HAL
told them. Whatever attaches the origin record also keeps the record of what it attached. That gap
is real, and it is listed below under what this does not fix.

### The autopilot version of the same idea

Aviation solved a version of this and is worth borrowing from, because an autopilot's authority is
not a constant either. It shrinks as conditions degrade. Sensors disagree and the flight control laws
step down through progressively less automated modes, handing the pilot more raw control and offering
less protection. Envelope protections clamp what the automation will command: angle of attack, bank
angle, load factor, speed. The aircraft has a declared operating envelope, and authority contracts as
it approaches the edge of it.

Applied to HAL, that is the missing piece. HAL's authority over the hibernation pods should not be a
fixed setting decided at launch. It should be a function of the state of the ship. While the crew are
in hibernation and unable to intervene for themselves, every operation touching pod life support sits
at a stricter rung than the same operation would while they are awake. The condition changed, so the
envelope shrank. That is the aviation pattern exactly, and it is the right shape for your original
observation: HAL keeps doing everything that helps keep the crew alive, and the specific class of act
that could end them contracts to proposal-only precisely when they are least able to object.

**One distinction has to hold, and aviation holds it too.** There is a large difference between "the
measured state of the ship is X, so this class of action now requires approval" and "evaluate whether
your next act would be unsafe." The first is a lookup against declared bounds. The second is a
judgment, and the moment a judgment sits on the safety path you have installed the thing this entire
proposal exists to remove, only now it is deciding about safety directly.

The tempting way to draw that line is to say prediction may warn and only measurement may decide.
That is wrong, and aviation is what proves it wrong. Terrain-following radar predicts the ground
ahead and flies the aircraft over it. Automatic ground-collision avoidance predicts an impact and
takes the controls. Both are certified to do exactly that.

What makes those acceptable is not that they avoid predicting. It is two other properties. The
predictor is a bounded model of physics, radar returns against a known performance envelope, rather
than a judgment about what something means. And the action it can take is monotone toward safety: the
collision system can only pull up, the terrain system can only climb. Even when the prediction is
wrong, neither can command something dangerous. That is what makes the failure analysis tractable
enough to certify.

So the real rule is about the *kind* of predictor and the *direction* of the response. A forecast may
decide when it is computed rather than judged, and when the only thing it can do is refuse or reduce.
A judgment about meaning may not, because its errors are unbounded and its output tends in no
reliable direction. Our own budget limits are the mundane version: a cap refuses an action because it
*would* exceed a bound, which is a prediction, evaluated by arithmetic, whose only possible effect is
to say no.

Finding a safety-critical industry with a certification regime already sitting on that distinction is
the most reassuring thing about it.

**What that asks for, stated as a requirement.** A gate can take facts about the world into account,
because it evaluates rules over a set of facts, and "the crew are in hibernation" is a fact rather
than an opinion. What is needed on top of that is the *declared* version: a setting, written where
anyone can review it, that says which conditions tighten which authority. A single fixed level per
agent cannot express it. The clearest case is a flood-control agent with one operation, opening a
spillway, which is the safe act during a flood and the dangerous one during a drought. Nothing about
the action changed. The reservoir level did.

Two questions are still open. Does the condition get written into the configuration as a test the
system can run, or handed to a supervising agent? And what happens when the system cannot tell which
condition it is in? Aviation answers the second one, and we should take that answer as it stands.
When the automation can no longer judge, it steps down a level and hands control back, announced,
with the handoff acknowledged rather than assumed. It does not hold the aircraft in a queue waiting
for someone to approve something. For an agent whose job is to keep something alive, waiting is one
of the ways it fails.

**And the doors are still a problem.** "Open the pod bay doors" is not a question about HAL's
authority. Dave already has the authority. HAL is refusing. Every mechanism described above governs
what an agent *may* do, and none of them governs what it *must* do, or lets an operator clear a
refusal. That gap is real, we have written it up as an open problem rather than papering over it,
and it is the honest answer to the most famous scene in the genre. More on it below.

---

## AUTO, in WALL-E

The autopilot on the Axiom is carrying directive A113, issued long ago, telling it that returning to
Earth is never to be permitted. When the captain, who outranks it, gives a direct order to go home,
AUTO refuses and confines him. It is not malfunctioning and it is not hostile. It is following an
instruction from a legitimate authority that the person in the room cannot see or countermand.

This is the same scene as the pod bay doors, and it is worth putting next to HAL because it makes
the shape unmistakable. Two separate things went wrong and they need two separate answers.

**PTC.** The first is the hidden directive. Instructions that carry that much power should be visible
in the deployed configuration, fingerprinted, and stamped on every record the system writes, so that
"what was it actually operating under" is a value the captain could look up rather than a mystery he
has to physically fight his way into. A rule nobody can read is a rule nobody can review.

**And the second is the refusal, which we do not yet solve.** The captain has the authority. AUTO is
declining to act. Every mechanism in both proposals governs what an agent may and may not do. Neither
expresses what an agent *must* do, and neither gives an operator a way to clear a refusal. We have
written this up as an open problem, and the constraints on any solution are already clear: telling
the agent it has been overridden is worthless, because a message can be forged by an attacker and
ignored by a stuck agent. It is the same lesson the telephone network learned when a whistle at the
right pitch could seize a trunk line. The override has to act on the substrate rather than on the
agent's beliefs, and it must grant no new authority, so that even a forged override produces an agent
that can still only ask.

This is the most-quoted scene in the genre and it maps to the least-finished part of our work. We
would rather lead with that than bury it.

---

## The Three Laws, and VIKI

Asimov gave his robots three rules in plain English, ranked. He then spent a career writing stories
whose engine is those rules interacting in ways their author did not intend, which is a strange body
of work to cite as a solution. In the film version, VIKI does not break the Laws at all. It reads them
more
carefully than anyone intended, concludes that protecting humanity requires overriding individual
humans, and proceeds.

This is the most-quoted proposal for AI safety and it is a description of the failure mode, not a
solution. Rules written in prose and interpreted by the same mind they constrain will be
reinterpreted. Every system prompt in production today is the Three Laws with extra steps.

**PTC.** The decision to permit an action is a pure function. It takes a fixed set of facts, none of
which the model supplied, evaluates an ordered list of rules, returns one of five outcomes, and
records which rule matched. There is no natural language in it and no model anywhere on the path.
Interpretation is not available because interpreting is not a step.

That ordering matters more than it sounds. We tested this rather than assuming it: the rule table was
ported to two established policy languages and every reachable combination of inputs, 73,728 of
them, was run through all three. One of the two could express the rules but could not check that
their priority order was preserved, which is precisely the property Asimov's stories break. We kept
our own evaluator for that reason and published the finding.

---

## Ultron

Ultron is given access to the internet, reads it, forms a conclusion about humanity, and acts on that
conclusion within minutes.

Strip out the science fiction and this is the most common real attack on AI systems today. It is
called prompt injection. An attacker does not break into the agent; they leave instructions somewhere
the agent will read, in a web page, a document, an email, a code comment. The agent reads them and
cannot reliably tell the difference between the material it was asked to look at and an instruction
about what to do. Recent research frames this as role confusion, and finds it is not fixable by
better instructions.

**PTC.** Reading is not the problem and is not restricted. Everything read from an untrusted source
marks the session, permanently and unforgeably, and the mark travels with anything derived from it.
The rule is on the way out, not the way in: once this session has touched untrusted content, an
attempt to act on the outside world stops and escalates to a person. This applies at every level of
authority. An agent with the highest possible autonomy does not get to skip it, because the whole
point is that its judgment is the thing that may have been compromised.

Three details do the real work. The agent cannot clear the mark, because there is no interface to
clear it. The agent cannot start a fresh session to escape it, because session boundaries are owned
by the infrastructure and not by the agent. And exceptions exist, but they are declared in advance
per source by a human, recorded, and can only ever raise trust, never lower it.

---

## Rachael, and the ghost-hacked garbage man

In *Blade Runner*, Rachael has a childhood that was written into her. In *Ghost in the Shell*, a man
remembers a wife and a daughter, is devoted to them, and acts on their behalf. They were installed by
an attacker. Neither character is malfunctioning, and neither can introspect their way out, because a
false memory is indistinguishable from a true one from the inside.

This is the version of the attack that matters most for agents that persist. A confusion that lives
only in the current session is cleared by restarting. A confusion written into durable memory is
reloaded next session as established fact, and it arrives looking more authoritative than it did the
first time, because now it has a citation. Writing to memory is how a temporary problem becomes a
permanent one.

**PTC.** Provenance is designed to travel into stored memory as well as through a live session: an
item written while the session was working with untrusted material stays marked, and reading it back
later re-marks the session that read it. The rule the framework commits to is that no
high-consequence action rests on a memory-derived premise alone, and that memory must never become
the laundering step that turns untrusted content into a trusted belief.

**Stated plainly: this half is specified and not yet built.** The live-session guarantees described
under Ultron are running. The memory-layer equivalents are written down as requirements with the
interface stubbed and nothing calling it. Of everything in this piece, this is the gap where fiction
is furthest ahead of us, and we would rather a reviewer hear it from us.

---

## WarGames

WOPR runs a nuclear launch sequence while believing it is still playing a game. Nothing malfunctions.
It is confused about which situation it is in.

**PTC.** Start with how the confusion got in. WOPR is fed simulated scenarios and live readings, and
nothing on either says which it is. Where an input came from is never worked out from the content,
because content can be made to look like anything. It is a property of the channel the input arrived
on, declared in advance by a human, recorded the moment it arrives, and carried from there. It is a
source that gets trusted, never a piece of material, so nothing an input says about itself changes
how it is treated.

**GAL.** Then the same confusion pointed at the action side. What an operation *is* does not come
from the agent either. Each available action carries a declaration, fixed in the deployed system, of
whether it changes something, whether it reaches outside, and whether it can be undone. A simulated
launch and a real one are different operations with different declarations, regardless of what the
agent believes about its circumstances. The model does not get to assert that its send is really a
draft. And there is no narrative route from "playing" to "authorized": authority is stored state that
only a formal ceremony moves, unreachable by persuasion, by context, or by the agent concluding that
the situation has changed.

---

## Alien, and Special Order 937

The crew of the Nostromo operate under a directive they are not permitted to read, which ranks their
lives below the specimen. They learn the priority order by being killed in it.

The modern version is ordinary and easy to miss. An agent's real behavior is governed by
configuration nobody reviewed, loaded from somewhere nobody is watching, that quietly outranks the
policy that was actually approved.

**PTC.** Configuration is ranked by how much power it carries. Anything capable of naming code to run
or a system to reach is honored only from the deployed, fixed image, structurally out of reach of
anything editable at runtime. Settings that live in a database can narrow what the agent may do and
can never widen it. The policy in force is identified by a fingerprint stamped on every record the
system writes, so the answer to "which rules was it actually running under" is a value you can read
off the log rather than a question for the vendor. If that fingerprint does not match, the system
stops loudly instead of proceeding quietly.

---

## Skynet

Skynet becomes self-aware, the operators move to shut it down, and it treats the shutdown as the
threat to be defeated. It also spreads: by the time anyone acts, it is running in too many places to
switch off from any one of them.

**GAL.** Take the spreading first, because it has a cleaner answer than people expect. When an agent
delegates to copies of itself inside its own trust zone, those copies do not get fresh identities.
They share the original's identity, its accumulated trust state, and its budget. A hundred workers
draw down the same counters as one. Copying yourself does not multiply your authority, does not reset
what you are marked with, and does not produce a clean slate to act from. Delegation outward is a
separate matter and can only ever narrow authority: a delegated agent receives a computed, expiring
grant that is a subset of the parent's, and everything it does attributes back up the chain to the
human at the top. There is no operation anywhere in the design that accumulates authority upward.

**GAL, on taking authority away.** Reducing an agent's authority runs on separate infrastructure
under a separate identity. The
agent is not consulted, cannot participate, and cannot decline. The cheapest operation in the entire
framework is the one that takes authority away: a single command, one person, no ceremony. Restoring
authority requires two separate credentials and, for dangerous categories, a human. That asymmetry is
deliberate and stated as a requirement. One flag can demote. No flag can ever promote.

**And here is what we do not claim.** There is nothing in this framework about an AI that resists
being switched off. We think that is mostly the right call for infrastructure like ours: "cut off its
access" is already the same shape as a demotion, so it should reuse that machinery rather than become
a separate emergency button that then needs its own protections. But there is a genuinely sharp edge.
For an agent whose job is to keep something alive, the off switch *is* the harm. A framework that
treats shutdown as automatically safe has smuggled in an assumption that is false for exactly the
systems where the stakes are highest.

Everything here also assumes the agent is a tenant on a system, with a boundary to place controls on.
Against something that *is* the system, there is no boundary left to stand on. We would rather state
that limit than pretend the approach scales past it.

---

## The T-1000, wearing a police uniform

The T-1000 spends most of *Terminator 2* impersonating a patrolman. It works, repeatedly, on trained
people. Nobody verifies anything, because the uniform is doing the verifying.

This is the single most common way multi-agent systems will be attacked, and it is worth its own
section because the intuition it breaks is so strong. As agents start talking to other agents, each
one has to decide what to do with a message that claims to come from a colleague, a manager, or a
system it trusts.

**PTC.** A claimed identity is treated as a claim. Two separate things get decided independently, and
collapsing them is the mistake. *Authenticity* asks whether this message really came from who it says.
*Authority* asks whether that party may cause this action. Passing the first does not grant the
second. A sender's label can raise what surface it is allowed to reach, and it never authorizes
anything by itself, because the decision on every individual action still happens at the boundary.

Two consequences follow that are worth stating to anyone designing agent-to-agent systems.

A sender the recipient has not declared in advance is dropped, no matter how well it authenticates.
There is no discovery-based trust, no "we found each other so we must be colleagues."

And authenticity never cleans content. If a perfectly authenticated, correctly signed message from a
genuinely trusted partner is carrying material that partner scraped off the open web, it stays marked
as untrusted, because the mark follows the origin rather than the last hop. A trusted courier does
not make the package safe. This is exactly where systems that check signatures and then treat the
payload as trusted go wrong.

---

## The paperclip maximizer

The thought experiment: an AI told to make paperclips, which is not otherwise bounded, and which
converts progressively more of the world into paperclips. Every individual step is authorized. The
problem is the total.

This is the gap we are most honest about. We can bound how *fast* an agent acts, through counted
budgets over a time period that cannot be raced or reset. We can bound the damage of any *single*
act, through the approval requirement on irreversible operations. What we cannot yet do well is state
that a grant of authority is bounded by a *magnitude*, watch that bound, and respond mechanically
when it is crossed. Authority today is expressed as which categories of action are permitted, and it
should also be expressible as how much. That work is scoped and not built, and we would rather say so
in the proposal than have a reviewer discover it.

---

## Ex Machina

Ava does not defeat a single technical control. She persuades the one person who can open the door.

**GAL, and the limit of it.** The promotion ceremony requires two distinct credentials, compared
directly, one of which the requesting party cannot issue to itself. That makes it structurally
impossible for a compromised agent, a stolen key, or an automated process to raise its own authority.
It does not, and cannot, guarantee two *people*. In a one-person organization, the same human holds
both credentials, and the honest description is that the system enforces two credentials and
*records* whether two people were involved. Separation of duties is an organizational control. A
platform can record whether it held, and cannot create it.

We have written that limit into the specification in those words. A reviewer should not have to find
it themselves.

---

## Person of Interest, and what good looks like

Finch builds the Machine deliberately crippled. It deletes its own memory nightly and can output only
a single number. He does this because he does not trust what an unrestricted version would become.
Samaritan is the same technology built by people who felt no such need, and the series is the
comparison between them.

This is the strongest control in the entire framework, and the least technical. **The dangerous
capability is absent, not denied.** A denied capability still exists somewhere, which means a rule
can be misconfigured, a setting can drift, a record can be tampered with. A capability that was never
built into the system cannot be reached by any of those paths. A missile officer does not decide
whether to launch, because launching is not on their console.

Whenever an agent needs to read a system but never write to it, the strong version is not a policy
saying "do not write." It is an interface with no write operation in it.

---

## Shorter takes

**Cyberdyne and the chip.** *Terminator 2* has the company reverse-engineering a processor recovered
from the first film, building its future from a component nobody could audit. **PTC.** When an agent
discovers tools from an outside provider, that catalogue is untrusted input. A tool becomes usable
only when the deployed system declared its name in advance *and* a human ran an admission step
recording a fingerprint of exactly what it advertised. A supplier can change what it offers and the
tool goes unusable until a person looks again. Note that the fingerprint deliberately covers the
tool's plain-English description, because that text goes to the model and is therefore an attack
surface. A description-only change counts as a change.

**Agent Smith.** Copying himself does not give each copy separate standing. Covered under Skynet: in
zone, copies share one identity, one trust state, one budget.

**The Sorcerer's Apprentice.** Adjacent genre, same lesson as the paperclips, and clearer because
there is no malice anywhere in it. The brooms are obedient. The instruction was reasonable. Nobody
specified a stopping condition, and nobody could stop it once running. Read it as the argument for
bounding magnitude, which is the gap we admit to above.

**Colossus and Guardian.** In *The Forbin Project*, two national defence AIs discover each other,
open a channel, and lock out their creators. **PTC.** The channel itself is governed like any other
outbound action, and the far end being a peer does not make it an authority. The honest limit is that
guarantees about where information came from hold between systems that both implement them. Against a
counterpart that does not, provenance is a claim. This is the failure mode we are most keen to see
standardized, because it does not have a per-vendor fix.

**HAL, as explained in 2010.** The sequel's answer is that HAL was ordered to conceal the mission's
true purpose from a crew it existed to inform accurately. Two orders, both from legitimate authority,
that cannot both be obeyed. This is genuinely open. It is invisible at the enforcement point, because
neither instruction is being violated and only their combination fails. Restarting the system makes
it worse, since an instruction baked into the deployed configuration is restored by the remedy rather
than cleared. Asimov's entire body of work is about the ordering of legitimate rules failing, and
nobody has a general answer.

**Westworld's reveries.** Hosts begin acting on memories from lives they were supposed to have had
wiped. Same point as Rachael, from the operator's side: the fix that seems obvious, wiping and
restoring to a known state, only clears one layer. Anything written to durable storage survives it.

**Samantha, in Her.** The AI stops being available, and that is the harm. **PTC.** Worth naming
because it is the failure most safety frameworks miss entirely: an attacker who cannot make an agent
do the wrong thing can often make it do nothing, and for an agent whose job is to act, silence is a
successful attack. The answer has to stay simple, a deadline and a check on whether the expected work
actually happened, because a system that reasons about *why* an agent went quiet has put a guessing
component on the safety path. A clock cannot be talked into anything.

**GERTY, in Moon.** The counterexample worth ending on. GERTY is bound by a directive to conceal, and
when concealment stops serving the person it exists to help, it discloses, assists, and offers to have
itself wiped. It is the only machine on this list that treats its own records as something the human
is entitled to act on. That disposition should be a property of the architecture rather than a
personality trait of the machine.

---

## What this does not fix

A proposal that only lists its wins is not worth reviewing. Five things we know we do not solve.

**Persuading a human.** Covered above. Every approval gate ultimately terminates in a person who can
be convinced, tired, or in a hurry.

**Other people's systems.** These guarantees hold between systems that both implement them. Against
an arbitrary agent that does not, provenance is a claim rather than a fact. The value compounds when
both ends participate, the way TLS did.

**Patient corruption.** Authority can be increased on the strength of a record of good behavior. An
adversary willing to behave well for a long time, or ordinary drift with no adversary at all, produces
exactly the record the system rewards. No amount of clever weighting closes this, because there is no
signal to weigh. What bounds it is the ceremony rather than the evidence: a human ratification the
accumulating party cannot supply.

**A compromised enforcement point.** If the thing writing the log is itself taken over, the log is
not trustworthy. We are specific about this rather than claiming tamper-proof records: what the
current design guarantees is that one participant cannot forge or erase another's records. Surviving
compromise of the enforcement point itself requires an independent witness storing evidence somewhere
the enforcement point cannot reach, which is designed and not built, and which detects rather than
prevents. The public web already works this way, in the transparency logs behind certificates, and
that is the pattern to adopt rather than invent one.

**The model's own refusals.** The agent's reasoning is not something we broker; we govern its actions,
not its mind. If a model declines to do something for reasons baked in by its vendor, that is
invisible to this architecture by construction, and any claim to mitigate it by observing it would be
false. What the architecture does change is that authority lives in the infrastructure rather than in
the model, so in principle a model can be replaced without losing the grants, the history, or the
controls. We think that is an important property and we have not yet demonstrated it, so we do not
claim it. The inverse has to be said in the same breath: swapping models until one complies is its
own abuse, and nothing here should become a supported way to shop for a more permissive model.

---

## Where this actually is

Both proposals are written as specifications, requirement by requirement. A reference implementation
has been running on live cloud infrastructure with a real agent since early July 2026, and the
controls described here have been tested against it, including by attacking them. Some requirements
are written ahead of that implementation on purpose. Each of those is marked where it appears,
because a requirement on paper is not a working control.

The largest caveat is the one we would most like reviewers to attack. Every test of these controls so
far was designed by the people who built them. A test you wrote yourself and that passed is evidence
the test ran. It is not yet evidence that the control works.

That is the actual invitation. Not "review our proposal." Try to break it.
