# Authority-change safety — design problem for a future session

**Status: design call, not yet decided.** This doc frames the deferred session on *changing an
agent's authority while it runs* — increasing it (promotion / loosening the envelope) and decreasing
it (demotion / tightening). It exists so that session starts from the analysis below rather than
cold. Nothing here is built; the broker-destub Phase 3 work (sa#122) is pure mechanism and does not
depend on resolving any of this.

## Why this is not the obvious problem

The intuition is "decreasing an agent's authority is always safe; increasing it is always risky."
That is **false**, and the repo already carries the concept that explains why: the safe-default
polarity (`abstain-is-safe` vs `positive-safe-action`) **must never live in the base — it is
re-derived per agent** (see `CLAUDE.md`). This doc is the worked proof of why that invariant exists.

Two different safeties get conflated:

- **Authorization integrity** (domain-invariant, belongs in the base): the broker never lets an
  agent exceed its envelope; gaining a capability requires the promotion-ceremony HMAC key. A
  fully-compromised agent, or a UI writing the envelope store, cannot mint itself new capability.
  This is what the Phase 3 hash-binding enforces.
- **Mission safety** (polarity-relative, per-agent): whether the agent *acting or not-acting*
  produces a safe real-world outcome. This is the thing the base must not assume.

The risk of an authority change is not a function of its **direction**. It is a function of whether
the change moves the agent **toward or away from its domain's safe default**.

## Four domains, gamed out

| Domain | Safe default (what inaction does) | Dangerous change | vs. the naive intuition |
|---|---|---|---|
| Missileer / launch | Abstain — not launching is safe | **Granting** launch authority (fratricide) | Matches: increase risky, decrease safe |
| Bedside sepsis alert | Act — not alerting kills | **Revoking** the alert authority | **Inverts**: the *decrease* is deadly |
| Home security | *Per-action*: unlock-in-fire is act-safe; unlock-normally is abstain-safe | Both, by action | Neither — polarity splits *within one agent* |
| Stock trading | *State-dependent*: sell authority is safe-to-hold in a crash, risky in a calm market | Both, and it flips with world state | Neither — polarity moves with the world |

## Structural findings

1. **Polarity is per-action-class, not per-agent.** Home security alone breaks a scalar `polarity`
   field: unlock-during-fire and unlock-under-normal-conditions have opposite safe defaults in the
   *same* agent. The envelope must map polarity per action-class.

2. **Polarity can be state-dependent.** Trading shows the safe default is not static config — it
   depends on world state. Deciding whether a given change is safe may itself be a context-aware
   judgment (plausibly the job of a trusted supervisor agent, see below), not a lookup.

3. **Revocation is the unguarded-but-dangerous direction.** This is the sharp one. The crypto
   asymmetry — *gaining* capability is hard (needs the ceremony key), *losing* it is mechanically
   free — silently bakes in abstain-safe polarity. In an act-safe domain that is exactly backwards:
   it is *hard to make the agent safe* (grant the life-saving alert) and *trivial to make it unsafe*
   (revoke it with a one-line envelope edit the crypto happily allows). So HITL runs **both ways**,
   and in act-safe domains revocation must be gated as heavily as granting is in abstain-safe ones —
   which crypto-on-gain cannot provide.

## The mechanism / policy split this implies

**Base (polarity-blind mechanism):**
- Capability-gain stays crypto-gated by the promotion ceremony — authorization integrity.
- A **bidirectional oversight hook** fires on *any* envelope change, grant or revoke. The seam
  already exists: the identity stack has both a `promotionRole` **and** a `demotionRole`, so
  demotion is already a first-class privileged operation — it just lacks a policy that decides when
  a demotion requires human escalation.

**Per-agent (policy, in the envelope):**
- The envelope declares, **per action-class and per direction**, which oversight rung
  (`in-loop` / `on-loop` / `out-of-loop`) an authority change requires. This is the existing grant
  `level` rung, applied to the meta-action of *changing* authority.

**Supervisor agents compose cleanly.** A trusted agent that makes in-its-own-envelope decisions
about *another* agent's envelope acts within its own envelope, whose polarity governs when
editing-another's-authority must escalate to a human. The oversight rung applies to the
envelope-edit action itself.

## Pattern to carry in: revocation-as-handoff

De-authorization creates an obligation gap. Revoking the sepsis-alert duty is only safe if the duty
is **transferred** (to a clinician or a successor agent), not dropped. This is the mirror of the
blue/green idea for *increasing* authority (shunt new work to the new version, don't patch live):
the dual for *decreasing* is *don't revoke the old version's duty until a successor has assumed it*.
Both directions are really the same requirement — **continuity of coverage during authority
transitions** — which is a cleaner unifying frame than "increase vs decrease."

## Open questions for the session

1. How is per-action-class polarity represented in the typed `Envelope`
   (`safe_agents/broker/schemas/envelope.py`) without leaking a safe-default *value* into the base?
2. State-dependent polarity: is it declarative (predicates over world state in the envelope) or
   delegated to a supervisor agent's judgment? What does the broker do when it cannot evaluate the
   predicate?
3. What is the demotion ceremony? Does revocation route through `demotionRole` with the same
   rigor promotion gets, gated by the per-agent oversight rung?
4. Continuity-of-coverage: is handoff/overlap a base-provided primitive (both directions) or a
   per-agent concern? How does blue/green shunting interact with the grant `envelopeHash` binding
   during the overlap window?
5. Supervisor authority: what does an on-loop supervisor agent's envelope look like when its
   in-envelope actions are *edits to another agent's envelope*?

## Prior art in shipping control systems (added 2026-08-04)

Two industries have already fielded the state-dependent-authority problem this doc defers. Neither
is a source we design *from* in the firewall sense; both are public engineering practice worth
naming, and one of them answers open question 2's tail outright.

### Aviation: an authority envelope that contracts with conditions

An autopilot's authority is not constant. It steps down through progressively less automated control
laws as sensor confidence degrades, and envelope protections clamp what the automation will command
(angle of attack, bank angle, load factor, speed). Authority contracts as the aircraft approaches the
edge of a declared operating envelope. That is finding 2's shape as certified practice rather than as
an open question.

**The line it draws is ours, arrived at independently, and it is not the line first stated here.**
This section originally read "prediction may alarm; only measurement may gate," which is false, and
the maintainer falsified it the same day by naming terrain-following radar (2026-08-04). TFR predicts terrain
ahead and commands the aircraft, as does automatic ground-collision avoidance. Both actuate on a
forecast, and both are certified to do it. The corrected rule is better and describes our own system
more accurately:

> **A prediction may gate when the predictor is a bounded, validated model of physics or arithmetic
> rather than a judgment about meaning, AND the actuation is monotone toward safety, able to move
> only in the safe direction.**

TFR's predictor is radar returns against a known performance envelope and its actuation can only
climb. Auto-GCAS can only pull up. Neither can command something dangerous even when the prediction
is wrong, which is what makes the failure analysis tractable and the certification possible. What may
never gate is a *semantic* judgment, because its output is monotone in nothing and its error is
unbounded.

**We already gate on prediction, and the original wording obscured it.** `cap_budget_breached`
refuses a call because it *would* carry the counter past a bound. That is a forecast, evaluated
deterministically by arithmetic, whose only possible effect is to refuse. It satisfies both clauses of
the corrected rule, which is why it has never been in tension with `docs/deterministic-gate.md`. The
`transform` verb has the same shape: it substitutes a narrower operation and can never widen (it
carries arguments through verbatim — #273). Monotonicity toward
the safe direction, not the absence of prediction, is what the deterministic-gate rule is actually
protecting. Cite this when the rule is challenged as over-strict, because the over-strict reading is
the one we published first.

**It answers open question 2's tail** ("what does the broker do when it cannot evaluate the
predicate?"). The aviation answer is: degrade to a lower level of automation and hand control back,
announced, with the handoff positively acknowledged rather than assumed. It does not hold the
aircraft while something queues for approval. Adopt this. For an act-safe agent, holding is a failure
mode, and §"revocation-as-handoff" already says the duty must be transferred rather than dropped. The
autopilot disconnect protocol is that pattern made concrete: the warning cannot be silenced until a
human has positively assumed control.

### Driving automation: finding 3, shipped

Consumer L2 lane centering detects driver presence by sensing steering torque, warns when hands-off
persists, and then **disables lane keeping**. Observed first-hand on a rented Toyota Corolla,
2026-07 (the maintainer).

The detector is right and is worth noting as an independent instance of the liveness contract: it is
deterministic, and it observes *that* the driver is unresponsive, never *why*. A torque sensor cannot
be talked out of its reading. That is `Envelope.liveness` and PTC-42 in a shipping product.

**The response is finding 3 in the wild.** The capability is withdrawn at precisely the moment it
becomes most valuable, because the triggering condition (an unavailable driver) is the condition under
which lane keeping matters. Revocation is mechanically free and is the dangerous direction. It is also
§"revocation-as-handoff" failing: the duty is dropped to a driver who has not assumed it and, in the
limiting case, cannot. Aviation requires acknowledgment; this hands back to an empty seat.

**Steelman it, because the honest version is more useful.** Under SAE J3016 an L2 system declares the
human as the fallback, so terminating and alerting is conformant to its declared level; performing a
minimal risk maneuver is an L3 obligation. A poorly executed shoulder stop could be worse than a
handback. And higher-tier hands-off L2 systems that use camera-based driver monitoring (GM Super
Cruise, Ford BlueCruise) do escalate to a controlled stop with hazards, so the industry has moved
toward the positive safe action where the sensing supports it.

**Two further details from the same observation, both of which make it worse than stated above.**

*The reversion was silent enough to miss.* Lane keeping switched itself off and the driver continued
for some time without noticing, discovering it only by glancing at the console (the maintainer,
2026-08-04). So
the handback is not merely to a seat that cannot assume the duty; it is to an operator who does not
know a handback occurred, and who therefore keeps behaving as though the capability is still active.
That is the mental-model divergence in the second lesson below, except the system *created* the
divergence itself, by changing its own authority state without insisting the operator notice. The
domestic comparison is the sharp one: the same car will chime indefinitely about an unfastened
seatbelt. It already knows how to insist, and the insistence was allocated to the lower-stakes event.
This is precisely what the autopilot disconnect warning exists to prevent, and it upgrades
"announced" in the aviation section above from a nicety to the load-bearing part.

*The proxy is defeatable and a market exists for defeating it.* Steering torque is a proxy for driver
presence, not the property itself, and aftermarket wheel weights that supply the proxy are openly
sold. The general rule: **a detector that measures a proxy rather than the property creates a market
for proxy-suppliers**, and the cheaper the proxy is to forge, the faster that market appears. It is
also why camera-based driver monitoring, which measures something much closer to the property,
displaced torque sensing in the systems that do perform the stop.

Read that as validation of a choice we already made rather than as a new requirement. The liveness
contract's sign of life is deliberately *not* a heartbeat: it is a successful audit or ledger append
of a declared `expected_op`, an artifact the agent cannot forge and cannot produce without actually
having done the work (`docs/friction-doctrine.md` §availability). Torque is a heartbeat. An audit
append is proof of work. When specifying any future obligation detector under #344, this is the test
to apply: can the subject emit the signal without performing the duty? If yes, wheel weights will
exist for it.

**Two lessons worth carrying into the design call.**

First, *the polarity was not derived from what inaction causes in the domain; it was derived from where
liability sits.* Those are different functions and they disagree exactly in the cases that matter. An
abstain-safe default installed into an act-safe domain for liability reasons is finding 3 arriving
through the org chart rather than through a config edit, and no crypto gate on the envelope will catch
it. This is a mechanism of polarity corruption the repo has not previously named.

Second, *an authority envelope has to be legible to the operator.* The declared automation level
determines whose job the fallback is, but the operator's mental model of the system is what actually
governs their behavior. Divergence between the two is the failure, and it is the same shape as this
repo's rule that a control which looks enabled but is not is worse than either polarity
(`docs/friction-doctrine.md` rule 3).

## Relationship to current work

- **Phase 3 / sa#122 (broker-destub)** is mechanism-only: real envelope hash → decision + audit,
  verify-at-decision, loud quarantine on mismatch. It bakes in no polarity and is unaffected by this
  design call. It *provides* the hash-binding that makes envelope changes detectable in the first
  place.
- This design call is the natural companion to the earlier-deferred "increasing authority for a
  running agent" question (blue/green vs live-patch), now scoped to **both** directions.
- See also: the `taint-completeness` follow-on epic (sa#136/137) and the polarity invariant in
  `CLAUDE.md`.
