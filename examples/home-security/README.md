# home-security — deferred (per-action polarity)

**Status: skeleton only. No manifest is authored here yet.**

A **fictional** home-security agent (locks, alarms, cameras) is the archetype that
breaks a *scalar* `envelope.polarity` field, so its manifest is intentionally NOT
written yet.

## Why it is deferred

This agent is the gallery's **composite** case: it needs *both* polarity shapes at once,
which is why it is the most demanding archetype here and the one that argues hardest about
what the schema has to become.

**First, the safe default splits by action-class:**

- `sound_alarm` is *act-safe* — a false alarm is an annoyance; a missed intrusion or fire
  is the harm. Failing to act is the expensive direction.
- `unlock_door` is *abstain-safe* — a spurious unlock is a break-in. Acting is the
  expensive direction.

Two *different* ops, opposite safe defaults, one agent — so no single agent-wide scalar is
correct for both. That much a per-action **map** would fix.

**But it doesn't stop there — one of those ops also moves with world state:**

- `unlock_door` **under normal conditions** is *abstain-safe* — an unnecessary unlock is a
  break-in.
- `unlock_door` **during a fire** is *act-safe* — failing to unlock traps someone inside.

Same action-class, opposite defaults, and nothing about the *op* changed — the world did. A
per-action map is a **lookup**, and a lookup cannot read the world, so the map that fixed the
first problem does not fix this one.

Together these mean home-security cannot be expressed by a scalar **or** by a map: it needs
polarity evaluated as a function of *both* the action-class and the world state. (A real
home-security system might well not be built this way — the point is that this is a compact,
legible way to show both shifts in one agent. [`../flood-gate/`](../flood-gate/) deliberately
*isolates* the state-dependent shift in a single-op agent, which is the cleaner place to name
that shape on its own.)

The current `Envelope` schema (`safe_agents/broker/schemas/envelope.py`) carries a single
scalar `polarity: "abstain" | "act"`. Authoring a home-security manifest today would force a
wrong, agent-wide polarity onto at least one action-class — a latent safety bug.

## What it is waiting on

**Both** structural findings in
[`docs/authority-change-safety.md`](../../docs/authority-change-safety.md) — finding 1
("polarity is per-action-class, not per-agent") *and* finding 2 ("polarity can be
state-dependent"). Because this agent exhibits both, it is the example that suggests the two
findings may not be independent design calls: a polarity evaluated over `(action, state)`
subsumes a per-action map, so shipping the map first could be an intermediate the general
form makes redundant. Worth settling in that design session before either lands.

Until then, see **missileer** (abstain-safe) and **sepsis-detection** (act-safe) for the
two poles the base already supports.
