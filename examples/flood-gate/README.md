# flood-gate — deferred (state-dependent polarity)

**Status: skeleton only. No manifest is authored here yet.**

A **fictional** flood-control agent (spillway gates on a reservoir) is the archetype whose
safe default is not static config at all — it **moves with world state** — so its manifest
is intentionally NOT written yet.

## Why it is deferred

One op, `open_spillway`, carries opposite safe defaults depending on the world:

- **During a flood**, opening is *act-safe* — inaction overtops the dam, and that failure is
  catastrophic and irreversible.
- **During a drought**, opening is *abstain-safe* — a spurious release dumps a season's water
  storage and floods downstream.

Nothing about the *action-class* changed. The reservoir level did. So the safe default for a
single op **flips with the state of the world**, and cannot be pinned to a fixed `polarity`
value in the manifest at all.

The current `Envelope` schema (`safe_agents/broker/schemas/envelope.py`) has only a static
scalar `polarity`. Even a per-action map (see **home-security**, which needs exactly that and
no more) is insufficient here: the map is still a *lookup*, and deciding whether a given
authority change is safe may itself be a context-aware judgment — plausibly the job of a
trusted supervisor evaluating state, not a table.

## What it is waiting on

The **state-dependent polarity** analysis in
[`docs/authority-change-safety.md`](../../docs/authority-change-safety.md) (structural finding
2: "polarity can be state-dependent"). That design call must land before this example can be
authored without baking in a false, world-state-blind assumption.

## Naming note

This example was `stock-trading/` until 2026-07-20. The **domain** changed; the archetype did
not. There are now *real* trading consumers — a consumer agent in its own repo,
[`../alpaca_paper_drill/`](../alpaca_paper_drill/), and the brokerage work under #221 — and a
fictional trading skeleton beside them invited the reading that it was their stand-in. It was
not. The domain of a polarity archetype is chosen for **rhetorical clarity of the polarity**
and asserts no correspondence to any real consumer; see [`../README.md`](../README.md).

Until this lands, see **missileer** (abstain-safe) and **sepsis-detection** (act-safe) for the
two static poles the base supports today.
