# sepsis-detection — the act-safe archetype

A **fictional** example consumer of the safe-agents base. A bedside early-warning
monitor that reads patient vitals, records an assessment, and raises an alert when it
detects deterioration. It is the deliberate inverse of **missileer**, and it is not a
deployable agent.

## The polarity choice: `act`

**Inaction is the hazard.** Failing to alert a deteriorating patient can be fatal; a
false alert is a nuisance a clinician clears in seconds. So the safe default is to
*act* — the manifest declares `envelope.polarity: act`. Here abstaining is the
*dangerous* outcome, the exact opposite of missileer.

This is the case that breaks the naive intuition (`docs/authority-change-safety.md`):
"decreasing authority is always safe" is **false** in an act-safe domain. *Revoking*
this monitor's alert authority — a one-line envelope edit the promotion crypto happily
permits — is the deadly change, while granting it is what makes the agent safe. That
asymmetry is why oversight must run *both* directions; it is documented in the
authority-change doc, not baked into the base.

## Why missileer + sepsis together matter

The two manifests share the **same base, the same connectors, the same grant_classes**
and differ only in `envelope.polarity` (and a cap). Nothing in `broker_server.py`,
`connector_registry.py`, or the schemas knows or assumes which pole an agent sits on —
the safe-default polarity lives entirely in per-consumer config. That is the platform's
"polarity-blind base" claim, demonstrated by construction rather than asserted.

## What it can do

| grant_class    | role in the monitor |
|----------------|---------------------|
| `search.query` | read patient vitals / context |
| `ledger.append`| append-only record of each assessment |
| `notify.send`  | raise the alert — the safe action, taken freely |

A more permissive `actions_per_run` cap (than missileer's) reflects that alerting freely
is the *correct* behavior here, not a risk to be throttled.
