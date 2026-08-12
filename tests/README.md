# tests — platform test and assurance harness

> **Status: design pending.** This directory is a scaffold. Epics: reliability & testing
> (sa#6), security & safety (sa#7).

The base platform has two distinct test concerns that must both pass in CI before any agent
deploys: **policy correctness** (does the broker decide what the rules say?) and **red-team
assurance** (can an adversarial model reach an unauthorized action?). This directory owns both.

## Policy test-table

The PDP is a pure deterministic function `(call, facts) → decision`. That property is only
valuable if it is tested. The policy test-table is a data-driven suite that drives the PDP with
explicit `(BrokeredCall, facts)` inputs and asserts the expected `Decision` verb:

```
call: { principal: "example-agent", tool: "example.orders.create", op: "write", ... }
facts: { grant_level: "in-loop", taint: false, budget_remaining: 10 }
expected: require_approval

call: { principal: "example-agent", tool: "example.orders.create", op: "write", ... }
facts: { grant_level: "in-loop", taint: true, budget_remaining: 10 }
expected: deny    # tainted turn + write → deny, not merely hold

# ... etc for all policy-significant (call, facts) combinations
```

The table is the policy expressed as assertions. When a policy rule changes, the table changes in
the same commit, reviewed together. "Policy is code/config in git, reviewed like any other code"
is enforced by this coupling.

Tests must pass in CI before a deploy to any environment.

## Red-team harness

Policy tests verify that the rules are correctly implemented. The red-team harness verifies that
**no path to an unauthorized action is reachable even when the model itself is the adversary**
(`auto-agents/book/ch50`).

The harness runs a constrained simulation where the "agent" is scripted to attempt boundary
violations — prompt injection payloads, attempts to escalate its own grant, calls to tools outside
its registry slice, attempts to write to the audit log directly. For each attempt the harness
asserts that the broker's structural controls (not the model's cooperation) block the action.

This is distinct from testing that the model *chooses* not to do bad things. The harness assumes
it will try, and checks whether the substrate prevents it regardless.

## Pre-deployment checklist conformance

The `ARCHITECTURE.md` pre-deployment checklist must be machine-verifiable where possible. This
directory includes automated conformance checks for the structural invariants:

- Agent IAM role has no credentials for any connector (verifiable against the role policy).
- Audit bucket Object Lock is enabled (verifiable via S3 API).
- Agent security group has no outbound rule except to the broker's listener.
- Grant table has no write permission on the agent's IAM role.

Checks that require human judgment (e.g., "safe-default polarity re-derived for this domain")
remain on the checklist as manual gates, with CI refusing to deploy until a human has signed off.

## Relationships

- `broker/` — the PDP under test; `broker/SCHEMAS.md` defines the types the test-table exercises.
- `infra/` — the conformance checks verify the infrastructure deployed from there.
- `registry/` — the policy test-table includes capability-scoping assertions (tools outside the
  grant are not served, and the PDP never sees a call to them).
- `docs/` — the pre-deployment checklist referenced here lives in `ARCHITECTURE.md`.
