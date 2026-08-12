# BUILD — ordered build plan for the broker

The order in which to actually build the broker, and the AWS-serverless mapping it lands on. Ranked
by **security-per-unit-effort** (`auto-agents/tool-broker-sketch.md` §"Minimum viable vs full"): each
tier is independently shippable and moves real enforcement out of the model before the next is
started.

> **Status: HISTORICAL BUILD PLAN. Do not read shipped-status from this file.** Its original note
> said "nothing in `broker/` is implemented yet," which stopped being true long ago and was never
> updated; the per-tier **[design-only]** markers below were never revised either and are equally
> unreliable. Much of Tiers 0 to 4 is shipped, drilled and running in production. This file is
> retained for the *ordering rationale* (security-per-unit-effort), which is still the reason the
> tiers are sequenced as they are.
>
> For what is actually built, read `broker/README.md`, `broker/SCHEMAS.md`, `docs/GAL.md` §11, and
> `docs/PTC.md` §10 to §11, all of which carry current status. `docs/posture-ladder.md` is the rule
> for how any such claim must be worded. Correcting the per-tier markers needs a tier-by-tier
> adjudication that has not been done, so they are left visibly stale rather than half-updated.
> Corrected 2026-08-04 after a sub-agent sourcing status from here had to be told to disregard it.

## The AWS-serverless instantiation

One instantiation of the broker; many others are possible (`tool-broker-sketch.md` closing; the
stack defaults in the global standards — API Gateway HTTP API + Lambda, Secrets Manager, DynamoDB
on-demand, S3 Object Lock). The compute mode changes *where the broker process sits*, never the
invariants; durable state always lives **outside** the compute so it survives restart and the audit
can't die with an ephemeral host (`ARCHITECTURE.md` §"Broker placement across the cloud arms").

| Concern | AWS service | Why |
|---|---|---|
| Broker process (PEP/PDP) | **Lambda** behind **API Gateway** as the MCP proxy — or a sidecar process/container on EC2/Fargate | Separate-identity compute the agent's egress is pinned to. |
| **Separate identity** (invariant 3) | A distinct **IAM role** for the broker, never assumed by the agent | A code-exec bug in the harness can't reach the credential store. |
| Connector credentials (invariant 1) | **Secrets Manager** | Creds live only here; the agent role has no `secretsmanager:GetSecretValue`. |
| Grant / counter / intent / idempotency state | **DynamoDB** (on-demand, single-table) | Durable, external, atomic counters (caps can't be raced); survives an ephemeral host. |
| The WORM audit | **S3 Object Lock** (GOVERNANCE mode) | Append-only / write-once against the broker and agent roles; an administrator holding `s3:BypassGovernanceRetention` can still shorten retention, which COMPLIANCE would prevent and we deliberately do not use. Hash-chain on top, and the chain is unkeyed SHA-256 (`docs/posture-ladder.md`). |
| Approval-prompt push | **EventBridge / SNS** → the messaging channel | Notifier is separate from the agent; the human approves out-of-band. |
| Egress confinement (invariant 2) | Security group / subnet / VPC endpoints (EC2/Fargate); for Lambda, network-path scoping so the agent's only reachable tool surface is the broker | Enforced at the network layer, not in agent code. |

Non-sensitive config goes in **SSM Parameter Store**, sensitive creds in **Secrets Manager** (never
hardcoded). Environment naming is exactly `development` / `staging` / `production`.

## Build order

### Tier 0 — MVP, the 80% **[design-only]**

The minimum that moves enforcement out of the model and gives a real tape. Build this for **every**
agent; a low-risk agent can stop here.

1. **Broker holds the credentials.** Connector creds in Secrets Manager; the agent's IAM role cannot
   read them. (Invariant 1.)
2. **Agent egress restricted to the broker**, at the network layer. (Invariant 2.)
3. **Broker under a separate IAM identity.** (Invariant 3.)
4. **The static tool manifest** — classify every op's `effect`/`external`/`reversible` once, in
   code. (`SCHEMAS.md` BrokeredCall.)
5. **Default-deny on writes**; reads allow-by-scope. The pure `decide()` PDP, unit-tested against a
   case table.
6. **Capability-scoped tool lists per principal** — the PEP serves each principal only its granted
   tools (Grant gating); an ungranted tool never reaches `decide()`.
7. **Broker-emitted append-only audit** — write an `AuditRecord` to S3 Object Lock on every
   decision. (Hash-chaining is Tier 2; even a plain append-only tape beats agent-written logs.)

Proof-of-build: a red-team agent with a fully jailbroken prompt cannot read a connector cred, cannot
reach a connector except through the broker, and every attempt appears in the S3 tape.

### Tier 1 — approval queue + durable counters **[design-only]**

For any agent with an external write.

1. **Out-of-band approval (WYSIWYE).** `require_approval` materializes an `Intent` in DynamoDB
   (id, materializedRequest, expiry, status); the turn ends; a separate notifier (EventBridge/SNS)
   pushes the *materialized* bytes; the human approves on a path authenticated to them; the broker
   executes the **stored** request; unapproved intents auto-deny at expiry.
2. **Durable spend/rate counters** — DynamoDB atomic counters so two concurrent runs can't both slip
   under a cap. Idempotency keys enforced. (`Budgets`; pre-deploy checklist "caps are atomic
   counters.")

### Tier 2 — taint, tamper-evidence, real policy engine **[design-only]**

For agents reading untrusted inbound data.

1. **Taint tracking** — mark untrusted sources at ingestion, propagate through derived results, key
   the external-write-in-tainted-turn rule on it. (The prompt-injection cut.)
2. **Hash-chained audit** — add `prevHash`/`hash` over the Tier-0 tape; a deletion or edit becomes
   detectable, a gap in `seq` shows.
3. **A real policy engine** — move the ruleset to **Cedar** or **OPA/Rego** so policy is declarative,
   reviewed as code (the PAP), and unit-tested in CI (the policy test-table from the pre-deploy
   checklist).

### Tier 3 — the autonomy ratchet **[design-only]**

For agents graduating off "human approves every write." Implements `grant-lifecycle.md`:

1. **Autonomy level as stored per-class `Grant` state** in DynamoDB.
2. **Recorded maker-checker promotion** writing `PromotionRecord` (maker ≠ checker; sound,
   covered-distribution evidence).
3. **Automatic, deterministic, hysteretic demotion** on `budget_breach` (and, once Tier 4 exists,
   `stale_confidence` / `corroboration_failure`) — no model in the loop. **Drill it.**

### Tier 4 — high-stakes / adversarial only **[design-only]**

Build only when an adversary shapes what the agent sees, or actions draw on a scarce resource. Skip
for a benign personal-assistant load (Proportionality).

1. **Constructed confidence + drift detection** — self-consistency / ensemble / conformal as a
   deterministic PIP input (never a raw model logprob); distribution-watch sets `stale` → feeds the
   `stale_confidence` demotion trigger.
2. **Corroboration quorum** on inputs — k-of-n independent sources, physical/market sanity bounds as
   the cheapest independent source; failure feeds the `corroboration_failure` trigger.
3. **Robust-randomized allocation with auditable seeds** — the hard cap (envelope) stays
   deterministic; allocation *within* it is randomized (minimax/DRO) and the seed is committed and
   logged in the `AuditRecord` (commit-reveal / VRF).

## Pre-deployment checklist

Every agent adopting this broker must pass the checklist in `ARCHITECTURE.md` §"Pre-deployment
checklist" before going live — the three invariants, default-deny + capability-scoped registry,
external append-only audit, durable atomic counters, out-of-band approval with WYSIWYE, the
**per-domain safe-default polarity**, taint propagation, a drilled deterministic demotion path, a
passing policy test-table, and a named owner + signed promotion record per grant.

## Cross-references

- Mechanism + invariants: `README.md`
- Canonical schemas: `SCHEMAS.md`
- Autonomy state machine: `grant-lifecycle.md`
- Compute-mode placement (EC2 / Lambda-woken / Fargate): `../core/` (the substrate / cloud arms)
- Memory as a taint source: `../memory/`
