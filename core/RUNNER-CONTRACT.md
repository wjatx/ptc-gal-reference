# Runner Contract

The portable seam for **scheduled, unattended agent jobs** — agents that produce an artifact on a
cadence, run without a human present, and must not depend on any one machine being awake. This is
the **canonical platform copy** (the base owns it as substrate); it was first proven in a live
consumer agent and is designed to be reused by every agent that adopts the base.

The goal is a **thin seam, not a framework.** Standardize only what the *substrate* must see — how
a job is invoked, how secrets arrive, how output persists, how a run is recorded, how failure is
signaled. Everything *behind* the seam (the pipeline, the model orchestration, the quality gates)
is the agent's own business and may be as bespoke as its result demands. **We do not trade output
quality for portability:** if an agent's best result needs a substrate-specific snowflake, the seam
still standardizes its ops surface, and the agent is free to be a snowflake behind it.

## Two layers

- **Layer 1 — the runner contract (this document).** Mandatory, thin. The seven seam elements
  below. Satisfy them and the agent runs on any supported arm (always-on EC2, Lambda-woken EC2,
  Fargate) with a small adapter, observable uniformly.
- **Layer 2 — the quality-pattern kit.** Optional, rich. Reusable *internal* motifs (clean-room
  verify gate, maker≠checker acceptance, fan-out reasoning, the graduated-autonomy action gate). An
  agent reaches into it; it does not constrain the agent.

The boundary is the point: portability is enforced only at the seam; quality is unconstrained
behind it.

## The seam carries the broker, not just the job

This contract predates the broker but does not replace it. In safe-agents the seam carries one
extra invariant beyond the original seven: **whichever arm runs the entrypoint must co-place a
separate-identity broker and confine the agent's egress to it at the network layer** (see
`../ARCHITECTURE.md` → "Broker placement across the cloud arms" and `arms.md`). The seven elements
below describe how a *job* is operated portably; the broker invariants describe how its *actions*
are mediated safely. Both must hold for an agent to be deployable.

## The safety spine: graduated, evidence-gated autonomy

Not "the agent only proposes." An agent takes actions of varying blast radius, and **which actions
it may take alone is a line that moves with its track record.** Every irreversible action passes an
independent gate; the gate routes it to one of `autonomous` · `autonomous-with-reporting` ·
`hitl-queued` · `blocked`, chosen by **action class** and **current trust level**.

Three invariants make moving that line safe:

1. **The line is data, not code.** A versioned per-action-class policy (the grant lifecycle, owned
   by `broker/`). The run record logs which path each action took *and the policy version in
   force* — so "what was the agent allowed to do on date D" is auditable forever.
2. **Blast radius is bounded by a limiter the agent cannot override.** Enforced *outside* the agent
   — at the broker (hard caps, atomic counters), or in protected-branch CI it can't disable. Never
   let the agent be the thing that respects its own limits.
3. **Autonomous execution requires a deterministic predicate.** Auto-act only where "safe" is
   machine-checkable (tests green, request within caps, no protected path touched). Where it isn't
   checkable, it's HITL by construction. The track record is what earns moving a class from
   `hitl-queued` toward `autonomous`.

The seam **reserves** the action-authorization decision (element 5 logs it) so the line can move
without re-architecting — even for an agent that is all-`blocked` today.

---

## Layer 1 — the seven seam elements

A job conforms when it provides all seven.

### 1. One headless entrypoint
A single command runs the whole job to completion, non-interactively, **idempotent for a given
logical date** (safe to re-run). Exit codes are the contract:
- `0` — ran and acted (status `ok`).
- `0` + a `skipped-closed` run record — ran, no work (e.g. market closed).
- non-zero — failed (status `fail`).

Convention: `run.sh`, kept as the canonical entrypoint on every arm.

### 2. Secrets via environment, not files
Read configuration and secrets from **environment variables first**, falling back to a local `.env`
only for developer convenience. No host-specific paths baked in. This is what lets each arm's secret
store (EC2 SSM/Secrets Manager, Fargate Secrets Manager) inject the same way. **Under the broker
model the only secrets the agent env carries are non-connector** (model OAuth token, run-record
write creds); connector credentials never reach the agent — they live in the broker.

### 3. A cheap pre-flight gate
Decide early and cheaply whether there is work, and exit clean (the `skipped-closed` record) *before*
spending the expensive LLM pass. (Trading example: the Alpaca trading-day calendar check.)

### 4. Self-owned, declared output persistence
The job persists its own durable artifact and assumes **nothing about the filesystem surviving**.
The substrate supplies only write credentials (via env). Three sinks cover the family of agents:
- **git push** — committed, human-auditable artifacts.
- **notification** — a human-facing message (see element 6).
- **approval queue** — proposals queued for human disposition; structurally the same as a ledger
  the owner acts on.

### 5. A machine-readable run record → DynamoDB
Every run (success **or** failure) writes one structured record to a durable, arm-independent store,
so observability + the watchdog are uniform and the autonomy audit trail is permanent.

**Store:** DynamoDB, on-demand, PITR on. Table `safe-agents-<environment>-agent-runs`
(CDK `resourceName(env, "agent-runs")`; `development` / `staging` / `production` — never
`dev`/`prod`), provisioned in `infra/lib/state-stack.ts`.

```
agentId (HASH, S)  = "<job>"            e.g. example-agent   (no "JOB#" prefix)
runId   (RANGE, S) = "sched-<ISO-UTC>"  e.g. sched-2026-07-07T201608Z
                     for SCHEDULED runs; manual/proof runs use a distinct prefix,
                     so multiple records per civil day are expected.
attrs:
  status               "ok" | "skipped-closed" | "fail"
  arm                  "ec2" | "ec2-woken" | "fargate" | "local"
  ts                   ISO-8601 UTC (…Z) — the run's timestamp
  results              short human/structured summary of the run
  policy_version       autonomy-policy version in force this run
  action_dispositions  list of { action_class, decision, ref }
                       decision ∈ autonomous | reported | hitl_queued | blocked
  expires_at           optional epoch TTL for raw history rows
```

**Reader Query** (the watcher and any observability reader): to answer "did `<job>` complete a
healthy scheduled run for civil date `<D>`?", Query
`agentId = :job AND begins_with(runId, "sched-<D>")` — the sort-key prefix selects only that
day's scheduled runs (no scan, excludes manual/proof noise) — then take the latest by `ts`.
`ok`/`skipped-closed` are healthy; `fail` (or a missing record) alarms.
The core job stays stdlib — it always writes a **local** record too; the DynamoDB write is an
**adapter concern** (optional `boto3`, guarded; degrades to local-only when AWS isn't configured).
A job never *fails* because the run-record store is unreachable.

### 6. A notification seam
Human-facing messages go through one swappable interface; the job names the action ("notify"), not
the channel. Convention: `notify.sh`. (Telegram today; swap here, not in the job.)

### 7. A liveness signal — two independent forms
Liveness must be detectable by something **outside the arm being watched**, two ways that fail
independently:
- **Push ping** on healthy completion to an external uptime monitor — catches *total arm death* (the
  box never woke, the schedule never fired). Unset = no-op.
- **Pull check** of the DynamoDB run record by the external watcher — catches *ran-but-failed* /
  *did-not-run-on-a-due-day*, and gives history.

---

## The external watcher (shared across all agents)

A scheduled checker that lives **off** every arm, so it survives any one arm dying. **GitHub Actions
cron** is the home — arm-independent, free, adjacent to the repo.

- Runs daily, shortly after the latest possible completion time.
- For each agent that *should* have run today (consults the relevant calendar to avoid holiday false
  alarms), Queries `safe-agents-<env>-agent-runs` for `agentId=<job> AND begins_with(runId,
  "sched-<today>")` and takes the latest by `ts`.
- Pages (Telegram / GitHub issue) if no record is found or its `status` is not `ok`/`skipped-closed`
  (e.g. `fail`).

The universal cure for the laptop-off / box-asleep class of bug, written once, reused by every
agent. GitHub cron is UTC-only (±a few minutes drift); pick a UTC time safely after the run window
and document the DST caveat.

---

## Arm adapters (thin wrappers around the same job)

The job is identical; each adapter invokes the entrypoint, supplies secrets + write creds, co-places
the broker, and ships the run record. See `arms.md` for the full per-arm treatment.

- **Always-on EC2** — systemd timer → `run.sh`; broker as a local sidecar under its own role; agent
  confined to broker-only egress by a **confined netns + security group** (not OpenShell — arm64/
  x86_64 mismatch; see `PORTING.md`). Today's proven path.
- **Lambda-woken / scheduled EC2** — a scoped Lambda enqueues + wakes the box; same confinement while
  running. Proven (the consumer agent's airlock).
- **Fargate** — container with repo + Claude Code + `run.sh`; EventBridge Scheduler → `RunTask`;
  broker as a sidecar task; egress restricted by task networking. **Unbuilt.**

**Routing rule (quality drives the arm):** the richer an agent's multi-agent internals, the more it
favors a full-Claude-Code arm (EC2 / Fargate container) over a constrained one.

---

## Conformance checklist (per agent)

- [ ] Single headless entrypoint, idempotent per logical date, exit-code contract honored
- [ ] Secrets read from env first, `.env` fallback only; **no connector creds in the agent env**
- [ ] Cheap pre-flight gate before the expensive pass
- [ ] Output persisted by the job to a declared durable sink
- [ ] Structured run record written to `safe-agents-<env>-agent-runs` (local fallback always)
- [ ] Notifications go through the swappable seam
- [ ] Liveness: push ping + pull-checkable run record
- [ ] Registered with the external GitHub Actions watcher
- [ ] Action-authorization decision recorded (even if all `blocked`/`autonomous` today)
- [ ] **Broker co-placed for this arm; agent egress confined to it at the network layer**
