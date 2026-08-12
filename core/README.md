# core — the substrate

`core/` owns the **substrate**: how a trusted-autonomy agent gets provisioned, deployed, run,
and observed — independent of what the agent *does*. The `broker/` is the architectural center
(see `../ARCHITECTURE.md`); `core/` is the ground the broker and agent stand on, and the seam
that keeps an agent portable across compute modes.

Four things live here:

1. **The runner contract** (`RUNNER-CONTRACT.md`) — the thin portable seam. Satisfy its seven
   elements and an agent runs on any supported cloud arm with a small adapter, observably and
   uniformly. This is platform, not agent-specific; `core/` holds the canonical copy.
2. **The three cloud arms** (`arms.md`) — always-on EC2, Lambda-woken/scheduled EC2, and Fargate.
   The compute mode changes *where the broker process sits*, never the invariants.
3. **The agent pipeline** — provision → deploy → smoke, operated from a workstation/CI, driven by
   a per-agent manifest. No monolith; each stage is an idempotent script keyed by instance id +
   agent name.
4. **The per-agent manifest/envelope schema** (`manifest-schema.md`) — one declarative file per
   agent: its repo, secrets, policy, smoke test, **the cloud arm it runs on**, and its risk
   **envelope** (caps, allowlists, reversibility classes, abstention thresholds, fallback budgets,
   input-trust map, promotion predicates, and the re-derived safe-default polarity).

`PORTING.md` is the reference-and-re-derivation plan: the proven development-harness and
consumer-agent patterns, how each is re-derived clean in `core/`, and what is net-new. **This pass is design +
scaffold + re-derivation plan — not working implementations.**

## The broker sits in every arm — that is the point

`core/` does not get to relax the broker invariants because a given compute mode is convenient.
In **every** arm the substrate must place a **separate-identity broker** between the agent and the
world:

- The **agent holds no connector credentials**; they live only in the broker's secret store.
- The **agent's only egress is the broker**, enforced at the **network layer** (security group /
  subnet / sandbox egress policy) — never in code the agent runs. (The agent's own model inference
  to `api.anthropic.com` is not a connector; the broker mediates *tools/actions*, not the brain.)
- The **broker runs under a separate IAM identity** from the agent — different role, ideally a
  different process / container / task.

The arms differ only in *where the broker process physically sits* and *how egress confinement is
spelled*:

| Arm | Broker placement | Agent→broker egress confinement | Durable state |
|---|---|---|---|
| **Always-on EC2** | separate local process / sidecar under its own IAM role | agent in a **confined netns** whose only outbound route is the broker (security-group enforced) | DynamoDB / S3 Object Lock — off-box |
| **Lambda-woken / scheduled EC2** | same as above while running; the waking Lambda is a scoped principal carrying no connector creds | same confined netns; Lambda only enqueues + wakes | same — survives the box sleeping |
| **Fargate** | separate task / sidecar container, per-container task-role | agent container egress restricted by task networking (awsvpc + security group) to the broker task | same — never on the task's ephemeral disk |

OpenShell is reserved for the **dev-box arm only** (x86_64/RHEL environment); it is not the confinement mechanism for autonomous agent arms. See `PORTING.md` §Open questions for the arm64/x86_64 forcing reason.

The rule the substrate enforces uniformly: **durable state (grants, counters, intents, audit)
always lives outside the compute**, so it survives restart and the audit can't die with an
ephemeral host. An arm is only "supported" once it can place the broker this way and confine the
agent's egress at the network layer.

## How an agent declares its arm

An agent is a manifest (`agents/<name>.yaml`) + a per-agent egress policy + its own git repo.
The manifest's `arm:` field selects the compute mode; the pipeline and the chosen arm's adapter
read it. The same `run.sh` entrypoint runs unchanged on every arm — only the adapter around it
(how secrets arrive, how the broker is co-placed, how the run record ships) differs.

```
seed-agent  →  provision-agent-host  →  deploy-agent  →  smoke-agent      →  (teardown)
(secrets)      (a host for the arm)     (agent + broker   (prove it runs,
                                         on the host)      confined to broker)
```

See `manifest-schema.md` for the full manifest + envelope, `arms.md` for what is built vs unbuilt
per arm, and `PORTING.md` for where each piece comes from.

## Status (2026-06-28)

Scaffold + design. The runner contract and the provision/deploy/smoke pipeline are **proven** in a
development harness (driving a consumer agent); the always-on and Lambda-woken EC2 arms **exist** in
that consumer agent as reference patterns and are re-derived here. **Fargate is unbuilt.** The broker-
per-arm placement is the net-new substrate work this base adds on top of the reference patterns —
those arms confine egress to a *connector allowlist*, not to a broker; closing
that gap is the first substrate milestone (see `PORTING.md` and the open questions there).
