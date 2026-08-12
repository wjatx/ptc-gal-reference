# The three cloud arms

An **arm** is a compute mode an agent can run on. The runner contract (`RUNNER-CONTRACT.md`) keeps
the *job* identical across arms; an arm is the thin adapter around `run.sh` plus the answer to two
substrate questions: **where does the broker process sit**, and **how is the agent's egress confined
to it at the network layer**. The compute mode changes those two things and nothing about the
invariants (`../ARCHITECTURE.md` → "Broker placement across the cloud arms").

Three rules hold in **every** arm:

1. Durable state — grants, counters, intents, **audit** — lives **outside** the compute (DynamoDB /
   S3 Object Lock), so it survives restart and the audit can't die with an ephemeral host.
2. The broker runs under a **separate IAM identity** from the agent.
3. The agent's **only egress is the broker**, enforced at the network layer — not in agent code.

An arm is "supported" only once it can satisfy all three. Today two arms are proven in a consumer
agent's live deployment and serve as reference patterns here; one arm is unbuilt. **Honest status:** the reference
implementations confine egress to a *connector allowlist* (Anthropic + Alpaca + Telegram + Tavily),
which is the pre-broker model — closing the gap to *broker-only* egress is the first substrate
milestone, tracked in `PORTING.md`.

---

## Arm 1 — Always-on EC2

**Status: proven (a consumer agent, reference pattern). Re-derived here.** A small always-on box runs
the same `run.sh` on a systemd timer, authenticating Claude Code with a subscription OAuth token
(flat billing). The natural home for any *persistent / intraday* component an agent's roadmap adds.

**Egress confinement on this arm is a confined netns + security group**, not OpenShell. The arm
runs arm64 Amazon Linux; OpenShell requires x86_64 + RHEL. OpenShell is the dev-box arm's
confinement — not the agent-arm enforcement mechanism. See `PORTING.md` §Open questions.

| Aspect | Proven pattern (the consumer agent, for reference) | Target under the broker model |
|---|---|---|
| Compute | t4g.small Amazon Linux 2023, IMDSv2-only, SG egress-only, SSM access (no inbound) | unchanged |
| Schedule | `example-agent.timer` → `run-agent.sh` (fetch secrets → export contract env → `run.sh`) | unchanged |
| **Broker placement** | *none — agent calls connectors directly over the egress allowlist* | **separate local process / sidecar under its own IAM role**; agent in a **confined netns** whose only outbound route is the broker |
| Egress confinement | security group allowlisting connector hosts (pre-broker model) | **confined netns** policy allowlists only the broker endpoint + `api.anthropic.com`; enforced at the network layer, not in agent code |
| Identity | one instance role (`dynamodb:PutItem` on `agent-runs-*`, `secretsmanager:GetSecretValue` on `<agent>/*`, SSM core) | **two** roles: agent role (run-record write + model token) and broker role (connector secrets); split process/identity |
| Durable state | DynamoDB `agent-runs-*` off-box; git push-back for artifacts | unchanged (already external) |
| Secrets | fetched on-box via instance role, exported into the run env | connector secrets move to the **broker's** store; agent env keeps only non-connector + OAuth token |

Bootstrap is `user-data.sh` (cloud-init): installs git/node/python + Claude Code CLI + a boto3
venv, clones the repo via the deploy key, writes `run-agent.sh` and the timer. One manual step: the
subscription OAuth token can't be minted headless (`claude setup-token` → put into Secrets Manager;
expires yearly).

**Reference pattern:** the consumer agent's EC2 bootstrap directory (`user-data.sh` and its README).
**Re-derived clean:** the bootstrap is generalized to take agent name / repo / arm from the
manifest instead of being agent-specific, and a broker-sidecar bootstrap block is added (net-new).

---

## Arm 2 — Lambda-woken / scheduled EC2

**Status: proven (a consumer agent's responsive-agent airlock, reference pattern). Re-derived here.**
Same EC2 box, but woken on demand by an event rather than (or in addition to) a timer — the
event-driven path behind the two-way / responsive agent. A scoped Lambda is the front door; the
box does the work.

The consumer agent's shape (the inbound airlock): Telegram → API Gateway → **guardrail Lambda**
(verifies the Telegram secret-token header, allow-lists the owner, dedupes on `update_id`, screens
+ classifies with Bedrock Haiku) → queue + **wake the runner** (or emit a `RunnerReady` event if
it's already up) → a **command-sender Lambda** drains the queue and dispatches a read-only worker
over SSM, which replies via `notify.sh`.

| Aspect | Proven pattern (airlock, for reference) | Target under the broker model |
|---|---|---|
| Trigger | API Gateway → guardrail Lambda → SQS → wake EC2 (`emit-runner-ready.sh`, `responsive-agent-ready.service`) | unchanged shape |
| **Waking Lambda** | a scoped principal; screens input, carries no creds to the box | unchanged — **and must carry no connector creds**; it only enqueues + wakes |
| **Broker placement** | *none — same direct-connector model as Arm 1 while running* | **same local sidecar as Arm 1** while the box is up |
| Egress confinement | the read-only worker (`respond.sh`) is structurally denied Bash/Write/Edit + secret-scrubbed env | net-layer broker-only egress, same as Arm 1; the `respond.sh` structural gate stays as defense-in-depth |
| Durable state | DynamoDB interactions table (dedupe), SQS queue | unchanged |

The Lambda-woken arm is where **input trust** earns its keep: inbound messages are `untrusted` in
the envelope's `input_trust_map`, and the guardrail Lambda is the taint boundary. Phase 1 is
read-only Q&A; the broker is what would let it safely take *actions* later without trusting the
inbound channel.

**Reference pattern:** the consumer agent's SAM inbound-airlock stack, plus its
`emit-runner-ready.sh` and `responsive-agent-ready.service` units. **Re-derived
clean:** Telegram→owner specifics generalized into a manifest-driven inbound config; the
guardrail/dedupe/screen pattern retained.

---

## Arm 3 — Fargate

**Status: UNBUILT.** In reserve for burst / scheduled batch where you don't want an always-on box.
ECS clusters are free — pay only per-second of task runtime. No consumer-agent code exists for this;
it is designed here, not ported.

| Aspect | Design target |
|---|---|
| Compute | a task definition: container with repo + Claude Code + `run.sh`; sized per agent |
| Schedule | EventBridge Scheduler → `RunTask` (cron + timezone) for scheduled agents; or invoked on an event for burst |
| **Broker placement** | a **separate sidecar task / container** with its own **task role**; the agent container has a different task role |
| Egress confinement | agent container egress restricted by **task networking** to the broker task only (awsvpc mode, security group / no NAT route to connectors) |
| Durable state | DynamoDB + S3 Object Lock, off-task (the task disk is ephemeral by definition — nothing durable may live there) |
| Secrets | Fargate Secrets Manager integration; connector secrets to the broker task, OAuth token to the agent task |

**Why it's attractive:** the per-container task-role boundary makes the "separate IAM identity" and
"egress confined to the broker" invariants *natural* rather than bolted-on — arguably the cleanest
arm for the broker model, which is why it's worth building even though the EC2 arms work today.

**Why it's deferred:** no proven bootstrap, and the heavy-fan-out quality routing rule
(`RUNNER-CONTRACT.md`) means agents with rich multi-agent internals may prefer a long-lived
container anyway. Build it when an agent actually needs burst/scheduled-batch economics, or as the
reference implementation of broker-per-arm done cleanly.

---

## Choosing an arm (the `arm:` manifest field)

- **`ec2`** — always-on or has a persistent/intraday component; flat-billing OAuth; lowest lift.
- **`ec2-woken`** — needs a responsive / event-driven front door (inbound Q&A, webhooks) on top of
  (or instead of) a schedule.
- **`fargate`** — pure scheduled/burst batch, no persistence, wants per-second billing and the
  clean per-task identity boundary — once built.

All three run the identical `run.sh` and satisfy the same seven seam elements; the manifest's `arm`
just selects the adapter. Durable state and the broker live outside the compute in every case.
