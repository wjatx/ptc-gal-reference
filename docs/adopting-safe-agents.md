# Adopting safe-agents — a guide for consuming agents

This guide is for a session that takes an existing agent — a daily trading agent is the worked
example throughout — and **refactors it to stand on the safe-agents platform**: hold no connector
credentials, route every side effect through the broker, declare a risk envelope, and pick a
substrate arm — so the agent
becomes *configuration* on a trusted floor, not re-implemented mechanism.

Read `ARCHITECTURE.md` and `broker/SCHEMAS.md` in this repo alongside this guide. For the concrete
**install-and-invoke** mechanics — how your repo pins the SDK as a git dependency, what it exposes,
and how the pipeline resolves *your* agent package from *your* path — see `docs/consuming-the-sdk.md`.

---

## 1. The one idea

> **The agent holds no connector credentials. Its only egress is the broker. The broker decides
> every call, injects the credential itself, executes, and writes a tamper-evident audit under a
> separate identity. A fully compromised agent can still only *ask*.**

Everything below is machinery in service of that sentence. If a change would let the agent reach a
connector directly, or hold a connector secret, it's wrong.

## 2. What the platform gives you (so you don't rebuild it)

- **Four substrate arms**, all behind one runner contract. Current live-proven status against the
  nine-gate bar in §7 (as of 2026-07-01):
  - `fargate` — scale-to-zero burst task (EventBridge → RunTask). **Fully proven live, G1–G9**
    (confined agent → broker → `claude -p` + a real brokered call → run record → S3 audit, plus the
    scheduler-fire). This is the most complete reference.
  - `local` — a confined container on a Mac/edge device (Podman), same broker mediation locally.
    **Fully real / proven** (the reference implementation of the whole stack; local audit is not
    tamper-evident without off-device sync — documented).
  - `ec2-woken` — a **sleeping** box woken by an event: API Gateway → guardrail Lambda (the
    "airlock") → SQS + `StartInstances`; the box drains the queue, runs, and sleeps. Cheapest for
    bursty inbound. **Fully proven live, end to end** (sa#34): guardrail (200/4xx/injection/dedup)
    → wake → drain a real message → confined brokered run (model + a brokered tool call via the
    broker) → run record → self-stop.
  - `ec2` — always-on scheduled box (systemd timer). Confinement (netns) proven; the real-broker
    on-box round-trip (G9) is proven on the EC2 substrate via the ec2-woken box, which is itself a
    confined EC2 instance routing to the broker service (sa#98).
- **The broker** — the deterministic decision + audit engine. Deployed as a **persistent service**
  (the two-box topology): one broker box per environment holds the connector creds and reaches the
  outside world; confined agents route to it at `broker.safe-agents.local`.
- **The runner contract** — the 8-element harness every agent run satisfies (identity, run record,
  etc.); see `core/RUNNER-CONTRACT.md`.
- **The pipeline** — `provision → deploy → smoke` per arm, plus tagged, idempotent, zero-orphan
  teardown.
- **The infra floor** (CDK) — VPC (isolated agent subnet + NAT broker subnet + VPC endpoints), the
  DynamoDB tables (grants/counters/intents/agent-runs, single-table `pk`/`sk`), the S3 Object Lock
  audit bucket, KMS, and the two IAM identities: **agentRole** (zero connector authority) and
  **brokerRole** (the sole holder of connector creds + audit write).

## 3. Choose an arm

| Your workload | Arm | Why |
|---|---|---|
| Runs on a schedule (daily/cron), can scale to zero | **`fargate`** | EventBridge Scheduler → RunTask; pay only for the minutes it runs |
| Bursty / stateless, scale-to-zero | `fargate` | per-second billing, no box to manage |
| Reacts to inbound events, should sleep when idle | `ec2-woken` | airlock wakes it (see caveat below) |
| Long-lived / always-on, needs a persistent box | `ec2` | simplest; systemd timer |
| Must run on-device / data can't leave the machine | `local` | same broker mediation, local backends |

**The example agent** does a **daily scheduled run** → **`fargate`** is the fit. Scheduling is *native*
to the arm: `fargate_provision` takes a `schedule_expression` + `timezone` and wires an
**EventBridge Scheduler rule → ECS RunTask** — RunTask is a first-class scheduler target, so you
need **no separate EventBridge-event-plus-Lambda** to kick it off. A daily run is just:

```python
fargate_provision(manifest, aws, environment="production",
                  schedule_expression="cron(0 13 * * ? *)",   # e.g. 13:00 daily
                  timezone="America/New_York")
```

Each day the scheduler launches a fresh, confined RunTask → broker round-trip → run record → it
exits (scale-to-zero; cheaper than an always-on EC2 idling 23h/day). This is **proven live** —
a scheduler-fired RunTask ran the full capstone end-to-end (sa#103, sa#36).

> **When to use `ec2-woken` instead:** only for *event-driven* wakes (an inbound webhook/message
> should boot a sleeping box, stay warm through the exchange, and sleep when idle). A daily
> *scheduled* agent doesn't need the airlock at all. The full ec2-woken loop is proven live (sa#34),
> so it's ready when you want the warm-box conversational UX — the example agent, being scheduled today,
> just doesn't need it yet.

## 4. Write a manifest

An agent is a manifest (`agents/<name>.yaml`) — a name, an arm, an `inbound:` block (for woken), and
the grants/envelope. The manifest is the risk envelope; the mechanism is the platform. See
`agents/smoke-woken.yaml` and `agents/smoke-fargate.yaml` for minimal working examples.

For a woken agent, the `inbound:` block carries the **normalized** contract — the airlock is
channel-agnostic and sees only `{owner, message_id, text}`. The **channel adapter** (Telegram →
normalized) lives in *your* agent's inbound block, never in the platform stack (that's the
decoupling rule — zero `telegram`/`chat_id` strings reach the airlock).

## 5. Route through the broker (the refactor that matters)

Today the example agent calls connectors (Alpaca, Telegram) directly with its own keys. To adopt:

1. **Remove every connector credential from the agent.** The agent process gets exactly its model
   token (`CLAUDE_CODE_OAUTH_TOKEN`, injected from Secrets Manager by *secret id*, never plaintext)
   and nothing else.
2. **Replace direct connector calls with brokered calls.** Instead of `alpaca.submit_order(...)`,
   the agent POSTs to the broker's tool-call API (`broker.safe-agents.local:8080/call`) with
   `{tool, op, args, idempotency_key}`. The broker decides (allow / deny / transform /
   require_approval / abstain), injects the Alpaca credential itself, executes, audits, and returns
   a result the agent never sees the secret behind.
3. **Model inference goes through the broker proxy** (`HTTPS_PROXY=http://broker.safe-agents.local:8443`)
   — a domain-allowlisted forward proxy, so even the model call is on the broker's egress path.
4. **Declare grants.** Each `(principal × action-class)` the agent may perform is a **Grant** written
   by the promotion flow (maker-checker, `promotionRole`) — the broker only *reads* grants. An
   op with no grant is *removed from the served registry*, not merely refused.

The broker's contract is the **seven schemas** (Grant · BrokeredCall · Decision · Intent ·
AuditRecord · Budgets · PromotionRecord) in `broker/SCHEMAS.md`. The five **decision verbs**
(allow/deny/transform/require_approval/abstain) are orthogonal to the grant **level**
(in-loop / on-loop / out-of-loop). **Never bake the safe-default polarity into the platform** — it's
re-derived per agent (abstain-is-safe for a trading agent that shouldn't act on doubt;
positive-safe-action elsewhere).

## 6. Add a real connector

A connector is the one place credentials live, and it lives with the broker, never the agent.
Implement the `Connector` protocol (`execute(tool, op, args, credential) -> result`); the broker's
`Doer` fetches the credential from Secrets Manager at call time and passes it in — the credential
never leaves that function scope, never reaches the audit record (args are hashed to `argsDigest`),
and never reaches the agent. See `safe_agents/connectors/github_connector.py` for a real read-only
example of a shared connector (the pattern the example agent's agent-owned Alpaca connector should follow;
see `safe_agents/connectors/README.md` for the shared-vs-agent-owned split).

## 7. Provision + prove it

```
# per-agent, via the installed console entrypoint (dry-run first):
safe-agents agents/<name>.yaml --env development --dry-run
safe-agents agents/<name>.yaml --env development                  # live
# teardown (tagged, zero-orphan):
safe-agents agents/<name>.yaml --env development --phase teardown
```

(`safe-agents` is the console script the package installs; it's equivalent to
`python -m safe_agents.pipeline.cli`.) Each arm's provision lives in `safe_agents/arms/<arm>/provision.py`
(the woken box in `safe_agents/arms/ec2_woken/box_provision.py`). The **nine-gate bar** each arm clears
(provision · bootstrap-clean · egress-confinement · model-via-broker · runner-contract · zero-orphan
teardown · tests+capstone · egress-drift · real-broker round-trip) is the acceptance you're
inheriting, already proven live.

## 8. The confinement you get for free

- **Network:** the agent runs in an isolated subnet (no NAT) with a security group whose egress is
  the broker + the specific AWS endpoints it legitimately needs (DynamoDB/S3 gateway endpoints;
  SQS/Secrets Manager interface endpoints for a self-managing woken box) — never the internet or a
  connector host directly. Local/EC2 boxes add a container/netns blackhole. The smoke-egress
  assertions prove the connector/model paths are closed except through the broker.
- **Identity:** the agent's IAM role has *no* connector-secret access (`*/connectors/*` is
  broker-only); the broker runs under a separate `brokerRole`. Two identities, enforced by AWS.
- **Audit:** every attempt — allow, deny, *and connector failure* — lands on a hash-chained,
  Object-Lock (WORM) audit tape written under the broker's identity. The agent can't read or forge it.
- **Operational safety net:** a woken box is expected to wake, run, and sleep in minutes; a
  scheduled ops check alerts (Telegram) on any safe-agents EC2 running > 3h (a hung box), and the
  box self-stops on a max-lifetime timer — so a stuck run is both surfaced and cost-bounded.

## 9. Adoption checklist for the example agent

- [ ] Pick the arm: **`fargate`** (daily scheduled run, scale-to-zero). Provision with
      `schedule_expression` (a daily cron) + `timezone` — the arm wires EventBridge Scheduler →
      RunTask; no separate Lambda needed.
- [ ] Write `<your-repo>/agents/<agent>.yaml` (arm: fargate + the daily schedule).
- [ ] Strip Alpaca/Telegram credentials from the agent; the agent keeps only its model token.
- [ ] Add an Alpaca `Connector` to the broker (credential from Secrets Manager under
      `<agent>/connectors/alpaca`, brokerRole-readable only). If the example agent also *sends* Telegram,
      that's a broker connector too (or a brokered notify op) — not an agent-held token.
- [ ] Replace direct trades/messages with brokered `/call`s (`idempotency_key` per intent).
- [ ] Declare grants for the trading action-classes via the promotion flow; set the agent's
      **safe-default = abstain** (don't act on doubt).
- [ ] Provision + run the smoke capstone; confirm smoke-egress passes, a brokered trade round-trips
      with an audit record, the daily schedule fires a RunTask, and the agent holds no secret.
- [ ] Retire the agent-local scheduling/creds once the Fargate schedule + broker cover them. (Keep
      your own inbound-airlock stack only if you later add an event-driven wake path — see the
      ec2-woken note.)

## 10. The all-Fargate conversational pattern (daily message + replies)

The example agent isn't just a daily job — it sends a daily Telegram message and you **reply to steer
it** (ask for elaboration, and soon, have it take actions). That's *two triggers on the same
confined Fargate agent*, both scale-to-zero. Here's the end-to-end wiring, entirely on proven
pieces (the only cost is ~1-min cold-start per turn; if that ever bites, the `ec2-woken` warm-box
arm is the upgrade — same manifest, same broker refactor).

```
  DAILY (push):
    EventBridge Scheduler  --cron(daily)-->  RunTask (confined Fargate agent)
        agent builds the stock digest, sends it via the broker's Telegram connector, exits.

  REPLY (pull, per message):
    You reply in Telegram
        --> Telegram webhook --> API Gateway --> AIRLOCK guardrail Lambda
              (verify token · allow-list YOU as owner · injection-screen · dedup on message_id)
        --> ecs:RunTask   (NOT StartInstances/SQS — the guardrail targets RunTask for the
                           all-Fargate path; RunTask is a first-class target just like the scheduler)
        --> a fresh confined Fargate task runs ONE turn:
              1. load conversation context from the session store (DynamoDB, keyed by chat_id)
              2. treat your message as DATA (never an instruction to obey blindly)
              3. do the work through the BROKER: claude -p via the model proxy, and any
                 action (a trade, a data pull, the reply itself) as a brokered /call
              4. send the reply via the broker's Telegram connector
              5. persist the updated context; exit (scale-to-zero)
```

**What's already proven** (reuse as-is): the scheduler → RunTask path (sa#36/#103); the airlock
guardrail's screen/allow-list/dedup (sa#34); the confined agent → broker round-trip + run record +
audit (sa#36/#39).

**What you build for this pattern** (small, all on the platform's grain):
- **Guardrail → RunTask target.** Today the airlock guardrail targets SQS + `StartInstances` (the
  woken-box path). For all-Fargate, point it at `ecs:RunTask` instead, passing the normalized
  `{owner, message_id, text}` as container overrides (env). One IAM statement (`ecs:RunTask` +
  `iam:PassRole` on the agent/exec roles) and a target swap — the screening logic is unchanged.
- **Session store.** A DynamoDB table keyed by `chat_id` (+ a turn/thread id) holding the running
  conversation context, so each stateless task reloads the thread. Single-table `pk`/`sk` like the
  rest of the floor. The daily digest seeds the thread; each reply appends.
- **Telegram as a broker connector.** *Outbound* Telegram (the digest + the replies) is a
  **brokered `notify` op**, not an agent-held bot token — the bot token lives with the broker under
  `<agent>/connectors/telegram`, and the agent only asks the broker to send. This keeps the "agent
  holds no creds" invariant even for its own channel. (The *inbound* Telegram→normalized adapter
  stays in the manifest's `inbound:` block, per §4.)

**Idempotency + safety carry straight over.** The guardrail's `message_id` dedup means a
Telegram/webhook retry can't double-trigger a turn; each brokered action uses an `idempotency_key`
(e.g. `chat_id:message_id`) so a re-run can't double-trade; and the agent's **abstain-is-safe**
default means an ambiguous instruction from a reply is refused, not guessed. A reply that asks for a
trade the grants don't cover is simply not in the served registry — the broker can't be talked into
it.

**Latency note.** Each reply cold-starts a task (~30–60s). Fine for an async Telegram exchange;
if you later want snappy multi-turn, move the *reply* trigger to `ec2-woken` (guardrail →
`StartInstances`, box stays warm through the exchange, sleeps when idle) — the daily push stays on
the scheduler, and nothing else changes.

The result: the example agent becomes a manifest + a domain connector + a risk envelope on top of a
proven, confined, audited floor — and every other agent you build afterward is the same shape.
