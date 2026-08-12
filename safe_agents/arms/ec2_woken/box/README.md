# ec2-woken box — the wake → drain → run → sleep loop (sa#98)

This directory is the **box side** of the ec2-woken arm: the confined EC2 agent box that the
inbound airlock (`../airlock.yaml`, `../provision.py`) wakes. Where the airlock decides *whether
to wake*, the box does the work — then puts itself back to sleep.

```
airlock Lambda ──ec2:StartInstances──▶  BOX boots
                                          │
                          systemd: responsive-agent-ready.service
                                          │
                        emit-runner-ready.sh   (readiness marker)
                                          │
                              drain.sh  ── loop ──▶  poll SQS (long-poll 20s)
                                          │              │
                                          │      valid  ─┤─▶ run-brokered.sh  (confined + brokered turn)
                                          │      poison ─┤─▶ delete (never reprocess)
                                          │      empty  ─┘─▶ idle_polls++
                                          │
                          idle_polls == IDLE_POLLS  ──▶  aws ec2 stop-instances (SELF) ──▶ SLEEP
```

## Confinement — topology, not netns

The woken box uses **topology confinement like the Fargate arm**, not an in-box netns. It runs in
the **isolated agent subnet** on the **agent SG** whose only egress route is the broker service
`broker.safe-agents.local`. The box holds **no connector credentials**; its only egress is the
broker. A fully compromised box "can still only ask". The broker runs separately as its own
service (the woken box is a pure agent, so — unlike the always-on EC2 arm — it does not co-host
the broker proxy and therefore does not need the broker subnet).

## The two-identity split — what the box role may do

The box reuses the IdentityStack base `agentRole` (zero connector authority) via a per-box
instance profile, plus ONE inline policy carrying **exactly**:

| Action | Resource | Why |
|---|---|---|
| `sqs:ReceiveMessage` / `sqs:DeleteMessage` | the ONE airlock inbound queue | drain the wake queue |
| `ec2:StopInstances` | instances tagged `Agent=<agent>` + `Arm=ec2-woken` (== self) | sleep when idle |
| `dynamodb:PutItem` | the agent-runs table | write a run record per message |
| `kms:GenerateDataKey` / `Decrypt` / `DescribeKey` | the tables CMK | the run-record table is CMK-encrypted |
| `secretsmanager:GetSecretValue` | the box's OWN oauth-token secret | the model brain (not a connector) |

**No `*/connectors/*`, no bare `*` resource, no secrets wildcard** — asserted in
`../tests/test_ec2_woken_box.py::TestBoxRoleHoldsNoConnectorCreds`. Connector credentials live
only in the broker store; the box asks the broker for every real tool/connector call.

## The drain loop (`drain.sh`)

Poll → run → delete → idle-sleep:

1. **poll** the airlock SQS queue (`aws sqs receive-message`, 20s long-poll).
2. **parse** via `drain_logic.py` — a valid `{owner, message_id, text}` event, a poison
   (present-but-malformed body), or an empty poll.
3. valid → **run** `run-brokered.sh` with the message text as `TASK_TEXT` (DATA, never obeyed as
   instructions) and a `RUN_ID` derived from the message id; then **delete** the message.
   *Delete-after-attempt*: exactly one attempt per message, whatever the outcome, so a poison or
   repeatedly-failing message can never wedge the box in a loop (no DLQ is wired; a loud log is the
   record). Poison → delete + keep draining. Empty → increment the idle counter.
4. after `IDLE_POLLS` (default 3) consecutive empty polls → **self-stop**: read the own instance
   id from IMDSv2 and `aws ec2 stop-instances`. The box sleeps until the next wake.

Every `aws` call strips `HTTPS_PROXY` (the broker allowlist is the model API only; the AWS control
plane — SQS, EC2-stop, IMDS — goes direct via the VPC endpoints).

## The per-message runner (`run-brokered.sh`)

Same shape as the Fargate runner (`safe_agents/arms/fargate/run.sh`) but the task comes from an SQS
message instead of a fixed prompt. Per message it: points `HTTPS_PROXY` at the broker; optionally
runs the four smoke-egress assertions (`SA_RUN_SMOKE=1`); runs `claude -p "<message text>"` through
the broker proxy; makes a brokered `github.whoami` tool call (proving the broker path with no creds
on the box); and writes a run record (`agentId`, `runId`, `status`, `arm=ec2-woken`, `messageId`,
`results`) to the agent-runs table. Output is line-buffered (`stdbuf`) so logs survive an abrupt
stop.

## Env contract (`/etc/safe-agents/agent.env`, written by `box_provision.py`)

| Var | Consumed by | Meaning |
|---|---|---|
| `AGENT_NAME` | both | agent id (run-record PK, readiness marker) |
| `SA_BROKER_DNS` | both | broker DNS (`broker.safe-agents.local`) |
| `SA_MODEL_PROXY_PORT` / `SA_TOOL_API_PORT` | run-brokered | broker model-proxy / tool-API ports (`8443` / `8080`) |
| `AGENT_RUNS_TABLE` | both | agent-runs DynamoDB table (run records) |
| `INBOUND_QUEUE_URL` | drain | the airlock SQS queue to drain |
| `AWS_DEFAULT_REGION` | both | region for the aws CLI |
| `IDLE_POLLS` | drain | consecutive empty polls before self-stop (default 3) |
| `SA_OAUTH_SECRET_ID` | run-brokered | Secrets Manager id of the model oauth token (resolved at runtime; NOT stored plaintext) |
| `RUN_ID` / `MESSAGE_ID` / `TASK_TEXT` | run-brokered | set per message by drain.sh |

`drain.sh` derives `RUN_ID`/`MESSAGE_ID`/`TASK_TEXT` per message and passes them into
`run-brokered.sh`; `run-brokered.sh` resolves `CLAUDE_CODE_OAUTH_TOKEN` from `SA_OAUTH_SECRET_ID`
if it is not already in the environment.

## Provision / teardown (`../box_provision.py`)

- **`ec2_woken_box_provision(manifest, aws, *, environment, region, instance_type, image_id, idle_polls)`**
  — resolves the infra exports (agent subnet + agent SG, agent-runs table, tables CMK, broker DNS),
  ensures the per-box instance profile + the box inline policy, renders user-data (which installs
  the drain loop + systemd unit + `agent.env`), launches the box in the agent subnet on the agent
  SG (IMDSv2-only), and returns the instance id (the airlock's `RunnerInstanceId`).
- **`ec2_woken_box_teardown(manifest, aws, *, environment)`** — terminates the box (by tags) and
  removes the per-box instance profile + inline policy. Idempotent; never touches the airlock stack
  or any `infra/` floor resource.

The box uses the airlock's **deterministic** queue name
(`safe-agents-<env>-<agent>-airlock-inbound`), so there is no deploy cycle: provision the box
first, then deploy the airlock with `RunnerInstanceId` = the returned box id.

## Deploying a live loop (deployer steps)

1. **Provision the box:** `ec2_woken_box_provision(...)` → note the returned instance id.
2. **Deploy the airlock** (`ec2_woken_provision`) with `runner_instance_id` = that id.
3. **POST** a normalized `{owner, message_id, text}` event (with the shared-token header) to the
   airlock `InboundEndpointUrl`.
4. **Watch:** the guardrail wakes the box → systemd runs `drain.sh` → it drains the message and
   runs `run-brokered.sh` → a run record appears in the agent-runs table (`arm=ec2-woken`,
   `messageId=<id>`) → after `IDLE_POLLS` empty polls the box `stop-instances` itself and sleeps.
