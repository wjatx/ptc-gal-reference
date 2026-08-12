# ec2-woken arm — inbound airlock wake path (Arm, sa#34)

The ec2-woken arm is an **event-driven WAKE mechanism** for a *sleeping* EC2 agent box.
An inbound event does not run the agent directly — it passes through an untrusted-input
**airlock** that screens it and, only on pass, wakes the box and hands the event off.

```
normalized inbound event                 AWS
{owner, message_id, text}  ──POST──▶  HTTP API  ──▶  guardrail Lambda  ──▶  SQS (inbound)
   (a consuming agent's                 webhook        (taint boundary,        │
    channel adapter emits                              no connector creds)     ├─▶ ec2:StartInstances
    this shape — out of scope)                                                 │      (wake the box)
                                                                               ▼
                                                        the box drains SQS on wake
                                                        (box/responsive-agent-ready.service)
```

## The guardrail is a taint boundary that holds NO credentials

The Lambda is the load-bearing safety property of this arm. It carries **no connector
credentials** and its execution role grants **only**:

| Action | Resource | Why |
|---|---|---|
| `ec2:StartInstances` | the ONE `RunnerInstanceId` | wake the box (starting a running box is a safe no-op) |
| `sqs:SendMessage` | the ONE inbound queue | enqueue the accepted event for the box to drain |
| `dynamodb:PutItem` | the dedup table | conditional put for message-id idempotency (no read needed) |
| CloudWatch Logs | (SAM-managed basic-execution) | structured logs |

Explicitly **NO `secretsmanager:*`** and **NO `*/connectors/*`** — asserted in the
template comments and in `tests/test_ec2_woken_arm.py::TestGuardrailHoldsNoCredentials`.
A fully compromised airlock "can still only ask" — here, it can only wake the box.

The broker is **not** in this stack. It lives on the EC2 box (sa#98). The airlock only
decides *whether to wake*; every actual tool/connector call the woken agent makes still
goes through the broker on the box.

### The waker's grant posture (#209 — why it holds no broker grant)

The brief's broker-placement invariant reads "the waking Lambda is itself a principal
with a scoped grant." For this arm that is satisfied on the **IAM plane, deliberately
not the grant plane**: the waker is an IAM principal whose *scoped grant* is the
minimal execution role above — it invokes **no brokered capability** (waking a box is
not a connector call), so there is no (principal, action-class) coordinate for a broker
grant to govern and seeding one would be authority theater. The two planes split
cleanly: the waker's blast radius is bounded by IAM (it can only wake); the *woken
agent's* blast radius is bounded by the broker (it can still only ask). A waker that
grew a brokered capability (e.g. sending a notification itself) would cross the line
and MUST become a broker principal with its own grant at that moment — the
`TestGuardrailHoldsNoCredentials` conformance suite is the tripwire that keeps the
role's action set enumerated.

## Agent-agnostic normalized event shape

The airlock sees ONLY:

```json
{"owner": "<opaque owner id>", "message_id": "<str>", "text": "<str>"}
```

`owner` is an **opaque identifier**, not a channel-specific id. The **channel adapter**
that turns a concrete channel message into this shape lives in a *consuming agent's*
manifest `inbound:` block — it is out of scope for the airlock stack, which stays
channel-agnostic. There is zero channel vocabulary in this arm.

## Guardrail flow (order matters — `airlock/handler.py`)

1. **token** — constant-time compare the shared-secret header → `401` on mismatch.
2. **parse** — the normalized JSON body → `400` if malformed.
3. **allow-list** — `owner` against `OwnerAllowList` → `403` if not listed.
4. **dedup** — conditional PutItem on `message_id` → `200` no-op if already seen.
5. **injection screen** — `text` against `InjectionScreenPattern` → **drop** (log + `200`,
   NOT enqueued, NOT woken) on match. A bad regex fails **closed**.
6. **intent classify** — env-driven `IntentModel` / `IntentPrompt`; a thin, swappable stub
   (a real classifier would send `text` as DATA to the box's brokered model proxy — no
   vendor/model is hardcoded).
7. **accept** — `SendMessage` to SQS + `StartInstances` → `200`.

The decision logic (`process_inbound`) is **pure** with respect to an injected `Effects`
bundle (dedup put, enqueue, wake), so the whole path is unit-testable with no AWS.

## Provision / teardown

`provision.py` (read-side AWS via the injected `AWSInterface`; the SAM deploy/delete via
an injected callable — the `sam` CLI by default, a fake in tests):

- **`ec2_woken_provision(manifest, aws, *, environment, region, runner_instance_id, sam_deploy, template_path)`**
  — reads the manifest `inbound:` block, resolves the shared token from Secrets Manager
  (injected into the Lambda env at deploy time — never read at runtime), discovers the box
  to wake by the arm tag set (or takes an explicit id), and deploys `airlock.yaml`
  parameterized from all of the above. Returns `{stack_name, parameters, outputs}`.
- **`ec2_woken_teardown(manifest, aws, *, environment, region, sam_delete)`** — deletes
  the whole airlock stack in one `sam delete`. Idempotent; never touches the box or the
  `infra/` floor.

**Why the `sam` CLI, not CloudFormation via `AWSInterface`:** the airlock is a SAM app
whose Lambda code must be packaged + uploaded; `sam deploy` does that in one command.
Adding CFN package/change-set plumbing to the (already large) `AWSInterface` + `FakeAWS`
would be far more surface for no gain. The deploy step is **injected**, so tests never
shell out. The stack is self-contained (no `ImportValue` from `infra/`); the CLI's
managed deploy bucket is the only prerequisite.

Stack name follows the pipeline convention: `ec2-woken-<agent>-<environment>`. Every
resource is tagged `Project / Environment / Agent / ManagedBy / Name / Arm=ec2-woken`.

## Box-side drain (`box/`)

`box/emit-runner-ready.sh` + `box/responsive-agent-ready.service` are the box-side seam:
a systemd unit that, on wake, long-polls the airlock SQS queue, spools each normalized
event for the agent runner, and signals "runner ready". Agent-agnostic and
agent-name-parameterized (config from `/etc/safe-agents/agent.env`); holds no connector
credentials — it only moves already-guardrailed events onto the local spool.

## Pipeline wiring

`safe_agents/pipeline/phases.py` dispatches `arm: ec2-woken`:
- `provision_phase` → `ec2_woken_provision`
- `teardown_phase` → `ec2_woken_teardown`
- `deploy_phase` / `smoke_phase` are substrate-generic.

## Deferred

- **The live box-drain loop** — feeding the spooled events into a confined + brokered
  agent run and replying needs the running EC2 box (sa#98). `box/emit-runner-ready.sh` is
  the drain + readiness seam; it does not itself run the agent.
- **The real intent classifier** — the classify step is a wired, env-driven stub; a real
  classifier calls the box's brokered model proxy (never a hardcoded vendor model).
- **The channel adapter** — the concrete-channel → normalized-shape mapping lives in a
  consuming agent's manifest `inbound:` block, never in this arm.
