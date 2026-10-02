# Fargate arm — scheduled, serverless agent compute (Arm 3)

The Fargate arm runs a confined agent as a **short-lived, scheduled ECS task**.
It is the cloud-native, serverless sibling of the always-on EC2 arm and the
OS-isolated RHEL arm: same broker invariants, different substrate.

## Two-task topology (not a sidecar)

The broker is **not** co-placed in the agent's task. It runs as its own
long-lived ECS service (provisioned by `infra/` ComputeStack), reachable at
`broker.safe-agents.local` via CloudMap service discovery. The agent runs as a
**separate** task:

```
EventBridge Scheduler ──RunTask──▶ [agent task]  ──egress (broker SG only)──▶ [broker service]
   (cron + timezone)                isolated subnet                              broker.safe-agents.local
                                    agentSG, no public IP                        :8080 tool API / :8443 model proxy
```

## Topology-based confinement (no netns)

The agent is confined by **awsvpc network topology**, the cloud-native analogue
of the RHEL arm's network namespace:

- Launched in the **isolated agent subnets** (`agent-subnet-ids`) — no NAT, no IGW.
- On the **agentSG** (`agent-sg-id`), whose only egress route (NetworkStack
  topology) is the broker SG.
- **`AssignPublicIp=DISABLED`.**

So a fully compromised agent "can still only ask": its only reachable network
peer is the broker, which holds the connector credentials and decides per call.

## Two-identity split (per-agent roles)

Fargate is the first arm that **creates** per-agent IAM roles rather than reusing
the IdentityStack base `agentRole` via an instance profile:

| Role | Trust | Carries |
|---|---|---|
| **taskRole** | `ecs-tasks.amazonaws.com` | ONLY the arm extensions: `dynamodb:PutItem` on the agent-runs table + `secretsmanager:GetSecretValue` on **this agent's** oauth-token secret. **No connector creds** (broker-only). |
| **executionRole** | `ecs-tasks.amazonaws.com` | `AmazonECSTaskExecutionRolePolicy` (ECR pull + log writes) + a narrow `GetSecretValue` inline so ECS can inject the oauth token. |
| **schedulerRole** | `scheduler.amazonaws.com` | `ecs:RunTask` on the agent's task-def family + `iam:PassRole` on the task + execution roles. |

The machine-checkable invariant: no taskRole statement Resource matches
`*/connectors/*` (`BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN`). Tested in
`tests/test_fargate_arm.py::TestNoConnectorCredsInvariant`.

## Container env contract (the runner reads these)

The task definition sets exactly these plain env vars (names are load-bearing —
the separately-built runner depends on them) plus one injected secret:

| Var | Source |
|---|---|
| `SA_BROKER_DNS` | `broker-service-dns` export (`broker.safe-agents.local`) |
| `SA_MODEL_PROXY_PORT` | `8443` (broker model-inference proxy) |
| `SA_TOOL_API_PORT` | `8080` (broker tool-call API) |
| `AGENT_RUNS_TABLE` | `agent-runs-table-name` export |
| `AGENT_NAME` | the agent's manifest name |
| `RUN_ID` | placeholder; overridden per run (scheduled target / capstone RunTask) |
| `AWS_DEFAULT_REGION` | task region |
| `CLAUDE_CODE_OAUTH_TOKEN` | **secret** — injected from `safe-agents/{env}/agents/{agent}/oauth-token` |

## Provision / teardown

`provision.py` exposes (all via the injected `AWSInterface` — `FakeAWS` in tests,
`LiveAWS` for real deploys; no boto3 at import time):

- **`fargate_provision(manifest, aws, *, environment, schedule_expression, timezone, image_uri, allow_mutable_image_tag, region, state)`**
  — creates the three roles, registers the arm64 task def (cpu 256 / mem 512)
  naming the image in `image_uri`, and creates the EventBridge Scheduler rule.
  `image_uri` is required and names the image by digest; see "The image is named by digest" below.
  `schedule_expression` + `timezone` are **parameters**, never hardcoded policy.
  `state` defaults to `DISABLED` — a provision never auto-enables a
  production schedule before its first manual proof; the caller enables explicitly
  afterward. Returns a summary dict (task-def / role / schedule ARNs, `schedule_state`).
  Idempotent.
- **`fargate_teardown(manifest, aws, *, environment)`** — deletes the schedule,
  deregisters every active task-def revision in the family, and deletes the three
  per-agent roles (detach managed + delete inline first). Idempotent, zero-orphan,
  and never touches the broker service or the `infra/` floor.
- **`fargate_run_once(aws, manifest, *, environment, run_id, region)`** — the
  capstone one-off `RunTask` in the isolated topology with `RUN_ID` overridden.
  It runs the newest ACTIVE task-definition revision in the agent's family, which is
  the last `fargate_provision` for that agent. It chooses no image of its own: the
  revision names the image that provision registered.

All resource names derive deterministically from `environment` + agent name
(`_fargate_resource_names`) so teardown needs no saved state. Every resource is
tagged `Project / Environment / Agent / ManagedBy / Name / Arm=fargate`.

## The image is named by digest

`fargate_provision` has no default image. The task definition names exactly the reference the
caller passes:

```python
fargate_provision(
    manifest, aws, environment="development",
    image_uri="<ecr-agent-repo-uri>@sha256:<64 lowercase hex characters>",
)
```

From the pipeline CLI the same value is `--image-uri`:

```bash
safe-agents agents/<name>.yaml --env development \
  --image-uri "<ecr-agent-repo-uri>@sha256:<64 lowercase hex characters>"
```

A digest is the hash of the image manifest, so the task runs the image that was reviewed. Get it
by reading it back after the push, as `docs/consumer-image-contract.md` describes: `podman push
--digestfile <file> ...` writes it, and `aws ecr describe-images --repository-name
safe-agents-<env>-agent --image-ids imageTag=<tag> --query 'imageDetails[0].imageDigest' --output
text` prints it. The repository URI is the `ecr-agent-repo-uri` infra export.

With no `image_uri` the provision raises `ImagePinError` before it makes any AWS call, and a dry
run fails the same way. An earlier version defaulted to `<ecr-agent-repo-uri>:latest`. That
default is gone: the agent repository's tags are immutable, so `latest` could be pushed once and
never refreshed, and in a repository that allows overwrites it names whatever was pushed last.

To name the image by tag anyway, pass the tag reference together with the override:
`image_uri="<ecr-agent-repo-uri>:<tag>", allow_mutable_image_tag=True`, or `--image-uri
<ecr-agent-repo-uri>:<tag> --allow-mutable-image-tag`. The override still needs `image_uri`; no
flag brings back an implicit `latest`. It is recorded three ways: a WARNING log line naming the
image and the tag, the same line as a step in the pipeline plan, and `image_source: "mutable-tag"`
in the summary dict `fargate_provision` returns. The override is a per-run switch. It is a
parameter of the call and a flag of the command, and nothing reads it from the manifest or the
environment.

The rules live in `safe_agents/pipeline/image_pin.py`, the Python half of `infra/lib/image-pin.ts`.

## Pipeline wiring

`safe_agents/pipeline/phases.py` dispatches `arm: fargate`:
- `provision_phase` → `fargate_provision`, passing `--image-uri` and `--allow-mutable-image-tag`
  through. `--ami-id` and `--allow-newest-ami` do not apply to this arm and are an error.
- `teardown_phase` → `fargate_teardown`
- `deploy_phase` / `smoke_phase` are substrate-generic; the conformance harness
  is the smoke gate (local mode in CI). The live capstone uses `fargate_run_once`.

## Deferred

- **No in-task code bundle pull** — the agent image is expected to be self-contained
  (built + pushed to the agent ECR repo). The EC2 arm's S3 bundle path is not used here.
  What a consumer-built image must do is now an explicit contract:
  `docs/consumer-image-contract.md` (#68; the first real consumer lands in its own repo).
- **Live smoke poll** — `fargate_run_once` launches the task; polling its exit code
  via `aws.describe_task(cluster, task_arn)` to gate the capstone is left to the
  deploy driver (the interface method exists; no automatic wait loop yet).
- **Deploy phase.** `deploy_phase` does nothing arm-specific for Fargate. The image is part of
  the task definition, so running a different image means running the provision phase again
  with the new `--image-uri`, which registers a new task-definition revision.
