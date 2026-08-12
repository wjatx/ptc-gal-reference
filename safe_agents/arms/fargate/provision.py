"""
Fargate arm provisioner and teardown — Arm 3 (scheduled Fargate task, sa#36 C2b).

Re-derives the agent-host provisioning for the serverless Fargate substrate,
generalized for any agent via manifest parameters. Mirrors the EC2 arm
(safe_agents/arms/ec2/provision.py) structure: an injected AWSInterface, a
`fargate_provision` / `fargate_teardown` pair, per-agent IAM extensions carrying
ONLY the agent's own model-token read + run-record write, deterministic resource
naming for stateless teardown discovery, and the standard arm tag set.

How it plugs into the pipeline (sa#32):
    provision_phase() in safe_agents/pipeline/phases.py calls fargate_provision() for
    arm=fargate; teardown_phase() calls fargate_teardown(). All AWS calls go
    through the injected AWSInterface — FakeAWS for unit tests, LiveAWS for real
    deploys. No boto3 is imported at module load time.

Topology — two confined tasks, not a sidecar:
    The broker runs as its OWN long-lived ECS service (ComputeStack), reachable
    at broker.safe-agents.local via CloudMap. The agent runs as a SEPARATE,
    short-lived scheduled task in the ISOLATED agent subnets on the agentSG —
    whose only egress route (NetworkStack topology) is the broker SG. There is
    no netns here: confinement is the awsvpc subnet + SG, the cloud-native
    analogue of the RHEL arm's netns. The agent holds no connector credentials;
    its only outbound path is the broker.

Two-identity split (mirrors EC2 sa#33, re-derived for Fargate's role model):
    Fargate is the first arm that CREATES per-agent roles (rather than reusing
    the IdentityStack base agentRole via an instance profile):
      taskRole       — the in-container identity. Carries ONLY the arm
                       extensions: run-record PutItem on agent-runs-<env> and
                       GetSecretValue on THIS agent's oauth-token secret. NO
                       connector creds (broker-only) — see agent_role_extensions().
      executionRole  — the ECS agent identity (not the container's). Pulls the
                       image from ECR, writes logs, and injects the oauth-token
                       secret into the container's env. AmazonECSTaskExecutionRolePolicy
                       (managed) + a narrow GetSecretValue inline on the oauth secret.
      schedulerRole  — assumed by EventBridge Scheduler to RunTask: ecs:RunTask on
                       the task def + iam:PassRole on the task + execution roles.

Resource naming + tagging:
    Every resource name derives deterministically from environment + agent name
    (see _fargate_resource_names) so teardown finds them without saved state.
    Every resource is also tagged with the standard set (Project/Environment/
    Agent/ManagedBy/Name/Arm=fargate) for auditing + secondary discovery.

Teardown (fargate_teardown):
    Deletes the schedule, deregisters every active task-def revision in the
    family, and deletes the three per-agent roles (inline policies + managed
    attachments first). Idempotent, zero-orphan; never touches the broker
    service or any infra/ floor resource.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from safe_agents.pipeline.aws_interface import AWSInterface
    from safe_agents.pipeline.manifest import DeploymentManifest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The Secrets Manager resource ARN pattern the IdentityStack grants brokerRole.
# The taskRole extensions produced by agent_role_extensions() must NOT match this
# pattern — the machine-checkable invariant for the two-identity split (mirrors EC2).
BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN = "*/connectors/*"

# The scheduler role is created immediately before CreateSchedule; its trust policy can take
# a few seconds to propagate, during which CreateSchedule raises SchedulerRoleNotReadyError.
# Retry with exponential backoff (2s, 4s, 8s, …) — mirrors the EC2 arm's RunInstances IAM retry.
_SCHEDULE_IAM_RACE_MAX_ATTEMPTS = 6
_SCHEDULE_IAM_RACE_BACKOFF_BASE_S = 2.0


def _create_schedule_with_iam_retry(
    aws: "AWSInterface",
    *,
    max_attempts: int = _SCHEDULE_IAM_RACE_MAX_ATTEMPTS,
    backoff_base: float = _SCHEDULE_IAM_RACE_BACKOFF_BASE_S,
    **kwargs,
) -> str:
    """Call aws.create_schedule, retrying on SchedulerRoleNotReadyError.

    EventBridge Scheduler validates that the target role is assumable at CreateSchedule
    time; a just-created scheduler role may not have propagated yet. Retries with
    exponential backoff up to max_attempts. Pass backoff_base=0 in FakeAWS tests to avoid
    real sleeps. All kwargs are forwarded verbatim to aws.create_schedule (keyword-only).
    """
    from safe_agents.pipeline.aws_interface import SchedulerRoleNotReadyError  # noqa: PLC0415

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return aws.create_schedule(**kwargs)
        except SchedulerRoleNotReadyError as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
            wait = backoff_base * (2 ** (attempt - 1))
            logger.warning(
                "fargate_provision: scheduler role not ready (attempt %d/%d); retrying in %.1fs",
                attempt, max_attempts, wait,
            )
            time.sleep(wait)
    raise RuntimeError(
        f"fargate_provision: CreateSchedule failed after {max_attempts} attempts "
        f"(scheduler-role propagation race): {last_exc}"
    ) from last_exc

# Fargate task size: arm64, smallest valid Fargate combo (0.25 vCPU / 0.5 GB).
DEFAULT_CPU = "256"
DEFAULT_MEMORY = "512"

# arm64 Linux runtime platform for the task definition.
RUNTIME_PLATFORM = {"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"}

# The runner reads these container env vars (the runner-contract for the Fargate
# arm). DO NOT rename without updating the runner — these names are load-bearing.
SA_MODEL_PROXY_PORT = "8443"
SA_TOOL_API_PORT = "8080"

# Default schedule when the caller passes none. A placeholder, not a real cadence
# — the schedule expression + timezone are provision PARAMETERS, never hardcoded
# policy. rate(1 day) keeps a disabled-by-default-ish cadence for the capstone.
DEFAULT_SCHEDULE_EXPRESSION = "rate(1 day)"
DEFAULT_TIMEZONE = "UTC"

# RUN_ID env placeholder. Each actual run (scheduled target or the capstone
# RunTask) overrides this via container overrides; the task-def default is a
# clearly-non-real sentinel so an un-overridden run is obvious in the audit.
RUN_ID_PLACEHOLDER = "placeholder-overridden-per-run"

# AWS-managed policy the execution role needs (ECR pull + CloudWatch Logs write).
ECS_TASK_EXECUTION_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)

# Trust policies (assume-role) for the per-agent roles.
_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_SCHEDULER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def _fargate_resource_names(environment: str, agent_name: str) -> dict[str, str]:
    """Deterministic per-agent resource names (so teardown needs no saved state).

    Example (environment=development, agent=myagent):
        base        safe-agents-development-myagent-fargate
        task_role   safe-agents-development-myagent-fargate-task
        exec_role   safe-agents-development-myagent-fargate-exec
        sched_role  safe-agents-development-myagent-fargate-scheduler
        family      safe-agents-development-myagent-fargate
        schedule    safe-agents-development-myagent-fargate
        log_group   /safe-agents/development/myagent/fargate
    """
    base = f"safe-agents-{environment}-{agent_name}-fargate"
    return {
        "base": base,
        "task_role": f"{base}-task",
        "exec_role": f"{base}-exec",
        "scheduler_role": f"{base}-scheduler",
        "family": base,
        "schedule": base,
        "container": agent_name,
        "log_group": f"/safe-agents/{environment}/{agent_name}/fargate",
    }


def _oauth_secret_name(environment: str, agent_name: str) -> str:
    """Secrets Manager id of the agent's model (Claude Code) OAuth token.

    The deployer seeds this out of band before the capstone. Referenced by name
    in the task-def `secrets:` block and scoped in the task/exec role IAM.
    """
    return f"safe-agents/{environment}/agents/{agent_name}/oauth-token"


def _arm_tags(environment: str, agent_name: str) -> dict[str, str]:
    """Standard tag set applied to every resource provision creates.

    Includes Arm=fargate so cross-arm audits can distinguish substrates.
    """
    return {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
        "Name": f"safe-agents-{environment}-{agent_name}",
        "Arm": "fargate",
    }


# ---------------------------------------------------------------------------
# IAM policy definitions (testable at the rendered-policy level)
# ---------------------------------------------------------------------------

def agent_role_extensions(
    agent_name: str,
    environment: str,
    agent_runs_table_arn: str,
    oauth_secret_name: str,
    tables_key_arn: str,
) -> list[dict]:
    """IAM statements the Fargate arm attaches to the per-agent taskRole.

    The agent process (inside the container) gets EXACTLY these rights and nothing
    else — no connector authority (broker-only):

      RunRecord  — PutItem on the agent-runs table for this environment.
      RunRecordKey — GenerateDataKey/Decrypt on the tables CMK, required because the
                   agent-runs table is customer-managed-encrypted (PutItem to a CMK
                   table fails with AccessDenied on kms:GenerateDataKey otherwise).
      OauthToken — GetSecretValue on the agent's own oauth-token secret path
                   (NOT */connectors/* — that is broker-only territory).

    Returned as plain dicts (IAM statement shape) so the no-connector-creds
    invariant is assertable in unit tests with no AWS SDK involved.
    """
    return [
        {
            # Run-record write only. No read on grants/counters/intents (broker-only).
            "Sid": f"RunRecord{environment.capitalize()}",
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": agent_runs_table_arn,
        },
        {
            # The agent-runs table is CMK-encrypted; a PutItem needs to wrap the item
            # data key. Scoped to the single tables CMK — not kms:* on all keys.
            "Sid": "RunRecordKey",
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": tables_key_arn,
        },
        {
            # OAuth token: the agent reads ONLY its own model token. The broker
            # connector-keys path (*/connectors/*) is entirely absent here. The
            # wildcard suffix covers the Secrets Manager version suffix on the ARN.
            "Sid": "OauthToken",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": f"arn:*:secretsmanager:*:*:secret:{oauth_secret_name}*",
        },
    ]


def _execution_role_secrets_policy(oauth_secret_name: str) -> list[dict]:
    """Inline statements for the execution role: inject the oauth-token secret.

    The managed AmazonECSTaskExecutionRolePolicy covers ECR pull + log writes
    (CreateLogStream/PutLogEvents) but NOT GetSecretValue on a specific secret, nor
    logs:CreateLogGroup. GetSecretValue must be granted so ECS can resolve the task-def
    `secrets:` block at start; CreateLogGroup is needed because the task def sets
    awslogs-create-group=true (the first run in the isolated subnet creates its group).
    """
    return [
        {
            "Sid": "InjectOauthToken",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": f"arn:*:secretsmanager:*:*:secret:{oauth_secret_name}*",
        },
        {
            "Sid": "CreateLogGroup",
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup"],
            "Resource": "arn:*:logs:*:*:log-group:/safe-agents/*",
        },
    ]


def _scheduler_role_policy(
    task_role_arn: str,
    execution_role_arn: str,
    task_def_family: str,
) -> list[dict]:
    """Inline statements for the EventBridge Scheduler invoke role.

    Lets the scheduler RunTask the agent's task def and PassRole the task +
    execution roles to ECS (required for RunTask with task/execution roles).
    """
    return [
        {
            "Sid": "RunAgentTask",
            "Effect": "Allow",
            "Action": ["ecs:RunTask"],
            # Any active revision of THIS agent's family.
            "Resource": f"arn:aws:ecs:*:*:task-definition/{task_def_family}:*",
        },
        {
            "Sid": "PassTaskRoles",
            "Effect": "Allow",
            "Action": ["iam:PassRole"],
            "Resource": [task_role_arn, execution_role_arn],
        },
    ]


# ---------------------------------------------------------------------------
# Container env contract (the runner reads these — load-bearing names)
# ---------------------------------------------------------------------------

def build_container_environment(
    *,
    broker_service_dns: str,
    agent_runs_table_name: str,
    agent_name: str,
    region: str,
    run_id: str = RUN_ID_PLACEHOLDER,
) -> dict[str, str]:
    """The EXACT plain-env contract the Fargate runner consumes.

    These names are a contract with the (separately built) runner. Do not rename:
        SA_BROKER_DNS         broker CloudMap DNS (= broker.safe-agents.local)
        SA_MODEL_PROXY_PORT   broker model-inference proxy port (8443)
        SA_TOOL_API_PORT      broker tool-call API port (8080)
        AGENT_RUNS_TABLE      DynamoDB table for run records
        AGENT_NAME            this agent's name
        RUN_ID                per-run id (overridden per run; placeholder here)
        AWS_DEFAULT_REGION    boto3 region for the in-container SDK
    """
    return {
        "SA_BROKER_DNS": broker_service_dns,
        "SA_MODEL_PROXY_PORT": SA_MODEL_PROXY_PORT,
        "SA_TOOL_API_PORT": SA_TOOL_API_PORT,
        "AGENT_RUNS_TABLE": agent_runs_table_name,
        "AGENT_NAME": agent_name,
        "RUN_ID": run_id,
        "AWS_DEFAULT_REGION": region,
    }


# ---------------------------------------------------------------------------
# Infra-export resolution (mirrors EC2's _ssm helper)
# ---------------------------------------------------------------------------

def _make_ssm_resolver(aws: "AWSInterface", environment: str):
    """Return a resolver that reads /safe-agents/{env}/{key} or raises if absent."""

    def _ssm(key: str) -> str:
        path = f"/safe-agents/{environment}/{key}"
        value = aws.get_ssm_param(path)
        if not value:
            raise RuntimeError(
                f"fargate_provision: SSM param {path!r} not found; "
                "has the infra/ foundation stack been deployed for this environment?"
            )
        return value

    return _ssm


# NetworkStack publishes network-mode alongside the per-agent subnet/SG exports.
# 'secure' (the floor) keeps agent subnets private — egress via NAT/interface
# endpoints, no public IP. 'open' makes them public subnets where a task must be
# assigned a public IP to reach the internet (no NAT, no endpoints).
NETWORK_MODE_KEY = "network-mode"
NETWORK_MODE_SECURE = "secure"
NETWORK_MODE_OPEN = "open"


def _resolve_network_mode(aws: "AWSInterface", environment: str) -> str:
    """Read the NetworkStack network-mode param, defaulting to 'secure' if absent.

    Backward compatible: an environment provisioned before this param was published
    reads as 'secure' — private subnets, public IP disabled (the pre-flag topology).
    """
    value = aws.get_ssm_param(f"/safe-agents/{environment}/{NETWORK_MODE_KEY}")
    return value.strip() if value else NETWORK_MODE_SECURE


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

def fargate_provision(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
    schedule_expression: str = DEFAULT_SCHEDULE_EXPRESSION,
    timezone: str = DEFAULT_TIMEZONE,
    image_uri: Optional[str] = None,
    region: str = "us-east-1",
    state: str = "DISABLED",
) -> dict:
    """Provision the scheduled Fargate task for arm=fargate.

    Steps (all via the injected AWSInterface — FakeAWS in tests):
      1. Resolve infra exports (cluster-arn, broker-service-dns, agent-subnet-ids,
         agent-sg-id, agent-runs-table-name/arn, ecr-agent-repo-uri).
      2. Create the per-agent taskRole (ecs-tasks trust) + its arm-extension inline
         policy (run-record PutItem + oauth-token GetSecretValue ONLY).
      3. Create the executionRole (ecs-tasks trust) + attach the managed
         AmazonECSTaskExecutionRolePolicy + a narrow oauth-secret GetSecretValue inline.
      4. Create the schedulerRole (scheduler trust) + ecs:RunTask + iam:PassRole inline.
      5. Register the arm64 task definition (cpu 256 / mem 512), the runner-contract
         container env, and the oauth-token secret injection.
      6. Create the EventBridge Scheduler schedule → ECS RunTask in the agent
         subnets + agentSG. Public IP follows the NetworkStack network-mode:
         DISABLED for 'secure' (private subnets, the default), ENABLED for 'open'
         (public subnets with no NAT/endpoint egress).

    Idempotent: re-running reuses existing roles (create_role is name-idempotent;
    put_role_policy / attach are idempotent) and registers a new task-def revision
    + upserts the schedule.

    Parameters
    ----------
    manifest:               Loaded deployment manifest. Must have arm="fargate".
    aws:                    AWSInterface implementation (injected by the pipeline).
    environment:            Deployment environment (resolves infra SSM exports).
    schedule_expression:    cron(...) / rate(...) — a PARAMETER, not hardcoded policy.
    timezone:               IANA timezone for the schedule — a PARAMETER.
    image_uri:              Full container image URI. When None, resolved as
                            <ecr-agent-repo-uri>:latest from infra SSM.
    region:                 AWS region (for logs + the in-container AWS_DEFAULT_REGION).
    state:                  Initial EventBridge Scheduler state. Defaults to DISABLED —
                            deliberately different from create_schedule's own ENABLED
                            default — because a provision should never enable a production
                            schedule before its first manual proof (sa#115); the schedule
                            fires once immediately on creation even if disabled seconds
                            later, so the only correct fix is provisioning DISABLED.

    Returns
    -------
    Summary dict: task_definition_arn, task_role_arn, execution_role_arn,
    scheduler_role_arn, schedule_arn, family, schedule_state.
    """
    agent_name = manifest.name
    _ssm = _make_ssm_resolver(aws, environment)

    # -- Step 1: resolve infra exports ----------------------------------------
    cluster_arn = _ssm("cluster-arn")
    broker_service_dns = _ssm("broker-service-dns")
    agent_subnet_ids = [s.strip() for s in _ssm("agent-subnet-ids").split(",") if s.strip()]
    agent_sg_id = _ssm("agent-sg-id")
    agent_runs_table_name = _ssm("agent-runs-table-name")
    agent_runs_table_arn = _ssm("agent-runs-table-arn")
    tables_key_arn = _ssm("tables-key-arn")  # CMK on agent-runs; PutItem needs GenerateDataKey
    # 'open' subnets are public and have no NAT/endpoint egress → the task needs a
    # public IP; 'secure' (default) keeps it disabled. Resolved once, plumbed below.
    network_mode = _resolve_network_mode(aws, environment)
    assign_public_ip = "ENABLED" if network_mode == NETWORK_MODE_OPEN else "DISABLED"
    if image_uri is None:
        image_uri = f"{_ssm('ecr-agent-repo-uri')}:latest"

    names = _fargate_resource_names(environment, agent_name)
    tags = _arm_tags(environment, agent_name)
    oauth_secret_name = _oauth_secret_name(environment, agent_name)

    # -- Step 2: per-agent taskRole (the in-container identity) ----------------
    task_role_arn = aws.create_role(names["task_role"], _ECS_TASKS_TRUST, tags)
    aws.put_role_policy(
        names["task_role"],
        names["task_role"],
        {
            "Version": "2012-10-17",
            "Statement": agent_role_extensions(
                agent_name, environment, agent_runs_table_arn, oauth_secret_name,
                tables_key_arn,
            ),
        },
    )

    # -- Step 3: executionRole (the ECS agent identity) ------------------------
    execution_role_arn = aws.create_role(names["exec_role"], _ECS_TASKS_TRUST, tags)
    aws.attach_role_managed_policy(names["exec_role"], ECS_TASK_EXECUTION_MANAGED_POLICY)
    aws.put_role_policy(
        names["exec_role"],
        names["exec_role"],
        {
            "Version": "2012-10-17",
            "Statement": _execution_role_secrets_policy(oauth_secret_name),
        },
    )

    # -- Step 4: schedulerRole (assumed by EventBridge Scheduler) --------------
    scheduler_role_arn = aws.create_role(names["scheduler_role"], _SCHEDULER_TRUST, tags)
    aws.put_role_policy(
        names["scheduler_role"],
        names["scheduler_role"],
        {
            "Version": "2012-10-17",
            "Statement": _scheduler_role_policy(
                task_role_arn, execution_role_arn, names["family"]
            ),
        },
    )

    # -- Step 5: register the task definition ----------------------------------
    # ECS secret injection routes by the valueFrom PREFIX: an arn:aws:secretsmanager:...
    # value goes to Secrets Manager (and the execution role's GetSecretValue), while a bare
    # name is treated as an SSM parameter. So the oauth secret MUST be a full Secrets Manager
    # ARN, not the bare name. The account id is lifted from the agent-runs table ARN (already
    # resolved) to avoid an extra STS call.
    account_id = agent_runs_table_arn.split(":")[4]
    oauth_secret_arn = (
        f"arn:aws:secretsmanager:{region}:{account_id}:secret:{oauth_secret_name}"
    )
    log_configuration = {
        "logDriver": "awslogs",
        "options": {
            "awslogs-group": names["log_group"],
            "awslogs-region": region,
            "awslogs-stream-prefix": agent_name,
            "awslogs-create-group": "true",
        },
    }
    task_def_arn = aws.register_task_definition(
        family=names["family"],
        task_role_arn=task_role_arn,
        execution_role_arn=execution_role_arn,
        cpu=DEFAULT_CPU,
        memory=DEFAULT_MEMORY,
        container_name=names["container"],
        image=image_uri,
        environment=build_container_environment(
            broker_service_dns=broker_service_dns,
            agent_runs_table_name=agent_runs_table_name,
            agent_name=agent_name,
            region=region,
        ),
        secrets={"CLAUDE_CODE_OAUTH_TOKEN": oauth_secret_arn},
        log_configuration=log_configuration,
        runtime_platform=RUNTIME_PLATFORM,
        network_mode="awsvpc",
        tags=tags,
    )

    # -- Step 6: EventBridge Scheduler → ECS RunTask ---------------------------
    target = {
        "Arn": cluster_arn,
        "RoleArn": scheduler_role_arn,
        "EcsParameters": {
            "TaskDefinitionArn": task_def_arn,
            "LaunchType": "FARGATE",
            "TaskCount": 1,
            "NetworkConfiguration": {
                "awsvpcConfiguration": {
                    "Subnets": agent_subnet_ids,
                    "SecurityGroups": [agent_sg_id],
                    "AssignPublicIp": assign_public_ip,
                }
            },
        },
    }
    schedule_arn = _create_schedule_with_iam_retry(
        aws,
        name=names["schedule"],
        schedule_expression=schedule_expression,
        timezone=timezone,
        target=target,
        tags=tags,
        state=state,
    )

    logger.info(
        "fargate_provision: provisioned agent %r (task-def %s, schedule %s)",
        agent_name, task_def_arn, schedule_arn,
    )
    return {
        "task_definition_arn": task_def_arn,
        "task_role_arn": task_role_arn,
        "execution_role_arn": execution_role_arn,
        "scheduler_role_arn": scheduler_role_arn,
        "schedule_arn": schedule_arn,
        "family": names["family"],
        "schedule_state": state,
    }


# ---------------------------------------------------------------------------
# Capstone / smoke RunTask
# ---------------------------------------------------------------------------

def fargate_run_once(
    aws: "AWSInterface",
    manifest: "DeploymentManifest",
    *,
    environment: str = "development",
    run_id: str = "capstone",
    region: str = "us-east-1",
    extra_env: dict[str, str] | None = None,
) -> str:
    """Launch a single one-off run of the agent task (the capstone RunTask path).

    Resolves the cluster + agent subnets/SG from infra SSM, picks the newest ACTIVE
    task-def revision for the agent's family, and RunTask's it with RUN_ID overridden
    and public IP set per the NetworkStack network-mode (disabled for 'secure', the
    default; enabled for 'open' public subnets). Returns the task ARN.

    extra_env adds container env overrides for this run only (e.g. the run.sh
    SA_SMOKE_* knobs, to point the brokered-call proof at a really-granted action
    class). RUN_ID is owned by run_id and cannot be overridden through extra_env.

    The smoke gate proper (conformance harness) runs in smoke_phase; this is the
    live "does the wired task actually start and exit 0" capstone probe — poll the
    result with aws.describe_task(cluster_arn, task_arn).
    """
    _ssm = _make_ssm_resolver(aws, environment)
    cluster_arn = _ssm("cluster-arn")
    agent_subnet_ids = [s.strip() for s in _ssm("agent-subnet-ids").split(",") if s.strip()]
    agent_sg_id = _ssm("agent-sg-id")
    # 'open' public subnets need a public IP for egress; 'secure' (default) disables it.
    assign_public_ip = _resolve_network_mode(aws, environment) == NETWORK_MODE_OPEN

    names = _fargate_resource_names(environment, manifest.name)
    task_defs = aws.list_task_definitions(names["family"])
    if not task_defs:
        raise RuntimeError(
            f"fargate_run_once: no active task definition for family {names['family']!r}; "
            "run fargate_provision first."
        )
    # Highest revision = newest (family:NN; lexical max is wrong past 9, so sort by int).
    task_def_arn = max(task_defs, key=lambda a: int(a.rsplit(":", 1)[-1]))

    env_overrides = [{"name": "RUN_ID", "value": run_id}]
    env_overrides += [
        {"name": k, "value": v} for k, v in (extra_env or {}).items() if k != "RUN_ID"
    ]
    overrides = {
        "containerOverrides": [
            {
                "name": names["container"],
                "environment": env_overrides,
            }
        ]
    }
    return aws.run_task(
        cluster=cluster_arn,
        task_definition=task_def_arn,
        subnets=agent_subnet_ids,
        security_groups=[agent_sg_id],
        assign_public_ip=assign_public_ip,
        overrides=overrides,
    )


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def _teardown_role(aws: "AWSInterface", role_name: str) -> bool:
    """Detach managed policies, delete inline policies, then delete the role.

    Returns True if the role existed and was deleted, False if already gone.
    Idempotent.
    """
    if aws.get_role(role_name) is None:
        return False
    for policy_arn in aws.list_attached_role_policies(role_name):
        aws.detach_role_managed_policy(role_name, policy_arn)
    for policy_name in aws.list_role_inline_policy_names(role_name):
        aws.delete_role_policy(role_name, policy_name)
    return aws.delete_role(role_name)


def fargate_teardown(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
) -> dict:
    """Remove all resources fargate_provision() created for this agent.

    Order: delete the schedule, deregister every active task-def revision in the
    family, then delete the three per-agent roles (managed detach + inline delete
    first). All resource names derive from the deterministic naming convention —
    no saved local state.

    Idempotent: a second call is a clean no-op (everything already gone).

    NEVER touches the broker ECS service or any infra/ floor resource (cluster,
    VPC, tables, ECR repos, the IdentityStack base roles).

    Returns
    -------
    Report dict:
        schedule_removed            — True if the schedule was deleted
        task_definitions_removed    — list of deregistered task-def ARNs
        roles_removed               — list of role names actually deleted
        roles_already_gone          — list of role names found already gone
    """
    names = _fargate_resource_names(environment, manifest.name)
    report: dict = {
        "schedule_removed": False,
        "task_definitions_removed": [],
        "roles_removed": [],
        "roles_already_gone": [],
    }

    # -- Schedule --------------------------------------------------------------
    report["schedule_removed"] = aws.delete_schedule(names["schedule"])

    # -- Task definitions (every active revision in the family) ----------------
    for task_def_arn in aws.list_task_definitions(names["family"]):
        if aws.deregister_task_definition(task_def_arn):
            report["task_definitions_removed"].append(task_def_arn)

    # -- Per-agent roles -------------------------------------------------------
    for role_name in (names["task_role"], names["exec_role"], names["scheduler_role"]):
        if _teardown_role(aws, role_name):
            report["roles_removed"].append(role_name)
        else:
            report["roles_already_gone"].append(role_name)

    logger.info(
        "fargate_teardown: agent %r — schedule_removed=%s, task_defs=%d, roles_removed=%s",
        manifest.name, report["schedule_removed"],
        len(report["task_definitions_removed"]), report["roles_removed"],
    )
    return report
