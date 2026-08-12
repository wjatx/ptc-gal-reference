"""
ec2-woken BOX provisioner + teardown — the confined, SQS-woken EC2 agent box (sa#98, sa#34 G9).

Companion to provision.py (which deploys the inbound *airlock* — the wake path). This module
provisions the BOX the airlock wakes: a confined EC2 instance that, on wake, drains its SQS
queue, runs each message as a confined + brokered agent turn, then self-stops (sleeps).

Confinement model (decision): TOPOLOGY confinement like the Fargate arm, NOT netns. The box is
launched in the ISOLATED agent subnet on the agent SG whose only egress route is the broker
service (broker.safe-agents.local). It holds NO connector credentials; its only egress is the
broker. This is simpler than the netns model the always-on EC2 arm uses (that box co-hosts the
broker proxy and so must sit on the broker subnet) — the woken box is a pure agent, the broker
runs separately as its own service.

Two-identity split (mirrors ec2/fargate):
    The box reuses the IdentityStack base agentRole (zero connector authority) via a per-box
    instance profile, and attaches ONE inline policy carrying exactly the rights the drain loop
    needs and nothing else (box_role_extensions):
        - sqs:ReceiveMessage / sqs:DeleteMessage  on the ONE airlock inbound queue
        - ec2:StopInstances                       on instances tagged as THIS agent's box (== self)
        - dynamodb:PutItem                        on the agent-runs table (run records)
        - kms:GenerateDataKey / Decrypt / DescribeKey  on the tables CMK (the table is CMK-encrypted)
        - secretsmanager:GetSecretValue           on the box's OWN oauth-token secret only
    There is NO connector authority (no */connectors/*), asserted machine-checkably in the tests.

Queue coupling without an ordering cycle:
    The airlock creates the queue, but the box needs the queue URL and the airlock needs the box's
    instance id. Rather than a deploy cycle, both sides use the airlock's DETERMINISTIC queue name
    (safe-agents-<env>-<agent>-airlock-inbound). So the box is provisioned first (this module),
    then the airlock is deployed with RunnerInstanceId = the returned box id. Until the airlock
    exists the box simply drains an absent queue and idle-sleeps; once a message is POSTed the
    airlock wakes it and it drains the now-present queue.

All AWS calls go through the injected AWSInterface — FakeAWS for unit tests, LiveAWS for deploys.
No boto3 is imported at module load time.
"""
from __future__ import annotations

import base64
import gzip
import logging
import time as _time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from safe_agents.pipeline.aws_interface import AWSInterface
    from safe_agents.pipeline.manifest import DeploymentManifest

# The Secrets Manager resource ARN pattern the IdentityStack grants brokerRole. The box role
# extensions must NOT match this pattern — the machine-checkable two-identity invariant.
BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN = "*/connectors/*"

# Default instance type for the woken box (arm64, small — the box sleeps most of the time).
DEFAULT_INSTANCE_TYPE = "t4g.small"

# Base AMI tag lookup (same prebuilt-AMI bakery as the EC2 arm, sa#84).
_BASE_AMI_TAG_KEY = "safe-agents:ami"
_BASE_AMI_TAG_VALUE = "base"
_BASE_AMI_VERSION_TAG_KEY = "safe-agents:ami-version"

# IAM instance-profile propagation race: RunInstances may reject a just-created profile for tens
# of seconds. Retry with exponential backoff (2s, 4s, 8s, ...). Pass backoff_base=0 in tests.
_IAM_RACE_MAX_ATTEMPTS = 6
_IAM_RACE_BACKOFF_BASE_S = 2

# The box-side files delivered to the box. Bin files land in /opt/safe-agents/bin; the systemd
# unit lands in /etc/systemd/system. They are staged in the deploy bucket and copied down at boot
# via the isolated subnet's S3 gateway endpoint — NOT embedded in user-data, which has a 16 KB
# base64 cap the embedded assets overflow (sa#98 live-provision fix).
_BOX_DIR = Path(__file__).parent / "box"
# self-stop-on-timeout.sh is the box-side lifetime cap (belt-and-suspenders): a systemd timer
# stops the box 3h after boot if the drain loop's own idle self-stop never fired (sa#98).
_BOX_EXECUTABLES = (
    "emit-runner-ready.sh",
    "run-brokered.sh",
    "drain.sh",
    "self-stop-on-timeout.sh",
)
_BOX_LIB = ("drain_logic.py",)
_BOX_BIN_FILES = (*_BOX_EXECUTABLES, *_BOX_LIB)
# The drain-loop unit is enabled directly; the lifetime-cap timer is enabled to arm the cap; its
# oneshot .service is fired BY the timer (not enabled itself, so it has no [Install]).
_DRAIN_UNIT = "responsive-agent-ready.service"
_SELF_STOP_TIMER = "self-stop-on-timeout.timer"
_UNIT_FILES = (_DRAIN_UNIT, "self-stop-on-timeout.service", _SELF_STOP_TIMER)
# Units enabled at boot (systemctl enable --now). The self-stop .service is intentionally absent.
_ENABLED_UNITS = (_DRAIN_UNIT, _SELF_STOP_TIMER)


def _box_s3_prefix(agent_name: str) -> str:
    """Per-agent deploy-bucket prefix under which the box assets are staged."""
    return f"ec2-woken/{agent_name}/box"


def _bin_key(agent_name: str, filename: str) -> str:
    return f"{_box_s3_prefix(agent_name)}/bin/{filename}"


def _unit_key(agent_name: str, filename: str) -> str:
    return f"{_box_s3_prefix(agent_name)}/systemd/{filename}"

# Container/runner port contract (identical to the Fargate arm — same broker service).
SA_MODEL_PROXY_PORT = "8443"
SA_TOOL_API_PORT = "8080"

# Default consecutive-empty-poll count before the box self-stops.
DEFAULT_IDLE_POLLS = "3"


# ---------------------------------------------------------------------------
# Naming + tags
# ---------------------------------------------------------------------------

def _box_resource_name(environment: str, agent_name: str) -> str:
    """Per-box IAM resource name (instance profile + inline policy). Deterministic for teardown."""
    return f"safe-agents-{environment}-{agent_name}-woken-box"


def _arm_tags(environment: str, agent_name: str) -> dict[str, str]:
    """Standard tag set applied to every resource the box provision creates (Arm=ec2-woken)."""
    return {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
        "Name": f"safe-agents-{environment}-{agent_name}-woken-box",
        "Arm": "ec2-woken",
    }


def _inbound_queue_name(environment: str, agent_name: str) -> str:
    """The airlock's deterministic inbound queue name (must match airlock.yaml)."""
    return f"safe-agents-{environment}-{agent_name}-airlock-inbound"


def _inbound_queue_arn(region: str, account_id: str, environment: str, agent_name: str) -> str:
    return f"arn:aws:sqs:{region}:{account_id}:{_inbound_queue_name(environment, agent_name)}"


def _inbound_queue_url(region: str, account_id: str, environment: str, agent_name: str) -> str:
    return (
        f"https://sqs.{region}.amazonaws.com/{account_id}/"
        f"{_inbound_queue_name(environment, agent_name)}"
    )


# ---------------------------------------------------------------------------
# IAM policy (testable at the rendered-policy level)
# ---------------------------------------------------------------------------

def box_role_extensions(
    agent_name: str,
    environment: str,
    agent_runs_table_arn: str,
    oauth_secret_id: str,
    tables_key_arn: str,
    inbound_queue_arn: str,
    deploy_bucket: str,
) -> list[dict]:
    """IAM statements the box provision attaches to the base agentRole for THIS box.

    These sit on top of the IdentityStack's zero-connector-authority baseline. They are EXACTLY
    the rights the drain loop + S3-delivered boot need — no connector authority (broker-only).
    Returned as plain dicts (IAM statement shape) so the no-connector-creds invariant is
    assertable with no AWS SDK.
    """
    return [
        {
            # S3-delivered boot: read ONLY this agent's staged box assets (the drain loop + unit),
            # scoped to the per-agent prefix. GetObject only — no ListBucket, no other prefixes, no
            # other buckets. This is deploy-bucket read, NOT a connector credential.
            "Sid": "BoxAssetsRead",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": f"arn:aws:s3:::{deploy_bucket}/{_box_s3_prefix(agent_name)}/*",
        },
        {
            # Drain: receive + delete on the ONE airlock inbound queue (deterministic name).
            "Sid": "DrainAirlockQueue",
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
            "Resource": inbound_queue_arn,
        },
        {
            # Sleep: stop ONLY instances tagged as THIS agent's woken box (== self). The instance
            # id is unknown at policy-authoring time (the policy is attached before RunInstances),
            # so "self" is expressed as a resource-tag condition rather than a literal instance arn.
            "Sid": "SelfStop",
            "Effect": "Allow",
            "Action": ["ec2:StopInstances"],
            "Resource": "arn:aws:ec2:*:*:instance/*",
            "Condition": {
                "StringEquals": {
                    "aws:ResourceTag/Agent": agent_name,
                    "aws:ResourceTag/Arm": "ec2-woken",
                }
            },
        },
        {
            # Run-record write only. No read on grants/counters/intents (broker-only).
            "Sid": f"RunRecord{environment.capitalize()}",
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": agent_runs_table_arn,
        },
        {
            # The agent-runs table is CMK-encrypted; a PutItem must wrap the item data key.
            # Scoped to the single tables CMK — not kms:* on all keys. Mirrors the Fargate arm.
            "Sid": "RunRecordKey",
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": tables_key_arn,
        },
        {
            # OAuth token: the box reads ONLY its own model token. The broker connector-keys path
            # (*/connectors/*) is entirely absent here. The wildcard suffix covers the Secrets
            # Manager version suffix appended to the secret ARN.
            "Sid": "OauthToken",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": f"arn:*:secretsmanager:*:*:secret:{oauth_secret_id}*",
        },
    ]


# ---------------------------------------------------------------------------
# User-data rendering
# ---------------------------------------------------------------------------

def _read_box_file(name: str) -> str:
    return (_BOX_DIR / name).read_text()


def render_box_user_data(
    *,
    agent_name: str,
    deploy_bucket: str,
    broker_dns: str,
    agent_runs_table: str,
    inbound_queue_url: str,
    region: str,
    oauth_secret_id: str,
    idle_polls: str = DEFAULT_IDLE_POLLS,
) -> str:
    """Render the SMALL cloud-init user-data that turns a base AMI into a woken box.

    The box assets (the drain + self-stop scripts + drain_logic.py + the drain unit and the
    lifetime-cap timer/service) are staged in the deploy bucket by the provision and copied down
    here via the isolated subnet's S3 gateway
    endpoint — NOT embedded, because base64(gzip(embedded)) overflows EC2's 16 KB user-data cap
    (sa#98 live-provision fix). Explicit per-object `aws s3 cp` (not `--recursive`) keeps the box
    role to `s3:GetObject` only — no `s3:ListBucket`. User-data then writes the env contract
    (oauth token by SECRET ID, never plaintext) and enables the drain service, so
    wake -> drain -> run -> sleep runs.
    """
    bin_copies = "\n".join(
        f'aws s3 cp "s3://{deploy_bucket}/{_bin_key(agent_name, f)}" '
        f'"/opt/safe-agents/bin/{f}"'
        for f in _BOX_BIN_FILES
    )
    unit_copies = "\n".join(
        f'aws s3 cp "s3://{deploy_bucket}/{_unit_key(agent_name, u)}" '
        f"/etc/systemd/system/{u}"
        for u in _UNIT_FILES
    )
    unit_enables = "\n".join(
        f"systemctl enable --now {u}" for u in _ENABLED_UNITS
    )
    return f"""#!/usr/bin/env bash
# safe-agents ec2-woken box bootstrap (rendered by box_provision.render_box_user_data).
set -euo pipefail

# Unprivileged, connector-credential-free service user.
id -u safe-agents >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin safe-agents
install -d -o safe-agents -g safe-agents /opt/safe-agents/bin /etc/safe-agents /var/lib/safe-agents

# /run is tmpfs — wiped on every reboot, and user-data only runs on the FIRST boot. A tmpfiles.d
# drop-in recreates the runtime dir (owned by the unprivileged service user) on EVERY boot, so the
# drain service's ExecStartPre can write its ready marker on a WAKE boot too. Without this the
# service failed on wake with "mkdir /run/safe-agents: Permission denied" (sa#105).
echo 'd /run/safe-agents 0755 safe-agents safe-agents -' > /etc/tmpfiles.d/safe-agents.conf
systemd-tmpfiles --create /etc/tmpfiles.d/safe-agents.conf

# Box assets from the deploy bucket (isolated-subnet S3 gateway endpoint; GetObject only, no
# ListBucket). No proxy is set this early in boot, but strip it defensively — S3 goes direct.
export AWS_DEFAULT_REGION={region}
{bin_copies}
{unit_copies}

chmod 0755 /opt/safe-agents/bin/*.sh
chmod 0644 /opt/safe-agents/bin/drain_logic.py
chown -R safe-agents:safe-agents /opt/safe-agents

# Env contract consumed by drain.sh + run-brokered.sh. The oauth token is referenced by SECRET
# ID (resolved at runtime via the box's own GetSecretValue grant) — never written here as plaintext.
cat > /etc/safe-agents/agent.env <<'__SA_ENV__'
AGENT_NAME={agent_name}
SA_BROKER_DNS={broker_dns}
SA_MODEL_PROXY_PORT={SA_MODEL_PROXY_PORT}
SA_TOOL_API_PORT={SA_TOOL_API_PORT}
AGENT_RUNS_TABLE={agent_runs_table}
INBOUND_QUEUE_URL={inbound_queue_url}
AWS_DEFAULT_REGION={region}
IDLE_POLLS={idle_polls}
SA_OAUTH_SECRET_ID={oauth_secret_id}
__SA_ENV__
chmod 0640 /etc/safe-agents/agent.env
chown root:safe-agents /etc/safe-agents/agent.env

systemctl daemon-reload
{unit_enables}
"""


# ---------------------------------------------------------------------------
# AMI + IAM helpers (re-derived compactly from the EC2 arm)
# ---------------------------------------------------------------------------

def _pick_newest_ami(images: list[dict]) -> str:
    if not images:
        raise RuntimeError(
            "ec2_woken_box_provision: no base AMI found with tag "
            f"{_BASE_AMI_TAG_KEY}={_BASE_AMI_TAG_VALUE!r}; run the AMI bakery (sa#84) or pass image_id."
        )
    return max(images, key=lambda img: img["tags"].get(_BASE_AMI_VERSION_TAG_KEY, ""))["image_id"]


def _ensure_instance_profile(
    aws: "AWSInterface",
    profile_name: str,
    role_name: str,
    policy_name: str,
    policy_doc: dict,
    tags: dict,
) -> str:
    """Idempotently ensure the per-box instance profile exists with the role + inline policy."""
    profile = aws.get_instance_profile(profile_name)
    if profile is None:
        profile_arn = aws.create_instance_profile(profile_name, tags)
        aws.add_role_to_instance_profile(profile_name, role_name)
        logger.info("ec2_woken_box_provision: created instance profile %r", profile_name)
    else:
        profile_arn = profile["arn"]
        if role_name not in profile.get("roles", []):
            aws.add_role_to_instance_profile(profile_name, role_name)
    aws.put_role_policy(role_name, policy_name, policy_doc)
    return profile_arn


def _run_instances_with_iam_retry(
    aws: "AWSInterface",
    *,
    max_attempts: int = _IAM_RACE_MAX_ATTEMPTS,
    backoff_base: float = _IAM_RACE_BACKOFF_BASE_S,
    **kwargs,
) -> str:
    """Call aws.run_instances, retrying on the IAM instance-profile propagation race."""
    from safe_agents.pipeline.aws_interface import IamProfileNotReadyError  # noqa: PLC0415

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return aws.run_instances(**kwargs)
        except IamProfileNotReadyError as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
            _time.sleep(backoff_base * (2 ** (attempt - 1)))
    raise RuntimeError(
        f"ec2_woken_box_provision: RunInstances failed after {max_attempts} attempts "
        f"(IAM profile propagation race): {last_exc}"
    ) from last_exc


def _upload_box_assets(aws: "AWSInterface", deploy_bucket: str, agent_name: str) -> None:
    """Stage the drain-loop assets in the deploy bucket under the per-agent box prefix.

    The box copies these down at boot via the isolated subnet's S3 gateway endpoint (user-data
    cannot carry them — they overflow the 16 KB base64 cap). Bin files go under .../box/bin/, the
    systemd unit under .../box/systemd/ — both inside the single prefix the box role can read.
    """
    for filename in _BOX_BIN_FILES:
        aws.put_object(deploy_bucket, _bin_key(agent_name, filename), _read_box_file(filename))
    for filename in _UNIT_FILES:
        aws.put_object(deploy_bucket, _unit_key(agent_name, filename), _read_box_file(filename))


# ---------------------------------------------------------------------------
# Provision
# ---------------------------------------------------------------------------

def ec2_woken_box_provision(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
    region: str = "us-east-1",
    instance_type: str = DEFAULT_INSTANCE_TYPE,
    image_id: Optional[str] = None,
    idle_polls: str = DEFAULT_IDLE_POLLS,
    _iam_backoff_base: float = _IAM_RACE_BACKOFF_BASE_S,
) -> str:
    """Provision the confined, SQS-woken EC2 box for arm=ec2-woken. Returns the instance id.

    Steps (all via the injected AWSInterface):
      1. Resolve infra exports (agent-role-arn, the ISOLATED agent subnet + agent SG, the
         agent-runs table name/arn, the tables CMK arn, the broker service DNS, the deploy bucket).
      2. Stage the drain-loop assets in the deploy bucket (S3-delivered boot — user-data has a
         16 KB base64 cap the embedded assets overflow).
      3. Ensure a per-box instance profile carrying the base agentRole + the box inline policy
         (box_role_extensions: box-assets read + drain + self-stop + run-record + CMK + own-oauth ONLY).
      4. Render the (now tiny) user-data (copies assets from S3, writes agent.env, enables the drain
         service) and launch the box in the agent subnet on the agent SG (topology confinement),
         IMDSv2-only.

    The returned instance id is what the airlock's RunnerInstanceId must point at.
    """
    agent_name = manifest.name

    def _ssm(key: str) -> str:
        path = f"/safe-agents/{environment}/{key}"
        value = aws.get_ssm_param(path)
        if not value:
            raise RuntimeError(
                f"ec2_woken_box_provision: SSM param {path!r} not found; "
                "has the infra/ foundation stack been deployed for this environment?"
            )
        return value

    # -- Step 1: infra exports. Topology confinement uses the ISOLATED agent subnet + agent SG
    # (→ the broker only), PLUS the endpoint SG so the box can reach the AWS *interface* endpoints
    # it needs from a no-NAT subnet: SQS (its inbound queue) and Secrets Manager (its oauth token).
    # (The Fargate agent didn't need these — ECS injected the oauth via the execution role and it
    # never touched SQS. An EC2 woken box makes those API calls itself, so it needs endpoint reach.)
    # Confinement still holds: no NAT + no internet route, so the broker remains the only path to
    # the model + connectors; the box's IAM confines WHAT it may do at each endpoint.
    agent_role_arn = _ssm("agent-role-arn")
    agent_sg_id = _ssm("agent-sg-id")
    endpoint_sg_id = _ssm("endpoint-sg-id")
    agent_subnet_id = _ssm("agent-subnet-ids").split(",")[0].strip()
    agent_runs_table_name = _ssm("agent-runs-table-name")
    agent_runs_table_arn = _ssm("agent-runs-table-arn")
    tables_key_arn = _ssm("tables-key-arn")
    broker_dns = _ssm("broker-service-dns")
    deploy_bucket = _ssm("deploy-bucket-name")

    role_name = agent_role_arn.split("/")[-1]
    account_id = agent_runs_table_arn.split(":")[4]
    oauth_secret_id = manifest.secrets.oauth_token or f"{agent_name}/claude-oauth-token"

    inbound_queue_arn = _inbound_queue_arn(region, account_id, environment, agent_name)
    inbound_queue_url = _inbound_queue_url(region, account_id, environment, agent_name)

    # -- Resolve the AMI (prebuilt base AMI by tag, or caller override) --
    if image_id is None:
        image_id = _pick_newest_ami(
            aws.describe_images({_BASE_AMI_TAG_KEY: _BASE_AMI_TAG_VALUE})
        )

    tags = _arm_tags(environment, agent_name)
    profile_name = _box_resource_name(environment, agent_name)
    policy_name = profile_name

    # -- Step 2: stage the drain-loop assets in the deploy bucket (S3-delivered boot) --
    _upload_box_assets(aws, deploy_bucket, agent_name)

    # -- Step 3: per-box instance profile + the box inline policy (no connector authority) --
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": box_role_extensions(
            agent_name, environment, agent_runs_table_arn, oauth_secret_id,
            tables_key_arn, inbound_queue_arn, deploy_bucket,
        ),
    }
    profile_arn = _ensure_instance_profile(aws, profile_name, role_name, policy_name, policy_doc, tags)

    # -- Step 4: render user-data + launch the box in the agent subnet on the agent SG --
    user_data_plain = render_box_user_data(
        agent_name=agent_name,
        deploy_bucket=deploy_bucket,
        broker_dns=broker_dns,
        agent_runs_table=agent_runs_table_name,
        inbound_queue_url=inbound_queue_url,
        region=region,
        oauth_secret_id=oauth_secret_id,
        idle_polls=idle_polls,
    )
    # gzip then base64: cloud-init auto-detects gzip-magic user-data and decompresses it. The
    # assets are now S3-delivered, so this stays well under the 16 KB encoded user-data cap.
    user_data_b64 = base64.b64encode(gzip.compress(user_data_plain.encode())).decode()

    instance_id = _run_instances_with_iam_retry(
        aws,
        name=agent_name,
        image_id=image_id,
        instance_type=instance_type,
        iam_instance_profile_arn=profile_arn,
        security_group_ids=[agent_sg_id, endpoint_sg_id],
        subnet_id=agent_subnet_id,
        user_data_b64=user_data_b64,
        tags=tags,
        backoff_base=_iam_backoff_base,
    )

    logger.info(
        "ec2_woken_box_provision: launched confined woken box %s for agent %r "
        "(subnet=%s sg=%s queue=%s)",
        instance_id, agent_name, agent_subnet_id, agent_sg_id, inbound_queue_url,
    )
    return instance_id


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def ec2_woken_box_teardown(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
) -> dict:
    """Remove the box ec2_woken_box_provision() created for this agent.

    Discovers the box by the standard tag set (Project + Environment + Agent + ManagedBy),
    terminates it, and removes the per-box instance profile + inline policy (names from the
    deterministic convention — no saved state). Idempotent; NEVER touches the airlock stack, the
    base agentRole, or any infra/ floor resource.
    """
    report: dict = {
        "instances_terminated": [],
        "instances_already_gone": [],
        "profile_removed": False,
        "profile_already_gone": False,
        "policy_removed": False,
        "policy_already_gone": False,
        "role_name": "",
    }

    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": manifest.name,
        "ManagedBy": "safe-agents-pipeline",
        "Arm": "ec2-woken",
    }
    instances = aws.describe_instances_by_tags(discovery_tags)
    if instances:
        instance_ids = [i["instance_id"] for i in instances]
        terminated = aws.terminate_instances(instance_ids)
        report["instances_terminated"] = terminated
        report["instances_already_gone"] = [i for i in instance_ids if i not in terminated]

    resource_name = _box_resource_name(environment, manifest.name)
    role_arn = aws.get_ssm_param(f"/safe-agents/{environment}/agent-role-arn") or ""
    role_name = role_arn.split("/")[-1] if role_arn else ""
    report["role_name"] = role_name

    if role_name and aws.delete_role_policy(role_name, resource_name):
        report["policy_removed"] = True
    else:
        report["policy_already_gone"] = True

    if aws.delete_instance_profile(resource_name):
        report["profile_removed"] = True
    else:
        report["profile_already_gone"] = True

    logger.info("ec2_woken_box_teardown: agent %r — %s", manifest.name, report)
    return report
