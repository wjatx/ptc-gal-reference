"""
RHEL+OpenShell arm provisioner and teardown — arm=rhel-openshell (sa#91).

Re-derives the RHEL host provisioning from a development harness's reference
(its infrastructure/dev-box.yaml + bootstrap.sh), re-derived CLEAN per the
decoupling discipline (snapshot-then-own; no harness code imported).

How it plugs into the pipeline:
    provision_phase() in safe_agents/pipeline/phases.py calls rhel_openshell_provision()
    for arm=rhel-openshell. teardown_phase() calls rhel_openshell_teardown().

Reuses the EC2 arm's hardened pipeline gating (sa#90):
    wait_for_clean_start, _ensure_foundation, _wait_for_iam_propagation,
    _run_instances_with_iam_retry, wait_for_ssm_online are imported from
    arms.ec2.provision — the canonical implementation lives there.

RHEL-specific differences from the EC2 arm:
    AMI:      Prefers the prebuilt safe-agents RHEL base AMI (sa#109, tag
              safe-agents:ami=base-rhel) — like the EC2 arm's tag-resolved base AMI
              but built from a RHEL 9 x86_64 parent. Falls back to the RHEL 9
              marketplace AMI (Red Hat owner 309956199498 + name filter) when no
              bake exists. The prebuilt AMI is what makes the box config-only.
    Instance: m7i.xlarge (x86_64, 4 vCPU, 16 GB). Root /dev/sda1, 100 GB gp3.
              RHEL+OpenShell is x86_64 only; arm64 is not supported by OpenShell.
    Subnet:   agent-subnet-ids (isolated, no NAT) + agent SG + endpoint SG — the same
              converged two-box placement the EC2 arm uses (sa#35). The confined agent
              does a real brokered round-trip against the broker SERVICE; the netns is a
              defense-in-depth layer that FORWARDS to the broker (agent-netns-setup.sh).
    IAM:      GetSecretValue on <agent>/* (deploy key, runner-keys, oauth token);
              EC2 arm uses the narrower <agent>/claude-oauth-token* path. Plus the
              tables-CMK KMS grant (run-record PutItem into the CMK-encrypted table).
    Bootstrap:Config-only on the prebuilt AMI (sa#109): the internet toolchain (SSM
              agent, AWS CLI, node/claude via npm, dnf core tools) is baked in, so a
              box in the isolated no-NAT subnet boots without egress. bootstrap.sh's
              install scripts are guarded (command -v short-circuits) — see the RHEL
              bakery at arms/rhel_openshell/ami and its README.
    Tagging:  Adds Arm=rhel-openshell tag so teardown never touches EC2 instances
              for the same agent.

Two-identity split:
    agentRole  — SSM core + GetSecretValue on <agent>/* + S3 deploy-bundle read
                 + run-record PutItem. Holds NO connector creds.
    brokerRole — reads connector credentials (*/connectors/*), managed by IdentityStack.

IAM profile naming:
    safe-agents-{environment}-{agent_name}-rhel  (suffix distinguishes from EC2 arm).
"""
from __future__ import annotations

import base64
import gzip
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from safe_agents.pipeline.aws_interface import AWSInterface
    from safe_agents.pipeline.manifest import DeploymentManifest


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

_TEMPLATE_PATH = Path(__file__).parent / "user-data.sh.tmpl"

_REQUIRED_PARAMS: frozenset[str] = frozenset(
    {"name", "arm", "oauth_token", "environment", "broker_dns", "agent_runs_table", "region"}
)

_MARKER_RE = re.compile(r"\{\{([^}]+)\}\}")


def render_user_data(params: dict[str, str]) -> str:
    """Render user-data.sh.tmpl with the given manifest parameters.

    All {{key}} markers are replaced with their corresponding values. Raises
    ValueError if required keys are missing or any markers remain after
    substitution.

    Parameters
    ----------
    params:
        Mapping of template-marker names to their string values.

    Returns
    -------
    The rendered shell script as a plain string (not base64-encoded).
    """
    missing = _REQUIRED_PARAMS - set(params)
    if missing:
        raise ValueError(
            f"render_user_data: missing required template params: {sorted(missing)}"
        )

    with _TEMPLATE_PATH.open(encoding="utf-8") as fh:
        rendered = fh.read()

    for key, value in params.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)

    remaining = _MARKER_RE.findall(rendered)
    if remaining:
        raise ValueError(
            f"render_user_data: unsubstituted template markers after render: {remaining}"
        )

    return rendered


# ---------------------------------------------------------------------------
# IAM policy (agent_role_extensions for the RHEL+OpenShell arm)
# ---------------------------------------------------------------------------

# The Secrets Manager broker connector-keys pattern. agentRole MUST NOT match this.
BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN = "*/connectors/*"


def agent_role_extensions(
    manifest_name: str,
    environment: str,
    agent_runs_table_arn: str,
    tables_key_arn: str,
) -> list[dict]:
    """IAM policy statements the rhel-openshell arm attaches to agentRole.

    GetSecretValue scope is broader than the EC2 arm: the RHEL host bootstraps
    from a marketplace AMI and needs the deploy key + runner-keys + oauth_token
    all under the agent's own Secrets Manager namespace (<agent>/*).
    The broker connector-keys path (*/connectors/*) is entirely absent.

    Converged two-box model (sa#35): run-brokered.sh writes a run record to the
    CMK-encrypted agent-runs table, so the role gains a KMS grant on the ONE tables
    CMK (GenerateDataKey/Decrypt) — mirrors the EC2 arm's RunRecordKey statement.

    Parameters
    ----------
    manifest_name:
        The agent's deployment manifest name. Used to scope IAM resources.
    environment:
        Deployment environment (development | staging | production).
    agent_runs_table_arn:
        ARN of the agent-runs DynamoDB table for this environment.
    tables_key_arn:
        ARN of the tables CMK (StateStack "tables-key-arn"). The agent-runs table
        is CMK-encrypted; the run-record PutItem needs GenerateDataKey/Decrypt on it.
    """
    return [
        {
            # Run-record write (same as EC2 arm).
            "Sid": f"RunRecord{environment.capitalize()}",
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": agent_runs_table_arn,
        },
        {
            # The agent-runs table is CMK-encrypted; a PutItem must wrap the item data
            # key. Scoped to the single tables CMK — not kms:* on all keys. Mirrors the
            # EC2 arm + the Fargate arm.
            "Sid": "RunRecordKey",
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": tables_key_arn,
        },
        {
            # Agent secrets: deploy key + runner-keys + oauth_token — all scoped
            # to this agent's namespace. The broker connector-keys path (*/connectors/*)
            # is absent; brokerRole holds those.
            "Sid": "AgentSecrets",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": f"arn:*:secretsmanager:*:*:secret:{manifest_name}/*",
        },
        {
            # S3 deploy bucket: agent code bundle + platform/contract bundle.
            # Same as the EC2 arm.
            "Sid": "DeployBundleRead",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [
                f"arn:aws:s3:::safe-agents-{environment}-deploy/agents/{manifest_name}/*",
                f"arn:aws:s3:::safe-agents-{environment}-deploy/platform/*",
            ],
        },
        {
            # SSM Session Manager: enables access without inbound SSH.
            "Sid": "SsmCore",
            "Effect": "Allow",
            "Action": [
                "ssm:UpdateInstanceInformation",
                "ssmmessages:CreateControlChannel",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel",
                "ec2messages:AcknowledgeMessage",
                "ec2messages:DeleteMessage",
                "ec2messages:FailMessage",
                "ec2messages:GetEndpoint",
                "ec2messages:GetMessages",
                "ec2messages:SendReply",
            ],
            "Resource": "*",
        },
    ]


# ---------------------------------------------------------------------------
# RHEL AMI resolution
# ---------------------------------------------------------------------------

# Tag that identifies a prebuilt safe-agents RHEL base AMI (sa#109). The RHEL
# bakery (arms/rhel_openshell/ami) tags its output AMI with this so a fresh
# provision into the ISOLATED no-NAT subnet boots config-only — the toolchain
# (node/claude/aws-cli/ssm-agent) is already baked in, no internet needed at boot.
# Distinct from the EC2 arm's "base" so the two bakeries never cross wires.
BASE_RHEL_AMI_TAG_FILTER: dict[str, str] = {"safe-agents:ami": "base-rhel"}

# Red Hat's AWS account ID (owner of RHEL marketplace AMIs in all regions).
RHEL_OWNER_ID = "309956199498"

# Name glob for RHEL 9 x86_64 Hourly2 GP3 AMIs (marketplace).
# To refresh the latest AMI ID for a region:
#   aws ec2 describe-images --owners 309956199498 \
#     --filters "Name=name,Values=RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3" \
#     --query "sort_by(Images, &CreationDate)[-1].{id:ImageId,name:Name}" \
#     --output table
RHEL9_NAME_PATTERN = "RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3"


def _pick_newest_rhel_ami(images: list[dict]) -> str:
    """Return the image_id of the newest RHEL 9 AMI.

    Selects the most recently created image by creation_date (ISO 8601 string,
    lexicographically sortable). Raises RuntimeError when the list is empty.
    """
    if not images:
        raise RuntimeError(
            "rhel_openshell_provision: no RHEL 9 AMI found for owner "
            f"{RHEL_OWNER_ID!r} with name pattern {RHEL9_NAME_PATTERN!r}. "
            "Run the describe-images refresh command (see RHEL9_NAME_PATTERN comment) "
            "to confirm the AMI is available in this region."
        )
    return max(images, key=lambda img: img.get("creation_date", ""))["image_id"]


def _resolve_base_ami(aws: "AWSInterface") -> str:
    """Resolve the AMI the RHEL box launches from.

    Prefers a prebuilt safe-agents RHEL base AMI (sa#109): the newest self-owned
    image tagged ``safe-agents:ami=base-rhel``. That AMI has the toolchain baked
    in, so the box boots config-only in the ISOLATED no-NAT agent subnet.

    Falls back to the RHEL 9 marketplace AMI (owner + name filter) when no bake
    exists yet — a fresh account, or before the first bake runs. The fallback is
    the pre-sa#109 behavior; it only completes bootstrap in a subnet with egress.
    """
    baked = aws.describe_images(BASE_RHEL_AMI_TAG_FILTER)
    if baked:
        newest = max(baked, key=lambda img: img.get("creation_date", ""))
        logger.info(
            "rhel_openshell_provision: using prebuilt base AMI %s (tag %s)",
            newest["image_id"], BASE_RHEL_AMI_TAG_FILTER,
        )
        return newest["image_id"]

    logger.warning(
        "rhel_openshell_provision: no prebuilt base AMI tagged %s found; falling "
        "back to the RHEL 9 marketplace AMI. A fresh box in the isolated no-NAT "
        "subnet needs the bake (sa#109) to complete bootstrap — run the "
        "safe-agents-base-rhel Image Builder pipeline first.",
        BASE_RHEL_AMI_TAG_FILTER,
    )
    rhel_images = aws.describe_images_by_owner_name(RHEL_OWNER_ID, RHEL9_NAME_PATTERN)
    return _pick_newest_rhel_ami(rhel_images)


# ---------------------------------------------------------------------------
# Instance config constants
# ---------------------------------------------------------------------------

# m7i.xlarge: x86_64, 4 vCPU, 16 GB RAM — production default.
# OpenShell is x86_64 only; arm64 AMIs are NOT compatible.
# t3.medium (4 GB) is the minimum floor for interactive + sandbox use.
DEFAULT_INSTANCE_TYPE = "m7i.xlarge"

# RHEL 9 roots at /dev/sda1 (NOT /dev/xvda which is AL2023's device name).
# Using the wrong name creates a second unused volume and leaves root at the
# AMI's ~10 GB default. cloud-init grows the FS on boot to fill the volume.
RHEL_ROOT_DEVICE = "/dev/sda1"
RHEL_ROOT_VOLUME_GIB = 100
RHEL_ROOT_VOLUME_TYPE = "gp3"

# Polling / timing constants (same values as EC2 arm for consistency).
_CLEAN_START_EC2_TIMEOUT_S = 120.0
_CLEAN_START_IAM_TIMEOUT_S = 30.0
_CLEAN_START_POLL_INTERVAL_S = 5.0
_IAM_PROPAGATION_POLL_INTERVAL_S = 5.0
_IAM_PROPAGATION_MAX_WAIT_S = 60.0
_IAM_PROPAGATION_BUFFER_S = 5.0
_SSM_ONLINE_TIMEOUT_S = 300.0
_SSM_ONLINE_POLL_INTERVAL_S = 10.0


def _resource_name(environment: str, agent_name: str) -> str:
    """Naming convention for per-agent IAM resources on the RHEL arm.

    Appends '-rhel' to distinguish from EC2 arm profiles for the same agent.
    Example: "safe-agents-development-smoke-rhel-openshell-rhel".
    """
    return f"safe-agents-{environment}-{agent_name}-rhel"


def _arm_tags(environment: str, agent_name: str) -> dict[str, str]:
    """Standard tag set for RHEL+OpenShell arm resources.

    Includes Arm=rhel-openshell so teardown never accidentally touches EC2
    instances for the same agent, and so Cost Explorer can attribute RHEL costs.
    """
    return {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
        "Arm": "rhel-openshell",
        "Name": f"safe-agents-{environment}-{agent_name}-rhel",
    }


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

def rhel_openshell_provision(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
    region: str = "us-east-1",
    instance_type: str = DEFAULT_INSTANCE_TYPE,
    image_id: Optional[str] = None,
    # Poll-interval overrides for tests — keep defaults at production values.
    # Pass 0.0 for poll intervals and short timeouts in unit tests to avoid real sleeps.
    _clean_start_ec2_timeout: float = _CLEAN_START_EC2_TIMEOUT_S,
    _clean_start_iam_timeout: float = _CLEAN_START_IAM_TIMEOUT_S,
    _clean_start_poll_interval: float = _CLEAN_START_POLL_INTERVAL_S,
    _iam_poll_interval: float = _IAM_PROPAGATION_POLL_INTERVAL_S,
    _iam_max_wait: float = _IAM_PROPAGATION_MAX_WAIT_S,
    _iam_extra_buffer: float = _IAM_PROPAGATION_BUFFER_S,
    _ssm_timeout: float = _SSM_ONLINE_TIMEOUT_S,
    _ssm_poll_interval: float = _SSM_ONLINE_POLL_INTERVAL_S,
) -> str:
    """Provision the RHEL+OpenShell host for arm=rhel-openshell.

    Reuses the EC2 arm's hardened five-step gating (sa#90):
      0. wait_for_clean_start — prior instances terminated; IAM profile stable.
      1. ensure_foundation (idempotent) — create/reuse instance profile + inline policy.
      2. wait_for_iam_propagation — poll until role visible in profile, then buffer.
      3. launch_instance — RunInstances with IAM-race retry; /dev/sda1 100 GB gp3.
      4. wait_for_ssm_online — poll SSM until PingStatus='Online'.

    Provision reports success ONLY after step 4 confirms SSM Online. A false success
    on an unmanaged box is never returned.

    Parameters
    ----------
    manifest:
        Loaded deployment manifest. Must have arm="rhel-openshell".
    aws:
        AWSInterface implementation. Injected by the pipeline.
    environment:
        Deployment environment. Used to resolve infra SSM parameters.
    instance_type:
        EC2 instance type. Defaults to m7i.xlarge (x86_64; OpenShell requires x86_64).
    image_id:
        AMI ID. When None (default), resolved by RHEL owner+name filter.

    Returns
    -------
    EC2 instance ID (e.g. "i-0abc123def456789a").
    """
    # Reuse the EC2 arm's hardened gating functions (lazy import — arms/ec2 is a
    # sibling package; importable when core/ is on sys.path).
    from safe_agents.arms.ec2.provision import (  # noqa: PLC0415
        _ensure_foundation,
        _run_instances_with_iam_retry,
        _wait_for_iam_propagation,
        wait_for_clean_start,
        wait_for_ssm_online,
    )

    def _ssm(key: str) -> str:
        path = f"/safe-agents/{environment}/{key}"
        value = aws.get_ssm_param(path)
        if not value:
            raise RuntimeError(
                f"rhel_openshell_provision: SSM param {path!r} not found; "
                "has the infra/ foundation stack been deployed for this environment?"
            )
        return value

    agent_role_arn = _ssm("agent-role-arn")
    # Converged two-box confinement (sa#35, Option A): the box runs in the ISOLATED agent subnet
    # (no NAT) on the agent SG — whose only egress is the broker SG (+ the endpoint SG for the AWS
    # interface endpoints) — the SAME placement the proven EC2 arm + ec2-woken box use. The subnet
    # has no internet route and the agent SG permits only the broker, so the box (and anything in
    # its netns) physically cannot reach the internet or a connector host. That is what makes the
    # smoke-egress assertion hold; the netns is a SECOND, process-isolation layer that forwards to
    # the broker. The endpoint SG lets the box reach Secrets Manager (its oauth) + DynamoDB (run
    # records) + SSM (on-demand run-brokered invocation) from a no-NAT subnet.
    #
    # sa#109: this box now launches from a prebuilt RHEL base AMI (tag safe-agents:ami=base-rhel,
    # resolved by _resolve_base_ami below) with the internet toolchain — SSM agent, AWS CLI,
    # node/claude via npm, dnf core tools — baked in. npm's registry is not S3-backed, so baking is
    # exactly what lets a FRESH provision into this isolated no-NAT subnet complete bootstrap. When
    # no bake exists yet, _resolve_base_ami falls back to the RHEL 9 marketplace AMI (which only
    # completes bootstrap in a subnet with egress).
    agent_sg_id = _ssm("agent-sg-id")
    endpoint_sg_id = _ssm("endpoint-sg-id")
    # agent-subnet-ids is a comma-joined list; use the first subnet (isolated, no NAT).
    agent_subnet_id = _ssm("agent-subnet-ids").split(",")[0].strip()
    agent_runs_table_arn = _ssm("agent-runs-table-arn")
    agent_runs_table_name = _ssm("agent-runs-table-name")
    tables_key_arn = _ssm("tables-key-arn")
    broker_dns = _ssm("broker-service-dns")

    role_name = agent_role_arn.split("/")[-1]

    # AMI: prefer the prebuilt safe-agents RHEL base AMI (sa#109, tag
    # safe-agents:ami=base-rhel); fall back to the RHEL 9 marketplace AMI when no
    # bake exists. The prebuilt AMI is what makes this box config-only in the
    # isolated no-NAT subnet.
    if image_id is None:
        image_id = _resolve_base_ami(aws)

    tags = _arm_tags(environment, manifest.name)
    profile_name = _resource_name(environment, manifest.name)
    policy_name = profile_name  # one inline policy per agent per env

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": agent_role_extensions(
            manifest.name, environment, agent_runs_table_arn, tables_key_arn
        ),
    }

    # -- Step 0: wait_for_clean_start (precondition gate) ----------------------
    wait_for_clean_start(
        aws,
        environment=environment,
        agent_name=manifest.name,
        profile_name=profile_name,
        role_name=role_name,
        ec2_timeout=_clean_start_ec2_timeout,
        iam_timeout=_clean_start_iam_timeout,
        poll_interval=_clean_start_poll_interval,
    )

    # -- Step 1: ensure_foundation (idempotent) --------------------------------
    profile_arn = _ensure_foundation(
        aws, profile_name, role_name, policy_name, policy_doc, tags
    )

    # -- Step 2: wait_for_iam_propagation -------------------------------------
    _wait_for_iam_propagation(
        aws, profile_name, role_name,
        poll_interval=_iam_poll_interval,
        max_wait=_iam_max_wait,
        extra_buffer=_iam_extra_buffer,
    )

    # -- Render user-data ------------------------------------------------------
    # sa#35: broker_dns / agent_runs_table / region are threaded into the box env contract
    # (/etc/safe-agents/agent.env) so run-brokered.sh can do the broker-SERVICE round-trip + the
    # run-record write, replacing the old co-located model-proxy stub.
    params: dict[str, str] = {
        "name": manifest.name,
        "arm": manifest.arm,
        "oauth_token": manifest.secrets.oauth_token or f"{manifest.name}/claude-oauth-token",
        "environment": environment,
        "broker_dns": broker_dns,
        "agent_runs_table": agent_runs_table_name,
        "region": region,
    }
    user_data_plain = render_user_data(params)
    # The rendered RHEL bootstrap exceeds EC2's 25,600-byte user-data limit. cloud-init
    # auto-detects gzip-magic user-data and decompresses it before running, so gzip then base64
    # (the documented technique for this limit). ~13KB raw -> ~5KB gzipped, well under the cap.
    user_data_b64 = base64.b64encode(gzip.compress(user_data_plain.encode())).decode()

    # RHEL 9 root device: /dev/sda1 (AL2023 uses /dev/xvda; wrong name creates
    # a second unused volume and leaves root at the AMI's ~10 GB default).
    block_device_mappings = [
        {
            "DeviceName": RHEL_ROOT_DEVICE,
            "Ebs": {
                "VolumeSize": RHEL_ROOT_VOLUME_GIB,
                "VolumeType": RHEL_ROOT_VOLUME_TYPE,
                "DeleteOnTermination": True,
            },
        }
    ]

    # -- Step 3: launch_instance -----------------------------------------------
    instance_id = _run_instances_with_iam_retry(
        aws,
        name=manifest.name,
        image_id=image_id,
        instance_type=instance_type,
        iam_instance_profile_arn=profile_arn,
        security_group_ids=[agent_sg_id, endpoint_sg_id],
        subnet_id=agent_subnet_id,
        user_data_b64=user_data_b64,
        tags=tags,
        block_device_mappings=block_device_mappings,
    )

    # -- Step 4: wait_for_ssm_online -------------------------------------------
    wait_for_ssm_online(
        aws, instance_id,
        timeout=_ssm_timeout,
        poll_interval=_ssm_poll_interval,
    )

    return instance_id


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def rhel_openshell_teardown(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
) -> dict:
    """Remove all resources rhel_openshell_provision() created for this agent.

    Discovery uses the standard tag set PLUS Arm=rhel-openshell, so EC2 arm
    instances for the same agent name are never touched by the RHEL teardown.
    Derives the per-agent IAM profile and policy names from the same naming
    convention used in rhel_openshell_provision() — no reliance on saved state.

    Idempotent: a second call is a clean no-op (everything already gone).
    NEVER removes infra foundation resources (base agentRole, VPC, DynamoDB tables).

    Returns
    -------
    Report dict with keys:
        instances_terminated   — list of instance IDs actually terminated
        instances_already_gone — list of IDs found already in terminal state
        profile_removed        — True if the per-agent profile was deleted
        profile_already_gone   — True if the profile was not found (already gone)
        policy_removed         — True if the inline policy was deleted
        policy_already_gone    — True if the policy was not found (already gone)
        role_name              — IAM role name the policy was targeted at
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

    # Discovery includes Arm=rhel-openshell so EC2 arm instances are never touched.
    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": manifest.name,
        "ManagedBy": "safe-agents-pipeline",
        "Arm": "rhel-openshell",
    }
    instances = aws.describe_instances_by_tags(discovery_tags)

    if instances:
        instance_ids = [i["instance_id"] for i in instances]
        terminated = aws.terminate_instances(instance_ids)
        report["instances_terminated"] = terminated
        already_gone = [iid for iid in instance_ids if iid not in terminated]
        report["instances_already_gone"] = already_gone

    resource_name = _resource_name(environment, manifest.name)

    role_arn = aws.get_ssm_param(f"/safe-agents/{environment}/agent-role-arn") or ""
    role_name = role_arn.split("/")[-1] if role_arn else ""
    report["role_name"] = role_name

    if role_name:
        removed = aws.delete_role_policy(role_name, resource_name)
        if removed:
            report["policy_removed"] = True
        else:
            report["policy_already_gone"] = True
    else:
        report["policy_already_gone"] = True

    profile_removed = aws.delete_instance_profile(resource_name)
    if profile_removed:
        report["profile_removed"] = True
    else:
        report["profile_already_gone"] = True

    return report
