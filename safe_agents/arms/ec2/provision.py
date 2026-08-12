"""
EC2 arm provisioner and teardown — Arm 1 (always-on EC2).

Re-derives the bootstrap + EC2 provisioning from a consumer agent's reference
pattern, generalized for any agent via manifest parameters. See arms.md §Arm 1
and PORTING.md for the re-derivation rationale.

How it plugs into the pipeline (sa#32):
    provision_phase() in safe_agents/pipeline/phases.py calls ec2_provision() for arm=ec2.
    teardown_phase() calls ec2_teardown() to remove everything ec2_provision() created.
    The same AWSInterface abstraction is used throughout — FakeAWS for unit tests,
    LiveAWS for real deploys. No boto3 is imported at module load time.

Two-identity split (sa#33):
    agentRole  — zero connector authority (IdentityStack baseline). The EC2 arm
                 adds: run-record PutItem on agent-runs-<env>, GetSecretValue on
                 the agent's oauth_token path only, and SSM Session Manager core.
                 See agent_role_extensions() below.
    brokerRole — reads connector credentials (*/connectors/*), reads grants,
                 reads/writes counters+intents, PutObject-only to audit bucket.
                 Defined in IdentityStack; the broker role resource pattern is
                 BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN (tested separately).

Egress confinement (sa#35, Option A — the two-box broker model):
    The box runs in the ISOLATED agent subnet (no NAT) on the agent SG (egress = broker
    SG only) + the endpoint SG (AWS interface endpoints) — the same placement the proven
    ec2-woken box uses. The confined agent does a REAL brokered round-trip against the
    broker SERVICE at broker.safe-agents.local; the netns is KEPT as a defense-in-depth
    process-isolation layer that FORWARDS to the broker (agent-netns-setup.sh) rather than
    blackholing to a co-located stub. The per-turn runner is run-brokered.sh.

Resource tagging:
    Every resource provision creates is tagged with the standard set so teardown can
    discover them without relying on saved local state:
        Project=safe-agents
        Environment=<environment>
        Agent=<manifest.name>
        ManagedBy=safe-agents-pipeline

Teardown (ec2_teardown):
    Discovers instances by tags, terminates them, removes the per-agent instance
    profile and inline policy. Never touches infra foundation resources (the base
    agentRole or the infra VPC/tables).
"""
from __future__ import annotations

import base64
import gzip
import logging
import re
import time as _time
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

# Parameters the template requires. Validated in render_user_data().
# sa#85: repo and deploy_key_secret removed — code now arrives via S3 bundle,
# not git clone; no deploy key is needed in the prebuilt-AMI model.
# sa#35: broker_dns / agent_runs_table / region added — the converged two-box model
# writes them into /etc/safe-agents/agent.env for run-brokered.sh (broker SERVICE
# round-trip + run-record write), replacing the old co-located model-proxy stub.
_REQUIRED_PARAMS: frozenset[str] = frozenset(
    {"name", "arm", "oauth_token", "environment", "broker_dns", "agent_runs_table", "region"}
)

_MARKER_RE = re.compile(r"\{\{([^}]+)\}\}")


def render_user_data(params: dict[str, str]) -> str:
    """Render user-data.sh.tmpl with the given manifest parameters.

    All {{key}} markers are replaced with their corresponding values. Raises
    ValueError if required keys are missing or any markers remain after
    substitution (which would indicate a typo in the caller's params dict).

    Parameters
    ----------
    params:
        Mapping of template-marker names to their string values. Must include
        all keys in _REQUIRED_PARAMS.

    Returns
    -------
    The rendered shell script as a plain string (not base64-encoded).
    """
    missing = _REQUIRED_PARAMS - set(params)
    if missing:
        raise ValueError(
            f"render_user_data: missing required template params: {sorted(missing)}"
        )

    with _TEMPLATE_PATH.open() as fh:
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
# Two-identity policy definitions (testable at the rendered-policy level)
# ---------------------------------------------------------------------------

# The Secrets Manager resource ARN pattern the IdentityStack grants brokerRole.
# The agentRole extensions produced by agent_role_extensions() must NOT match
# this pattern — that is the machine-checkable invariant for the two-identity split.
BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN = "*/connectors/*"


def agent_role_extensions(
    manifest_name: str,
    environment: str,
    agent_runs_table_arn: str,
    tables_key_arn: str,
) -> list[dict]:
    """IAM policy statements the EC2 arm attaches to the agentRole.

    These sit on top of the IdentityStack's zero-policy agentRole baseline
    (which holds no connector authority). The arm adds only the minimum rights
    the box needs to run a confined + brokered turn:

      RunRecord    — PutItem on the agent-runs table for this environment.
      RunRecordKey — the tables CMK (the agent-runs table is CMK-encrypted, so a
                     PutItem must wrap the item data key). Scoped to the ONE CMK.
      OauthToken   — GetSecretValue on the agent's own oauth_token secret path
                     (NOT */connectors/* — broker-only territory).
      DeployBundleRead — GetObject on this agent's + the platform's deploy prefixes.
      SsmCore      — Session Manager access; no inbound SSH on the instance.

    The two-box shape mirrors the ec2-woken box_role_extensions (Secrets Manager on
    its own oauth, DynamoDB PutItem on agent-runs, KMS on the tables CMK) and holds
    NO connector authority. The returned statements are plain dicts (IAM policy
    statement shape) so they can be asserted in unit tests without any AWS SDK.

    Parameters
    ----------
    manifest_name:
        The agent's deployment manifest name (e.g. "test-stub"). Used to scope
        the oauth_token secret ARN to this agent's namespace only.
    environment:
        Deployment environment (development | staging | production). Used in
        the Sid tags for auditing clarity.
    agent_runs_table_arn:
        ARN of the agent-runs DynamoDB table for this environment. Exported by
        StateStack as "agent-runs-table-arn" and resolved via SSM at provision time.
    tables_key_arn:
        ARN of the tables CMK (StateStack "tables-key-arn"). The agent-runs table
        is CMK-encrypted; the run-record PutItem needs GenerateDataKey/Decrypt on it.
    """
    return [
        {
            # Run-record write: agentRole may write its own run records.
            # No read access to the grants/counters/intents tables (broker-only).
            "Sid": f"RunRecord{environment.capitalize()}",
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": agent_runs_table_arn,
        },
        {
            # The agent-runs table is CMK-encrypted; a PutItem must wrap the item data
            # key. Scoped to the single tables CMK — not kms:* on all keys. Mirrors the
            # ec2-woken box + the Fargate arm.
            "Sid": "RunRecordKey",
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": tables_key_arn,
        },
        {
            # OAuth token: agentRole reads ONLY the agent's own oauth_token path.
            # The broker connector-keys path (*/connectors/*) is entirely absent here.
            # A wildcard suffix covers the Secrets Manager version suffix appended to
            # the secret ARN (e.g. "test-stub/claude-oauth-token-AbCdEf").
            "Sid": "OauthToken",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": (
                f"arn:*:secretsmanager:*:*:secret:{manifest_name}/claude-oauth-token*"
            ),
        },
        {
            # S3 deploy bucket: read ONLY this agent's code bundle and the shared
            # platform bundle (the conformance harness). Delivered at boot via the S3
            # gateway endpoint (sa#88: code + harness arrive via S3, not git). No write,
            # no other agents' paths, no other buckets.
            "Sid": "DeployBundleRead",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [
                f"arn:aws:s3:::safe-agents-{environment}-deploy/agents/{manifest_name}/*",
                f"arn:aws:s3:::safe-agents-{environment}-deploy/platform/*",
            ],
        },
        {
            # SSM Session Manager: enables interactive troubleshooting without opening
            # inbound SSH ports. IMDSv2-only box; no inbound rules on the agentSG.
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
# Provisioning
# ---------------------------------------------------------------------------

# Tag filter for the prebuilt base AMI (sa#84 bakery writes these tags).
# Key: "safe-agents:ami", value: "base" — selects the base image.
_BASE_AMI_TAG_KEY = "safe-agents:ami"
_BASE_AMI_TAG_VALUE = "base"

# Tag used to pick the newest image when multiple base AMIs exist.
# The bakery stamps a monotonically increasing version string (e.g. "20241201-01").
_BASE_AMI_VERSION_TAG_KEY = "safe-agents:ami-version"

# Default instance type for the always-on EC2 arm (arm64, 2 vCPU, 2 GB RAM).
DEFAULT_INSTANCE_TYPE = "t4g.small"

# IAM instance-profile propagation race: RunInstances may return
# "Invalid IAM Instance Profile ARN" for tens of seconds after profile creation.
# Retry with exponential backoff until the profile is ready or this cap is hit.
_IAM_RACE_MAX_ATTEMPTS = 6
_IAM_RACE_BACKOFF_BASE_S = 2  # seconds; delay doubles each attempt

# Clean-start precondition gate: runs BEFORE ensure_foundation to verify that
# prior resources from a previous provision have actually finished cleaning up.
_CLEAN_START_EC2_TIMEOUT_S = 120.0     # max seconds to wait for prior instances to terminate
_CLEAN_START_IAM_TIMEOUT_S = 30.0      # max seconds to wait for profile to reach stable state
_CLEAN_START_POLL_INTERVAL_S = 5.0     # seconds between precondition polls

# IAM propagation polling: after creating the instance profile, poll until the
# role is visible, plus a small buffer before launching.
_IAM_PROPAGATION_POLL_INTERVAL_S = 5.0   # seconds between get_instance_profile polls
_IAM_PROPAGATION_MAX_WAIT_S = 60.0       # max seconds before giving up
_IAM_PROPAGATION_BUFFER_S = 5.0          # extra buffer after role is seen (IAM eventual-consistency)

# SSM Online polling: after launch, poll until the instance registers with SSM.
# Provision must NOT report success until SSM confirms the instance is managed.
_SSM_ONLINE_TIMEOUT_S = 300.0     # default max seconds to wait (configurable; override in tests)
_SSM_ONLINE_POLL_INTERVAL_S = 10.0  # seconds between describe_instance_information polls


def _pick_newest_ami(images: list[dict]) -> str:
    """Return the image_id of the newest base AMI from a describe_images result.

    Selects by the safe-agents:ami-version tag value (lexicographic max, which
    works for ISO-date-prefixed versions like "20241201-01"). Raises RuntimeError
    when the list is empty (no base AMI available).
    """
    if not images:
        raise RuntimeError(
            "ec2_provision: no base AMI found with tag "
            f"{_BASE_AMI_TAG_KEY}={_BASE_AMI_TAG_VALUE!r}; "
            "has the AMI bakery (sa#84) been run for this account/region?"
        )
    return max(images, key=lambda img: img["tags"].get(_BASE_AMI_VERSION_TAG_KEY, ""))["image_id"]


def _run_instances_with_iam_retry(
    aws: "AWSInterface",
    *,
    max_attempts: int = _IAM_RACE_MAX_ATTEMPTS,
    backoff_base: float = _IAM_RACE_BACKOFF_BASE_S,
    **kwargs,
) -> str:
    """Call aws.run_instances, retrying on IamProfileNotReadyError.

    IAM instance profiles take up to ~10 s to propagate after creation. RunInstances
    returns "Invalid IAM Instance Profile ARN" during that window. This wrapper
    retries with exponential backoff (2 s, 4 s, 8 s, …) up to max_attempts times.

    Parameters
    ----------
    aws:
        AWSInterface (real or fake).
    max_attempts:
        Total attempts before re-raising the last error.
    backoff_base:
        Base delay in seconds; doubles each retry. Pass 0 in tests that
        use FakeAWS to avoid real sleeps.
    **kwargs:
        Forwarded verbatim to aws.run_instances (all keyword-only).

    Returns
    -------
    EC2 instance ID on success.
    """
    from safe_agents.pipeline.aws_interface import IamProfileNotReadyError  # noqa: PLC0415

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return aws.run_instances(**kwargs)
        except IamProfileNotReadyError as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
            wait = backoff_base * (2 ** (attempt - 1))
            logger.warning(
                "ec2_provision: IAM profile not ready (attempt %d/%d); "
                "retrying in %.1f s",
                attempt, max_attempts, wait,
            )
            _time.sleep(wait)
    raise RuntimeError(
        f"ec2_provision: RunInstances failed after {max_attempts} attempts "
        f"(IAM profile propagation race): {last_exc}"
    ) from last_exc


def _wait_for_ec2_clean(
    aws: "AWSInterface",
    discovery_tags: dict,
    *,
    timeout: float,
    poll_interval: float,
) -> None:
    """Wait until no non-terminal instances exist with the agent's discovery tags.

    Classifies non-terminated instances into two buckets:
      - 'shutting-down' / 'stopping' → transitional; wait for them to reach 'terminated'.
      - 'running' / 'pending' / 'stopped'  → actively blocking; raise immediately
        (a prior provision is still live — teardown is required before re-provisioning).

    Raises RuntimeError if transitional instances do not terminate within timeout.
    """
    import time as _clock  # local import: real monotonic bypasses _time mock in tests

    deadline = _clock.monotonic() + timeout
    while True:
        instances = aws.describe_instances_by_tags(discovery_tags)
        if not instances:
            return  # No non-terminal instances: slot is clear

        transitional_states = frozenset({"shutting-down", "stopping"})
        blocking = [i for i in instances if i["state"] not in transitional_states]
        transitional = [i for i in instances if i["state"] in transitional_states]

        if blocking:
            ids = [i["instance_id"] for i in blocking]
            states = {i["instance_id"]: i["state"] for i in blocking}
            raise RuntimeError(
                f"ec2_provision: prior instance(s) {ids} are still active "
                f"(states: {states}). Run '--phase teardown' before re-provisioning "
                f"agent {discovery_tags.get('Agent', '?')!r}. "
                "Terminating a live agent instance requires an explicit teardown."
            )

        # Only transitional instances remain — wait for them to finish terminating.
        if _clock.monotonic() >= deadline:
            ids = [i["instance_id"] for i in transitional]
            raise RuntimeError(
                f"ec2_provision: prior instance(s) {ids} are still in transition "
                f"(shutting-down/stopping) and did not reach 'terminated' within "
                f"{timeout:.0f}s. Check the EC2 console for stuck terminations."
            )
        logger.debug(
            "ec2_provision: prior instance(s) %s still transitioning (%s); waiting ...",
            [i["instance_id"] for i in transitional],
            [i["state"] for i in transitional],
        )
        _time.sleep(poll_interval)


def _wait_for_iam_clean(
    aws: "AWSInterface",
    profile_name: str,
    role_name: str,
    *,
    timeout: float,
    poll_interval: float,
) -> None:
    """Wait until the instance profile is in a stable state for a fresh provision.

    A stable state is one of:
      - Profile absent (fully deleted): ensure_foundation will create it.
      - Profile present with the role attached: ensure_foundation will reuse it.

    Profile exists but role NOT attached is unstable — it indicates a delete is in
    flight (role was removed but profile not yet deleted). Poll until it stabilizes.

    Raises RuntimeError if the profile does not reach a stable state within timeout.
    """
    import time as _clock  # local import: real monotonic bypasses _time mock in tests

    deadline = _clock.monotonic() + timeout
    while True:
        profile = aws.get_instance_profile(profile_name)

        if profile is None:
            # Fully absent: clean for create path.
            return

        if role_name in profile.get("roles", []):
            # Fully present with role: clean for reuse path.
            return

        # Profile present but role not attached: unstable (delete in flight).
        if _clock.monotonic() >= deadline:
            raise RuntimeError(
                f"ec2_provision: instance profile {profile_name!r} exists but role "
                f"{role_name!r} is not attached, and did not stabilize within {timeout:.0f}s. "
                "A prior teardown may be stuck mid-delete. "
                "Check the IAM console and retry."
            )
        logger.debug(
            "ec2_provision: profile %r exists but role %r not attached; "
            "waiting for stable state ...",
            profile_name, role_name,
        )
        _time.sleep(poll_interval)


def wait_for_clean_start(
    aws: "AWSInterface",
    environment: str,
    agent_name: str,
    profile_name: str,
    role_name: str,
    *,
    ec2_timeout: float = _CLEAN_START_EC2_TIMEOUT_S,
    iam_timeout: float = _CLEAN_START_IAM_TIMEOUT_S,
    poll_interval: float = _CLEAN_START_POLL_INTERVAL_S,
) -> None:
    """Pre-provision precondition gate: verify prior resources have finished cleaning up.

    This runs as the very first step of ec2_provision (before ensure_foundation or
    RunInstances). It checks two conditions:

    1. EC2: no prior instance with this agent's tags is still alive.
       - Transitional (shutting-down/stopping): wait until terminated (bounded by ec2_timeout).
       - Actively alive (running/pending/stopped): raise immediately — teardown required.

    2. IAM: the per-agent instance profile is in a stable state:
       - Fully absent (fresh provision) OR fully present with role attached (reuse).
       - Profile with role NOT attached is unstable (mid-delete): wait until stable.

    The gate guarantees the initial conditions are true before we build. Without it,
    a rapid teardown→re-provision cycle could race: the old profile mid-delete collides
    with profile creation, or a still-terminating instance confuses tag discovery.

    This function is also callable independently (e.g., from the verify phase) to
    check whether a slot is ready for re-provisioning.

    Parameters
    ----------
    aws:            AWSInterface implementation.
    environment:    Deployment environment (for tag-based EC2 discovery).
    agent_name:     Agent name (for tag-based EC2 discovery).
    profile_name:   Per-agent instance profile name to check.
    role_name:      IAM role name that must appear in the profile (if present).
    ec2_timeout:    Max seconds to wait for prior instances to terminate (default 120s).
    iam_timeout:    Max seconds to wait for profile to stabilize (default 30s).
    poll_interval:  Seconds between polls for both EC2 and IAM checks (default 5s).
                    Pass 0.0 in tests with monkeypatched _time.sleep for fast loops.

    Raises
    ------
    RuntimeError if either precondition does not hold within its timeout.
    """
    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
    }
    _wait_for_ec2_clean(aws, discovery_tags, timeout=ec2_timeout, poll_interval=poll_interval)
    _wait_for_iam_clean(aws, profile_name, role_name, timeout=iam_timeout, poll_interval=poll_interval)


def _ensure_foundation(
    aws: "AWSInterface",
    profile_name: str,
    role_name: str,
    policy_name: str,
    policy_doc: dict,
    tags: dict,
) -> str:
    """Idempotently ensure the instance profile and inline policy exist.

    Creates the instance profile and attaches the role IF the profile is absent.
    If the profile already exists (e.g. a rapid teardown→re-provision cycle left it
    behind, or the profile is a stable per-agent resource), it is reused without
    deletion. This avoids the SSM-registration race that arises when the profile is
    churned on every provision.

    The inline policy is always put/updated (put_role_policy is idempotent) so the
    correct permission set is guaranteed regardless of whether the profile was new or
    reused.

    Parameters
    ----------
    aws:            AWSInterface implementation.
    profile_name:   Per-agent instance profile name (naming convention from _resource_name).
    role_name:      IAM role name to attach (the base agentRole from IdentityStack).
    policy_name:    Inline policy name (same as profile_name).
    policy_doc:     Policy document dict (from agent_role_extensions).
    tags:           Standard tag set to apply when creating a new profile.

    Returns
    -------
    Instance profile ARN.
    """
    profile = aws.get_instance_profile(profile_name)
    if profile is None:
        # Profile is absent — create it and attach the role.
        profile_arn = aws.create_instance_profile(profile_name, tags)
        aws.add_role_to_instance_profile(profile_name, role_name)
        logger.info("ec2_provision: created instance profile %r", profile_name)
    else:
        # Profile already exists — reuse its ARN.
        profile_arn = profile["arn"]
        logger.info("ec2_provision: reusing existing instance profile %r", profile_name)
        if role_name not in profile.get("roles", []):
            # Role not yet visible (or was never attached) — attach it now.
            # add_role_to_instance_profile is idempotent: handles "already attached" gracefully.
            aws.add_role_to_instance_profile(profile_name, role_name)

    # Always put/update the inline policy (idempotent; ensures correct permission set
    # whether the profile was new or reused from a prior provision run).
    aws.put_role_policy(role_name, policy_name, policy_doc)
    return profile_arn


def _wait_for_iam_propagation(
    aws: "AWSInterface",
    profile_name: str,
    role_name: str,
    *,
    poll_interval: float = _IAM_PROPAGATION_POLL_INTERVAL_S,
    max_wait: float = _IAM_PROPAGATION_MAX_WAIT_S,
    extra_buffer: float = _IAM_PROPAGATION_BUFFER_S,
) -> None:
    """Poll get_instance_profile until the role is visible, then wait a small buffer.

    IAM is eventually consistent: even after add_role_to_instance_profile returns,
    get_instance_profile may not immediately reflect the association. This wait
    ensures the profile is usable before RunInstances is attempted.

    The extra_buffer is an additional bounded wait after the role becomes visible —
    accounting for downstream IAM caches that RunInstances may consult.

    Parameters
    ----------
    aws:            AWSInterface implementation.
    profile_name:   Per-agent instance profile name to poll.
    role_name:      IAM role name that must appear in the profile's Roles list.
    poll_interval:  Seconds between polls (default 5s; pass 0 in tests).
    max_wait:       Max seconds to wait before raising (default 60s).
    extra_buffer:   Additional seconds to wait after the role is visible (default 5s).

    Raises
    ------
    RuntimeError if the role is not visible within max_wait seconds.
    """
    import time as _clock  # local import: real monotonic even when _time is mocked in tests

    deadline = _clock.monotonic() + max_wait
    while True:
        profile = aws.get_instance_profile(profile_name)
        if profile and role_name in profile.get("roles", []):
            # Role is now visible; wait the extra buffer for downstream IAM cache flush.
            _time.sleep(extra_buffer)
            logger.info(
                "ec2_provision: IAM role %r visible in profile %r", role_name, profile_name
            )
            return
        if _clock.monotonic() >= deadline:
            break
        logger.debug(
            "ec2_provision: waiting for IAM role %r to appear in profile %r ...",
            role_name, profile_name,
        )
        _time.sleep(poll_interval)

    raise RuntimeError(
        f"ec2_provision: IAM role {role_name!r} was not visible in instance profile "
        f"{profile_name!r} within {max_wait}s. IAM propagation may be stuck — "
        "check the IAM console and retry the provision."
    )


def wait_for_ssm_online(
    aws: "AWSInterface",
    instance_id: str,
    *,
    timeout: float = _SSM_ONLINE_TIMEOUT_S,
    poll_interval: float = _SSM_ONLINE_POLL_INTERVAL_S,
) -> None:
    """Poll SSM until this instance reports PingStatus 'Online'.

    Provision MUST NOT report success until SSM confirms the instance is managed.
    If the instance never registers within the timeout, this raises RuntimeError
    with a clear diagnostic — a false success on an unmanaged box is never returned.

    Used by both ec2_provision (as part of its success criterion) and the standalone
    verify phase (pipeline verify_phase) to independently re-check SSM reachability.

    Parameters
    ----------
    aws:           AWSInterface implementation.
    instance_id:   EC2 instance ID to wait for.
    timeout:       Max seconds to wait before raising (default 300s).
    poll_interval: Seconds between polls (default 10s; pass 0.0 in tests for fast loops).

    Raises
    ------
    RuntimeError if the instance is not SSM-Online within the timeout.
    """
    import time as _clock  # local import: real monotonic even when _time is mocked in tests

    deadline = _clock.monotonic() + timeout
    while True:
        ping_status = aws.describe_ssm_instance_information(instance_id)
        if ping_status == "Online":
            logger.info("ec2_provision: instance %s is SSM Online", instance_id)
            return
        if ping_status is not None:
            logger.debug(
                "ec2_provision: instance %s SSM ping status: %s (waiting ...)",
                instance_id, ping_status,
            )
        if _clock.monotonic() >= deadline:
            break
        _time.sleep(poll_interval)

    raise RuntimeError(
        f"ec2_provision: instance {instance_id!r} did not register with SSM as 'Online' "
        f"within {timeout:.0f}s. The instance is running but unmanaged — remote smoke "
        "cannot reach it. Check the SSM Agent logs on the instance and verify the IAM "
        "policy includes all SSM Session Manager permissions (SsmCore statement)."
    )


def _resource_name(environment: str, agent_name: str) -> str:
    """Naming convention for per-agent IAM resources (profile + inline policy).

    Derives a deterministic name from environment + agent name so teardown can
    find them without persisted state. Example: "safe-agents-development-smoke-ec2".
    """
    return f"safe-agents-{environment}-{agent_name}"


def _arm_tags(environment: str, agent_name: str) -> dict[str, str]:
    """Standard tag set applied to every resource provision creates.

    Teardown discovers resources by these tags (Project + Environment + Agent +
    ManagedBy). All four tags are required on every resource.
    """
    return {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
        "Name": f"safe-agents-{environment}-{agent_name}",
    }


def ec2_provision(
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
    """Provision the EC2 instance for arm=ec2.

    Runs five explicit steps with waits/conditionals to eliminate the SSM
    re-provision race (sa#90):

      0. wait_for_clean_start — pre-provision gate: prior instances are terminated
         (or raises if any are still alive); IAM profile is in a stable state
         (absent or fully present with role attached).
      1. ensure_foundation (idempotent) — create the instance profile + attach
         the agent-role inline policy IF absent; reuse without delete if present.
      2. wait_for_iam_propagation — poll get_instance_profile until the role is
         visible, plus a bounded buffer (IAM eventual-consistency).
      3. launch_instance — RunInstances with the existing IAM-race retry.
      4. wait_for_ssm_online — poll SSM describe-instance-information until
         PingStatus='Online'; raises loudly if it never converges.

    Provision reports success ONLY after step 4 confirms the instance is SSM-managed.
    Returning from this function on an unmanaged box is never acceptable.

    All AWS calls go through the injected AWSInterface — use FakeAWS for unit
    tests (no live AWS required), LiveAWS for real deploys.

    Parameters
    ----------
    manifest:
        Loaded deployment manifest. Must have arm="ec2".
    aws:
        AWSInterface implementation. Injected by the pipeline.
    environment:
        Deployment environment. Used to resolve infra SSM parameters.
    instance_type:
        EC2 instance type. Defaults to t4g.small (arm64, free-tier eligible).
    image_id:
        AMI ID. When None (default), resolved by tag from the prebuilt base AMI.
    _clean_start_ec2_timeout, _clean_start_iam_timeout, _clean_start_poll_interval:
        Test hooks for the clean-start precondition gate (default production values).
        Pass short timeouts + 0.0 poll interval in tests.
    _iam_poll_interval, _iam_max_wait, _iam_extra_buffer:
        Test hooks for the IAM propagation wait (default production values).
    _ssm_timeout, _ssm_poll_interval:
        Test hooks for the SSM Online wait (default production values).

    Returns
    -------
    EC2 instance ID (e.g. "i-0abc123def456789a").
    """
    # -- Resolve infra exports via SSM (published by infra/ foundation stacks) --
    # SSM path convention: /safe-agents/{environment}/{key}  (naming.ts: ssmParameterName)
    def _ssm(key: str) -> str:
        path = f"/safe-agents/{environment}/{key}"
        value = aws.get_ssm_param(path)
        if not value:
            raise RuntimeError(
                f"ec2_provision: SSM param {path!r} not found; "
                "has the infra/ foundation stack been deployed for this environment?"
            )
        return value

    agent_role_arn = _ssm("agent-role-arn")
    # Converged two-box confinement (sa#35, Option A): the box runs in the ISOLATED agent subnet
    # (no NAT) on the agent SG — whose only egress is the broker SG (+ the endpoint SG for the AWS
    # interface endpoints) — the SAME placement the proven ec2-woken box uses. The subnet has no
    # internet route and the agent SG permits only the broker, so the box (and anything in its
    # netns) physically cannot reach the internet or a connector host. There is NO co-located
    # model-proxy any more (the broker is its own service), so the old broker-subnet placement is
    # gone. The endpoint SG lets the box reach Secrets Manager (its oauth) + DynamoDB (run records)
    # + SSM (on-demand run-brokered invocation) from a no-NAT subnet.
    agent_sg_id = _ssm("agent-sg-id")
    endpoint_sg_id = _ssm("endpoint-sg-id")
    # agent-subnet-ids is a comma-joined list; use the first subnet.
    agent_subnet_id = _ssm("agent-subnet-ids").split(",")[0].strip()
    agent_runs_table_arn = _ssm("agent-runs-table-arn")
    agent_runs_table_name = _ssm("agent-runs-table-name")
    tables_key_arn = _ssm("tables-key-arn")
    broker_dns = _ssm("broker-service-dns")

    # Role name is the last path segment of the ARN (works for both role and
    # instance-profile ARN shapes, since the name is always the final /-segment).
    role_name = agent_role_arn.split("/")[-1]

    # -- Resolve AMI (prebuilt base AMI via tag lookup, or caller override) ----
    # sa#85: look up the newest AMI tagged safe-agents:ami=base (built by sa#84
    # bakery) rather than the public AL2023 SSM parameter. A caller may pass an
    # explicit image_id to skip the lookup (e.g. for targeted testing).
    if image_id is None:
        images = aws.describe_images({_BASE_AMI_TAG_KEY: _BASE_AMI_TAG_VALUE})
        image_id = _pick_newest_ami(images)

    # -- Tag set (applied to every resource for teardown discovery) -----------
    tags = _arm_tags(environment, manifest.name)
    profile_name = _resource_name(environment, manifest.name)
    policy_name = profile_name  # same name; one policy per agent per env

    # -- Inline policy document (agent_role_extensions statements) ------------
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": agent_role_extensions(
            manifest.name, environment, agent_runs_table_arn, tables_key_arn
        ),
    }

    # -- Step 0: wait_for_clean_start (precondition gate) ----------------------
    # Verify that prior resources from a previous provision have finished cleaning
    # up: no live prior instances with this agent's tags, IAM profile in a stable
    # state. Without this gate, a rapid teardown→re-provision cycle can collide.
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
    # Creates the instance profile + attaches the inline policy IF absent.
    # If the profile already exists from a prior provision, reuses it — never
    # deletes+recreates, which would trigger the SSM-registration race.
    profile_arn = _ensure_foundation(aws, profile_name, role_name, policy_name, policy_doc, tags)

    # -- Step 2: wait_for_iam_propagation -------------------------------------
    # Even after add_role_to_instance_profile returns, IAM is eventually consistent:
    # RunInstances may see a stale view. Wait until the role is visible in the profile.
    _wait_for_iam_propagation(
        aws, profile_name, role_name,
        poll_interval=_iam_poll_interval,
        max_wait=_iam_max_wait,
        extra_buffer=_iam_extra_buffer,
    )

    # -- Render user-data ------------------------------------------------------
    # sa#85: repo and deploy_key_secret removed — the prebuilt-AMI model pulls
    # the agent code bundle from S3 (no git clone / deploy key needed here).
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
    # gzip then base64: cloud-init auto-detects gzip-magic user-data and decompresses it before
    # running, so this is the documented technique for the 16 KB / 25,600-byte encoded user-data
    # limit (matches the RHEL arm). base64-alone overflows once the netns-confinement wiring (sa#97)
    # is present; gzip drops ~17 KB raw to ~5 KB, well under the cap.
    user_data_b64 = base64.b64encode(gzip.compress(user_data_plain.encode())).decode()

    # -- Step 3: launch_instance (with IAM propagation belt+suspenders retry) --
    # _run_instances_with_iam_retry retries on "Invalid IAM Instance Profile ARN"
    # with exponential backoff — belt-and-suspenders on top of the propagation wait.
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
    )

    # -- Step 4: wait_for_ssm_online -------------------------------------------
    # Provision MUST NOT report success on an unmanaged box. Poll SSM until the
    # instance registers as Online. Raises loudly if it never converges.
    wait_for_ssm_online(
        aws, instance_id,
        timeout=_ssm_timeout,
        poll_interval=_ssm_poll_interval,
    )

    return instance_id


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def ec2_teardown(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
) -> dict:
    """Remove all resources ec2_provision() created for this agent.

    Discovers EC2 instances by the standard tag set (Project + Environment +
    Agent + ManagedBy). Derives the per-agent instance profile and inline
    policy names from the naming convention used in ec2_provision() — no
    reliance on saved local state.

    Idempotent: a second call is a clean no-op (everything already gone).

    NEVER removes infra foundation resources (the base agentRole, VPC, or
    DynamoDB tables). Those are owned by infra/ stacks, not this arm.

    Parameters
    ----------
    manifest:
        Loaded deployment manifest. Must have arm="ec2".
    aws:
        AWSInterface implementation. Injected by the pipeline.
    environment:
        Deployment environment. Must match what was used at provision time.

    Returns
    -------
    Report dict with keys:
        instances_terminated  — list of instance IDs actually terminated
        instances_already_gone — list of IDs found already in terminal state
        profile_removed       — True if the per-agent profile was deleted
        profile_already_gone  — True if the profile was not found (already gone)
        policy_removed        — True if the inline policy was deleted
        policy_already_gone   — True if the policy was not found (already gone)
        role_name             — IAM role name the policy was targeted at
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

    # -- Discover instances by the standard tag set ---------------------------
    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": manifest.name,
        "ManagedBy": "safe-agents-pipeline",
    }
    instances = aws.describe_instances_by_tags(discovery_tags)

    if instances:
        instance_ids = [i["instance_id"] for i in instances]
        terminated = aws.terminate_instances(instance_ids)
        report["instances_terminated"] = terminated
        already_gone = [iid for iid in instance_ids if iid not in terminated]
        report["instances_already_gone"] = already_gone
    # else: no instances found — they were never provisioned or already gone

    # -- Remove inline policy and instance profile (by naming convention) -----
    resource_name = _resource_name(environment, manifest.name)

    # Resolve the agentRole name from infra SSM (same path as provision).
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
        # SSM param not found — infra may not be deployed; note but continue.
        report["policy_already_gone"] = True

    profile_removed = aws.delete_instance_profile(resource_name)
    if profile_removed:
        report["profile_removed"] = True
    else:
        report["profile_already_gone"] = True

    return report
