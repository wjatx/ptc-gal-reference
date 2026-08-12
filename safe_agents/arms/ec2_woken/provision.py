"""
ec2-woken arm provisioner + teardown — the inbound airlock wake path (sa#34).

Re-derives the responsive-agent inbound path, generalized for any agent and stripped
to the broker-centric, agent-agnostic core:

    normalized inbound event ─▶ HTTP API webhook ─▶ guardrail Lambda ─▶ SQS + StartInstances

The guardrail Lambda is an untrusted-input taint boundary that holds NO connector
credentials. This module deploys the airlock SAM stack (airlock.yaml + airlock/) and
tears it down, parameterized from the agent manifest's `inbound:` block.

How it plugs into the pipeline (sa#32):
    provision_phase() calls ec2_woken_provision() for arm=ec2-woken; teardown_phase()
    calls ec2_woken_teardown(). Read-side AWS calls (secret read, instance discovery)
    go through the injected AWSInterface (FakeAWS in tests). The stack deploy/delete
    goes through an injected `sam_deploy` / `sam_delete` callable — defaulting to the
    `sam` CLI (see _cli_sam_deploy / _cli_sam_delete) but swappable for tests.

Why the `sam` CLI (not CloudFormation via AWSInterface):
    The airlock is a SAM app (Transform: AWS::Serverless-2016-10-31) whose Lambda code
    must be packaged and uploaded. `sam deploy` does exactly that in one command; adding
    CFN package/create-change-set/execute to the (already large) AWSInterface + FakeAWS
    would be far more surface for no gain. The deploy step is injected so tests never
    shell out. The airlock stack is self-contained — it does not ImportValue from infra/,
    so the CLI's managed deploy bucket is the only prerequisite.
"""
from __future__ import annotations

import json
import logging
import shlex
import subprocess
from typing import TYPE_CHECKING, Callable, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from safe_agents.pipeline.aws_interface import AWSInterface
    from safe_agents.pipeline.manifest import DeploymentManifest

# The airlock's Lambda execution role must never gain connector authority. This is the
# same machine-checkable pattern the other arms assert (no Resource matches */connectors/*).
BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN = "*/connectors/*"

# Stack name convention mirrors the pipeline: <arm>-<name>-<environment>.
_STACK_TEMPLATE = "ec2-woken-{name}-{environment}"


# ---------------------------------------------------------------------------
# Naming + tags
# ---------------------------------------------------------------------------

def _stack_name(agent_name: str, environment: str) -> str:
    return _STACK_TEMPLATE.format(name=agent_name, environment=environment)


def _arm_tags(environment: str, agent_name: str) -> dict[str, str]:
    """Standard tag set applied to every resource the arm provisions (Arm=ec2-woken)."""
    return {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
        "Name": f"safe-agents-{environment}-{agent_name}",
        "Arm": "ec2-woken",
    }


# ---------------------------------------------------------------------------
# Manifest inbound: block
# ---------------------------------------------------------------------------

def read_inbound_block(manifest: "DeploymentManifest") -> dict:
    """Extract + validate the manifest's `inbound:` block for the airlock.

    Required keys (agent-agnostic):
        owner_allow_list        list[str] — opaque owner identifiers allowed to wake
        injection_screen_pattern str      — regex; a match drops the message
        channel_token_secret    str       — Secrets Manager id of the shared webhook token

    Optional (defaulted by the SAM template if absent):
        intent_model / intent_prompt      env-driven classifier config
    """
    raw = manifest.raw.get("inbound")
    if not isinstance(raw, dict):
        raise RuntimeError(
            "ec2_woken_provision: manifest has no `inbound:` block; the ec2-woken arm "
            "needs owner_allow_list + injection_screen_pattern + channel_token_secret."
        )
    missing = [
        k for k in ("owner_allow_list", "injection_screen_pattern", "channel_token_secret")
        if not raw.get(k)
    ]
    if missing:
        raise RuntimeError(
            f"ec2_woken_provision: manifest `inbound:` block missing required key(s): {missing}"
        )
    allow_list = raw["owner_allow_list"]
    if not isinstance(allow_list, list) or not all(isinstance(o, str) for o in allow_list):
        raise RuntimeError(
            "ec2_woken_provision: inbound.owner_allow_list must be a list of strings"
        )
    return {
        "owner_allow_list": allow_list,
        "injection_screen_pattern": raw["injection_screen_pattern"],
        "channel_token_secret": raw["channel_token_secret"],
        "intent_model": raw.get("intent_model"),
        "intent_prompt": raw.get("intent_prompt"),
    }


# ---------------------------------------------------------------------------
# Runner discovery
# ---------------------------------------------------------------------------

def _discover_runner_instance_id(
    aws: "AWSInterface", agent_name: str, environment: str
) -> str:
    """Find the sleeping EC2 box to wake by the standard arm tag set.

    The box itself is provisioned by the EC2 arm (sa#98, deferred); the airlock only
    needs its instance id. Fails loudly if no box is found rather than deploying a wake
    path that points at nothing.
    """
    tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": agent_name,
        "ManagedBy": "safe-agents-pipeline",
    }
    instances = aws.describe_instances_by_tags(tags)
    if not instances:
        raise RuntimeError(
            f"ec2_woken_provision: no EC2 box found with tags {tags}; provision the "
            "ec2-woken box first (sa#98) or pass runner_instance_id= explicitly."
        )
    return instances[0]["instance_id"]


# ---------------------------------------------------------------------------
# SAM deploy / delete (injected; default shells out to the `sam` CLI)
# ---------------------------------------------------------------------------

# A deployer takes (template_path, stack_name, parameter_overrides, tags, region) and
# returns the stack outputs as a dict. A deleter takes (stack_name, region) -> bool.
SamDeploy = Callable[[str, str, dict, dict, str], dict]
SamDelete = Callable[[str, str], bool]


def _param_overrides_args(overrides: dict) -> list[str]:
    """Render --parameter-overrides as Key=Value tokens (SAM CLI form).

    The SAM CLI re-tokenizes each override with shlex, so a value containing spaces or
    quotes (a JSON allow-list, a regex with alternation, a prompt sentence) is split and
    truncated unless it is shlex-quoted first. shlex.quote makes each value survive SAM's
    tokenizer intact — without it OwnerAllowList='["x"]' arrives as just '[' and a regex
    truncates at its first space.
    """
    return [f"{k}={shlex.quote(str(v))}" for k, v in overrides.items()]


def _cli_sam_deploy(
    template_path: str, stack_name: str, parameter_overrides: dict, tags: dict, region: str
) -> dict:
    """Deploy the airlock stack via the `sam` CLI, then read its outputs. LIVE path.

    NOTE (security): the shared token is passed via --parameter-overrides, which is
    visible in the deployer's process listing for the duration of the command. That is
    acceptable for a deployer-run command (the token is a shared webhook secret, not a
    connector credential) but should move to a samconfig/SSM-sourced override if the
    deploy is ever run somewhere multi-tenant.
    """
    deploy_cmd = [
        "sam", "deploy",
        "--template-file", template_path,
        "--stack-name", stack_name,
        "--capabilities", "CAPABILITY_IAM",
        "--no-confirm-changeset",
        "--no-fail-on-empty-changeset",
        "--resolve-s3",
        "--region", region,
        "--tags", *[f"{k}={shlex.quote(str(v))}" for k, v in tags.items()],
        "--parameter-overrides", *_param_overrides_args(parameter_overrides),
    ]
    logger.info("ec2_woken_provision: sam deploy %s", stack_name)
    subprocess.run(deploy_cmd, check=True)

    outputs_raw = subprocess.run(
        ["sam", "list", "stack-outputs", "--stack-name", stack_name,
         "--region", region, "--output", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
    try:
        outputs = json.loads(outputs_raw)
    except json.JSONDecodeError:
        return {}
    # `sam list stack-outputs` returns a list of {OutputKey, OutputValue, ...}.
    return {o["OutputKey"]: o.get("OutputValue") for o in outputs}


def _cli_sam_delete(stack_name: str, region: str) -> bool:
    """Delete the airlock stack via the `sam` CLI. Idempotent. LIVE path."""
    logger.info("ec2_woken_provision: sam delete %s", stack_name)
    result = subprocess.run(
        ["sam", "delete", "--stack-name", stack_name, "--region", region, "--no-prompts"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Provision
# ---------------------------------------------------------------------------

def _template_path() -> str:
    from pathlib import Path  # noqa: PLC0415
    return str(Path(__file__).parent / "airlock.yaml")


def ec2_woken_provision(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",
    *,
    environment: str = "development",
    region: str = "us-east-1",
    runner_instance_id: Optional[str] = None,
    sam_deploy: Optional[SamDeploy] = None,
    template_path: Optional[str] = None,
) -> dict:
    """Provision the inbound airlock wake stack for arm=ec2-woken.

    Steps:
      1. Read the manifest `inbound:` block (owner_allow_list, injection_screen_pattern,
         channel_token_secret, optional intent_model/intent_prompt).
      2. Resolve the token value from Secrets Manager (via the injected AWSInterface).
         The value is injected into the Lambda env at deploy time — the guardrail never
         reads Secrets Manager at runtime (it has no secretsmanager access).
      3. Resolve the runner instance id (explicit arg, else discover by the arm tag set).
      4. Deploy the airlock SAM stack, parameterized from the above. Returns stack outputs.

    Idempotent: `sam deploy` is a change-set upsert; re-running reconciles the stack.

    Parameters
    ----------
    runner_instance_id: override the tag-discovered box id (useful before sa#98 lands).
    sam_deploy:         injected deployer (default: the `sam` CLI). Tests pass a fake.
    template_path:      override the airlock.yaml path (default: alongside this module).

    Returns
    -------
    Summary dict: stack_name, parameters (the overrides sent), outputs (stack outputs).
    """
    agent_name = manifest.name
    inbound = read_inbound_block(manifest)

    # -- Step 2: token from Secrets Manager (deploy-time injection, not runtime read) --
    token = aws.get_secret(inbound["channel_token_secret"])
    if not token:
        raise RuntimeError(
            f"ec2_woken_provision: channel token secret "
            f"{inbound['channel_token_secret']!r} not found or empty; seed it first."
        )

    # -- Step 3: the box to wake --------------------------------------------------------
    if runner_instance_id is None:
        runner_instance_id = _discover_runner_instance_id(aws, agent_name, environment)

    # -- Step 4: parameters + deploy ----------------------------------------------------
    parameter_overrides: dict[str, str] = {
        "Environment": environment,
        "AgentName": agent_name,
        "OwnerAllowList": json.dumps(inbound["owner_allow_list"]),
        "InjectionScreenPattern": inbound["injection_screen_pattern"],
        "InboundChannelToken": token,
        "RunnerInstanceId": runner_instance_id,
    }
    # Only override the classifier params when the manifest sets them — otherwise the
    # SAM template's env-driven defaults apply (never hardcoded in code).
    if inbound["intent_model"]:
        parameter_overrides["IntentModel"] = inbound["intent_model"]
    if inbound["intent_prompt"]:
        parameter_overrides["IntentPrompt"] = inbound["intent_prompt"]

    stack = _stack_name(agent_name, environment)
    tags = _arm_tags(environment, agent_name)
    deploy = sam_deploy or _cli_sam_deploy
    tmpl = template_path or _template_path()

    outputs = deploy(tmpl, stack, parameter_overrides, tags, region)

    logger.info("ec2_woken_provision: provisioned airlock stack %r for agent %r",
                stack, agent_name)
    return {
        "stack_name": stack,
        "parameters": parameter_overrides,
        "outputs": outputs,
    }


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def ec2_woken_teardown(
    manifest: "DeploymentManifest",
    aws: "AWSInterface",  # noqa: ARG001 — kept for arm-symmetric signature
    *,
    environment: str = "development",
    region: str = "us-east-1",
    sam_delete: Optional[SamDelete] = None,
) -> dict:
    """Remove the airlock stack ec2_woken_provision() created for this agent.

    Deletes the whole SAM stack (guardrail Lambda, HTTP API, SQS queue, dedup table,
    execution role) in one `sam delete`. Idempotent — deleting an absent stack is a
    clean no-op. NEVER touches the EC2 box itself (owned by the EC2 arm / sa#98) or any
    infra/ floor resource.

    Returns
    -------
    Report dict: stack_name, stack_removed (bool).
    """
    stack = _stack_name(manifest.name, environment)
    delete = sam_delete or _cli_sam_delete
    removed = delete(stack, region)
    logger.info("ec2_woken_teardown: agent %r — stack %r removed=%s",
                manifest.name, stack, removed)
    return {"stack_name": stack, "stack_removed": removed}
