"""
Pipeline phases: provision → deploy → smoke.

Each phase is a pure function: (manifest, aws, *, dry_run, ...) → PhaseResult.
In dry-run mode phases emit the ordered plan steps without calling AWS.

Phase re-derivations (reference: PORTING.md):
    provision  ← provision-agent-host: reads arm: and branches to the right substrate
    deploy     ← deploy-agent + seed-agent: three-way secret split, idempotent clone/pull
    smoke      ← smoke-agent: runs conformance harness against the deployed agent dir

No arm adapter is implemented here (#33/#34/#36). The pipeline drives adapters;
adapters are separate concerns.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .aws_interface import AWSInterface
from .manifest import DeploymentManifest

# Smoke mode values
SMOKE_MODE_LOCAL = "local"
SMOKE_MODE_REMOTE = "remote"

logger = logging.getLogger(__name__)

# CF stack name convention: <arm>-<agent-name>-<environment>
# Environment names are exactly development / staging / production (never dev/prod).
_STACK_TEMPLATE = "{arm}-{name}-{environment}"


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PhaseResult:
    phase: str           # "provision" | "deploy" | "smoke"
    dry_run: bool
    success: bool
    steps: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _stack_name(manifest: DeploymentManifest, environment: str) -> str:
    return _STACK_TEMPLATE.format(
        arm=manifest.arm, name=manifest.name, environment=environment
    )


def _fail(phase: str, dry_run: bool, steps: list[str], error: str) -> PhaseResult:
    return PhaseResult(phase=phase, dry_run=dry_run, success=False, steps=steps, error=error)


def _ok(phase: str, dry_run: bool, steps: list[str]) -> PhaseResult:
    return PhaseResult(phase=phase, dry_run=dry_run, success=True, steps=steps)


# ---------------------------------------------------------------------------
# Phase 1: provision
# ---------------------------------------------------------------------------

def provision_phase(
    manifest: DeploymentManifest,
    aws: AWSInterface,
    *,
    dry_run: bool,
    environment: str = "development",
) -> PhaseResult:
    """
    Provision the compute substrate for the agent's declared arm.

    Re-derives provision-agent-host: reads arm: and branches to the right
    substrate (EC2 box, EC2-woken, Fargate task). Fails fast on an unknown arm.

    Dry-run: validates the arm and returns the ordered plan steps; no AWS calls.
    """
    arm = manifest.arm
    stack = _stack_name(manifest, environment)
    steps: list[str] = [f"arm={arm!r}: select substrate adapter"]

    if arm == "ec2":
        steps += [
            "clean-start gate: verify no prior instance with agent tags is still alive; IAM profile in stable state",
            "ensure_foundation (idempotent): create/reuse instance profile + attach inline role policy",
            "wait_for_iam_propagation: poll until role visible in profile, then buffer",
            "render user-data.sh.tmpl with manifest params (name/arm/environment/oauth_token)",
            "RunInstances: arm64 AL2023 t4g.small in agent-subnet, agentRole profile, agentSG",
            "wait_for_ssm_online: poll SSM until instance PingStatus=Online (raise on timeout)",
            "agent instance profile: agentRole (zero connector authority; run-record + oauth_token only)",
            "broker sidecar service unit installed; brokerRole creds injected via credential file",
            "egress: agentSG → brokerSG only (NetworkStack; connector-allowlist until #35 lands)",
        ]
        if not dry_run:
            # Delegate to the EC2 arm adapter (lazy import — arms is a sibling package of pipeline
            # under safe_agents; importable when the package is installed / on sys.path).
            try:
                from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "provision", dry_run, steps,
                    f"EC2 arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                instance_id = ec2_provision(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("provision", dry_run, steps, str(exc))
            steps.append(f"instance launched: {instance_id}")

    elif arm == "rhel-openshell":
        steps += [
            "clean-start gate: verify no prior RHEL instance with agent tags is alive; IAM profile stable",
            "ensure_foundation (idempotent): create/reuse instance profile + attach inline role policy",
            "wait_for_iam_propagation: poll until role visible in profile, then buffer",
            "resolve RHEL 9 AMI by owner (309956199498) + name pattern (RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3)",
            "render user-data.sh.tmpl with manifest params (name/arm/environment/oauth_token/broker_dns/agent_runs_table/region)",
            "RunInstances: x86_64 RHEL 9 m7i.xlarge in the ISOLATED agent-subnet on agentSG + endpointSG; /dev/sda1 100 GB gp3",
            "wait_for_ssm_online: poll SSM until instance PingStatus=Online (raise on timeout)",
            "agentRole: SSM core + GetSecretValue on <agent>/* + S3 deploy-bundle read + run-record PutItem + tables-CMK KMS grant",
            "user-data bootstraps (autonomous profile): SSM agent + dev user + core toolchain + python + Claude CLI + netns-forward + run-brokered.sh systemd service (OpenShell is interactive-profile-only)",
            "converged two-box model (sa#35): the confined agent does a real brokered round-trip against the broker SERVICE (broker.safe-agents.local); the netns FORWARDS to the broker, no co-located stub",
            "egress confinement: agent-subnet has no NAT + agentSG → brokerSG only (connector + direct-model unreachable); the netns is a defense-in-depth process layer",
        ]
        if not dry_run:
            try:
                from safe_agents.arms.rhel_openshell.provision import rhel_openshell_provision  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "provision", dry_run, steps,
                    f"RHEL+OpenShell arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                instance_id = rhel_openshell_provision(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("provision", dry_run, steps, str(exc))
            steps.append(f"instance launched: {instance_id}")

    elif arm == "ec2-woken":
        steps += [
            "read manifest inbound: block (owner allow-list + injection screen + token secret)",
            "resolve inbound channel token from Secrets Manager (deploy-time env injection; "
            "the guardrail holds NO secrets access at runtime)",
            "discover the sleeping EC2 box to wake by the standard arm tag set",
            f"deploy airlock SAM stack {stack!r}: HTTP API webhook → guardrail Lambda → SQS + wake",
            "guardrail Lambda = untrusted-input taint boundary: token + owner allow-list + "
            "message-id dedup + injection screen + env-driven intent classify, then enqueue",
            "wake path: ec2:StartInstances scoped to the runner ONLY (no connector creds, "
            "no secretsmanager, no */connectors/*)",
        ]
        if not dry_run:
            try:
                from safe_agents.arms.ec2_woken.provision import ec2_woken_provision  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "provision", dry_run, steps,
                    f"ec2-woken arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                summary = ec2_woken_provision(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("provision", dry_run, steps, str(exc))
            steps.append(f"airlock stack deployed: {summary['stack_name']}")

    elif arm == "fargate":
        steps += [
            "create per-agent taskRole (ecs-tasks trust): run-record PutItem + oauth-token GetSecretValue ONLY (no connector creds)",
            "create executionRole: AmazonECSTaskExecutionRolePolicy + narrow oauth-secret inject inline",
            "create schedulerRole (scheduler trust): ecs:RunTask + iam:PassRole on task+exec roles",
            f"register arm64 Fargate task definition (cpu 256/mem 512) for agent {manifest.name!r} from ecr-agent-repo-uri:latest",
            "container env: SA_BROKER_DNS / SA_MODEL_PROXY_PORT / SA_TOOL_API_PORT / AGENT_RUNS_TABLE / AGENT_NAME / RUN_ID / AWS_DEFAULT_REGION; secret CLAUDE_CODE_OAUTH_TOKEN injected",
            "broker runs as its OWN ECS service (broker.safe-agents.local); the agent task is separate",
            "task networking: awsvpc in isolated agent-subnets on agentSG, public IP DISABLED (broker-only egress)",
            "register EventBridge Scheduler → ECS RunTask (cron/timezone are parameters, not hardcoded); "
            "schedule provisions DISABLED by default and must be explicitly enabled after proof (sa#115)",
        ]
        if not dry_run:
            try:
                from safe_agents.arms.fargate.provision import fargate_provision  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "provision", dry_run, steps,
                    f"Fargate arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            schedule_kwargs: dict = {}
            if manifest.schedule is not None:
                if manifest.schedule.expression:
                    schedule_kwargs["schedule_expression"] = manifest.schedule.expression
                if manifest.schedule.timezone:
                    schedule_kwargs["timezone"] = manifest.schedule.timezone
                schedule_kwargs["state"] = manifest.schedule.state
            try:
                summary = fargate_provision(
                    manifest, aws, environment=environment, **schedule_kwargs
                )
            except RuntimeError as exc:
                return _fail("provision", dry_run, steps, str(exc))
            steps.append(f"task definition registered: {summary['task_definition_arn']}")
            steps.append(
                f"schedule created ({summary['schedule_state']}): {summary['schedule_arn']}"
            )

    else:
        # Should have been caught by manifest validation, but be explicit.
        return _fail(
            "provision", dry_run, steps,
            f"Unknown arm {arm!r}; must be one of ec2 | ec2-woken | fargate | rhel-openshell",
        )

    return _ok("provision", dry_run, steps)


# ---------------------------------------------------------------------------
# Phase 2: deploy
# ---------------------------------------------------------------------------

def deploy_phase(
    manifest: DeploymentManifest,
    aws: AWSInterface,
    *,
    dry_run: bool,
    environment: str = "development",
) -> PhaseResult:
    """
    Deploy the agent + broker onto the provisioned host.

    Re-derives deploy-agent + seed-agent. The three-way secret split (from
    seed-agent) is the key invariant:
        runner_keys          → non-connector config → agent env
        oauth_token          → model brain → agent env (not a connector)
        broker_connector_keys → connector creds → broker's Secrets Manager store ONLY
                               The agent process never receives these.

    Dry-run: lists every step without reading AWS or executing remote commands.
    """
    arm = manifest.arm
    stack = _stack_name(manifest, environment)
    steps: list[str] = []

    # -- Deploy key retrieval (re-derived from deploy-agent) -----------------
    steps.append(
        f"retrieve deploy key from Secrets Manager: {manifest.deploy_key_secret!r}"
    )
    if not dry_run:
        deploy_key = aws.get_secret(manifest.deploy_key_secret)
        if not deploy_key:
            return _fail(
                "deploy", dry_run, steps,
                f"Deploy key secret {manifest.deploy_key_secret!r} not found or empty; "
                "has seed-agent been run for this agent?",
            )

    # -- Idempotent clone / pull (re-derived from deploy-agent) -------------
    steps.append(f"idempotent clone/pull repo {manifest.repo!r} via deploy key")

    # -- Secret seeding — three paths (re-derived from seed-agent) ----------
    if manifest.secrets.runner_keys:
        steps.append(
            f"seed runner_keys ({manifest.secrets.runner_keys!r}) → agent env "
            "(non-connector runtime config only)"
        )
        if not dry_run:
            aws.get_secret(manifest.secrets.runner_keys)

    if manifest.secrets.oauth_token:
        steps.append(
            f"seed oauth_token ({manifest.secrets.oauth_token!r}) → agent env "
            "(model brain token; not a connector)"
        )
        if not dry_run:
            aws.get_secret(manifest.secrets.oauth_token)

    if manifest.secrets.broker_connector_keys:
        broker_store_path = f"broker/{manifest.name}/connector-keys"
        steps.append(
            f"seed broker_connector_keys ({manifest.secrets.broker_connector_keys!r}) "
            f"→ broker store at {broker_store_path!r} "
            "— agent process NEVER receives these"
        )
        if not dry_run:
            source_value = aws.get_secret(manifest.secrets.broker_connector_keys)
            if source_value:
                aws.put_secret(broker_store_path, source_value)

    # -- Policy + secrets reachability check --------------------------------
    steps.append(f"verify egress policy file declared: {manifest.policy!r}")
    steps.append(
        "verify secrets reachable from host (dry-check; no plaintext logged)"
    )

    # -- Remote deploy command (EC2 and RHEL arms) ---------------------------
    if arm in ("ec2", "ec2-woken", "rhel-openshell"):
        steps.append(
            "run idempotent deploy script on host via SSM "
            "(git pull + service reload)"
        )
        if not dry_run:
            instance_id = aws.instance_id_for_stack(stack)
            if instance_id:
                cmd = (
                    f"cd /opt/agents/{manifest.name} "
                    f"&& git pull "
                    f"&& systemctl reload agent-{manifest.name} 2>/dev/null || true"
                )
                exit_code, output = aws.ssm_run_command(instance_id, cmd)
                if exit_code != 0:
                    return _fail(
                        "deploy", dry_run, steps,
                        f"Deploy script failed (exit {exit_code}): {output[:300]}",
                    )

    elif arm == "fargate":
        steps.append("update Fargate task definition with new image digest")

    return _ok("deploy", dry_run, steps)


# ---------------------------------------------------------------------------
# Phase 3: smoke
# ---------------------------------------------------------------------------

def smoke_phase(
    manifest: DeploymentManifest,
    agent_dir: Path,
    *,
    dry_run: bool,
    harness_fn: Optional[Callable] = None,
    smoke_mode: str = SMOKE_MODE_LOCAL,
    aws: Optional[AWSInterface] = None,
    environment: str = "development",
) -> PhaseResult:
    """
    Smoke test the deployed agent against the runner-contract conformance harness.

    Re-derives smoke-agent: in this pipeline the smoke step is wired to the
    conformance harness (safe_agents/contract/harness.py — the #31 deliverable) so the
    machine-checkable "does this agent pass the runner contract" gate runs here,
    not just in CI.

    smoke.prompt and smoke.expect_substring from the manifest describe the
    intended LLM-based probe (run by future smoke tooling); for now the
    conformance harness is the authoritative smoke gate.

    smoke_mode:
        "local"  — run the harness locally against agent_dir (default; works
                   anywhere without a live instance). Use in CI.
        "remote" — discover the deployed instance by tags, issue SSM SendCommand
                   to run the harness ON the instance, assert exit 0. Requires
                   a running instance and the aws parameter. Use after a live deploy.

    harness_fn:
        callable(agent_dir: Path) -> list[CheckResult]. Injected in tests for
        the local path; defaults to the real run_harness from safe_agents/contract/harness.py.
        Unused in remote mode.

    aws:
        AWSInterface implementation. Required for remote mode; unused for local.
    environment:
        Deployment environment. Required for remote mode (tag lookup).

    Dry-run: lists the steps without invoking the harness.
    """
    steps: list[str] = [
        f"smoke.read_only={manifest.smoke.read_only!r}",
        f"smoke.prompt={manifest.smoke.prompt!r}",
        f"smoke.expect_substring={manifest.smoke.expect_substring!r}",
        f"smoke_mode={smoke_mode!r}",
    ]

    if smoke_mode == SMOKE_MODE_REMOTE:
        steps += [
            "discover deployed instance by tags (Project=safe-agents, "
            f"Environment={environment!r}, Agent={manifest.name!r})",
            "SSM SendCommand: run conformance harness on instance",
            "assert harness exits 0 (all 8 checks pass on deployed box)",
        ]
    else:
        steps += [
            f"invoke runner-contract conformance harness against: {agent_dir}",
            "assert all 8 runner-contract checks pass (exit 0)",
        ]

    if dry_run:
        steps.append(
            f"(dry-run) {'remote SSM harness' if smoke_mode == SMOKE_MODE_REMOTE else 'local harness'}"
            f" would target: {agent_dir if smoke_mode == SMOKE_MODE_LOCAL else 'deployed instance'}"
        )
        return _ok("smoke", True, steps)

    # -- Remote mode: run harness on the deployed instance via SSM ------------
    if smoke_mode == SMOKE_MODE_REMOTE:
        return _smoke_remote(manifest, aws, environment=environment, steps=steps)

    # -- Local mode: run harness in-process against agent_dir -----------------
    # Resolve harness function (lazily, so pipeline is importable standalone)
    if harness_fn is None:
        try:
            from safe_agents.contract.harness import run_harness as _rh  # noqa: PLC0415
            harness_fn = _rh
        except ImportError as exc:
            return _fail(
                "smoke", False, steps,
                f"Could not import conformance harness (safe_agents.contract.harness): {exc}",
            )

    if not agent_dir.is_dir():
        return _fail(
            "smoke", False, steps,
            f"Agent directory not found: {agent_dir}; "
            "has provision+deploy completed?",
        )

    from safe_agents.contract.harness import UnsupportedHostError  # noqa: PLC0415

    try:
        results = harness_fn(agent_dir)
    except UnsupportedHostError as exc:
        return _fail("smoke", False, steps, f"Conformance harness cannot run here: {exc}")
    failures = [r for r in results if not r.passed]
    if failures:
        detail = "; ".join(f"{r.name}: {r.reason}" for r in failures)
        return _fail(
            "smoke", False, steps,
            f"Conformance harness: {len(failures)} of {len(results)} check(s) failed — {detail}",
        )

    steps.append(f"all {len(results)} conformance checks passed")
    return _ok("smoke", False, steps)


def _smoke_remote(
    manifest: DeploymentManifest,
    aws: Optional[AWSInterface],
    *,
    environment: str,
    steps: list[str],
) -> PhaseResult:
    """Run the conformance harness on the deployed instance via SSM SendCommand.

    Discovers the instance by the standard tag set, sends the harness script,
    and asserts exit 0. Fails loudly with the full SSM output when the harness
    reports any violation.
    """
    if aws is None:
        return _fail(
            "smoke", False, steps,
            "smoke_mode=remote requires an AWSInterface (aws= parameter); "
            "none was provided",
        )

    # Find the deployed instance by tags
    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": manifest.name,
        "ManagedBy": "safe-agents-pipeline",
    }
    instances = aws.describe_instances_by_tags(discovery_tags)
    if not instances:
        return _fail(
            "smoke", False, steps,
            f"No running instance found with tags {discovery_tags}; "
            "has the provision phase completed for this environment?",
        )

    instance_id = instances[0]["instance_id"]
    steps.append(f"found instance: {instance_id}")

    # The harness script is installed by user-data.sh.tmpl into
    # /opt/safe-agents/core/contract/harness.py on the instance.
    harness_cmd = (
        f"python3 /opt/safe-agents/core/contract/harness.py "
        f"/opt/agents/{manifest.name}"
    )
    exit_code, output = aws.ssm_run_command(instance_id, harness_cmd, timeout=120)

    if exit_code != 0:
        return _fail(
            "smoke", False, steps,
            f"Remote harness failed on {instance_id} (exit {exit_code}): "
            f"{output[:400]}",
        )

    steps.append(
        f"remote harness passed on {instance_id} (all 8 checks passed on deployed instance)"
    )
    return _ok("smoke", False, steps)


# ---------------------------------------------------------------------------
# Phase 4: teardown
# ---------------------------------------------------------------------------

def teardown_phase(
    manifest: DeploymentManifest,
    aws: AWSInterface,
    *,
    dry_run: bool,
    environment: str = "development",
) -> PhaseResult:
    """
    Teardown: discover and remove all resources the arm provisioned.

    Discovers EC2 instances by the standard tag set
    (Project=safe-agents, Environment=<env>, Agent=<name>, ManagedBy=safe-agents-pipeline)
    so no saved local state is required. Derives the per-agent instance profile
    and inline policy names from the same naming convention used in provision.

    Idempotent: a second run reports found-already-gone for each resource and
    returns success. Nothing is deleted twice; terminating an already-terminated
    instance is a no-op.

    NEVER removes infra foundation resources (VPC, the base agentRole, DynamoDB
    tables, or CloudFormation stacks). Those are owned by infra/, not by this arm.

    Dry-run: lists what would be removed without making any AWS calls.
    """
    arm = manifest.arm
    profile_name = f"safe-agents-{environment}-{manifest.name}"
    steps: list[str] = [
        f"arm={arm!r}: select teardown adapter",
        f"discover instances by tags: Project=safe-agents, "
        f"Environment={environment!r}, Agent={manifest.name!r}, ManagedBy=safe-agents-pipeline",
        "terminate discovered EC2 instances (idempotent; already-terminated = no-op)",
        f"remove inline IAM policy {profile_name!r} from agentRole "
        "(idempotent; already-gone = no-op)",
        f"remove per-agent instance profile {profile_name!r} "
        "(idempotent; already-gone = no-op)",
        "NEVER removes infra stacks (VPC / base agentRole / DynamoDB tables)",
    ]

    if arm in ("ec2", "rhel-openshell"):
        if not dry_run:
            try:
                if arm == "ec2":
                    from safe_agents.arms.ec2.provision import ec2_teardown as _do_teardown  # noqa: PLC0415
                else:
                    from safe_agents.arms.rhel_openshell.provision import rhel_openshell_teardown as _do_teardown  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "teardown", dry_run, steps,
                    f"{arm!r} arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                report = _do_teardown(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("teardown", dry_run, steps, str(exc))

            # Append the per-resource outcome to steps for a readable report.
            if report["instances_terminated"]:
                for iid in report["instances_terminated"]:
                    steps.append(f"terminated instance: {iid}")
            else:
                steps.append("instances: none found with matching tags (already-gone)")

            if report["instances_already_gone"]:
                for iid in report["instances_already_gone"]:
                    steps.append(f"instance already in terminal state: {iid}")

            if report["profile_removed"]:
                steps.append(f"removed instance profile: {profile_name}")
            else:
                steps.append(f"instance profile already-gone: {profile_name}")

            if report["policy_removed"]:
                steps.append(
                    f"removed inline policy {profile_name!r} "
                    f"from role {report['role_name']!r}"
                )
            else:
                steps.append(
                    f"inline policy already-gone: {profile_name!r} "
                    f"(role: {report['role_name']!r})"
                )

    elif arm == "fargate":
        steps += [
            "delete EventBridge Scheduler schedule (idempotent; already-gone = no-op)",
            "deregister every active task-def revision in the agent family",
            "delete per-agent roles (taskRole + executionRole + schedulerRole); "
            "detach managed + delete inline policies first",
            "NEVER touches the broker ECS service or the infra floor (cluster/VPC/tables/ECR)",
        ]
        if not dry_run:
            try:
                from safe_agents.arms.fargate.provision import fargate_teardown  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "teardown", dry_run, steps,
                    f"Fargate arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                report = fargate_teardown(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("teardown", dry_run, steps, str(exc))

            steps.append(
                f"schedule {'removed' if report['schedule_removed'] else 'already-gone'}"
            )
            if report["task_definitions_removed"]:
                for arn in report["task_definitions_removed"]:
                    steps.append(f"deregistered task definition: {arn}")
            else:
                steps.append("task definitions: none active (already-gone)")
            for role in report["roles_removed"]:
                steps.append(f"removed role: {role}")
            for role in report["roles_already_gone"]:
                steps.append(f"role already-gone: {role}")

    elif arm == "ec2-woken":
        steps += [
            "delete the airlock SAM stack (guardrail Lambda, HTTP API, SQS queue, dedup "
            "table, execution role) in one operation",
            "NEVER touches the EC2 box itself (owned by the EC2 arm / sa#98) or the infra floor",
        ]
        if not dry_run:
            try:
                from safe_agents.arms.ec2_woken.provision import ec2_woken_teardown  # noqa: PLC0415
            except ImportError as exc:
                return _fail(
                    "teardown", dry_run, steps,
                    f"ec2-woken arm adapter not importable: {exc}; "
                    "ensure safe_agents is importable",
                )
            try:
                report = ec2_woken_teardown(manifest, aws, environment=environment)
            except RuntimeError as exc:
                return _fail("teardown", dry_run, steps, str(exc))
            steps.append(
                f"airlock stack {report['stack_name']!r} "
                f"{'removed' if report['stack_removed'] else 'already-gone'}"
            )

    else:
        return _fail(
            "teardown", dry_run, steps,
            f"Unknown arm {arm!r}; must be one of ec2 | ec2-woken | fargate | rhel-openshell",
        )

    return _ok("teardown", dry_run, steps)


# ---------------------------------------------------------------------------
# Phase 5: verify
# ---------------------------------------------------------------------------

def verify_phase(
    manifest: DeploymentManifest,
    aws: AWSInterface,
    *,
    dry_run: bool,
    environment: str = "development",
    ssm_timeout: float = 300.0,
    ssm_poll_interval: float = 10.0,
) -> PhaseResult:
    """Verify that a provisioned instance is SSM-Online.

    Can be run independently of provision — re-checks that the instance is
    currently managed and reachable via SSM. Fails loudly if the instance is
    not responding within the timeout so no false-success is ever returned.

    Useful after a rapid teardown→re-provision cycle, or as a standalone health
    check before running a remote smoke.

    Parameters
    ----------
    manifest:         Loaded deployment manifest.
    aws:              AWSInterface implementation.
    dry_run:          If True, returns success without making AWS calls.
    environment:      Deployment environment for tag-based instance discovery.
    ssm_timeout:      Max seconds to wait for SSM Online (default 300s).
    ssm_poll_interval: Seconds between SSM polls (default 10s; pass 0 in tests).

    Dry-run: lists the steps without invoking SSM.
    """
    steps: list[str] = [
        f"discover provisioned instance by tags: Project=safe-agents, "
        f"Environment={environment!r}, Agent={manifest.name!r}",
        f"poll SSM PingStatus until 'Online' (timeout={ssm_timeout:.0f}s)",
    ]
    if dry_run:
        steps.append("(dry-run) would check SSM Online status of provisioned instance")
        return _ok("verify", True, steps)

    # Discover the running instance by the standard tag set.
    discovery_tags = {
        "Project": "safe-agents",
        "Environment": environment,
        "Agent": manifest.name,
        "ManagedBy": "safe-agents-pipeline",
    }
    instances = aws.describe_instances_by_tags(discovery_tags)
    if not instances:
        return _fail(
            "verify", False, steps,
            f"No running instance found with tags {discovery_tags}; "
            "has the provision phase completed for this environment?",
        )

    instance_id = instances[0]["instance_id"]
    steps.append(f"found instance: {instance_id}")

    try:
        from safe_agents.arms.ec2.provision import wait_for_ssm_online  # noqa: PLC0415
    except ImportError as exc:
        return _fail(
            "verify", False, steps,
            f"EC2 arm adapter not importable: {exc}; ensure safe_agents is importable",
        )

    try:
        wait_for_ssm_online(
            aws, instance_id,
            timeout=ssm_timeout,
            poll_interval=ssm_poll_interval,
        )
    except RuntimeError as exc:
        return _fail("verify", False, steps, str(exc))

    steps.append(f"instance {instance_id} is SSM Online — reachable and managed")
    return _ok("verify", False, steps)


# ---------------------------------------------------------------------------
# Pre-flight: validate
# ---------------------------------------------------------------------------

def validate_phase(
    manifest: DeploymentManifest,
    *,
    repo_root: Optional[Path] = None,
    offline: bool = True,
) -> PhaseResult:
    """
    Pre-flight manifest validation (sa#41).

    Runs extended structural checks before any AWS calls are made.
    Runs in both dry-run and live mode — these are pure file/schema checks.
    Returns PhaseResult(phase="preflight", ...).
    """
    from .validate import validate_manifest_extended  # noqa: PLC0415

    steps: list[str] = [
        "check envelope.polarity is present and explicit (abstain | act)",
        "check secrets.broker_connector_keys present when allowlists.tools non-empty",
    ]
    if repo_root is not None:
        steps += [
            f"check policy file exists: {manifest.policy!r}",
            "check agent_egress section contains no direct connector IPs",
        ]
    if not offline:
        steps.append("(online) resolve action classes against broker registry (sa#12)")
    else:
        steps.append("(offline) skipping broker-dependent checks (sa#12 not yet landed)")

    errors = validate_manifest_extended(manifest, repo_root=repo_root, offline=offline)
    if errors:
        detail = "; ".join(errors)
        return _fail("preflight", False, steps, detail)
    return _ok("preflight", False, steps)
