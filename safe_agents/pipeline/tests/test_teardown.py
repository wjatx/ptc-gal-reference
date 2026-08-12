"""
Teardown phase tests — acceptance criteria for sa#1 gap (complete teardown automation).

All tests are AWS-free: AWS calls go through FakeAWS.

Acceptance criteria:
    1. After a fake provision, teardown terminates the tagged instance, removes
       the per-agent instance profile, and removes the inline IAM policy.
    2. A second teardown run is a clean no-op (all found-already-gone).
    3. The PhaseResult steps report exactly what was removed vs. already-gone.
    4. Teardown never calls infra-stack operations (no CF stack, no base role deletion).
    5. A teardown dry-run shows the plan without any AWS calls.
    6. A full dry-run plan (provision→deploy→smoke→teardown-available) renders coherently.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safe_agents.pipeline import (
    ALL_PHASES,
    FakeAWS,
    PHASES_ORDERED,
    load_manifest,
    run_pipeline,
    teardown_phase,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_EC2_MANIFEST = AGENTS_DIR / "smoke-ec2.yaml"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ENV = "development"


@pytest.fixture()
def fake_aws_provisioned() -> FakeAWS:
    """FakeAWS that has been through a full fake ec2_provision() call.

    After this fixture the FakeAWS internal state contains:
      - one running instance tagged with the smoke-ec2 standard tags
      - one per-agent instance profile (safe-agents-development-smoke-ec2)
      - one inline IAM policy (safe-agents-development-smoke-ec2 on agentRole)
    """
    aws = FakeAWS()
    # Seed the SSM params provision needs
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-role-arn",
        "arn:aws:iam::123456789012:role/safe-agents-development-AgentRole",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/endpoint-sg-id", "sg-0endpoint999")
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-subnet-ids", "subnet-0abc1234,subnet-0def5678"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-arn",
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-name", "safe-agents-development-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/tables-key-arn",
        "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-cmk",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/broker-service-dns", "broker.safe-agents.local")
    # sa#85: prebuilt base AMI replaces the public AL2023 SSM parameter lookup.
    aws.seed_image(
        "ami-0fakebaseami001",
        {"safe-agents:ami": "base", "safe-agents:ami-version": "20241201-01"},
        creation_date="2024-12-01T00:00:00Z",
    )

    # Run a fake provision to populate FakeAWS state
    from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

    manifest = load_manifest(SMOKE_EC2_MANIFEST)
    ec2_provision(manifest, aws, environment=ENV)

    # Reset the call log so test assertions start from a clean slate
    aws.calls.clear()
    return aws


# ---------------------------------------------------------------------------
# 1. Teardown removes tagged instance + profile + policy
# ---------------------------------------------------------------------------

class TestTeardownRemovesProvisionedResources:
    def test_teardown_terminates_tagged_instance(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown must terminate the instance that provision launched."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        assert result.success, f"teardown_phase failed: {result.error}"
        assert fake_aws_provisioned.was_called("terminate_instances"), (
            "teardown must call terminate_instances to remove the EC2 instance"
        )
        # The instance should now be terminated in FakeAWS state
        instance_id = next(iter(fake_aws_provisioned._instances))
        assert fake_aws_provisioned._instances[instance_id]["state"] == "terminated", (
            f"Instance {instance_id!r} should be in 'terminated' state after teardown"
        )

    def test_teardown_removes_instance_profile(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown must delete the per-agent instance profile."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        profile_name = f"safe-agents-{ENV}-{manifest.name}"
        assert profile_name in fake_aws_provisioned._instance_profiles, (
            f"Pre-condition: profile {profile_name!r} must exist before teardown"
        )

        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        assert profile_name not in fake_aws_provisioned._instance_profiles, (
            f"Profile {profile_name!r} must be removed by teardown"
        )
        assert fake_aws_provisioned.was_called("delete_instance_profile", profile_name), (
            "teardown must call delete_instance_profile"
        )

    def test_teardown_removes_inline_policy(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown must delete the inline IAM policy from the agentRole."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        policy_name = f"safe-agents-{ENV}-{manifest.name}"
        # Verify the policy exists before teardown
        has_policy = any(
            k[1] == policy_name for k in fake_aws_provisioned._role_policies
        )
        assert has_policy, (
            f"Pre-condition: inline policy {policy_name!r} must exist before teardown"
        )

        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        remaining = any(
            k[1] == policy_name for k in fake_aws_provisioned._role_policies
        )
        assert not remaining, (
            f"Inline policy {policy_name!r} must be removed by teardown"
        )
        assert fake_aws_provisioned.was_called("delete_role_policy"), (
            "teardown must call delete_role_policy"
        )

    def test_teardown_phase_reports_removed_resources_in_steps(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """The PhaseResult steps must describe what was removed."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        steps_text = " ".join(result.steps)
        assert "terminated" in steps_text.lower() or "terminate" in steps_text.lower(), (
            "Teardown steps must mention instance termination"
        )
        assert "profile" in steps_text.lower(), (
            "Teardown steps must mention the instance profile"
        )
        assert "policy" in steps_text.lower(), (
            "Teardown steps must mention the inline policy"
        )


# ---------------------------------------------------------------------------
# 2. Second teardown is a clean no-op
# ---------------------------------------------------------------------------

class TestTeardownIdempotency:
    def test_second_teardown_is_success(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """A second teardown run must succeed (not fail with 'not found' errors)."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        # First run
        result1 = teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)
        assert result1.success, f"First teardown failed: {result1.error}"
        fake_aws_provisioned.calls.clear()

        # Second run
        result2 = teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)
        assert result2.success, f"Second teardown must succeed (idempotent): {result2.error}"

    def test_second_teardown_makes_no_terminate_call(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """After teardown, a second run finds no instances and skips terminate_instances."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        # First run terminates the instance
        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)
        fake_aws_provisioned.calls.clear()

        # Second run: instance is in 'terminated' state, describe_by_tags returns []
        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        assert not fake_aws_provisioned.was_called("terminate_instances"), (
            "Second teardown must not call terminate_instances (nothing to terminate)"
        )

    def test_second_teardown_reports_already_gone(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Second teardown steps must report already-gone for profile and policy."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        result2 = teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)
        steps_text = " ".join(result2.steps).lower()
        assert "already" in steps_text or "gone" in steps_text, (
            "Second teardown steps must indicate resources were already gone"
        )


# ---------------------------------------------------------------------------
# 3. Teardown never touches infra stacks
# ---------------------------------------------------------------------------

class TestTeardownNeverTargetsInfra:
    def test_teardown_does_not_call_instance_id_for_stack(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown must not look up CloudFormation stack resources."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        assert not fake_aws_provisioned.was_called("instance_id_for_stack"), (
            "Teardown must not use CF stack lookup — it discovers by tags"
        )

    def test_teardown_does_not_delete_agentRole_itself(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown removes the inline policy ON the role, never the role itself.

        The base agentRole is an infra resource (IdentityStack). Teardown only
        removes what the arm provisioned (per-agent profile + inline policy).
        """
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        teardown_phase(manifest, fake_aws_provisioned, dry_run=False, environment=ENV)

        # Verify no IAM role deletion calls were made
        role_deletion_calls = [
            c for c in fake_aws_provisioned.calls
            if c[0] in ("delete_role", "detach_role_policy", "delete_policy")
        ]
        assert not role_deletion_calls, (
            f"Teardown must not delete the infra agentRole; "
            f"unexpected calls: {role_deletion_calls}"
        )


# ---------------------------------------------------------------------------
# 4. Teardown dry-run
# ---------------------------------------------------------------------------

class TestTeardownDryRun:
    def test_teardown_dry_run_succeeds_without_aws_calls(self) -> None:
        """Dry-run teardown must not make any AWS calls."""
        aws = FakeAWS()
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = teardown_phase(manifest, aws, dry_run=True, environment=ENV)

        assert result.success, f"teardown dry-run failed: {result.error}"
        assert result.dry_run is True
        # In dry-run, the only AWS call allowed is none (steps describe what would happen)
        aws_mutation_calls = [
            c for c in aws.calls
            if c[0] in (
                "terminate_instances", "delete_instance_profile",
                "delete_role_policy", "create_instance_profile",
                "put_role_policy",
            )
        ]
        assert not aws_mutation_calls, (
            f"Dry-run must not make mutating AWS calls; got: {aws_mutation_calls}"
        )

    def test_teardown_dry_run_steps_describe_plan(self) -> None:
        """Dry-run steps must describe the teardown plan."""
        aws = FakeAWS()
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = teardown_phase(manifest, aws, dry_run=True, environment=ENV)

        steps_text = " ".join(result.steps).lower()
        assert "tag" in steps_text or "discover" in steps_text, (
            "Dry-run steps must mention tag-based discovery"
        )
        assert "infra" in steps_text or "never" in steps_text, (
            "Dry-run steps must note that infra resources are NOT removed"
        )


# ---------------------------------------------------------------------------
# 5. Full pipeline teardown via run_pipeline
# ---------------------------------------------------------------------------

class TestTeardownViaRunPipeline:
    def test_teardown_phase_available_via_run_pipeline(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """run_pipeline with phases=('teardown',) must invoke teardown_phase."""
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=False,
            aws=fake_aws_provisioned,
            environment=ENV,
            phases=("teardown",),
        )
        assert result.success, (
            "run_pipeline teardown must succeed; errors:\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        phase_names = [pr.phase for pr in result.phase_results]
        assert "teardown" in phase_names, (
            f"teardown phase must appear in results; got {phase_names}"
        )

    def test_teardown_not_in_default_run(
        self, fake_aws_provisioned: FakeAWS
    ) -> None:
        """Teardown must not run as part of the default provision→deploy→smoke pipeline."""
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=fake_aws_provisioned,
            environment=ENV,
            agent_dir=TEST_STUB_DIR,
        )
        phase_names = [pr.phase for pr in result.phase_results]
        assert "teardown" not in phase_names, (
            "Teardown must be opt-in only; it must NOT appear in a default dry-run"
        )
        assert list(PHASES_ORDERED) == phase_names, (
            f"Default run must produce exactly {list(PHASES_ORDERED)}; got {phase_names}"
        )

    def test_all_phases_includes_teardown(self) -> None:
        """ALL_PHASES must include teardown (for --phase choices in CLI)."""
        assert "teardown" in ALL_PHASES, (
            f"ALL_PHASES must include 'teardown'; got {ALL_PHASES}"
        )
        assert "teardown" not in PHASES_ORDERED, (
            "PHASES_ORDERED (default run) must NOT include teardown"
        )
