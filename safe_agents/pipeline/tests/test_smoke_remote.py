"""
Remote smoke + agent-dir resolution tests — acceptance criteria for sa#1 gaps 2 + 3.

Gap 2 (remote smoke):
    - Remote mode issues SSM SendCommand to the deployed instance and passes when
      the harness exits 0.
    - Remote mode fails loudly (not silently) when no instance is found.
    - Local mode still works (existing behavior preserved).

Gap 3 (agent-dir resolution):
    - A manifest with agent_package: test-stub resolves the smoke target to
      agents/test-stub (not agents/smoke-ec2 which does not exist).
    - A manifest without agent_package falls back to agents/<name>.
    - Local smoke against the resolved agents/test-stub passes all 8 checks.

All tests are AWS-free: AWS calls go through FakeAWS.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safe_agents.broker.tests.platform_marks import requires_posix_exec
from safe_agents.pipeline import (
    FakeAWS,
    SMOKE_MODE_LOCAL,
    SMOKE_MODE_REMOTE,
    load_manifest,
    run_pipeline,
    smoke_phase,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_EC2_MANIFEST = AGENTS_DIR / "smoke-ec2.yaml"
TEST_STUB_MANIFEST = AGENTS_DIR / "test-stub.yaml"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"

ENV = "development"


def _failure_detail(result) -> str:
    """Why a PipelineResult failed. It has no `error` of its own: each PhaseResult
    carries one, and `aborted_at` names the phase that stopped the run."""
    lines = [f"aborted_at={result.aborted_at!r}"]
    lines += [f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_aws_with_instance() -> FakeAWS:
    """FakeAWS seeded with a running 'smoke-ec2' instance (post-provision state)."""
    aws = FakeAWS()
    # Seed SSM params for teardown/smoke discovery
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-role-arn",
        "arn:aws:iam::123456789012:role/safe-agents-development-AgentRole",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/endpoint-sg-id", "sg-0endpoint999")
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-subnet-ids", "subnet-0abc1234"
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

    # Run provision to populate the FakeAWS instance state
    from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

    manifest = load_manifest(SMOKE_EC2_MANIFEST)
    ec2_provision(manifest, aws, environment=ENV)
    aws.calls.clear()
    return aws


# ---------------------------------------------------------------------------
# Gap 2: Remote smoke
# ---------------------------------------------------------------------------

class TestRemoteSmoke:
    def test_remote_smoke_issues_ssm_command_to_instance(
        self, fake_aws_with_instance: FakeAWS
    ) -> None:
        """Remote smoke must discover the instance and send an SSM command."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,  # agent_dir unused in remote mode but required arg
            dry_run=False,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=fake_aws_with_instance,
            environment=ENV,
        )
        assert result.success, f"Remote smoke failed: {result.error}"
        assert fake_aws_with_instance.was_called("describe_instances_by_tags"), (
            "Remote smoke must discover the instance by tags"
        )
        assert fake_aws_with_instance.was_called("ssm_run_command"), (
            "Remote smoke must issue SSM SendCommand to run the harness"
        )

    def test_remote_smoke_passes_when_ssm_exits_zero(
        self, fake_aws_with_instance: FakeAWS
    ) -> None:
        """FakeAWS ssm_run_command returns exit 0 → remote smoke must pass."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=fake_aws_with_instance,
            environment=ENV,
        )
        assert result.success, f"Remote smoke must pass when harness exits 0: {result.error}"
        steps_text = " ".join(result.steps)
        assert "passed" in steps_text.lower() or "remote" in steps_text.lower(), (
            "Steps must confirm remote harness passed"
        )

    def test_remote_smoke_fails_when_no_instance_found(self) -> None:
        """Remote smoke must fail loudly when no instance matches the tags."""
        aws = FakeAWS()  # empty — no instances
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=aws,
            environment=ENV,
        )
        assert not result.success, (
            "Remote smoke must fail when no instance is found"
        )
        assert result.error, "Remote smoke must provide an error message"
        assert "instance" in (result.error or "").lower() or "tag" in (result.error or "").lower(), (
            f"Error must explain that no instance was found; got: {result.error!r}"
        )

    def test_remote_smoke_fails_when_ssm_exits_nonzero(
        self, fake_aws_with_instance: FakeAWS
    ) -> None:
        """Remote smoke must fail loudly when SSM command exits non-zero."""
        # Patch FakeAWS to return a failure
        def failing_ssm(instance_id, command, *, timeout=60):
            fake_aws_with_instance.calls.append(("ssm_run_command", instance_id, command))
            return 1, "ELEMENT_1_HEADLESS_ENTRYPOINT: run.sh does not exist"

        fake_aws_with_instance.ssm_run_command = failing_ssm  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=fake_aws_with_instance,
            environment=ENV,
        )
        assert not result.success, (
            "Remote smoke must fail when the remote harness exits non-zero"
        )
        assert result.error, "Remote smoke must surface the harness output in the error"

    def test_remote_smoke_dry_run_skips_aws(self) -> None:
        """Dry-run remote smoke must not call AWS."""
        aws = FakeAWS()
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=True,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=aws,
            environment=ENV,
        )
        assert result.success
        assert result.dry_run is True
        assert not aws.calls, f"Dry-run must make no AWS calls; got {aws.calls}"

    def test_remote_smoke_requires_aws_param(self) -> None:
        """Remote smoke without aws= must fail with a clear message."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_REMOTE,
            aws=None,  # not provided
            environment=ENV,
        )
        assert not result.success
        assert "aws" in (result.error or "").lower() or "interface" in (result.error or "").lower(), (
            f"Error must mention the missing aws= param; got: {result.error!r}"
        )

    def test_remote_smoke_via_run_pipeline(
        self, fake_aws_with_instance: FakeAWS
    ) -> None:
        """run_pipeline with smoke_mode=remote must discover + SSM the instance."""
        # Seed the secrets deploy phase needs
        fake_aws_with_instance.seed_secret("smoke-ec2/runner-keys", "{}")
        fake_aws_with_instance.seed_secret("smoke-ec2/broker-keys", '{"K": "v"}')
        fake_aws_with_instance.seed_secret("smoke-ec2/claude-oauth-token", "tok")
        fake_aws_with_instance.calls.clear()

        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=False,
            aws=fake_aws_with_instance,
            environment=ENV,
            phases=("smoke",),
            smoke_mode=SMOKE_MODE_REMOTE,
            agent_dir=TEST_STUB_DIR,
        )
        assert result.success, (
            "run_pipeline remote smoke must succeed; error:\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        assert fake_aws_with_instance.was_called("ssm_run_command"), (
            "run_pipeline remote smoke must issue SSM command"
        )


# ---------------------------------------------------------------------------
# Gap 2: Local smoke mode preserved
# ---------------------------------------------------------------------------

class TestLocalSmokePreserved:
    def test_local_smoke_uses_harness_fn_not_ssm(self) -> None:
        """Local smoke must not issue any SSM calls."""
        aws = FakeAWS()
        harness_called = []

        def recording_harness(agent_dir: Path):
            from safe_agents.contract.harness import ALL_CHECKS, CheckResult  # noqa: PLC0415
            harness_called.append(agent_dir)
            return [
                CheckResult(name=c.__name__, passed=True, reason="local pass")
                for c in ALL_CHECKS
            ]

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_LOCAL,
            aws=aws,
            harness_fn=recording_harness,
        )
        assert result.success, f"Local smoke failed: {result.error}"
        assert harness_called == [TEST_STUB_DIR], (
            "Local smoke must call the injected harness_fn with agent_dir"
        )
        assert not aws.was_called("ssm_run_command"), (
            "Local smoke must not issue any SSM commands"
        )
        assert not aws.was_called("describe_instances_by_tags"), (
            "Local smoke must not look up instances"
        )

    @requires_posix_exec
    def test_local_smoke_real_harness_test_stub_passes_8_checks(self) -> None:
        """Local smoke with the real harness against agents/test-stub must pass all 8."""
        from safe_agents.contract.harness import run_harness  # noqa: PLC0415

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            smoke_mode=SMOKE_MODE_LOCAL,
            harness_fn=run_harness,
        )
        assert result.success, (
            f"Local smoke against test-stub must pass all 8 checks; error: {result.error}"
        )


# ---------------------------------------------------------------------------
# Gap 3: Agent-dir resolution
# ---------------------------------------------------------------------------

class TestAgentDirResolution:
    def test_smoke_ec2_manifest_has_agent_package(self) -> None:
        """smoke-ec2.yaml must declare agent_package: test-stub."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        assert manifest.agent_package == "test-stub", (
            f"smoke-ec2.yaml must have agent_package: test-stub; "
            f"got agent_package={manifest.agent_package!r}"
        )

    def test_run_pipeline_resolves_agent_package_to_test_stub(self) -> None:
        """run_pipeline for smoke-ec2.yaml must resolve smoke dir to agents/test-stub."""
        aws = FakeAWS()
        observed_dirs: list[Path] = []

        def capturing_harness(agent_dir: Path):
            from safe_agents.contract.harness import ALL_CHECKS, CheckResult  # noqa: PLC0415
            observed_dirs.append(agent_dir)
            return [CheckResult(c.__name__, True, "ok") for c in ALL_CHECKS]

        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=False,
            aws=aws,
            phases=("smoke",),
            smoke_mode=SMOKE_MODE_LOCAL,
            harness_fn=capturing_harness,
        )
        assert result.success, f"Smoke failed: {_failure_detail(result)}"
        assert observed_dirs, "harness must have been called"
        resolved = observed_dirs[0]
        assert resolved.name == "test-stub", (
            f"Smoke must target agents/test-stub (via agent_package); "
            f"resolved to {resolved!r}"
        )

    def test_manifest_without_agent_package_falls_back_to_name(self) -> None:
        """A manifest without agent_package resolves to agents/<manifest.name>."""
        manifest = load_manifest(TEST_STUB_MANIFEST)
        assert manifest.agent_package is None, (
            f"test-stub.yaml should not have agent_package; got {manifest.agent_package!r}"
        )
        # The pipeline resolves to agents/<name> = agents/test-stub — which happens to
        # exist here. Verify the resolution logic uses manifest.name.
        aws = FakeAWS()
        observed_dirs: list[Path] = []

        def capturing_harness(agent_dir: Path):
            from safe_agents.contract.harness import ALL_CHECKS, CheckResult  # noqa: PLC0415
            observed_dirs.append(agent_dir)
            return [CheckResult(c.__name__, True, "ok") for c in ALL_CHECKS]

        result = run_pipeline(
            TEST_STUB_MANIFEST,
            dry_run=False,
            aws=aws,
            phases=("smoke",),
            harness_fn=capturing_harness,
        )
        assert result.success, f"Smoke failed: {_failure_detail(result)}"
        assert observed_dirs[0].name == "test-stub", (
            f"Without agent_package, smoke resolves to agents/<manifest.name>; "
            f"resolved to {observed_dirs[0]!r}"
        )

    @requires_posix_exec
    def test_smoke_ec2_local_smoke_against_test_stub_passes_all_8(self) -> None:
        """End-to-end: smoke-ec2.yaml local smoke must pass all 8 checks via test-stub."""
        from safe_agents.contract.harness import run_harness  # noqa: PLC0415

        aws = FakeAWS()
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=False,
            aws=aws,
            phases=("smoke",),
            smoke_mode=SMOKE_MODE_LOCAL,
            harness_fn=run_harness,
        )
        assert result.success, (
            "smoke-ec2 local smoke must pass all 8 checks via agents/test-stub; "
            f"{_failure_detail(result)}"
        )

    def test_dry_run_smoke_ec2_shows_coherent_plan(self) -> None:
        """Full dry-run for smoke-ec2.yaml must list provision→deploy→smoke coherently."""
        aws = FakeAWS()
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=aws,
            agent_dir=TEST_STUB_DIR,
        )
        assert result.success, (
            "Dry-run must succeed for smoke-ec2.yaml; errors:\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        phase_names = [pr.phase for pr in result.phase_results]
        assert phase_names == ["provision", "deploy", "smoke"], (
            f"Dry-run must show provision→deploy→smoke; got {phase_names}"
        )
        # Smoke step must reference the test-stub path or package name
        smoke_pr = next(pr for pr in result.phase_results if pr.phase == "smoke")
        steps_text = " ".join(smoke_pr.steps)
        assert "test-stub" in steps_text or "harness" in steps_text.lower(), (
            "Smoke dry-run steps must reference the agent package (test-stub)"
        )
