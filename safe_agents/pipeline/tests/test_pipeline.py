"""
Pipeline tests — acceptance criteria for sa#32.

All tests are AWS-free: AWS calls are isolated behind FakeAWS.
The smoke phase is tested with both the injected fake harness_fn and the real
conformance harness against agents/test-stub.

Acceptance criteria:
    1. A valid manifest parses + validates.
    2. An invalid manifest fails with a clear, descriptive ManifestError.
    3. Dry-run produces the expected ordered plan (provision→deploy→smoke)
       with all phases present and successful.
    4. The smoke phase invokes the conformance harness against agents/test-stub
       and passes all 8 checks.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from safe_agents.pipeline import (
    FakeAWS,
    ManifestError,
    PHASES_ORDERED,
    load_manifest,
    manifest_get,
    run_pipeline,
    smoke_phase,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"
TEST_STUB_MANIFEST = AGENTS_DIR / "test-stub.yaml"

# Ordered phases the pipeline must run.
EXPECTED_PHASE_ORDER = list(PHASES_ORDERED)  # ["provision", "deploy", "smoke"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_VALID_MANIFEST = textwrap.dedent("""\
    name: my-agent
    repo: git@github.com:Third-Ralph/my-agent.git
    deploy_key_secret: my-agent/deploy-key
    arm: ec2
    policy: policies/my-agent.yaml
    secrets:
      runner_keys: my-agent/runner-keys
      broker_connector_keys: my-agent/broker-keys
      oauth_token: my-agent/oauth-token
    smoke:
      read_only: true
      prompt: "In one sentence, what does this agent do?"
      expect_substring: agent
    envelope:
      polarity: abstain
""")


@pytest.fixture()
def valid_manifest_file(tmp_path: Path) -> Path:
    """Write a minimal valid deployment manifest and return its path."""
    f = tmp_path / "my-agent.yaml"
    f.write_text(MINIMAL_VALID_MANIFEST)
    return f


@pytest.fixture()
def fake_aws() -> FakeAWS:
    """A FakeAWS pre-seeded with secrets the test manifests reference."""
    aws = FakeAWS()
    aws.seed_secret("my-agent/deploy-key", "DUMMY-DEPLOY-KEY-FIXTURE")
    aws.seed_secret("my-agent/runner-keys", '{"LOG_LEVEL": "info"}')
    aws.seed_secret("my-agent/broker-keys", '{"CONNECTOR_KEY": "secret"}')
    aws.seed_secret("my-agent/oauth-token", "oauth-tok-abc")
    aws.seed_secret("test-stub/deploy-key", "DUMMY-DEPLOY-KEY-FIXTURE")
    aws.seed_secret("test-stub/runner-keys", '{}')
    aws.seed_secret("test-stub/broker-keys", '{"KEY": "val"}')
    aws.seed_secret("test-stub/claude-oauth-token", "oauth-tok-xyz")
    return aws


def _fake_harness_all_pass(agent_dir: Path):
    """Fake harness_fn that reports all 8 checks as passed."""
    from safe_agents.contract.harness import (  # noqa: PLC0415
        ALL_CHECKS,
        CheckResult,
    )
    return [
        CheckResult(name=check.__name__, passed=True, reason="fake pass")
        for check in ALL_CHECKS
    ]


# ---------------------------------------------------------------------------
# Criterion 1: valid manifest parses + validates
# ---------------------------------------------------------------------------

class TestManifestParsing:
    def test_valid_manifest_loads(self, valid_manifest_file: Path) -> None:
        m = load_manifest(valid_manifest_file)
        assert m.name == "my-agent"
        assert m.arm == "ec2"
        assert m.repo == "git@github.com:Third-Ralph/my-agent.git"
        assert m.smoke.prompt == "In one sentence, what does this agent do?"
        assert m.smoke.expect_substring == "agent"
        assert m.secrets.runner_keys == "my-agent/runner-keys"
        assert m.secrets.broker_connector_keys == "my-agent/broker-keys"
        assert m.secrets.oauth_token == "my-agent/oauth-token"

    def test_real_test_stub_manifest_loads(self) -> None:
        """agents/test-stub.yaml must parse and validate."""
        m = load_manifest(TEST_STUB_MANIFEST)
        assert m.name == "test-stub"
        assert m.arm in ("ec2", "ec2-woken", "fargate")
        assert m.smoke.prompt
        assert m.smoke.expect_substring

    def test_envelope_is_preserved(self, valid_manifest_file: Path, tmp_path: Path) -> None:
        """Envelope half (broker-facing) is preserved pass-through in raw."""
        f = tmp_path / "with-envelope.yaml"
        with valid_manifest_file.open() as fh:
            data = yaml.safe_load(fh)
        data["envelope"] = {"polarity": "abstain", "caps": {"actions_per_run": 0}}
        f.write_text(yaml.dump(data))
        m = load_manifest(f)
        assert m.envelope == {"polarity": "abstain", "caps": {"actions_per_run": 0}}


# ---------------------------------------------------------------------------
# Criterion 2: invalid manifest raises ManifestError with a clear message
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "remove_field,expected_fragment",
    [
        ("name",               "name"),
        ("repo",               "repo"),
        ("deploy_key_secret",  "deploy_key_secret"),
        ("arm",                "arm"),
        ("policy",             "policy"),
        ("secrets",            "secrets"),
        ("smoke",              "smoke"),
    ],
    ids=[
        "missing-name",
        "missing-repo",
        "missing-deploy-key",
        "missing-arm",
        "missing-policy",
        "missing-secrets",
        "missing-smoke",
    ],
)
def test_missing_required_field_fails(
    tmp_path: Path, remove_field: str, expected_fragment: str
) -> None:
    data = yaml.safe_load(MINIMAL_VALID_MANIFEST)
    del data[remove_field]
    f = tmp_path / "bad.yaml"
    f.write_text(yaml.dump(data))
    with pytest.raises(ManifestError) as exc_info:
        load_manifest(f)
    assert expected_fragment in str(exc_info.value), (
        f"Expected {expected_fragment!r} in error message; got: {exc_info.value}"
    )


def test_bad_arm_fails(tmp_path: Path) -> None:
    data = yaml.safe_load(MINIMAL_VALID_MANIFEST)
    data["arm"] = "docker"
    f = tmp_path / "bad-arm.yaml"
    f.write_text(yaml.dump(data))
    with pytest.raises(ManifestError) as exc_info:
        load_manifest(f)
    assert "arm" in str(exc_info.value).lower()
    assert "docker" in str(exc_info.value)


def test_nonexistent_manifest_fails() -> None:
    with pytest.raises(ManifestError) as exc_info:
        load_manifest(Path("/no/such/manifest.yaml"))
    assert "not found" in str(exc_info.value).lower()


def test_missing_smoke_prompt_fails(tmp_path: Path) -> None:
    data = yaml.safe_load(MINIMAL_VALID_MANIFEST)
    del data["smoke"]["prompt"]
    f = tmp_path / "bad-smoke.yaml"
    f.write_text(yaml.dump(data))
    with pytest.raises(ManifestError) as exc_info:
        load_manifest(f)
    assert "smoke.prompt" in str(exc_info.value)


# ---------------------------------------------------------------------------
# manifest_get — dotted-path reader
# ---------------------------------------------------------------------------

class TestManifestGet:
    MANIFEST = {
        "name": "test-agent",
        "arm": "ec2",
        "smoke": {"prompt": "say hi", "expect_substring": "hi"},
        "secrets": {"runner_keys": "path/to/keys"},
    }

    def test_top_level_key(self) -> None:
        assert manifest_get(self.MANIFEST, "name") == "test-agent"

    def test_nested_key(self) -> None:
        assert manifest_get(self.MANIFEST, "smoke.prompt") == "say hi"

    def test_deeply_nested(self) -> None:
        assert manifest_get(self.MANIFEST, "secrets.runner_keys") == "path/to/keys"

    def test_missing_key_raises(self) -> None:
        with pytest.raises(KeyError) as exc_info:
            manifest_get(self.MANIFEST, "does_not_exist")
        assert "does_not_exist" in str(exc_info.value)

    def test_missing_nested_key_raises(self) -> None:
        with pytest.raises(KeyError) as exc_info:
            manifest_get(self.MANIFEST, "smoke.nonexistent")
        assert "nonexistent" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Criterion 3: dry-run produces expected ordered plan
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_returns_all_three_phases(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        assert result.dry_run is True
        phases_run = [pr.phase for pr in result.phase_results]
        assert phases_run == EXPECTED_PHASE_ORDER, (
            f"Expected phases {EXPECTED_PHASE_ORDER}, got {phases_run}"
        )

    def test_dry_run_all_phases_succeed(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        failures = [pr for pr in result.phase_results if not pr.success]
        assert not failures, (
            "Dry-run should succeed for a valid manifest; "
            + "\n".join(f"  {pr.phase}: {pr.error}" for pr in failures)
        )
        assert result.success

    def test_dry_run_provision_phase_steps_present(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        provision_result = next(pr for pr in result.phase_results if pr.phase == "provision")
        # Must mention the arm
        steps_text = " ".join(provision_result.steps)
        assert "ec2" in steps_text.lower()

    def test_dry_run_deploy_phase_three_secret_paths(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        deploy_result = next(pr for pr in result.phase_results if pr.phase == "deploy")
        steps_text = " ".join(deploy_result.steps)
        # All three secret paths must be mentioned.
        assert "runner_keys" in steps_text
        assert "oauth_token" in steps_text
        assert "broker_connector_keys" in steps_text
        # broker_connector_keys must be described as going to the broker only.
        broker_key_step = next(
            (s for s in deploy_result.steps if "broker_connector_keys" in s), None
        )
        assert broker_key_step is not None
        assert "broker" in broker_key_step.lower(), (
            "Connector key step must mention that creds go to the broker"
        )
        assert "never" in broker_key_step.lower() or "only" in broker_key_step.lower(), (
            "Connector key step must make clear the agent never receives creds"
        )

    def test_dry_run_smoke_phase_references_agent_dir(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        smoke_result = next(pr for pr in result.phase_results if pr.phase == "smoke")
        steps_text = " ".join(smoke_result.steps)
        assert "test-stub" in steps_text or "harness" in steps_text.lower()

    def test_dry_run_does_not_call_aws(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        # Dry-run must not hit the AWS interface at all.
        assert fake_aws.calls == [], (
            f"Dry-run made unexpected AWS calls: {fake_aws.calls}"
        )

    def test_dry_run_phase_subset(
        self, valid_manifest_file: Path, fake_aws: FakeAWS
    ) -> None:
        """Running only --phase provision should produce exactly one phase result."""
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            phases=("provision",),
        )
        assert [pr.phase for pr in result.phase_results] == ["provision"]


# ---------------------------------------------------------------------------
# Criterion 4: smoke phase invokes conformance harness against agents/test-stub
# ---------------------------------------------------------------------------

class TestSmokePhase:
    def test_smoke_passes_real_harness_against_test_stub(
        self, valid_manifest_file: Path
    ) -> None:
        """
        Smoke phase with the real conformance harness must pass all 8 checks
        against agents/test-stub — no AWS needed.
        """
        from safe_agents.contract.harness import run_harness  # noqa: PLC0415

        manifest = load_manifest(valid_manifest_file)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            harness_fn=run_harness,
        )
        assert result.success, (
            f"Smoke phase failed against test-stub: {result.error}"
        )
        assert result.phase == "smoke"

    def test_smoke_harness_fn_injected(
        self, valid_manifest_file: Path
    ) -> None:
        """Injected harness_fn is called with the agent_dir."""
        called_with: list[Path] = []

        def recording_harness(agent_dir: Path):
            called_with.append(agent_dir)
            return _fake_harness_all_pass(agent_dir)

        manifest = load_manifest(valid_manifest_file)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            harness_fn=recording_harness,
        )
        assert result.success
        assert called_with == [TEST_STUB_DIR], (
            f"harness_fn was called with {called_with!r}; expected [{TEST_STUB_DIR!r}]"
        )

    def test_smoke_dry_run_skips_harness(
        self, valid_manifest_file: Path
    ) -> None:
        """Dry-run must not invoke the harness function."""
        harness_called = []

        def never_harness(agent_dir: Path):
            harness_called.append(agent_dir)
            return []

        manifest = load_manifest(valid_manifest_file)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=True,
            harness_fn=never_harness,
        )
        assert result.success
        assert result.dry_run is True
        assert harness_called == []

    def test_smoke_fails_for_missing_agent_dir(
        self, valid_manifest_file: Path
    ) -> None:
        """Pointing the smoke phase at a non-existent dir must fail clearly."""
        from safe_agents.contract.harness import run_harness  # noqa: PLC0415

        manifest = load_manifest(valid_manifest_file)
        result = smoke_phase(
            manifest,
            Path("/no/such/agent"),
            dry_run=False,
            harness_fn=run_harness,
        )
        assert not result.success
        assert "not found" in (result.error or "").lower()

    def test_smoke_reports_named_failures(
        self, valid_manifest_file: Path
    ) -> None:
        """When the harness reports failures, smoke_phase surfaces the violation names."""
        from safe_agents.contract.harness import CheckResult  # noqa: PLC0415

        def always_fail_harness(agent_dir: Path):
            return [
                CheckResult(
                    name="ELEMENT_1_HEADLESS_ENTRYPOINT",
                    passed=False,
                    reason="run.sh does not exist",
                )
            ]

        manifest = load_manifest(valid_manifest_file)
        result = smoke_phase(
            manifest,
            TEST_STUB_DIR,
            dry_run=False,
            harness_fn=always_fail_harness,
        )
        assert not result.success
        assert "ELEMENT_1_HEADLESS_ENTRYPOINT" in (result.error or "")


# ---------------------------------------------------------------------------
# Agent-package resolution: no monorepo-sibling assumption (sa#106 Phase 3)
# ---------------------------------------------------------------------------

class TestAgentPackageResolution:
    """The pipeline resolves an agent package beside its manifest (or under an
    explicit --agent-root), NOT via a repo-root-relative agents/ jump — so a
    manifest + its connectors resolve from an arbitrary out-of-tree path."""

    @staticmethod
    def _recording_harness(sink: list):
        def _h(agent_dir: Path):
            sink.append(agent_dir)
            return _fake_harness_all_pass(agent_dir)
        return _h

    def test_resolves_agent_package_from_out_of_tree_dir(
        self, fake_aws: FakeAWS, tmp_path: Path
    ) -> None:
        """An external agent repo (manifest + package dir with a dummy connector)
        living in a tmpdir resolves with NO monorepo assumption. This fails under
        the old manifest_path.parent.parent/'agents' jump (which would look in
        <tmp>/agents/my-agent and find nothing)."""
        agent_repo = tmp_path / "external-agent-repo"
        agent_repo.mkdir()
        manifest_path = agent_repo / "my-agent.yaml"
        manifest_path.write_text(MINIMAL_VALID_MANIFEST)
        # The agent package sits beside its manifest, holding an agent-owned connector.
        pkg_dir = agent_repo / "my-agent"
        pkg_dir.mkdir()
        (pkg_dir / "connector.py").write_text("# dummy agent-owned connector\n")

        seen: list[Path] = []
        result = run_pipeline(
            manifest_path,
            dry_run=False,
            aws=fake_aws,
            phases=("smoke",),
            harness_fn=self._recording_harness(seen),
        )

        assert result.success, f"pipeline failed: {result.aborted_at}"
        assert seen == [pkg_dir], (
            f"expected the harness to run against {pkg_dir!r} (beside the manifest), "
            f"got {seen!r} — a monorepo-relative jump would have looked elsewhere"
        )

    def test_agent_root_overrides_resolution_base(
        self, fake_aws: FakeAWS, tmp_path: Path
    ) -> None:
        """An explicit agent_root resolves <agent_root>/<package> regardless of
        where the manifest lives."""
        manifest_path = tmp_path / "manifests" / "my-agent.yaml"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(MINIMAL_VALID_MANIFEST)
        # Package lives under a SEPARATE root, not beside the manifest.
        agent_root = tmp_path / "packages"
        pkg_dir = agent_root / "my-agent"
        pkg_dir.mkdir(parents=True)

        seen: list[Path] = []
        result = run_pipeline(
            manifest_path,
            dry_run=False,
            aws=fake_aws,
            agent_root=agent_root,
            phases=("smoke",),
            harness_fn=self._recording_harness(seen),
        )

        assert result.success, f"pipeline failed: {result.aborted_at}"
        assert seen == [pkg_dir]

    def test_explicit_agent_dir_wins_over_agent_root(
        self, fake_aws: FakeAWS, tmp_path: Path
    ) -> None:
        """agent_dir has the highest precedence."""
        manifest_path = tmp_path / "my-agent.yaml"
        manifest_path.write_text(MINIMAL_VALID_MANIFEST)
        explicit = tmp_path / "explicit-pkg"
        explicit.mkdir()

        seen: list[Path] = []
        result = run_pipeline(
            manifest_path,
            dry_run=False,
            aws=fake_aws,
            agent_dir=explicit,
            agent_root=tmp_path / "ignored-root",
            phases=("smoke",),
            harness_fn=self._recording_harness(seen),
        )

        assert result.success
        assert seen == [explicit]

    def test_in_tree_test_stub_still_resolves_by_default(
        self, fake_aws: FakeAWS
    ) -> None:
        """Back-compat: the committed in-tree agents/test-stub.yaml resolves to
        agents/test-stub with no agent_dir/agent_root given (the package sits
        beside its manifest, exactly as the old monorepo layout produced)."""
        seen: list[Path] = []
        result = run_pipeline(
            TEST_STUB_MANIFEST,
            dry_run=False,
            aws=fake_aws,
            phases=("smoke",),
            harness_fn=self._recording_harness(seen),
        )

        assert result.success, f"pipeline failed: {result.aborted_at}"
        assert seen == [TEST_STUB_DIR]


# ---------------------------------------------------------------------------
# Full pipeline integration (fake AWS, real harness, test-stub fixture)
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_full_dry_run_with_real_stub_manifest(
        self, fake_aws: FakeAWS
    ) -> None:
        """End-to-end dry-run against the committed agents/test-stub.yaml."""
        result = run_pipeline(
            TEST_STUB_MANIFEST,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        assert result.success, (
            "Full dry-run should succeed for the test-stub manifest;\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        assert [pr.phase for pr in result.phase_results] == EXPECTED_PHASE_ORDER
        assert result.aborted_at is None

    def test_smoke_only_with_real_harness(self, fake_aws: FakeAWS) -> None:
        """
        End-to-end: provision+deploy in dry-run, smoke with real harness against
        agents/test-stub. Proves the smoke step wiring to #31 works.
        """
        from safe_agents.contract.harness import run_harness  # noqa: PLC0415

        result = run_pipeline(
            TEST_STUB_MANIFEST,
            dry_run=False,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            phases=("smoke",),
            harness_fn=run_harness,
        )
        assert result.success, (
            "Smoke-only run with real harness failed: "
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        smoke_result = result.phase_results[0]
        assert smoke_result.phase == "smoke"
        assert smoke_result.success

    def test_pipeline_aborts_after_first_phase_failure(
        self, tmp_path: Path, fake_aws: FakeAWS
    ) -> None:
        """If provision fails, deploy and smoke must not run."""
        # Use an arm value that triggers a live provision failure in non-dry-run
        # (fargate is not implemented).
        data = yaml.safe_load(MINIMAL_VALID_MANIFEST)
        data["arm"] = "fargate"
        f = tmp_path / "fargate-agent.yaml"
        f.write_text(yaml.dump(data))

        result = run_pipeline(
            f,
            dry_run=False,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        assert not result.success
        assert result.aborted_at == "provision"
        # Only one phase should have run.
        assert len(result.phase_results) == 1

    def test_print_plan_produces_output(
        self, valid_manifest_file: Path, fake_aws: FakeAWS, capsys: Any
    ) -> None:
        result = run_pipeline(
            valid_manifest_file,
            dry_run=True,
            aws=fake_aws,
            agent_dir=TEST_STUB_DIR,
            harness_fn=_fake_harness_all_pass,
        )
        result.print_plan()
        captured = capsys.readouterr()
        assert "provision" in captured.out.upper() or "PROVISION" in captured.out
        assert "deploy" in captured.out.upper() or "DEPLOY" in captured.out
        assert "smoke" in captured.out.upper() or "SMOKE" in captured.out
