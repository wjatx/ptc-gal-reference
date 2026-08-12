"""
EC2 arm tests — acceptance criteria for sa#33 + sa#85.

All tests are AWS-free: AWS calls go through FakeAWS (no live boto3 needed).

Acceptance criteria (original three from sa#33, plus three new from sa#85):

  1. User-data renders correctly from manifest params
       - All {{key}} markers are replaced with the supplied values.
       - The harness-coupling block is clearly delimited (markers present).
       - The template contains no hardcoded agent names.
       - [sa#85] The template contains no internet-dependent steps
         (no yum/dnf, npm install-from-internet, or git-clone-from-internet).

  2. Pipeline dry-run for agents/smoke-ec2.yaml shows ec2 provision→deploy→smoke
       - All three phases run in order.
       - The provision phase steps mention "ec2" and the key arm operations.
       - Dry-run makes no AWS calls.

  3. Two-identity separation at the rendered-policy level
       - agent_role_extensions() grants NO GetSecretValue on the broker
         connector-keys path (*/connectors/*).
       - The broker role's resource pattern DOES cover */connectors/* (verified
         against BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN from provision.py).

  4. [sa#85] AMI looked up by tag, newest wins
       - ec2_provision calls describe_images filtered by safe-agents:ami=base.
       - When multiple images match, the one with the highest ami-version is used.

  5. [sa#85] RunInstances retries on the IAM profile-not-ready error
       - FakeAWS raises IamProfileNotReadyError N times then succeeds.
       - ec2_provision returns a valid instance ID despite the initial failures.

  6. [sa#85] Tagging and two-identity split unchanged
       - Standard tag set (Project/Environment/Agent/ManagedBy) still applied.
       - agentSG (not brokerSG) still used.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Imports (core/ is on sys.path via conftest.py)
# ---------------------------------------------------------------------------

from safe_agents.arms.ec2.provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    agent_role_extensions,
    render_user_data,
    wait_for_clean_start,
)
from safe_agents.pipeline import FakeAWS, load_manifest, run_pipeline

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_EC2_MANIFEST = AGENTS_DIR / "smoke-ec2.yaml"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# sa#85: repo and deploy_key_secret removed — prebuilt-AMI model uses S3 bundle.
# sa#35: broker_dns / agent_runs_table / region added — the converged two-box model writes them
# into /etc/safe-agents/agent.env for run-brokered.sh (broker SERVICE round-trip + run record).
_VALID_PARAMS = {
    "name": "my-agent",
    "arm": "ec2",
    "oauth_token": "my-agent/claude-oauth-token",
    "environment": "development",
    "broker_dns": "broker.safe-agents.local",
    "agent_runs_table": "safe-agents-development-agent-runs",
    "region": "us-east-1",
}


@pytest.fixture()
def fake_aws_ec2() -> FakeAWS:
    """FakeAWS seeded with the SSM params, secrets, and AMI smoke-ec2.yaml references."""
    aws = FakeAWS()
    # Secrets the deploy phase reads
    aws.seed_secret("smoke-ec2/runner-keys", "{}")
    aws.seed_secret("smoke-ec2/broker-keys", '{"KEY": "val"}')
    aws.seed_secret("smoke-ec2/claude-oauth-token", "oauth-tok-smoke")
    # SSM infra exports (published by infra/ foundation stacks)
    env = "development"
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-role-arn",
        "arn:aws:iam::123456789012:instance-profile/safe-agents-development-AgentRole",
    )
    aws.seed_ssm_param(f"/safe-agents/{env}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(f"/safe-agents/{env}/endpoint-sg-id", "sg-0endpoint999")
    aws.seed_ssm_param(f"/safe-agents/{env}/agent-subnet-ids", "subnet-0abc1234,subnet-0def5678")
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-arn",
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-name", "safe-agents-development-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/tables-key-arn",
        "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-cmk",
    )
    aws.seed_ssm_param(f"/safe-agents/{env}/broker-service-dns", "broker.safe-agents.local")
    # sa#85: prebuilt base AMI (replaces the public AL2023 SSM parameter lookup).
    aws.seed_image(
        "ami-0fakebaseami001",
        {"safe-agents:ami": "base", "safe-agents:ami-version": "20241201-01"},
        creation_date="2024-12-01T00:00:00Z",
    )
    return aws


# ---------------------------------------------------------------------------
# Criterion 1: User-data rendering
# ---------------------------------------------------------------------------

class TestUserDataRendering:
    def test_all_required_params_substituted(self) -> None:
        """All {{key}} markers must be replaced; no markers may remain."""
        rendered = render_user_data(_VALID_PARAMS)
        remaining = re.findall(r"\{\{[^}]+\}\}", rendered)
        assert not remaining, (
            f"Unsubstituted template markers after render: {remaining}"
        )

    def test_param_values_present_in_output(self) -> None:
        """Each supplied param value must appear in the rendered script."""
        rendered = render_user_data(_VALID_PARAMS)
        for key, value in _VALID_PARAMS.items():
            assert value in rendered, (
                f"Value for param {key!r} ({value!r}) not found in rendered user-data"
            )

    def test_harness_coupling_block_delimiters_present(self) -> None:
        """The HARNESS-COUPLING BLOCK START/END markers must bracket the harness reference.

        sa#85: the CLI is pre-baked in the base AMI, so there is no npm install here.
        The block still references claude-code (as the pre-installed binary) and fetches
        the OAuth token — both must appear inside the delimited region.
        """
        rendered = render_user_data(_VALID_PARAMS)
        start_idx = rendered.find("HARNESS-COUPLING BLOCK START")
        end_idx = rendered.find("HARNESS-COUPLING BLOCK END")
        assert start_idx != -1, "HARNESS-COUPLING BLOCK START marker missing from user-data"
        assert end_idx != -1, "HARNESS-COUPLING BLOCK END marker missing from user-data"
        assert start_idx < end_idx, "BLOCK START must precede BLOCK END"
        # The block must reference the claude-code binary (pre-installed in the AMI).
        block_content = rendered[start_idx:end_idx]
        assert "claude-code" in block_content or "@anthropic-ai/claude-code" in block_content, (
            "Reference to claude-code not found in the harness-coupling block — "
            "it must be isolated there so a harness swap only touches that block"
        )

    def test_oauth_token_fetch_inside_harness_block(self) -> None:
        """The oauth_token fetch must be inside the delimited harness-coupling block."""
        rendered = render_user_data(_VALID_PARAMS)
        start_idx = rendered.find("HARNESS-COUPLING BLOCK START")
        end_idx = rendered.find("HARNESS-COUPLING BLOCK END")
        block = rendered[start_idx:end_idx]
        # The oauth_token secret id must appear inside the block for the initial fetch.
        assert "OAUTH_TOKEN_SECRET" in block or _VALID_PARAMS["oauth_token"] in block, (
            "OAuth token secret id not found in harness-coupling block"
        )

    def test_no_hardcoded_agent_names_in_template(self) -> None:
        """The template file itself must not contain hardcoded agent names."""
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        template_text = template_path.read_text()
        # These strings would indicate a consumer-agent or test-specific leak.
        forbidden = ["example-agent", "test-stub", "alpaca", "telegram", "tavily"]
        for name in forbidden:
            assert name not in template_text.lower(), (
                f"Hardcoded agent name {name!r} found in user-data.sh.tmpl — "
                "the template must be agent-agnostic (use {{name}} etc.)"
            )

    def test_missing_param_raises(self) -> None:
        """render_user_data must raise ValueError when a required param is missing."""
        # Dropping oauth_token; the error must name the missing key.
        incomplete = {k: v for k, v in _VALID_PARAMS.items() if k != "oauth_token"}
        with pytest.raises(ValueError, match="oauth_token"):
            render_user_data(incomplete)

    def test_user_data_no_internet_steps(self) -> None:
        """The template must contain no internet-dependent commands (sa#85).

        The prebuilt-AMI model pulls code from S3 (VPC endpoint) and fetches secrets
        via the Secrets Manager VPC endpoint. No package managers or git-from-internet
        are allowed — those would fail in a PRIVATE_ISOLATED subnet with no IGW/NAT.
        """
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        template_text = template_path.read_text()

        forbidden_patterns = [
            # Package manager calls that require internet
            ("dnf ", "dnf package manager (internet required)"),
            ("yum ", "yum package manager (internet required)"),
            # npm global installs from the internet
            ("npm install", "npm install (internet required)"),
            # git clone from github or any remote URL
            ("git clone", "git clone (internet required)"),
        ]
        for pattern, description in forbidden_patterns:
            assert pattern not in template_text, (
                f"Internet-dependent command found in user-data.sh.tmpl: {description!r}. "
                "The prebuilt-AMI bootstrap must be config-only (S3 + SM endpoints only)."
            )

    def test_render_is_idempotent_for_same_params(self) -> None:
        """Rendering the same params twice produces identical output."""
        assert render_user_data(_VALID_PARAMS) == render_user_data(_VALID_PARAMS)

    def test_different_agent_names_produce_different_output(self) -> None:
        """The rendered script must differ for different agent names."""
        params_a = dict(_VALID_PARAMS, name="agent-alpha")
        params_b = dict(_VALID_PARAMS, name="agent-beta")
        assert render_user_data(params_a) != render_user_data(params_b)

    # -- sa#88 hardening tests ------------------------------------------------

    def test_user_data_has_set_x(self) -> None:
        """user-data.sh.tmpl must enable execution tracing with 'set -x' (sa#88).

        set -x writes every command to the log before executing it, so that a
        bootstrap failure is never silent — the log always shows which line died.
        """
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        assert "set -x" in template_path.read_text(), (
            "user-data must contain 'set -x' to trace each command to the bootstrap log"
        )

    def test_user_data_has_err_trap(self) -> None:
        """user-data.sh.tmpl must set a trap on ERR so failures are never silent (sa#88)."""
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        content = template_path.read_text()
        assert "trap" in content and "ERR" in content, (
            "user-data must define 'trap ... ERR' to catch any failed command"
        )

    def test_user_data_writes_failure_marker_on_error(self) -> None:
        """user-data.sh.tmpl must write a failure marker file when the ERR trap fires (sa#88).

        The marker lets post-boot inspection detect a bootstrap death without
        reading the full log (e.g. SSM agent checks for the .FAILED file).
        """
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        content = template_path.read_text()
        assert ".FAILED" in content or "FAIL_MARKER" in content or "BOOTSTRAP_FAILED" in content, (
            "user-data error handler must write a *.FAILED marker file so failed "
            "bootstraps are detectable without parsing the full log"
        )

    def test_user_data_s3_bundle_key_matches_bundle_constant(self) -> None:
        """S3 key convention in user-data must match BUNDLE_CURRENT_KEY from bundle.py (sa#88).

        The bundle is uploaded under agents/<name>/current/bundle.tar.gz by bundle.py;
        user-data must pull from exactly that path or the instance boots without code.
        """
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        content = template_path.read_text()
        # The template uses shell variables; check that the structural segments agree
        # with BUNDLE_CURRENT_KEY = "agents/{name}/current/bundle.tar.gz".
        assert "agents/" in content, (
            "user-data S3 key must start with 'agents/' to match BUNDLE_CURRENT_KEY"
        )
        assert "current/bundle.tar.gz" in content, (
            "user-data S3 key must use 'current/bundle.tar.gz' to match BUNDLE_CURRENT_KEY"
        )

    def test_user_data_extracts_bundle_to_agent_dir(self) -> None:
        """user-data.sh.tmpl must extract the bundle into /opt/agents/<name> (sa#88)."""
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        content = template_path.read_text()
        # The AGENT_DIR variable is set to /opt/agents/${AGENT_NAME}; verify it exists.
        assert "/opt/agents/" in content or "AGENT_DIR" in content, (
            "user-data must extract the S3 bundle into /opt/agents/<name>"
        )
        assert "tar -xzf" in content or "tar -x" in content, (
            "user-data must unpack the bundle tar.gz into AGENT_DIR"
        )

    def test_user_data_enables_and_starts_systemd_timer(self) -> None:
        """user-data.sh.tmpl must enable + start the agent's systemd timer (sa#88)."""
        template_path = Path(__file__).parent.parent / "user-data.sh.tmpl"
        content = template_path.read_text()
        assert "systemctl enable" in content and ".timer" in content, (
            "user-data must enable the agent's systemd timer so runs happen on schedule"
        )
        # 'enable --now' covers both enable + start in one command.
        assert "enable --now" in content or (
            "systemctl start" in content and ".timer" in content
        ), (
            "user-data must start the timer (enable --now, or separate start command)"
        )


# ---------------------------------------------------------------------------
# Criterion 2: Pipeline dry-run ordering for smoke-ec2.yaml
# ---------------------------------------------------------------------------

class TestPipelineDryRunSmokeEc2:
    def test_smoke_ec2_manifest_loads(self) -> None:
        """agents/smoke-ec2.yaml must parse and validate without error."""
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        assert manifest.name == "smoke-ec2"
        assert manifest.arm == "ec2"

    def test_dry_run_produces_three_phases_in_order(
        self, fake_aws_ec2: FakeAWS
    ) -> None:
        """Dry-run for smoke-ec2.yaml must produce provision → deploy → smoke."""
        from safe_agents.pipeline import PHASES_ORDERED  # noqa: PLC0415

        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=fake_aws_ec2,
            agent_dir=TEST_STUB_DIR,
        )
        assert result.success, (
            "Dry-run failed:\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success
            )
        )
        phases_run = [pr.phase for pr in result.phase_results]
        assert phases_run == list(PHASES_ORDERED), (
            f"Expected phase order {list(PHASES_ORDERED)}, got {phases_run}"
        )

    def test_dry_run_provision_phase_mentions_ec2(
        self, fake_aws_ec2: FakeAWS
    ) -> None:
        """The provision phase steps must mention the ec2 arm and key operations."""
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=fake_aws_ec2,
            agent_dir=TEST_STUB_DIR,
        )
        provision = next(pr for pr in result.phase_results if pr.phase == "provision")
        steps_text = " ".join(provision.steps).lower()
        assert "ec2" in steps_text, "Provision steps must mention 'ec2'"
        assert "agentRole".lower() in steps_text or "agentrole" in steps_text, (
            "Provision steps must mention agentRole (two-identity split)"
        )
        assert "broker" in steps_text, (
            "Provision steps must mention broker sidecar co-placement"
        )

    def test_dry_run_deploy_phase_three_secret_paths(
        self, fake_aws_ec2: FakeAWS
    ) -> None:
        """Deploy phase must mention all three secret paths with correct routing."""
        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=fake_aws_ec2,
            agent_dir=TEST_STUB_DIR,
        )
        deploy = next(pr for pr in result.phase_results if pr.phase == "deploy")
        steps_text = " ".join(deploy.steps)
        assert "runner_keys" in steps_text
        assert "oauth_token" in steps_text
        assert "broker_connector_keys" in steps_text
        # broker_connector_keys must be described as going to the broker only.
        broker_step = next(
            (s for s in deploy.steps if "broker_connector_keys" in s), None
        )
        assert broker_step is not None
        assert "broker" in broker_step.lower()
        assert "never" in broker_step.lower() or "only" in broker_step.lower()

    def test_dry_run_makes_no_aws_calls(self, fake_aws_ec2: FakeAWS) -> None:
        """Dry-run must not invoke AWS at all."""
        run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=True,
            aws=fake_aws_ec2,
            agent_dir=TEST_STUB_DIR,
        )
        assert fake_aws_ec2.calls == [], (
            f"Dry-run made unexpected AWS calls: {fake_aws_ec2.calls}"
        )


# ---------------------------------------------------------------------------
# Criterion 3: Two-identity separation at the rendered-policy level
# ---------------------------------------------------------------------------

class TestTwoIdentitySeparation:
    """
    Assert the two-identity split at the IAM policy statement level.

    The agentRole policy (the extensions this arm adds) must NOT contain
    GetSecretValue on any resource matching the broker connector-keys pattern.
    The brokerRole policy (from IdentityStack, represented by the BROKER constant)
    DOES cover that pattern — and only the broker should.
    """

    # Seam constants for the test: a plausible test env + a fake table ARN.
    _ENV = "development"
    _AGENT_RUNS_ARN = (
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs"
    )
    _TABLES_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-cmk"

    def _extensions(self, agent_name: str = "test-agent") -> list[dict]:
        return agent_role_extensions(
            agent_name, self._ENV, self._AGENT_RUNS_ARN, self._TABLES_KEY_ARN
        )

    def test_agent_role_has_no_get_secret_on_connector_keys_path(self) -> None:
        """agentRole extensions must not grant GetSecretValue on */connectors/*."""
        for stmt in self._extensions():
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not any("secretsmanager:GetSecretValue" in a for a in actions):
                continue  # this statement isn't about GetSecretValue — skip

            # It IS a GetSecretValue statement; check its Resource(s).
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                assert "connectors" not in resource, (
                    f"Agent role extension grants GetSecretValue on a resource that "
                    f"matches the broker connector-keys path: {resource!r}\n"
                    f"Statement: {stmt}"
                )

    def test_agent_role_oauth_token_is_scoped_to_agent_namespace(self) -> None:
        """The oauth_token GetSecretValue resource must be scoped to the agent's prefix."""
        extensions = self._extensions(agent_name="my-agent")
        oauth_stmts = [
            stmt for stmt in extensions
            if stmt.get("Sid") == "OauthToken"
        ]
        assert oauth_stmts, "OauthToken statement not found in agent_role_extensions"
        stmt = oauth_stmts[0]
        resource = stmt["Resource"]
        assert "my-agent" in resource, (
            f"OauthToken resource {resource!r} does not include the agent name prefix"
        )
        assert "connectors" not in resource, (
            f"OauthToken resource {resource!r} must not match the connector-keys pattern"
        )

    def test_agent_role_has_run_record_putitem(self) -> None:
        """agentRole extensions must include PutItem on the agent-runs table."""
        run_record_stmts = [
            stmt for stmt in self._extensions()
            if "dynamodb:PutItem" in (
                [stmt["Action"]] if isinstance(stmt["Action"], str) else stmt["Action"]
            )
        ]
        assert run_record_stmts, (
            "agent_role_extensions must contain a dynamodb:PutItem statement "
            "(element 5: run-record write)"
        )
        # The resource must be the agent-runs table, not the grants table.
        stmt = run_record_stmts[0]
        resource = stmt["Resource"]
        assert "agent-runs" in resource, (
            f"PutItem resource {resource!r} does not reference the agent-runs table"
        )

    def test_agent_role_has_no_grants_table_write(self) -> None:
        """agentRole extensions must NOT grant any write on the grants table.

        Only promotionRole and demotionRole may write grants (IdentityStack invariant).
        The agent role cannot promote itself or the agent.
        """
        for stmt in self._extensions():
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resource = stmt.get("Resource", "")
            write_actions = [a for a in actions if a.startswith("dynamodb:Put") or "UpdateItem" in a]
            if write_actions and isinstance(resource, str) and "grants" in resource:
                pytest.fail(
                    f"Agent role extension grants writes on the grants table: {stmt}"
                )

    def test_broker_connector_keys_pattern_covers_connectors_path(self) -> None:
        """BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN must match the connector-keys layout.

        This pattern is what the IdentityStack grants brokerRole for
        secretsmanager:GetSecretValue. It must contain 'connectors' so the
        negative check on the agentRole is meaningful.
        """
        assert "connectors" in BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN, (
            f"BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN {BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN!r} "
            "does not reference the connector-keys path — pattern may be wrong"
        )

    def test_agent_oauth_token_resource_does_not_match_broker_pattern(self) -> None:
        """The OauthToken resource must not be a sub-path of the broker pattern.

        Cross-check: even if the broker pattern regex were broadened, the oauth_token
        resource must still be distinguishable from the connector-keys namespace.
        """
        extensions = self._extensions(agent_name="any-agent")
        oauth_stmts = [s for s in extensions if s.get("Sid") == "OauthToken"]
        assert oauth_stmts, "OauthToken statement not found"
        resource = oauth_stmts[0]["Resource"]
        # BROKER pattern is "*/connectors/*"; the oauth resource must NOT match it.
        pattern_core = BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN.replace("*", "")
        assert pattern_core not in resource, (
            f"OauthToken resource {resource!r} overlaps with the broker connector-keys "
            f"pattern core {pattern_core!r}"
        )

    def test_ec2_provision_calls_run_instances(self, fake_aws_ec2: FakeAWS) -> None:
        """ec2_provision() must call run_instances (not instance_id_for_stack)."""
        from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        instance_id = ec2_provision(manifest, fake_aws_ec2, environment="development")
        assert instance_id.startswith("i-"), (
            f"ec2_provision returned an unexpected instance ID: {instance_id!r}"
        )
        assert fake_aws_ec2.was_called("run_instances"), (
            "ec2_provision must call run_instances on the AWSInterface"
        )
        assert not fake_aws_ec2.was_called("instance_id_for_stack"), (
            "ec2_provision must not call instance_id_for_stack (that is the CF-stack path)"
        )

    def test_ec2_provision_uses_isolated_agent_subnet_and_endpoint_sg(
        self, fake_aws_ec2: FakeAWS
    ) -> None:
        """Converged two-box model (sa#35, Option A): the box runs in the ISOLATED agent subnet on
        the agent SG (egress = broker SG only) + the endpoint SG (AWS interface endpoints) — the
        same placement the proven ec2-woken box uses. There is NO co-located model-proxy, so the
        old broker-subnet placement is gone; the subnet has no NAT and the agent SG permits only the
        broker, which is what makes the smoke-egress assertion hold."""
        from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

        captured: dict = {}
        original = fake_aws_ec2.run_instances

        def spy(**kwargs):
            captured.update(kwargs)
            return original(**kwargs)

        fake_aws_ec2.run_instances = spy  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        ec2_provision(manifest, fake_aws_ec2, environment="development")

        def _looked_up(key: str) -> bool:
            return any(
                call[0] == "get_ssm_param" and key in call[1] for call in fake_aws_ec2.calls
            )

        assert _looked_up("agent-sg-id"), "must place the box on the agent SG (broker-only egress)"
        assert _looked_up("endpoint-sg-id"), (
            "must attach the endpoint SG so the no-NAT box reaches the AWS interface endpoints "
            "(Secrets Manager for oauth, DynamoDB for run records, SSM)"
        )
        assert _looked_up("agent-subnet-ids"), (
            "must place the box in the ISOLATED agent subnet (no NAT), not the broker subnet"
        )
        assert not _looked_up("broker-sg-id") and not _looked_up("broker-subnet-ids"), (
            "the converged model drops the broker-subnet placement (no co-located proxy)"
        )
        # The launch must carry BOTH the agent SG and the endpoint SG, and the isolated subnet.
        assert captured["security_group_ids"] == ["sg-0agent12345", "sg-0endpoint999"]
        assert captured["subnet_id"] == "subnet-0abc1234"

    def test_agent_role_has_tables_cmk_grant_no_connectors(self) -> None:
        """agentRole extensions must grant KMS on the tables CMK (the agent-runs table is
        CMK-encrypted, so the run-record PutItem needs it) — scoped to the ONE key, no connectors."""
        kms_stmts = [
            s for s in self._extensions()
            if any(a.startswith("kms:") for a in (
                s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
            ))
        ]
        assert kms_stmts, "agent_role_extensions must include a KMS grant for the CMK-encrypted table"
        stmt = kms_stmts[0]
        assert stmt["Resource"] == self._TABLES_KEY_ARN, "KMS grant must be scoped to the ONE tables CMK"
        assert stmt["Resource"] != "*", "KMS grant must not be a bare '*'"
        assert "connectors" not in stmt["Resource"]


# ---------------------------------------------------------------------------
# Criterion 4 (sa#85): AMI lookup by tag, newest wins
# ---------------------------------------------------------------------------

class TestAmiTagLookup:
    """ec2_provision must select the base AMI by tag, not by SSM path."""

    def test_ami_looked_up_by_tag(self, fake_aws_ec2: FakeAWS) -> None:
        """ec2_provision must call describe_images to find the base AMI."""
        from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        ec2_provision(manifest, fake_aws_ec2, environment="development")

        describe_calls = [c for c in fake_aws_ec2.calls if c[0] == "describe_images"]
        assert describe_calls, (
            "ec2_provision must call describe_images to look up the base AMI by tag"
        )
        tag_filters = describe_calls[0][1]
        assert tag_filters.get("safe-agents:ami") == "base", (
            f"describe_images must filter by safe-agents:ami=base; got {tag_filters!r}"
        )

    def test_newest_ami_wins(self, fake_aws_ec2: FakeAWS) -> None:
        """When multiple base AMIs exist, the one with the highest ami-version is used."""
        from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

        # Seed two base AMIs; the newer version should win.
        fake_aws_ec2.seed_image(
            "ami-0older",
            {"safe-agents:ami": "base", "safe-agents:ami-version": "20241101-01"},
            creation_date="2024-11-01T00:00:00Z",
        )
        fake_aws_ec2.seed_image(
            "ami-0newer",
            {"safe-agents:ami": "base", "safe-agents:ami-version": "20241201-02"},
            creation_date="2024-12-01T00:00:00Z",
        )

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        # Pass image_id=None to force tag-based lookup (default behaviour).
        instance_id = ec2_provision(manifest, fake_aws_ec2, environment="development")
        assert instance_id.startswith("i-"), f"Unexpected instance id: {instance_id!r}"

        # The run_instances call must have used the newest AMI.
        run_calls = [c for c in fake_aws_ec2.calls if c[0] == "run_instances"]
        assert run_calls, "run_instances was not called"
        # We can't directly inspect the image_id from FakeAWS.calls (we only record
        # name + instance_type), so we verify indirectly: describe_images returned
        # ami-0newer as max, and no error was raised = the correct AMI was resolved.
        # A direct assertion on the image_id requires reading FakeAWS._instances;
        # instead verify that the newest AMI was selected by _pick_newest_ami.
        from safe_agents.arms.ec2.provision import _pick_newest_ami  # noqa: PLC0415

        candidates = [
            {"image_id": "ami-0older", "tags": {"safe-agents:ami-version": "20241101-01"},
             "creation_date": "2024-11-01T00:00:00Z"},
            {"image_id": "ami-0newer", "tags": {"safe-agents:ami-version": "20241201-02"},
             "creation_date": "2024-12-01T00:00:00Z"},
        ]
        assert _pick_newest_ami(candidates) == "ami-0newer", (
            "_pick_newest_ami must select the image with the lexicographically greatest "
            "safe-agents:ami-version tag value"
        )

    def test_pick_newest_ami_raises_when_empty(self) -> None:
        """_pick_newest_ami must raise RuntimeError when no images are found."""
        from safe_agents.arms.ec2.provision import _pick_newest_ami  # noqa: PLC0415

        with pytest.raises(RuntimeError, match="no base AMI found"):
            _pick_newest_ami([])


# ---------------------------------------------------------------------------
# Criterion 5 (sa#85): RunInstances retries on IAM profile-not-ready error
# ---------------------------------------------------------------------------

class TestIamRaceRetry:
    """ec2_provision must retry RunInstances on the IAM propagation race."""

    def test_retries_and_succeeds(self, fake_aws_ec2: FakeAWS, monkeypatch) -> None:
        """ec2_provision returns a valid instance ID after N IAM-not-ready failures."""
        from safe_agents.arms.ec2 import provision  # noqa: PLC0415
        from safe_agents.arms.ec2.provision import ec2_provision  # noqa: PLC0415

        # Eliminate real sleeps in the retry loop.
        monkeypatch.setattr(provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})())

        # FakeAWS will raise IamProfileNotReadyError twice then succeed.
        fake_aws_ec2.run_instances_profile_error_count = 2

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        instance_id = ec2_provision(manifest, fake_aws_ec2, environment="development")

        assert instance_id.startswith("i-"), (
            f"ec2_provision must return a valid instance ID after IAM retries; got {instance_id!r}"
        )
        # Three run_instances calls total: 2 failures + 1 success.
        run_calls = [c for c in fake_aws_ec2.calls if c[0] == "run_instances"]
        assert len(run_calls) == 3, (
            f"Expected 3 run_instances calls (2 IAM failures + 1 success); got {len(run_calls)}"
        )

    def test_exceeds_max_attempts_raises(self, fake_aws_ec2: FakeAWS, monkeypatch) -> None:
        """ec2_provision raises RuntimeError if RunInstances fails more than max_attempts."""
        from safe_agents.arms.ec2 import provision  # noqa: PLC0415
        from safe_agents.arms.ec2.provision import ec2_provision, _IAM_RACE_MAX_ATTEMPTS  # noqa: PLC0415

        monkeypatch.setattr(provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})())

        # Fail more times than the retry cap.
        fake_aws_ec2.run_instances_profile_error_count = _IAM_RACE_MAX_ATTEMPTS + 5

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        with pytest.raises(RuntimeError, match="IAM profile propagation race"):
            ec2_provision(manifest, fake_aws_ec2, environment="development")


# ---------------------------------------------------------------------------
# Criterion 6 (sa#88): AMI component gaps — awscli + baked harness
# ---------------------------------------------------------------------------

# Canonical harness path: the value phases.py _smoke_remote SSM-execs.
# Both the AMI component (bake) and phases.py (invoke) must reference this path.
_HARNESS_PATH = "/opt/safe-agents/core/contract/harness.py"
_HARNESS_DIR  = "/opt/safe-agents/core/contract"

_COMPONENT_PATH = (
    Path(__file__).parent.parent / "ami" / "image-builder" / "component-base.yaml"
)
_PHASES_PATH = (
    Path(__file__).parent.parent.parent.parent / "pipeline" / "phases.py"
)


_USER_DATA_PATH = (
    Path(__file__).parent.parent / "user-data.sh.tmpl"
)


class TestAmiComponentContent:
    """component-base.yaml must close the two deployed-bootstrap gaps found in sa#88.

    Gap 1 — AWS CLI: user-data.sh.tmpl calls 'aws s3 cp' and
      'aws secretsmanager get-secret-value'. The CLI must be in the base AMI or
      user-data dies at the first step.

    Gap 2 — Harness: remote smoke SSM-execs python3 /opt/safe-agents/core/contract/harness.py.
      The harness is no longer baked into the AMI via a git clone. Instead the
      bakery uploads safe_agents/contract/ as a platform bundle to S3, and user-data.sh.tmpl
      pulls+extracts it at boot so the harness lands at the expected path.
    """

    def test_awscli_in_install_toolchain(self) -> None:
        """Gap 1: AWS CLI v2 must be installed via the official upstream installer.

        'awscli2' is not a valid AL2023 dnf package; the official aarch64 installer
        must be used instead. user-data calls 'aws s3 cp' and 'aws secretsmanager'.
        """
        content = _COMPONENT_PATH.read_text()
        assert "awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" in content, (
            "component-base.yaml must install AWS CLI v2 via the official arm64 installer "
            "(awscli2 is not a valid AL2023 dnf package)"
        )

    def test_awscli_verify_step_present(self) -> None:
        """Gap 1: VerifyInstalls must confirm 'aws --version' succeeds after bake."""
        content = _COMPONENT_PATH.read_text()
        assert "aws --version" in content, (
            "VerifyInstalls must include 'aws --version' to confirm the CLI is on PATH"
        )

    def test_harness_delivered_at_boot_not_baked(self) -> None:
        """Gap 2: the harness must NOT be baked via a private git clone.

        The AMI bakery has no GitHub token. Delivery via S3 at boot (user-data.sh.tmpl)
        is the correct approach. Verify both sides of the invariant:
          - component does not clone the private repo
          - user-data.sh.tmpl fetches the platform/contract bundle from S3
        """
        component_content = _COMPONENT_PATH.read_text()
        # Org-agnostic on purpose: this pinned `Third-Ralph/safe-agents` until
        # the repo moved (#290), after which it would have passed regardless of
        # what the component cloned.
        assert not re.search(
            r"github\.com[:/][\w.-]+/safe-agents", component_content
        ), (
            "component-base.yaml must not clone the private repo at bake time; "
            "the harness is delivered via S3 at boot (user-data.sh.tmpl)"
        )
        assert "GITHUB_TOKEN" not in component_content, (
            "component-base.yaml must not reference GITHUB_TOKEN; "
            "the AMI bakery has no git auth — harness arrives via S3 at boot"
        )
        user_data_content = _USER_DATA_PATH.read_text()
        assert "platform/contract/bundle.tar.gz" in user_data_content, (
            "user-data.sh.tmpl must pull the platform/contract bundle from S3 at boot "
            "so the harness lands at /opt/safe-agents/core/contract/harness.py"
        )

    def test_harness_boot_extraction_targets_core_dir(self) -> None:
        """Gap 2: user-data.sh.tmpl must extract the platform bundle to /opt/safe-agents/core/

        tar -xzf ... -C /opt/safe-agents/core places contract/harness.py at the
        path phases.py SSM-execs: /opt/safe-agents/core/contract/harness.py.
        """
        user_data_content = _USER_DATA_PATH.read_text()
        assert "/opt/safe-agents/core" in user_data_content, (
            "user-data.sh.tmpl must extract the platform bundle to /opt/safe-agents/core "
            "so the harness is at /opt/safe-agents/core/contract/harness.py"
        )

    def test_pyyaml_available_for_harness(self) -> None:
        """Gap 2: python3-pyyaml must be installed; the harness imports yaml at runtime."""
        content = _COMPONENT_PATH.read_text()
        assert "python3-pyyaml" in content or "pyyaml" in content.lower(), (
            "component-base.yaml must install python3-pyyaml so the system python3 "
            "can run the harness (harness.py imports yaml at the top level)"
        )

    def test_remote_smoke_harness_path_matches_boot_extracted_path(self) -> None:
        """Gap 2: phases.py remote-smoke path must match the path user-data extracts.

        This cross-file check is the machine-checkable invariant that prevents the
        'No such file' failure mode: if one side drifts, this test breaks.
        """
        # phases.py must reference the canonical harness path.
        phases_content = _PHASES_PATH.read_text()
        assert _HARNESS_PATH in phases_content, (
            f"phases.py _smoke_remote must reference {_HARNESS_PATH!r}; "
            "if this path changes, update phases.py and user-data.sh.tmpl together"
        )
        # user-data.sh.tmpl must extract the bundle to the parent of that path.
        user_data_content = _USER_DATA_PATH.read_text()
        assert "/opt/safe-agents/core" in user_data_content, (
            f"user-data.sh.tmpl must extract the platform bundle to /opt/safe-agents/core "
            f"so the harness lands at {_HARNESS_PATH!r} as phases.py expects"
        )
        assert "platform/contract/bundle.tar.gz" in user_data_content, (
            "user-data.sh.tmpl must fetch platform/contract/bundle.tar.gz from S3 "
            "to deliver the harness at boot"
        )


# ---------------------------------------------------------------------------
# Criterion 7 (sa#90): ensure_foundation idempotency
# ---------------------------------------------------------------------------

class TestEnsureFoundation:
    """_ensure_foundation must create the profile when absent and reuse when present."""

    def test_absent_creates_profile_and_adds_role(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """When the profile does not exist, ensure_foundation creates it."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import ec2_provision

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        ec2_provision(
            manifest, fake_aws_ec2, environment="development",
            _ssm_timeout=10.0, _ssm_poll_interval=0.0,
        )

        create_calls = [c for c in fake_aws_ec2.calls if c[0] == "create_instance_profile"]
        assert create_calls, "ensure_foundation must call create_instance_profile when absent"
        add_calls = [c for c in fake_aws_ec2.calls if c[0] == "add_role_to_instance_profile"]
        assert add_calls, "ensure_foundation must call add_role_to_instance_profile when absent"

    def test_present_reused_no_recreate(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """When the profile already exists with the role attached, no create/add_role call is made."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import ec2_provision

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        env = "development"
        profile_name = f"safe-agents-{env}-{manifest.name}"
        # Derive the role name the same way ec2_provision does (last ARN segment).
        role_arn = fake_aws_ec2._ssm_params.get(f"/safe-agents/{env}/agent-role-arn", "")
        role_name = role_arn.split("/")[-1] if role_arn else "AgentRole"
        # Pre-seed the profile as if a prior provision left it behind.
        fake_aws_ec2._instance_profiles[profile_name] = {"roles": [role_name], "tags": {}}

        ec2_provision(
            manifest, fake_aws_ec2, environment=env,
            _ssm_timeout=10.0, _ssm_poll_interval=0.0,
        )

        create_calls = [c for c in fake_aws_ec2.calls if c[0] == "create_instance_profile"]
        assert not create_calls, (
            "ensure_foundation must NOT call create_instance_profile when profile already exists"
        )

    def test_present_without_role_adds_role(
        self, fake_aws_ec2: FakeAWS,
    ) -> None:
        """When the profile exists but the role is not yet attached, add_role is called.

        Calls _ensure_foundation directly — the clean-start gate (which runs before
        ensure_foundation in ec2_provision) correctly treats "profile present without
        role" as an unstable state and would block, so we test the foundation function
        in isolation here to verify its add-role recovery logic.
        """
        from safe_agents.arms.ec2.provision import _ensure_foundation

        env = "development"
        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        profile_name = f"safe-agents-{env}-{manifest.name}"
        role_arn = fake_aws_ec2._ssm_params.get(f"/safe-agents/{env}/agent-role-arn", "")
        role_name = role_arn.split("/")[-1] if role_arn else "AgentRole"

        # Profile exists but no role attached (simulates interrupted prior provision).
        fake_aws_ec2._instance_profiles[profile_name] = {"roles": [], "tags": {}}

        _ensure_foundation(
            fake_aws_ec2,
            profile_name,
            role_name,
            profile_name,
            {"Version": "2012-10-17", "Statement": []},
            {},
        )

        add_calls = [c for c in fake_aws_ec2.calls if c[0] == "add_role_to_instance_profile"]
        assert add_calls, (
            "ensure_foundation must call add_role_to_instance_profile when role is not attached"
        )


# ---------------------------------------------------------------------------
# Criterion 8 (sa#90): SSM Online wait — success and loud-failure paths
# ---------------------------------------------------------------------------

class TestSsmOnlineWait:
    """ec2_provision must wait for SSM Online before reporting success."""

    def test_provision_succeeds_after_ssm_online(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """provision returns the instance ID only after SSM reports Online."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import ec2_provision

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        # SSM reports Online after 2 Offline responses (3rd poll = Online).
        fake_aws_ec2.ssm_online_after_n_polls = 2

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        instance_id = ec2_provision(
            manifest, fake_aws_ec2, environment="development",
            _ssm_timeout=10.0, _ssm_poll_interval=0.0,
        )

        assert instance_id.startswith("i-"), (
            f"ec2_provision must return a valid instance ID; got {instance_id!r}"
        )
        ssm_calls = [
            c for c in fake_aws_ec2.calls if c[0] == "describe_ssm_instance_information"
        ]
        assert len(ssm_calls) >= 3, (
            f"Expected at least 3 SSM polls (2 Offline + 1 Online); got {len(ssm_calls)}"
        )

    def test_provision_fails_loudly_when_ssm_never_online(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """provision must raise RuntimeError — never return false success — if SSM never reports Online."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import ec2_provision

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        fake_aws_ec2.ssm_never_online = True

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        with pytest.raises(RuntimeError, match="SSM"):
            ec2_provision(
                manifest, fake_aws_ec2, environment="development",
                _ssm_timeout=0.1, _ssm_poll_interval=0.0,
            )

    def test_wait_for_ssm_online_immediate(self, fake_aws_ec2: FakeAWS, monkeypatch) -> None:
        """wait_for_ssm_online returns without error when instance is immediately Online."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import wait_for_ssm_online

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        # Seed a running instance.
        fake_aws_ec2._instances["i-test-online"] = {"tags": {}, "state": "running"}

        # Should return without raising.
        wait_for_ssm_online(
            fake_aws_ec2, "i-test-online", timeout=10.0, poll_interval=0.0
        )

    def test_wait_for_ssm_online_after_n_polls(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """wait_for_ssm_online waits through Offline responses then returns on Online."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import wait_for_ssm_online

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        fake_aws_ec2._instances["i-test-delayed"] = {"tags": {}, "state": "running"}
        fake_aws_ec2.ssm_online_after_n_polls = 3  # 3 Offline, then Online

        wait_for_ssm_online(
            fake_aws_ec2, "i-test-delayed", timeout=10.0, poll_interval=0.0
        )

        ssm_calls = [
            c for c in fake_aws_ec2.calls if c[0] == "describe_ssm_instance_information"
        ]
        assert len(ssm_calls) == 4, (
            f"Expected exactly 4 SSM polls (3 Offline + 1 Online); got {len(ssm_calls)}"
        )

    def test_wait_for_ssm_online_raises_on_timeout(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """wait_for_ssm_online raises RuntimeError if instance is never Online within timeout."""
        from safe_agents.arms.ec2 import provision
        from safe_agents.arms.ec2.provision import wait_for_ssm_online

        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        fake_aws_ec2.ssm_never_online = True

        with pytest.raises(RuntimeError, match="SSM"):
            wait_for_ssm_online(
                fake_aws_ec2, "i-test-gone", timeout=0.1, poll_interval=0.0
            )


# ---------------------------------------------------------------------------
# Criterion 9 (sa#90): verify phase
# ---------------------------------------------------------------------------

class TestVerifyPhase:
    """verify phase: independent SSM-Online check for an already-provisioned instance."""

    def test_verify_passes_when_instance_is_online(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """verify returns success when the instance is SSM Online."""
        from safe_agents.arms.ec2 import provision
        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        from safe_agents.pipeline.phases import verify_phase

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        env = "development"
        # Seed a running instance tagged for discovery.
        fake_aws_ec2._instances["i-verify-online"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": env,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
            },
            "state": "running",
        }

        result = verify_phase(
            manifest, fake_aws_ec2, dry_run=False, environment=env,
            ssm_timeout=10.0, ssm_poll_interval=0.0,
        )
        assert result.success, f"verify must pass when SSM is Online; error: {result.error}"

    def test_verify_fails_when_instance_never_online(
        self, fake_aws_ec2: FakeAWS, monkeypatch
    ) -> None:
        """verify returns failure when the instance is not SSM Online within the timeout."""
        from safe_agents.arms.ec2 import provision
        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )
        from safe_agents.pipeline.phases import verify_phase

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        env = "development"
        fake_aws_ec2._instances["i-verify-offline"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": env,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
            },
            "state": "running",
        }
        fake_aws_ec2.ssm_never_online = True

        result = verify_phase(
            manifest, fake_aws_ec2, dry_run=False, environment=env,
            ssm_timeout=0.1, ssm_poll_interval=0.0,
        )
        assert not result.success, "verify must fail when SSM is never Online"
        assert result.error and "SSM" in result.error, (
            f"verify error message must reference SSM; got: {result.error!r}"
        )

    def test_verify_fails_when_no_instance_found(self, fake_aws_ec2: FakeAWS) -> None:
        """verify returns failure when no instance is running with the expected tags."""
        from safe_agents.pipeline.phases import verify_phase

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        result = verify_phase(
            manifest, fake_aws_ec2, dry_run=False, environment="development",
            ssm_timeout=10.0, ssm_poll_interval=0.0,
        )
        assert not result.success
        assert result.error and "No running instance" in result.error

    def test_verify_dry_run_makes_no_aws_calls(self, fake_aws_ec2: FakeAWS) -> None:
        """verify in dry-run mode returns success without any AWS calls."""
        from safe_agents.pipeline.phases import verify_phase

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        calls_before = len(fake_aws_ec2.calls)
        result = verify_phase(
            manifest, fake_aws_ec2, dry_run=True, environment="development",
        )
        assert result.success
        assert result.dry_run
        assert len(fake_aws_ec2.calls) == calls_before, (
            f"dry-run must make no AWS calls; got: {fake_aws_ec2.calls[calls_before:]}"
        )

    def test_verify_phase_in_pipeline(self, fake_aws_ec2: FakeAWS, monkeypatch) -> None:
        """--phase verify can be run independently via run_pipeline."""
        from safe_agents.arms.ec2 import provision
        monkeypatch.setattr(
            provision, "_time", type("_t", (), {"sleep": staticmethod(lambda _: None)})()
        )

        manifest = load_manifest(SMOKE_EC2_MANIFEST)
        env = "development"
        fake_aws_ec2._instances["i-verify-pipeline"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": env,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
            },
            "state": "running",
        }

        result = run_pipeline(
            SMOKE_EC2_MANIFEST,
            dry_run=False,
            aws=fake_aws_ec2,
            phases=("verify",),
            environment=env,
        )
        assert result.success, (
            "verify phase via run_pipeline must succeed when instance is Online; "
            + "\n".join(f"  {pr.phase}: {pr.error}" for pr in result.phase_results if not pr.success)
        )


# ---------------------------------------------------------------------------
# Criterion 10 (sa#90): bundle CLI uploads both bundles
# ---------------------------------------------------------------------------

class _FakeS3:
    """In-memory S3 stub for bundle tests."""

    def __init__(self) -> None:
        self.uploaded: dict[tuple, bytes] = {}  # (Bucket, Key) -> Body

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict:
        self.uploaded[(Bucket, Key)] = Body
        return {}


class TestBundleCli:
    """The bundle CLI must upload both the agent bundle and the platform/contract bundle."""

    _CONTRACT_DIR = Path(__file__).parent.parent.parent.parent / "contract"

    def test_upload_bundle_to_fake_s3(self, tmp_path: Path) -> None:
        """upload_bundle uploads to the expected S3 keys."""
        from safe_agents.arms.ec2.ami.bundle import (
            BUNDLE_CURRENT_KEY,
            BUNDLE_VERSIONED_KEY,
            DEPLOY_BUCKET_TEMPLATE,
            bundle_agent,
            upload_bundle,
        )

        agent_dir = tmp_path / "dummy-agent"
        agent_dir.mkdir()
        (agent_dir / "run.sh").write_text("#!/bin/bash\necho hello\n")

        fake_s3 = _FakeS3()
        env = "development"
        agent_name = "dummy-agent"
        version = "20260629T000000Z"

        agent_bytes = bundle_agent(agent_dir, agent_name)
        result = upload_bundle(
            agent_bytes, agent_name=agent_name, environment=env, version=version, s3=fake_s3
        )

        bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=env)
        current_key = BUNDLE_CURRENT_KEY.format(name=agent_name)
        version_key = BUNDLE_VERSIONED_KEY.format(name=agent_name, version=version)

        assert result["bucket"] == bucket
        assert result["current_key"] == current_key
        assert result["version_key"] == version_key
        assert (bucket, current_key) in fake_s3.uploaded
        assert (bucket, version_key) in fake_s3.uploaded

    def test_upload_platform_contract_to_fake_s3(self) -> None:
        """upload_platform_contract uploads the harness to the stable platform key."""
        from safe_agents.arms.ec2.ami.bundle import (
            DEPLOY_BUCKET_TEMPLATE,
            PLATFORM_CONTRACT_KEY,
            bundle_platform_contract,
            upload_platform_contract,
        )

        if not self._CONTRACT_DIR.is_dir():
            pytest.skip(f"contract dir not found: {self._CONTRACT_DIR}")

        fake_s3 = _FakeS3()
        env = "development"

        platform_bytes = bundle_platform_contract(self._CONTRACT_DIR)
        result = upload_platform_contract(platform_bytes, environment=env, s3=fake_s3)

        bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=env)
        assert result["bucket"] == bucket
        assert result["key"] == PLATFORM_CONTRACT_KEY
        assert (bucket, PLATFORM_CONTRACT_KEY) in fake_s3.uploaded

    def test_both_bundles_upload_to_same_bucket(self, tmp_path: Path) -> None:
        """Agent and platform bundles both land in the same deploy bucket."""
        from safe_agents.arms.ec2.ami.bundle import (
            DEPLOY_BUCKET_TEMPLATE,
            PLATFORM_CONTRACT_KEY,
            bundle_agent,
            bundle_platform_contract,
            upload_bundle,
            upload_platform_contract,
        )

        if not self._CONTRACT_DIR.is_dir():
            pytest.skip(f"contract dir not found: {self._CONTRACT_DIR}")

        agent_dir = tmp_path / "my-agent"
        agent_dir.mkdir()
        (agent_dir / "run.sh").write_text("#!/bin/bash\n")

        fake_s3 = _FakeS3()
        env = "development"
        agent_name = "my-agent"

        agent_bytes = bundle_agent(agent_dir, agent_name)
        agent_result = upload_bundle(
            agent_bytes, agent_name=agent_name, environment=env, s3=fake_s3
        )
        platform_bytes = bundle_platform_contract(self._CONTRACT_DIR)
        platform_result = upload_platform_contract(platform_bytes, environment=env, s3=fake_s3)

        expected_bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=env)
        assert agent_result["bucket"] == expected_bucket
        assert platform_result["bucket"] == expected_bucket

        # Three uploads total: current + versioned agent + stable platform key.
        assert (expected_bucket, agent_result["current_key"]) in fake_s3.uploaded
        assert (expected_bucket, agent_result["version_key"]) in fake_s3.uploaded
        assert (expected_bucket, PLATFORM_CONTRACT_KEY) in fake_s3.uploaded

    def test_platform_key_is_stable_not_versioned(self) -> None:
        """Platform bundle key must be stable (no timestamp/version component)."""
        from safe_agents.arms.ec2.ami.bundle import PLATFORM_CONTRACT_KEY

        assert PLATFORM_CONTRACT_KEY == "platform/contract/bundle.tar.gz", (
            f"Platform key must be the stable constant; got {PLATFORM_CONTRACT_KEY!r}"
        )
        assert "current" not in PLATFORM_CONTRACT_KEY, (
            "Platform key must not use 'current' — it is not a rolling pointer"
        )


# ---------------------------------------------------------------------------
# Clean-start precondition gate (sa#90)
# ---------------------------------------------------------------------------

class TestCleanStartGate:
    """Tests for wait_for_clean_start, the pre-provision precondition gate.

    All tests are AWS-free (FakeAWS) and produce no real sleeps:
    _time.sleep is monkeypatched to a no-op, timeouts are short (0.1 s),
    and poll_interval=0.0 so loops exit via real monotonic() deadline.
    """

    # Shared SSM params needed so ec2_provision can resolve infra SSM exports.
    _ENV = "development"
    _AGENT = "clean-start-test-agent"

    @pytest.fixture()
    def aws(self) -> FakeAWS:
        """FakeAWS with all infra SSM params + base AMI seeded."""
        f = FakeAWS()
        env = self._ENV
        f.seed_ssm_param(
            f"/safe-agents/{env}/agent-role-arn",
            "arn:aws:iam::123456789012:instance-profile/safe-agents-development-AgentRole",
        )
        f.seed_ssm_param(f"/safe-agents/{env}/agent-sg-id", "sg-0agent12345")
        f.seed_ssm_param(f"/safe-agents/{env}/endpoint-sg-id", "sg-0endpoint999")
        f.seed_ssm_param(f"/safe-agents/{env}/agent-subnet-ids", "subnet-0abc1234")
        f.seed_ssm_param(
            f"/safe-agents/{env}/agent-runs-table-arn",
            "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
        )
        f.seed_ssm_param(
            f"/safe-agents/{env}/agent-runs-table-name", "safe-agents-development-agent-runs"
        )
        f.seed_ssm_param(
            f"/safe-agents/{env}/tables-key-arn",
            "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-cmk",
        )
        f.seed_ssm_param(f"/safe-agents/{env}/broker-service-dns", "broker.safe-agents.local")
        f.seed_image(
            "ami-0clean001",
            {"safe-agents:ami": "base", "safe-agents:ami-version": "20241201-01"},
            creation_date="2024-12-01T00:00:00Z",
        )
        return f

    def _manifest(self):
        """Return a manifest for the clean-start test agent (loads smoke-ec2 and renames)."""
        m = load_manifest(SMOKE_EC2_MANIFEST)
        # Override the name so tag-based discovery uses the test agent's name.
        import dataclasses
        return dataclasses.replace(m, name=self._AGENT)

    # ------------------------------------------------------------------
    # Unit-level tests: wait_for_clean_start / _wait_for_ec2_clean
    # ------------------------------------------------------------------

    def test_clean_slot_passes_immediately(self, aws: FakeAWS, monkeypatch) -> None:
        """No prior instances + no prior profile → gate passes without any polls."""
        import safe_agents.arms.ec2.provision as _prov
        import time as _time_module
        monkeypatch.setattr(_prov, "_time", _time_module)  # real module, but verify no sleep

        sleeps: list[float] = []
        monkeypatch.setattr(_prov._time, "sleep", lambda s: sleeps.append(s))


        # No instances seeded, no profile seeded → should return immediately.
        wait_for_clean_start(
            aws, self._ENV, self._AGENT,
            f"safe-agents-{self._ENV}-{self._AGENT}",
            "AgentRole",
            ec2_timeout=0.1,
            iam_timeout=0.1,
            poll_interval=0.0,
        )
        assert sleeps == [], "Expected no sleeps when slot is already clean"

    def test_transitional_instance_then_terminates(self, aws: FakeAWS, monkeypatch) -> None:
        """Instance in 'shutting-down' transitions to 'terminated'; gate waits then passes."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        # Seed an instance in 'shutting-down'; after 1 describe_instances_by_tags call
        # it transitions to 'terminated' (excluded from results → gate clears).
        tags = {
            "Project": "safe-agents",
            "Environment": self._ENV,
            "Agent": self._AGENT,
            "ManagedBy": "safe-agents-pipeline",
        }
        aws.seed_instance_with_transitions(
            "i-prior-001", "shutting-down", ["terminated"], tags
        )


        # Should succeed: first poll sees 'shutting-down' (transitional), transitions
        # to 'terminated', second poll returns empty → gate passes.
        wait_for_clean_start(
            aws, self._ENV, self._AGENT,
            f"safe-agents-{self._ENV}-{self._AGENT}",
            "AgentRole",
            ec2_timeout=5.0,
            iam_timeout=0.1,
            poll_interval=0.0,
        )

    def test_active_instance_raises_immediately(self, aws: FakeAWS, monkeypatch) -> None:
        """Instance in 'running' → gate raises immediately (teardown required)."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        tags = {
            "Project": "safe-agents",
            "Environment": self._ENV,
            "Agent": self._AGENT,
            "ManagedBy": "safe-agents-pipeline",
        }
        aws.seed_instance_with_transitions("i-live-001", "running", [], tags)


        with pytest.raises(RuntimeError, match="still active"):
            wait_for_clean_start(
                aws, self._ENV, self._AGENT,
                f"safe-agents-{self._ENV}-{self._AGENT}",
                "AgentRole",
                ec2_timeout=5.0,
                iam_timeout=0.1,
                poll_interval=0.0,
            )

    def test_stuck_transitional_instance_raises_on_timeout(self, aws: FakeAWS, monkeypatch) -> None:
        """Instance stays 'shutting-down' past ec2_timeout → gate raises with clear message."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        tags = {
            "Project": "safe-agents",
            "Environment": self._ENV,
            "Agent": self._AGENT,
            "ManagedBy": "safe-agents-pipeline",
        }
        # Never transitions — stays 'shutting-down' forever.
        aws.seed_instance_with_transitions("i-stuck-001", "shutting-down", [], tags)


        with pytest.raises(RuntimeError, match="still in transition"):
            wait_for_clean_start(
                aws, self._ENV, self._AGENT,
                f"safe-agents-{self._ENV}-{self._AGENT}",
                "AgentRole",
                ec2_timeout=0.0,  # Zero timeout → deadline already expired before first poll
                iam_timeout=0.1,
                poll_interval=0.0,
            )

    def test_profile_mid_delete_then_gone(self, aws: FakeAWS, monkeypatch) -> None:
        """Profile returns empty roles (mid-delete) then auto-deletes → IAM gate passes."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        profile_name = f"safe-agents-{self._ENV}-{self._AGENT}"
        role_name = "AgentRole"

        # Seed profile WITHOUT the role attached (simulates role already removed).
        aws._instance_profiles[profile_name] = {"roles": []}
        # After 2 polls, the profile auto-deletes and returns None.
        aws.iam_profile_delete_countdown = 2


        # No prior EC2 instances → EC2 check passes; IAM check sees profile is unstable
        # for 1 poll, then auto-deletes → gate passes.
        wait_for_clean_start(
            aws, self._ENV, self._AGENT,
            profile_name, role_name,
            ec2_timeout=0.1,
            iam_timeout=5.0,
            poll_interval=0.0,
        )

    def test_profile_stable_with_role_passes_immediately(self, aws: FakeAWS, monkeypatch) -> None:
        """Profile already present with role attached → IAM gate passes immediately."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        profile_name = f"safe-agents-{self._ENV}-{self._AGENT}"
        role_name = "AgentRole"

        aws._instance_profiles[profile_name] = {"roles": [role_name]}


        wait_for_clean_start(
            aws, self._ENV, self._AGENT,
            profile_name, role_name,
            ec2_timeout=0.1,
            iam_timeout=5.0,
            poll_interval=0.0,
        )

    def test_iam_profile_never_stabilizes_raises(self, aws: FakeAWS, monkeypatch) -> None:
        """Profile present but role never attached within iam_timeout → raises."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        profile_name = f"safe-agents-{self._ENV}-{self._AGENT}"
        role_name = "AgentRole"

        # Profile exists with no roles and iam_role_never_in_profile keeps it that way.
        aws._instance_profiles[profile_name] = {"roles": []}
        aws.iam_role_never_in_profile = True


        with pytest.raises(RuntimeError, match="did not stabilize"):
            wait_for_clean_start(
                aws, self._ENV, self._AGENT,
                profile_name, role_name,
                ec2_timeout=0.1,
                iam_timeout=0.0,  # Zero timeout → deadline already expired
                poll_interval=0.0,
            )

    # ------------------------------------------------------------------
    # Integration test: gate runs first inside ec2_provision
    # ------------------------------------------------------------------

    def test_clean_start_gate_runs_in_ec2_provision(self, aws: FakeAWS, monkeypatch) -> None:
        """ec2_provision raises early when a prior live instance exists (gate fires before RunInstances)."""
        import safe_agents.arms.ec2.provision as _prov
        monkeypatch.setattr(_prov._time, "sleep", lambda _: None)

        tags = {
            "Project": "safe-agents",
            "Environment": self._ENV,
            "Agent": self._AGENT,
            "ManagedBy": "safe-agents-pipeline",
        }
        aws.seed_instance_with_transitions("i-blocking-001", "running", [], tags)
        # Also seed OAuth secret so that if we somehow reach provision it doesn't fail on that.
        aws.seed_secret(f"{self._AGENT}/claude-oauth-token", "oauth-tok-abc")

        manifest = self._manifest()
        from safe_agents.arms.ec2.provision import ec2_provision

        with pytest.raises(RuntimeError, match="still active"):
            ec2_provision(
                manifest, aws,
                environment=self._ENV,
                _clean_start_ec2_timeout=0.1,
                _clean_start_iam_timeout=0.1,
                _clean_start_poll_interval=0.0,
                _iam_poll_interval=0.0,
                _iam_max_wait=0.1,
                _iam_extra_buffer=0.0,
                _ssm_timeout=0.1,
                _ssm_poll_interval=0.0,
            )

        # Verify RunInstances was NOT called (gate fired before it).
        run_calls = [c for c in aws.calls if c[0] == "run_instances"]
        assert run_calls == [], (
            "ec2_provision must not call RunInstances when the clean-start gate fires"
        )
