"""
Fargate arm tests — acceptance criteria for sa#36 (C2b).

All tests are AWS-free: AWS calls go through FakeAWS (no live boto3 needed).
Mirrors safe_agents/arms/ec2/tests/test_ec2_arm.py.

Acceptance criteria:

  1. fargate_provision creates the three per-agent roles + task def + schedule,
     all tagged with the standard arm set (Arm=fargate).

  2. The taskRole carries ONLY the arm extensions (run-record PutItem + the
     agent's own oauth-token GetSecretValue) — the no-connector-creds invariant:
     NO statement Resource matches the broker connector-keys pattern */connectors/*.

  3. The task-def container env EXACTLY matches the runner contract
     (SA_BROKER_DNS / SA_MODEL_PROXY_PORT / SA_TOOL_API_PORT / AGENT_RUNS_TABLE /
     AGENT_NAME / RUN_ID / AWS_DEFAULT_REGION) and injects CLAUDE_CODE_OAUTH_TOKEN
     from the agent's Secrets Manager oauth-token (by name).

  4. The schedule targets ECS RunTask in the ISOLATED agent subnets + agentSG,
     public IP DISABLED, cluster from the infra export.

  5. fargate_teardown removes the schedule, deregisters every task-def revision,
     and deletes all three roles; idempotent (second call = clean no-op).

  6. Pipeline dry-run for agents/smoke-fargate.yaml shows fargate
     provision→deploy→smoke in order, with no AWS calls.

  7. The live (FakeAWS) provision path through provision_phase succeeds.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

# core/ is on sys.path via conftest.py
from safe_agents.arms.fargate.provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    DEFAULT_CPU,
    DEFAULT_MEMORY,
    NETWORK_MODE_KEY,
    SA_MODEL_PROXY_PORT,
    SA_TOOL_API_PORT,
    _create_schedule_with_iam_retry,
    _fargate_resource_names,
    _oauth_secret_name,
    _resolve_network_mode,
    agent_role_extensions,
    build_container_environment,
    fargate_provision,
    fargate_run_once,
    fargate_teardown,
)
from safe_agents.pipeline import FakeAWS, load_manifest, run_pipeline
from safe_agents.pipeline.manifest import Schedule
from safe_agents.pipeline.phases import provision_phase, teardown_phase

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_FARGATE_MANIFEST = AGENTS_DIR / "smoke-fargate.yaml"
RUN_SH = Path(__file__).parent.parent / "run.sh"

ENV = "development"
AGENT = "smoke-fargate"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_aws_fargate() -> FakeAWS:
    """FakeAWS seeded with the infra SSM exports + secrets smoke-fargate.yaml needs."""
    aws = FakeAWS()
    # Secrets the deploy phase reads
    aws.seed_secret("smoke-fargate/runner-keys", "{}")
    aws.seed_secret("smoke-fargate/broker-keys", '{"KEY": "val"}')
    aws.seed_secret("smoke-fargate/claude-oauth-token", "oauth-tok-smoke")
    # SSM infra exports (published by infra/ foundation stacks)
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/cluster-arn",
        "arn:aws:ecs:us-east-1:123456789012:cluster/safe-agents-development",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/broker-service-dns", "broker.safe-agents.local")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/agent-subnet-ids", "subnet-0abc1234,subnet-0def5678")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-name", "safe-agents-development-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-arn",
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/ecr-agent-repo-uri",
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/safe-agents-development-agent",
    )
    return aws


@pytest.fixture()
def manifest():
    return load_manifest(SMOKE_FARGATE_MANIFEST)


# ---------------------------------------------------------------------------
# Criterion 1: resources created + tagged
# ---------------------------------------------------------------------------


class TestProvisionCreatesResources:
    def test_returns_summary_with_all_arns(self, fake_aws_fargate, manifest) -> None:
        summary = fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        for key in (
            "task_definition_arn",
            "task_role_arn",
            "execution_role_arn",
            "scheduler_role_arn",
            "schedule_arn",
            "family",
        ):
            assert summary[key], f"summary missing/empty key {key!r}: {summary}"

    def test_creates_three_roles(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        for role in (names["task_role"], names["exec_role"], names["scheduler_role"]):
            assert fake_aws_fargate.get_role(role) is not None, f"role {role!r} not created"

    def test_task_role_trust_is_ecs_tasks(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        trust = fake_aws_fargate.get_role(names["task_role"])["assume_role_policy"]
        principal = trust["Statement"][0]["Principal"]["Service"]
        assert principal == "ecs-tasks.amazonaws.com"

    def test_scheduler_role_trust_is_scheduler(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        trust = fake_aws_fargate.get_role(names["scheduler_role"])["assume_role_policy"]
        principal = trust["Statement"][0]["Principal"]["Service"]
        assert principal == "scheduler.amazonaws.com"

    def test_execution_role_has_managed_policy(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        attached = fake_aws_fargate.list_attached_role_policies(names["exec_role"])
        assert any("AmazonECSTaskExecutionRolePolicy" in p for p in attached), (
            f"execution role missing the ECS task-execution managed policy: {attached}"
        )

    def test_registers_task_definition(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        assert fake_aws_fargate.was_called("register_task_definition")
        assert len(fake_aws_fargate._ecs_task_definitions) == 1

    def test_creates_schedule(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        assert names["schedule"] in fake_aws_fargate._schedules

    def test_all_resources_tagged_arm_fargate(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        # roles
        for role in (names["task_role"], names["exec_role"], names["scheduler_role"]):
            tags = fake_aws_fargate._created_roles[role]["tags"]
            assert tags["Arm"] == "fargate"
            assert tags["Project"] == "safe-agents"
            assert tags["Agent"] == AGENT
            assert tags["Environment"] == ENV
        # task def
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        assert td["tags"]["Arm"] == "fargate"
        # schedule
        assert fake_aws_fargate._schedules[names["schedule"]]["tags"]["Arm"] == "fargate"

    def test_task_def_is_arm64_and_awsvpc(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        assert td["cpu"] == DEFAULT_CPU == "256"
        assert td["memory"] == DEFAULT_MEMORY == "512"
        assert td["runtime_platform"]["cpuArchitecture"] == "ARM64"
        assert td["network_mode"] == "awsvpc"

    def test_task_def_image_from_ecr_export(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        assert td["image"].endswith("/safe-agents-development-agent:latest")

    def test_image_uri_override(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(
            manifest, fake_aws_fargate, environment=ENV, image_uri="my.repo/x:abc123"
        )
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        assert td["image"] == "my.repo/x:abc123"

    def test_schedule_expression_and_timezone_are_parameters(
        self, fake_aws_fargate, manifest
    ) -> None:
        fargate_provision(
            manifest,
            fake_aws_fargate,
            environment=ENV,
            schedule_expression="cron(0 9 * * ? *)",
            timezone="America/New_York",
        )
        names = _fargate_resource_names(ENV, AGENT)
        sched = fake_aws_fargate._schedules[names["schedule"]]
        assert sched["schedule_expression"] == "cron(0 9 * * ? *)"
        assert sched["timezone"] == "America/New_York"

    def test_schedule_defaults_to_disabled(self, fake_aws_fargate, manifest) -> None:
        """sa#115: with no state kwarg, fargate_provision's own default (DISABLED)
        applies — a provision must never enable a production schedule before its
        first manual proof."""
        summary = fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        assert fake_aws_fargate._schedules[names["schedule"]]["state"] == "DISABLED"
        assert summary["schedule_state"] == "DISABLED"

    def test_schedule_state_enabled_override(self, fake_aws_fargate, manifest) -> None:
        """A caller can explicitly opt into ENABLED (post-proof)."""
        summary = fargate_provision(
            manifest, fake_aws_fargate, environment=ENV, state="ENABLED"
        )
        names = _fargate_resource_names(ENV, AGENT)
        assert fake_aws_fargate._schedules[names["schedule"]]["state"] == "ENABLED"
        assert summary["schedule_state"] == "ENABLED"


# ---------------------------------------------------------------------------
# Criterion 2: two-identity invariant (no connector creds on the taskRole)
# ---------------------------------------------------------------------------


class TestNoConnectorCredsInvariant:
    def test_task_role_has_no_connector_path(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        policy = fake_aws_fargate._role_policies[(names["task_role"], names["task_role"])]
        for stmt in policy["Statement"]:
            resources = stmt["Resource"]
            resources = resources if isinstance(resources, list) else [resources]
            for r in resources:
                assert "/connectors/" not in r, (
                    f"taskRole statement {stmt['Sid']!r} grants the broker connector path "
                    f"{r!r} — violates the two-identity split"
                )

    def test_extensions_grant_runrecord_and_oauth_only(self) -> None:
        stmts = agent_role_extensions(
            AGENT, ENV, "arn:aws:dynamodb:::table/x", _oauth_secret_name(ENV, AGENT),
            "arn:aws:kms:::key/tables",
        )
        sids = {s["Sid"] for s in stmts}
        assert any(sid.startswith("RunRecord") for sid in sids)
        assert "OauthToken" in sids
        assert "RunRecordKey" in sids  # KMS for the CMK-encrypted run-record table
        # run-record + its CMK data-key + oauth — the minimal rights, nothing more.
        assert len(stmts) == 3, f"taskRole must carry exactly 3 statements, got {sids}"
        # the KMS grant is scoped to the one tables key, not kms:* on all keys.
        kms = next(s for s in stmts if s["Sid"] == "RunRecordKey")
        assert kms["Resource"] == "arn:aws:kms:::key/tables"
        assert "*" not in kms["Resource"]
        # no statement grants any connector authority.
        assert all("connectors" not in str(s.get("Resource", "")) for s in stmts)

    def test_oauth_resource_does_not_match_connector_pattern(self) -> None:
        stmts = agent_role_extensions(
            AGENT, ENV, "arn:aws:dynamodb:::table/x", _oauth_secret_name(ENV, AGENT),
            "arn:aws:kms:::key/tables",
        )
        oauth = next(s for s in stmts if s["Sid"] == "OauthToken")
        assert BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN.strip("*") not in oauth["Resource"]
        assert "/agents/" in oauth["Resource"]


# ---------------------------------------------------------------------------
# Criterion 3: container env contract + secret injection
# ---------------------------------------------------------------------------


class TestContainerEnvContract:
    def test_build_container_environment_exact_keys(self) -> None:
        env = build_container_environment(
            broker_service_dns="broker.safe-agents.local",
            agent_runs_table_name="safe-agents-development-agent-runs",
            agent_name=AGENT,
            region="us-east-1",
        )
        assert set(env.keys()) == {
            "SA_BROKER_DNS",
            "SA_MODEL_PROXY_PORT",
            "SA_TOOL_API_PORT",
            "AGENT_RUNS_TABLE",
            "AGENT_NAME",
            "RUN_ID",
            "AWS_DEFAULT_REGION",
        }

    def test_env_values(self) -> None:
        env = build_container_environment(
            broker_service_dns="broker.safe-agents.local",
            agent_runs_table_name="tbl",
            agent_name=AGENT,
            region="us-east-1",
        )
        assert env["SA_BROKER_DNS"] == "broker.safe-agents.local"
        assert env["SA_MODEL_PROXY_PORT"] == SA_MODEL_PROXY_PORT == "8443"
        assert env["SA_TOOL_API_PORT"] == SA_TOOL_API_PORT == "8080"
        assert env["AGENT_RUNS_TABLE"] == "tbl"
        assert env["AGENT_NAME"] == AGENT
        assert env["AWS_DEFAULT_REGION"] == "us-east-1"
        assert env["RUN_ID"]  # placeholder present

    def test_task_def_env_matches_contract(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        env = td["environment"]
        assert env["SA_BROKER_DNS"] == "broker.safe-agents.local"
        assert env["SA_MODEL_PROXY_PORT"] == "8443"
        assert env["SA_TOOL_API_PORT"] == "8080"
        assert env["AGENT_RUNS_TABLE"] == "safe-agents-development-agent-runs"
        assert env["AGENT_NAME"] == AGENT
        assert "RUN_ID" in env
        assert env["AWS_DEFAULT_REGION"] == "us-east-1"

    def test_oauth_token_injected_as_secret_not_env(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        td = next(iter(fake_aws_fargate._ecs_task_definitions.values()))
        # Must be a full Secrets Manager ARN (not a bare name) so ECS routes injection to
        # Secrets Manager + the execution role's GetSecretValue — a bare name is treated as
        # an SSM parameter and fails with ssm:GetParameters AccessDenied.
        secret_val = td["secrets"]["CLAUDE_CODE_OAUTH_TOKEN"]
        assert secret_val.startswith("arn:aws:secretsmanager:")
        assert secret_val.endswith(_oauth_secret_name(ENV, AGENT))
        # The raw token must never be a plain env var.
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in td["environment"]


# ---------------------------------------------------------------------------
# Criterion 4: schedule target topology
# ---------------------------------------------------------------------------


class TestScheduleTarget:
    def test_target_uses_isolated_subnets_sg_public_ip_disabled(
        self, fake_aws_fargate, manifest
    ) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        target = fake_aws_fargate._schedules[names["schedule"]]["target"]
        vpc = target["EcsParameters"]["NetworkConfiguration"]["awsvpcConfiguration"]
        assert vpc["Subnets"] == ["subnet-0abc1234", "subnet-0def5678"]
        assert vpc["SecurityGroups"] == ["sg-0agent12345"]
        assert vpc["AssignPublicIp"] == "DISABLED"

    def test_target_cluster_and_launch_type(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        target = fake_aws_fargate._schedules[names["schedule"]]["target"]
        assert target["Arn"].endswith("cluster/safe-agents-development")
        assert target["EcsParameters"]["LaunchType"] == "FARGATE"

    @pytest.mark.parametrize(
        "seeded_mode, expected",
        [
            (None, "DISABLED"),        # param absent → 'secure' default (backward compatible)
            ("secure", "DISABLED"),    # private subnets: no public IP
            ("open", "ENABLED"),       # public subnets, no NAT/endpoints: needs a public IP
        ],
    )
    def test_public_ip_follows_network_mode(
        self, fake_aws_fargate, manifest, seeded_mode, expected
    ) -> None:
        if seeded_mode is not None:
            fake_aws_fargate.seed_ssm_param(
                f"/safe-agents/{ENV}/{NETWORK_MODE_KEY}", seeded_mode
            )
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        vpc = fake_aws_fargate._schedules[names["schedule"]]["target"][
            "EcsParameters"
        ]["NetworkConfiguration"]["awsvpcConfiguration"]
        assert vpc["AssignPublicIp"] == expected


class TestNetworkModeResolution:
    """network-mode is read from the NetworkStack SSM export; absent → 'secure' (the
    backward-compatible floor). Only 'open' flips the task to a public IP."""

    def test_defaults_to_secure_when_absent(self, fake_aws_fargate) -> None:
        assert _resolve_network_mode(fake_aws_fargate, ENV) == "secure"

    @pytest.mark.parametrize("mode", ["secure", "open"])
    def test_reads_seeded_mode(self, fake_aws_fargate, mode) -> None:
        fake_aws_fargate.seed_ssm_param(f"/safe-agents/{ENV}/{NETWORK_MODE_KEY}", mode)
        assert _resolve_network_mode(fake_aws_fargate, ENV) == mode


# ---------------------------------------------------------------------------
# Criterion 5: teardown
# ---------------------------------------------------------------------------


class TestTeardown:
    def test_teardown_removes_everything(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        report = fargate_teardown(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)

        assert report["schedule_removed"] is True
        assert len(report["task_definitions_removed"]) == 1
        assert set(report["roles_removed"]) == {
            names["task_role"],
            names["exec_role"],
            names["scheduler_role"],
        }
        # nothing left behind
        assert names["schedule"] not in fake_aws_fargate._schedules
        assert fake_aws_fargate.list_task_definitions(names["family"]) == []
        for role in (names["task_role"], names["exec_role"], names["scheduler_role"]):
            assert fake_aws_fargate.get_role(role) is None

    def test_teardown_idempotent(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        fargate_teardown(manifest, fake_aws_fargate, environment=ENV)
        report2 = fargate_teardown(manifest, fake_aws_fargate, environment=ENV)
        names = _fargate_resource_names(ENV, AGENT)
        assert report2["schedule_removed"] is False
        assert report2["task_definitions_removed"] == []
        assert report2["roles_removed"] == []
        assert set(report2["roles_already_gone"]) == {
            names["task_role"],
            names["exec_role"],
            names["scheduler_role"],
        }

    def test_teardown_on_nothing_is_clean_noop(self, fake_aws_fargate, manifest) -> None:
        report = fargate_teardown(manifest, fake_aws_fargate, environment=ENV)
        assert report["schedule_removed"] is False
        assert report["roles_removed"] == []


# ---------------------------------------------------------------------------
# Criterion 6: pipeline dry-run
# ---------------------------------------------------------------------------


class TestPipelineDryRun:
    def test_three_phases_in_order(self, fake_aws_fargate) -> None:
        result = run_pipeline(
            SMOKE_FARGATE_MANIFEST, dry_run=True, aws=fake_aws_fargate
        )
        phases = [pr.phase for pr in result.phase_results]
        assert phases == ["provision", "deploy", "smoke"]
        assert result.success

    def test_provision_phase_mentions_fargate_ops(self, fake_aws_fargate) -> None:
        result = run_pipeline(
            SMOKE_FARGATE_MANIFEST, dry_run=True, aws=fake_aws_fargate
        )
        provision = next(pr for pr in result.phase_results if pr.phase == "provision")
        blob = " ".join(provision.steps).lower()
        assert "taskrole" in blob
        assert "eventbridge scheduler" in blob
        assert "awsvpc" in blob
        assert "disabled" in blob  # public IP disabled

    def test_dry_run_makes_no_aws_calls(self, fake_aws_fargate) -> None:
        run_pipeline(SMOKE_FARGATE_MANIFEST, dry_run=True, aws=fake_aws_fargate)
        assert fake_aws_fargate.calls == [], (
            f"Dry-run made unexpected AWS calls: {fake_aws_fargate.calls}"
        )


# ---------------------------------------------------------------------------
# Criterion 7: live (FakeAWS) provision + teardown through the phase layer
# ---------------------------------------------------------------------------


class TestPhaseLayerWiring:
    def test_provision_phase_live_succeeds(self, fake_aws_fargate, manifest) -> None:
        result = provision_phase(
            manifest, fake_aws_fargate, dry_run=False, environment=ENV
        )
        assert result.success, result.error
        assert fake_aws_fargate.was_called("register_task_definition")
        assert fake_aws_fargate.was_called("create_schedule")

    def test_teardown_phase_live_succeeds(self, fake_aws_fargate, manifest) -> None:
        provision_phase(manifest, fake_aws_fargate, dry_run=False, environment=ENV)
        result = teardown_phase(
            manifest, fake_aws_fargate, dry_run=False, environment=ENV
        )
        assert result.success, result.error

    def test_provision_phase_reads_manifest_schedule(self, fake_aws_fargate, manifest) -> None:
        """sa#115: provision_phase forwards manifest.schedule's expression/timezone/state
        through to fargate_provision (and on to aws.create_schedule)."""
        scheduled_manifest = dataclasses.replace(
            manifest,
            schedule=Schedule(
                expression="cron(0 9 * * ? *)",
                timezone="America/New_York",
                state="ENABLED",
            ),
        )
        result = provision_phase(
            scheduled_manifest, fake_aws_fargate, dry_run=False, environment=ENV
        )
        assert result.success, result.error
        names = _fargate_resource_names(ENV, AGENT)
        sched = fake_aws_fargate._schedules[names["schedule"]]
        assert sched["schedule_expression"] == "cron(0 9 * * ? *)"
        assert sched["timezone"] == "America/New_York"
        assert sched["state"] == "ENABLED"

    def test_provision_phase_defaults_disabled_when_manifest_has_no_schedule(
        self, fake_aws_fargate, manifest
    ) -> None:
        """sa#115: when manifest.schedule is None entirely, fargate_provision's own
        DISABLED default kicks in — DISABLED is the floor no matter what the manifest says."""
        assert manifest.schedule is None  # smoke-fargate.yaml declares no schedule block
        result = provision_phase(
            manifest, fake_aws_fargate, dry_run=False, environment=ENV
        )
        assert result.success, result.error
        names = _fargate_resource_names(ENV, AGENT)
        assert fake_aws_fargate._schedules[names["schedule"]]["state"] == "DISABLED"


# ---------------------------------------------------------------------------
# Capstone RunTask
# ---------------------------------------------------------------------------


class TestRunOnce:
    def test_run_once_launches_in_isolated_topology(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        task_arn = fargate_run_once(
            fake_aws_fargate, manifest, environment=ENV, run_id="capstone-1"
        )
        assert task_arn
        task = fake_aws_fargate._ecs_tasks[task_arn]
        assert task["assign_public_ip"] is False
        assert task["security_groups"] == ["sg-0agent12345"]
        assert task["subnets"] == ["subnet-0abc1234", "subnet-0def5678"]
        # RUN_ID overridden for this run
        override_env = task["overrides"]["containerOverrides"][0]["environment"]
        assert {"name": "RUN_ID", "value": "capstone-1"} in override_env

    @pytest.mark.parametrize(
        "seeded_mode, expected",
        [
            (None, False),       # param absent → 'secure' default
            ("secure", False),   # private subnets: no public IP
            ("open", True),      # public subnets: needs a public IP
        ],
    )
    def test_run_once_public_ip_follows_network_mode(
        self, fake_aws_fargate, manifest, seeded_mode, expected
    ) -> None:
        if seeded_mode is not None:
            fake_aws_fargate.seed_ssm_param(
                f"/safe-agents/{ENV}/{NETWORK_MODE_KEY}", seeded_mode
            )
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        task_arn = fargate_run_once(
            fake_aws_fargate, manifest, environment=ENV, run_id="capstone-mode"
        )
        assert fake_aws_fargate._ecs_tasks[task_arn]["assign_public_ip"] is expected

    def test_run_once_without_provision_raises(self, fake_aws_fargate, manifest) -> None:
        with pytest.raises(RuntimeError, match="no active task definition"):
            fargate_run_once(fake_aws_fargate, manifest, environment=ENV)

    def test_run_once_extra_env_lands_in_overrides(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        task_arn = fargate_run_once(
            fake_aws_fargate,
            manifest,
            environment=ENV,
            run_id="capstone-2",
            extra_env={"SA_SMOKE_TOOL": "alpaca", "SA_SMOKE_OP": "account"},
        )
        task = fake_aws_fargate._ecs_tasks[task_arn]
        override_env = task["overrides"]["containerOverrides"][0]["environment"]
        assert {"name": "SA_SMOKE_TOOL", "value": "alpaca"} in override_env
        assert {"name": "SA_SMOKE_OP", "value": "account"} in override_env
        assert {"name": "RUN_ID", "value": "capstone-2"} in override_env

    def test_run_once_extra_env_cannot_override_run_id(self, fake_aws_fargate, manifest) -> None:
        fargate_provision(manifest, fake_aws_fargate, environment=ENV)
        task_arn = fargate_run_once(
            fake_aws_fargate,
            manifest,
            environment=ENV,
            run_id="capstone-3",
            extra_env={"RUN_ID": "spoofed"},
        )
        task = fake_aws_fargate._ecs_tasks[task_arn]
        override_env = task["overrides"]["containerOverrides"][0]["environment"]
        # run_id owns RUN_ID: exactly one entry, and it is the run_id value.
        run_ids = [e["value"] for e in override_env if e["name"] == "RUN_ID"]
        assert run_ids == ["capstone-3"]


class TestRunShSmokeParameterization:
    """run.sh section (d) — the brokered-call proof is parameterized via SA_SMOKE_* env,
    with defaults that preserve the original github.whoami/login behavior, so a RunTask
    containerOverrides can point the proof at whatever action class is really granted."""

    def _content(self) -> str:
        return RUN_SH.read_text()

    def test_smoke_call_env_defaults(self) -> None:
        content = self._content()
        for line in (
            'SMOKE_TOOL="${SA_SMOKE_TOOL:-github}"',
            'SMOKE_OP="${SA_SMOKE_OP:-whoami}"',
            'SMOKE_ARGS_JSON="${SA_SMOKE_ARGS_JSON:-"{}"}"',
            'SMOKE_EXPECT="${SA_SMOKE_EXPECT:-login}"',
        ):
            assert line in content, f"run.sh must default the smoke-call knob: {line}"

    def test_call_body_uses_the_knobs(self) -> None:
        content = self._content()
        assert (
            '\\"tool\\":\\"${SMOKE_TOOL}\\",\\"op\\":\\"${SMOKE_OP}\\",\\"args\\":${SMOKE_ARGS_JSON}'
            in content
        ), "the /call body must be built from the SA_SMOKE_* knobs, not hardcoded"

    def test_expect_substring_asserted_alongside_allow(self) -> None:
        content = self._content()
        assert '"decision_kind"[[:space:]]*:[[:space:]]*"allow"' in content
        assert 'grep -qF -- "$SMOKE_EXPECT"' in content, (
            "the result assertion must check the SA_SMOKE_EXPECT substring"
        )

    def test_optional_knobs_documented_in_env_contract(self) -> None:
        header = "\n".join(self._content().splitlines()[:40])
        assert "OPTIONAL" in header
        for var in ("SA_SMOKE_TOOL", "SA_SMOKE_OP", "SA_SMOKE_ARGS_JSON", "SA_SMOKE_EXPECT"):
            assert var in header, f"header env contract must document {var}"


class TestSchedulerIamRaceRetry:
    """The scheduler role is created immediately before CreateSchedule; its trust policy
    can lag (IAM propagation). _create_schedule_with_iam_retry retries the race away."""

    def test_retries_then_succeeds(self, fake_aws_fargate) -> None:
        fake_aws_fargate.create_schedule_role_error_count = 2  # fail twice, then succeed
        arn = _create_schedule_with_iam_retry(
            fake_aws_fargate,
            backoff_base=0,  # no real sleeps in tests
            name="s",
            schedule_expression="rate(1 day)",
            timezone="UTC",
            target={"Arn": "x"},
            tags={},
        )
        assert arn  # succeeded after retrying past the propagation race
        assert fake_aws_fargate.create_schedule_role_error_count == 0

    def test_raises_after_max_attempts(self, fake_aws_fargate) -> None:
        fake_aws_fargate.create_schedule_role_error_count = 99  # never converges
        with pytest.raises(RuntimeError, match="propagation race"):
            _create_schedule_with_iam_retry(
                fake_aws_fargate,
                backoff_base=0,
                max_attempts=3,
                name="s",
                schedule_expression="rate(1 day)",
                timezone="UTC",
                target={"Arn": "x"},
                tags={},
            )

    def test_provision_survives_scheduler_race(self, fake_aws_fargate, manifest) -> None:
        # End-to-end: a couple of propagation errors don't fail the provision.
        fake_aws_fargate.create_schedule_role_error_count = 2
        summary = fargate_provision(
            manifest, fake_aws_fargate, environment=ENV,
            schedule_expression="rate(1 day)", timezone="UTC",
        )
        assert summary["schedule_arn"]
