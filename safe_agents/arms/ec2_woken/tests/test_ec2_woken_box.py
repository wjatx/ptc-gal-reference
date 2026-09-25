"""
ec2-woken BOX tests — acceptance criteria for sa#98 / sa#34 G9 (the woken drain-loop box).

Companion to test_ec2_woken_arm.py (which covers the airlock wake path). These tests cover the
BOX the airlock wakes: its confined provision, the NO-connector-creds invariant on its role, the
drain loop's pure message-parse + idle-exit logic, and the shell scripts' syntax.

All tests are AWS-free and network-free: read-side AWS goes through FakeAWS; run_instances kwargs
are captured via a thin spy; the drain logic is exercised as a pure module; the shell scripts are
syntax-checked with `bash -n`.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

# core/ is on sys.path via conftest.py
from safe_agents.arms.ec2_woken.box_provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    box_role_extensions,
    ec2_woken_box_provision,
    ec2_woken_box_teardown,
    render_box_user_data,
)
from safe_agents.broker.tests.platform_marks import requires_posix_bash
from safe_agents.pipeline import FakeAWS, load_manifest

# drain_logic is a box-side module (not on the package path); import it by file location.
_BOX_DIR = Path(__file__).parent.parent / "box"
sys.path.insert(0, str(_BOX_DIR))
import drain_logic  # noqa: E402

# ---------------------------------------------------------------------------
# Paths + constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent  # safe-agents/
SMOKE_WOKEN_MANIFEST = REPO_ROOT / "agents" / "smoke-woken.yaml"

ENV = "development"
AGENT = "smoke-woken"
REGION = "us-east-1"
ACCOUNT = "123456789012"
OAUTH_SECRET = "smoke-woken/claude-oauth-token"
DEPLOY_BUCKET = f"safe-agents-{ENV}-deploy"
BOX_PREFIX = f"ec2-woken/{AGENT}/box"

RUN_BROKERED = _BOX_DIR / "run-brokered.sh"
DRAIN = _BOX_DIR / "drain.sh"
EMIT_READY = _BOX_DIR / "emit-runner-ready.sh"


# ---------------------------------------------------------------------------
# Fakes / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_aws_box() -> FakeAWS:
    """FakeAWS seeded with the infra SSM exports + the base AMI + the oauth secret."""
    aws = FakeAWS()
    aws.seed_secret(OAUTH_SECRET, "PLAINTEXT-TOKEN-VALUE-xyz")
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-role-arn",
        f"arn:aws:iam::{ACCOUNT}:role/safe-agents-{ENV}-AgentRole",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/agent-sg-id", "sg-0agentisolated")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/endpoint-sg-id", "sg-0endpoint")
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-subnet-ids", "subnet-0agentiso1,subnet-0agentiso2"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-name", f"safe-agents-{ENV}-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/agent-runs-table-arn",
        f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/safe-agents-{ENV}-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{ENV}/tables-key-arn",
        f"arn:aws:kms:{REGION}:{ACCOUNT}:key/abcd-1234-cmk",
    )
    aws.seed_ssm_param(f"/safe-agents/{ENV}/broker-service-dns", "broker.safe-agents.local")
    aws.seed_ssm_param(f"/safe-agents/{ENV}/deploy-bucket-name", DEPLOY_BUCKET)
    aws.seed_image(
        "ami-0fakebaseami001",
        {"safe-agents:ami": "base", "safe-agents:ami-version": "20241201-01"},
    )
    return aws


@pytest.fixture()
def manifest():
    return load_manifest(SMOKE_WOKEN_MANIFEST)


def _capture_run_instances(aws: FakeAWS) -> dict:
    """Wrap aws.run_instances so the test can inspect the launch kwargs (subnet/SG/tags)."""
    captured: dict = {}
    original = aws.run_instances

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    aws.run_instances = spy  # type: ignore[method-assign]
    return captured


# ---------------------------------------------------------------------------
# Criterion 1: the box provision launches a CONFINED box (agent subnet + agent SG)
# ---------------------------------------------------------------------------

class TestBoxProvisionConfinement:
    def test_returns_instance_id(self, fake_aws_box, manifest) -> None:
        instance_id = ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        assert instance_id.startswith("i-")

    def test_launched_in_agent_subnet_and_sg(self, fake_aws_box, manifest) -> None:
        captured = _capture_run_instances(fake_aws_box)
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        # Topology confinement: the ISOLATED agent subnet + the agent SG (→ broker) + the endpoint
        # SG (→ AWS interface endpoints: SQS for the queue, Secrets Manager for the oauth token).
        assert captured["subnet_id"] == "subnet-0agentiso1"
        assert captured["security_group_ids"] == ["sg-0agentisolated", "sg-0endpoint"]

    def test_tags_arm_ec2_woken(self, fake_aws_box, manifest) -> None:
        captured = _capture_run_instances(fake_aws_box)
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        tags = captured["tags"]
        assert tags["Arm"] == "ec2-woken"
        assert tags["Project"] == "safe-agents"
        assert tags["Agent"] == AGENT

    def test_user_data_carries_the_env_contract(self, fake_aws_box, manifest) -> None:
        captured = _capture_run_instances(fake_aws_box)
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        import gzip  # noqa: PLC0415

        user_data = gzip.decompress(base64.b64decode(captured["user_data_b64"])).decode()
        # The queue url + broker dns + agent name reach the box via agent.env.
        assert "broker.safe-agents.local" in user_data
        assert f"safe-agents-{ENV}-{AGENT}-airlock-inbound" in user_data
        assert f"AGENT_NAME={AGENT}" in user_data
        # The oauth token is referenced by SECRET ID, never baked in as a plaintext value.
        assert f"SA_OAUTH_SECRET_ID={OAUTH_SECRET}" in user_data
        assert "PLAINTEXT-TOKEN-VALUE-xyz" not in user_data
        # The drain loop + unit are S3-delivered (copied down at boot), not embedded.
        assert f"s3://{DEPLOY_BUCKET}/{BOX_PREFIX}/bin/drain.sh" in user_data
        assert f"s3://{DEPLOY_BUCKET}/{BOX_PREFIX}/systemd/responsive-agent-ready.service" in user_data
        assert "systemctl enable --now responsive-agent-ready.service" in user_data

    def test_user_data_is_well_under_the_16kb_cap(self, fake_aws_box, manifest) -> None:
        # The live-provision bug: base64(gzip(user_data)) must fit EC2's 16384-byte cap. With the
        # assets moved to S3, the encoded user-data is tiny.
        captured = _capture_run_instances(fake_aws_box)
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        assert len(captured["user_data_b64"]) < 16384

    def test_box_assets_uploaded_to_deploy_bucket(self, fake_aws_box, manifest) -> None:
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        # Every drain-loop asset is staged under the per-agent prefix; content round-trips.
        staged = fake_aws_box._s3_buckets[DEPLOY_BUCKET]
        for name in ("run-brokered.sh", "drain.sh", "emit-runner-ready.sh", "drain_logic.py"):
            key = f"{BOX_PREFIX}/bin/{name}"
            assert fake_aws_box.was_called("put_object", DEPLOY_BUCKET, key)
            assert staged[key] == (_BOX_DIR / name).read_bytes()
        unit_key = f"{BOX_PREFIX}/systemd/responsive-agent-ready.service"
        assert unit_key in staged

    def test_image_id_override_skips_ami_lookup(self, fake_aws_box, manifest) -> None:
        captured = _capture_run_instances(fake_aws_box)
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION,
            image_id="ami-override", _iam_backoff_base=0,
        )
        assert captured["image_id"] == "ami-override"
        assert not fake_aws_box.was_called("describe_images")

    def test_missing_infra_export_raises(self, manifest) -> None:
        aws = FakeAWS()  # nothing seeded; broker-service-dns will be missing
        with pytest.raises(RuntimeError, match="SSM param"):
            ec2_woken_box_provision(aws=aws, manifest=manifest, environment=ENV, _iam_backoff_base=0)


# ---------------------------------------------------------------------------
# Criterion 2: the box role carries NO connector creds (two-identity invariant)
# ---------------------------------------------------------------------------

class TestBoxRoleHoldsNoConnectorCreds:
    """The load-bearing safety property: the box role grants exactly the drain rights and no
    connector authority. Asserted on the ACTUAL inline policy the provision attaches."""

    @pytest.fixture()
    def statements(self, fake_aws_box, manifest) -> list[dict]:
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        # The inline policy the provision put on the base agentRole for this box.
        policy_name = f"safe-agents-{ENV}-{AGENT}-woken-box"
        role_name = f"safe-agents-{ENV}-AgentRole"
        doc = fake_aws_box._role_policies[(role_name, policy_name)]
        return doc["Statement"]

    @staticmethod
    def _actions(stmts: list[dict]) -> set[str]:
        actions: set[str] = set()
        for s in stmts:
            a = s["Action"]
            actions.update(a if isinstance(a, list) else [a])
        return actions

    @staticmethod
    def _resources(stmts: list[dict]) -> list[str]:
        out: list[str] = []
        for s in stmts:
            r = s["Resource"]
            out.extend(r if isinstance(r, list) else [r])
        return out

    def test_no_connector_path(self, statements) -> None:
        needle = BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN.strip("*")  # "/connectors/"
        for r in self._resources(statements):
            assert needle not in r, f"box role references a connector path: {r!r}"

    def test_no_wildcard_secret_or_star_resource(self, statements) -> None:
        # The only "*" resource permitted is the ec2 self-stop (guarded by a resource-tag
        # condition); no statement may grant a bare "*" or a secrets/dynamodb wildcard.
        for s in statements:
            resources = s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]
            for r in resources:
                if r == "arn:aws:ec2:*:*:instance/*":
                    assert "Condition" in s, "ec2 self-stop must be tag-conditioned"
                    continue
                assert r != "*", f"statement {s.get('Sid')} grants a bare '*' resource"

    def test_exactly_the_expected_actions(self, statements) -> None:
        assert self._actions(statements) == {
            "s3:GetObject",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "ec2:StopInstances",
            "dynamodb:PutItem",
            "kms:GenerateDataKey",
            "kms:Decrypt",
            "kms:DescribeKey",
            "secretsmanager:GetSecretValue",
        }

    def test_box_assets_read_scoped_to_prefix_getobject_only(self, statements) -> None:
        assets = next(s for s in statements if s["Sid"] == "BoxAssetsRead")
        # GetObject only (no ListBucket — the boot uses explicit per-object cp), scoped to this
        # agent's box prefix in the deploy bucket. It is deploy-bucket read, NOT a connector cred.
        assert assets["Action"] == ["s3:GetObject"]
        assert assets["Resource"] == f"arn:aws:s3:::{DEPLOY_BUCKET}/{BOX_PREFIX}/*"
        assert "/connectors/" not in assets["Resource"]

    def test_secret_scoped_to_own_oauth_token_only(self, statements) -> None:
        secret_stmt = next(s for s in statements if s["Sid"] == "OauthToken")
        assert OAUTH_SECRET in secret_stmt["Resource"]
        assert "/connectors/" not in secret_stmt["Resource"]

    def test_self_stop_is_tag_scoped(self, statements) -> None:
        stop = next(s for s in statements if s["Sid"] == "SelfStop")
        cond = stop["Condition"]["StringEquals"]
        assert cond["aws:ResourceTag/Agent"] == AGENT
        assert cond["aws:ResourceTag/Arm"] == "ec2-woken"

    def test_queue_scoped_to_the_airlock_inbound_queue(self, statements) -> None:
        drain = next(s for s in statements if s["Sid"] == "DrainAirlockQueue")
        assert drain["Resource"].endswith(f"safe-agents-{ENV}-{AGENT}-airlock-inbound")

    def test_role_extensions_helper_matches(self) -> None:
        # The helper is deterministic and connector-free on its own (unit-level).
        stmts = box_role_extensions(
            AGENT, ENV,
            agent_runs_table_arn=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/t",
            oauth_secret_id=OAUTH_SECRET,
            tables_key_arn=f"arn:aws:kms:{REGION}:{ACCOUNT}:key/k",
            inbound_queue_arn=f"arn:aws:sqs:{REGION}:{ACCOUNT}:q",
            deploy_bucket=DEPLOY_BUCKET,
        )
        for r in self._resources(stmts):
            assert "/connectors/" not in r


# ---------------------------------------------------------------------------
# Criterion 3: teardown removes the box + its per-box IAM
# ---------------------------------------------------------------------------

class TestBoxTeardown:
    def test_teardown_terminates_and_cleans_iam(self, fake_aws_box, manifest) -> None:
        instance_id = ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        report = ec2_woken_box_teardown(manifest, fake_aws_box, environment=ENV)
        assert instance_id in report["instances_terminated"]
        assert report["profile_removed"] is True
        assert report["policy_removed"] is True

    def test_teardown_is_idempotent(self, fake_aws_box, manifest) -> None:
        ec2_woken_box_provision(
            manifest, fake_aws_box, environment=ENV, region=REGION, _iam_backoff_base=0,
        )
        ec2_woken_box_teardown(manifest, fake_aws_box, environment=ENV)
        report = ec2_woken_box_teardown(manifest, fake_aws_box, environment=ENV)
        assert report["instances_terminated"] == []
        assert report["profile_already_gone"] is True


# ---------------------------------------------------------------------------
# Criterion 4: the drain loop's pure message-parse + idle-exit logic
# ---------------------------------------------------------------------------

def _receive_envelope(owner="owner-smoke", message_id="m1", text="do a thing") -> str:
    body = json.dumps({"owner": owner, "message_id": message_id, "text": text})
    return json.dumps({"Messages": [{"Body": body, "ReceiptHandle": "rh-1"}]})


class TestDrainLogic:
    def test_parse_valid_message(self) -> None:
        msg = drain_logic.parse_receive(_receive_envelope())
        assert msg is not None
        ev = drain_logic.parse_normalized(msg["Body"])
        assert ev == {"owner": "owner-smoke", "message_id": "m1", "text": "do a thing"}

    def test_empty_poll_returns_none(self) -> None:
        assert drain_logic.parse_receive(json.dumps({})) is None
        assert drain_logic.parse_receive("{}") is None
        assert drain_logic.parse_receive("not json") is None

    def test_malformed_body_is_poison(self) -> None:
        env = json.dumps({"Messages": [{"Body": "{ not json", "ReceiptHandle": "rh"}]})
        msg = drain_logic.parse_receive(env)
        assert msg is not None  # a message IS present
        assert drain_logic.parse_normalized(msg["Body"]) is None  # but its body is poison

    def test_normalized_coerces_int_message_id(self) -> None:
        ev = drain_logic.parse_normalized(json.dumps({"owner": "o", "message_id": 42, "text": "x"}))
        assert ev["message_id"] == "42"

    @pytest.mark.parametrize(
        "body",
        [
            json.dumps({"message_id": "m", "text": "x"}),   # missing owner
            json.dumps({"owner": "", "message_id": "m", "text": "x"}),  # empty owner
            json.dumps({"owner": "o", "message_id": "", "text": "x"}),  # empty message_id
            json.dumps([1, 2, 3]),                            # not a dict
        ],
    )
    def test_normalized_rejects_malformed(self, body) -> None:
        assert drain_logic.parse_normalized(body) is None

    def test_run_id_is_deterministic_and_safe(self) -> None:
        assert drain_logic.run_id_for("m1") == "woken-m1"
        # non-key-safe chars collapse to '-'
        assert drain_logic.run_id_for("a/b:c") == "woken-a-b-c"
        assert drain_logic.run_id_for("m1") == drain_logic.run_id_for("m1")

    def test_idle_exit_predicate(self) -> None:
        assert drain_logic.should_self_stop(3, 3) is True
        assert drain_logic.should_self_stop(2, 3) is False
        assert drain_logic.should_self_stop(4, 3) is True

    def test_extract_cli_valid(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(_BOX_DIR / "drain_logic.py"), "extract"],
            input=_receive_envelope(text="hello world"),
            capture_output=True, text=True,
        )
        assert proc.returncode == drain_logic.EXIT_OK
        fields = dict(line.split("\t", 1) for line in proc.stdout.splitlines())
        assert fields["MESSAGE_ID"] == "m1"
        assert fields["RECEIPT"] == "rh-1"
        assert base64.b64decode(fields["TEXT_B64"]).decode() == "hello world"

    def test_extract_cli_empty_and_poison_exit_codes(self) -> None:
        empty = subprocess.run(
            [sys.executable, str(_BOX_DIR / "drain_logic.py"), "extract"],
            input="{}", capture_output=True, text=True,
        )
        assert empty.returncode == drain_logic.EXIT_EMPTY

        poison_env = json.dumps({"Messages": [{"Body": "nope", "ReceiptHandle": "rh-x"}]})
        poison = subprocess.run(
            [sys.executable, str(_BOX_DIR / "drain_logic.py"), "extract"],
            input=poison_env, capture_output=True, text=True,
        )
        assert poison.returncode == drain_logic.EXIT_POISON
        # poison still emits the receipt so the drain can delete it
        assert "rh-x" in poison.stdout


# ---------------------------------------------------------------------------
# Criterion 5: the three box shell scripts are syntactically valid
# ---------------------------------------------------------------------------

class TestShellScriptsParse:
    @requires_posix_bash
    @pytest.mark.parametrize("script", [RUN_BROKERED, DRAIN, EMIT_READY])
    def test_bash_n_clean(self, script: Path) -> None:
        assert script.is_file(), f"missing box script: {script}"
        proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert proc.returncode == 0, f"bash -n failed for {script.name}: {proc.stderr}"


# ---------------------------------------------------------------------------
# Criterion 6: render_box_user_data is a self-contained bootstrap
# ---------------------------------------------------------------------------

class TestRenderUserData:
    def _render(self) -> str:
        return render_box_user_data(
            agent_name=AGENT,
            deploy_bucket=DEPLOY_BUCKET,
            broker_dns="broker.safe-agents.local",
            agent_runs_table=f"safe-agents-{ENV}-agent-runs",
            inbound_queue_url=(
                f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/"
                f"safe-agents-{ENV}-{AGENT}-airlock-inbound"
            ),
            region=REGION,
            oauth_secret_id=OAUTH_SECRET,
        )

    def test_copies_all_box_files_from_s3_and_enables_service(self) -> None:
        rendered = self._render()
        for name in ("run-brokered.sh", "drain.sh", "emit-runner-ready.sh", "drain_logic.py"):
            assert f"s3://{DEPLOY_BUCKET}/{BOX_PREFIX}/bin/{name}" in rendered
            assert f"/opt/safe-agents/bin/{name}" in rendered
        assert f"s3://{DEPLOY_BUCKET}/{BOX_PREFIX}/systemd/responsive-agent-ready.service" in rendered
        assert "systemctl enable --now responsive-agent-ready.service" in rendered
        assert "INBOUND_QUEUE_URL=" in rendered

    def test_no_recursive_cp_keeps_role_getobject_only(self) -> None:
        # Explicit per-object cp (not --recursive) is what lets the box role omit s3:ListBucket.
        assert "--recursive" not in self._render()

    def test_encoded_user_data_fits_the_16kb_cap(self) -> None:
        import gzip  # noqa: PLC0415

        encoded = base64.b64encode(gzip.compress(self._render().encode())).decode()
        assert len(encoded) < 16384
