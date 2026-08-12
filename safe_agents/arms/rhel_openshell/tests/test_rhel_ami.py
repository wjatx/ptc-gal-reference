"""
RHEL base-AMI bakery tests — acceptance criteria for sa#109.

All tests are AWS-free: every AWS call goes through FakeAWS.

Acceptance criteria:
  1. The image-builder/ config files are syntactically valid (JSON parses, YAML parses)
     and internally consistent (names/tags match the teardown + provision constants).
  2. The recipe references a RHEL 9 x86_64 parent and /dev/sda1 — NOT AL2023 / arm64 /xvda.
  3. The component bakes the boot toolchain: SSM agent, AWS CLI v2 (x86_64), Node.js,
     Claude Code CLI, uv/ruff, python3-pyyaml — and preserves nft + SELinux (no iptables,
     no SELinux disable).
  4. dist-config tags the output AMI safe-agents:ami=base-rhel.
  5. teardown constants target the base-rhel bake; rhel_bake_teardown removes a seeded bake
     and is idempotent, reusing the shared (EC2) teardown engine.
  6. provision resolves the prebuilt base-rhel AMI when present, and falls back to the RHEL
     marketplace AMI when no bake exists.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from safe_agents.pipeline.aws_interface import FakeAWS
from safe_agents.arms.rhel_openshell.ami import teardown as rhel_bake
from safe_agents.arms.rhel_openshell.ami.teardown import rhel_bake_teardown
from safe_agents.arms.rhel_openshell.provision import (
    RHEL_OWNER_ID,
    rhel_openshell_provision,
)
from safe_agents.pipeline import load_manifest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

AMI_DIR = Path(__file__).parent.parent / "ami"
IB_DIR = AMI_DIR / "image-builder"
RECIPE_PATH = IB_DIR / "recipe-base.json"
COMPONENT_PATH = IB_DIR / "component-base.yaml"
INFRA_PATH = IB_DIR / "infra-config.json"
PIPELINE_PATH = IB_DIR / "pipeline.json"
DIST_PATH = IB_DIR / "dist-config.json"

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent  # safe-agents/
SMOKE_MANIFEST = REPO_ROOT / "agents" / "smoke-rhel-openshell.yaml"

_RHEL_AMI_ID = "ami-0dcaef0e21f109874"
_RHEL_AMI_NAME = "RHEL-9.8_HVM-20250506-x86_64-1893-Hourly2-GP3"
_BAKED_AMI_ID = "ami-0bakedrhel00001"

# Pass to rhel_openshell_provision in all unit tests to avoid real sleeps.
_FAST = dict(
    _clean_start_ec2_timeout=1.0,
    _clean_start_iam_timeout=1.0,
    _clean_start_poll_interval=0.0,
    _iam_poll_interval=0.0,
    _iam_max_wait=1.0,
    _iam_extra_buffer=0.0,
    _ssm_timeout=10.0,
    _ssm_poll_interval=0.0,
)


def _seed_infra(aws: FakeAWS, env: str = "development") -> FakeAWS:
    """Seed the infra SSM params provision needs (mirrors the arm-test fixture)."""
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-role-arn",
        "arn:aws:iam::123456789012:instance-profile/safe-agents-development-AgentRole",
    )
    aws.seed_ssm_param(f"/safe-agents/{env}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(f"/safe-agents/{env}/endpoint-sg-id", "sg-0endpoint9999")
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-subnet-ids", "subnet-0agent-isolated,subnet-0agent-b"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-arn",
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-name", "safe-agents-development-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/tables-key-arn",
        "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-tables-cmk",
    )
    aws.seed_ssm_param(f"/safe-agents/{env}/broker-service-dns", "broker.safe-agents.local")
    return aws


# ---------------------------------------------------------------------------
# Criterion 1: config-file validity + internal consistency
# ---------------------------------------------------------------------------

class TestConfigFileValidity:
    def test_all_config_files_exist(self) -> None:
        for p in (RECIPE_PATH, COMPONENT_PATH, INFRA_PATH, PIPELINE_PATH, DIST_PATH):
            assert p.is_file(), f"missing bakery config file: {p}"

    @pytest.mark.parametrize("path", [RECIPE_PATH, INFRA_PATH, PIPELINE_PATH, DIST_PATH])
    def test_json_files_parse(self, path: Path) -> None:
        """Every JSON config must parse (syntactic validity)."""
        json.loads(path.read_text())

    def test_component_yaml_parses(self) -> None:
        """component-base.yaml must be valid YAML with the AWSTOE shape."""
        doc = yaml.safe_load(COMPONENT_PATH.read_text())
        assert doc.get("schemaVersion") == 1.0, "component must declare schemaVersion 1.0"
        phase_names = {p["name"] for p in doc["phases"]}
        assert {"build", "validate"} <= phase_names, (
            "component must define both a build and a validate phase"
        )

    def test_recipe_names_match_teardown_prefix(self) -> None:
        recipe = json.loads(RECIPE_PATH.read_text())
        assert recipe["name"] == rhel_bake.IB_RESOURCE_PREFIX, (
            "recipe name must match the teardown IB_RESOURCE_PREFIX so teardown finds it"
        )

    def test_infra_and_dist_names_match_prefix(self) -> None:
        infra = json.loads(INFRA_PATH.read_text())
        dist = json.loads(DIST_PATH.read_text())
        assert infra["name"] == f"{rhel_bake.IB_RESOURCE_PREFIX}-infra"
        assert dist["name"] == f"{rhel_bake.IB_RESOURCE_PREFIX}-dist"

    def test_pipeline_arns_reference_rhel_resources(self) -> None:
        pipeline = json.loads(PIPELINE_PATH.read_text())
        assert pipeline["name"] == f"{rhel_bake.IB_RESOURCE_PREFIX}-pipeline"
        for key in (
            "imageRecipeArn",
            "infrastructureConfigurationArn",
            "distributionConfigurationArn",
        ):
            assert rhel_bake.IB_RESOURCE_PREFIX in pipeline[key], (
                f"pipeline {key} must reference the {rhel_bake.IB_RESOURCE_PREFIX} resources"
            )


# ---------------------------------------------------------------------------
# Criterion 2: recipe references RHEL 9 x86_64 (not AL2023 / arm64)
# ---------------------------------------------------------------------------

class TestRecipeRhelParent:
    def test_recipe_root_device_is_sda1(self) -> None:
        """RHEL roots at /dev/sda1 (NOT AL2023's /dev/xvda)."""
        recipe = json.loads(RECIPE_PATH.read_text())
        devices = [m["deviceName"] for m in recipe["blockDeviceMappings"]]
        assert "/dev/sda1" in devices, (
            "recipe must map the RHEL root device /dev/sda1 (arm64 EC2 uses /dev/xvda)"
        )
        assert "/dev/xvda" not in devices, (
            "recipe must NOT use /dev/xvda — that is the AL2023 device name"
        )

    def test_recipe_parent_is_rhel_not_al2023(self) -> None:
        """The parent image must be a RHEL 9 reference, not the AL2023 arm64 managed parent."""
        recipe = json.loads(RECIPE_PATH.read_text())
        parent = recipe["parentImage"]
        assert "amazon-linux" not in parent.lower(), (
            "recipe parentImage must not be the AL2023 managed image (that is the EC2 arm)"
        )
        assert "arm64" not in parent.lower(), (
            "recipe parentImage must not be arm64 — the rhel-openshell arm is x86_64 only"
        )
        # RHEL is a marketplace AMI resolved by ID (a ${RHEL9_PARENT_AMI} placeholder).
        assert "RHEL9_PARENT_AMI" in parent or parent.startswith("ami-"), (
            "recipe parentImage must reference the RHEL 9 x86_64 AMI "
            "(placeholder ${RHEL9_PARENT_AMI} or a concrete ami-id)"
        )

    def test_recipe_encrypted_gp3_root(self) -> None:
        recipe = json.loads(RECIPE_PATH.read_text())
        ebs = recipe["blockDeviceMappings"][0]["ebs"]
        assert ebs["encrypted"] is True, "root volume must be encrypted"
        assert ebs["volumeType"] == "gp3", "root volume must be gp3"


# ---------------------------------------------------------------------------
# Criterion 3: component bakes the boot toolchain + preserves nft/SELinux
# ---------------------------------------------------------------------------

class TestComponentBakesToolchain:
    def _content(self) -> str:
        return COMPONENT_PATH.read_text()

    def test_supported_os_is_rhel9(self) -> None:
        """The component header/deploy comment must target RHEL 9 (create-component OS)."""
        assert "Red Hat Enterprise Linux 9" in self._content(), (
            "component must document '--supported-os-versions [\"Red Hat Enterprise Linux 9\"]'"
        )

    def test_bakes_claude_cli_in_harness_block(self) -> None:
        content = self._content()
        start = content.find("HARNESS-COUPLING BLOCK START")
        end = content.find("HARNESS-COUPLING BLOCK END")
        assert start != -1 and end != -1 and start < end, (
            "component must bracket the Claude install with HARNESS-COUPLING markers"
        )
        block = content[start:end]
        assert "@anthropic-ai/claude-code" in block, (
            "the Claude Code CLI (npm) install must be inside the HARNESS-COUPLING block"
        )

    def test_bakes_node(self) -> None:
        assert "nodejs" in self._content(), "component must install Node.js (Claude CLI needs it)"

    def test_bakes_awscli_x86_64(self) -> None:
        """AWS CLI v2 must use the x86_64 installer (RHEL arm is x86_64, not aarch64)."""
        content = self._content()
        assert "awscli-exe-linux-x86_64.zip" in content, (
            "component must install AWS CLI v2 via the x86_64 installer"
        )
        assert "aarch64" not in content, (
            "component must NOT use the aarch64 AWS CLI installer — the RHEL arm is x86_64"
        )

    def test_bakes_ssm_agent(self) -> None:
        """RHEL AMIs omit the SSM agent; the bake must install + enable it."""
        content = self._content()
        assert "amazon-ssm-agent" in content, "component must install the SSM agent"
        assert "enable amazon-ssm-agent" in content, "component must enable the SSM agent service"

    def test_bakes_python_env_and_pyyaml(self) -> None:
        content = self._content()
        assert "astral.sh/uv/install.sh" in content, "component must install uv"
        assert "ruff" in content, "component must install ruff"
        assert "python3-pyyaml" in content, (
            "component must install python3-pyyaml (the harness imports yaml at runtime)"
        )

    def test_ruff_baked_into_system_bin_dir(self) -> None:
        """ruff must land in /usr/local/bin, not root's ~/.local/bin.

        `uv tool install` as root defaults to /root/.local/bin, which the dev user's
        `command -v ruff` offline guard (install-python-env.sh) cannot see — the boot
        would then fall into a network install the no-NAT subnet cannot perform.
        """
        assert "UV_TOOL_BIN_DIR=/usr/local/bin" in self._content(), (
            "the uv tool install must set UV_TOOL_BIN_DIR=/usr/local/bin so ruff is on "
            "the dev user's PATH at runtime"
        )

    def test_does_not_bake_iptables(self) -> None:
        """RHEL uses nftables (already on the AMI); iptables must NOT be baked."""
        content = self._content()
        # Guard against installing iptables packages (comment mentions are fine, but no
        # 'dnf install ... iptables' token).
        non_comment = "\n".join(
            ln for ln in content.splitlines() if not ln.strip().startswith("#")
        )
        assert "iptables" not in non_comment, (
            "component must NOT install iptables — the RHEL arm's netns setup uses nft"
        )

    def test_verifies_nft_present(self) -> None:
        assert "command -v nft" in self._content(), (
            "component must verify nftables is present (the arm's NAT tool)"
        )

    def test_does_not_disable_selinux(self) -> None:
        """The bake must never disable SELinux (the arm relies on restorecon/enforcing)."""
        content = self._content()
        lowered = content.lower()
        assert "setenforce 0" not in lowered, "component must not run setenforce 0"
        assert "selinux=disabled" not in lowered, "component must not set SELINUX=disabled"
        assert 'getenforce)" = "Enforcing"' in content, (
            "component validate phase must assert SELinux stayed Enforcing"
        )

    def test_does_not_clone_private_repo(self) -> None:
        """The bakery has no git token; the harness arrives via S3 at boot, not a bake clone.

        Matched org-agnostically: this asserted the literal
        `Third-Ralph/safe-agents` until the repo moved (#290), at which point it
        would have passed however the component cloned. The pattern deliberately
        does not ban `github.com` outright — the component legitimately adds the
        `cli.github.com` RPM repo to install the GitHub CLI.
        """
        content = self._content()
        assert not re.search(r"github\.com[:/][\w.-]+/safe-agents", content)
        assert "GITHUB_TOKEN" not in content


# ---------------------------------------------------------------------------
# Criterion 4: dist-config tags the AMI safe-agents:ami=base-rhel
# ---------------------------------------------------------------------------

class TestDistConfigTagging:
    def test_ami_tag_is_base_rhel(self) -> None:
        dist = json.loads(DIST_PATH.read_text())
        tags = dist["distributions"][0]["amiDistributionConfiguration"]["amiTags"]
        assert tags["safe-agents:ami"] == "base-rhel", (
            "dist-config must tag the AMI safe-agents:ami=base-rhel so provision resolves it"
        )

    def test_dist_tag_matches_teardown_and_provision(self) -> None:
        """The dist-config tag, teardown filter, and provision filter must agree."""
        dist = json.loads(DIST_PATH.read_text())
        tag_value = dist["distributions"][0]["amiDistributionConfiguration"]["amiTags"][
            "safe-agents:ami"
        ]
        assert rhel_bake.AMI_TAG_FILTER == {"safe-agents:ami": tag_value}, (
            "teardown AMI_TAG_FILTER must match the dist-config AMI tag"
        )


# ---------------------------------------------------------------------------
# Criterion 5: teardown constants + engine reuse
# ---------------------------------------------------------------------------

class TestRhelBakeTeardown:
    ENV = "development"

    def _baked_aws(self) -> FakeAWS:
        """FakeAWS pre-populated as if a full RHEL bake cycle ran."""
        aws = FakeAWS()
        prefix = rhel_bake.IB_RESOURCE_PREFIX
        aws.seed_image(
            _BAKED_AMI_ID,
            {"safe-agents:ami": "base-rhel", "Project": "safe-agents"},
            creation_date="2026-06-01T00:00:00Z",
            snapshot_ids=["snap-0rhelbake0001"],
        )
        aws.seed_imagebuilder_pipeline(
            f"arn:aws:imagebuilder:us-east-1:123456789012:image-pipeline/{prefix}-pipeline",
            f"{prefix}-pipeline",
        )
        aws.seed_imagebuilder_recipe(
            f"arn:aws:imagebuilder:us-east-1:123456789012:image-recipe/{prefix}/1.0.0", prefix
        )
        aws.seed_imagebuilder_infra_config(
            f"arn:aws:imagebuilder:us-east-1:123456789012:infrastructure-configuration/{prefix}-infra",
            f"{prefix}-infra",
        )
        aws.seed_imagebuilder_dist_config(
            f"arn:aws:imagebuilder:us-east-1:123456789012:distribution-configuration/{prefix}-dist",
            f"{prefix}-dist",
        )
        comp_version = f"arn:aws:imagebuilder:us-east-1:123456789012:component/{prefix}/1.0.0"
        aws.seed_imagebuilder_component(comp_version, [f"{comp_version}/1"])
        aws.seed_s3_bucket(
            f"safe-agents-{self.ENV}-deploy",
            keys=["agents/x/current/bundle.tar.gz", "image-builder-logs/build.log"],
        )
        aws.seed_iam_role(
            rhel_bake.DEFAULT_IB_ROLE_NAME,
            attached_policies=["arn:aws:iam::aws:policy/EC2InstanceProfileForImageBuilder"],
        )
        aws._instance_profiles[rhel_bake.DEFAULT_IB_PROFILE_NAME] = {
            "roles": [rhel_bake.DEFAULT_IB_ROLE_NAME],
            "tags": {},
        }
        return aws

    def test_constants_target_base_rhel(self) -> None:
        assert rhel_bake.IB_RESOURCE_PREFIX == "safe-agents-base-rhel"
        assert rhel_bake.AMI_TAG_FILTER == {"safe-agents:ami": "base-rhel"}
        assert rhel_bake.DEFAULT_IB_ROLE_NAME == "safe-agents-base-rhel-imagebuilder"
        assert rhel_bake.DEFAULT_IB_PROFILE_NAME == "safe-agents-base-rhel-imagebuilder"

    def test_teardown_removes_rhel_ami(self) -> None:
        report = rhel_bake_teardown(self._baked_aws(), self.ENV)
        assert _BAKED_AMI_ID in report["amis_deregistered"], (
            "rhel_bake_teardown must deregister the base-rhel AMI"
        )

    def test_teardown_removes_ib_resources(self) -> None:
        report = rhel_bake_teardown(self._baked_aws(), self.ENV)
        assert report["ib_pipelines_deleted"], "must delete the RHEL pipeline"
        assert report["ib_recipes_deleted"], "must delete the RHEL recipe"
        assert report["ib_components_deleted"], "must delete the RHEL component build version"
        assert report["ib_role_deleted"], "must delete the RHEL IB role"

    def test_teardown_only_cleans_ib_logs(self) -> None:
        aws = self._baked_aws()
        report = rhel_bake_teardown(aws, self.ENV)
        assert report["bucket_log_objects_deleted"] == 1
        remaining = set(aws.list_bucket_objects(f"safe-agents-{self.ENV}-deploy"))
        assert "agents/x/current/bundle.tar.gz" in remaining, (
            "deploy bundles must survive a bake teardown"
        )

    def test_teardown_idempotent(self) -> None:
        aws = self._baked_aws()
        rhel_bake_teardown(aws, self.ENV)
        report2 = rhel_bake_teardown(aws, self.ENV)
        assert report2["amis_deregistered"] == []
        assert report2["ib_pipelines_deleted"] == []
        assert report2["ib_role_already_gone"] is True

    def test_teardown_does_not_touch_ec2_base_ami(self) -> None:
        """A RHEL teardown must not deregister the EC2 arm's base AMI (tag 'base')."""
        aws = self._baked_aws()
        aws.seed_image(
            "ami-0ec2base00001",
            {"safe-agents:ami": "base", "Project": "safe-agents"},
            creation_date="2026-06-01T00:00:00Z",
            snapshot_ids=["snap-0ec2base0001"],
        )
        report = rhel_bake_teardown(aws, self.ENV)
        assert "ami-0ec2base00001" not in report["amis_deregistered"], (
            "RHEL teardown (tag base-rhel) must not touch the EC2 base AMI (tag base)"
        )
        assert "ami-0ec2base00001" in aws._amis, "EC2 base AMI must survive the RHEL teardown"


# ---------------------------------------------------------------------------
# Criterion 6: provision resolves the prebuilt AMI, falls back to marketplace
# ---------------------------------------------------------------------------

class TestProvisionResolvesBakedAmi:
    ENV = "development"

    def test_uses_prebuilt_ami_when_present(self) -> None:
        """When a base-rhel AMI is baked, RunInstances must launch from it (not marketplace)."""
        aws = _seed_infra(FakeAWS())
        aws.seed_image(
            _BAKED_AMI_ID,
            {"safe-agents:ami": "base-rhel"},
            creation_date="2026-06-01T00:00:00Z",
        )
        # A marketplace AMI is also available; the prebuilt one must win.
        aws.seed_marketplace_image(
            _RHEL_AMI_ID, RHEL_OWNER_ID, _RHEL_AMI_NAME, creation_date="2025-05-06T00:00:00Z"
        )

        captured: dict = {}
        original = aws.run_instances

        def spy(**kwargs):
            captured.update(kwargs)
            return original(**kwargs)

        aws.run_instances = spy  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, aws, environment=self.ENV, **_FAST)

        assert captured["image_id"] == _BAKED_AMI_ID, (
            f"provision must launch from the prebuilt base-rhel AMI; got {captured.get('image_id')!r}"
        )
        # With a baked AMI present, the marketplace lookup must be skipped entirely.
        assert not aws.was_called("describe_images_by_owner_name"), (
            "provision must not fall back to the marketplace lookup when a bake exists"
        )

    def test_picks_newest_prebuilt_ami(self) -> None:
        """With multiple base-rhel bakes, the newest by creation_date wins."""
        aws = _seed_infra(FakeAWS())
        aws.seed_image(
            "ami-0oldrhelbake",
            {"safe-agents:ami": "base-rhel"},
            creation_date="2026-01-01T00:00:00Z",
        )
        aws.seed_image(
            "ami-0newrhelbake",
            {"safe-agents:ami": "base-rhel"},
            creation_date="2026-06-01T00:00:00Z",
        )
        captured: dict = {}
        original = aws.run_instances
        aws.run_instances = lambda **kw: (captured.update(kw), original(**kw))[1]  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, aws, environment=self.ENV, **_FAST)
        assert captured["image_id"] == "ami-0newrhelbake"

    def test_falls_back_to_marketplace_when_no_bake(self) -> None:
        """With no base-rhel AMI, provision falls back to the RHEL marketplace AMI."""
        aws = _seed_infra(FakeAWS())
        aws.seed_marketplace_image(
            _RHEL_AMI_ID, RHEL_OWNER_ID, _RHEL_AMI_NAME, creation_date="2025-05-06T00:00:00Z"
        )
        captured: dict = {}
        original = aws.run_instances
        aws.run_instances = lambda **kw: (captured.update(kw), original(**kw))[1]  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, aws, environment=self.ENV, **_FAST)

        assert aws.was_called("describe_images_by_owner_name"), (
            "provision must fall back to the marketplace lookup when no bake exists"
        )
        assert captured["image_id"] == _RHEL_AMI_ID
