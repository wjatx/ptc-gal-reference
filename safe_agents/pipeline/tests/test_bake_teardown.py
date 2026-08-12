"""
Bake-artifact teardown tests — acceptance criteria for sa#89.

All tests are AWS-free: every AWS call goes through FakeAWS.

Acceptance criteria:
    1. After a fake bake, bake_teardown() removes every artifact class:
       - base AMIs + their backing snapshots
       - Image Builder pipeline, image build versions, recipe, infra-config,
         dist-config, component build versions
       - Image Builder log objects under image-builder-logs/ in the deploy bucket
       - Image Builder IAM instance profile + role
    2. A second bake_teardown() run is a clean no-op (all already-gone).
    3. The report dict describes exactly what was removed vs. already-gone.
    4. bake_teardown() never targets infra resources (agentRole, VPC, CF stacks).
    5. Component build versions are deleted by build-version ARN (not version ARN) —
       the sharp edge from the live capstone.
    6. The deploy bucket is shared floor infrastructure (StateStack-owned): a bake
       teardown removes only its own image-builder-logs/ objects and never deletes
       the bucket or the agent/platform deploy bundles.
"""
from __future__ import annotations

import pytest

from safe_agents.pipeline.aws_interface import FakeAWS
from safe_agents.arms.ec2.ami.teardown import (
    DEFAULT_IB_PROFILE_NAME,
    DEFAULT_IB_ROLE_NAME,
    IB_RESOURCE_PREFIX,
    bake_teardown,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENV = "development"
BUCKET_NAME = f"safe-agents-{ENV}-deploy"

# Representative ARNs that match the real naming convention.
PIPELINE_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:image-pipeline/safe-agents-base-pipeline"
IMAGE_VERSION_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:image/safe-agents-base/1.0.0/1"
IMAGE_BUILD_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:image/safe-agents-base/1.0.0/1/1"
RECIPE_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:image-recipe/safe-agents-base/1.0.0"
INFRA_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:infrastructure-configuration/safe-agents-base-infra"
DIST_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:distribution-configuration/safe-agents-base-dist"
COMPONENT_VERSION_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:component/safe-agents-base/1.0.0"
COMPONENT_BUILD_ARN = "arn:aws:imagebuilder:us-east-1:123456789012:component/safe-agents-base/1.0.0/1"

AMI_ID = "ami-0basetestami001"
SNAPSHOT_ID = "snap-0abc123def456789a"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_baked_aws() -> FakeAWS:
    """FakeAWS pre-populated as if a full bake cycle ran."""
    aws = FakeAWS()

    # AMI + snapshot
    aws.seed_image(
        AMI_ID,
        {"safe-agents:ami": "base", "Project": "safe-agents"},
        creation_date="2026-06-01T00:00:00Z",
        snapshot_ids=[SNAPSHOT_ID],
    )

    # Image Builder resources
    aws.seed_imagebuilder_pipeline(PIPELINE_ARN, "safe-agents-base-pipeline")
    aws.seed_imagebuilder_image(IMAGE_VERSION_ARN, [IMAGE_BUILD_ARN])
    aws.seed_imagebuilder_recipe(RECIPE_ARN, "safe-agents-base")
    aws.seed_imagebuilder_infra_config(INFRA_ARN, "safe-agents-base-infra")
    aws.seed_imagebuilder_dist_config(DIST_ARN, "safe-agents-base-dist")
    aws.seed_imagebuilder_component(COMPONENT_VERSION_ARN, [COMPONENT_BUILD_ARN])

    # S3 deploy bucket with objects
    aws.seed_s3_bucket(BUCKET_NAME, keys=["agents/test/current/bundle.tar.gz", "image-builder-logs/build.log"])

    # IAM Image Builder role + instance profile
    aws.seed_iam_role(
        DEFAULT_IB_ROLE_NAME,
        attached_policies=["arn:aws:iam::aws:policy/EC2InstanceProfileForImageBuilder"],
    )
    aws._instance_profiles[DEFAULT_IB_PROFILE_NAME] = {
        "roles": [DEFAULT_IB_ROLE_NAME],
        "tags": {"Project": "safe-agents"},
    }

    return aws


@pytest.fixture()
def baked_aws() -> FakeAWS:
    """FakeAWS after a full bake cycle, with call log cleared."""
    aws = _make_baked_aws()
    aws.calls.clear()
    return aws


# ---------------------------------------------------------------------------
# 1. Full bake teardown removes every artifact class
# ---------------------------------------------------------------------------

class TestBakeTeardownRemovesAllArtifacts:
    def test_amis_deregistered(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert AMI_ID in report["amis_deregistered"], (
            "bake_teardown must deregister the base AMI"
        )
        assert AMI_ID not in baked_aws._amis, (
            "AMI must be absent from FakeAWS state after teardown"
        )

    def test_snapshots_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert SNAPSHOT_ID in report["snapshots_deleted"], (
            "bake_teardown must delete the backing snapshot"
        )

    def test_ib_pipeline_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert PIPELINE_ARN in report["ib_pipelines_deleted"], (
            "bake_teardown must delete the Image Builder pipeline"
        )
        assert PIPELINE_ARN not in baked_aws._ib_pipelines, (
            "Pipeline must be absent from FakeAWS state after teardown"
        )

    def test_ib_image_build_versions_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert IMAGE_BUILD_ARN in report["ib_images_deleted"], (
            "bake_teardown must delete the image build version"
        )
        assert IMAGE_BUILD_ARN not in baked_aws._ib_image_build_versions, (
            "Image build version must be absent from FakeAWS state after teardown"
        )

    def test_ib_recipe_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert RECIPE_ARN in report["ib_recipes_deleted"]
        assert RECIPE_ARN not in baked_aws._ib_recipes

    def test_ib_infra_config_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert INFRA_ARN in report["ib_infra_configs_deleted"]
        assert INFRA_ARN not in baked_aws._ib_infra_configs

    def test_ib_dist_config_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert DIST_ARN in report["ib_dist_configs_deleted"]
        assert DIST_ARN not in baked_aws._ib_dist_configs

    def test_ib_component_build_versions_deleted(self, baked_aws: FakeAWS) -> None:
        """Sharp edge: component must be deleted by build-version ARN."""
        report = bake_teardown(baked_aws, environment=ENV)

        assert COMPONENT_BUILD_ARN in report["ib_components_deleted"], (
            "bake_teardown must delete the component BUILD-VERSION ARN, not the version ARN"
        )
        assert COMPONENT_BUILD_ARN not in baked_aws._ib_component_build_versions, (
            "Component build version must be absent from FakeAWS state after teardown"
        )

    def test_only_ib_logs_cleaned_bundles_preserved(self, baked_aws: FakeAWS) -> None:
        """Only image-builder-logs/ objects are removed; deploy bundles survive."""
        report = bake_teardown(baked_aws, environment=ENV)

        assert report["bucket_log_objects_deleted"] == 1, (
            "bake_teardown must remove only the image-builder-logs/ objects (1 seeded)"
        )
        remaining = set(baked_aws.list_bucket_objects(BUCKET_NAME))
        assert "agents/test/current/bundle.tar.gz" in remaining, (
            "deploy bundles must NOT be removed by a bake teardown"
        )
        assert not any(k.startswith("image-builder-logs/") for k in remaining), (
            "all image-builder-logs/ objects must be removed"
        )

    def test_deploy_bucket_never_deleted(self, baked_aws: FakeAWS) -> None:
        """The floor-owned deploy bucket must survive a bake teardown (no delete_bucket)."""
        bake_teardown(baked_aws, environment=ENV)

        assert BUCKET_NAME in baked_aws._s3_buckets, (
            "bake_teardown must not delete the StateStack-owned deploy bucket"
        )
        assert not baked_aws.was_called("delete_bucket"), (
            "bake_teardown must never call delete_bucket on the shared deploy bucket"
        )

    def test_ib_profile_removed(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert report["ib_profile_removed"] is True
        assert DEFAULT_IB_PROFILE_NAME not in baked_aws._instance_profiles

    def test_ib_managed_policy_detached(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert len(report["ib_role_managed_policies_detached"]) == 1, (
            "The managed policy must be detached from the IB role"
        )

    def test_ib_role_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        assert report["ib_role_deleted"] is True
        assert DEFAULT_IB_ROLE_NAME not in baked_aws._iam_roles


# ---------------------------------------------------------------------------
# 2. Component deletion uses build-version ARN (not version ARN) — sharp edge
# ---------------------------------------------------------------------------

class TestComponentBuildVersionSharpEdge:
    def test_component_deleted_by_build_version_arn(self, baked_aws: FakeAWS) -> None:
        """Verify list_imagebuilder_component_build_versions is called before deletion."""
        bake_teardown(baked_aws, environment=ENV)

        # list_imagebuilder_component_build_versions must have been called with the
        # version ARN, producing the build-version ARN for actual deletion.
        assert baked_aws.was_called(
            "list_imagebuilder_component_build_versions", COMPONENT_VERSION_ARN
        ), "Must call list_imagebuilder_component_build_versions with the VERSION ARN"

        # delete_imagebuilder_component must have been called with the BUILD-VERSION ARN.
        assert baked_aws.was_called(
            "delete_imagebuilder_component", COMPONENT_BUILD_ARN
        ), "Must call delete_imagebuilder_component with the BUILD-VERSION ARN"

    def test_version_arn_not_used_for_deletion(self, baked_aws: FakeAWS) -> None:
        """delete_imagebuilder_component must never be called with the version ARN."""
        bake_teardown(baked_aws, environment=ENV)

        bad_calls = [
            c for c in baked_aws.calls
            if c[0] == "delete_imagebuilder_component" and c[1] == COMPONENT_VERSION_ARN
        ]
        assert not bad_calls, (
            "delete_imagebuilder_component must use the BUILD-VERSION ARN, "
            f"not the version ARN {COMPONENT_VERSION_ARN!r}"
        )


# ---------------------------------------------------------------------------
# 3. Second run is a clean no-op
# ---------------------------------------------------------------------------

class TestBakeTeardownIdempotency:
    def test_second_run_succeeds(self, baked_aws: FakeAWS) -> None:
        bake_teardown(baked_aws, environment=ENV)
        baked_aws.calls.clear()

        # Second run — everything is already gone.
        report = bake_teardown(baked_aws, environment=ENV)

        # Nothing should have been removed on the second run.
        assert report["amis_deregistered"] == []
        assert report["snapshots_deleted"] == []
        assert report["ib_pipelines_deleted"] == []
        assert report["ib_images_deleted"] == []
        assert report["ib_components_deleted"] == []
        assert report["bucket_log_objects_deleted"] == 0
        assert report["ib_role_deleted"] is False

    def test_second_run_reports_already_gone(self, baked_aws: FakeAWS) -> None:
        bake_teardown(baked_aws, environment=ENV)
        report2 = bake_teardown(baked_aws, environment=ENV)

        # AMIs already gone
        assert report2["amis_already_gone"] == [] or report2["amis_deregistered"] == [], (
            "Second run should not deregister AMIs that are already gone"
        )
        assert report2["bucket_log_objects_deleted"] == 0, (
            "Second run must find no Image Builder logs to remove"
        )
        assert report2["ib_role_already_gone"] is True, (
            "Second run must report IB role already-gone"
        )

    def test_second_run_does_not_call_deregister(self, baked_aws: FakeAWS) -> None:
        """After teardown, describe_images returns [] so deregister_image is never called."""
        bake_teardown(baked_aws, environment=ENV)
        baked_aws.calls.clear()

        bake_teardown(baked_aws, environment=ENV)

        assert not baked_aws.was_called("deregister_image"), (
            "Second run must not call deregister_image (AMI already gone)"
        )


# ---------------------------------------------------------------------------
# 4. bake_teardown never targets infra resources
# ---------------------------------------------------------------------------

class TestBakeTeardownNeverTargetsInfra:
    def test_no_cf_stack_operations(self, baked_aws: FakeAWS) -> None:
        bake_teardown(baked_aws, environment=ENV)

        cf_calls = [c for c in baked_aws.calls if "stack" in c[0].lower()]
        assert not cf_calls, (
            f"bake_teardown must not make CloudFormation stack calls; got: {cf_calls}"
        )

    def test_no_base_agent_role_deletion(self, baked_aws: FakeAWS) -> None:
        """bake_teardown must not delete or detach policies from the base agentRole."""
        baked_aws.calls.clear()
        bake_teardown(baked_aws, environment=ENV)

        # "delete_role" should only target the IB role, not any infra role.
        delete_role_calls = [c for c in baked_aws.calls if c[0] == "delete_role"]
        for call in delete_role_calls:
            role_name = call[1]
            assert "agentRole" not in role_name and "agent-role" not in role_name, (
                f"bake_teardown must not delete the infra agentRole; got: {role_name}"
            )

    def test_no_terminate_instances(self, baked_aws: FakeAWS) -> None:
        """bake_teardown only removes bake artifacts, not EC2 instances."""
        bake_teardown(baked_aws, environment=ENV)

        assert not baked_aws.was_called("terminate_instances"), (
            "bake_teardown must not terminate EC2 instances (that is teardown's job)"
        )


# ---------------------------------------------------------------------------
# 5. Report content
# ---------------------------------------------------------------------------

class TestBakeTeardownReport:
    def test_report_has_all_expected_keys(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)

        expected_keys = {
            "amis_deregistered",
            "amis_already_gone",
            "snapshots_deleted",
            "snapshots_already_gone",
            "ib_pipelines_deleted",
            "ib_images_deleted",
            "ib_recipes_deleted",
            "ib_infra_configs_deleted",
            "ib_dist_configs_deleted",
            "ib_components_deleted",
            "bucket_log_objects_deleted",
            "ib_profile_removed",
            "ib_role_managed_policies_detached",
            "ib_role_deleted",
            "ib_role_already_gone",
        }
        missing = expected_keys - set(report.keys())
        assert not missing, f"Report is missing keys: {missing}"

    def test_report_counts_objects_deleted(self, baked_aws: FakeAWS) -> None:
        report = bake_teardown(baked_aws, environment=ENV)
        assert report["bucket_log_objects_deleted"] == 1


# ---------------------------------------------------------------------------
# 6. Empty environment (nothing to remove) — no errors, no-op report
# ---------------------------------------------------------------------------

class TestBakeTeardownEmptyEnvironment:
    def test_empty_env_succeeds(self) -> None:
        """bake_teardown on a pristine FakeAWS must return without error."""
        aws = FakeAWS()
        report = bake_teardown(aws, environment=ENV)

        assert report["amis_deregistered"] == []
        assert report["ib_pipelines_deleted"] == []
        assert report["bucket_log_objects_deleted"] == 0
        assert report["ib_role_already_gone"] is True

    def test_empty_env_does_not_call_deregister(self) -> None:
        aws = FakeAWS()
        bake_teardown(aws, environment=ENV)

        assert not aws.was_called("deregister_image")
        assert not aws.was_called("delete_snapshot")
        assert not aws.was_called("delete_imagebuilder_pipeline")


# ---------------------------------------------------------------------------
# 7. Live-shape regression — FakeAWS mirrors real boto3 key names + owner filter
#
# Root cause of issue #89: LiveAWS passed `filters=[{"name": "name",
# "values": ["safe-agents-base*"]}]` to all imagebuilder list APIs. The
# imagebuilder API rejects '*' in filter values (allowed pattern:
# ^[0-9a-zA-Z./_ :,{}"-]{1,1024}$) with InvalidParameterValueException.
# The except-block caught it silently and returned [], so every IB resource
# was reported as already-gone while it actually existed — they got orphaned.
#
# Fix: drop the API filter from all six list methods; rely on the Python
# startswith() filter that was already present. FakeAWS now applies the same
# prefix filter (extracting name from ARN) so this class would catch a
# regression where resources with a non-matching name slip through.
# ---------------------------------------------------------------------------

# A second prefix that must NOT match any "safe-agents-base" resources.
OTHER_PREFIX = "other-project"

OTHER_IMAGE_VERSION_ARN = (
    "arn:aws:imagebuilder:us-east-1:123456789012:image/other-project/1.0.0/1"
)
OTHER_COMPONENT_VERSION_ARN = (
    "arn:aws:imagebuilder:us-east-1:123456789012:component/other-project/1.0.0"
)


class TestLiveShapeRegression:
    """FakeAWS list methods must mirror the real boto3 shape: return only
    resources whose name starts with name_prefix, no wildcards."""

    def test_images_filtered_by_prefix(self) -> None:
        """list_imagebuilder_images must exclude ARNs whose name does not match."""
        aws = FakeAWS()
        aws.seed_imagebuilder_image(IMAGE_VERSION_ARN, [IMAGE_BUILD_ARN])
        # Seed a second image under a different name — must NOT appear.
        aws.seed_imagebuilder_image(OTHER_IMAGE_VERSION_ARN, [])

        result = aws.list_imagebuilder_images(IB_RESOURCE_PREFIX)

        assert IMAGE_VERSION_ARN in result, "Matching image must be returned"
        assert OTHER_IMAGE_VERSION_ARN not in result, (
            "Non-matching image must be excluded by name-prefix filter"
        )

    def test_components_filtered_by_prefix(self) -> None:
        """list_imagebuilder_components must exclude ARNs whose name does not match."""
        aws = FakeAWS()
        aws.seed_imagebuilder_component(COMPONENT_VERSION_ARN, [COMPONENT_BUILD_ARN])
        # Seed a component under a different name — must NOT appear.
        aws.seed_imagebuilder_component(OTHER_COMPONENT_VERSION_ARN, [])

        result = aws.list_imagebuilder_components(IB_RESOURCE_PREFIX)

        assert COMPONENT_VERSION_ARN in result, "Matching component must be returned"
        assert OTHER_COMPONENT_VERSION_ARN not in result, (
            "Non-matching component must be excluded by name-prefix filter"
        )

    def test_teardown_does_not_touch_other_prefix_resources(self) -> None:
        """bake_teardown must not delete IB resources whose name doesn't match the prefix."""
        aws = _make_baked_aws()
        # Add resources under a different name — teardown must leave them alone.
        other_pipeline_arn = (
            "arn:aws:imagebuilder:us-east-1:123456789012"
            ":image-pipeline/other-project-pipeline"
        )
        aws.seed_imagebuilder_pipeline(other_pipeline_arn, "other-project-pipeline")
        aws.seed_imagebuilder_image(OTHER_IMAGE_VERSION_ARN, [])
        aws.seed_imagebuilder_component(OTHER_COMPONENT_VERSION_ARN, [])

        bake_teardown(aws, environment=ENV)

        assert other_pipeline_arn in aws._ib_pipelines, (
            "bake_teardown must not delete pipelines outside its name prefix"
        )
        assert OTHER_IMAGE_VERSION_ARN in aws._ib_image_versions, (
            "bake_teardown must not delete image versions outside its name prefix"
        )
        assert OTHER_COMPONENT_VERSION_ARN in aws._ib_component_versions, (
            "bake_teardown must not delete component versions outside its name prefix"
        )
