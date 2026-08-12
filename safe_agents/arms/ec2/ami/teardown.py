"""
bake_teardown — remove all artifacts left by a safe-agents Image Builder bake cycle.

Call bake_teardown() after destroying the arm instance (core/bin/teardown) to
bring the bake artifact estate to zero orphans.

Naming conventions (load-bearing — must match image-builder/ config files):
    AMI tag filter:           {"safe-agents:ami": "base"}
    Image Builder prefix:     "safe-agents-base"
    Pipeline name:            "safe-agents-base-pipeline"
    Recipe name:              "safe-agents-base"
    Infra-config name:        "safe-agents-base-infra"
    Dist-config name:         "safe-agents-base-dist"
    Component name:           "safe-agents-base"
    Deploy bucket:            "safe-agents-<env>-deploy"
    IB role (conventional):   "safe-agents-base-imagebuilder"
    IB profile (conventional):"safe-agents-base-imagebuilder"

Deletion order matters:
    1. Pipeline  — disables new builds before touching dependent resources.
    2. Image build versions — must go before recipe/component can be deleted.
    3. Recipe, dist-config, infra-config — order among these is arbitrary.
    4. Component build versions — SHARP EDGE: delete by BUILD-VERSION ARN
       (list_imagebuilder_component_build_versions), NOT the version ARN.
    5. AMIs + their backing snapshots.
    6. S3 deploy bucket — empty first, then delete.
    7. Image Builder IAM role + instance profile.

All operations are idempotent: a resource that is already gone is skipped and
reported as "already-gone". A second run is a clean no-op.
"""
from __future__ import annotations

import logging
from typing import Optional

from safe_agents.pipeline.aws_interface import AWSInterface

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource name constants (must match image-builder/ config files)
# ---------------------------------------------------------------------------

# AMI tag that identifies every base AMI baked by this pipeline.
AMI_TAG_FILTER: dict[str, str] = {"safe-agents:ami": "base"}

# Common name prefix for all Image Builder resources.
IB_RESOURCE_PREFIX = "safe-agents-base"

# Deploy bucket template (must match bundle.py and provision.py).
DEPLOY_BUCKET_TEMPLATE = "safe-agents-{environment}-deploy"

# The deploy bucket is shared floor infrastructure owned by the State stack
# (StateStack DeployBucket). A bake teardown must NEVER delete it, nor the
# agent/platform bundles other deploys depend on — it only cleans the Image
# Builder build logs it wrote, which land under this prefix.
IB_LOG_PREFIX = "image-builder-logs/"

# Default IAM role + profile name for the Image Builder build instance.
# These are created outside of CDK (see image-builder/ README). Override
# via the ib_role_name / ib_profile_name parameters if your account uses
# a different name.
DEFAULT_IB_ROLE_NAME = "safe-agents-base-imagebuilder"
DEFAULT_IB_PROFILE_NAME = "safe-agents-base-imagebuilder"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def bake_teardown(
    aws: AWSInterface,
    environment: str,
    *,
    ib_role_name: str = DEFAULT_IB_ROLE_NAME,
    ib_profile_name: str = DEFAULT_IB_PROFILE_NAME,
    ib_resource_prefix: str = IB_RESOURCE_PREFIX,
    ami_tag_filter: Optional[dict[str, str]] = None,
) -> dict:
    """Remove all bake artifacts for one bake cycle. Idempotent.

    Parameters
    ----------
    aws:
        AWSInterface implementation (LiveAWS for real teardown; FakeAWS in tests).
    environment:
        Deployment environment (development | staging | production). Selects the
        deploy bucket to empty and delete.
    ib_role_name:
        IAM role name for the Image Builder build instance. Defaults to
        "safe-agents-base-imagebuilder".
    ib_profile_name:
        IAM instance profile name for the Image Builder build instance. Defaults
        to "safe-agents-base-imagebuilder".
    ib_resource_prefix:
        Name prefix used to discover Image Builder resources (pipeline / recipe /
        infra-config / dist-config / component). Defaults to "safe-agents-base".
    ami_tag_filter:
        Tag filter dict used to find base AMIs. Defaults to
        {"safe-agents:ami": "base"}.

    Returns
    -------
    dict with the following keys (all are lists of ARNs / IDs unless noted):
        amis_deregistered         — AMI IDs deregistered
        amis_already_gone         — AMI IDs not found (already gone)
        snapshots_deleted         — EBS snapshot IDs deleted
        snapshots_already_gone    — snapshot IDs not found
        ib_pipelines_deleted      — Image Builder pipeline ARNs deleted
        ib_images_deleted         — Image Builder image build-version ARNs deleted
        ib_recipes_deleted        — recipe ARNs deleted
        ib_infra_configs_deleted  — infrastructure-config ARNs deleted
        ib_dist_configs_deleted   — distribution-config ARNs deleted
        ib_components_deleted     — component build-version ARNs deleted
        bucket_log_objects_deleted — int: number of Image Builder log objects
                                     removed from the (floor-owned) deploy bucket.
                                     The bucket itself and the deploy bundles are
                                     never touched (StateStack owns the bucket).
        ib_profile_removed        — bool: True if the IB instance profile was removed
        ib_role_managed_policies_detached — list of policy ARNs detached
        ib_role_deleted           — bool: True if the IB role was deleted
        ib_role_already_gone      — bool: True if the IB role was not found
    """
    tag_filter = ami_tag_filter if ami_tag_filter is not None else AMI_TAG_FILTER
    report: dict = {
        "amis_deregistered": [],
        "amis_already_gone": [],
        "snapshots_deleted": [],
        "snapshots_already_gone": [],
        "ib_pipelines_deleted": [],
        "ib_images_deleted": [],
        "ib_recipes_deleted": [],
        "ib_infra_configs_deleted": [],
        "ib_dist_configs_deleted": [],
        "ib_components_deleted": [],
        "bucket_log_objects_deleted": 0,
        "ib_profile_removed": False,
        "ib_role_managed_policies_detached": [],
        "ib_role_deleted": False,
        "ib_role_already_gone": False,
    }

    _teardown_ib_pipeline(aws, ib_resource_prefix, report)
    _teardown_ib_images(aws, ib_resource_prefix, report)
    _teardown_ib_recipe(aws, ib_resource_prefix, report)
    _teardown_ib_dist_config(aws, ib_resource_prefix, report)
    _teardown_ib_infra_config(aws, ib_resource_prefix, report)
    _teardown_ib_components(aws, ib_resource_prefix, report)
    _teardown_amis(aws, tag_filter, report)
    _teardown_bucket(aws, environment, report)
    _teardown_ib_iam(aws, ib_role_name, ib_profile_name, report)

    return report


# ---------------------------------------------------------------------------
# Internal teardown steps
# ---------------------------------------------------------------------------

def _teardown_ib_pipeline(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete the Image Builder pipeline."""
    pipelines = aws.list_imagebuilder_pipelines(prefix)
    for pipeline in pipelines:
        arn = pipeline["arn"]
        deleted = aws.delete_imagebuilder_pipeline(arn)
        if deleted:
            logger.info("Deleted Image Builder pipeline: %s", arn)
            report["ib_pipelines_deleted"].append(arn)
        else:
            logger.debug("Image Builder pipeline already gone: %s", arn)


def _teardown_ib_images(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete all Image Builder image build versions for this pipeline.

    Must run before the recipe or component can be deleted.
    """
    version_arns = aws.list_imagebuilder_images(prefix)
    for version_arn in version_arns:
        build_arns = aws.list_imagebuilder_image_build_versions(version_arn)
        for build_arn in build_arns:
            deleted = aws.delete_imagebuilder_image(build_arn)
            if deleted:
                logger.info("Deleted Image Builder image build version: %s", build_arn)
                report["ib_images_deleted"].append(build_arn)
            else:
                logger.debug("Image Builder image build version already gone: %s", build_arn)


def _teardown_ib_recipe(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete Image Builder image recipes."""
    recipe_arns = aws.list_imagebuilder_recipes(prefix)
    for arn in recipe_arns:
        deleted = aws.delete_imagebuilder_recipe(arn)
        if deleted:
            logger.info("Deleted Image Builder recipe: %s", arn)
            report["ib_recipes_deleted"].append(arn)
        else:
            logger.debug("Image Builder recipe already gone: %s", arn)


def _teardown_ib_dist_config(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete Image Builder distribution configurations."""
    dc_arns = aws.list_imagebuilder_dist_configs(prefix)
    for arn in dc_arns:
        deleted = aws.delete_imagebuilder_dist_config(arn)
        if deleted:
            logger.info("Deleted Image Builder dist-config: %s", arn)
            report["ib_dist_configs_deleted"].append(arn)
        else:
            logger.debug("Image Builder dist-config already gone: %s", arn)


def _teardown_ib_infra_config(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete Image Builder infrastructure configurations."""
    iac_arns = aws.list_imagebuilder_infra_configs(prefix)
    for arn in iac_arns:
        deleted = aws.delete_imagebuilder_infra_config(arn)
        if deleted:
            logger.info("Deleted Image Builder infra-config: %s", arn)
            report["ib_infra_configs_deleted"].append(arn)
        else:
            logger.debug("Image Builder infra-config already gone: %s", arn)


def _teardown_ib_components(
    aws: AWSInterface, prefix: str, report: dict
) -> None:
    """Delete Image Builder component build versions.

    Sharp edge: must call list_imagebuilder_component_build_versions() to get
    the build-version ARNs; delete_imagebuilder_component() refuses the version
    ARN (it requires the build-version ARN).
    """
    version_arns = aws.list_imagebuilder_components(prefix)
    for version_arn in version_arns:
        build_arns = aws.list_imagebuilder_component_build_versions(version_arn)
        for build_arn in build_arns:
            deleted = aws.delete_imagebuilder_component(build_arn)
            if deleted:
                logger.info("Deleted Image Builder component build version: %s", build_arn)
                report["ib_components_deleted"].append(build_arn)
            else:
                logger.debug(
                    "Image Builder component build version already gone: %s", build_arn
                )


def _teardown_amis(
    aws: AWSInterface, tag_filter: dict[str, str], report: dict
) -> None:
    """Deregister base AMIs and delete their backing snapshots."""
    images = aws.describe_images(tag_filter)
    for image in images:
        image_id = image["image_id"]
        # Collect snapshot IDs before deregistering (they become invisible after).
        snapshot_ids = aws.describe_image_snapshots(image_id)
        deregistered = aws.deregister_image(image_id)
        if deregistered:
            logger.info("Deregistered AMI: %s", image_id)
            report["amis_deregistered"].append(image_id)
        else:
            logger.debug("AMI already gone: %s", image_id)
            report["amis_already_gone"].append(image_id)

        for snap_id in snapshot_ids:
            deleted = aws.delete_snapshot(snap_id)
            if deleted:
                logger.info("Deleted snapshot: %s (was backing %s)", snap_id, image_id)
                report["snapshots_deleted"].append(snap_id)
            else:
                logger.debug("Snapshot already gone: %s", snap_id)
                report["snapshots_already_gone"].append(snap_id)


def _teardown_bucket(
    aws: AWSInterface, environment: str, report: dict
) -> None:
    """Remove only this bake's Image Builder log objects from the deploy bucket.

    The deploy bucket is shared floor infrastructure owned by the State stack, so
    a bake teardown neither deletes the bucket nor the agent/platform deploy
    bundles other deploys rely on — it cleans only the ``image-builder-logs/``
    objects this bake produced.
    """
    bucket_name = DEPLOY_BUCKET_TEMPLATE.format(environment=environment)
    log_keys = [
        k for k in aws.list_bucket_objects(bucket_name) if k.startswith(IB_LOG_PREFIX)
    ]
    if log_keys:
        deleted_count = aws.delete_objects(bucket_name, log_keys)
        report["bucket_log_objects_deleted"] = deleted_count
        logger.info(
            "Deleted %d Image Builder log objects from s3://%s/%s",
            deleted_count, bucket_name, IB_LOG_PREFIX,
        )


def _teardown_ib_iam(
    aws: AWSInterface,
    role_name: str,
    profile_name: str,
    report: dict,
) -> None:
    """Remove the Image Builder IAM instance profile and role.

    Sequence:
        1. delete_instance_profile — removes the profile (which also removes
           role associations) using the existing interface method.
        2. Detach managed policies from the role.
        3. Delete inline policies from the role (reuses delete_role_policy).
        4. delete_role.
    """
    # 1. Instance profile (reuse the existing shared method)
    removed = aws.delete_instance_profile(profile_name)
    report["ib_profile_removed"] = removed
    if removed:
        logger.info("Removed Image Builder instance profile: %s", profile_name)
    else:
        logger.debug("Image Builder instance profile already gone: %s", profile_name)

    # 2. Detach managed policies
    managed_arns = aws.list_attached_role_policies(role_name)
    if not managed_arns:
        # Role not found or no managed policies — check if role exists at all
        inline_names = aws.list_role_inline_policy_names(role_name)
        if not inline_names:
            # Role is absent; skip role deletion.
            report["ib_role_already_gone"] = True
            logger.debug("Image Builder role not found (already gone): %s", role_name)
            return

    for policy_arn in managed_arns:
        aws.detach_role_managed_policy(role_name, policy_arn)
        report["ib_role_managed_policies_detached"].append(policy_arn)
        logger.info(
            "Detached managed policy %s from role %s", policy_arn, role_name
        )

    # 3. Delete inline policies
    inline_names = aws.list_role_inline_policy_names(role_name)
    for policy_name in inline_names:
        aws.delete_role_policy(role_name, policy_name)
        logger.info("Deleted inline policy %r from role %s", policy_name, role_name)

    # 4. Delete the role
    deleted = aws.delete_role(role_name)
    if deleted:
        logger.info("Deleted Image Builder role: %s", role_name)
        report["ib_role_deleted"] = True
    else:
        logger.debug("Image Builder role already gone: %s", role_name)
        report["ib_role_already_gone"] = True
