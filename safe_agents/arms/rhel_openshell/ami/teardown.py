"""
rhel_bake_teardown — remove all artifacts left by a rhel-openshell Image Builder
bake cycle (sa#109).

The teardown ENGINE is shared: it is the same idempotent, deletion-ordered
``bake_teardown`` the EC2 arm uses (arms.ec2.ami.teardown), which is fully
parameterized by resource prefix / AMI tag filter / IB role+profile names. This
module only supplies the RHEL-specific constants and a thin wrapper, so the RHEL
bakery inherits every sharp edge the EC2 teardown already learned (component
deletion by BUILD-VERSION ARN, deploy bucket never deleted, etc.) without
duplicating the logic.

Naming conventions (load-bearing — must match image-builder/ config files):
    AMI tag filter:           {"safe-agents:ami": "base-rhel"}
    Image Builder prefix:     "safe-agents-base-rhel"
    Pipeline name:            "safe-agents-base-rhel-pipeline"
    Recipe name:              "safe-agents-base-rhel"
    Infra-config name:        "safe-agents-base-rhel-infra"
    Dist-config name:         "safe-agents-base-rhel-dist"
    Component name:           "safe-agents-base-rhel"
    IB role (conventional):   "safe-agents-base-rhel-imagebuilder"
    IB profile (conventional):"safe-agents-base-rhel-imagebuilder"
"""
from __future__ import annotations

from typing import Optional

from safe_agents.arms.ec2.ami.teardown import bake_teardown
from safe_agents.pipeline.aws_interface import AWSInterface

# ---------------------------------------------------------------------------
# RHEL bake resource-name constants (must match image-builder/ config files)
# ---------------------------------------------------------------------------

# AMI tag that identifies every RHEL base AMI baked by this pipeline. Distinct
# from the EC2 arm's "base" so provision + teardown never cross wires.
AMI_TAG_FILTER: dict[str, str] = {"safe-agents:ami": "base-rhel"}

# Common name prefix for all RHEL Image Builder resources.
IB_RESOURCE_PREFIX = "safe-agents-base-rhel"

# Default IAM role + profile name for the RHEL Image Builder build instance.
DEFAULT_IB_ROLE_NAME = "safe-agents-base-rhel-imagebuilder"
DEFAULT_IB_PROFILE_NAME = "safe-agents-base-rhel-imagebuilder"


def rhel_bake_teardown(
    aws: AWSInterface,
    environment: str,
    *,
    ib_role_name: str = DEFAULT_IB_ROLE_NAME,
    ib_profile_name: str = DEFAULT_IB_PROFILE_NAME,
    ib_resource_prefix: str = IB_RESOURCE_PREFIX,
    ami_tag_filter: Optional[dict[str, str]] = None,
) -> dict:
    """Remove all RHEL bake artifacts for one bake cycle. Idempotent.

    Thin wrapper over the shared ``bake_teardown`` with RHEL constants. See that
    function for the full report-dict shape and deletion ordering.
    """
    return bake_teardown(
        aws,
        environment,
        ib_role_name=ib_role_name,
        ib_profile_name=ib_profile_name,
        ib_resource_prefix=ib_resource_prefix,
        ami_tag_filter=ami_tag_filter if ami_tag_filter is not None else AMI_TAG_FILTER,
    )
