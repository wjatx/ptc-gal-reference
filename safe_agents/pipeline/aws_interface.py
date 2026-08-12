"""
AWS interface — isolates boto3 calls behind an injectable abstract base so the
pipeline logic is unit-testable with no live AWS.

Pattern re-derived from a development harness:
    instance_id_for_stack  ← _pipeline-lib.sh::instance_id_for_stack
    ssm_run_command        ← _pipeline-lib.sh::ssm_run_as_dev (base64-over-SSM)
    get_secret / put_secret ← seed-agent secret store calls

LiveAWS: real boto3; all clients are created lazily (no import at module load).
FakeAWS: in-memory stub for unit tests; records every call for assertions.
"""
from __future__ import annotations

import abc
import logging
import time as _time
from typing import Optional

logger = logging.getLogger(__name__)


class IamProfileNotReadyError(RuntimeError):
    """Raised when RunInstances fails because the IAM instance profile has not
    yet propagated (IAM eventual-consistency race). Callers should retry with
    bounded backoff. Maps to the AWS error "Invalid IAM Instance Profile ARN".
    """


class SchedulerRoleNotReadyError(RuntimeError):
    """Raised when EventBridge Scheduler CreateSchedule fails because the just-created
    scheduler role's trust policy has not yet propagated (IAM eventual-consistency race).
    Callers should retry with bounded backoff. Maps to the AWS ValidationException
    "The execution role you provide must allow AWS EventBridge Scheduler to assume the role".
    """


class AWSInterface(abc.ABC):
    """Abstract interface for all AWS calls the pipeline makes."""

    @abc.abstractmethod
    def get_secret(self, secret_id: str) -> Optional[str]:
        """Return the secret string value, or None if not found / access denied."""

    @abc.abstractmethod
    def put_secret(self, secret_id: str, value: str) -> None:
        """Create or update a Secrets Manager secret (upsert semantics)."""

    @abc.abstractmethod
    def instance_id_for_stack(self, stack_name: str) -> Optional[str]:
        """Return the EC2 instance id for the 'Instance' resource in a CF stack."""

    @abc.abstractmethod
    def ssm_run_command(
        self, instance_id: str, command: str, *, timeout: int = 60
    ) -> tuple[int, str]:
        """Run a shell command on an instance via SSM. Returns (exit_code, output)."""

    @abc.abstractmethod
    def get_ssm_param(self, name: str) -> Optional[str]:
        """Return an SSM Parameter Store value, or None if not found.

        Used by arm adapters to resolve infra exports (agent-role-arn,
        agent-sg-id, agent-subnet-ids, agent-runs-table-arn) from the paths
        published by infra/lib/naming.ts: /safe-agents/{env}/{key}.
        """

    @abc.abstractmethod
    def run_instances(
        self,
        *,
        name: str,
        image_id: str,
        instance_type: str,
        iam_instance_profile_arn: str,
        security_group_ids: list,
        subnet_id: str,
        user_data_b64: str,
        tags: dict,
        block_device_mappings: Optional[list] = None,
    ) -> str:
        """Launch an EC2 instance with the given parameters. Returns the instance ID.

        Used by arm adapters (ec2, rhel-openshell) to provision agent hosts.
        All parameters are keyword-only to prevent positional-argument mistakes.

        Parameters
        ----------
        name:
            Agent name; used to derive the instance Name tag.
        image_id:
            AMI ID (e.g. arm64 Amazon Linux 2023 resolved via SSM).
        instance_type:
            EC2 instance type (e.g. "t4g.small", "m7i.xlarge").
        iam_instance_profile_arn:
            ARN of the agentRole instance profile (imported from IdentityStack).
        security_group_ids:
            List of security group IDs; the agentSG from NetworkStack goes here.
        subnet_id:
            The subnet ID to launch the instance in.
        user_data_b64:
            Base64-encoded cloud-init user-data (rendered from user-data.sh.tmpl).
        tags:
            Key-value tags applied to the instance.
        block_device_mappings:
            Optional list of block device mapping dicts. When None (default), the
            AMI's block device mapping is used unchanged. Pass a list to override
            (e.g. the rhel-openshell arm sets /dev/sda1 to 100 GB gp3).

        Returns
        -------
        EC2 instance ID string (e.g. "i-0abc123def456789a").
        """

    # -------------------------------------------------------------------------
    # EC2 lifecycle (teardown)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def describe_instances_by_tags(self, tags: dict[str, str]) -> list[dict]:
        """Return running/stopped instances whose tags are a superset of `tags`.

        Each entry is a dict with at least {"instance_id": str, "state": str}.
        Terminated instances are excluded. Used by teardown to discover what
        provision created (rather than relying on saved local state).
        """

    @abc.abstractmethod
    def terminate_instances(self, instance_ids: list[str]) -> list[str]:
        """Terminate the given instances. Returns the IDs that were actually
        terminated (i.e. were not already in a terminal state)."""

    @abc.abstractmethod
    def describe_images(self, tag_filters: dict[str, str]) -> list[dict]:
        """Return AMI images owned by this account matching all given tag filters.

        Each entry is a dict with at least:
            {"image_id": str, "tags": dict[str, str], "creation_date": str}

        Used by the EC2 arm to find the newest prebuilt base AMI (tagged
        safe-agents:ami=base) rather than resolving a public SSM parameter.
        """

    @abc.abstractmethod
    def describe_images_by_owner_name(
        self, owner_id: str, name_pattern: str
    ) -> list[dict]:
        """Return AMI images by owner account ID and name glob (for marketplace AMIs).

        Each entry is a dict with at least:
            {"image_id": str, "name": str, "creation_date": str}

        Used by the rhel-openshell arm to look up RHEL 9 marketplace AMIs by
        Red Hat's owner ID (309956199498) and a name pattern, since those AMIs
        are not tagged with safe-agents bakery tags.

        To refresh the RHEL 9 AMI for a region:
            aws ec2 describe-images --owners 309956199498 \\
                --filters "Name=name,Values=RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3" \\
                --query "sort_by(Images, &CreationDate)[-1].{id:ImageId,name:Name}" \\
                --output table
        """

    # -------------------------------------------------------------------------
    # IAM — per-agent instance profile + inline policy (teardown)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def get_instance_profile(self, profile_name: str) -> Optional[dict]:
        """Return profile info for an existing instance profile, or None if not found.

        The returned dict contains:
            "arn"   — instance profile ARN (str)
            "roles" — role names currently attached (list[str])

        Used by ensure_foundation to decide whether to create or reuse the profile,
        and by _wait_for_iam_propagation to poll until the role is visible.
        """

    @abc.abstractmethod
    def describe_ssm_instance_information(self, instance_id: str) -> Optional[str]:
        """Return the SSM PingStatus for an instance, or None if not registered with SSM.

        Possible return values: "Online", "Offline", "ConnectionLost", None.
        Used by wait_for_ssm_online to poll until the instance is SSM-managed.
        """

    @abc.abstractmethod
    def create_instance_profile(self, name: str, tags: dict) -> str:
        """Create an IAM instance profile with the given name and tags.

        Returns the instance profile ARN.
        """

    @abc.abstractmethod
    def add_role_to_instance_profile(self, profile_name: str, role_name: str) -> None:
        """Associate an IAM role with an instance profile.

        Idempotent: if the role is already attached, this is a no-op.
        """

    @abc.abstractmethod
    def delete_instance_profile(self, profile_name: str) -> bool:
        """Remove all roles from the instance profile then delete it.

        Idempotent: returns True if the profile existed and was removed,
        False if it was not found (already-gone).
        """

    @abc.abstractmethod
    def put_role_policy(
        self, role_name: str, policy_name: str, policy_document: dict
    ) -> None:
        """Attach or replace an inline policy on an IAM role."""

    @abc.abstractmethod
    def delete_role_policy(self, role_name: str, policy_name: str) -> bool:
        """Delete an inline policy from an IAM role.

        Idempotent: returns True if the policy existed and was removed,
        False if it was not found (already-gone).
        """

    # -------------------------------------------------------------------------
    # AMI deregistration + snapshot cleanup (bake teardown)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def describe_image_snapshots(self, image_id: str) -> list[str]:
        """Return the EBS snapshot IDs backing an AMI (to delete after deregistering).

        Returns an empty list if the image is not found.
        """

    @abc.abstractmethod
    def deregister_image(self, image_id: str) -> bool:
        """Deregister an AMI.

        Idempotent: returns True if the image was deregistered, False if already gone.
        """

    @abc.abstractmethod
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete an EBS snapshot.

        Idempotent: returns True if the snapshot was deleted, False if already gone.
        """

    # -------------------------------------------------------------------------
    # Image Builder teardown
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def list_imagebuilder_pipelines(self, name_prefix: str) -> list[dict]:
        """Return Image Builder pipelines whose name starts with name_prefix.

        Each entry: {"arn": str, "name": str}.
        """

    @abc.abstractmethod
    def delete_imagebuilder_pipeline(self, arn: str) -> bool:
        """Delete an Image Builder pipeline. Idempotent (returns False if already gone)."""

    @abc.abstractmethod
    def list_imagebuilder_images(self, name_prefix: str) -> list[str]:
        """Return image VERSION ARNs for images owned by this account whose name
        starts with name_prefix.

        These are NOT build-version ARNs — callers must call
        list_imagebuilder_image_build_versions() to get deletable ARNs.
        """

    @abc.abstractmethod
    def list_imagebuilder_image_build_versions(self, image_version_arn: str) -> list[str]:
        """Return build-version ARNs for a given image version ARN.

        delete_imagebuilder_image() takes these ARNs (not the version ARN).
        """

    @abc.abstractmethod
    def delete_imagebuilder_image(self, build_version_arn: str) -> bool:
        """Delete an Image Builder image build version. Idempotent."""

    @abc.abstractmethod
    def list_imagebuilder_recipes(self, name_prefix: str) -> list[str]:
        """Return image recipe ARNs whose name starts with name_prefix."""

    @abc.abstractmethod
    def delete_imagebuilder_recipe(self, arn: str) -> bool:
        """Delete an Image Builder image recipe. Idempotent."""

    @abc.abstractmethod
    def list_imagebuilder_infra_configs(self, name_prefix: str) -> list[str]:
        """Return infrastructure configuration ARNs whose name starts with name_prefix."""

    @abc.abstractmethod
    def delete_imagebuilder_infra_config(self, arn: str) -> bool:
        """Delete an Image Builder infrastructure configuration. Idempotent."""

    @abc.abstractmethod
    def list_imagebuilder_dist_configs(self, name_prefix: str) -> list[str]:
        """Return distribution configuration ARNs whose name starts with name_prefix."""

    @abc.abstractmethod
    def delete_imagebuilder_dist_config(self, arn: str) -> bool:
        """Delete an Image Builder distribution configuration. Idempotent."""

    @abc.abstractmethod
    def list_imagebuilder_components(self, name_prefix: str) -> list[str]:
        """Return component VERSION ARNs owned by this account whose name starts
        with name_prefix.

        These are NOT build-version ARNs — callers must call
        list_imagebuilder_component_build_versions() to get deletable ARNs.
        Sharp edge: delete_imagebuilder_component() requires build-version ARNs.
        """

    @abc.abstractmethod
    def list_imagebuilder_component_build_versions(self, version_arn: str) -> list[str]:
        """Return build-version ARNs for a given component version ARN.

        Sharp edge: delete_imagebuilder_component() requires these ARNs, NOT the
        version ARN passed into this method.
        """

    @abc.abstractmethod
    def delete_imagebuilder_component(self, build_version_arn: str) -> bool:
        """Delete an Image Builder component build version.

        Idempotent. Must be called with a BUILD-VERSION ARN (from
        list_imagebuilder_component_build_versions), not a version ARN.
        """

    # -------------------------------------------------------------------------
    # S3 teardown (deploy bucket)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def put_object(self, bucket_name: str, key: str, body: "str | bytes") -> None:
        """Upload an object to a bucket (create/overwrite).

        Used by arm adapters to stage box/agent code assets in the deploy bucket for
        S3-delivered boot (the ec2-woken box copies its drain-loop assets from S3 via the
        isolated subnet's S3 gateway endpoint, rather than embedding them in user-data —
        user-data has a 16 KB base64 cap). `body` may be str (utf-8 encoded) or bytes.
        """

    @abc.abstractmethod
    def list_bucket_objects(self, bucket_name: str) -> list[str]:
        """Return all object keys in a bucket.

        Returns an empty list if the bucket is not found (already-gone).
        """

    @abc.abstractmethod
    def delete_objects(self, bucket_name: str, keys: list[str]) -> int:
        """Delete the given object keys from a bucket. Returns the count deleted."""

    @abc.abstractmethod
    def delete_bucket(self, bucket_name: str) -> bool:
        """Delete an (empty) bucket.

        Idempotent: returns True if the bucket was deleted, False if already gone.
        """

    # -------------------------------------------------------------------------
    # IAM role management (for Image Builder role teardown)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def list_attached_role_policies(self, role_name: str) -> list[str]:
        """Return ARNs of managed policies attached to the role.

        Returns an empty list if the role is not found.
        """

    @abc.abstractmethod
    def detach_role_managed_policy(self, role_name: str, policy_arn: str) -> bool:
        """Detach a managed policy from a role.

        Idempotent: returns True if detached, False if already not attached.
        """

    @abc.abstractmethod
    def list_role_inline_policy_names(self, role_name: str) -> list[str]:
        """Return names of inline policies on the role.

        Returns an empty list if the role is not found.
        """

    @abc.abstractmethod
    def delete_role(self, role_name: str) -> bool:
        """Delete an IAM role (caller must detach all policies first).

        Idempotent: returns True if the role was deleted, False if already gone.
        """

    # -------------------------------------------------------------------------
    # IAM — per-agent role creation (Fargate arm; sa#36)
    # -------------------------------------------------------------------------
    #
    # The Fargate arm is the first arm that CREATES per-agent IAM roles (task
    # role + execution role + scheduler-invoke role), each with its own
    # trust policy, rather than reusing the IdentityStack base agentRole via an
    # instance profile (the EC2/RHEL pattern). These methods support that.

    @abc.abstractmethod
    def create_role(
        self, role_name: str, assume_role_policy_document: dict, tags: dict
    ) -> str:
        """Create an IAM role with the given trust (assume-role) policy + tags.

        Returns the role ARN. Idempotent: if a role with this name already
        exists, returns its ARN without modifying the trust policy (the caller
        owns the name via the deterministic per-agent naming convention).
        """

    @abc.abstractmethod
    def get_role(self, role_name: str) -> Optional[dict]:
        """Return role info for an existing role, or None if not found.

        The returned dict contains at least:
            "arn"                 — role ARN (str)
            "assume_role_policy"  — the trust policy document (dict)
        """

    @abc.abstractmethod
    def attach_role_managed_policy(self, role_name: str, policy_arn: str) -> None:
        """Attach an AWS-managed policy (by ARN) to a role.

        Idempotent: a no-op if the policy is already attached. Used by the
        Fargate execution role to attach AmazonECSTaskExecutionRolePolicy.
        """

    # -------------------------------------------------------------------------
    # ECS / Fargate (sa#36)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def register_task_definition(
        self,
        *,
        family: str,
        task_role_arn: str,
        execution_role_arn: str,
        cpu: str,
        memory: str,
        container_name: str,
        image: str,
        environment: dict[str, str],
        secrets: dict[str, str],
        log_configuration: dict,
        runtime_platform: dict,
        network_mode: str,
        tags: dict,
    ) -> str:
        """Register a Fargate task definition. Returns the task definition ARN.

        Parameters
        ----------
        family:
            Task definition family name (the per-agent naming convention).
        task_role_arn:
            ARN of the per-agent task role (the in-container identity).
        execution_role_arn:
            ARN of the execution role (ECR pull + log writes + secret injection).
        cpu / memory:
            Fargate task size as strings ("256" / "512").
        container_name / image:
            The single container's name and image URI (<ecr-repo>:tag).
        environment:
            Plain key→value container env (the runner contract; see provision.py).
        secrets:
            key→valueFrom map: the env var name → Secrets Manager secret ARN/name
            (injected by ECS at task start; never appears in plaintext env).
        log_configuration:
            awslogs driver config dict.
        runtime_platform:
            {"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"}.
        network_mode:
            "awsvpc" for Fargate.
        tags:
            Standard arm tag set (for auditing / secondary discovery).
        """

    @abc.abstractmethod
    def deregister_task_definition(self, task_definition: str) -> bool:
        """Deregister a task definition (by ARN or family:revision).

        Idempotent: returns True if it was active and got deregistered,
        False if it was not found / already inactive.
        """

    @abc.abstractmethod
    def list_task_definitions(self, family_prefix: str) -> list[str]:
        """Return ACTIVE task-definition ARNs whose family starts with family_prefix.

        Used by teardown to discover every revision registered for an agent's
        family (deterministic family name), so all are deregistered.
        """

    @abc.abstractmethod
    def run_task(
        self,
        *,
        cluster: str,
        task_definition: str,
        subnets: list[str],
        security_groups: list[str],
        assign_public_ip: bool,
        overrides: Optional[dict] = None,
    ) -> str:
        """Run a Fargate task once (RunTask). Returns the task ARN.

        Used by the capstone / smoke path to launch a one-off run of the agent
        task in the isolated agent subnets + SG, with public IP disabled.
        """

    @abc.abstractmethod
    def describe_task(self, cluster: str, task_arn: str) -> Optional[dict]:
        """Return status info for a running/stopped task, or None if not found.

        The returned dict contains at least:
            "last_status"  — e.g. "PROVISIONING" | "RUNNING" | "STOPPED"
            "exit_code"    — the container exit code (int) once STOPPED, else None
        """

    # -------------------------------------------------------------------------
    # EventBridge Scheduler (sa#36)
    # -------------------------------------------------------------------------

    @abc.abstractmethod
    def create_schedule(
        self,
        *,
        name: str,
        schedule_expression: str,
        timezone: str,
        target: dict,
        tags: Optional[dict] = None,
        state: str = "ENABLED",
    ) -> str:
        """Create an EventBridge Scheduler schedule. Returns the schedule ARN.

        Idempotent: if a schedule with this name exists, it is updated in place
        (upsert) and its ARN returned.

        Parameters
        ----------
        name:
            Schedule name (per-agent naming convention).
        schedule_expression:
            cron(...) or rate(...) expression (a provision parameter, no default
            baked into the arm).
        timezone:
            IANA timezone for the cron expression (a provision parameter).
        target:
            The target dict (ECS RunTask): cluster ARN, the scheduler-invoke
            role ARN, and EcsParameters (task def + awsvpc network config).
        tags:
            Standard arm tag set.
        state:
            Initial schedule state, 'ENABLED' or 'DISABLED' (AWS API default is ENABLED).
        """

    @abc.abstractmethod
    def get_schedule(self, name: str) -> Optional[dict]:
        """Return schedule info for an existing schedule, or None if not found."""

    @abc.abstractmethod
    def delete_schedule(self, name: str) -> bool:
        """Delete an EventBridge Scheduler schedule.

        Idempotent: returns True if it existed and was deleted, False if already gone.
        """


# ---------------------------------------------------------------------------
# Live implementation — real boto3, lazy clients
# ---------------------------------------------------------------------------

class LiveAWS(AWSInterface):
    """Real AWS. All boto3 clients are created on first use (lazy import)."""

    def __init__(self, region: str = "us-east-1") -> None:
        self._region = region
        self._sm = None   # secretsmanager client, populated lazily
        self._ssm = None  # ssm client, populated lazily
        self._cf = None   # cloudformation client, populated lazily
        self._ec2 = None  # ec2 client, populated lazily
        self._iam = None  # iam client, populated lazily

    # -- lazy client factories -----------------------------------------------

    def _secrets_client(self):
        if self._sm is None:
            import boto3  # noqa: PLC0415
            self._sm = boto3.client("secretsmanager", region_name=self._region)
        return self._sm

    def _ssm_client(self):
        if self._ssm is None:
            import boto3  # noqa: PLC0415
            self._ssm = boto3.client("ssm", region_name=self._region)
        return self._ssm

    def _cf_client(self):
        if self._cf is None:
            import boto3  # noqa: PLC0415
            self._cf = boto3.client("cloudformation", region_name=self._region)
        return self._cf

    def _ec2_client(self):
        if self._ec2 is None:
            import boto3  # noqa: PLC0415
            self._ec2 = boto3.client("ec2", region_name=self._region)
        return self._ec2

    def _iam_client(self):
        if self._iam is None:
            import boto3  # noqa: PLC0415
            self._iam = boto3.client("iam")  # IAM is global; no region param
        return self._iam

    # -- interface -----------------------------------------------------------

    def get_secret(self, secret_id: str) -> Optional[str]:
        try:
            resp = self._secrets_client().get_secret_value(SecretId=secret_id)
            return resp.get("SecretString")
        except Exception as exc:
            logger.warning("get_secret(%r) failed: %s", secret_id, exc)
            return None

    def put_secret(self, secret_id: str, value: str) -> None:
        sm = self._secrets_client()
        try:
            sm.put_secret_value(SecretId=secret_id, SecretString=value)
        except sm.exceptions.ResourceNotFoundException:
            sm.create_secret(Name=secret_id, SecretString=value)

    def instance_id_for_stack(self, stack_name: str) -> Optional[str]:
        """Re-derives instance_id_for_stack from _pipeline-lib.sh."""
        try:
            resp = self._cf_client().describe_stack_resource(
                StackName=stack_name,
                LogicalResourceId="Instance",
            )
            return resp["StackResourceDetail"]["PhysicalResourceId"]
        except Exception as exc:
            logger.warning("instance_id_for_stack(%r) failed: %s", stack_name, exc)
            return None

    def ssm_run_command(
        self, instance_id: str, command: str, *, timeout: int = 60
    ) -> tuple[int, str]:
        """
        Re-derives ssm_run_as_dev from _pipeline-lib.sh: sends the command
        to the instance via SSM and polls for completion.
        """
        ssm = self._ssm_client()
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=timeout,
        )
        command_id = resp["Command"]["CommandId"]

        # Poll until the command reaches a terminal state.
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            _time.sleep(2)
            inv = ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
            status = inv["Status"]
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                exit_code = 0 if status == "Success" else 1
                output = (
                    inv.get("StandardOutputContent", "")
                    + inv.get("StandardErrorContent", "")
                )
                return exit_code, output

        return 1, f"SSM command {command_id!r} did not complete within {timeout}s"

    def get_ssm_param(self, name: str) -> Optional[str]:
        """Return an SSM Parameter Store value, or None if not found."""
        try:
            resp = self._ssm_client().get_parameter(Name=name, WithDecryption=True)
            return resp["Parameter"]["Value"]
        except Exception as exc:
            logger.warning("get_ssm_param(%r) failed: %s", name, exc)
            return None

    def run_instances(
        self,
        *,
        name: str,
        image_id: str,
        instance_type: str,
        iam_instance_profile_arn: str,
        security_group_ids: list,
        subnet_id: str,
        user_data_b64: str,
        tags: dict,
        block_device_mappings: Optional[list] = None,
    ) -> str:
        """Launch an EC2 instance. Returns the instance ID.

        Raises IamProfileNotReadyError when the IAM instance profile has not yet
        propagated (the "Invalid IAM Instance Profile ARN" error from EC2). The
        caller retries with bounded backoff on this error.
        """
        ec2 = self._ec2_client()
        tag_specs = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
        kwargs: dict = dict(
            ImageId=image_id,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Arn": iam_instance_profile_arn},
            SecurityGroupIds=security_group_ids,
            SubnetId=subnet_id,
            UserData=user_data_b64,
            MetadataOptions={"HttpTokens": "required"},  # IMDSv2-only
            TagSpecifications=tag_specs,
        )
        if block_device_mappings:
            kwargs["BlockDeviceMappings"] = block_device_mappings
        try:
            resp = ec2.run_instances(**kwargs)
        except Exception as exc:
            if "Invalid IAM Instance Profile" in str(exc):
                raise IamProfileNotReadyError(str(exc)) from exc
            raise
        return resp["Instances"][0]["InstanceId"]

    def describe_images(self, tag_filters: dict[str, str]) -> list[dict]:
        """Return AMI images owned by this account matching all tag filters."""
        ec2 = self._ec2_client()
        filters = [{"Name": f"tag:{k}", "Values": [v]} for k, v in tag_filters.items()]
        try:
            resp = ec2.describe_images(Owners=["self"], Filters=filters)
        except Exception as exc:
            logger.warning("describe_images failed: %s", exc)
            return []
        result = []
        for image in resp.get("Images", []):
            image_tags = {t["Key"]: t["Value"] for t in image.get("Tags", [])}
            result.append({
                "image_id": image["ImageId"],
                "tags": image_tags,
                "creation_date": image.get("CreationDate", ""),
            })
        return result

    def describe_images_by_owner_name(
        self, owner_id: str, name_pattern: str
    ) -> list[dict]:
        """Return AMI images by owner account ID and name glob.

        Used by the rhel-openshell arm to look up RHEL marketplace AMIs
        (owner 309956199498) without needing safe-agents bakery tags.
        """
        ec2 = self._ec2_client()
        try:
            resp = ec2.describe_images(
                Owners=[owner_id],
                Filters=[{"Name": "name", "Values": [name_pattern]}],
            )
        except Exception as exc:
            logger.warning(
                "describe_images_by_owner_name(%r, %r) failed: %s",
                owner_id, name_pattern, exc,
            )
            return []
        result = []
        for image in resp.get("Images", []):
            result.append({
                "image_id": image["ImageId"],
                "name": image.get("Name", ""),
                "creation_date": image.get("CreationDate", ""),
            })
        return result

    # -------------------------------------------------------------------------
    # EC2 lifecycle (teardown)
    # -------------------------------------------------------------------------

    def describe_instances_by_tags(self, tags: dict[str, str]) -> list[dict]:
        """Return non-terminated instances matching all given tags."""
        ec2 = self._ec2_client()
        filters = [{"Name": f"tag:{k}", "Values": [v]} for k, v in tags.items()]
        filters.append({
            "Name": "instance-state-name",
            "Values": ["pending", "running", "stopping", "stopped"],
        })
        try:
            resp = ec2.describe_instances(Filters=filters)
        except Exception as exc:
            logger.warning("describe_instances_by_tags failed: %s", exc)
            return []
        result = []
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                result.append({
                    "instance_id": inst["InstanceId"],
                    "state": inst["State"]["Name"],
                })
        return result

    def terminate_instances(self, instance_ids: list[str]) -> list[str]:
        """Terminate instances. Returns IDs that were not already terminated."""
        if not instance_ids:
            return []
        ec2 = self._ec2_client()
        try:
            ec2.terminate_instances(InstanceIds=instance_ids)
        except Exception as exc:
            logger.warning("terminate_instances failed: %s", exc)
            return []
        return instance_ids  # return all requested IDs (they are now terminating)

    # -------------------------------------------------------------------------
    # IAM — per-agent instance profile + inline policy (teardown)
    # -------------------------------------------------------------------------

    def get_instance_profile(self, profile_name: str) -> Optional[dict]:
        """Return profile info dict (arn, roles) or None if not found."""
        iam = self._iam_client()
        try:
            resp = iam.get_instance_profile(InstanceProfileName=profile_name)
            profile = resp["InstanceProfile"]
            return {
                "arn": profile["Arn"],
                "roles": [r["RoleName"] for r in profile.get("Roles", [])],
            }
        except iam.exceptions.NoSuchEntityException:
            return None
        except Exception as exc:
            logger.warning("get_instance_profile(%r) failed: %s", profile_name, exc)
            return None

    def describe_ssm_instance_information(self, instance_id: str) -> Optional[str]:
        """Return the SSM PingStatus for an instance, or None if not registered."""
        ssm = self._ssm_client()
        try:
            resp = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            info_list = resp.get("InstanceInformationList", [])
            if not info_list:
                return None
            return info_list[0].get("PingStatus")
        except Exception as exc:
            logger.warning(
                "describe_ssm_instance_information(%r) failed: %s", instance_id, exc
            )
            return None

    def create_instance_profile(self, name: str, tags: dict) -> str:
        """Create a per-agent IAM instance profile. Returns the ARN."""
        iam = self._iam_client()
        tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
        resp = iam.create_instance_profile(InstanceProfileName=name, Tags=tag_list)
        return resp["InstanceProfile"]["Arn"]

    def add_role_to_instance_profile(self, profile_name: str, role_name: str) -> None:
        """Associate a role with an instance profile. Idempotent (no-op if already attached)."""
        iam = self._iam_client()
        try:
            iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        except Exception as exc:
            # LimitExceededException is raised when the role is already attached.
            if "LimitExceeded" in type(exc).__name__ or "already" in str(exc).lower():
                logger.debug(
                    "add_role_to_instance_profile: role %r already attached to %r (no-op)",
                    role_name, profile_name,
                )
            else:
                raise

    def delete_instance_profile(self, profile_name: str) -> bool:
        """Remove all roles from the profile then delete it. Idempotent."""
        iam = self._iam_client()
        try:
            resp = iam.get_instance_profile(InstanceProfileName=profile_name)
        except iam.exceptions.NoSuchEntityException:
            return False  # already gone
        for role in resp["InstanceProfile"].get("Roles", []):
            try:
                iam.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name, RoleName=role["RoleName"]
                )
            except Exception as exc:
                logger.warning(
                    "remove_role_from_instance_profile(%r, %r) failed: %s",
                    profile_name, role["RoleName"], exc,
                )
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False

    def put_role_policy(
        self, role_name: str, policy_name: str, policy_document: dict
    ) -> None:
        """Attach or replace an inline policy on an IAM role."""
        import json  # noqa: PLC0415
        self._iam_client().put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
        )

    def delete_role_policy(self, role_name: str, policy_name: str) -> bool:
        """Delete an inline policy from a role. Idempotent."""
        iam = self._iam_client()
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False

    # -------------------------------------------------------------------------
    # AMI deregistration + snapshot cleanup (bake teardown)
    # -------------------------------------------------------------------------

    def describe_image_snapshots(self, image_id: str) -> list[str]:
        """Return snapshot IDs backing an AMI."""
        ec2 = self._ec2_client()
        try:
            resp = ec2.describe_images(ImageIds=[image_id], Owners=["self"])
        except Exception as exc:
            logger.warning("describe_image_snapshots(%r) failed: %s", image_id, exc)
            return []
        snapshot_ids = []
        for image in resp.get("Images", []):
            for mapping in image.get("BlockDeviceMappings", []):
                snap = mapping.get("Ebs", {}).get("SnapshotId")
                if snap:
                    snapshot_ids.append(snap)
        return snapshot_ids

    def deregister_image(self, image_id: str) -> bool:
        """Deregister an AMI. Idempotent."""
        ec2 = self._ec2_client()
        try:
            ec2.deregister_image(ImageId=image_id)
            return True
        except Exception as exc:
            if "InvalidAMIID" in str(exc) or "does not exist" in str(exc).lower():
                return False
            logger.warning("deregister_image(%r) failed: %s", image_id, exc)
            return False

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete an EBS snapshot. Idempotent."""
        ec2 = self._ec2_client()
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return True
        except Exception as exc:
            if "InvalidSnapshot" in str(exc):
                return False
            logger.warning("delete_snapshot(%r) failed: %s", snapshot_id, exc)
            return False

    # -------------------------------------------------------------------------
    # Image Builder teardown
    # -------------------------------------------------------------------------

    def _ib_client(self):
        """Lazy Image Builder boto3 client."""
        if not hasattr(self, "_imagebuilder"):
            import boto3  # noqa: PLC0415
            self._imagebuilder = boto3.client("imagebuilder", region_name=self._region)
        return self._imagebuilder

    def list_imagebuilder_pipelines(self, name_prefix: str) -> list[dict]:
        """Return Image Builder pipelines whose name starts with name_prefix.

        LIVE-SHAPE: The imagebuilder API rejects '*' in filter values
        (allowed pattern: ^[0-9a-zA-Z./_ :,{}"-]{1,1024}$). Do not pass wildcard
        filters — fetch all and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_image_pipelines()
        except Exception as exc:
            logger.warning("list_imagebuilder_pipelines(%r) failed: %s", name_prefix, exc)
            return []
        return [
            {"arn": p["arn"], "name": p["name"]}
            for p in resp.get("imagePipelineList", [])
            if p["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_pipeline(self, arn: str) -> bool:
        """Delete an Image Builder pipeline. Idempotent."""
        ib = self._ib_client()
        try:
            ib.delete_image_pipeline(imagePipelineArn=arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_pipeline(%r) failed: %s", arn, exc)
            return False

    def list_imagebuilder_images(self, name_prefix: str) -> list[str]:
        """Return image version ARNs owned by this account whose name starts with name_prefix.

        LIVE-SHAPE: Wildcard is not allowed in imagebuilder filter values; fetch all
        owner=Self images and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_images(owner="Self")
        except Exception as exc:
            logger.warning("list_imagebuilder_images(%r) failed: %s", name_prefix, exc)
            return []
        return [
            v["arn"]
            for v in resp.get("imageVersionList", [])
            if v["name"].startswith(name_prefix)
        ]

    def list_imagebuilder_image_build_versions(self, image_version_arn: str) -> list[str]:
        """Return build-version ARNs for a given image version ARN."""
        ib = self._ib_client()
        try:
            resp = ib.list_image_build_versions(imageVersionArn=image_version_arn)
        except Exception as exc:
            logger.warning(
                "list_imagebuilder_image_build_versions(%r) failed: %s",
                image_version_arn, exc,
            )
            return []
        return [s["arn"] for s in resp.get("imageSummaryList", [])]

    def delete_imagebuilder_image(self, build_version_arn: str) -> bool:
        """Delete an Image Builder image build version. Idempotent."""
        ib = self._ib_client()
        try:
            ib.delete_image(imageBuildVersionArn=build_version_arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_image(%r) failed: %s", build_version_arn, exc)
            return False

    def list_imagebuilder_recipes(self, name_prefix: str) -> list[str]:
        """Return image recipe ARNs whose name starts with name_prefix.

        LIVE-SHAPE: Wildcard is not allowed in imagebuilder filter values; fetch all
        owner=Self recipes and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_image_recipes(owner="Self")
        except Exception as exc:
            logger.warning("list_imagebuilder_recipes(%r) failed: %s", name_prefix, exc)
            return []
        return [
            r["arn"]
            for r in resp.get("imageRecipeSummaryList", [])
            if r["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_recipe(self, arn: str) -> bool:
        """Delete an Image Builder image recipe. Idempotent."""
        ib = self._ib_client()
        try:
            ib.delete_image_recipe(imageRecipeArn=arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_recipe(%r) failed: %s", arn, exc)
            return False

    def list_imagebuilder_infra_configs(self, name_prefix: str) -> list[str]:
        """Return infrastructure configuration ARNs whose name starts with name_prefix.

        LIVE-SHAPE: Wildcard is not allowed in imagebuilder filter values; fetch all
        infra configs and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_infrastructure_configurations()
        except Exception as exc:
            logger.warning("list_imagebuilder_infra_configs(%r) failed: %s", name_prefix, exc)
            return []
        return [
            c["arn"]
            for c in resp.get("infrastructureConfigurationSummaryList", [])
            if c["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_infra_config(self, arn: str) -> bool:
        """Delete an Image Builder infrastructure configuration. Idempotent."""
        ib = self._ib_client()
        try:
            ib.delete_infrastructure_configuration(infrastructureConfigurationArn=arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_infra_config(%r) failed: %s", arn, exc)
            return False

    def list_imagebuilder_dist_configs(self, name_prefix: str) -> list[str]:
        """Return distribution configuration ARNs whose name starts with name_prefix.

        LIVE-SHAPE: Wildcard is not allowed in imagebuilder filter values; fetch all
        dist configs and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_distribution_configurations()
        except Exception as exc:
            logger.warning("list_imagebuilder_dist_configs(%r) failed: %s", name_prefix, exc)
            return []
        return [
            d["arn"]
            for d in resp.get("distributionConfigurationSummaryList", [])
            if d["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_dist_config(self, arn: str) -> bool:
        """Delete an Image Builder distribution configuration. Idempotent."""
        ib = self._ib_client()
        try:
            ib.delete_distribution_configuration(distributionConfigurationArn=arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_dist_config(%r) failed: %s", arn, exc)
            return False

    def list_imagebuilder_components(self, name_prefix: str) -> list[str]:
        """Return component VERSION ARNs owned by this account whose name starts with name_prefix.

        LIVE-SHAPE: Wildcard is not allowed in imagebuilder filter values; fetch all
        owner=Self components and filter by prefix in Python (see issue #89).
        """
        ib = self._ib_client()
        try:
            resp = ib.list_components(owner="Self")
        except Exception as exc:
            logger.warning("list_imagebuilder_components(%r) failed: %s", name_prefix, exc)
            return []
        return [
            c["arn"]
            for c in resp.get("componentVersionList", [])
            if c["name"].startswith(name_prefix)
        ]

    def list_imagebuilder_component_build_versions(self, version_arn: str) -> list[str]:
        """Return build-version ARNs for a given component version ARN.

        Sharp edge: these build-version ARNs (not the version ARN) are required
        by delete_imagebuilder_component().
        """
        ib = self._ib_client()
        try:
            resp = ib.list_component_build_versions(componentVersionArn=version_arn)
        except Exception as exc:
            logger.warning(
                "list_imagebuilder_component_build_versions(%r) failed: %s",
                version_arn, exc,
            )
            return []
        return [c["arn"] for c in resp.get("componentSummaryList", [])]

    def delete_imagebuilder_component(self, build_version_arn: str) -> bool:
        """Delete an Image Builder component build version. Idempotent.

        Must be called with a BUILD-VERSION ARN, not a version ARN.
        """
        ib = self._ib_client()
        try:
            ib.delete_component(componentBuildVersionArn=build_version_arn)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_imagebuilder_component(%r) failed: %s", build_version_arn, exc)
            return False

    # -------------------------------------------------------------------------
    # S3 teardown (deploy bucket)
    # -------------------------------------------------------------------------

    def _s3_client(self):
        """Lazy S3 boto3 client."""
        if not hasattr(self, "_s3"):
            import boto3  # noqa: PLC0415
            self._s3 = boto3.client("s3", region_name=self._region)
        return self._s3

    def put_object(self, bucket_name: str, key: str, body: "str | bytes") -> None:
        """Upload an object to a bucket (create/overwrite)."""
        s3 = self._s3_client()
        data = body.encode() if isinstance(body, str) else body
        s3.put_object(Bucket=bucket_name, Key=key, Body=data)

    def list_bucket_objects(self, bucket_name: str) -> list[str]:
        """Return all object keys in a bucket. Returns [] if bucket not found."""
        s3 = self._s3_client()
        keys: list[str] = []
        paginator = s3.get_paginator("list_objects_v2")
        try:
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get("Contents", []):
                    keys.append(obj["Key"])
        except Exception as exc:
            if "NoSuchBucket" in str(exc):
                return []
            logger.warning("list_bucket_objects(%r) failed: %s", bucket_name, exc)
            return []
        return keys

    def delete_objects(self, bucket_name: str, keys: list[str]) -> int:
        """Delete object keys from a bucket in batches of 1000. Returns count deleted."""
        if not keys:
            return 0
        s3 = self._s3_client()
        deleted_count = 0
        # S3 delete_objects accepts at most 1000 keys per call.
        batch_size = 1000
        for i in range(0, len(keys), batch_size):
            batch = keys[i : i + batch_size]
            objects = [{"Key": k} for k in batch]
            try:
                resp = s3.delete_objects(
                    Bucket=bucket_name, Delete={"Objects": objects, "Quiet": True}
                )
                deleted_count += len(batch) - len(resp.get("Errors", []))
            except Exception as exc:
                logger.warning("delete_objects batch failed: %s", exc)
        return deleted_count

    def delete_bucket(self, bucket_name: str) -> bool:
        """Delete an (empty) S3 bucket. Idempotent."""
        s3 = self._s3_client()
        try:
            s3.delete_bucket(Bucket=bucket_name)
            return True
        except Exception as exc:
            if "NoSuchBucket" in str(exc):
                return False
            logger.warning("delete_bucket(%r) failed: %s", bucket_name, exc)
            return False

    # -------------------------------------------------------------------------
    # IAM role management (for Image Builder role teardown)
    # -------------------------------------------------------------------------

    def list_attached_role_policies(self, role_name: str) -> list[str]:
        """Return ARNs of managed policies attached to the role. Returns [] if not found."""
        iam = self._iam_client()
        try:
            resp = iam.list_attached_role_policies(RoleName=role_name)
            return [p["PolicyArn"] for p in resp.get("AttachedPolicies", [])]
        except iam.exceptions.NoSuchEntityException:
            return []
        except Exception as exc:
            logger.warning("list_attached_role_policies(%r) failed: %s", role_name, exc)
            return []

    def detach_role_managed_policy(self, role_name: str, policy_arn: str) -> bool:
        """Detach a managed policy from a role. Idempotent."""
        iam = self._iam_client()
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False
        except Exception as exc:
            logger.warning(
                "detach_role_managed_policy(%r, %r) failed: %s", role_name, policy_arn, exc
            )
            return False

    def list_role_inline_policy_names(self, role_name: str) -> list[str]:
        """Return names of inline policies on the role. Returns [] if role not found."""
        iam = self._iam_client()
        try:
            resp = iam.list_role_policies(RoleName=role_name)
            return resp.get("PolicyNames", [])
        except iam.exceptions.NoSuchEntityException:
            return []
        except Exception as exc:
            logger.warning("list_role_inline_policy_names(%r) failed: %s", role_name, exc)
            return []

    def delete_role(self, role_name: str) -> bool:
        """Delete an IAM role (caller must detach all policies first). Idempotent."""
        iam = self._iam_client()
        try:
            iam.delete_role(RoleName=role_name)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False
        except Exception as exc:
            logger.warning("delete_role(%r) failed: %s", role_name, exc)
            return False

    # -------------------------------------------------------------------------
    # IAM — per-agent role creation (Fargate arm; sa#36)
    # -------------------------------------------------------------------------

    def create_role(
        self, role_name: str, assume_role_policy_document: dict, tags: dict
    ) -> str:
        """Create an IAM role with a trust policy + tags. Idempotent on name."""
        import json  # noqa: PLC0415
        iam = self._iam_client()
        existing = self.get_role(role_name)
        if existing is not None:
            return existing["arn"]
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
        return resp["Role"]["Arn"]

    def get_role(self, role_name: str) -> Optional[dict]:
        """Return role info (arn, assume_role_policy) or None if not found."""
        iam = self._iam_client()
        try:
            resp = iam.get_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            return None
        except Exception as exc:
            logger.warning("get_role(%r) failed: %s", role_name, exc)
            return None
        role = resp["Role"]
        return {
            "arn": role["Arn"],
            "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
        }

    def attach_role_managed_policy(self, role_name: str, policy_arn: str) -> None:
        """Attach an AWS-managed policy to a role. Idempotent."""
        iam = self._iam_client()
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except Exception as exc:
            if "already" in str(exc).lower():
                logger.debug(
                    "attach_role_managed_policy: %r already on %r (no-op)",
                    policy_arn, role_name,
                )
            else:
                raise

    # -------------------------------------------------------------------------
    # ECS / Fargate (sa#36)
    # -------------------------------------------------------------------------

    def _ecs_client(self):
        """Lazy ECS boto3 client."""
        if not hasattr(self, "_ecs"):
            import boto3  # noqa: PLC0415
            self._ecs = boto3.client("ecs", region_name=self._region)
        return self._ecs

    def register_task_definition(
        self,
        *,
        family: str,
        task_role_arn: str,
        execution_role_arn: str,
        cpu: str,
        memory: str,
        container_name: str,
        image: str,
        environment: dict[str, str],
        secrets: dict[str, str],
        log_configuration: dict,
        runtime_platform: dict,
        network_mode: str,
        tags: dict,
    ) -> str:
        """Register a Fargate task definition. Returns the task definition ARN."""
        ecs = self._ecs_client()
        container_def = {
            "name": container_name,
            "image": image,
            "essential": True,
            "environment": [
                {"name": k, "value": v} for k, v in environment.items()
            ],
            "secrets": [
                {"name": k, "valueFrom": v} for k, v in secrets.items()
            ],
            "logConfiguration": log_configuration,
        }
        resp = ecs.register_task_definition(
            family=family,
            taskRoleArn=task_role_arn,
            executionRoleArn=execution_role_arn,
            networkMode=network_mode,
            requiresCompatibilities=["FARGATE"],
            cpu=cpu,
            memory=memory,
            runtimePlatform=runtime_platform,
            containerDefinitions=[container_def],
            tags=[{"key": k, "value": v} for k, v in tags.items()],
        )
        return resp["taskDefinition"]["taskDefinitionArn"]

    def deregister_task_definition(self, task_definition: str) -> bool:
        """Deregister a task definition (ARN or family:revision). Idempotent."""
        ecs = self._ecs_client()
        try:
            ecs.deregister_task_definition(taskDefinition=task_definition)
            return True
        except Exception as exc:
            if "ClientException" in type(exc).__name__ or "not found" in str(exc).lower():
                return False
            logger.warning("deregister_task_definition(%r) failed: %s", task_definition, exc)
            return False

    def list_task_definitions(self, family_prefix: str) -> list[str]:
        """Return ACTIVE task-definition ARNs for a family prefix."""
        ecs = self._ecs_client()
        arns: list[str] = []
        try:
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(
                familyPrefix=family_prefix, status="ACTIVE"
            ):
                arns.extend(page.get("taskDefinitionArns", []))
        except Exception as exc:
            logger.warning("list_task_definitions(%r) failed: %s", family_prefix, exc)
            return []
        return arns

    def run_task(
        self,
        *,
        cluster: str,
        task_definition: str,
        subnets: list[str],
        security_groups: list[str],
        assign_public_ip: bool,
        overrides: Optional[dict] = None,
    ) -> str:
        """Run a Fargate task once. Returns the task ARN."""
        ecs = self._ecs_client()
        kwargs: dict = dict(
            cluster=cluster,
            taskDefinition=task_definition,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": subnets,
                    "securityGroups": security_groups,
                    "assignPublicIp": "ENABLED" if assign_public_ip else "DISABLED",
                }
            },
        )
        if overrides:
            kwargs["overrides"] = overrides
        resp = ecs.run_task(**kwargs)
        tasks = resp.get("tasks", [])
        if not tasks:
            failures = resp.get("failures", [])
            raise RuntimeError(f"run_task failed: {failures}")
        return tasks[0]["taskArn"]

    def describe_task(self, cluster: str, task_arn: str) -> Optional[dict]:
        """Return {last_status, exit_code} for a task, or None if not found."""
        ecs = self._ecs_client()
        try:
            resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        except Exception as exc:
            logger.warning("describe_task(%r) failed: %s", task_arn, exc)
            return None
        tasks = resp.get("tasks", [])
        if not tasks:
            return None
        task = tasks[0]
        exit_code = None
        for container in task.get("containers", []):
            if "exitCode" in container:
                exit_code = container["exitCode"]
                break
        return {"last_status": task.get("lastStatus"), "exit_code": exit_code}

    # -------------------------------------------------------------------------
    # EventBridge Scheduler (sa#36)
    # -------------------------------------------------------------------------

    def _scheduler_client(self):
        """Lazy EventBridge Scheduler boto3 client."""
        if not hasattr(self, "_scheduler"):
            import boto3  # noqa: PLC0415
            self._scheduler = boto3.client("scheduler", region_name=self._region)
        return self._scheduler

    def create_schedule(
        self,
        *,
        name: str,
        schedule_expression: str,
        timezone: str,
        target: dict,
        tags: Optional[dict] = None,
        state: str = "ENABLED",
    ) -> str:
        """Create (or update) an EventBridge Scheduler schedule. Returns the ARN."""
        sched = self._scheduler_client()
        kwargs: dict = dict(
            Name=name,
            ScheduleExpression=schedule_expression,
            ScheduleExpressionTimezone=timezone,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=target,
            State=state,
        )
        try:
            resp = sched.create_schedule(**kwargs)
            return resp["ScheduleArn"]
        except Exception as exc:
            if "ConflictException" in type(exc).__name__ or "already exists" in str(exc).lower():
                resp = sched.update_schedule(**kwargs)
                return resp["ScheduleArn"]
            # The scheduler role was just created; its trust policy may not have propagated.
            # Surface as a typed retryable error so the caller can back off (IAM race).
            if "assume the role" in str(exc).lower():
                raise SchedulerRoleNotReadyError(str(exc)) from exc
            raise

    def get_schedule(self, name: str) -> Optional[dict]:
        """Return schedule info or None if not found."""
        sched = self._scheduler_client()
        try:
            resp = sched.get_schedule(Name=name)
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return None
            logger.warning("get_schedule(%r) failed: %s", name, exc)
            return None
        return {
            "arn": resp.get("Arn"),
            "schedule_expression": resp.get("ScheduleExpression"),
            "timezone": resp.get("ScheduleExpressionTimezone"),
            "target": resp.get("Target"),
            "state": resp.get("State"),
        }

    def delete_schedule(self, name: str) -> bool:
        """Delete an EventBridge Scheduler schedule. Idempotent."""
        sched = self._scheduler_client()
        try:
            sched.delete_schedule(Name=name)
            return True
        except Exception as exc:
            if "ResourceNotFoundException" in type(exc).__name__:
                return False
            logger.warning("delete_schedule(%r) failed: %s", name, exc)
            return False


# ---------------------------------------------------------------------------
# Fake implementation — in-memory, no network, for unit tests
# ---------------------------------------------------------------------------

class FakeAWS(AWSInterface):
    """In-memory AWS stub for unit tests. Records every call for post-hoc assertion."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._ssm_params: dict[str, str] = {}
        # EC2 instances: instance_id -> {"tags": dict, "state": str}
        self._instances: dict[str, dict] = {}
        # IAM instance profiles: profile_name -> {"roles": list[str], "tags": dict}
        self._instance_profiles: dict[str, dict] = {}
        # IAM inline policies: (role_name, policy_name) -> policy_document dict
        self._role_policies: dict[tuple, dict] = {}
        # IAM roles: role_name -> {"attached_policies": list[str], "inline_policies": list[str]}
        self._iam_roles: dict[str, dict] = {}
        # AMI images: image_id -> {"tags": dict, "creation_date": str, "snapshot_ids": list[str]}
        # (Also kept in self._images for describe_images compatibility)
        self._amis: dict[str, dict] = {}
        # AMI images: list of {"image_id": str, "tags": dict, "creation_date": str}
        self._images: list[dict] = []
        # Marketplace AMIs (owner+name lookup, used by rhel-openshell arm):
        # list of {"image_id": str, "owner_id": str, "name": str, "creation_date": str}
        self._marketplace_images: list[dict] = []
        # Image Builder resources
        # Pipelines: pipeline_arn -> {"name": str}
        self._ib_pipelines: dict[str, dict] = {}
        # Image versions: version_arn -> list of build_version_arns
        self._ib_image_versions: dict[str, list[str]] = {}
        # Image build versions (deletable): build_version_arn -> True (present)
        self._ib_image_build_versions: set[str] = set()
        # Recipes: recipe_arn -> {"name": str}
        self._ib_recipes: dict[str, dict] = {}
        # Infra configs: iac_arn -> {"name": str}
        self._ib_infra_configs: dict[str, dict] = {}
        # Dist configs: dc_arn -> {"name": str}
        self._ib_dist_configs: dict[str, dict] = {}
        # Component versions: version_arn -> list of build_version_arns
        self._ib_component_versions: dict[str, list[str]] = {}
        # Component build versions (deletable): build_version_arn -> True (present)
        self._ib_component_build_versions: set[str] = set()
        # EBS snapshots: snapshot_id (flat set for fast membership checks across deregister)
        self._snapshots: set[str] = set()
        # S3 buckets: bucket_name -> {key: bytes}
        self._s3_buckets: dict[str, dict[str, bytes]] = {}
        # IAM created roles (Fargate arm): role_name -> {"arn","assume_role_policy","tags"}.
        # create_role also registers an entry in self._iam_roles so the shared
        # attach/detach/list/delete role methods operate on it consistently.
        self._created_roles: dict[str, dict] = {}
        # ECS task definitions: arn -> {"family","revision","status","tags",...full def}
        self._ecs_task_definitions: dict[str, dict] = {}
        # ECS family -> latest revision number (monotonic per family)
        self._ecs_family_revisions: dict[str, int] = {}
        # ECS tasks launched via run_task: task_arn -> {"cluster","task_definition",...}
        self._ecs_tasks: dict[str, dict] = {}
        # EventBridge Scheduler schedules: name -> {"arn","schedule_expression",...}
        self._schedules: dict[str, dict] = {}
        # EC2 instance state transition queue (for clean-start gate tests).
        # instance_id -> list of states; on each describe_instances_by_tags call that
        # matches the instance, the NEXT state is popped and applied AFTER results are
        # returned (so callers see the current state first, then it advances).
        self._instance_state_transitions: dict[str, list[str]] = {}
        # Set > 0 to simulate the IAM profile propagation race: run_instances will
        # raise IamProfileNotReadyError this many times before succeeding.
        self.run_instances_profile_error_count: int = 0
        # Set > 0 to simulate the scheduler-role trust-policy propagation race:
        # create_schedule raises SchedulerRoleNotReadyError this many times before succeeding.
        self.create_schedule_role_error_count: int = 0
        # IAM role-in-profile eventual-consistency simulation.
        # get_instance_profile returns an empty roles list this many times before
        # reflecting the real state (role visible after the counter reaches 0).
        self.iam_role_in_profile_after_n_polls: int = 0
        # If True, get_instance_profile always returns the profile without any roles
        # (simulates an IAM propagation that never converges).
        self.iam_role_never_in_profile: bool = False
        # Simulate profile mid-delete: get_instance_profile returns {"roles": []}
        # for this many calls, then auto-deletes the profile and returns None.
        # Used to test the clean-start IAM precondition gate.
        self.iam_profile_delete_countdown: int = 0
        # SSM Online status simulation.
        # describe_ssm_instance_information returns "Offline" this many times before
        # returning "Online" (counter decremented on each call, then returns Online).
        self.ssm_online_after_n_polls: int = 0
        # If True, describe_ssm_instance_information always returns None
        # (instance never registers with SSM — for the loud-failure test).
        self.ssm_never_online: bool = False
        # Each entry is a tuple: (method_name, *args)
        self.calls: list[tuple] = []

    # -- test helpers --------------------------------------------------------

    def seed_secret(self, secret_id: str, value: str) -> None:
        """Pre-populate a secret so get_secret returns it."""
        self._secrets[secret_id] = value

    def seed_ssm_param(self, name: str, value: str) -> None:
        """Pre-populate an SSM parameter so get_ssm_param returns it."""
        self._ssm_params[name] = value

    def seed_instance_with_transitions(
        self,
        instance_id: str,
        initial_state: str,
        transitions: list[str],
        tags: dict,
    ) -> None:
        """Pre-populate an instance with a sequence of state transitions.

        On each describe_instances_by_tags call that matches the instance, the
        NEXT state in the transitions list is applied AFTER the result is computed.
        This lets tests model "instance starts shutting-down, then terminates after
        N polls" without real AWS.

        Example — shutting-down for 1 poll then terminated:
            seed_instance_with_transitions("i-x", "shutting-down", ["terminated"], tags)
            # Call 1: returns [{"instance_id": "i-x", "state": "shutting-down"}],
            #         then transitions state to "terminated".
            # Call 2: state is "terminated" → excluded from results.
        """
        self._instances[instance_id] = {"tags": dict(tags), "state": initial_state}
        self._instance_state_transitions[instance_id] = list(transitions)

    def seed_marketplace_image(
        self, image_id: str, owner_id: str, name: str, creation_date: str = ""
    ) -> None:
        """Pre-populate a marketplace AMI so describe_images_by_owner_name can return it."""
        self._marketplace_images.append(
            {"image_id": image_id, "owner_id": owner_id, "name": name, "creation_date": creation_date}
        )

    def seed_image(self, image_id: str, tags: dict[str, str], *, creation_date: str = "", snapshot_ids: list[str] | None = None) -> None:
        """Pre-populate an AMI so describe_images can return it."""
        self._images.append({"image_id": image_id, "tags": dict(tags), "creation_date": creation_date})
        snaps = list(snapshot_ids or [])
        self._amis[image_id] = {
            "tags": dict(tags),
            "creation_date": creation_date,
            "snapshot_ids": snaps,
        }
        # Track snapshots in a flat set so delete_snapshot works after deregister_image
        # removes the AMI from _amis (which would cause lazy-init to miss them).
        self._snapshots.update(snaps)

    def seed_iam_role(self, role_name: str, attached_policies: list[str] | None = None) -> None:
        """Pre-populate an IAM role so list_attached_role_policies etc. can return data."""
        self._iam_roles[role_name] = {
            "attached_policies": list(attached_policies or []),
        }

    def seed_s3_bucket(self, bucket_name: str, keys: list[str] | None = None) -> None:
        """Pre-populate an S3 bucket (optionally with object keys)."""
        self._s3_buckets[bucket_name] = {k: b"" for k in (keys or [])}

    def seed_imagebuilder_pipeline(self, arn: str, name: str) -> None:
        """Pre-populate an Image Builder pipeline."""
        self._ib_pipelines[arn] = {"name": name}

    def seed_imagebuilder_image(
        self, version_arn: str, build_version_arns: list[str]
    ) -> None:
        """Pre-populate an Image Builder image (version + build versions)."""
        self._ib_image_versions[version_arn] = list(build_version_arns)
        self._ib_image_build_versions.update(build_version_arns)

    def seed_imagebuilder_recipe(self, arn: str, name: str) -> None:
        """Pre-populate an Image Builder recipe."""
        self._ib_recipes[arn] = {"name": name}

    def seed_imagebuilder_infra_config(self, arn: str, name: str) -> None:
        """Pre-populate an Image Builder infrastructure configuration."""
        self._ib_infra_configs[arn] = {"name": name}

    def seed_imagebuilder_dist_config(self, arn: str, name: str) -> None:
        """Pre-populate an Image Builder distribution configuration."""
        self._ib_dist_configs[arn] = {"name": name}

    def seed_imagebuilder_component(
        self, version_arn: str, build_version_arns: list[str]
    ) -> None:
        """Pre-populate an Image Builder component (version + build versions).

        Sharp edge: delete_imagebuilder_component() must be called with a
        build-version ARN (from list_imagebuilder_component_build_versions),
        not the version ARN seeded here.
        """
        self._ib_component_versions[version_arn] = list(build_version_arns)
        self._ib_component_build_versions.update(build_version_arns)

    def was_called(self, method: str, *args) -> bool:
        """Return True if a call matching method + args (prefix match) was recorded."""
        for call in self.calls:
            if call[0] == method and call[1:len(args) + 1] == args:
                return True
        return False

    # -- interface -----------------------------------------------------------

    def get_secret(self, secret_id: str) -> Optional[str]:
        self.calls.append(("get_secret", secret_id))
        return self._secrets.get(secret_id)

    def put_secret(self, secret_id: str, value: str) -> None:
        self.calls.append(("put_secret", secret_id))
        self._secrets[secret_id] = value

    def instance_id_for_stack(self, stack_name: str) -> Optional[str]:
        self.calls.append(("instance_id_for_stack", stack_name))
        return f"i-fake-{stack_name}"

    def ssm_run_command(
        self, instance_id: str, command: str, *, timeout: int = 60
    ) -> tuple[int, str]:
        self.calls.append(("ssm_run_command", instance_id, command))
        # Return a realistic-looking harness success output so remote smoke passes.
        return 0, "All 8 checks passed.\n[fake-ssm]"

    def get_ssm_param(self, name: str) -> Optional[str]:
        self.calls.append(("get_ssm_param", name))
        # Return seeded value, or synthesize a plausible fake for well-known infra paths.
        if name in self._ssm_params:
            return self._ssm_params[name]
        if "/safe-agents/" in name:
            # Derive a plausible fake from the key segment.
            key = name.rsplit("/", 1)[-1]
            if key.endswith("-arn"):
                return f"arn:aws:iam::123456789012:role/{key}"
            if key.endswith("-id"):
                return f"fake-{key}-abc123"
            if key.endswith("-ids"):
                return "fake-subnet-abc123,fake-subnet-def456"
        return None

    def run_instances(
        self,
        *,
        name: str,
        image_id: str,
        instance_type: str,
        iam_instance_profile_arn: str,
        security_group_ids: list,
        subnet_id: str,
        user_data_b64: str,
        tags: dict,
        block_device_mappings: Optional[list] = None,
    ) -> str:
        self.calls.append(("run_instances", name, instance_type, subnet_id))
        if self.run_instances_profile_error_count > 0:
            self.run_instances_profile_error_count -= 1
            raise IamProfileNotReadyError(
                "Invalid IAM Instance Profile ARN "
                f"(simulated; {self.run_instances_profile_error_count} errors remaining)"
            )
        instance_id = f"i-fake-{name[:20]}-ec2"
        self._instances[instance_id] = {
            "tags": tags,
            "state": "running",
            "subnet_id": subnet_id,
            "block_device_mappings": block_device_mappings,
        }
        return instance_id

    # -------------------------------------------------------------------------
    # EC2 lifecycle (teardown)
    # -------------------------------------------------------------------------

    def describe_instances_by_tags(self, tags: dict[str, str]) -> list[dict]:
        self.calls.append(("describe_instances_by_tags", tags))
        result = []
        for iid, idata in self._instances.items():
            if idata["state"] == "terminated":
                continue
            instance_tags = idata.get("tags", {})
            if all(instance_tags.get(k) == v for k, v in tags.items()):
                result.append({"instance_id": iid, "state": idata["state"]})
        # Apply pending state transitions for matching instances (fires AFTER results
        # are computed, so callers see the current state first, then it advances on
        # the next call — accurately modeling EC2's asynchronous state machine).
        for item in result:
            iid = item["instance_id"]
            pending = self._instance_state_transitions.get(iid)
            if pending:
                self._instances[iid]["state"] = pending.pop(0)
        return result

    def terminate_instances(self, instance_ids: list[str]) -> list[str]:
        self.calls.append(("terminate_instances", instance_ids))
        terminated = []
        for iid in instance_ids:
            if iid in self._instances and self._instances[iid]["state"] != "terminated":
                self._instances[iid]["state"] = "terminated"
                terminated.append(iid)
        return terminated

    # -------------------------------------------------------------------------
    # IAM — per-agent instance profile + inline policy (teardown)
    # -------------------------------------------------------------------------

    def get_instance_profile(self, profile_name: str) -> Optional[dict]:
        self.calls.append(("get_instance_profile", profile_name))
        if profile_name not in self._instance_profiles:
            return None
        arn = f"arn:aws:iam::123456789012:instance-profile/{profile_name}"
        # Simulate profile mid-delete: return empty roles for N calls, then auto-delete
        # and return None (models "delete in flight" for the clean-start gate tests).
        if self.iam_profile_delete_countdown > 0:
            self.iam_profile_delete_countdown -= 1
            if self.iam_profile_delete_countdown == 0:
                del self._instance_profiles[profile_name]
                return None
            return {"arn": arn, "roles": []}
        # Simulate IAM eventual-consistency: return profile without roles for N polls.
        if self.iam_role_never_in_profile:
            return {"arn": arn, "roles": []}
        if self.iam_role_in_profile_after_n_polls > 0:
            self.iam_role_in_profile_after_n_polls -= 1
            return {"arn": arn, "roles": []}
        return {"arn": arn, "roles": list(self._instance_profiles[profile_name].get("roles", []))}

    def describe_ssm_instance_information(self, instance_id: str) -> Optional[str]:
        self.calls.append(("describe_ssm_instance_information", instance_id))
        # Simulate never-online (instance never registers with SSM).
        if self.ssm_never_online:
            return None
        # Simulate delayed registration: return Offline for N polls, then Online.
        if self.ssm_online_after_n_polls > 0:
            self.ssm_online_after_n_polls -= 1
            return "Offline"
        # Instance must exist (not terminated) to be considered Online.
        inst = self._instances.get(instance_id)
        if inst and inst.get("state") not in ("terminated", "shutting-down"):
            return "Online"
        return None

    def create_instance_profile(self, name: str, tags: dict) -> str:
        self.calls.append(("create_instance_profile", name))
        self._instance_profiles[name] = {"roles": [], "tags": tags}
        return f"arn:aws:iam::123456789012:instance-profile/{name}"

    def add_role_to_instance_profile(self, profile_name: str, role_name: str) -> None:
        self.calls.append(("add_role_to_instance_profile", profile_name, role_name))
        if profile_name in self._instance_profiles:
            roles = self._instance_profiles[profile_name]["roles"]
            if role_name not in roles:
                roles.append(role_name)

    def delete_instance_profile(self, profile_name: str) -> bool:
        self.calls.append(("delete_instance_profile", profile_name))
        if profile_name in self._instance_profiles:
            del self._instance_profiles[profile_name]
            return True
        return False

    def put_role_policy(
        self, role_name: str, policy_name: str, policy_document: dict
    ) -> None:
        self.calls.append(("put_role_policy", role_name, policy_name))
        self._role_policies[(role_name, policy_name)] = policy_document

    def delete_role_policy(self, role_name: str, policy_name: str) -> bool:
        self.calls.append(("delete_role_policy", role_name, policy_name))
        key = (role_name, policy_name)
        if key in self._role_policies:
            del self._role_policies[key]
            return True
        return False

    def describe_images(self, tag_filters: dict[str, str]) -> list[dict]:
        self.calls.append(("describe_images", tag_filters))
        result = []
        for image in self._images:
            image_tags = image.get("tags", {})
            if all(image_tags.get(k) == v for k, v in tag_filters.items()):
                result.append(dict(image))
        return result

    def describe_images_by_owner_name(
        self, owner_id: str, name_pattern: str
    ) -> list[dict]:
        import fnmatch  # noqa: PLC0415
        self.calls.append(("describe_images_by_owner_name", owner_id, name_pattern))
        return [
            {"image_id": img["image_id"], "name": img["name"], "creation_date": img["creation_date"]}
            for img in self._marketplace_images
            if img["owner_id"] == owner_id and fnmatch.fnmatch(img["name"], name_pattern)
        ]

    # -------------------------------------------------------------------------
    # AMI deregistration + snapshot cleanup (bake teardown)
    # -------------------------------------------------------------------------

    def describe_image_snapshots(self, image_id: str) -> list[str]:
        self.calls.append(("describe_image_snapshots", image_id))
        ami = self._amis.get(image_id)
        if ami is None:
            return []
        return list(ami.get("snapshot_ids", []))

    def deregister_image(self, image_id: str) -> bool:
        self.calls.append(("deregister_image", image_id))
        if image_id in self._amis:
            del self._amis[image_id]
            self._images = [i for i in self._images if i["image_id"] != image_id]
            return True
        return False

    def delete_snapshot(self, snapshot_id: str) -> bool:
        self.calls.append(("delete_snapshot", snapshot_id))
        # _snapshots is a flat set maintained by seed_image (populated at seed time,
        # not lazily, so it survives deregister_image removing the AMI from _amis).
        if snapshot_id in self._snapshots:
            self._snapshots.discard(snapshot_id)
            return True
        return False

    # -------------------------------------------------------------------------
    # Image Builder teardown
    # -------------------------------------------------------------------------

    def list_imagebuilder_pipelines(self, name_prefix: str) -> list[dict]:
        self.calls.append(("list_imagebuilder_pipelines", name_prefix))
        return [
            {"arn": arn, "name": data["name"]}
            for arn, data in self._ib_pipelines.items()
            if data["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_pipeline(self, arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_pipeline", arn))
        if arn in self._ib_pipelines:
            del self._ib_pipelines[arn]
            return True
        return False

    def list_imagebuilder_images(self, name_prefix: str) -> list[str]:
        self.calls.append(("list_imagebuilder_images", name_prefix))
        # Mirror LiveAWS: extract resource name from ARN (owner=Self implicit in FakeAWS)
        # and filter by prefix. ARN format: ...image/NAME/version...
        result = []
        for version_arn in self._ib_image_versions:
            resource_name = version_arn.split(":")[-1].split("/")[1]
            if resource_name.startswith(name_prefix):
                result.append(version_arn)
        return result

    def list_imagebuilder_image_build_versions(self, image_version_arn: str) -> list[str]:
        self.calls.append(("list_imagebuilder_image_build_versions", image_version_arn))
        return list(self._ib_image_versions.get(image_version_arn, []))

    def delete_imagebuilder_image(self, build_version_arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_image", build_version_arn))
        if build_version_arn in self._ib_image_build_versions:
            self._ib_image_build_versions.discard(build_version_arn)
            # Also remove from the version map
            for ver, builds in self._ib_image_versions.items():
                if build_version_arn in builds:
                    builds.remove(build_version_arn)
            return True
        return False

    def list_imagebuilder_recipes(self, name_prefix: str) -> list[str]:
        self.calls.append(("list_imagebuilder_recipes", name_prefix))
        return [
            arn
            for arn, data in self._ib_recipes.items()
            if data["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_recipe(self, arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_recipe", arn))
        if arn in self._ib_recipes:
            del self._ib_recipes[arn]
            return True
        return False

    def list_imagebuilder_infra_configs(self, name_prefix: str) -> list[str]:
        self.calls.append(("list_imagebuilder_infra_configs", name_prefix))
        return [
            arn
            for arn, data in self._ib_infra_configs.items()
            if data["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_infra_config(self, arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_infra_config", arn))
        if arn in self._ib_infra_configs:
            del self._ib_infra_configs[arn]
            return True
        return False

    def list_imagebuilder_dist_configs(self, name_prefix: str) -> list[str]:
        self.calls.append(("list_imagebuilder_dist_configs", name_prefix))
        return [
            arn
            for arn, data in self._ib_dist_configs.items()
            if data["name"].startswith(name_prefix)
        ]

    def delete_imagebuilder_dist_config(self, arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_dist_config", arn))
        if arn in self._ib_dist_configs:
            del self._ib_dist_configs[arn]
            return True
        return False

    def list_imagebuilder_components(self, name_prefix: str) -> list[str]:
        self.calls.append(("list_imagebuilder_components", name_prefix))
        # Mirror LiveAWS: extract resource name from ARN and filter by prefix.
        # ARN format: ...component/NAME/version...
        result = []
        for version_arn in self._ib_component_versions:
            resource_name = version_arn.split(":")[-1].split("/")[1]
            if resource_name.startswith(name_prefix):
                result.append(version_arn)
        return result

    def list_imagebuilder_component_build_versions(self, version_arn: str) -> list[str]:
        self.calls.append(("list_imagebuilder_component_build_versions", version_arn))
        return list(self._ib_component_versions.get(version_arn, []))

    def delete_imagebuilder_component(self, build_version_arn: str) -> bool:
        self.calls.append(("delete_imagebuilder_component", build_version_arn))
        if build_version_arn in self._ib_component_build_versions:
            self._ib_component_build_versions.discard(build_version_arn)
            for ver, builds in self._ib_component_versions.items():
                if build_version_arn in builds:
                    builds.remove(build_version_arn)
            return True
        return False

    # -------------------------------------------------------------------------
    # S3 teardown (deploy bucket)
    # -------------------------------------------------------------------------

    def put_object(self, bucket_name: str, key: str, body: "str | bytes") -> None:
        self.calls.append(("put_object", bucket_name, key))
        data = body.encode() if isinstance(body, str) else body
        self._s3_buckets.setdefault(bucket_name, {})[key] = data

    def list_bucket_objects(self, bucket_name: str) -> list[str]:
        self.calls.append(("list_bucket_objects", bucket_name))
        bucket = self._s3_buckets.get(bucket_name)
        if bucket is None:
            return []
        return list(bucket.keys())

    def delete_objects(self, bucket_name: str, keys: list[str]) -> int:
        self.calls.append(("delete_objects", bucket_name, keys))
        bucket = self._s3_buckets.get(bucket_name, {})
        deleted = 0
        for k in keys:
            if k in bucket:
                del bucket[k]
                deleted += 1
        return deleted

    def delete_bucket(self, bucket_name: str) -> bool:
        self.calls.append(("delete_bucket", bucket_name))
        if bucket_name in self._s3_buckets:
            del self._s3_buckets[bucket_name]
            return True
        return False

    # -------------------------------------------------------------------------
    # IAM role management (for Image Builder role teardown)
    # -------------------------------------------------------------------------

    def list_attached_role_policies(self, role_name: str) -> list[str]:
        self.calls.append(("list_attached_role_policies", role_name))
        role = self._iam_roles.get(role_name)
        if role is None:
            return []
        return list(role.get("attached_policies", []))

    def detach_role_managed_policy(self, role_name: str, policy_arn: str) -> bool:
        self.calls.append(("detach_role_managed_policy", role_name, policy_arn))
        role = self._iam_roles.get(role_name)
        if role is None:
            return False
        policies = role.get("attached_policies", [])
        if policy_arn in policies:
            policies.remove(policy_arn)
            return True
        return False

    def list_role_inline_policy_names(self, role_name: str) -> list[str]:
        self.calls.append(("list_role_inline_policy_names", role_name))
        # Derive from _role_policies (shared with the per-agent teardown path)
        return [
            policy_name
            for (rn, policy_name) in self._role_policies
            if rn == role_name
        ]

    def delete_role(self, role_name: str) -> bool:
        self.calls.append(("delete_role", role_name))
        self._created_roles.pop(role_name, None)
        if role_name in self._iam_roles:
            del self._iam_roles[role_name]
            return True
        return False

    # -------------------------------------------------------------------------
    # IAM — per-agent role creation (Fargate arm; sa#36)
    # -------------------------------------------------------------------------

    def create_role(
        self, role_name: str, assume_role_policy_document: dict, tags: dict
    ) -> str:
        self.calls.append(("create_role", role_name))
        arn = f"arn:aws:iam::123456789012:role/{role_name}"
        if role_name in self._created_roles:
            return self._created_roles[role_name]["arn"]
        self._created_roles[role_name] = {
            "arn": arn,
            "assume_role_policy": dict(assume_role_policy_document),
            "tags": dict(tags),
        }
        # Register in the shared role map so attach/detach/list/delete operate on it.
        self._iam_roles.setdefault(role_name, {"attached_policies": []})
        return arn

    def get_role(self, role_name: str) -> Optional[dict]:
        self.calls.append(("get_role", role_name))
        role = self._created_roles.get(role_name)
        if role is None:
            return None
        return {"arn": role["arn"], "assume_role_policy": role["assume_role_policy"]}

    def attach_role_managed_policy(self, role_name: str, policy_arn: str) -> None:
        self.calls.append(("attach_role_managed_policy", role_name, policy_arn))
        role = self._iam_roles.setdefault(role_name, {"attached_policies": []})
        if policy_arn not in role["attached_policies"]:
            role["attached_policies"].append(policy_arn)

    # -------------------------------------------------------------------------
    # ECS / Fargate (sa#36)
    # -------------------------------------------------------------------------

    def register_task_definition(
        self,
        *,
        family: str,
        task_role_arn: str,
        execution_role_arn: str,
        cpu: str,
        memory: str,
        container_name: str,
        image: str,
        environment: dict[str, str],
        secrets: dict[str, str],
        log_configuration: dict,
        runtime_platform: dict,
        network_mode: str,
        tags: dict,
    ) -> str:
        self.calls.append(("register_task_definition", family))
        revision = self._ecs_family_revisions.get(family, 0) + 1
        self._ecs_family_revisions[family] = revision
        arn = f"arn:aws:ecs:us-east-1:123456789012:task-definition/{family}:{revision}"
        self._ecs_task_definitions[arn] = {
            "family": family,
            "revision": revision,
            "status": "ACTIVE",
            "task_role_arn": task_role_arn,
            "execution_role_arn": execution_role_arn,
            "cpu": cpu,
            "memory": memory,
            "container_name": container_name,
            "image": image,
            "environment": dict(environment),
            "secrets": dict(secrets),
            "log_configuration": dict(log_configuration),
            "runtime_platform": dict(runtime_platform),
            "network_mode": network_mode,
            "tags": dict(tags),
        }
        return arn

    def deregister_task_definition(self, task_definition: str) -> bool:
        self.calls.append(("deregister_task_definition", task_definition))
        td = self._ecs_task_definitions.get(task_definition)
        if td is None or td["status"] != "ACTIVE":
            return False
        td["status"] = "INACTIVE"
        return True

    def list_task_definitions(self, family_prefix: str) -> list[str]:
        self.calls.append(("list_task_definitions", family_prefix))
        return [
            arn
            for arn, td in self._ecs_task_definitions.items()
            if td["status"] == "ACTIVE" and td["family"].startswith(family_prefix)
        ]

    def run_task(
        self,
        *,
        cluster: str,
        task_definition: str,
        subnets: list[str],
        security_groups: list[str],
        assign_public_ip: bool,
        overrides: Optional[dict] = None,
    ) -> str:
        self.calls.append(("run_task", cluster, task_definition))
        task_arn = f"arn:aws:ecs:us-east-1:123456789012:task/{cluster}/fake{len(self._ecs_tasks)}"
        self._ecs_tasks[task_arn] = {
            "cluster": cluster,
            "task_definition": task_definition,
            "subnets": list(subnets),
            "security_groups": list(security_groups),
            "assign_public_ip": assign_public_ip,
            "overrides": overrides,
            "last_status": "RUNNING",
            "exit_code": 0,
        }
        return task_arn

    def describe_task(self, cluster: str, task_arn: str) -> Optional[dict]:
        self.calls.append(("describe_task", cluster, task_arn))
        task = self._ecs_tasks.get(task_arn)
        if task is None:
            return None
        return {"last_status": task["last_status"], "exit_code": task["exit_code"]}

    # -------------------------------------------------------------------------
    # EventBridge Scheduler (sa#36)
    # -------------------------------------------------------------------------

    def create_schedule(
        self,
        *,
        name: str,
        schedule_expression: str,
        timezone: str,
        target: dict,
        tags: Optional[dict] = None,
        state: str = "ENABLED",
    ) -> str:
        self.calls.append(("create_schedule", name))
        if self.create_schedule_role_error_count > 0:
            self.create_schedule_role_error_count -= 1
            raise SchedulerRoleNotReadyError(
                "must allow AWS EventBridge Scheduler to assume the role "
                f"(simulated; {self.create_schedule_role_error_count} errors remaining)"
            )
        arn = f"arn:aws:scheduler:us-east-1:123456789012:schedule/default/{name}"
        self._schedules[name] = {
            "arn": arn,
            "schedule_expression": schedule_expression,
            "timezone": timezone,
            "target": dict(target),
            "tags": dict(tags or {}),
            "state": state,
        }
        return arn

    def get_schedule(self, name: str) -> Optional[dict]:
        self.calls.append(("get_schedule", name))
        sched = self._schedules.get(name)
        if sched is None:
            return None
        return dict(sched)

    def delete_schedule(self, name: str) -> bool:
        self.calls.append(("delete_schedule", name))
        if name in self._schedules:
            del self._schedules[name]
            return True
        return False
