"""
Deployment manifest loading and validation.

Re-derives the dotted-path reader (manifest_get) from the proven pattern in a
development harness's `_pipeline-lib.sh`, generalised to be agent-agnostic Python.

Consumers: pipeline orchestration, seed/provision/deploy/smoke phases.
Schema reference: core/manifest-schema.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# Arms the pipeline knows how to dispatch.
VALID_ARMS: frozenset[str] = frozenset({"ec2", "ec2-woken", "fargate", "rhel-openshell"})


class ManifestError(ValueError):
    """Raised when a manifest is missing, malformed, or fails validation."""


# ---------------------------------------------------------------------------
# Sub-structures
# ---------------------------------------------------------------------------

@dataclass
class Secrets:
    runner_keys: Optional[str] = None
    """Secrets Manager path for non-connector runtime config → agent env."""

    broker_connector_keys: Optional[str] = None
    """Secrets Manager path for connector creds → broker store ONLY. Agent never receives these."""

    oauth_token: Optional[str] = None
    """Secrets Manager path for model brain token (not a connector)."""


@dataclass
class Smoke:
    prompt: str
    expect_substring: str
    read_only: bool = True


@dataclass
class Schedule:
    expression: Optional[str] = None
    """cron(...) / rate(...) expression. When None, the arm's own default applies."""

    timezone: Optional[str] = None
    """IANA timezone for the cron expression. When None, the arm's own default applies."""

    state: str = "DISABLED"
    """Initial EventBridge Scheduler state. Defaults DISABLED — a provision should never
    enable a production schedule before its first manual proof (sa#115)."""


@dataclass
class DeploymentManifest:
    """Pipeline-facing deployment manifest (agents/<name>.yaml, manifest half only)."""

    name: str
    repo: str
    deploy_key_secret: str
    arm: str
    policy: str
    secrets: Secrets
    smoke: Smoke
    raw: dict = field(default_factory=dict, repr=False)

    # Envelope is preserved for the broker; the pipeline does not interpret it.
    envelope: Optional[dict] = field(default=None, repr=False)

    # schedule: optional, arm=fargate-only. Absent for every non-fargate manifest
    # (and most fargate manifests too — the arm's own defaults apply when None).
    schedule: Optional[Schedule] = field(default=None)

    # agent_package: optional package name the smoke phase should target,
    # resolved as <agent-root>/<agent_package> (agent-root defaults to the
    # manifest's own directory; see run_pipeline). When absent the pipeline
    # falls back to <agent-root>/<name>. Use this when the manifest name (e.g.
    # smoke-ec2) differs from the package being exercised (e.g. test-stub).
    agent_package: Optional[str] = field(default=None)


# ---------------------------------------------------------------------------
# Dotted-path reader — re-derived from _pipeline-lib.sh::manifest_get
# ---------------------------------------------------------------------------

def manifest_get(manifest: dict, dotted_path: str) -> Any:
    """Navigate a nested manifest dict via a dotted path.

    Re-derives the development-harness pattern:
        manifest_get example-agent arm          → "ec2"
        manifest_get example-agent smoke.prompt → "..."

    Raises KeyError with a descriptive message when any segment is missing.
    """
    parts = dotted_path.split(".")
    node = manifest
    traversed: list[str] = []
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            location = ".".join(traversed) if traversed else "<root>"
            raise KeyError(
                f"manifest_get: key {part!r} not found at {location!r} "
                f"(full path: {dotted_path!r})"
            )
        traversed.append(part)
        node = node[part]
    return node


# ---------------------------------------------------------------------------
# Loader + validator
# ---------------------------------------------------------------------------

def load_manifest(path: Path) -> DeploymentManifest:
    """Load and validate an agent deployment manifest YAML.

    Returns a DeploymentManifest on success.
    Raises ManifestError with a human-readable explanation on any failure.
    """
    if not path.exists():
        raise ManifestError(f"Manifest not found: {path}")

    try:
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ManifestError(f"Manifest parse error in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ManifestError(
            f"Manifest must be a YAML mapping; got {type(raw).__name__} in {path}"
        )

    errors: list[str] = []

    # Top-level required string fields.
    for field_name in ("name", "repo", "deploy_key_secret", "arm", "policy"):
        val = raw.get(field_name)
        if not val or not isinstance(val, str):
            errors.append(f"missing or empty required field: {field_name!r}")

    # arm must be a known value.
    arm = raw.get("arm", "")
    if arm and arm not in VALID_ARMS:
        errors.append(
            f"arm={arm!r} is not a known arm; must be one of {sorted(VALID_ARMS)}"
        )

    # secrets section — required; at least one path should be present.
    secrets_raw = raw.get("secrets") or {}
    if not isinstance(secrets_raw, dict):
        errors.append("'secrets' must be a YAML mapping")
        secrets_raw = {}
    if not secrets_raw:
        errors.append("'secrets' section is empty; at least one secret path is required")

    # smoke section — required; prompt and expect_substring are required.
    smoke_raw = raw.get("smoke") or {}
    if not isinstance(smoke_raw, dict):
        errors.append("'smoke' must be a YAML mapping")
        smoke_raw = {}
    else:
        for key in ("prompt", "expect_substring"):
            if not smoke_raw.get(key):
                errors.append(f"smoke.{key} is required")

    # schedule section — optional; arm=fargate only. When present, validate state.
    _VALID_SCHEDULE_STATES = {"ENABLED", "DISABLED"}
    schedule_raw = raw.get("schedule")
    if schedule_raw is not None:
        if not isinstance(schedule_raw, dict):
            errors.append("'schedule' must be a YAML mapping")
            schedule_raw = {}
        else:
            state = schedule_raw.get("state")
            if state is not None and state not in _VALID_SCHEDULE_STATES:
                errors.append(
                    f"schedule.state={state!r} is not valid; "
                    f"must be one of {sorted(_VALID_SCHEDULE_STATES)}"
                )

    if errors:
        raise ManifestError(
            f"Manifest validation failed for {path}:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    return DeploymentManifest(
        name=raw["name"],
        repo=raw["repo"],
        deploy_key_secret=raw["deploy_key_secret"],
        arm=raw["arm"],
        policy=raw["policy"],
        secrets=Secrets(
            runner_keys=secrets_raw.get("runner_keys"),
            broker_connector_keys=secrets_raw.get("broker_connector_keys"),
            oauth_token=secrets_raw.get("oauth_token"),
        ),
        smoke=Smoke(
            prompt=smoke_raw["prompt"],
            expect_substring=smoke_raw["expect_substring"],
            read_only=bool(smoke_raw.get("read_only", True)),
        ),
        raw=raw,
        envelope=raw.get("envelope"),
        agent_package=raw.get("agent_package") or None,
        schedule=(
            Schedule(
                expression=schedule_raw.get("expression"),
                timezone=schedule_raw.get("timezone"),
                state=schedule_raw.get("state", "DISABLED"),
            )
            if schedule_raw is not None
            else None
        ),
    )
