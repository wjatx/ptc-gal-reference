"""safe_agents.pipeline — manifest-driven provision/deploy/smoke/teardown pipeline for safe-agents."""

from .aws_interface import AWSInterface, FakeAWS, LiveAWS
from .manifest import DeploymentManifest, ManifestError, load_manifest, manifest_get
from .phases import (
    SMOKE_MODE_LOCAL,
    SMOKE_MODE_REMOTE,
    PhaseResult,
    deploy_phase,
    provision_phase,
    smoke_phase,
    teardown_phase,
    validate_phase,
)
from .pipeline import ALL_PHASES, PHASES_ORDERED, PipelineResult, run_pipeline
from .validate import validate_manifest, validate_manifest_extended

__all__ = [
    "ALL_PHASES",
    "AWSInterface",
    "DeploymentManifest",
    "FakeAWS",
    "LiveAWS",
    "ManifestError",
    "PHASES_ORDERED",
    "PhaseResult",
    "PipelineResult",
    "SMOKE_MODE_LOCAL",
    "SMOKE_MODE_REMOTE",
    "deploy_phase",
    "load_manifest",
    "manifest_get",
    "provision_phase",
    "run_pipeline",
    "smoke_phase",
    "teardown_phase",
    "validate_manifest",
    "validate_manifest_extended",
    "validate_phase",
]
