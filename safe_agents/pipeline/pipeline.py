"""
Pipeline orchestration: provision → deploy → smoke.

Entry point for callers. Reads an agent deployment manifest and drives the
three phases in order. Each phase is idempotent; the pipeline can be re-run
at any point without harm.

--dry-run / plan mode: validates the manifest and prints the ordered plan
without making any AWS calls. The plan is the "what would happen" description
a human approves before actual provisioning begins.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .aws_interface import AWSInterface, LiveAWS
from .manifest import DeploymentManifest, load_manifest
from .phases import (
    SMOKE_MODE_LOCAL,
    PhaseResult,
    deploy_phase,
    provision_phase,
    smoke_phase,
    teardown_phase,
    validate_phase,
    verify_phase,
)

logger = logging.getLogger(__name__)

# Default pipeline run order (provision → deploy → smoke).
PHASES_ORDERED: tuple[str, ...] = ("provision", "deploy", "smoke")
# All valid phase names (teardown and verify are opt-in; not in the default run).
ALL_PHASES: tuple[str, ...] = ("provision", "deploy", "smoke", "verify", "teardown")


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    manifest: DeploymentManifest
    dry_run: bool
    environment: str
    phase_results: list[PhaseResult] = field(default_factory=list)
    aborted_at: Optional[str] = None

    @property
    def success(self) -> bool:
        if self.aborted_at:
            return False
        return bool(self.phase_results) and all(r.success for r in self.phase_results)

    def print_plan(self) -> None:
        """Print the ordered plan to stdout."""
        tag = "[DRY-RUN] " if self.dry_run else ""
        print(
            f"\n{tag}Pipeline plan — agent={self.manifest.name!r}  "
            f"arm={self.manifest.arm!r}  env={self.environment!r}"
        )
        print("=" * 72)
        for pr in self.phase_results:
            status = "PASS" if pr.success else "FAIL"
            dr_tag = "[dry-run] " if pr.dry_run else ""
            print(f"\n  [{status}] {dr_tag}{pr.phase.upper()}")
            for step in pr.steps:
                print(f"    -> {step}")
            if pr.error:
                print(f"    ERROR: {pr.error}")
        print("=" * 72)
        if self.success:
            print("Plan OK — all phases would succeed.\n")
        elif self.aborted_at:
            print(f"Pipeline aborted at phase {self.aborted_at!r} — see error above.\n")
        else:
            print("Pipeline failed — see errors above.\n")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_pipeline(
    manifest_path: Path,
    *,
    dry_run: bool = False,
    environment: str = "development",
    agent_dir: Optional[Path] = None,
    agent_root: Optional[Path] = None,
    aws: Optional[AWSInterface] = None,
    phases: tuple[str, ...] = PHASES_ORDERED,
    harness_fn: Optional[Callable] = None,
    repo_root: Optional[Path] = None,
    smoke_mode: str = SMOKE_MODE_LOCAL,
) -> PipelineResult:
    """
    Run the provision → deploy → smoke pipeline for one agent manifest.

    Parameters
    ----------
    manifest_path:
        Path to the agent deployment manifest YAML (e.g. agents/my-agent.yaml).
    dry_run:
        If True, validate + print the plan without calling AWS or running the
        conformance harness. All phases report success when no structural
        errors are found.
    environment:
        Deployment target: exactly development | staging | production.
    agent_dir:
        Explicit agent package directory for the local smoke phase. When given,
        used as-is (highest precedence). Must be an existing directory for a
        live local smoke run.
    agent_root:
        Directory under which the agent package resolves as
        <agent_root>/<manifest.agent_package or manifest.name>. Defaults to the
        manifest's OWN directory (manifest_path.parent) — the agent package sits
        beside its manifest. This deliberately makes NO monorepo-sibling
        assumption (no jump to a repo-root-relative agents/ dir), so a manifest
        and its connectors resolve from an arbitrary path. Ignored when
        agent_dir is given.
    aws:
        AWSInterface implementation. Defaults to LiveAWS() (real boto3). Inject
        FakeAWS for unit tests.
    phases:
        Subset of phases to run (default: provision→deploy→smoke). Pass
        ("teardown",) to run only teardown, or ("smoke",) for a smoke-only
        recheck. Teardown is NOT in the default set — it must be opted in.
    harness_fn:
        callable(agent_dir: Path) -> list[CheckResult]. Injected in tests;
        defaults to the real conformance harness at runtime.
    smoke_mode:
        "local"  — run harness locally against agent_dir (default, CI-friendly).
        "remote" — run harness on the deployed instance via SSM SendCommand.

    Returns
    -------
    PipelineResult. Call .print_plan() to display; check .success for pass/fail.
    """
    manifest = load_manifest(manifest_path)

    if aws is None:
        aws = LiveAWS()

    result = PipelineResult(
        manifest=manifest,
        dry_run=dry_run,
        environment=environment,
    )

    # Pre-flight: extended manifest validation (sa#41).
    # Runs structural + (if repo_root given) policy checks before any AWS call.
    # On failure: logged in phase_results, pipeline aborts.
    # Skip pre-flight for teardown-only runs (manifest may reference unreachable
    # policy paths on a machine that never had the full checkout).
    if phases != ("teardown",):
        preflight = validate_phase(manifest, repo_root=repo_root)
        if not preflight.success:
            result.phase_results.append(preflight)
            result.aborted_at = "preflight"
            return result

    result = PipelineResult(
        manifest=manifest,
        dry_run=dry_run,
        environment=environment,
    )

    # Resolve the agent package directory for the smoke phase:
    # prefer manifest.agent_package when set, else fall back to manifest.name.
    # Precedence: explicit agent_dir > agent_root/<pkg> > <manifest-dir>/<pkg>.
    # The default resolves the package BESIDE its manifest (agent_root defaults
    # to manifest_path.parent) — no monorepo-sibling jump to a repo-root agents/
    # dir — so a manifest + its connectors resolve from an arbitrary path.
    package_name = manifest.agent_package or manifest.name
    if agent_dir is not None:
        resolved_dir = agent_dir
    else:
        base = agent_root if agent_root is not None else manifest_path.parent
        resolved_dir = base / package_name

    for phase_name in ALL_PHASES:
        if phase_name not in phases:
            continue

        if phase_name == "provision":
            pr = provision_phase(
                manifest, aws, dry_run=dry_run, environment=environment
            )

        elif phase_name == "deploy":
            pr = deploy_phase(
                manifest, aws, dry_run=dry_run, environment=environment
            )

        elif phase_name == "smoke":
            pr = smoke_phase(
                manifest,
                resolved_dir,
                dry_run=dry_run,
                harness_fn=harness_fn,
                smoke_mode=smoke_mode,
                aws=aws,
                environment=environment,
            )

        elif phase_name == "verify":
            pr = verify_phase(
                manifest, aws, dry_run=dry_run, environment=environment
            )

        elif phase_name == "teardown":
            pr = teardown_phase(
                manifest, aws, dry_run=dry_run, environment=environment
            )

        else:
            continue  # unknown phase name — skip silently

        result.phase_results.append(pr)

        if not pr.success:
            result.aborted_at = phase_name
            break  # abort: later phases depend on earlier ones succeeding

    return result
