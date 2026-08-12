"""
CLI entrypoint for the manifest-driven provision/deploy/smoke pipeline.

Usage:
    python3 -m safe_agents.pipeline.cli agents/my-agent.yaml [--dry-run] [--env development]

From the repo root (core working directory):
    python3 -m safe_agents.pipeline.cli ../agents/test-stub.yaml --dry-run
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .pipeline import ALL_PHASES, PHASES_ORDERED, run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description=(
            "Manifest-driven provision/deploy/smoke pipeline. "
            "Reads agents/<name>.yaml and drives the three phases in order.\n\n"
            "Pass --dry-run to validate and print the plan without calling AWS."
        ),
    )
    parser.add_argument(
        "manifest",
        help="Path to the agent deployment manifest YAML (e.g. agents/my-agent.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Validate + print the plan without calling AWS or running smoke",
    )
    parser.add_argument(
        "--env",
        default="development",
        choices=["development", "staging", "production"],
        dest="environment",
        metavar="ENV",
        help="Deployment environment: development | staging | production (default: development)",
    )
    parser.add_argument(
        "--agent-dir",
        default=None,
        metavar="DIR",
        help=(
            "Explicit agent package directory for the smoke phase "
            "(highest precedence; overrides --agent-root)"
        ),
    )
    parser.add_argument(
        "--agent-root",
        default=None,
        metavar="DIR",
        help=(
            "Directory under which the agent package resolves as "
            "<agent-root>/<manifest.agent_package or name>. "
            "Defaults to the manifest's own directory (no monorepo assumption)."
        ),
    )
    parser.add_argument(
        "--phase",
        choices=list(ALL_PHASES),
        action="append",
        dest="phases",
        default=None,
        metavar="PHASE",
        help=(
            "Run only this phase (repeatable; default: provision→deploy→smoke). "
            "Use --phase teardown to destroy arm-provisioned resources. "
            "Example: --phase provision --phase deploy"
        ),
    )
    parser.add_argument(
        "--smoke-mode",
        choices=["local", "remote"],
        default="local",
        dest="smoke_mode",
        metavar="MODE",
        help=(
            "Smoke verification mode: "
            "local — run harness locally against the agent package dir (default, CI-safe); "
            "remote — run harness on the deployed instance via SSM (requires a live deploy)"
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    manifest_path = Path(args.manifest).resolve()
    agent_dir = Path(args.agent_dir).resolve() if args.agent_dir else None
    agent_root = Path(args.agent_root).resolve() if args.agent_root else None
    phases = tuple(args.phases) if args.phases else PHASES_ORDERED

    result = run_pipeline(
        manifest_path,
        dry_run=args.dry_run,
        environment=args.environment,
        agent_dir=agent_dir,
        agent_root=agent_root,
        phases=phases,
        smoke_mode=args.smoke_mode,
    )
    result.print_plan()
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
