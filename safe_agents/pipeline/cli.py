"""
CLI entrypoint for the manifest-driven provision/deploy/smoke pipeline.

Usage:
    python3 -m safe_agents.pipeline.cli agents/my-agent.yaml [--dry-run] [--env development] \
        (--ami-id ami-... | --image-uri <repository-uri>@sha256:<64 hex>)

The provision phase launches exactly what the operator names: --ami-id for the arms that launch
an instance (ec2, rhel-openshell), --image-uri by digest for the fargate arm. With neither it
refuses. --allow-newest-ami and --allow-mutable-image-tag are the overrides; each is recorded in
the plan and logged at WARNING. These four are command-line flags only: nothing reads them from
the manifest or the environment. See safe_agents/pipeline/image_pin.py.

From the repo root (core working directory):
    python3 -m safe_agents.pipeline.cli ../agents/test-stub.yaml --dry-run --ami-id ami-...
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence

from .image_pin import (
    ALLOW_MUTABLE_IMAGE_TAG_FLAG,
    ALLOW_NEWEST_AMI_FLAG,
    AMI_ID_FLAG,
    IMAGE_URI_FLAG,
)
from .pipeline import ALL_PHASES, PHASES_ORDERED, run_pipeline


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description=(
            "Manifest-driven provision/deploy/smoke pipeline. "
            "Reads agents/<name>.yaml and drives the three phases in order.\n\n"
            "Pass --dry-run to validate and print the plan without calling AWS.\n\n"
            "The provision phase launches what you name and has no default: pass "
            f"{AMI_ID_FLAG} (ec2, rhel-openshell) or {IMAGE_URI_FLAG} by digest (fargate)."
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
    image = parser.add_argument_group(
        "what the provision phase launches",
        "There is no default AMI and no default image. A flag that the manifest's arm does not "
        "use is an error. The two --allow-* overrides are recorded in the plan and logged at "
        "WARNING; they are flags of this command only and are not read from the manifest or "
        "the environment.",
    )
    image.add_argument(
        AMI_ID_FLAG,
        default=None,
        dest="ami_id",
        metavar="AMI_ID",
        help=(
            "The AMI to launch from, for the arms that launch an instance (ec2, "
            'rhel-openshell): "ami-" plus 8 or 17 lowercase hex characters. It is the output of '
            "the arm's bake."
        ),
    )
    image.add_argument(
        IMAGE_URI_FLAG,
        default=None,
        dest="image_uri",
        metavar="IMAGE_URI",
        help=(
            "The container image for the fargate arm, by digest: "
            "<repository-uri>@sha256:<64 lowercase hex characters>. Read the digest back after "
            "the push (podman push --digestfile, or aws ecr describe-images)."
        ),
    )
    image.add_argument(
        ALLOW_NEWEST_AMI_FLAG,
        action="store_true",
        default=False,
        dest="allow_newest_ami",
        help=(
            f"Override: with no {AMI_ID_FLAG}, launch the newest AMI by the arm's tag rule "
            "(rhel-openshell falls back to the Red Hat marketplace AMI with the highest release "
            "when no baked AMI exists). What launches may not be what was reviewed."
        ),
    )
    image.add_argument(
        ALLOW_MUTABLE_IMAGE_TAG_FLAG,
        action="store_true",
        default=False,
        dest="allow_mutable_image_tag",
        help=(
            f"Override: {IMAGE_URI_FLAG} may name a tag (<repository-uri>:<tag>) instead of a "
            f"digest. {IMAGE_URI_FLAG} is still required; there is no implicit latest."
        ),
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
    args = parser.parse_args(argv)

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
        ami_id=args.ami_id,
        image_uri=args.image_uri,
        allow_newest_ami=args.allow_newest_ami,
        allow_mutable_image_tag=args.allow_mutable_image_tag,
    )
    result.print_plan()
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
