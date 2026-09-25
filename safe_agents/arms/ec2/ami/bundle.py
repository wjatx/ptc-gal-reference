"""
agent-code bundling and S3 upload for the safe-agents prebuilt-AMI delivery model.

Replaces the git-clone bootstrap (user-data.sh.tmpl) with S3-fetched bundles:
  - CI bundles the agent package (tar.gz) and uploads via upload_bundle().
  - The instance pulls from the S3 gateway endpoint at boot (no internet needed).

S3 conventions (load-bearing — must match the boot script and provision.py):
  Bucket:         safe-agents-<env>-deploy
  Current key:    agents/<name>/current/bundle.tar.gz
  Versioned key:  agents/<name>/<version>/bundle.tar.gz

The S3PutClient Protocol keeps boto3 out of the import path so tests can inject
a fake without patching globals. Only the CLI path imports boto3.
"""
from __future__ import annotations

import io
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

# ---------------------------------------------------------------------------
# Key convention (load-bearing — must match boot script and provision.py)
# ---------------------------------------------------------------------------

DEPLOY_BUCKET_TEMPLATE = "safe-agents-{environment}-deploy"
BUNDLE_CURRENT_KEY = "agents/{name}/current/bundle.tar.gz"
BUNDLE_VERSIONED_KEY = "agents/{name}/{version}/bundle.tar.gz"

# Platform bundle key — stable (not versioned): all deploys of the same code
# share one copy. Boot script extracts this to /opt/safe-agents/core/ so the
# harness lands at /opt/safe-agents/core/contract/harness.py, the path that
# the remote smoke phase SSM-execs (safe_agents/pipeline/phases.py _smoke_remote).
PLATFORM_CONTRACT_KEY = "platform/contract/bundle.tar.gz"

# Default excludes: build artifacts and VCS directories with no place in a
# deployed bundle. Callers can extend via the `excludes` parameter.
_DEFAULT_EXCLUDES: frozenset[str] = frozenset({
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    "*.pyc",
    "*.pyo",
})


# ---------------------------------------------------------------------------
# S3 interface (structural subtyping — testable without boto3)
# ---------------------------------------------------------------------------

class S3PutClient(Protocol):
    """Minimal S3 interface required by upload_bundle."""

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict:
        ...


def _make_s3_client() -> S3PutClient:
    """Return a real boto3 S3 client (lazy import — boto3 only needed at runtime)."""
    import boto3  # noqa: PLC0415

    return boto3.client("s3")  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Bundle creation
# ---------------------------------------------------------------------------

def _exclude_filter(excludes: frozenset[str]):
    """Return a tarfile filter function that omits entries matching `excludes`."""

    def _filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = Path(tarinfo.name).name
        # Exact-name match (e.g. "__pycache__", ".git").
        if name in excludes:
            return None
        # Glob-style suffix pattern (e.g. "*.pyc" matches "foo.pyc").
        for pattern in excludes:
            if pattern.startswith("*.") and name.endswith(pattern[1:]):
                return None
        return tarinfo

    return _filter


def bundle_agent(
    agent_dir: Path,
    agent_name: str,
    *,
    excludes: frozenset[str] | None = None,
) -> bytes:
    """Create an in-memory tar.gz bundle of an agent directory.

    The archive root is `agent_name` so it unpacks cleanly as:
        <agent_name>/run.sh
        <agent_name>/manifest.yaml
        ...

    Parameters
    ----------
    agent_dir:
        Path to the agent package directory (e.g. ``agents/test-stub``).
    agent_name:
        Short name used as the root inside the archive (e.g. ``"test-stub"``).
    excludes:
        Extra filenames or ``*.ext`` glob patterns to omit, merged with the
        default excludes (__pycache__, .git, *.pyc, etc.).

    Returns
    -------
    Raw bytes of a gzip-compressed tar archive.
    """
    all_excludes = _DEFAULT_EXCLUDES | (excludes or frozenset())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(
            agent_dir,
            arcname=agent_name,
            filter=_exclude_filter(all_excludes),
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def upload_bundle(
    bundle_bytes: bytes,
    agent_name: str,
    environment: str,
    version: str | None = None,
    *,
    s3: S3PutClient | None = None,
) -> dict:
    """Upload a bundle to S3 at the standard current + versioned keys.

    Two uploads per call (both or neither, barring intermittent failures):
      agents/<name>/current/bundle.tar.gz    — always the latest
      agents/<name>/<version>/bundle.tar.gz  — versioned copy (immutable)

    Parameters
    ----------
    bundle_bytes:
        Raw bundle bytes, typically from ``bundle_agent()``.
    agent_name:
        Agent short name (e.g. ``"test-stub"``).
    environment:
        Deployment environment: ``development`` | ``staging`` | ``production``.
    version:
        Version string for the versioned key. If None, a compact UTC timestamp
        is generated (``YYYYMMDDTHHMMSSZ``).
    s3:
        S3PutClient implementation. If None, a real boto3 client is created
        (lazy import). Inject a FakeS3 in unit tests to avoid live AWS calls.

    Returns
    -------
    dict with keys:
        ``bucket``      — deploy bucket name
        ``current_key`` — ``agents/<name>/current/bundle.tar.gz``
        ``version_key`` — ``agents/<name>/<version>/bundle.tar.gz``
        ``version``     — the version string used
    """
    if version is None:
        version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if s3 is None:
        s3 = _make_s3_client()

    bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=environment)
    current_key = BUNDLE_CURRENT_KEY.format(name=agent_name)
    version_key = BUNDLE_VERSIONED_KEY.format(name=agent_name, version=version)

    s3.put_object(Bucket=bucket, Key=current_key, Body=bundle_bytes)
    s3.put_object(Bucket=bucket, Key=version_key, Body=bundle_bytes)

    return {
        "bucket": bucket,
        "current_key": current_key,
        "version_key": version_key,
        "version": version,
    }


# ---------------------------------------------------------------------------
# Platform bundle (safe_agents/contract/ → S3 at boot)
# ---------------------------------------------------------------------------

def bundle_platform_contract(
    contract_dir: Path,
    *,
    excludes: frozenset[str] | None = None,
) -> bytes:
    """Create an in-memory tar.gz bundle of the safe_agents/contract/ directory.

    The archive root is ``contract`` so it extracts cleanly under any parent:

        tar -xzf bundle.tar.gz -C /opt/safe-agents/core

    yields:

        /opt/safe-agents/core/contract/harness.py
        /opt/safe-agents/core/contract/__init__.py
        ...

    That is the path the remote smoke phase SSM-execs:
        python3 /opt/safe-agents/core/contract/harness.py /opt/agents/<name>

    Parameters
    ----------
    contract_dir:
        Path to the ``safe_agents/contract/`` directory on the build host.
    excludes:
        Extra filenames or ``*.ext`` glob patterns to omit (merged with defaults).

    Returns
    -------
    Raw bytes of a gzip-compressed tar archive.
    """
    all_excludes = _DEFAULT_EXCLUDES | (excludes or frozenset())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(
            contract_dir,
            arcname="contract",
            filter=_exclude_filter(all_excludes),
        )
    return buf.getvalue()


def upload_platform_contract(
    bundle_bytes: bytes,
    environment: str,
    *,
    s3: S3PutClient | None = None,
) -> dict:
    """Upload the platform/contract bundle to the deploy bucket at a stable key.

    Unlike the agent bundle there is no versioned copy — the key is stable so
    the boot script always fetches the latest platform release for that env.

        s3://safe-agents-<env>-deploy/platform/contract/bundle.tar.gz

    Parameters
    ----------
    bundle_bytes:
        Raw bundle bytes, typically from ``bundle_platform_contract()``.
    environment:
        Deployment environment: ``development`` | ``staging`` | ``production``.
    s3:
        S3PutClient implementation. If None, a real boto3 client is created.

    Returns
    -------
    dict with keys:
        ``bucket`` — deploy bucket name
        ``key``    — ``platform/contract/bundle.tar.gz``
    """
    if s3 is None:
        s3 = _make_s3_client()

    bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=environment)
    s3.put_object(Bucket=bucket, Key=PLATFORM_CONTRACT_KEY, Body=bundle_bytes)

    return {"bucket": bucket, "key": PLATFORM_CONTRACT_KEY}


# Default contract directory: safe_agents/contract/ relative to this file.
# bundle.py lives at safe_agents/arms/ec2/ami/bundle.py → four parents up = core/ → contract/.
_DEFAULT_CONTRACT_DIR: Path = Path(__file__).parent.parent.parent.parent / "contract"

# Default rhel-bootstrap directory: safe_agents/arms/rhel_openshell/bootstrap/ relative to this file.
# bundle.py → ec2/ami/ → ec2/ → arms/ → core/ → arms/rhel_openshell/bootstrap/.
_DEFAULT_RHEL_BOOTSTRAP_DIR: Path = (
    Path(__file__).parent.parent.parent / "rhel_openshell" / "bootstrap"
)

# The RHEL box-side runner dir: safe_agents/arms/rhel_openshell/box/ (the converged run-brokered.sh,
# sa#35). Bundled ALONGSIDE bootstrap/ into the same rhel-bootstrap tarball so the box pulls one
# bundle at boot. Mirrors the EC2 arm's box/ dir; delivered via the S3 gateway endpoint.
_DEFAULT_RHEL_BOX_DIR: Path = (
    Path(__file__).parent.parent.parent / "rhel_openshell" / "box"
)

# Default ec2-bootstrap directory: safe_agents/arms/ec2/bootstrap/ relative to this file.
# bundle.py → ec2/ami/ → ec2/ → bootstrap/.
_DEFAULT_EC2_BOOTSTRAP_DIR: Path = Path(__file__).parent.parent / "bootstrap"

# The always-on EC2 box-side runner dir: safe_agents/arms/ec2/box/ (the converged run-brokered.sh,
# sa#35). Bundled ALONGSIDE bootstrap/ into the same ec2-bootstrap tarball so the box pulls one
# bundle at boot. Mirrors the ec2-woken box/ dir; delivered via the S3 gateway endpoint.
_DEFAULT_EC2_BOX_DIR: Path = Path(__file__).parent.parent / "box"


# ---------------------------------------------------------------------------
# RHEL bootstrap bundle (bootstrap/ → S3 at boot)
# ---------------------------------------------------------------------------

# Stable key (not versioned): all deploys of the same code share one copy, and
# the boot script always fetches the current platform release for that env.
RHEL_BOOTSTRAP_KEY = "platform/rhel-bootstrap/bundle.tar.gz"


def bundle_rhel_bootstrap(
    bootstrap_dir: Path,
    *,
    box_dir: Path | None = None,
    excludes: frozenset[str] | None = None,
) -> bytes:
    """Create an in-memory tar.gz bundle of the rhel_openshell/bootstrap/ + box/ dirs (sa#35).

    The archive root is ``rhel-bootstrap`` so it extracts cleanly:

        tar -xzf bundle.tar.gz -C /home/dev/rhel-bootstrap --strip-components=1

    yields:

        /home/dev/rhel-bootstrap/bootstrap.sh
        /home/dev/rhel-bootstrap/scripts/install-tools.sh
        /home/dev/rhel-bootstrap/scripts/install-openshell.sh
        /home/dev/rhel-bootstrap/box/run-brokered.sh
        ...

    bootstrap.sh then installs the confinement + runner scripts to /opt/safe-agents/bin. The
    converged two-box model drops the co-located model-proxy stub — the broker is its own service
    — so ``model-proxy-stub.py`` is never part of the delivered set even if a legacy copy lingers.

    Parameters
    ----------
    bootstrap_dir:
        Path to ``safe_agents/arms/rhel_openshell/bootstrap/`` on the build host.
    box_dir:
        Path to ``safe_agents/arms/rhel_openshell/box/`` (the run-brokered.sh runner). Defaults to the
        sibling ``box/`` dir. Bundled under ``rhel-bootstrap/box/`` in the same tarball.
    excludes:
        Extra filenames or ``*.ext`` glob patterns to omit (merged with defaults).

    Returns
    -------
    Raw bytes of a gzip-compressed tar archive.
    """
    all_excludes = _DEFAULT_EXCLUDES | {"model-proxy-stub.py"} | (excludes or frozenset())
    box_dir = box_dir if box_dir is not None else _DEFAULT_RHEL_BOX_DIR
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(
            bootstrap_dir,
            arcname="rhel-bootstrap",
            filter=_exclude_filter(all_excludes),
        )
        if box_dir.is_dir():
            tar.add(
                box_dir,
                arcname="rhel-bootstrap/box",
                filter=_exclude_filter(all_excludes),
            )
    return buf.getvalue()


def upload_rhel_bootstrap(
    bundle_bytes: bytes,
    environment: str,
    *,
    s3: S3PutClient | None = None,
) -> dict:
    """Upload the rhel-bootstrap bundle to the deploy bucket at its stable key.

    Unlike the agent bundle there is no versioned copy — the key is stable so
    the boot script always fetches the current platform release:

        s3://safe-agents-<env>-deploy/platform/rhel-bootstrap/bundle.tar.gz

    Parameters
    ----------
    bundle_bytes:
        Raw bundle bytes, typically from ``bundle_rhel_bootstrap()``.
    environment:
        Deployment environment: ``development`` | ``staging`` | ``production``.
    s3:
        S3PutClient implementation. If None, a real boto3 client is created.

    Returns
    -------
    dict with keys:
        ``bucket`` — deploy bucket name
        ``key``    — ``platform/rhel-bootstrap/bundle.tar.gz``
    """
    if s3 is None:
        s3 = _make_s3_client()

    bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=environment)
    s3.put_object(Bucket=bucket, Key=RHEL_BOOTSTRAP_KEY, Body=bundle_bytes)

    return {"bucket": bucket, "key": RHEL_BOOTSTRAP_KEY}


# ---------------------------------------------------------------------------
# EC2 bootstrap bundle (ec2/bootstrap/ → S3 at boot, sa#97)
# ---------------------------------------------------------------------------

# Stable key (not versioned), mirroring the rhel-bootstrap bundle: the EC2 boot
# script (user-data.sh.tmpl) fetches the netns + broker-proxy confinement scripts
# from here at boot via the S3 gateway endpoint (no internet).
EC2_BOOTSTRAP_KEY = "platform/ec2-bootstrap/bundle.tar.gz"


def bundle_ec2_bootstrap(
    bootstrap_dir: Path,
    *,
    box_dir: Path | None = None,
    excludes: frozenset[str] | None = None,
) -> bytes:
    """Create an in-memory tar.gz bundle of the ec2/bootstrap/ + ec2/box/ dirs (sa#35).

    The archive root is ``ec2-bootstrap`` so it extracts cleanly:

        tar -xzf bundle.tar.gz -C /opt/safe-agents

    yields:

        /opt/safe-agents/ec2-bootstrap/scripts/agent-netns-setup.sh
        /opt/safe-agents/ec2-bootstrap/scripts/smoke-egress.sh
        /opt/safe-agents/ec2-bootstrap/box/run-brokered.sh

    user-data then installs those to /opt/safe-agents/bin (the stable paths the netns-setup
    system service + the agent service exec). The converged two-box model drops the co-located
    model-proxy stub — the broker is its own service — so ``model-proxy-stub.py`` is no longer
    part of the delivered set even if the source dir still carries legacy files.

    Parameters
    ----------
    bootstrap_dir:
        Path to ``safe_agents/arms/ec2/bootstrap/`` on the build host.
    box_dir:
        Path to ``safe_agents/arms/ec2/box/`` (the run-brokered.sh runner). Defaults to the sibling
        ``box/`` dir. Bundled under ``ec2-bootstrap/box/`` in the same tarball.
    excludes:
        Extra filenames or ``*.ext`` glob patterns to omit (merged with defaults).

    Returns
    -------
    Raw bytes of a gzip-compressed tar archive.
    """
    # model-proxy-stub.py is intentionally NOT delivered in the converged two-box model (the
    # broker is its own service). The file remains in the source tree because the `local` arm
    # build-COPYs it for its own in-container proxy — but it never rides the EC2 box bundle.
    all_excludes = _DEFAULT_EXCLUDES | {"model-proxy-stub.py"} | (excludes or frozenset())
    box_dir = box_dir if box_dir is not None else _DEFAULT_EC2_BOX_DIR
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(
            bootstrap_dir,
            arcname="ec2-bootstrap",
            filter=_exclude_filter(all_excludes),
        )
        if box_dir.is_dir():
            tar.add(
                box_dir,
                arcname="ec2-bootstrap/box",
                filter=_exclude_filter(all_excludes),
            )
    return buf.getvalue()


def upload_ec2_bootstrap(
    bundle_bytes: bytes,
    environment: str,
    *,
    s3: S3PutClient | None = None,
) -> dict:
    """Upload the ec2-bootstrap bundle to the deploy bucket at its stable key (sa#97).

    Like the rhel-bootstrap bundle there is no versioned copy — the key is stable so
    the boot script always fetches the current platform release:

        s3://safe-agents-<env>-deploy/platform/ec2-bootstrap/bundle.tar.gz

    Parameters
    ----------
    bundle_bytes:
        Raw bundle bytes, typically from ``bundle_ec2_bootstrap()``.
    environment:
        Deployment environment: ``development`` | ``staging`` | ``production``.
    s3:
        S3PutClient implementation. If None, a real boto3 client is created.

    Returns
    -------
    dict with keys:
        ``bucket`` — deploy bucket name
        ``key``    — ``platform/ec2-bootstrap/bundle.tar.gz``
    """
    if s3 is None:
        s3 = _make_s3_client()

    bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=environment)
    s3.put_object(Bucket=bucket, Key=EC2_BOOTSTRAP_KEY, Body=bundle_bytes)

    return {"bucket": bucket, "key": EC2_BOOTSTRAP_KEY}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def read_manifest_identity(manifest_path: Path) -> tuple[str, str | None]:
    """Read (name, agent_package) from a deployment manifest YAML.

    The S3 bundle key is derived from the manifest ``name`` (the box pulls
    ``agents/<name>/current/bundle.tar.gz``), while the *source directory* to
    bundle is ``agent_package`` (which may differ — e.g. smoke-rhel-openshell
    packages the test-stub fixture). Returns ``agent_package`` as None when the
    manifest omits it (the caller defaults the source dir to the name).
    """
    import yaml  # noqa: PLC0415 — lazy import, like argparse in main()

    with manifest_path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict) or not raw.get("name"):
        raise SystemExit(
            f"error: manifest {manifest_path} missing required 'name' field"
        )
    return str(raw["name"]), (raw.get("agent_package") or None)


def main(argv: list[str] | None = None) -> None:
    """Bundle an agent directory and upload ALL platform bundles to the S3 deploy bucket.

    Uploads in one invocation:
      1. The agent bundle  (agents/<name>/current/bundle.tar.gz + versioned copy)
      2. The platform/contract bundle  (platform/contract/bundle.tar.gz)
      3. The rhel-bootstrap bundle  (platform/rhel-bootstrap/bundle.tar.gz)
      4. The ec2-bootstrap bundle  (platform/ec2-bootstrap/bundle.tar.gz)

    Usage (preferred — derives the S3 key from the manifest so name != package is safe)::

        python -m safe_agents.arms.ec2.ami.bundle \\
            --manifest agents/smoke-rhel-openshell.yaml \\
            --environment development

    Usage (explicit — --agent-name MUST equal the manifest 'name', not the package dir)::

        python -m safe_agents.arms.ec2.ami.bundle \\
            --agent-dir agents/test-stub \\
            --agent-name smoke-rhel-openshell \\
            --environment development \\
            [--version 20260628T120000Z] \\
            [--contract-dir core/contract] \\
            [--bootstrap-dir safe_agents/arms/rhel_openshell/bootstrap]

    Credentials: boto3 reads from the standard AWS credential chain (env vars,
    ~/.aws/credentials, or the instance profile). CI should use an OIDC role.
    """
    import argparse  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        description=(
            "Bundle an agent package and the platform bundles (contract + rhel-bootstrap), "
            "then upload all to the S3 deploy bucket."
        )
    )
    parser.add_argument(
        "--manifest",
        default=None,
        metavar="PATH",
        help=(
            "Path to a deployment manifest (agents/<name>.yaml). Preferred: derives the "
            "S3 key from the manifest 'name' and the source dir from 'agent_package', so "
            "the key always matches what the box pulls. Mutually exclusive with "
            "--agent-dir/--agent-name."
        ),
    )
    parser.add_argument(
        "--agent-dir",
        default=None,
        help="Path to the agent source directory. Use with --agent-name (or use --manifest).",
    )
    parser.add_argument(
        "--agent-name",
        default=None,
        help=(
            "S3 bundle name — MUST equal the manifest 'name' (the box pulls "
            "agents/<name>/...), which may differ from the package dir. Prefer --manifest."
        ),
    )
    parser.add_argument(
        "--environment",
        required=True,
        choices=("development", "staging", "production"),
        help="Target environment (selects the deploy bucket).",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Version tag for the versioned S3 key (default: UTC timestamp).",
    )
    parser.add_argument(
        "--contract-dir",
        default=None,
        metavar="DIR",
        help=(
            "Path to the core/contract directory containing the conformance harness. "
            f"Default: {_DEFAULT_CONTRACT_DIR}"
        ),
    )
    parser.add_argument(
        "--bootstrap-dir",
        default=None,
        metavar="DIR",
        help=(
            "Path to safe_agents/arms/rhel_openshell/bootstrap/ (RHEL box bootstrap scripts). "
            f"Default: {_DEFAULT_RHEL_BOOTSTRAP_DIR}"
        ),
    )
    parser.add_argument(
        "--ec2-bootstrap-dir",
        default=None,
        metavar="DIR",
        help=(
            "Path to safe_agents/arms/ec2/bootstrap/ (EC2 netns + broker-proxy confinement "
            f"scripts, sa#97). Default: {_DEFAULT_EC2_BOOTSTRAP_DIR}"
        ),
    )
    args = parser.parse_args(argv)

    # Resolve agent identity from --manifest (single source of truth) or the
    # explicit --agent-dir/--agent-name pair. --manifest avoids the footgun of
    # uploading under the package name when name != agent_package.
    if args.manifest:
        if args.agent_dir or args.agent_name:
            raise SystemExit(
                "error: --manifest is mutually exclusive with --agent-dir/--agent-name"
            )
        manifest_path = Path(args.manifest).resolve()
        if not manifest_path.is_file():
            raise SystemExit(f"error: manifest not found: {manifest_path}")
        agent_name, agent_package = read_manifest_identity(manifest_path)
        # agent_package is relative to the agents/ dir (the manifest's parent);
        # default the source dir to the manifest name when omitted.
        agent_dir = (manifest_path.parent / (agent_package or agent_name)).resolve()
    else:
        if not (args.agent_dir and args.agent_name):
            raise SystemExit(
                "error: provide --manifest, or both --agent-dir and --agent-name"
            )
        agent_name = args.agent_name
        agent_dir = Path(args.agent_dir).resolve()

    if not agent_dir.is_dir():
        raise SystemExit(f"error: agent-dir not found: {agent_dir}")

    contract_dir = Path(args.contract_dir).resolve() if args.contract_dir else _DEFAULT_CONTRACT_DIR
    if not contract_dir.is_dir():
        raise SystemExit(f"error: contract-dir not found: {contract_dir}")

    bootstrap_dir = (
        Path(args.bootstrap_dir).resolve() if args.bootstrap_dir else _DEFAULT_RHEL_BOOTSTRAP_DIR
    )
    if not bootstrap_dir.is_dir():
        raise SystemExit(f"error: bootstrap-dir not found: {bootstrap_dir}")

    ec2_bootstrap_dir = (
        Path(args.ec2_bootstrap_dir).resolve()
        if args.ec2_bootstrap_dir
        else _DEFAULT_EC2_BOOTSTRAP_DIR
    )
    if not ec2_bootstrap_dir.is_dir():
        raise SystemExit(f"error: ec2-bootstrap-dir not found: {ec2_bootstrap_dir}")

    bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=args.environment)
    print(f"Uploading to s3://{bucket} ...")

    # -- Agent bundle ----------------------------------------------------------
    print(f"Bundling agent: {agent_dir} ...")
    agent_bytes = bundle_agent(agent_dir, agent_name)
    print(f"  agent bundle size: {len(agent_bytes):,} bytes")
    agent_result = upload_bundle(
        agent_bytes,
        agent_name=agent_name,
        environment=args.environment,
        version=args.version,
    )
    print(f"  s3://{agent_result['bucket']}/{agent_result['current_key']}")
    print(f"  s3://{agent_result['bucket']}/{agent_result['version_key']}")
    print(f"  version={agent_result['version']}")

    # -- Platform/contract bundle ----------------------------------------------
    print(f"Bundling platform/contract: {contract_dir} ...")
    platform_bytes = bundle_platform_contract(contract_dir)
    print(f"  platform bundle size: {len(platform_bytes):,} bytes")
    platform_result = upload_platform_contract(platform_bytes, environment=args.environment)
    print(f"  s3://{platform_result['bucket']}/{platform_result['key']}")

    # -- RHEL bootstrap bundle -------------------------------------------------
    print(f"Bundling rhel-bootstrap: {bootstrap_dir} ...")
    bootstrap_bytes = bundle_rhel_bootstrap(bootstrap_dir)
    print(f"  rhel-bootstrap bundle size: {len(bootstrap_bytes):,} bytes")
    bootstrap_result = upload_rhel_bootstrap(bootstrap_bytes, environment=args.environment)
    print(f"  s3://{bootstrap_result['bucket']}/{bootstrap_result['key']}")

    # -- EC2 bootstrap bundle (sa#97) ------------------------------------------
    print(f"Bundling ec2-bootstrap: {ec2_bootstrap_dir} ...")
    ec2_bootstrap_bytes = bundle_ec2_bootstrap(ec2_bootstrap_dir)
    print(f"  ec2-bootstrap bundle size: {len(ec2_bootstrap_bytes):,} bytes")
    ec2_bootstrap_result = upload_ec2_bootstrap(ec2_bootstrap_bytes, environment=args.environment)
    print(f"  s3://{ec2_bootstrap_result['bucket']}/{ec2_bootstrap_result['key']}")

    print("Done.")


if __name__ == "__main__":
    main()
