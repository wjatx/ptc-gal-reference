"""
Unit tests for safe_agents/arms/ec2/ami/bundle.py (sa#84).

All tests are S3-free: AWS calls go through FakeS3. No live boto3 required.

Run from core/:
    cd core && ./.venv/bin/python -m pytest arms/ec2/tests/test_ami_bundle.py -q
"""
from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

import pytest

from safe_agents.arms.ec2.ami.bundle import (
    BUNDLE_CURRENT_KEY,
    BUNDLE_VERSIONED_KEY,
    DEPLOY_BUCKET_TEMPLATE,
    EC2_BOOTSTRAP_KEY,
    PLATFORM_CONTRACT_KEY,
    bundle_agent,
    bundle_ec2_bootstrap,
    bundle_platform_contract,
    read_manifest_identity,
    upload_bundle,
    upload_ec2_bootstrap,
    upload_platform_contract,
)


# ---------------------------------------------------------------------------
# Fake S3 client — records put_object calls for assertion
# ---------------------------------------------------------------------------

class FakeS3:
    """Minimal S3 double that records every put_object call."""

    def __init__(self) -> None:
        self.puts: list[dict] = []

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict:
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body})
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent_dir(tmp_path: Path, files: dict[str, str]) -> Path:
    agent_dir = tmp_path / "test-stub"
    agent_dir.mkdir()
    for name, content in files.items():
        (agent_dir / name).write_text(content)
    return agent_dir


def _names_in_bundle(data: bytes) -> list[str]:
    buf = io.BytesIO(data)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        return tar.getnames()


# ---------------------------------------------------------------------------
# bundle_agent — archive structure
# ---------------------------------------------------------------------------

def test_bundle_agent_returns_valid_tar_gz(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(tmp_path, {"run.sh": "#!/bin/bash\necho run"})
    data = bundle_agent(agent_dir, "test-stub")
    # Must round-trip as a valid gzip-compressed tar.
    names = _names_in_bundle(data)
    assert "test-stub/run.sh" in names


def test_bundle_agent_root_is_agent_name(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(tmp_path, {"manifest.yaml": "job: test-stub"})
    data = bundle_agent(agent_dir, "test-stub")
    for name in _names_in_bundle(data):
        assert name == "test-stub" or name.startswith("test-stub/"), (
            f"archive entry outside agent root: {name!r}"
        )


def test_bundle_agent_includes_expected_files(tmp_path: Path) -> None:
    files = {
        "run.sh": "#!/bin/bash",
        "manifest.yaml": "job: test-stub",
        "agent.py": "# agent",
    }
    agent_dir = _make_agent_dir(tmp_path, files)
    data = bundle_agent(agent_dir, "test-stub")
    base_names = {Path(n).name for n in _names_in_bundle(data)}
    for fname in files:
        assert fname in base_names, f"expected {fname!r} in bundle"


def test_bundle_agent_excludes_pycache(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(tmp_path, {"run.sh": "echo hi"})
    pycache = agent_dir / "__pycache__"
    pycache.mkdir()
    (pycache / "cached.cpython-312.pyc").write_text("compiled")

    data = bundle_agent(agent_dir, "test-stub")
    assert not any("__pycache__" in n for n in _names_in_bundle(data))


def test_bundle_agent_excludes_pyc_files(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(
        tmp_path, {"agent.py": "# agent", "agent.pyc": "compiled"}
    )
    data = bundle_agent(agent_dir, "test-stub")
    assert not any(n.endswith(".pyc") for n in _names_in_bundle(data))


def test_bundle_agent_excludes_git_dir(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(tmp_path, {"run.sh": "#!/bin/bash"})
    git_dir = agent_dir / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main")

    data = bundle_agent(agent_dir, "test-stub")
    assert not any(".git" in n for n in _names_in_bundle(data))


def test_bundle_agent_custom_excludes(tmp_path: Path) -> None:
    agent_dir = _make_agent_dir(
        tmp_path, {"run.sh": "hi", "secret.key": "PRIVATE"}
    )
    data = bundle_agent(agent_dir, "test-stub", excludes=frozenset({"secret.key"}))
    base_names = {Path(n).name for n in _names_in_bundle(data)}
    assert "secret.key" not in base_names
    assert "run.sh" in base_names


# ---------------------------------------------------------------------------
# upload_bundle — S3 calls and key format
# ---------------------------------------------------------------------------

_CASES = [
    ("test-stub", "development", "20260628T120000Z"),
    ("my-agent", "staging", "20260701T000000Z"),
    ("prod-agent", "production", "20260715T235959Z"),
]


@pytest.mark.parametrize("agent_name,environment,version", _CASES)
def test_upload_bundle_bucket_name(agent_name, environment, version) -> None:
    s3 = FakeS3()
    upload_bundle(b"data", agent_name, environment, version=version, s3=s3)
    expected = f"safe-agents-{environment}-deploy"
    assert all(p["Bucket"] == expected for p in s3.puts), s3.puts


@pytest.mark.parametrize("agent_name,environment,version", _CASES)
def test_upload_bundle_current_key(agent_name, environment, version) -> None:
    s3 = FakeS3()
    upload_bundle(b"data", agent_name, environment, version=version, s3=s3)
    keys = [p["Key"] for p in s3.puts]
    assert f"agents/{agent_name}/current/bundle.tar.gz" in keys, keys


@pytest.mark.parametrize("agent_name,environment,version", _CASES)
def test_upload_bundle_versioned_key(agent_name, environment, version) -> None:
    s3 = FakeS3()
    upload_bundle(b"data", agent_name, environment, version=version, s3=s3)
    keys = [p["Key"] for p in s3.puts]
    assert f"agents/{agent_name}/{version}/bundle.tar.gz" in keys, keys


def test_upload_bundle_uploads_exact_bytes() -> None:
    payload = b"tarball-content-bytes"
    s3 = FakeS3()
    upload_bundle(payload, "test-stub", "development", version="v1", s3=s3)
    assert all(p["Body"] == payload for p in s3.puts)


def test_upload_bundle_makes_exactly_two_puts() -> None:
    s3 = FakeS3()
    upload_bundle(b"x", "test-stub", "development", version="v1", s3=s3)
    assert len(s3.puts) == 2, f"expected 2 put_object calls, got {len(s3.puts)}"


def test_upload_bundle_returns_result_dict() -> None:
    s3 = FakeS3()
    result = upload_bundle(b"x", "test-stub", "staging", version="v2", s3=s3)
    assert result["bucket"] == "safe-agents-staging-deploy"
    assert result["current_key"] == "agents/test-stub/current/bundle.tar.gz"
    assert result["version_key"] == "agents/test-stub/v2/bundle.tar.gz"
    assert result["version"] == "v2"


def test_upload_bundle_auto_version_format() -> None:
    """Auto-generated version must be a compact UTC ISO timestamp (YYYYMMDDTHHMMSSZ)."""
    s3 = FakeS3()
    result = upload_bundle(b"x", "test-stub", "development", s3=s3)
    assert re.match(r"^\d{8}T\d{6}Z$", result["version"]), (
        f"unexpected version format: {result['version']!r}"
    )


def test_upload_bundle_auto_version_appears_in_versioned_key() -> None:
    s3 = FakeS3()
    result = upload_bundle(b"x", "test-stub", "development", s3=s3)
    assert result["version"] in result["version_key"]


# ---------------------------------------------------------------------------
# Convention constant format (load-bearing — must stay in sync with boot script)
# ---------------------------------------------------------------------------

def test_deploy_bucket_template_format() -> None:
    assert DEPLOY_BUCKET_TEMPLATE.format(environment="development") == (
        "safe-agents-development-deploy"
    )
    assert DEPLOY_BUCKET_TEMPLATE.format(environment="production") == (
        "safe-agents-production-deploy"
    )


def test_bundle_current_key_format() -> None:
    assert BUNDLE_CURRENT_KEY.format(name="test-stub") == (
        "agents/test-stub/current/bundle.tar.gz"
    )


def test_bundle_versioned_key_format() -> None:
    assert BUNDLE_VERSIONED_KEY.format(name="test-stub", version="20260628T120000Z") == (
        "agents/test-stub/20260628T120000Z/bundle.tar.gz"
    )


# ---------------------------------------------------------------------------
# PLATFORM_CONTRACT_KEY constant
# ---------------------------------------------------------------------------

def test_platform_contract_key_stable_value() -> None:
    """The key must be stable (no format placeholders) so the boot script always
    fetches the latest platform release without knowing a version string."""
    assert PLATFORM_CONTRACT_KEY == "platform/contract/bundle.tar.gz"


def test_platform_contract_key_no_format_placeholders() -> None:
    assert "{" not in PLATFORM_CONTRACT_KEY and "}" not in PLATFORM_CONTRACT_KEY


# ---------------------------------------------------------------------------
# bundle_platform_contract — archive structure
# ---------------------------------------------------------------------------

def _make_contract_dir(tmp_path: Path, files: dict[str, str]) -> Path:
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    for name, content in files.items():
        (contract_dir / name).write_text(content)
    return contract_dir


def test_bundle_platform_contract_returns_valid_tar_gz(tmp_path: Path) -> None:
    contract_dir = _make_contract_dir(tmp_path, {"harness.py": "# harness"})
    data = bundle_platform_contract(contract_dir)
    names = _names_in_bundle(data)
    assert "contract/harness.py" in names


def test_bundle_platform_contract_root_is_contract(tmp_path: Path) -> None:
    contract_dir = _make_contract_dir(
        tmp_path, {"harness.py": "# harness", "__init__.py": ""}
    )
    data = bundle_platform_contract(contract_dir)
    for name in _names_in_bundle(data):
        assert name == "contract" or name.startswith("contract/"), (
            f"archive entry outside contract root: {name!r}"
        )


def test_bundle_platform_contract_extracts_to_expected_path(tmp_path: Path) -> None:
    """Extracting to /opt/safe-agents/core must place harness at the remote smoke path."""
    contract_dir = _make_contract_dir(tmp_path, {"harness.py": "# harness"})
    data = bundle_platform_contract(contract_dir)
    names = _names_in_bundle(data)
    # After: tar -xzf bundle.tar.gz -C /opt/safe-agents/core
    # the result is /opt/safe-agents/core/contract/harness.py
    # which matches phases.py _smoke_remote harness_cmd.
    assert "contract/harness.py" in names


def test_bundle_platform_contract_excludes_pycache(tmp_path: Path) -> None:
    contract_dir = _make_contract_dir(tmp_path, {"harness.py": "# harness"})
    pycache = contract_dir / "__pycache__"
    pycache.mkdir()
    (pycache / "harness.cpython-312.pyc").write_text("compiled")
    data = bundle_platform_contract(contract_dir)
    assert not any("__pycache__" in n for n in _names_in_bundle(data))


def test_bundle_platform_contract_excludes_pyc(tmp_path: Path) -> None:
    contract_dir = _make_contract_dir(
        tmp_path, {"harness.py": "# harness", "harness.pyc": "compiled"}
    )
    data = bundle_platform_contract(contract_dir)
    assert not any(n.endswith(".pyc") for n in _names_in_bundle(data))


# ---------------------------------------------------------------------------
# upload_platform_contract — S3 calls and key format
# ---------------------------------------------------------------------------

_PLATFORM_ENV_CASES = ["development", "staging", "production"]


@pytest.mark.parametrize("environment", _PLATFORM_ENV_CASES)
def test_upload_platform_contract_bucket_name(environment: str) -> None:
    s3 = FakeS3()
    upload_platform_contract(b"data", environment, s3=s3)
    assert len(s3.puts) == 1
    assert s3.puts[0]["Bucket"] == f"safe-agents-{environment}-deploy"


@pytest.mark.parametrize("environment", _PLATFORM_ENV_CASES)
def test_upload_platform_contract_key(environment: str) -> None:
    s3 = FakeS3()
    upload_platform_contract(b"data", environment, s3=s3)
    assert s3.puts[0]["Key"] == "platform/contract/bundle.tar.gz"


def test_upload_platform_contract_makes_exactly_one_put() -> None:
    """One stable key — no versioned copy."""
    s3 = FakeS3()
    upload_platform_contract(b"payload", "development", s3=s3)
    assert len(s3.puts) == 1, f"expected 1 put_object call, got {len(s3.puts)}"


def test_upload_platform_contract_uploads_exact_bytes() -> None:
    payload = b"harness-bundle-bytes"
    s3 = FakeS3()
    upload_platform_contract(payload, "staging", s3=s3)
    assert s3.puts[0]["Body"] == payload


def test_upload_platform_contract_returns_result_dict() -> None:
    s3 = FakeS3()
    result = upload_platform_contract(b"x", "production", s3=s3)
    assert result["bucket"] == "safe-agents-production-deploy"
    assert result["key"] == "platform/contract/bundle.tar.gz"


# ---------------------------------------------------------------------------
# EC2 bootstrap bundle (sa#97) — netns + broker-proxy confinement scripts
# ---------------------------------------------------------------------------

def _make_ec2_bootstrap_dir(tmp_path: Path) -> Path:
    """A minimal ec2/bootstrap/ tree: scripts/ with the confinement scripts (sa#35: no stub)."""
    root = tmp_path / "bootstrap"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "agent-netns-setup.sh").write_text("#!/usr/bin/env bash\nip netns add agent-ns\n")
    (scripts / "smoke-egress.sh").write_text("#!/usr/bin/env bash\n")
    # The stub file remains in the source tree (the `local` arm build-COPYs it) but must be
    # EXCLUDED from the delivered ec2 bundle in the two-box model.
    (scripts / "model-proxy-stub.py").write_text("#!/usr/bin/env python3\n")
    return root


def _make_ec2_box_dir(tmp_path: Path) -> Path:
    """A minimal ec2/box/ tree: the run-brokered.sh runner (sa#35)."""
    box = tmp_path / "box"
    box.mkdir(parents=True)
    (box / "run-brokered.sh").write_text("#!/usr/bin/env bash\nclaude -p hi\n")
    return box


def test_ec2_bootstrap_key_stable_value() -> None:
    """Stable key (no placeholders) so the boot script always fetches the latest copy."""
    assert EC2_BOOTSTRAP_KEY == "platform/ec2-bootstrap/bundle.tar.gz"
    assert "{" not in EC2_BOOTSTRAP_KEY and "}" not in EC2_BOOTSTRAP_KEY


def test_bundle_ec2_bootstrap_root_is_ec2_bootstrap(tmp_path: Path) -> None:
    data = bundle_ec2_bootstrap(_make_ec2_bootstrap_dir(tmp_path))
    for name in _names_in_bundle(data):
        assert name == "ec2-bootstrap" or name.startswith("ec2-bootstrap/"), (
            f"archive entry outside ec2-bootstrap root: {name!r}"
        )


def test_bundle_ec2_bootstrap_includes_confinement_scripts(tmp_path: Path) -> None:
    """The arm-agnostic confinement scripts land under scripts/ (no model-proxy stub, sa#35)."""
    data = bundle_ec2_bootstrap(
        _make_ec2_bootstrap_dir(tmp_path), box_dir=_make_ec2_box_dir(tmp_path)
    )
    names = _names_in_bundle(data)
    for script in (
        "ec2-bootstrap/scripts/agent-netns-setup.sh",
        "ec2-bootstrap/scripts/smoke-egress.sh",
    ):
        assert script in names, f"expected {script!r} in the ec2-bootstrap bundle"
    assert "ec2-bootstrap/scripts/model-proxy-stub.py" not in names, (
        "the model-proxy stub must NOT be bundled (two-box model)"
    )


def test_bundle_ec2_bootstrap_includes_run_brokered_runner(tmp_path: Path) -> None:
    """The converged run-brokered.sh runner rides the same bundle under box/ (sa#35)."""
    data = bundle_ec2_bootstrap(
        _make_ec2_bootstrap_dir(tmp_path), box_dir=_make_ec2_box_dir(tmp_path)
    )
    assert "ec2-bootstrap/box/run-brokered.sh" in _names_in_bundle(data), (
        "run-brokered.sh must be delivered under ec2-bootstrap/box/ so user-data can install it"
    )


def test_bundle_ec2_bootstrap_extracts_to_expected_path(tmp_path: Path) -> None:
    """tar -C /opt/safe-agents yields /opt/safe-agents/ec2-bootstrap/scripts/... ."""
    data = bundle_ec2_bootstrap(_make_ec2_bootstrap_dir(tmp_path))
    assert "ec2-bootstrap/scripts/agent-netns-setup.sh" in _names_in_bundle(data)


def test_bundle_ec2_bootstrap_excludes_pycache(tmp_path: Path) -> None:
    root = _make_ec2_bootstrap_dir(tmp_path)
    pycache = root / "scripts" / "__pycache__"
    pycache.mkdir()
    (pycache / "model_proxy_stub.cpython-312.pyc").write_text("compiled")
    data = bundle_ec2_bootstrap(root)
    assert not any("__pycache__" in n for n in _names_in_bundle(data))


@pytest.mark.parametrize("environment", _PLATFORM_ENV_CASES)
def test_upload_ec2_bootstrap_bucket_and_key(environment: str) -> None:
    s3 = FakeS3()
    upload_ec2_bootstrap(b"data", environment, s3=s3)
    assert len(s3.puts) == 1
    assert s3.puts[0]["Bucket"] == f"safe-agents-{environment}-deploy"
    assert s3.puts[0]["Key"] == "platform/ec2-bootstrap/bundle.tar.gz"


def test_upload_ec2_bootstrap_makes_exactly_one_put() -> None:
    """One stable key — no versioned copy (mirrors the rhel-bootstrap bundle)."""
    s3 = FakeS3()
    upload_ec2_bootstrap(b"payload", "development", s3=s3)
    assert len(s3.puts) == 1, f"expected 1 put_object call, got {len(s3.puts)}"


def test_upload_ec2_bootstrap_uploads_exact_bytes_and_result() -> None:
    payload = b"ec2-bootstrap-bundle-bytes"
    s3 = FakeS3()
    result = upload_ec2_bootstrap(payload, "production", s3=s3)
    assert s3.puts[0]["Body"] == payload
    assert result["bucket"] == "safe-agents-production-deploy"
    assert result["key"] == "platform/ec2-bootstrap/bundle.tar.gz"


def test_ec2_bootstrap_key_matches_user_data_pull() -> None:
    """The bundle key must match the key user-data.sh.tmpl pulls (or the box boots unconfined)."""
    user_data = (Path(__file__).parent.parent / "user-data.sh.tmpl").read_text()
    assert EC2_BOOTSTRAP_KEY in user_data, (
        "user-data.sh.tmpl must pull the ec2-bootstrap bundle from EC2_BOOTSTRAP_KEY"
    )


# ---------------------------------------------------------------------------
# Component YAML — bake-bug assertions (no awscli2, no git-clone, official installer)
# ---------------------------------------------------------------------------

import yaml as _yaml  # noqa: E402

_COMPONENT_YAML = (
    Path(__file__).parent.parent / "ami" / "image-builder" / "component-base.yaml"
)


def _component_commands() -> list[str]:
    """Return all bash command strings from all steps in the component YAML."""
    doc = _yaml.safe_load(_component_yaml_text())
    commands: list[str] = []
    for phase in doc.get("phases", []):
        for step in phase.get("steps", []):
            for cmd in step.get("inputs", {}).get("commands", []):
                commands.append(str(cmd))
    return commands


def _component_yaml_text() -> str:
    return _COMPONENT_YAML.read_text()


def test_component_does_not_install_awscli2_via_dnf() -> None:
    """awscli2 is not a valid AL2023 package — must not appear in any dnf install."""
    for cmd in _component_commands():
        assert "awscli2" not in cmd, (
            f"Component must not reference awscli2 (not a valid AL2023 package); "
            f"found in: {cmd!r}"
        )


#: Any org's copy of this repo, under either name it has carried. Deliberately
#: NOT a literal path: this assertion once pinned `Third-Ralph/safe-agents`, the
#: repo moved org, and the guard would have passed no matter what the component
#: cloned. It then pinned the name `safe-agents`, and the repo was renamed again.
#: A guard that names a mutable identifier stops guarding the moment that
#: identifier changes, silently, so both names are matched under any org.
_PRIVATE_REPO_CLONE = re.compile(
    r"github\.com[:/][\w.-]+/(?:safe-agents|ptc-gal-reference)"
)


def test_component_does_not_clone_private_repo() -> None:
    """Harness is delivered via S3 at boot; no private git clone should remain."""
    for cmd in _component_commands():
        assert not _PRIVATE_REPO_CLONE.search(cmd), (
            f"Component must not clone the private repo at bake time; "
            f"found in: {cmd!r}"
        )
    assert "GITHUB_TOKEN" not in _component_yaml_text(), (
        "Component must not reference GITHUB_TOKEN (private-repo auth removed)"
    )


def test_component_installs_aws_cli_via_official_installer() -> None:
    """AWS CLI v2 must be installed via the official aarch64 upstream installer."""
    combined = " ".join(_component_commands())
    assert "awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" in combined, (
        "Component must download the official arm64 AWS CLI v2 installer"
    )
    assert "/tmp/aws/install" in combined, (
        "Component must run the /tmp/aws/install step"
    )


def test_component_installs_unzip() -> None:
    """unzip must be installed via dnf (needed to unpack the AWS CLI installer zip)."""
    dnf_lines = [c for c in _component_commands() if c.startswith("dnf install")]
    assert any("unzip" in line for line in dnf_lines), (
        f"Component must install unzip via dnf; dnf lines: {dnf_lines}"
    )


def test_component_verifies_aws_version() -> None:
    """VerifyInstalls step must still check aws --version after the installer change."""
    assert "aws --version" in _component_commands(), (
        "VerifyInstalls must still run 'aws --version'"
    )


# ---------------------------------------------------------------------------
# read_manifest_identity — the S3 key must come from the manifest name, not the
# package dir (the sa#35 footgun: name='smoke-rhel-openshell', package='test-stub')
# ---------------------------------------------------------------------------


def test_read_manifest_identity_name_and_package_differ(tmp_path: Path) -> None:
    m = tmp_path / "smoke-rhel-openshell.yaml"
    m.write_text("name: smoke-rhel-openshell\nagent_package: test-stub\narm: rhel-openshell\n")
    assert read_manifest_identity(m) == ("smoke-rhel-openshell", "test-stub")


def test_read_manifest_identity_package_absent_returns_none(tmp_path: Path) -> None:
    m = tmp_path / "test-stub.yaml"
    m.write_text("name: test-stub\narm: ec2\n")
    assert read_manifest_identity(m) == ("test-stub", None)


def test_read_manifest_identity_missing_name_raises(tmp_path: Path) -> None:
    m = tmp_path / "broken.yaml"
    m.write_text("arm: ec2\n")
    with pytest.raises(SystemExit):
        read_manifest_identity(m)
