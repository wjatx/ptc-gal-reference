"""
RHEL+OpenShell arm tests — acceptance criteria for sa#91.

All tests are AWS-free: AWS calls go through FakeAWS (no live boto3 needed).

Acceptance criteria:
  1. RHEL AMI resolved by owner/name filter; newest wins.
  2. Thin user-data template renders with required root-essentials only:
       - cgroups v2 delegation before dev user setup
       - SSM agent install (RHEL-specific, must be first major step)
       - dev user creation
       - S3 bundle delivery (agent + platform/contract + rhel-bootstrap)
       - invocation of bootstrap.sh as dev user
       - fail marker on ERR trap
  3a. No k8s tools, No Go/Rust, No Remote Control, No dev-UX packages in template.
  3b. Bootstrap structure (bootstrap/ dir): all required scripts present.
       - tmux in install-tools.sh
       - LIVE-VERIFIED install-openshell.sh (no version pin, no manual gateway add,
         XDG_RUNTIME_DIR + DBUS set, enable-linger present)
       - HARNESS-COUPLING BLOCK markers in setup-claude.sh
       - SA_PROFILE gate for interactive-only tools in bootstrap.sh
       - systemd timer written by bootstrap.sh
  4. Two-identity separation: agentRole grants NO connector-keys access.
  5. Host placed in the ISOLATED agent subnet + agent SG + endpoint SG (sa#35 converged
     two-box model), NOT the NAT broker subnet — mirrors the EC2 arm placement.
  6. Arm dispatch: phases.py registers rhel-openshell in provision + teardown.
  7. Teardown removes instances + per-host IAM (profile + inline policy).
  8. Pipeline gating reused: clean-start → foundation → IAM propagation → launch → SSM online.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Imports (core/ is on sys.path via conftest.py)
# ---------------------------------------------------------------------------

from safe_agents.arms.rhel_openshell.provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    RHEL9_NAME_PATTERN,
    RHEL_OWNER_ID,
    agent_role_extensions,
    render_user_data,
    rhel_openshell_provision,
    rhel_openshell_teardown,
    _pick_newest_rhel_ami,
)
from safe_agents.pipeline import FakeAWS, load_manifest, run_pipeline

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_MANIFEST = AGENTS_DIR / "smoke-rhel-openshell.yaml"
TEMPLATE_PATH = Path(__file__).parent.parent / "user-data.sh.tmpl"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"

# Bootstrap directory and script paths (for Criterion 3b assertions).
BOOTSTRAP_DIR = Path(__file__).parent.parent / "bootstrap"
INSTALL_TOOLS_SCRIPT = BOOTSTRAP_DIR / "scripts" / "install-tools.sh"
INSTALL_PYTHON_ENV_SCRIPT = BOOTSTRAP_DIR / "scripts" / "install-python-env.sh"
INSTALL_OPENSHELL_SCRIPT = BOOTSTRAP_DIR / "scripts" / "install-openshell.sh"
SETUP_CLAUDE_SCRIPT = BOOTSTRAP_DIR / "scripts" / "setup-claude.sh"
BOOTSTRAP_SCRIPT = BOOTSTRAP_DIR / "bootstrap.sh"
# sa#35 netns + broker-SERVICE egress confinement (autonomous profile, converged two-box model).
AGENT_NETNS_SETUP_SCRIPT = BOOTSTRAP_DIR / "scripts" / "agent-netns-setup.sh"
SMOKE_EGRESS_SCRIPT = BOOTSTRAP_DIR / "scripts" / "smoke-egress.sh"
RUN_BROKERED_SCRIPT = BOOTSTRAP_DIR.parent / "box" / "run-brokered.sh"

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_VALID_PARAMS = {
    "name": "my-agent",
    "arm": "rhel-openshell",
    "oauth_token": "my-agent/claude-oauth-token",
    "environment": "development",
    # sa#35 converged two-box model: the box env contract carries the broker SERVICE DNS,
    # the agent-runs table name, and the region (for run-brokered.sh).
    "broker_dns": "broker.safe-agents.local",
    "agent_runs_table": "safe-agents-development-agent-runs",
    "region": "us-east-1",
}

_RHEL_AMI_ID = "ami-0dcaef0e21f109874"
_RHEL_AMI_NAME = "RHEL-9.8_HVM-20250506-x86_64-1893-Hourly2-GP3"

# Pass to rhel_openshell_provision in all unit tests to avoid real sleeps.
# The EC2 arm's _wait_for_iam_propagation calls _time.sleep(extra_buffer) with
# a 5-second default that affects this module's tests too (same call stack).
_FAST = dict(
    _clean_start_ec2_timeout=1.0,
    _clean_start_iam_timeout=1.0,
    _clean_start_poll_interval=0.0,
    _iam_poll_interval=0.0,
    _iam_max_wait=1.0,
    _iam_extra_buffer=0.0,
    _ssm_timeout=10.0,
    _ssm_poll_interval=0.0,
)


@pytest.fixture()
def fake_aws() -> FakeAWS:
    """FakeAWS seeded with infra SSM params, secrets, and RHEL marketplace AMI."""
    aws = FakeAWS()
    aws.seed_secret("smoke-rhel-openshell/runner-keys", "{}")
    aws.seed_secret("smoke-rhel-openshell/broker-keys", '{"KEY": "val"}')
    aws.seed_secret("smoke-rhel-openshell/claude-oauth-token", "oauth-tok-rhel")
    env = "development"
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-role-arn",
        "arn:aws:iam::123456789012:instance-profile/safe-agents-development-AgentRole",
    )
    # Converged two-box placement (sa#35): isolated agent subnet + agent SG + endpoint SG,
    # broker SERVICE DNS, tables CMK — mirrors the EC2 arm's SSM contract.
    aws.seed_ssm_param(f"/safe-agents/{env}/agent-sg-id", "sg-0agent12345")
    aws.seed_ssm_param(f"/safe-agents/{env}/endpoint-sg-id", "sg-0endpoint9999")
    aws.seed_ssm_param(f"/safe-agents/{env}/agent-subnet-ids", "subnet-0agent-isolated,subnet-0agent-b")
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-arn",
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs",
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/agent-runs-table-name", "safe-agents-development-agent-runs"
    )
    aws.seed_ssm_param(
        f"/safe-agents/{env}/tables-key-arn",
        "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-tables-cmk",
    )
    aws.seed_ssm_param(f"/safe-agents/{env}/broker-service-dns", "broker.safe-agents.local")
    aws.seed_marketplace_image(
        _RHEL_AMI_ID, RHEL_OWNER_ID, _RHEL_AMI_NAME, creation_date="2025-05-06T00:00:00Z"
    )
    return aws


# ---------------------------------------------------------------------------
# Criterion 1: RHEL AMI resolved by owner/name filter, newest wins
# ---------------------------------------------------------------------------

class TestRhelAmiLookup:
    def test_pick_newest_rhel_ami_single(self) -> None:
        """_pick_newest_rhel_ami returns the only image in a single-item list."""
        images = [{"image_id": "ami-0abc", "name": "RHEL-9.8-foo", "creation_date": "2025-01-01"}]
        assert _pick_newest_rhel_ami(images) == "ami-0abc"

    def test_pick_newest_rhel_ami_multiple(self) -> None:
        """_pick_newest_rhel_ami selects the most recently created image."""
        images = [
            {"image_id": "ami-old", "name": "RHEL-9.0-foo", "creation_date": "2024-01-01"},
            {"image_id": "ami-new", "name": "RHEL-9.8-foo", "creation_date": "2025-05-06"},
        ]
        assert _pick_newest_rhel_ami(images) == "ami-new"

    def test_pick_newest_rhel_ami_raises_when_empty(self) -> None:
        """_pick_newest_rhel_ami must raise RuntimeError when no images are found."""
        with pytest.raises(RuntimeError, match="no RHEL 9 AMI found"):
            _pick_newest_rhel_ami([])

    def test_provision_calls_describe_images_by_owner_name(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision calls describe_images_by_owner_name (not describe_images)."""
        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, fake_aws, environment="development", **_FAST)

        lookup_calls = [
            c for c in fake_aws.calls if c[0] == "describe_images_by_owner_name"
        ]
        assert lookup_calls, (
            "rhel_openshell_provision must call describe_images_by_owner_name "
            "to resolve the RHEL marketplace AMI"
        )
        owner_arg, name_arg = lookup_calls[0][1], lookup_calls[0][2]
        assert owner_arg == RHEL_OWNER_ID, (
            f"Owner must be Red Hat's AWS account ID {RHEL_OWNER_ID!r}; got {owner_arg!r}"
        )
        assert "RHEL-9" in name_arg, (
            f"Name pattern must match RHEL 9 images; got {name_arg!r}"
        )

    def test_provision_checks_baked_ami_tag_first(
        self, fake_aws: FakeAWS,
    ) -> None:
        """sa#109: provision must check the prebuilt base-rhel AMI tag before the marketplace.

        The whole point of sa#109 is that the RHEL box launches from a prebuilt AMI
        (tag safe-agents:ami=base-rhel) so it is config-only in the isolated no-NAT
        subnet. Provision resolves that tag first; with no bake seeded it falls back
        to the marketplace lookup (asserted separately).
        """
        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, fake_aws, environment="development", **_FAST)

        tag_lookup_calls = [c for c in fake_aws.calls if c[0] == "describe_images"]
        assert tag_lookup_calls, (
            "rhel_openshell_provision must check the prebuilt base-rhel AMI tag "
            "(describe_images) before resolving the marketplace AMI"
        )
        # The tag filter must be the base-rhel tag, NOT the EC2 arm's 'base'.
        tag_filter = tag_lookup_calls[0][1]
        assert tag_filter == {"safe-agents:ami": "base-rhel"}, (
            f"base AMI tag filter must be safe-agents:ami=base-rhel; got {tag_filter!r}"
        )

    def test_rhel_ami_owner_and_pattern_constants(self) -> None:
        """RHEL_OWNER_ID and RHEL9_NAME_PATTERN constants must have expected values."""
        assert RHEL_OWNER_ID == "309956199498", (
            "RHEL_OWNER_ID must be Red Hat's AWS marketplace owner account"
        )
        assert "RHEL-9" in RHEL9_NAME_PATTERN, "name pattern must reference RHEL 9"
        assert "x86_64" in RHEL9_NAME_PATTERN, "name pattern must be x86_64 (OpenShell requirement)"


# ---------------------------------------------------------------------------
# Criterion 2: User-data template content
# ---------------------------------------------------------------------------

class TestUserDataRendering:
    def test_all_required_params_substituted(self) -> None:
        """All {{key}} markers must be replaced after render; none may remain."""
        rendered = render_user_data(_VALID_PARAMS)
        remaining = re.findall(r"\{\{[^}]+\}\}", rendered)
        assert not remaining, (
            f"Unsubstituted template markers after render: {remaining}"
        )

    def test_param_values_present_in_output(self) -> None:
        """Each supplied param value must appear in the rendered script."""
        rendered = render_user_data(_VALID_PARAMS)
        for key, value in _VALID_PARAMS.items():
            assert value in rendered, (
                f"Value for param {key!r} ({value!r}) not found in rendered user-data"
            )

    def test_missing_param_raises(self) -> None:
        """render_user_data raises ValueError when a required param is missing."""
        incomplete = {k: v for k, v in _VALID_PARAMS.items() if k != "oauth_token"}
        with pytest.raises(ValueError, match="oauth_token"):
            render_user_data(incomplete)

    def test_ssm_agent_install_present(self) -> None:
        """Template must install SSM agent (RHEL marketplace AMIs omit it)."""
        content = TEMPLATE_PATH.read_text()
        assert "amazon-ssm-agent" in content, (
            "user-data must install the SSM agent (RHEL AMIs do not bundle it)"
        )
        assert "enable --now amazon-ssm-agent" in content or "enable.*amazon-ssm-agent" in content, (
            "user-data must enable and start the SSM agent service"
        )

    def test_cgroups_delegation_before_dev_user(self) -> None:
        """cgroups v2 delegation must be configured before dev user creation.

        user@.service.d/delegate.conf must be written before 'useradd dev'
        because the delegation config is read when the user's systemd manager
        first starts at login time. Wrong order means OpenShell sandbox creation
        fails with 'controller cpu is not available'.
        """
        content = TEMPLATE_PATH.read_text()
        delegate_idx = content.find("Delegate=cpu cpuset io memory pids")
        useradd_idx = content.find("useradd")
        assert delegate_idx != -1, (
            "user-data must set Delegate=cpu cpuset io memory pids for cgroups v2"
        )
        assert useradd_idx != -1, "user-data must create the dev user"
        assert delegate_idx < useradd_idx, (
            "cgroups v2 delegation must be configured BEFORE the dev user is created "
            "(delegation is read when the user's systemd manager first starts)"
        )

    def test_dev_user_creation_present(self) -> None:
        """Template must create the dev user with NOPASSWD sudo."""
        content = TEMPLATE_PATH.read_text()
        assert "useradd" in content and "dev" in content, (
            "user-data must create the dev user"
        )
        assert "NOPASSWD" in content, (
            "user-data must grant the dev user NOPASSWD sudo (required for rootless podman)"
        )

    def test_harness_coupling_block_present_with_claude_cli(self) -> None:
        """HARNESS-COUPLING BLOCK must bracket the Claude Code CLI install in setup-claude.sh.

        In the thin-launcher model, the heavy install (including the HARNESS-COUPLING block)
        lives in bootstrap/scripts/setup-claude.sh rather than user-data.sh.tmpl.
        """
        content = SETUP_CLAUDE_SCRIPT.read_text()
        start_idx = content.find("HARNESS-COUPLING BLOCK START")
        end_idx = content.find("HARNESS-COUPLING BLOCK END")
        assert start_idx != -1, "HARNESS-COUPLING BLOCK START marker missing from setup-claude.sh"
        assert end_idx != -1, "HARNESS-COUPLING BLOCK END marker missing from setup-claude.sh"
        assert start_idx < end_idx, "BLOCK START must precede BLOCK END"
        block = content[start_idx:end_idx]
        assert "@anthropic-ai/claude-code" in block or "claude-code" in block, (
            "Claude Code CLI install must be inside the HARNESS-COUPLING block "
            "(to make harness swaps easy: only this block changes)"
        )

    def test_oauth_token_fetch_inside_harness_block(self) -> None:
        """The OAuth token check must be inside the HARNESS-COUPLING block in setup-claude.sh."""
        content = SETUP_CLAUDE_SCRIPT.read_text()
        start_idx = content.find("HARNESS-COUPLING BLOCK START")
        end_idx = content.find("HARNESS-COUPLING BLOCK END")
        block = content[start_idx:end_idx]
        assert "SA_OAUTH_TOKEN_SECRET" in block or "oauth_token" in block.lower(), (
            "OAuth token check must be inside the HARNESS-COUPLING block in setup-claude.sh"
        )

    def test_podman_install_present(self) -> None:
        """install-openshell.sh must install rootless podman (OpenShell container driver)."""
        content = INSTALL_OPENSHELL_SCRIPT.read_text()
        assert "podman" in content, (
            "install-openshell.sh must install rootless podman (OpenShell uses it as its container driver)"
        )

    def test_openshell_install_in_dev_context(self) -> None:
        """OpenShell install must be in the dev user's session (LIVE-VERIFIED #93).

        The thin user-data invokes bootstrap.sh as dev via `sudo -u dev -H bash -lc`.
        Inside install-openshell.sh (already running as dev), XDG_RUNTIME_DIR and
        DBUS_SESSION_BUS_ADDRESS must be set for `systemctl --user` to work.
        """
        # The thin user-data invokes bootstrap.sh as the dev user.
        tmpl = TEMPLATE_PATH.read_text()
        assert "sudo -u dev -H" in tmpl, (
            "user-data must invoke bootstrap.sh AS the dev user via sudo -u dev -H"
        )
        assert "bootstrap.sh" in tmpl, (
            "user-data must invoke bootstrap.sh (the heavy install lives there)"
        )
        # install-openshell.sh (running as dev) sets the user-bus vars.
        osh = INSTALL_OPENSHELL_SCRIPT.read_text()
        assert "openshell" in osh.lower(), "install-openshell.sh must install OpenShell"
        assert "install.sh | sh" in osh, "must use the native OpenShell installer"
        assert "XDG_RUNTIME_DIR" in osh and "DBUS_SESSION_BUS_ADDRESS" in osh, (
            "install-openshell.sh must set XDG_RUNTIME_DIR + DBUS so systemctl --user works"
        )
        assert "enable-linger" in osh, "dev must have linger enabled for the user manager"
        # The installer owns gateway registration (on :17670); no manual gateway add
        # in executable code (comments may reference the phrase for documentation).
        osh_non_comment = "\n".join(
            ln for ln in osh.splitlines() if not ln.strip().startswith("#")
        )
        assert "gateway add" not in osh_non_comment, (
            "install-openshell.sh must not run 'gateway add' in executable code; "
            "the installer registers the gateway on :17670 itself"
        )

    def test_s3_bundle_delivery_present(self) -> None:
        """Thin user-data must pull the agent code bundle from S3."""
        content = TEMPLATE_PATH.read_text()
        assert "s3 cp" in content or "aws s3" in content, (
            "user-data must pull the agent bundle from S3"
        )
        assert "agents/" in content, "S3 key must start with 'agents/' (BUNDLE_CURRENT_KEY)"
        assert "current/bundle.tar.gz" in content, (
            "S3 key must use 'current/bundle.tar.gz' to match BUNDLE_CURRENT_KEY"
        )

    def test_platform_contract_bundle_delivery_present(self) -> None:
        """Thin user-data must pull the platform/contract bundle from S3 (harness delivery)."""
        content = TEMPLATE_PATH.read_text()
        assert "platform/contract/bundle.tar.gz" in content, (
            "user-data must pull platform/contract/bundle.tar.gz from S3 so the "
            "conformance harness lands at /opt/safe-agents/core/contract/harness.py"
        )

    def test_rhel_bootstrap_bundle_delivery_present(self) -> None:
        """Thin user-data must pull the rhel-bootstrap bundle from S3."""
        content = TEMPLATE_PATH.read_text()
        assert "rhel-bootstrap" in content, (
            "user-data must pull the rhel-bootstrap bundle from S3 "
            "(platform/rhel-bootstrap/bundle.tar.gz)"
        )

    def test_user_data_invokes_bootstrap_sh(self) -> None:
        """Thin user-data must invoke bootstrap.sh to do the heavy install."""
        content = TEMPLATE_PATH.read_text()
        assert "bootstrap.sh" in content, (
            "user-data.sh.tmpl must invoke bootstrap.sh; the heavy install lives there"
        )

    def test_systemd_timer_enabled(self) -> None:
        """bootstrap.sh must enable + start the agent's systemd timer."""
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "systemctl enable" in content and ".timer" in content, (
            "bootstrap.sh must enable the agent's systemd timer"
        )
        assert "enable --now" in content, (
            "bootstrap.sh must start the timer (enable --now covers both enable + start)"
        )

    def test_set_x_present(self) -> None:
        """Template must have 'set -x' for execution tracing to the log."""
        assert "set -x" in TEMPLATE_PATH.read_text(), (
            "user-data must contain 'set -x' to trace each command to the bootstrap log"
        )

    def test_err_trap_present(self) -> None:
        """Template must set a trap on ERR so failures are never silent."""
        content = TEMPLATE_PATH.read_text()
        assert "trap" in content and "ERR" in content, (
            "user-data must define 'trap ... ERR' to catch any failed command"
        )

    def test_fail_marker_written_on_error(self) -> None:
        """Template must write a .FAILED marker when the ERR trap fires."""
        content = TEMPLATE_PATH.read_text()
        assert "FAIL_MARKER" in content or "BOOTSTRAP_FAILED" in content or ".FAILED" in content, (
            "user-data error handler must write a *.FAILED marker file "
            "so failed bootstraps are detectable without parsing the full log"
        )

    def test_render_idempotent(self) -> None:
        """Rendering the same params twice produces identical output."""
        assert render_user_data(_VALID_PARAMS) == render_user_data(_VALID_PARAMS)

    def test_different_agent_names_produce_different_output(self) -> None:
        """Rendered script must differ for different agent names."""
        params_a = dict(_VALID_PARAMS, name="agent-alpha")
        params_b = dict(_VALID_PARAMS, name="agent-beta")
        assert render_user_data(params_a) != render_user_data(params_b)


# ---------------------------------------------------------------------------
# Criterion 3a: No development-harness accent in user-data.sh.tmpl
# ---------------------------------------------------------------------------

class TestNoDevHarnessAccent:
    """The thin user-data template must not carry a development harness's dev-UX tooling."""

    _FORBIDDEN = [
        ("kubectl",       "k8s tool"),
        ("helm ",         "k8s package manager"),
        ("oc ",           "OpenShift CLI"),
        ("go install",    "Go language installation"),
        ("rustup",        "Rust toolchain"),
        ("cargo ",        "Rust build tool"),
        ("claude-remote", "Remote Control (an interactive-harness feature)"),
        ("remote-control","Remote Control service"),
        ("tmux.conf",     "dev-UX tmux config"),
        ("bashrc.toolbox","dev-harness bashrc overlay"),
        ("aliases.sh",    "dev-UX shell aliases"),
        ("ripgrep",       "dev-UX search tool"),
        ("example-agent", "consumer-agent accent"),
    ]

    @pytest.mark.parametrize("pattern,label", _FORBIDDEN)
    def test_forbidden_pattern_absent(self, pattern: str, label: str) -> None:
        """The given development-harness pattern must not appear in the user-data template."""
        content = TEMPLATE_PATH.read_text()
        assert pattern not in content, (
            f"user-data template contains a development-harness accent {label!r} ({pattern!r}). "
            "The thin user-data launcher must contain only root pre-bootstrap essentials."
        )

    def test_no_hardcoded_agent_names(self) -> None:
        """The template must not contain hardcoded agent names."""
        content = TEMPLATE_PATH.read_text()
        forbidden_names = ["example-agent", "test-stub", "alpaca", "telegram", "tavily"]
        for name in forbidden_names:
            assert name not in content.lower(), (
                f"Hardcoded agent name {name!r} found in user-data.sh.tmpl — "
                "the template must be agent-agnostic"
            )


# ---------------------------------------------------------------------------
# Criterion 3b: Bootstrap structure (bootstrap/ dir)
# ---------------------------------------------------------------------------

class TestBootstrapStructure:
    """The bootstrap/ directory must be present, complete, and correctly adapted."""

    def test_bootstrap_dir_exists(self) -> None:
        assert BOOTSTRAP_DIR.is_dir(), (
            f"bootstrap/ directory not found at {BOOTSTRAP_DIR}"
        )

    def test_bootstrap_sh_exists(self) -> None:
        assert BOOTSTRAP_SCRIPT.is_file(), (
            f"bootstrap/bootstrap.sh not found at {BOOTSTRAP_SCRIPT}"
        )

    def test_install_tools_sh_exists(self) -> None:
        assert INSTALL_TOOLS_SCRIPT.is_file(), (
            f"bootstrap/scripts/install-tools.sh not found at {INSTALL_TOOLS_SCRIPT}"
        )

    def test_install_openshell_sh_exists(self) -> None:
        assert INSTALL_OPENSHELL_SCRIPT.is_file(), (
            f"bootstrap/scripts/install-openshell.sh not found at {INSTALL_OPENSHELL_SCRIPT}"
        )

    def test_setup_claude_sh_exists(self) -> None:
        assert SETUP_CLAUDE_SCRIPT.is_file(), (
            f"bootstrap/scripts/setup-claude.sh not found at {SETUP_CLAUDE_SCRIPT}"
        )

    def test_tmux_in_install_tools(self) -> None:
        """install-tools.sh must install tmux — required by run-agent-sandbox.sh."""
        content = INSTALL_TOOLS_SCRIPT.read_text()
        assert "tmux" in content, (
            "install-tools.sh must install tmux; it is required by run-agent-sandbox.sh "
            "for the flock-based concurrency gate (a prior re-derivation dropped this)"
        )

    def test_openshell_no_hardcoded_version_pin(self) -> None:
        """install-openshell.sh must NOT pin a specific OpenShell version (LIVE-VERIFIED #93).

        Pinning (e.g. OPENSHELL_VERSION=0.0.71) caused a release-asset 404 when upstream
        churned to 0.0.72. The native installer always installs the current latest.
        """
        content = INSTALL_OPENSHELL_SCRIPT.read_text()
        # No 'OPENSHELL_VERSION=0.0' or similar concrete version pin in a functional line.
        # Comments explaining the no-pin decision are OK.
        non_comment_lines = [
            ln for ln in content.splitlines() if not ln.strip().startswith("#")
        ]
        non_comment_text = "\n".join(non_comment_lines)
        import re
        version_pin = re.search(r'OPENSHELL_VERSION=["\']?0\.\d+', non_comment_text)
        assert version_pin is None, (
            "install-openshell.sh must not pin a specific OpenShell version; "
            f"found: {version_pin.group() if version_pin else ''}"
        )

    def test_openshell_no_gateway_add(self) -> None:
        """install-openshell.sh must not run `gateway add` in executable code.

        The native installer's start_user_gateway() registers on :17670 (mtls).
        A manual `gateway add` uses the wrong port and creates a mis-registered entry.
        Comments may reference the phrase for documentation.
        """
        content = INSTALL_OPENSHELL_SCRIPT.read_text()
        non_comment = "\n".join(
            ln for ln in content.splitlines() if not ln.strip().startswith("#")
        )
        assert "gateway add" not in non_comment, (
            "install-openshell.sh must not run 'gateway add' in executable code; "
            "the installer registers the gateway on :17670 itself"
        )

    def test_openshell_xdg_and_dbus_set(self) -> None:
        """install-openshell.sh must set XDG_RUNTIME_DIR + DBUS_SESSION_BUS_ADDRESS."""
        content = INSTALL_OPENSHELL_SCRIPT.read_text()
        assert "XDG_RUNTIME_DIR" in content, (
            "install-openshell.sh must set XDG_RUNTIME_DIR so systemctl --user can connect"
        )
        assert "DBUS_SESSION_BUS_ADDRESS" in content, (
            "install-openshell.sh must set DBUS_SESSION_BUS_ADDRESS so systemctl --user can connect"
        )

    def test_openshell_enable_linger(self) -> None:
        """install-openshell.sh must enable linger so the podman socket survives logout."""
        assert "enable-linger" in INSTALL_OPENSHELL_SCRIPT.read_text(), (
            "install-openshell.sh must enable linger for the dev user"
        )

    def test_harness_coupling_markers_in_setup_claude(self) -> None:
        """setup-claude.sh must bracket the Claude Code install with HARNESS-COUPLING markers."""
        content = SETUP_CLAUDE_SCRIPT.read_text()
        assert "HARNESS-COUPLING BLOCK START" in content, (
            "HARNESS-COUPLING BLOCK START missing from setup-claude.sh"
        )
        assert "HARNESS-COUPLING BLOCK END" in content, (
            "HARNESS-COUPLING BLOCK END missing from setup-claude.sh"
        )

    def test_sa_profile_gate_in_bootstrap(self) -> None:
        """bootstrap.sh must gate interactive-only tools behind SA_PROFILE=interactive."""
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "SA_PROFILE" in content, "SA_PROFILE gate missing from bootstrap.sh"
        assert "interactive" in content, (
            "bootstrap.sh must reference SA_PROFILE=interactive for gated tools"
        )

    def test_bootstrap_ends_with_explicit_exit_zero(self) -> None:
        """bootstrap.sh must end with `exit 0` so the autonomous profile exits clean.

        Regression for the sa#35 live capstone: under `set -e`, ending the script on a
        bare `[ "${SA_PROFILE}" = "interactive" ] && log …` makes the exit status inherit
        the test result. On the autonomous profile the test is false → exit 1 → cloud-init
        marks user-data failed even though bootstrap fully succeeded. An explicit trailing
        `exit 0` keeps the exit code honest regardless of the last conditional.
        """
        lines = [
            ln.strip()
            for ln in BOOTSTRAP_SCRIPT.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert lines[-1] == "exit 0", (
            "bootstrap.sh must end with an explicit `exit 0`; a trailing bare conditional "
            "under `set -e` leaks a non-zero exit on the autonomous profile (sa#35 capstone)"
        )

    def test_languages_gated_by_sa_profile(self) -> None:
        """install-languages.sh must only run inside the SA_PROFILE=interactive block."""
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "install-languages.sh" in content, "install-languages.sh not referenced in bootstrap.sh"
        # The languages call must appear AFTER the SA_PROFILE=interactive guard.
        lang_idx = content.find("install-languages.sh")
        assert lang_idx > 0, "install-languages.sh call not found in bootstrap.sh"
        # Verify the interactive gate string appears before the languages call.
        gate_idx = content.find("SA_PROFILE.*interactive") if "SA_PROFILE.*interactive" in content \
            else content.find('"interactive"')
        assert gate_idx < lang_idx, (
            "install-languages.sh must appear inside the SA_PROFILE=interactive block, "
            "not run unconditionally"
        )

    def test_k8s_tools_gated_by_sa_profile(self) -> None:
        """install-k8s-tools.sh must only run inside the SA_PROFILE=interactive block."""
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "install-k8s-tools.sh" in content, "install-k8s-tools.sh not referenced in bootstrap.sh"
        gate_idx = content.find('"interactive"')
        k8s_idx = content.find("install-k8s-tools.sh")
        assert gate_idx < k8s_idx, (
            "install-k8s-tools.sh must appear inside the SA_PROFILE=interactive block"
        )

    def test_remote_control_gated_by_sa_profile(self) -> None:
        """Remote Control service must only be installed in the SA_PROFILE=interactive block."""
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "claude-remote-control.service" in content or "remote-control" in content, (
            "bootstrap.sh must reference Remote Control service installation"
        )
        gate_idx = content.find('"interactive"')
        rc_idx = content.find("remote-control")
        assert gate_idx < rc_idx, (
            "Remote Control must only be installed inside the SA_PROFILE=interactive block"
        )

    def test_openshell_gated_by_sa_profile(self) -> None:
        """install-openshell.sh must run ONLY inside the SA_PROFILE=interactive block.

        Egress confinement on the autonomous profile is the netns + broker-proxy model
        (docs/model-egress.md, sa#35), NOT OpenShell. The sandbox runtime installs only
        on the interactive dev-box profile, so its install call must sit after the gate.
        """
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "install-openshell.sh" in content, (
            "install-openshell.sh not referenced in bootstrap.sh"
        )
        gate_idx = content.find('"interactive"')
        openshell_idx = content.find("install-openshell.sh")
        assert gate_idx != -1, "SA_PROFILE=interactive gate not found in bootstrap.sh"
        assert openshell_idx > gate_idx, (
            "install-openshell.sh must appear INSIDE the SA_PROFILE=interactive block, "
            "not run unconditionally — the autonomous profile uses netns confinement, "
            "not the OpenShell sandbox"
        )

    def test_openshell_not_in_always_steps(self) -> None:
        """The 'always' numbered steps must not install OpenShell.

        The unconditional install steps are tools + python + claude only (3/3). OpenShell
        must not appear as a numbered 'always' step; it is interactive-profile-only.
        """
        content = BOOTSTRAP_SCRIPT.read_text()
        # The always-steps region ends where the interactive gate begins.
        gate_idx = content.find('if [ "${SA_PROFILE}" = "interactive" ]')
        assert gate_idx != -1, "interactive gate block not found in bootstrap.sh"
        always_region = content[:gate_idx]
        # No executable invocation of install-openshell.sh before the gate (comments OK).
        always_exec = "\n".join(
            ln for ln in always_region.splitlines() if not ln.strip().startswith("#")
        )
        assert "install-openshell.sh" not in always_exec, (
            "install-openshell.sh must not be invoked in the unconditional 'always' steps; "
            "OpenShell is interactive-profile-only (autonomous uses netns confinement)"
        )

    def test_autonomous_run_path_does_not_use_openshell(self) -> None:
        """The autonomous run path (systemd system service) must not route through OpenShell.

        Converged two-box model (sa#35): the system service execs the profile-selected RUN_EXEC —
        run-brokered.sh on the autonomous profile (under /opt, SELinux-clean). It must NOT invoke
        the OpenShell sandbox launcher (run-agent-sandbox.sh), which is the interactive run path.
        """
        content = BOOTSTRAP_SCRIPT.read_text()
        assert "ExecStart=${RUN_EXEC}" in content, (
            "the systemd system service must exec the profile-selected RUN_EXEC"
        )
        assert 'RUN_EXEC="/opt/safe-agents/bin/run-brokered.sh"' in content, (
            "the autonomous profile's RUN_EXEC must be run-brokered.sh (the converged runner)"
        )
        non_comment = "\n".join(
            ln for ln in content.splitlines() if not ln.strip().startswith("#")
        )
        assert "run-agent-sandbox" not in non_comment, (
            "bootstrap.sh must not wire the OpenShell sandbox launcher (run-agent-sandbox.sh) "
            "into the run path; the autonomous system service runs run-brokered.sh directly"
        )

    def test_config_dir_has_tmux_conf(self) -> None:
        assert (BOOTSTRAP_DIR / "config" / "tmux.conf").is_file(), (
            "bootstrap/config/tmux.conf not found — faithful snapshot from a development harness"
        )

    def test_systemd_dir_has_remote_control_service(self) -> None:
        assert (BOOTSTRAP_DIR / "systemd" / "claude-remote-control.service").is_file(), (
            "bootstrap/systemd/claude-remote-control.service not found"
        )

    def test_fetch_secrets_sh_exists(self) -> None:
        assert (BOOTSTRAP_DIR / "scripts" / "fetch-secrets.sh").is_file(), (
            "bootstrap/scripts/fetch-secrets.sh not found"
        )


# ---------------------------------------------------------------------------
# Criterion 4: Two-identity separation at the rendered-policy level
# ---------------------------------------------------------------------------

class TestTwoIdentitySeparation:
    _ENV = "development"
    _AGENT_RUNS_ARN = (
        "arn:aws:dynamodb:us-east-1:123456789012:table/safe-agents-development-agent-runs"
    )
    _TABLES_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-tables-cmk"

    def _extensions(self, agent_name: str = "test-agent") -> list[dict]:
        return agent_role_extensions(
            agent_name, self._ENV, self._AGENT_RUNS_ARN, self._TABLES_KEY_ARN
        )

    def test_agent_role_has_tables_cmk_kms_grant(self) -> None:
        """agentRole extensions must grant KMS on the ONE tables CMK (run-record PutItem, sa#35)."""
        stmts = self._extensions()
        kms_stmts = [s for s in stmts if s.get("Sid") == "RunRecordKey"]
        assert kms_stmts, "RunRecordKey (tables-CMK KMS grant) statement not found"
        actions = kms_stmts[0].get("Action", [])
        assert "kms:GenerateDataKey" in actions and "kms:Decrypt" in actions, (
            "RunRecordKey must allow GenerateDataKey + Decrypt so the CMK-encrypted run-record "
            "PutItem can wrap its data key"
        )
        assert kms_stmts[0]["Resource"] == self._TABLES_KEY_ARN, (
            "the KMS grant must be scoped to the single tables CMK, not kms:* on all keys"
        )

    def test_agent_role_has_no_get_secret_on_connector_keys(self) -> None:
        """agentRole extensions must not grant GetSecretValue on */connectors/*."""
        for stmt in self._extensions():
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not any("secretsmanager:GetSecretValue" in a for a in actions):
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                assert "connectors" not in resource, (
                    f"agentRole extension grants GetSecretValue on a resource matching "
                    f"the broker connector-keys path: {resource!r}"
                )

    def test_agent_role_secrets_scoped_to_agent_namespace(self) -> None:
        """The AgentSecrets statement resource must be scoped to <agent>/*."""
        extensions = self._extensions(agent_name="my-agent")
        secret_stmts = [s for s in extensions if s.get("Sid") == "AgentSecrets"]
        assert secret_stmts, "AgentSecrets statement not found in agent_role_extensions"
        resource = secret_stmts[0]["Resource"]
        assert "my-agent" in resource, (
            f"AgentSecrets resource {resource!r} must include the agent name prefix"
        )
        assert "connectors" not in resource, (
            f"AgentSecrets resource {resource!r} must not overlap with broker connector-keys"
        )

    def test_agent_role_has_run_record_putitem(self) -> None:
        """agentRole extensions must include PutItem on the agent-runs table."""
        stmts = self._extensions()
        putitem_stmts = [
            s for s in stmts
            if "dynamodb:PutItem" in (
                [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
            )
        ]
        assert putitem_stmts, "agent_role_extensions must contain dynamodb:PutItem"
        assert "agent-runs" in putitem_stmts[0]["Resource"], (
            "PutItem resource must reference the agent-runs table"
        )

    def test_agent_role_has_ssm_core_actions(self) -> None:
        """agentRole extensions must include SSM Session Manager actions."""
        stmts = self._extensions()
        ssm_stmts = [s for s in stmts if s.get("Sid") == "SsmCore"]
        assert ssm_stmts, "SsmCore statement not found in agent_role_extensions"
        actions = ssm_stmts[0].get("Action", [])
        assert "ssm:UpdateInstanceInformation" in actions, (
            "SsmCore must include ssm:UpdateInstanceInformation"
        )

    def test_broker_connector_keys_pattern_covers_connectors(self) -> None:
        """BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN must contain 'connectors'."""
        assert "connectors" in BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN, (
            f"BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN {BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN!r} "
            "must reference the connector-keys path"
        )


# ---------------------------------------------------------------------------
# Criterion 5: Host placed in the ISOLATED agent subnet + agent SG + endpoint SG
# (sa#35 converged two-box model; NOT the NAT broker subnet)
# ---------------------------------------------------------------------------

class TestSubnetPlacement:
    def test_provision_uses_isolated_agent_subnet_and_endpoint_sg(
        self, fake_aws: FakeAWS,
    ) -> None:
        """Provision must resolve the isolated agent-subnet-ids + agent-sg + endpoint-sg (not broker-*)."""
        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, fake_aws, environment="development", **_FAST)

        def _looked_up(key: str) -> bool:
            return any(
                c[0] == "get_ssm_param" and key in c[1] for c in fake_aws.calls
            )

        assert _looked_up("agent-subnet-ids"), (
            "rhel_openshell_provision must use the ISOLATED agent-subnet-ids (sa#35 two-box model), "
            "the same placement the EC2 arm uses"
        )
        assert _looked_up("agent-sg-id"), "provision must resolve the agent SG (egress = broker only)"
        assert _looked_up("endpoint-sg-id"), (
            "provision must resolve the endpoint SG so the no-NAT box reaches the AWS interface "
            "endpoints (Secrets Manager / DynamoDB / SSM)"
        )
        assert not _looked_up("broker-subnet-id"), (
            "rhel_openshell_provision must NOT use the NAT broker subnet any more — the converged "
            "model puts the box in the isolated agent subnet so confinement actually holds"
        )
        assert not _looked_up("broker-sg-id"), (
            "the host must be on the agent SG (broker-only egress), not the broker SG (allowAllOutbound)"
        )

    def test_run_instances_receives_isolated_subnet_and_both_sgs(
        self, fake_aws: FakeAWS,
    ) -> None:
        """RunInstances must get the isolated agent subnet + [agentSG, endpointSG]."""
        captured: dict = {}
        original = fake_aws.run_instances

        def spy(**kwargs):
            captured.update(kwargs)
            return original(**kwargs)

        fake_aws.run_instances = spy  # type: ignore[method-assign]

        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, fake_aws, environment="development", **_FAST)

        # The first isolated agent-subnet-ids value; both SGs (agent + endpoint) on the launch.
        assert captured["subnet_id"] == "subnet-0agent-isolated", (
            f"RunInstances subnet_id={captured.get('subnet_id')!r}, expected the isolated agent subnet"
        )
        assert captured["security_group_ids"] == ["sg-0agent12345", "sg-0endpoint9999"], (
            f"RunInstances security_group_ids must be [agentSG, endpointSG]; got "
            f"{captured.get('security_group_ids')!r}"
        )


# ---------------------------------------------------------------------------
# Criterion 6: Arm dispatch in phases.py
# ---------------------------------------------------------------------------

class TestArmDispatch:
    def test_smoke_manifest_loads_with_rhel_arm(self) -> None:
        """smoke-rhel-openshell.yaml must parse and validate successfully."""
        manifest = load_manifest(SMOKE_MANIFEST)
        assert manifest.name == "smoke-rhel-openshell"
        assert manifest.arm == "rhel-openshell"

    def test_dry_run_provision_mentions_rhel(self, fake_aws: FakeAWS) -> None:
        """Provision phase dry-run steps must mention rhel-openshell and key operations."""
        result = run_pipeline(
            SMOKE_MANIFEST, dry_run=True, aws=fake_aws, agent_dir=TEST_STUB_DIR,
        )
        assert result.success, (
            "Dry-run failed:\n"
            + "\n".join(
                f"  {pr.phase}: {pr.error}"
                for pr in result.phase_results if not pr.success
            )
        )
        provision = next(pr for pr in result.phase_results if pr.phase == "provision")
        steps_text = " ".join(provision.steps).lower()
        assert "rhel" in steps_text, "Provision steps must mention RHEL"
        assert "broker" in steps_text, "Provision steps must mention broker subnet or sidecar"

    def test_dry_run_makes_no_aws_calls(self, fake_aws: FakeAWS) -> None:
        """Dry-run must not invoke AWS at all."""
        run_pipeline(SMOKE_MANIFEST, dry_run=True, aws=fake_aws, agent_dir=TEST_STUB_DIR)
        assert fake_aws.calls == [], (
            f"Dry-run made unexpected AWS calls: {fake_aws.calls}"
        )

    def test_unknown_arm_rejected_by_phases(self, fake_aws: FakeAWS) -> None:
        """provision_phase must reject unknown arm values with a clear error."""
        from safe_agents.pipeline.phases import provision_phase
        from safe_agents.pipeline.manifest import DeploymentManifest, Secrets, Smoke

        bad_manifest = DeploymentManifest(
            name="x", repo="r", deploy_key_secret="s", arm="not-an-arm",
            policy="p", secrets=Secrets(), smoke=Smoke(prompt="?", expect_substring="x"),
        )
        result = provision_phase(bad_manifest, fake_aws, dry_run=False, environment="development")
        assert not result.success
        assert result.error and "not-an-arm" in result.error

    def test_rhel_arm_teardown_dispatch_dry_run(self, fake_aws: FakeAWS) -> None:
        """teardown_phase dry-run for rhel-openshell must succeed."""
        from safe_agents.pipeline.phases import teardown_phase

        manifest = load_manifest(SMOKE_MANIFEST)
        result = teardown_phase(manifest, fake_aws, dry_run=True, environment="development")
        assert result.success, f"teardown dry-run failed: {result.error}"


# ---------------------------------------------------------------------------
# Criterion 7: Teardown removes instances + per-host IAM
# ---------------------------------------------------------------------------

class TestTeardown:
    _ENV = "development"

    @pytest.fixture()
    def provisioned_aws(self, fake_aws: FakeAWS) -> FakeAWS:
        """FakeAWS with a RHEL instance already seeded as if provisioned."""
        env = self._ENV
        manifest = load_manifest(SMOKE_MANIFEST)
        profile_name = f"safe-agents-{env}-{manifest.name}-rhel"
        role_arn = fake_aws._ssm_params.get(f"/safe-agents/{env}/agent-role-arn", "")
        role_name = role_arn.split("/")[-1] if role_arn else "AgentRole"

        # Seed instance with RHEL arm tags.
        fake_aws._instances["i-rhel-001"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": env,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
                "Arm": "rhel-openshell",
            },
            "state": "running",
        }
        fake_aws._instance_profiles[profile_name] = {"roles": [role_name], "tags": {}}
        fake_aws._role_policies[(role_name, profile_name)] = {"Version": "2012-10-17", "Statement": []}
        return fake_aws

    def test_teardown_terminates_instance(self, provisioned_aws: FakeAWS) -> None:
        """rhel_openshell_teardown must terminate the RHEL instance."""
        manifest = load_manifest(SMOKE_MANIFEST)
        report = rhel_openshell_teardown(manifest, provisioned_aws, environment=self._ENV)
        assert report["instances_terminated"], (
            "teardown must terminate the provisioned instance"
        )
        assert "i-rhel-001" in report["instances_terminated"]

    def test_teardown_removes_iam_profile(self, provisioned_aws: FakeAWS) -> None:
        """rhel_openshell_teardown must delete the per-agent instance profile."""
        manifest = load_manifest(SMOKE_MANIFEST)
        report = rhel_openshell_teardown(manifest, provisioned_aws, environment=self._ENV)
        assert report["profile_removed"], (
            "teardown must delete the per-agent instance profile"
        )

    def test_teardown_removes_inline_policy(self, provisioned_aws: FakeAWS) -> None:
        """rhel_openshell_teardown must delete the inline IAM policy."""
        manifest = load_manifest(SMOKE_MANIFEST)
        report = rhel_openshell_teardown(manifest, provisioned_aws, environment=self._ENV)
        assert report["policy_removed"], (
            "teardown must delete the inline IAM policy from the agent role"
        )

    def test_teardown_idempotent(self, fake_aws: FakeAWS) -> None:
        """rhel_openshell_teardown is a no-op when nothing is provisioned."""
        manifest = load_manifest(SMOKE_MANIFEST)
        report = rhel_openshell_teardown(manifest, fake_aws, environment=self._ENV)
        assert report["instances_terminated"] == []
        assert report["profile_already_gone"]

    def test_teardown_does_not_touch_ec2_instances(self, fake_aws: FakeAWS) -> None:
        """Teardown must not terminate EC2 arm instances for the same agent."""
        env = self._ENV
        manifest = load_manifest(SMOKE_MANIFEST)
        # Seed an EC2 arm instance with the same agent name but WITHOUT Arm=rhel-openshell.
        fake_aws._instances["i-ec2-001"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": env,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
                # No "Arm" tag — this is an EC2 arm instance
            },
            "state": "running",
        }
        report = rhel_openshell_teardown(manifest, fake_aws, environment=env)
        assert "i-ec2-001" not in report["instances_terminated"], (
            "RHEL teardown must not terminate EC2 arm instances for the same agent; "
            "the Arm=rhel-openshell tag discriminates"
        )


# ---------------------------------------------------------------------------
# Criterion 8: Pipeline gating reused (provision end-to-end)
# ---------------------------------------------------------------------------

class TestProvisionGating:
    _ENV = "development"

    def test_provision_calls_run_instances(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must call run_instances (not instance_id_for_stack)."""
        manifest = load_manifest(SMOKE_MANIFEST)
        instance_id = rhel_openshell_provision(
            manifest, fake_aws, environment=self._ENV, **_FAST
        )
        assert instance_id.startswith("i-"), (
            f"rhel_openshell_provision must return a valid instance ID; got {instance_id!r}"
        )
        assert fake_aws.was_called("run_instances"), (
            "rhel_openshell_provision must call run_instances"
        )
        assert not fake_aws.was_called("instance_id_for_stack"), (
            "rhel_openshell_provision must not call instance_id_for_stack (CF-stack path)"
        )

    def test_provision_creates_instance_profile(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must create the per-agent instance profile."""
        manifest = load_manifest(SMOKE_MANIFEST)
        rhel_openshell_provision(manifest, fake_aws, environment=self._ENV, **_FAST)
        create_calls = [c for c in fake_aws.calls if c[0] == "create_instance_profile"]
        assert create_calls, (
            "ensure_foundation must create the per-agent instance profile when absent"
        )

    def test_provision_waits_for_ssm_online(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must poll SSM until Online before returning."""
        fake_aws.ssm_online_after_n_polls = 2  # 2 Offline, then Online

        manifest = load_manifest(SMOKE_MANIFEST)
        instance_id = rhel_openshell_provision(
            manifest, fake_aws, environment=self._ENV, **_FAST
        )
        assert instance_id.startswith("i-")
        ssm_calls = [c for c in fake_aws.calls if c[0] == "describe_ssm_instance_information"]
        assert len(ssm_calls) >= 3, (
            f"Expected at least 3 SSM polls (2 Offline + 1 Online); got {len(ssm_calls)}"
        )

    def test_provision_raises_when_ssm_never_online(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must raise RuntimeError if SSM never goes Online."""
        fake_aws.ssm_never_online = True

        manifest = load_manifest(SMOKE_MANIFEST)
        fast_short_ssm = dict(_FAST, _ssm_timeout=0.1)
        with pytest.raises(RuntimeError, match="SSM"):
            rhel_openshell_provision(
                manifest, fake_aws, environment=self._ENV, **fast_short_ssm
            )

    def test_provision_raises_when_no_rhel_ami_found(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must raise when no RHEL AMI is available."""
        # Clear all marketplace images.
        fake_aws._marketplace_images = []

        manifest = load_manifest(SMOKE_MANIFEST)
        with pytest.raises(RuntimeError, match="no RHEL 9 AMI found"):
            rhel_openshell_provision(manifest, fake_aws, environment=self._ENV, **_FAST)

    def test_provision_clean_start_gate_blocks_live_instance(
        self, fake_aws: FakeAWS,
    ) -> None:
        """rhel_openshell_provision must raise early when a prior RHEL instance is running."""
        manifest = load_manifest(SMOKE_MANIFEST)
        # Seed a running instance with the agent's standard tags.
        fake_aws._instances["i-prior-rhel"] = {
            "tags": {
                "Project": "safe-agents",
                "Environment": self._ENV,
                "Agent": manifest.name,
                "ManagedBy": "safe-agents-pipeline",
            },
            "state": "running",
        }

        with pytest.raises(RuntimeError, match="still active"):
            rhel_openshell_provision(manifest, fake_aws, environment=self._ENV, **_FAST)

        # RunInstances must NOT have been called (gate fired before it).
        run_calls = [c for c in fake_aws.calls if c[0] == "run_instances"]
        assert run_calls == [], "run_instances must not be called when the clean-start gate fires"


# ---------------------------------------------------------------------------
# RHEL bootstrap bundle (bundle.py extensions)
# ---------------------------------------------------------------------------

class TestRhelBootstrapBundle:
    """bundle_rhel_bootstrap() and upload_rhel_bootstrap() from bundle.py."""

    def test_bundle_rhel_bootstrap_creates_tarball(self) -> None:
        """bundle_rhel_bootstrap must produce a non-empty gzip tar archive."""
        import io as _io
        import tarfile as _tarfile

        from safe_agents.arms.ec2.ami.bundle import bundle_rhel_bootstrap

        data = bundle_rhel_bootstrap(BOOTSTRAP_DIR)
        assert isinstance(data, bytes) and len(data) > 100, (
            "bundle_rhel_bootstrap must return a non-empty bytes object"
        )
        with _tarfile.open(fileobj=_io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        assert any("bootstrap.sh" in n for n in names), (
            "rhel-bootstrap bundle must contain bootstrap.sh"
        )
        assert any("install-tools.sh" in n for n in names), (
            "rhel-bootstrap bundle must contain scripts/install-tools.sh"
        )
        assert any("install-openshell.sh" in n for n in names), (
            "rhel-bootstrap bundle must contain scripts/install-openshell.sh"
        )

    def test_bundle_excludes_pycache(self) -> None:
        """bundle_rhel_bootstrap must exclude __pycache__ and .pyc files."""
        import io as _io
        import tarfile as _tarfile

        from safe_agents.arms.ec2.ami.bundle import bundle_rhel_bootstrap

        data = bundle_rhel_bootstrap(BOOTSTRAP_DIR)
        with _tarfile.open(fileobj=_io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        assert not any("__pycache__" in n for n in names), (
            "rhel-bootstrap bundle must not include __pycache__ directories"
        )
        assert not any(n.endswith(".pyc") for n in names), (
            "rhel-bootstrap bundle must not include .pyc files"
        )

    def test_bundle_carries_run_brokered_runner(self) -> None:
        """The converged run-brokered.sh runner rides the rhel-bootstrap bundle under box/ (sa#35)."""
        import io as _io
        import tarfile as _tarfile

        from safe_agents.arms.ec2.ami.bundle import bundle_rhel_bootstrap

        data = bundle_rhel_bootstrap(BOOTSTRAP_DIR)
        with _tarfile.open(fileobj=_io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        assert any(n.endswith("box/run-brokered.sh") for n in names), (
            "rhel-bootstrap bundle must carry box/run-brokered.sh so bootstrap.sh can install it "
            "to /opt/safe-agents/bin (the autonomous system service execs it)"
        )

    def test_bundle_excludes_model_proxy_stub(self) -> None:
        """The co-located model-proxy stub must NOT ride the bundle (two-box model, sa#35)."""
        import io as _io
        import tarfile as _tarfile

        from safe_agents.arms.ec2.ami.bundle import bundle_rhel_bootstrap

        data = bundle_rhel_bootstrap(BOOTSTRAP_DIR)
        with _tarfile.open(fileobj=_io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        assert not any("model-proxy-stub.py" in n for n in names), (
            "the model-proxy stub must not be bundled — the broker is its own service now"
        )

    def test_upload_rhel_bootstrap_uses_correct_key(self) -> None:
        """upload_rhel_bootstrap must use the RHEL_BOOTSTRAP_KEY constant."""
        from safe_agents.arms.ec2.ami.bundle import RHEL_BOOTSTRAP_KEY, upload_rhel_bootstrap

        class _FakeS3:
            def __init__(self) -> None:
                self.puts: list[dict] = []

            def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict:
                self.puts.append({"Bucket": Bucket, "Key": Key, "size": len(Body)})
                return {}

        fake_s3 = _FakeS3()
        result = upload_rhel_bootstrap(b"test-bytes", environment="development", s3=fake_s3)

        assert result["key"] == RHEL_BOOTSTRAP_KEY, (
            f"upload_rhel_bootstrap must use RHEL_BOOTSTRAP_KEY; got {result['key']!r}"
        )
        assert "platform/rhel-bootstrap" in RHEL_BOOTSTRAP_KEY, (
            f"RHEL_BOOTSTRAP_KEY must be under platform/; got {RHEL_BOOTSTRAP_KEY!r}"
        )
        assert len(fake_s3.puts) == 1, (
            "upload_rhel_bootstrap must make exactly one put_object call "
            "(stable key, no versioned copy)"
        )
        assert fake_s3.puts[0]["Key"] == RHEL_BOOTSTRAP_KEY

    def test_upload_rhel_bootstrap_correct_bucket(self) -> None:
        """upload_rhel_bootstrap must use the standard deploy bucket."""
        from safe_agents.arms.ec2.ami.bundle import upload_rhel_bootstrap, DEPLOY_BUCKET_TEMPLATE

        class _FakeS3:
            def __init__(self) -> None:
                self.puts: list[dict] = []
            def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict:
                self.puts.append({"Bucket": Bucket, "Key": Key})
                return {}

        for env in ("development", "staging", "production"):
            fake_s3 = _FakeS3()
            upload_rhel_bootstrap(b"x", environment=env, s3=fake_s3)
            expected_bucket = DEPLOY_BUCKET_TEMPLATE.format(environment=env)
            assert fake_s3.puts[0]["Bucket"] == expected_bucket, (
                f"upload_rhel_bootstrap must use bucket {expected_bucket!r} for env {env!r}"
            )


# ---------------------------------------------------------------------------
# sa#35: netns + broker-SERVICE egress confinement (autonomous profile, Option A)
# ---------------------------------------------------------------------------
#
# Converged TWO-BOX model: the confined agent does a REAL brokered round-trip against the broker
# SERVICE at broker.safe-agents.local (like the EC2 arm + the ec2-woken box), while the netns is
# KEPT as a defense-in-depth process-isolation layer that now FORWARDS to the broker instead of
# blackholing to a co-located stub. There is no on-box model-proxy any more.

# The literal autonomous-profile guard used in bootstrap.sh. Note: a plain
# find('"autonomous"') would match the SA_PROFILE default assignment first, so
# tests anchor on the full guard expression instead.
_AUTONOMOUS_GUARD = '[ "${SA_PROFILE}" = "autonomous" ]'


class TestNetnsConfinementScripts:
    """The box-side scripts that realize the netns + broker-SERVICE model exist + are sound."""

    def test_netns_setup_script_exists(self) -> None:
        assert AGENT_NETNS_SETUP_SCRIPT.is_file(), (
            f"agent-netns-setup.sh not found at {AGENT_NETNS_SETUP_SCRIPT}"
        )

    def test_smoke_egress_script_exists(self) -> None:
        assert SMOKE_EGRESS_SCRIPT.is_file(), (
            f"smoke-egress.sh not found at {SMOKE_EGRESS_SCRIPT}"
        )

    def test_run_brokered_script_exists(self) -> None:
        assert RUN_BROKERED_SCRIPT.is_file(), (
            f"run-brokered.sh not found at {RUN_BROKERED_SCRIPT}"
        )

    def test_netns_setup_creates_namespace_and_veth(self) -> None:
        """agent-netns-setup.sh must create the named netns + a veth pair."""
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "ip netns add" in content, "must create the named network namespace"
        assert "type veth peer name" in content, "must create a veth pair (host↔agent link)"
        assert "ip link set" in content and "netns" in content, (
            "must move the agent-side veth into the namespace"
        )

    def test_netns_forwards_to_broker_not_blackhole(self) -> None:
        """The netns must FORWARD to the broker service, not blackhole.

        In the converged model the netns is a forwarding hop: a real default route via the host
        veth, plus host ip_forward + a nftables MASQUERADE for the veth /30. The old
        `blackhole default` (the dead-end that required a co-located stub) must be gone.
        """
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "ip route add blackhole" not in content, (
            "the netns must no longer install a blackhole default route — it forwards to the broker"
        )
        assert "ip route add default via" in content, (
            "the netns must have a default route via the host veth (forward to the broker)"
        )
        assert "net.ipv4.ip_forward=1" in content, (
            "the host must enable ip_forward so it routes netns egress to the broker"
        )

    def test_netns_uses_nft_masquerade(self) -> None:
        """RHEL 9 ships nftables (not the iptables wrapper); the MASQUERADE is an nft rule."""
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "masquerade" in content, (
            "the host must MASQUERADE the veth /30 so netns return traffic is SNATed to the host IP"
        )
        assert "nft add" in content and "nft add rule" in content, (
            "the RHEL netns must program the NAT via nftables (`nft`), the RHEL 9 default backend"
        )
        # The RHEL arm must NOT depend on the iptables compat binary (not on the base RHEL 9 AMI).
        non_comment = "\n".join(
            ln for ln in content.splitlines() if not ln.strip().startswith("#")
        )
        assert "iptables" not in non_comment, (
            "the RHEL netns setup must use `nft`, not the iptables wrapper (absent on the RHEL AMI)"
        )

    def test_netns_wires_dns_for_broker_resolution(self) -> None:
        """The netns must get a resolv.conf so broker.safe-agents.local resolves via the VPC resolver."""
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "/etc/netns/" in content and "resolv.conf" in content, (
            "agent-netns-setup.sh must install a per-netns /etc/netns/<ns>/resolv.conf so DNS works"
        )

    def test_netns_constants_match_the_committed_snapshot(self) -> None:
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "10.255.255.1" in content, "host veth IP must be 10.255.255.1"
        assert "10.255.255.2" in content, "agent veth IP must be 10.255.255.2"
        assert "PREFIX=30" in content, "the point-to-point link must be a /30"

    def test_netns_setup_is_idempotent(self) -> None:
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "ip netns del" in content, "must delete any prior namespace first (idempotent re-run)"

    def test_netns_setup_fails_loudly_without_ip(self) -> None:
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "command -v ip" in content, "must assert `ip` is present and fail loudly if not"

    def test_netns_setup_fails_loudly_without_nft(self) -> None:
        """Forwarding needs MASQUERADE; a missing `nft` must fail loudly (AMI-gap guard)."""
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "command -v nft" in content, (
            "must assert `nft` (nftables) is present (MASQUERADE) and fail loudly if the AMI lacks it"
        )


class TestRunBrokeredRunner:
    """run-brokered.sh does a real brokered round-trip against the broker SERVICE with a host/netns
    split: oauth fetch + run record on the HOST, claude -p + brokered tool call in the NETNS."""

    def _content(self) -> str:
        return RUN_BROKERED_SCRIPT.read_text()

    def test_bash_n_clean(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(RUN_BROKERED_SCRIPT)], capture_output=True, text=True
        )
        assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"

    def test_targets_broker_service_not_local_stub(self) -> None:
        """The runner must point at the broker SERVICE DNS, never the old 10.255.255.1 stub."""
        content = self._content()
        assert "10.255.255.1" not in content, (
            "run-brokered.sh must NOT target the old co-located stub IP (10.255.255.1)"
        )
        assert "SA_BROKER_DNS" in content, "must resolve the broker via SA_BROKER_DNS"
        assert 'HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}"' in content, (
            "must set HTTPS_PROXY to the broker service (not a veth-IP stub)"
        )

    def test_confined_phase_runs_claude_and_brokered_toolcall(self) -> None:
        """The NETNS phase runs claude -p + a brokered github.whoami — guarded by SA_CONFINED_PHASE."""
        content = self._content()
        assert "SA_CONFINED_PHASE" in content, "must gate the confined turn on SA_CONFINED_PHASE"
        assert "claude -p" in content, "the confined turn must run claude -p through the broker proxy"
        assert "github" in content and "whoami" in content and "/call" in content, (
            "the confined turn must POST a brokered github.whoami tool call to the broker /call API"
        )
        assert 'if [ "${SA_CONFINED_PHASE:-0}" = "1" ]; then' in content, (
            "the confined turn (claude -p + tool call) must be guarded by SA_CONFINED_PHASE"
        )

    def test_enters_netns_and_drops_to_dev_user(self) -> None:
        content = self._content()
        assert "ip netns exec" in content, "the host phase must enter the netns for the confined turn"
        assert "runuser" in content and "dev" in content, (
            "must drop to the unprivileged dev user inside the netns (RHEL AGENT_RUN_USER default)"
        )

    def test_run_user_defaults_to_dev(self) -> None:
        """RHEL drops to the `dev` user (EC2 uses ec2-user)."""
        content = self._content()
        assert 'RUN_USER="${AGENT_RUN_USER:-dev}"' in content, (
            "run-brokered.sh must default AGENT_RUN_USER to `dev` on the RHEL arm"
        )

    def test_exports_rhel_path_for_aws_and_claude(self) -> None:
        """RHEL puts aws + node/claude under /usr/local/bin; PATH must be exported at the top."""
        content = self._content()
        assert "/usr/local/bin" in content and "export PATH=" in content, (
            "run-brokered.sh must export a PATH including /usr/local/bin (RHEL aws/claude location) "
            "so both the host + netns phases find the binaries"
        )

    def test_host_phase_split_oauth_before_netns_run_record_after(self) -> None:
        """Host/netns split: fetch oauth on the HOST before entering the netns; write the run
        record on the HOST after the netns turn (both need AWS-endpoint reach the netns lacks)."""
        content = self._content()
        oauth_idx = content.find("secretsmanager get-secret-value")
        netns_idx = content.find("ip netns exec")
        putitem_idx = content.find("dynamodb put-item")
        assert oauth_idx != -1 and netns_idx != -1 and putitem_idx != -1
        assert oauth_idx < netns_idx, (
            "the oauth fetch must happen on the HOST before entering the confined netns"
        )
        assert putitem_idx > netns_idx, (
            "the run-record PutItem must happen on the HOST after the netns turn"
        )

    def test_run_record_tagged_arm_rhel_openshell(self) -> None:
        content = self._content()
        assert '\\"arm\\": {\\"S\\": \\"rhel-openshell\\"}' in content, (
            "the run record must be tagged arm=rhel-openshell"
        )

    def test_smoke_assertions_present(self) -> None:
        """The optional smoke asserts broker reachable + api.anthropic.com NOT reachable directly."""
        content = self._content()
        assert "api.telegram.org" in content, "smoke must check a connector host is unreachable"
        assert "api.anthropic.com" in content, "smoke must check the model endpoint"
        assert "-u HTTPS_PROXY" in content, "smoke must check the model is unreachable WITHOUT the proxy"
        assert "/dev/tcp/${BROKER}" in content, "smoke must check the broker service is reachable"


class TestNetnsConfinementWiring:
    """bootstrap.sh wires the netns + broker-service model, gated to the autonomous profile."""

    def _content(self) -> str:
        return BOOTSTRAP_SCRIPT.read_text()

    def test_netns_setup_unit_installed_under_autonomous_guard(self) -> None:
        content = self._content()
        guard_idx = content.find(_AUTONOMOUS_GUARD)
        assert guard_idx != -1, "bootstrap.sh must have an SA_PROFILE=autonomous guard"
        assert content.find("agent-netns-setup.service") > guard_idx, (
            "agent-netns-setup.service must be created inside the SA_PROFILE=autonomous block"
        )

    def test_no_broker_model_proxy_unit_or_stub(self) -> None:
        """The co-located model-proxy unit + stub install must be GONE (two-box model)."""
        content = self._content()
        assert "broker-model-proxy.service" not in content, (
            "the broker-model-proxy stub unit must be removed — the broker is its own service"
        )
        assert "model-proxy-stub.py" not in content, (
            "bootstrap.sh must not install the model-proxy stub any more"
        )

    def test_confinement_scripts_and_runner_installed_to_opt(self) -> None:
        """The exec'd scripts must be installed under /opt (SELinux init_t/203-EXEC)."""
        content = self._content()
        assert "/opt/safe-agents/bin/agent-netns-setup.sh" in content, (
            "agent-netns-setup.sh must be installed under /opt (a system service execs it)"
        )
        assert "/opt/safe-agents/bin/run-brokered.sh" in content, (
            "run-brokered.sh must be installed under /opt for the agent service to exec it"
        )

    def test_confinement_scripts_restorecon(self) -> None:
        """The exec'd scripts + unit files must be restorecon'd (RHEL SELinux, moved from /tmp)."""
        content = self._content()
        assert "restorecon" in content, "bootstrap.sh must restorecon the confinement files (RHEL SELinux)"
        assert content.count("agent-netns-setup.service") >= 2, (
            "agent-netns-setup.service should be written AND restorecon'd"
        )

    def test_agent_env_contract_written(self) -> None:
        """bootstrap.sh must write /etc/safe-agents/agent.env with the run-brokered contract."""
        content = self._content()
        assert "/etc/safe-agents/agent.env" in content, (
            "bootstrap.sh must write the env contract at /etc/safe-agents/agent.env"
        )
        for name in ("SA_BROKER_DNS=", "AGENT_RUNS_TABLE=", "SA_OAUTH_SECRET_ID=", "SA_NETNS_NAME=agent-ns"):
            assert name in content, f"agent.env heredoc must set {name!r}"

    def test_agent_env_heredoc_refs_only_vars_passed_through_sudo(self) -> None:
        """Every ${VAR} in the agent.env heredoc must be a var user-data actually exports.

        user-data.sh.tmpl passes ONLY the SA_-prefixed vars across the `sudo -u dev`
        boundary into bootstrap.sh; any other reference (e.g. the bare OAUTH_TOKEN_SECRET
        that broke the 2026-07-01 convergence) is unset there, and under `set -u` the
        expansion aborts the autonomous bootstrap before the netns units install.
        """
        content = self._content()
        heredoc = re.search(r"<<AGENTENV\n(.*?)\nAGENTENV", content, re.DOTALL)
        assert heredoc, "bootstrap.sh must write agent.env via the AGENTENV heredoc"
        refs = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", heredoc.group(1)))
        passed = set(re.findall(r"^\s*(SA_[A-Z0-9_]+)=", TEMPLATE_PATH.read_text(), re.MULTILINE))
        unknown = sorted(refs - passed)
        assert not unknown, (
            f"agent.env heredoc references vars never exported across the sudo boundary: {unknown}; "
            "user-data.sh.tmpl passes only SA_-prefixed vars into bootstrap.sh"
        )

    def test_autonomous_service_execs_run_brokered(self) -> None:
        """The autonomous run service must ExecStart run-brokered.sh (via RUN_EXEC)."""
        content = self._content()
        assert 'RUN_EXEC="/opt/safe-agents/bin/run-brokered.sh"' in content, (
            "the autonomous branch must set RUN_EXEC to the converged run-brokered.sh runner"
        )
        assert "ExecStart=${RUN_EXEC}" in content, (
            "the systemd run service must ExecStart the profile-selected RUN_EXEC"
        )

    def test_autonomous_service_requires_netns_setup(self) -> None:
        """The autonomous agent service must order after / require the netns-setup unit."""
        content = self._content()
        assert "Requires=agent-netns-setup.service" in content, (
            "the autonomous agent service must Requires=agent-netns-setup.service"
        )

    def test_autonomous_service_reads_env_file(self) -> None:
        """The autonomous service must load the env contract via EnvironmentFile."""
        content = self._content()
        assert "EnvironmentFile=/etc/safe-agents/agent.env" in content, (
            "the autonomous service must read /etc/safe-agents/agent.env (run-brokered contract)"
        )

    def test_interactive_keeps_direct_run(self) -> None:
        """The interactive (non-autonomous) branch execs run.sh directly via run-agent.sh."""
        content = self._content()
        assert 'exec "${SCRIPT_DIR}/run.sh"' in content, (
            "the interactive branch must exec run.sh directly (OpenShell confines it)"
        )


class TestSmokeEgressAssertions:
    """smoke-egress.sh proves (not trusts) the confinement: four assertions, run in-netns."""

    def _content(self) -> str:
        return SMOKE_EGRESS_SCRIPT.read_text()

    def test_runs_assertions_inside_the_netns(self) -> None:
        assert "ip netns exec" in self._content()

    def test_connector_unreachable_assertion(self) -> None:
        content = self._content()
        assert "CONNECTOR_HOST" in content and "unreachable" in content

    def test_broker_service_reachable_assertion(self) -> None:
        content = self._content()
        assert "/dev/tcp/${BROKER}" in content and "PROXY_PORT" in content, (
            "assertion 2: the broker SERVICE (not a veth IP) must be reachable"
        )

    def test_model_unreachable_directly_assertion(self) -> None:
        assert "-u HTTPS_PROXY" in self._content()

    def test_model_reachable_via_broker_service_assertion(self) -> None:
        content = self._content()
        assert 'HTTPS_PROXY="http://${BROKER}:${PROXY_PORT}"' in content, (
            "assertion 4: the model must be reachable VIA the broker service proxy"
        )

    def test_targets_broker_service_not_veth_ip(self) -> None:
        content = self._content()
        assert "SA_BROKER_DNS" in content, "smoke must resolve the broker via its service DNS"
        assert "10.255.255.1" not in content, (
            "smoke must target the broker service, not the old on-box veth-IP proxy"
        )

    def test_fails_loudly_on_any_breach(self) -> None:
        content = self._content()
        assert "CONFINEMENT FAILED" in content and "exit 1" in content


class TestOfflineBootGuards:
    """Every internet install in the boot path must be guarded on the binary existing.

    The box sits in the ISOLATED no-NAT agent subnet (sa#35): dnf repos, PyPI, and
    upstream installers are all unreachable at boot. provision.py's contract is
    'config-only on a baked AMI' (sa#109) — so each install must short-circuit via
    `command -v` when the tool is already baked in, while a non-baked marketplace
    host (which has egress in that scenario) still installs as before.
    """

    def test_awscli_install_guarded_in_user_data(self) -> None:
        """user-data must not curl awscli.amazonaws.com when aws is already baked in.

        The unconditional install ran BEFORE the S3 bundle pulls, so on the no-NAT
        subnet it tripped the ERR trap and killed the whole bootstrap.
        """
        content = TEMPLATE_PATH.read_text()
        guard_idx = content.find("command -v aws")
        install_idx = content.find("awscli-exe-linux-x86_64.zip")
        assert guard_idx != -1, "user-data must guard the AWS CLI install with `command -v aws`"
        assert install_idx != -1, (
            "the upstream AWS CLI install must remain as the marketplace-AMI fallback"
        )
        assert guard_idx < install_idx, (
            "the `command -v aws` guard must come BEFORE the upstream installer"
        )

    def test_usr_local_bin_on_path_before_aws_guard(self) -> None:
        """The baked CLI lives in /usr/local/bin, which cloud-init's root PATH omits."""
        content = TEMPLATE_PATH.read_text()
        path_idx = content.find("export PATH=/usr/local/bin:$PATH")
        guard_idx = content.find("command -v aws")
        assert path_idx != -1 and path_idx < guard_idx, (
            "user-data must put /usr/local/bin on PATH BEFORE the `command -v aws` guard, "
            "or the guard misses the baked CLI and falls into the unreachable upstream install"
        )

    def test_core_dnf_block_guarded_in_install_tools(self) -> None:
        """EPEL setup + the core dnf install must run only when a core binary is missing."""
        content = INSTALL_TOOLS_SCRIPT.read_text()
        guard_idx = content.find("_MISSING_CMDS")
        assert guard_idx != -1, (
            "install-tools.sh must probe for missing core binaries before touching dnf"
        )
        for netop in ("epel-release-latest-9", "dnf install -y --allowerasing"):
            idx = content.find(netop)
            assert idx != -1 and idx > guard_idx, (
                f"{netop!r} must live inside the missing-binaries guard — it needs egress "
                "the no-NAT subnet does not have"
            )

    def test_pip_upgrade_only_inside_pip_missing_branch(self) -> None:
        """`pip install --upgrade pip` needs PyPI; it must never run unconditionally."""
        content = INSTALL_PYTHON_ENV_SCRIPT.read_text()
        assert "python3 -m pip --version" in content, (
            "install-python-env.sh must probe for pip before any pip network operation"
        )
        for lineno, line in enumerate(content.splitlines(), 1):
            if "pip install --upgrade pip" in line and not line.strip().startswith("#"):
                assert line.startswith((" ", "\t")), (
                    f"install-python-env.sh:{lineno}: `pip install --upgrade pip` must sit "
                    "inside the pip-missing branch, never at top level"
                )

    def test_uv_install_guarded(self) -> None:
        content = INSTALL_PYTHON_ENV_SCRIPT.read_text()
        guard_idx = content.find("command -v uv")
        install_idx = content.find("astral.sh/uv/install.sh")
        assert guard_idx != -1 and install_idx != -1 and guard_idx < install_idx, (
            "the uv install must be guarded on `command -v uv` (baked in by sa#109)"
        )

    def test_ruff_install_guarded(self) -> None:
        content = INSTALL_PYTHON_ENV_SCRIPT.read_text()
        guard_idx = content.find("command -v ruff")
        assert guard_idx != -1, (
            "install-python-env.sh must guard the ruff install on `command -v ruff`"
        )
        for frag in ("uv tool install ruff", "pip install --user ruff", "pip install --upgrade ruff"):
            idx = content.find(frag)
            assert idx == -1 or idx > guard_idx, (
                f"{frag!r} must come after the `command -v ruff` guard"
            )
