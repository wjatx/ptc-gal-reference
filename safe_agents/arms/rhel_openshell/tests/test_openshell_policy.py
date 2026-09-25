"""
Tests for the OpenShell sandbox run model + policy (sa#92).

Acceptance criteria (all AWS-free and OpenShell-free):

  1. Generated policy whitelists EXACTLY the broker endpoint + api.anthropic.com.
       - KNOWN_CONNECTOR_HOSTS are all absent from network_policies.
       - Exactly two network_policy entries: 'anthropic_api' and 'broker'.
       - broker entry carries the parameterized host and port.
       - api.anthropic.com entry carries port 443.

  2. Filesystem policy matches the expected security baseline.
       - System paths (/usr, /lib, /lib64, /etc, /bin) are read-only.
       - /sandbox and /tmp are read-write.
       - include_workdir is True.

  3. Landlock and process sections match the RHEL sandbox baseline.
       - landlock.compatibility == 'best_effort'.
       - process.run_as_user == process.run_as_group == 'sandbox' (default).

  4. PolicyParams customisation is respected.
       - Non-default broker_host, broker_port, sandbox_user, sandbox_group.

  5. render_policy_yaml emits valid YAML that round-trips correctly.

  6. Run-model contract: the sandbox lifecycle script contains the correct
       command sequence (create / upload / exec / delete + trap).

  7. Concurrency gate: the wrapper script references flock and a configurable
       MAX slot count.

  8. Secret injection: the sandbox script injects ONLY the runner-key allowlist
       (CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY) and NOT any connector cred
       pattern.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from safe_agents.arms.rhel_openshell.openshell_policy import (
    KNOWN_CONNECTOR_HOSTS,
    PolicyParams,
    generate_policy,
    render_policy_yaml,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_hosts(policy: dict) -> list[str]:
    """Extract every 'host' value from network_policies endpoints."""
    hosts = []
    for section in policy.get("network_policies", {}).values():
        for ep in section.get("endpoints", []):
            if "host" in ep:
                hosts.append(ep["host"])
    return hosts


# ---------------------------------------------------------------------------
# 1. Whitelist correctness — broker + anthropic ONLY
# ---------------------------------------------------------------------------

class TestNetworkWhitelist:
    def test_no_connector_hosts_in_policy(self):
        """No known connector host may appear in the generated policy."""
        params = PolicyParams(agent_name="test-agent")
        policy = generate_policy(params)
        hosts = _all_hosts(policy)
        for connector in KNOWN_CONNECTOR_HOSTS:
            assert connector not in hosts, (
                f"connector host {connector!r} found in policy; "
                "it must be absent (behind the broker)"
            )

    def test_exactly_two_network_policy_sections(self):
        params = PolicyParams(agent_name="test-agent")
        policy = generate_policy(params)
        sections = list(policy["network_policies"].keys())
        assert set(sections) == {"anthropic_api", "broker"}, (
            f"expected exactly {{anthropic_api, broker}}, got {set(sections)}"
        )

    def test_anthropic_api_section_host_and_port(self):
        params = PolicyParams(agent_name="test-agent")
        policy = generate_policy(params)
        endpoints = policy["network_policies"]["anthropic_api"]["endpoints"]
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["host"] == "api.anthropic.com"
        assert ep["port"] == 443

    def test_broker_section_uses_params(self):
        params = PolicyParams(
            agent_name="my-agent", broker_host="10.0.1.5", broker_port=9090
        )
        policy = generate_policy(params)
        endpoints = policy["network_policies"]["broker"]["endpoints"]
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["host"] == "10.0.1.5"
        assert ep["port"] == 9090

    def test_broker_default_is_localhost(self):
        params = PolicyParams(agent_name="test-agent")
        policy = generate_policy(params)
        ep = policy["network_policies"]["broker"]["endpoints"][0]
        assert ep["host"] == "127.0.0.1"
        assert ep["port"] == 8080

    # Parametrize against every known connector host as an explicit regression.
    @pytest.mark.parametrize("connector_host", sorted(KNOWN_CONNECTOR_HOSTS))
    def test_connector_host_absent(self, connector_host: str):
        params = PolicyParams(agent_name="test-agent")
        hosts = _all_hosts(generate_policy(params))
        assert connector_host not in hosts


# ---------------------------------------------------------------------------
# 2. Filesystem policy baseline
# ---------------------------------------------------------------------------

class TestFilesystemPolicy:
    def setup_method(self):
        self.policy = generate_policy(PolicyParams(agent_name="test-agent"))
        self.fs = self.policy["filesystem_policy"]

    def test_include_workdir_true(self):
        assert self.fs["include_workdir"] is True

    def test_system_paths_are_read_only(self):
        ro = self.fs["read_only"]
        for path in ["/usr", "/lib", "/lib64", "/etc", "/bin"]:
            assert path in ro, f"{path} should be read-only"

    def test_sandbox_and_tmp_are_read_write(self):
        rw = self.fs["read_write"]
        assert "/sandbox" in rw
        assert "/tmp" in rw

    def test_include_workdir_false_respected(self):
        policy = generate_policy(PolicyParams(agent_name="x", workdir_include=False))
        assert policy["filesystem_policy"]["include_workdir"] is False


# ---------------------------------------------------------------------------
# 3. Landlock and process sections
# ---------------------------------------------------------------------------

class TestLandlockAndProcess:
    def setup_method(self):
        self.policy = generate_policy(PolicyParams(agent_name="test-agent"))

    def test_landlock_best_effort(self):
        assert self.policy["landlock"]["compatibility"] == "best_effort"

    def test_process_sandbox_user(self):
        proc = self.policy["process"]
        assert proc["run_as_user"] == "sandbox"
        assert proc["run_as_group"] == "sandbox"


# ---------------------------------------------------------------------------
# 4. PolicyParams customisation
# ---------------------------------------------------------------------------

class TestPolicyParamsCustomisation:
    def test_custom_sandbox_user(self):
        policy = generate_policy(
            PolicyParams(agent_name="a", sandbox_user="agent", sandbox_group="agent")
        )
        proc = policy["process"]
        assert proc["run_as_user"] == "agent"
        assert proc["run_as_group"] == "agent"

    def test_version_is_1(self):
        policy = generate_policy(PolicyParams(agent_name="a"))
        assert policy["version"] == 1


# ---------------------------------------------------------------------------
# 5. YAML round-trip
# ---------------------------------------------------------------------------

class TestYamlRenderAndRoundtrip:
    def test_render_is_valid_yaml(self):
        params = PolicyParams(agent_name="roundtrip-test", broker_port=7777)
        yaml_str = render_policy_yaml(params)
        parsed = yaml.safe_load(yaml_str)
        assert isinstance(parsed, dict)
        assert parsed["version"] == 1

    def test_yaml_round_trip_matches_generate(self):
        params = PolicyParams(agent_name="roundtrip-test", broker_port=7777)
        from_yaml = yaml.safe_load(render_policy_yaml(params))
        direct = generate_policy(params)
        assert from_yaml == direct

    def test_yaml_no_connector_hosts(self):
        yaml_str = render_policy_yaml(PolicyParams(agent_name="test"))
        for connector in KNOWN_CONNECTOR_HOSTS:
            assert connector not in yaml_str, (
                f"connector host {connector!r} leaked into YAML output"
            )


# ---------------------------------------------------------------------------
# 6. Run-model contract: sandbox lifecycle command sequence
# ---------------------------------------------------------------------------

SANDBOX_SCRIPT = (
    Path(__file__).parent.parent / "run-agent-sandbox.sh"
)


class TestSandboxLifecycleSequence:
    def setup_method(self):
        assert SANDBOX_SCRIPT.exists(), f"run-agent-sandbox.sh not found at {SANDBOX_SCRIPT}"
        self.script = SANDBOX_SCRIPT.read_text(encoding="utf-8")

    def test_sandbox_create_with_true_dev_null(self):
        """The create command must use `-- true </dev/null` to avoid blocking stdin."""
        assert "-- true </dev/null" in self.script, (
            "sandbox create must end with `-- true </dev/null` "
            "(bare create blocks on stdin — the development-harness gotcha)"
        )

    def test_sandbox_create_before_upload(self):
        """create must appear before upload in the script."""
        create_pos = self.script.find("sandbox create")
        upload_pos = self.script.find("sandbox upload")
        assert create_pos != -1 and upload_pos != -1
        assert create_pos < upload_pos, "create must precede upload"

    def test_sandbox_upload_before_exec(self):
        """upload must appear before exec in the script."""
        upload_pos = self.script.find("sandbox upload")
        exec_pos = self.script.find("sandbox exec")
        assert upload_pos != -1 and exec_pos != -1
        assert upload_pos < exec_pos, "upload must precede exec"

    def test_sandbox_delete_in_trap(self):
        """sandbox delete must be inside a trap so it runs on any exit."""
        # Both 'trap' and 'sandbox delete' must appear; trap must come before delete.
        trap_pos = self.script.find("trap ")
        delete_pos = self.script.find("sandbox delete")
        assert trap_pos != -1, "trap not found in script"
        assert delete_pos != -1, "sandbox delete not found in script"
        assert trap_pos < delete_pos, "trap should be set before sandbox delete is called"

    def test_no_tty_flag_on_exec(self):
        assert "--no-tty" in self.script, "exec must use --no-tty for unattended runs"

    def test_path_includes_usr_local_bin(self):
        """RHEL lesson: /usr/local/bin must be on PATH (claude is there as native ELF)."""
        assert "/usr/local/bin" in self.script


# ---------------------------------------------------------------------------
# 7. Concurrency gate
# ---------------------------------------------------------------------------

class TestConcurrencyGate:
    def setup_method(self):
        self.script = SANDBOX_SCRIPT.read_text(encoding="utf-8")

    def test_flock_present(self):
        assert "flock" in self.script, "flock-based concurrency gate not found"

    def test_max_slot_variable(self):
        """A MAX or slot cap variable must be present and default to ncpu-based expression."""
        assert "MAX" in self.script
        assert "nproc" in self.script, "default MAX should derive from nproc"

    def test_slot_directory_created(self):
        """Flock files live in a slots directory."""
        assert "SLOT_DIR" in self.script or "slots" in self.script

    def test_max_at_least_one(self):
        """The cap must be guarded against 0 (nproc could theoretically return 1)."""
        assert 'MAX" -lt 1' in self.script or "[ -lt 1 ]" in self.script or \
               "MAX=1" in self.script, \
               "MAX must be clamped to at least 1"


# ---------------------------------------------------------------------------
# 8. Secret injection — allowlist enforced, no connector creds
# ---------------------------------------------------------------------------

class TestSecretInjection:
    def setup_method(self):
        self.script = SANDBOX_SCRIPT.read_text(encoding="utf-8")

    def test_runner_key_allowlist_present(self):
        """The script must declare an explicit allowlist of runner keys."""
        assert "RUNNER_KEY_ALLOWLIST" in self.script

    def test_oauth_token_in_allowlist(self):
        assert "CLAUDE_CODE_OAUTH_TOKEN" in self.script

    def test_anthropic_api_key_in_allowlist(self):
        assert "ANTHROPIC_API_KEY" in self.script

    @pytest.mark.parametrize("connector_cred_pattern", [
        "TELEGRAM",
        "ALPACA",
        "TAVILY",
        "STRIPE",
        "OPENAI",
    ])
    def test_connector_cred_pattern_absent(self, connector_cred_pattern: str):
        """Connector credential patterns must not appear in the sandbox run script."""
        # Exclude comment lines when checking — comments are documentation.
        non_comment_lines = [
            ln for ln in self.script.splitlines()
            if not ln.strip().startswith("#")
        ]
        non_comment_text = "\n".join(non_comment_lines)
        assert connector_cred_pattern not in non_comment_text, (
            f"connector credential pattern {connector_cred_pattern!r} found in "
            "run-agent-sandbox.sh (outside comments); connector creds must NOT be injected"
        )

    def test_runner_keys_file_sourced_from_separate_file(self):
        """Runner keys come from a dedicated file, not a generic secrets dump."""
        assert "runner-keys.env" in self.script, (
            "runner keys should be sourced from ~/.runner-keys.env "
            "(not a generic .secrets.env that might contain connector creds)"
        )
