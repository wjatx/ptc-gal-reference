"""
EC2 arm — netns + broker-SERVICE egress confinement tests (sa#35, Option A).

Converges the always-on EC2 box onto the TWO-BOX broker model: the confined agent does a REAL
brokered round-trip against the broker SERVICE at broker.safe-agents.local (like the proven
ec2-woken box), while the netns is KEPT as a defense-in-depth process-isolation layer that now
FORWARDS to the broker instead of blackholing to a co-located stub. There is no on-box model-proxy
any more — the broker is its own service.

All tests are AWS-free and network-free: they assert on the box-side scripts + the rendered
user-data text, and bash-syntax-check the runner.

Run from core/:
    cd core && ./.venv/bin/python -m pytest arms/ec2/tests/test_ec2_confinement.py -q
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from safe_agents.arms.ec2.provision import render_user_data

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ARM_DIR = Path(__file__).parent.parent
SCRIPTS_DIR = ARM_DIR / "bootstrap" / "scripts"
AGENT_NETNS_SETUP_SCRIPT = SCRIPTS_DIR / "agent-netns-setup.sh"
SMOKE_EGRESS_SCRIPT = SCRIPTS_DIR / "smoke-egress.sh"
RUN_BROKERED_SCRIPT = ARM_DIR / "box" / "run-brokered.sh"
USER_DATA_TMPL = ARM_DIR / "user-data.sh.tmpl"

# The literal autonomous-profile guard used in user-data.sh.tmpl. A plain find('"autonomous"')
# would match the SA_PROFILE default first, so anchor on the full guard expression.
_AUTONOMOUS_GUARD = '[ "${SA_PROFILE}" = "autonomous" ]'

# Minimal render params (mirrors test_ec2_arm._VALID_PARAMS) for the rendered-output assertions.
_RENDER_PARAMS = {
    "name": "my-agent",
    "arm": "ec2",
    "oauth_token": "my-agent/claude-oauth-token",
    "environment": "development",
    "broker_dns": "broker.safe-agents.local",
    "agent_runs_table": "safe-agents-development-agent-runs",
    "region": "us-east-1",
}


# ---------------------------------------------------------------------------
# The box-side scripts that realize the netns + broker-service model
# ---------------------------------------------------------------------------

class TestNetnsConfinementScripts:
    """The EC2 confinement scripts exist, forward to the broker, and are sound."""

    def test_netns_setup_script_exists(self) -> None:
        assert AGENT_NETNS_SETUP_SCRIPT.is_file()

    def test_smoke_egress_script_exists(self) -> None:
        assert SMOKE_EGRESS_SCRIPT.is_file()

    def test_run_brokered_script_exists(self) -> None:
        assert RUN_BROKERED_SCRIPT.is_file(), (
            f"run-brokered.sh not found at {RUN_BROKERED_SCRIPT}"
        )

    def test_netns_setup_creates_namespace_and_veth(self) -> None:
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "ip netns add" in content, "must create the named network namespace"
        assert "type veth peer name" in content, "must create a veth pair (host↔agent link)"
        assert "ip link set" in content and "netns" in content, (
            "must move the agent-side veth into the namespace"
        )

    def test_netns_forwards_to_broker_not_blackhole(self) -> None:
        """The netns must FORWARD to the broker service, not blackhole.

        In the converged model the netns is a forwarding hop: a real default route via the host
        veth, plus host ip_forward + MASQUERADE for the veth /30. The old `blackhole default` (the
        dead-end that required a co-located stub) must be gone.
        """
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "ip route add blackhole" not in content, (
            "the netns must no longer install a blackhole default route — it forwards to the broker"
        )
        assert "ip route add default via" in content, (
            "the netns must have a default route via the host veth (forward to the broker)"
        )
        assert "MASQUERADE" in content, (
            "the host must MASQUERADE the veth /30 so netns return traffic is SNATed to the host IP"
        )
        assert "net.ipv4.ip_forward=1" in content, (
            "the host must enable ip_forward so it routes netns egress to the broker"
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

    def test_netns_setup_fails_loudly_without_iptables(self) -> None:
        """Forwarding needs MASQUERADE; a missing iptables must fail loudly (AMI-gap guard)."""
        content = AGENT_NETNS_SETUP_SCRIPT.read_text()
        assert "command -v iptables" in content, (
            "must assert `iptables` is present (MASQUERADE) and fail loudly if the AMI lacks it"
        )


# ---------------------------------------------------------------------------
# run-brokered.sh — the converged confined + brokered runner (host/netns split)
# ---------------------------------------------------------------------------

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
        # The claude call must be gated by the confined-phase guard (runs only inside the netns).
        assert 'if [ "${SA_CONFINED_PHASE:-0}" = "1" ]; then' in content, (
            "the confined turn (claude -p + tool call) must be guarded by SA_CONFINED_PHASE"
        )

    def test_enters_netns_and_drops_to_unprivileged_user(self) -> None:
        content = self._content()
        assert "ip netns exec" in content, "the host phase must enter the netns for the confined turn"
        assert "runuser" in content and "ec2-user" in content, (
            "must drop to the unprivileged ec2-user inside the netns (AGENT_RUN_USER default)"
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

    def test_run_record_tagged_arm_ec2(self) -> None:
        content = self._content()
        assert '\\"arm\\": {\\"S\\": \\"ec2\\"}' in content, (
            "the run record must be tagged arm=ec2 (not ec2-woken)"
        )

    def test_smoke_assertions_present(self) -> None:
        """The optional smoke asserts broker reachable + api.anthropic.com NOT reachable directly."""
        content = self._content()
        assert "api.telegram.org" in content, "smoke must check a connector host is unreachable"
        assert "api.anthropic.com" in content, "smoke must check the model endpoint"
        assert "-u HTTPS_PROXY" in content, "smoke must check the model is unreachable WITHOUT the proxy"
        assert "/dev/tcp/${BROKER}" in content, "smoke must check the broker service is reachable"


# ---------------------------------------------------------------------------
# user-data.sh.tmpl wires the converged model (netns forward + run-brokered service)
# ---------------------------------------------------------------------------

class TestNetnsConfinementWiring:
    """user-data.sh.tmpl wires the netns + broker-service model; the EC2 arm is always-autonomous."""

    def _user_data(self) -> str:
        return USER_DATA_TMPL.read_text()

    def _rendered(self) -> str:
        return render_user_data(_RENDER_PARAMS)

    def test_autonomous_profile_default(self) -> None:
        content = self._user_data()
        assert 'SA_PROFILE="${SA_PROFILE:-autonomous}"' in content

    def test_netns_setup_unit_installed_under_autonomous_guard(self) -> None:
        content = self._user_data()
        guard_idx = content.find(_AUTONOMOUS_GUARD)
        assert guard_idx != -1, "user-data must have an SA_PROFILE=autonomous guard"
        assert content.find("agent-netns-setup.service") > guard_idx, (
            "agent-netns-setup.service must be created inside the SA_PROFILE=autonomous block"
        )

    def test_no_broker_model_proxy_unit_or_stub(self) -> None:
        """The co-located model-proxy unit + stub install must be GONE (two-box model)."""
        content = self._user_data()
        assert "broker-model-proxy.service" not in content, (
            "the broker-model-proxy stub unit must be removed — the broker is its own service"
        )
        assert "model-proxy-stub.py" not in content, (
            "user-data must not install the model-proxy stub any more"
        )

    def test_ec2_bootstrap_bundle_pulled_from_s3(self) -> None:
        content = self._user_data()
        assert "platform/ec2-bootstrap/bundle.tar.gz" in content
        assert "aws s3 cp" in content and "ec2-bootstrap" in content

    def test_confinement_scripts_and_runner_installed_to_opt(self) -> None:
        content = self._user_data()
        assert "/opt/safe-agents/bin/agent-netns-setup.sh" in content
        assert "/opt/safe-agents/bin/run-brokered.sh" in content, (
            "run-brokered.sh must be installed under /opt for the agent service to exec it"
        )

    def test_agent_service_execs_run_brokered(self) -> None:
        content = self._user_data()
        assert "ExecStart=/opt/safe-agents/bin/run-brokered.sh" in content, (
            "the agent systemd service must ExecStart the converged run-brokered.sh runner"
        )

    def test_rendered_points_at_broker_service_not_stub(self) -> None:
        """Deliverable: the RENDERED user-data points at the broker SERVICE, not the 10.255.255.1 stub."""
        rendered = self._rendered()
        assert "broker.safe-agents.local" in rendered, (
            "rendered user-data must carry the broker service DNS in the env contract"
        )
        assert "10.255.255.1" not in rendered, (
            "rendered user-data must not reference the old co-located stub IP"
        )

    def test_agent_env_carries_run_brokered_contract(self) -> None:
        """The agent.env heredoc references the contract by NAME (expanded at boot); the concrete
        values are rendered into the top-of-script shell assignments the heredoc expands."""
        rendered = self._rendered()
        # Contract var names in the agent.env heredoc.
        for name in (
            "AGENT_NAME=",
            "SA_BROKER_DNS=",
            "AGENT_RUNS_TABLE=",
            "SA_OAUTH_SECRET_ID=",
            "SA_NETNS_NAME=agent-ns",
        ):
            assert name in rendered, f"agent.env must reference {name!r}"
        # The broker ports are literal in the template.
        assert 'SA_MODEL_PROXY_PORT="8443"' in rendered
        assert 'SA_TOOL_API_PORT="8080"' in rendered
        # The concrete param values are rendered into the assignments the heredoc expands.
        for val in (
            "broker.safe-agents.local",
            "safe-agents-development-agent-runs",
            "my-agent/claude-oauth-token",
        ):
            assert val in rendered, f"rendered user-data must carry {val!r}"

    def test_agent_service_requires_netns_setup(self) -> None:
        content = self._user_data()
        assert "Requires=agent-netns-setup.service" in content
        assert "After=agent-netns-setup.service" in content

    def test_agent_service_runs_as_root_for_netns_exec(self) -> None:
        content = self._user_data()
        assert "User=" not in content, (
            "the EC2 agent service must run as root (no User=) so run-brokered.sh can ip-netns-exec"
        )


# ---------------------------------------------------------------------------
# smoke-egress.sh — the four confinement assertions target the broker SERVICE
# ---------------------------------------------------------------------------

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
        assert '${HOST_IP}:${PROXY_PORT}' not in content, (
            "smoke must target the broker service, not the old on-box veth-IP proxy"
        )

    def test_fails_loudly_on_any_breach(self) -> None:
        content = self._content()
        assert "CONFINEMENT FAILED" in content and "exit 1" in content
