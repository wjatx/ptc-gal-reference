"""
OpenShell sandbox policy generator — broker-centric network whitelist (sa#92).

Generates per-agent OpenShell policy YAML enforcing default-deny egress,
whitelisting ONLY:
  1. The co-placed broker endpoint (parameterized host:port).
  2. api.anthropic.com:443 — for Claude inference by the claude CLI.

ALL connector hosts (api.telegram.org, alpaca.markets, api.tavily.com, etc.)
are absent from the whitelist.  Those connectors are reachable only through the
broker; a fully compromised agent "can still only ask."

This is the core re-derivation from a development harness's consumer-agent policy:
that agent whitelisted telegram + alpaca + tavily directly.  Here those hosts move
behind the broker — the whitelist shrinks to broker + inference only.

Usage::

    params = PolicyParams(agent_name="my-agent", broker_port=8080)
    yaml_str = render_policy_yaml(params)
    # write to a temp file and pass as --policy <file> to openshell sandbox create

Public surface:
    PolicyParams      — dataclass of per-agent parameters
    generate_policy   — returns the policy as a plain dict
    render_policy_yaml — returns YAML string (ready for --policy <file>)
    KNOWN_CONNECTOR_HOSTS — frozenset used in tests to assert the whitelist is clean
"""
from __future__ import annotations

from dataclasses import dataclass

import yaml


# ---------------------------------------------------------------------------
# Connector host registry — used in tests to assert the policy is clean.
# Adding a host here does NOT permit it; it documents what must be absent.
# ---------------------------------------------------------------------------

KNOWN_CONNECTOR_HOSTS: frozenset[str] = frozenset(
    {
        "api.telegram.org",
        "data.alpaca.markets",
        "paper-api.alpaca.markets",
        "api.alpaca.markets",
        "api.tavily.com",
        "api.twitter.com",
        "api.openai.com",
        "api.slack.com",
        "hooks.slack.com",
        "smtp.gmail.com",
        "api.stripe.com",
    }
)

# Binary paths verified on RHEL + OpenShell Ubuntu-24.04 sandbox base image.
# Claude Code is a native ELF at /usr/local/bin/claude (not node); the node
# path is kept as a fallback for node-based builds.
_CLAUDE_BINARIES: list[dict] = [
    {"path": "/usr/local/bin/claude"},  # Claude Code native ELF (verified on box)
    {"path": "/usr/bin/node"},          # fallback if node-based build is used
]

_AGENT_BINARIES: list[dict] = _CLAUDE_BINARIES + [
    {"path": "/usr/bin/python3"},
    {"path": "/sandbox/.venv/bin/python3"},  # sandbox venv python (verified on box)
]


@dataclass
class PolicyParams:
    """Parameters for a per-agent OpenShell sandbox policy.

    broker_host / broker_port identify the co-placed broker endpoint; they
    default to localhost:8080 for single-box deployments.  Override for
    multi-box or non-standard setups.
    """

    agent_name: str
    broker_host: str = "127.0.0.1"  # co-placed broker; LAN-local by default
    broker_port: int = 8080
    sandbox_user: str = "sandbox"
    sandbox_group: str = "sandbox"
    workdir_include: bool = True  # include_workdir: uploaded project dir is read-write


def generate_policy(params: PolicyParams) -> dict:
    """Return the OpenShell policy as a plain Python dict.

    The broker endpoint and api.anthropic.com are the ONLY whitelisted egress
    targets.  No connector hosts appear — those are behind the broker.
    filesystem_policy mirrors a consumer agent's baseline (read-only system
    paths; read-write /sandbox + /tmp + /dev/null + workdir).
    """
    return {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": params.workdir_include,
            "read_only": [
                "/usr",
                "/lib",
                "/lib64",
                "/etc",
                "/bin",
                "/proc",
                "/dev/urandom",
            ],
            "read_write": ["/sandbox", "/tmp", "/dev/null"],
        },
        "landlock": {
            "compatibility": "best_effort",
        },
        "process": {
            "run_as_user": params.sandbox_user,
            "run_as_group": params.sandbox_group,
        },
        "network_policies": {
            # Inference endpoint — the claude CLI calls this; no connector.
            "anthropic_api": {
                "name": "anthropic-inference",
                "endpoints": [
                    {
                        "host": "api.anthropic.com",
                        "port": 443,
                        "protocol": "rest",
                        "enforcement": "enforce",
                        "access": "read-write",
                    }
                ],
                "binaries": _CLAUDE_BINARIES,
            },
            # Co-placed broker — the agent's ONLY egress for tool calls.
            # All connector traffic flows through here; this is not a connector.
            "broker": {
                "name": "broker-endpoint",
                "endpoints": [
                    {
                        "host": params.broker_host,
                        "port": params.broker_port,
                        "protocol": "rest",
                        "enforcement": "enforce",
                        "access": "read-write",
                    }
                ],
                # All agent binaries may call the broker (claude + harness + python scripts).
                "binaries": _AGENT_BINARIES,
            },
        },
    }


def render_policy_yaml(params: PolicyParams) -> str:
    """Render the policy as a YAML string suitable for --policy <file>."""
    return yaml.dump(
        generate_policy(params),
        default_flow_style=False,
        sort_keys=False,
    )
