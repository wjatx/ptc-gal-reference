"""
RHEL arm — broker-centric, OS-isolated agent compute (sa#87, sa#92, sa#94).

The arm has two profiles (SA_PROFILE). The default **autonomous** profile confines
the agent with a netns whose only outbound route is the broker, which is also the
model-inference proxy (docs/model-egress.md, sa#35) — OpenShell is NOT installed.
The **interactive** dev-box profile runs each agent in an isolated OpenShell sandbox
whose default-deny network policy whitelists only the co-placed broker endpoint +
api.anthropic.com:443.

This module is the OpenShell sandbox policy generator (interactive profile only).

Public surface:
    PolicyParams        — policy generation parameters
    generate_policy     — returns the policy as a plain dict
    render_policy_yaml  — returns YAML string (pass as --policy <file> to openshell)
    KNOWN_CONNECTOR_HOSTS — frozenset of connector hosts that must be absent from policy

The sandbox lifecycle script is in run-agent-sandbox.sh (delivered via bootstrap).
"""
from .openshell_policy import (
    KNOWN_CONNECTOR_HOSTS,
    PolicyParams,
    generate_policy,
    render_policy_yaml,
)

__all__ = [
    "KNOWN_CONNECTOR_HOSTS",
    "PolicyParams",
    "generate_policy",
    "render_policy_yaml",
]
