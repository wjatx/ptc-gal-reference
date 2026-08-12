"""
EC2 arm — always-on EC2 compute (Arm 1, sa#33).

Public surface the pipeline uses:
    render_user_data                      — render user-data.sh.tmpl from manifest params
    ec2_provision                         — provision an EC2 instance via the AWSInterface
    agent_role_extensions                 — IAM policy statements the arm adds to agentRole
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN — the secret path agentRole must NOT access

See provision.py for full documentation.
"""
from .provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    agent_role_extensions,
    ec2_provision,
    render_user_data,
)

__all__ = [
    "BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN",
    "agent_role_extensions",
    "ec2_provision",
    "render_user_data",
]
