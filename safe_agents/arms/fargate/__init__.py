"""
Fargate arm — scheduled, serverless agent compute (Arm 3, sa#36).

Two-task topology (NOT a sidecar): the broker runs as its own long-lived ECS
service (broker.safe-agents.local); the agent runs as a separate short-lived
scheduled task in the ISOLATED agent subnets on the agentSG, whose only egress is
the broker. Confinement is the awsvpc subnet + SG (the cloud-native analogue of
the RHEL arm's netns), not a network namespace.

Public surface the pipeline uses:
    fargate_provision                      — provision the task role(s) + task def + schedule
    fargate_teardown                       — remove everything fargate_provision created
    fargate_run_once                       — one-off RunTask (the capstone probe)
    agent_role_extensions                  — IAM statements the arm adds to the taskRole
    build_container_environment            — the runner-contract container env
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN — the secret path the taskRole must NOT access

See provision.py for full documentation.
"""
from .provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    agent_role_extensions,
    build_container_environment,
    fargate_provision,
    fargate_run_once,
    fargate_teardown,
)

__all__ = [
    "BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN",
    "agent_role_extensions",
    "build_container_environment",
    "fargate_provision",
    "fargate_run_once",
    "fargate_teardown",
]
