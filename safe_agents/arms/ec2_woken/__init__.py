"""
ec2-woken arm — the inbound airlock wake path for a sleeping EC2 agent box (sa#34).

An event-driven WAKE mechanism, agent-agnostic and broker-centric:

    normalized inbound event ─▶ HTTP API webhook ─▶ guardrail Lambda ─▶ SQS + StartInstances

The guardrail Lambda is an untrusted-input taint boundary that holds NO connector
credentials — it only screens (shared-token header, owner allow-list, message-id dedup,
injection screen, env-driven intent classify) and, on pass, enqueues + wakes the box.
The broker is NOT in this stack; it lives on the EC2 box (sa#98). The channel adapter
(concrete channel → normalized {owner, message_id, text}) lives in a consuming agent's
manifest inbound: block, out of scope here.

Public surface the pipeline uses:
    ec2_woken_provision                    — deploy the airlock SAM stack from the manifest
    ec2_woken_teardown                     — remove the airlock stack
    read_inbound_block                     — parse/validate the manifest inbound: block
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN — the secret path the Lambda role must NOT access

See provision.py for full documentation and airlock/handler.py for the guardrail logic.
"""
from .box_provision import (
    box_role_extensions,
    ec2_woken_box_provision,
    ec2_woken_box_teardown,
    render_box_user_data,
)
from .provision import (
    BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN,
    ec2_woken_provision,
    ec2_woken_teardown,
    read_inbound_block,
)

__all__ = [
    "BROKER_CONNECTOR_KEYS_RESOURCE_PATTERN",
    "box_role_extensions",
    "ec2_woken_box_provision",
    "ec2_woken_box_teardown",
    "ec2_woken_provision",
    "ec2_woken_teardown",
    "read_inbound_block",
    "render_box_user_data",
]
