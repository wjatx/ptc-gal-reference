"""scoped_s3_connector.py — the reference per-capability IAM-scoping consumer (#175).

This is the worked example of the ``assumed_role`` credential strategy
(``safe_agents.broker.runtime.credentials.AssumedRole``) + the ``capability_iam``
manifest block. The manifest declares ``connector_auth: {s3: {strategy: assumed_role,
params: {role_arn: ...}}}`` and ``capability_iam: {s3: {actions: [...], resources:
[...]}}``. The broker assumes the deploy-provisioned, capability-scoped role and hands
THIS connector only the short-lived ``AssumedRoleCredential`` bundle — never the
broker's own identity, never a long-lived key.

The point of the example (doctrine 2): the connector's blast radius equals the role's
declared IAM scope. If it attempted an out-of-scope action, IAM — not the broker —
would deny it. Here that is *fictional and deterministic* (no real AWS call): the
connector demonstrates the shape (consume the bundle, run one narrow classified op)
and refuses anything outside its declared scope, mirroring how real IAM would.

Like ``examples/oauth_api/``, this is a consumer-owned connector reached via the
``connector_providers`` seam (sa#141) and written ONLY against the public surface —
``safe_agents.connectors`` — never against broker internals (the consumer-boundary
AST guard enforces that).

Doctrine 1 (no raw passthrough of long-lived material): this connector receives only
the short-lived STS bundle, never a long-lived key, and never echoes, logs, or returns
the credential it was given.

Doctrine 2 (no raw command/query passthrough): ``execute`` exposes one narrow,
classified capability (``s3.get_object`` on a declared key prefix), not a free-form
``s3.execute(<cmd>)`` — the ToolOp table (#171) classifies the op and ``capability_iam``
bounds the identity; a passthrough arg would defeat both.
"""

from __future__ import annotations

from typing import Any

# The ONLY safe-agents imports a consumer connector needs — the public connector
# surface, never safe_agents.broker internals. AssumedRoleCredential is the bundle
# shape the assumed_role strategy resolves.
from safe_agents.connectors import AssumedRoleCredential, Connector, Credential


class ScopedS3Connector:
    """Read one object from a (fictional) S3 bucket using a broker-assumed scoped role.

    Zero-arg instantiable and satisfying the ``Connector`` protocol
    (``execute(tool, op, args, credential)``) — the two things the registry's
    fail-closed provider check demands.
    """

    def execute(self, tool: str, op: str, args: Any, credential: Credential) -> Any:
        # `credential` here is the broker-assumed AssumedRoleCredential bundle — the
        # short-lived STS creds of the capability-scoped role, never the broker's own
        # identity and never a long-lived key. Require the bundle shape explicitly.
        if not isinstance(credential, AssumedRoleCredential):
            raise TypeError(
                "scoped_s3 requires an assumed-role credential bundle; got "
                f"{type(credential).__name__} — declare connector_auth.s3.strategy = assumed_role"
            )
        if not credential.session_token:
            raise ValueError("scoped_s3 requires live STS credentials (empty session token)")

        key = (args or {}).get("key", "")
        # Fictional deterministic "GetObject": in a real connector these bundle fields
        # would build a boto3 Session and sign the call; the scoped role — not this
        # code — is what bounds the effect. We surface the (non-secret) access-key id
        # for CloudTrail-style attribution and NEVER the secret material.
        return {
            "status": "ok",
            "op": "GetObject",
            "key": key,
            "assumed_identity": credential.access_key_id,  # identifier, not a secret
            "body": "",  # fictional: deterministic empty object body
        }


# Structural conformance, checked at import time so a drift from the protocol fails
# HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(ScopedS3Connector(), Connector)
