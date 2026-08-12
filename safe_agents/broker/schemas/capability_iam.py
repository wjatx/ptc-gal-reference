"""Per-capability IAM declaration — the consumer-facing minimal IAM a connector
capability runs with, consumed by the DEPLOY to provision a scoped role (#175).

Doctrine 2 of `broker/CONNECTOR-AUTH.md`: with an assumed-role/ambient-identity
credential, the credential *is* an identity, so its blast radius is whatever that
identity can do. The confinement answer is to scope the identity to exactly the
capability's declared IAM — never the broker's full role. This block is where a
consumer *declares* that minimal IAM (actions + resource ARNs); the deploy
(`infra/lib/`, CDK) reads it and provisions a role scoped to exactly that, trusting
the broker identity, and the `assumed_role` strategy assumes it at execute time. An
out-of-scope action is then denied by IAM, not by the broker.

Like the rest of the manifest's consumer-owned blocks (`tool_ops`, `connector_auth`),
the base owns the *shape* and the consumer *fills* it. There is no import-path or
policy-document seam here — a consumer names actions and resource ARNs as plain
strings; nothing store-loaded can inject a role, a trust policy, or a scoping (the
Envelope store loads an Envelope, which carries no IAM). The deploy is the only thing
that turns a declaration into a real role.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator


class CapabilityIam(BaseModel):
    """The minimal IAM one connector capability runs with (#175).

    Keyed by connector **tool name** in `AgentManifest.capability_iam` — the same key
    space as `connector_auth`, so a capability's credential strategy (`assumed_role`)
    and its IAM scope line up one-to-one. `actions` are IAM action strings (e.g.
    `"s3:GetObject"`); `resources` are the resource ARNs those actions are scoped to.
    Both must be non-empty — a scoped role with no actions or no resources is either a
    no-op or an unscoped wildcard, and #175's whole point is a bounded blast radius.
    """

    model_config = ConfigDict(extra="forbid")

    actions: list[str]
    resources: list[str]

    @field_validator("actions", "resources")
    @classmethod
    def _non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError(
                "capability_iam requires at least one entry — a scoped role with no "
                "actions or no resources is a no-op or an unscoped wildcard"
            )
        if any(not entry or not entry.strip() for entry in value):
            raise ValueError("capability_iam entries must be non-empty strings")
        return value
