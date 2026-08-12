# scoped_s3 — per-capability IAM scoping (#175, PTC Phase 3a)

A **fictional** reference consumer for the `assumed_role` credential strategy plus the
`capability_iam` manifest block — the confinement half of `broker/CONNECTOR-AUTH.md`.
It is the worked example behind conformance clauses **C6–C8**.

## What it shows

`#173` made a connector's credential a broker-resolved *strategy* instead of a static
string. `#175` finishes the story when the credential is an **identity**: an assumed
IAM role's blast radius is whatever that role can do, so the role must be scoped to
*exactly* the declared capability — never the broker's full identity (doctrine 2).

This example declares both halves for one capability, `s3.get_object`:

| declaration | block | consumed by |
|---|---|---|
| **how** the credential resolves | `connector_auth.s3 = {strategy: assumed_role, params: {role_arn}}` | the broker, per call |
| **what** IAM the capability runs with | `capability_iam.s3 = {actions, resources}` | the deploy (CDK), at provision time |

## The flow

1. **Declare** — `manifest.yaml` names the minimal IAM (`s3:GetObject` on one bucket
   prefix) and selects `assumed_role`.
2. **Provision** — the deploy (`infra/lib/`, CDK) reads `capability_iam` and creates a
   role scoped to exactly that, trusting the broker identity.
3. **Assume** — at execute time the broker (`credentials.AssumedRole`) STS-assumes the
   role and hands `scoped_s3_connector.py` only the short-lived
   `AssumedRoleCredential` bundle — never the broker's own identity, never a long-lived
   key.

**The payoff:** an out-of-scope action (a `PutObject`, a different bucket) is denied by
**IAM**, not by the broker. A fully compromised agent that somehow reached this
connector still cannot exceed one `GetObject` on one prefix.

## Fictional and deterministic

No real AWS call, no real bucket, no real STS. `scoped_s3_connector.py` consumes the
bundle shape and returns a deterministic empty object; the `role_arn` uses the
`000000000000` placeholder account. The invariants it proves are structural — the
connector receives an identity bundle (not a string), never echoes the secret material,
and exposes one narrow classified op rather than a free-form passthrough.

## The two doctrines

- **No raw passthrough of long-lived material** — the connector sees only the
  short-lived STS bundle; the role's trust stays in IAM.
- **No raw command/query passthrough** — `s3.get_object` is a narrow classified
  capability, not `s3.execute(<cmd>)`; the ToolOp table classifies the op and
  `capability_iam` bounds the identity.
