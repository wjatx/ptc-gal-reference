# Egress-policy drift standard (sa#52)

What counts as **egress-policy drift**, how severe each kind is, and what the off-substrate
auditor (sa#26) must diff. This is the *specification*; the auditor is the *implementation* that
calls `broker.auditor.check_egress_drift` with a live source and routes the alarms.

The network-layer egress confinement is the architectural load-bearer (`ARCHITECTURE.md`
invariant #2: a compromised agent "can still only ask"). If the live policy drifts from its
committed git definition, the confinement may have silently failed. Drift detection is how we
notice.

> **Note (2026-07-07).** The SG-layer source of truth below is the `SafeAgents-Network-<env>`
> template, whose full topology is now flag-gated behind `secureNetwork` and ships OFF for the
> current experiment floor (`docs/network-security-layer.md`). This standard describes drift against
> the `secureNetwork: true` deployment; in open mode the box-level SG carries less confinement to
> drift from, and the netns/proxy layer remains the agent-confinement check.

## Two layers — and why both are required

A single autonomous box co-hosts the agent and the broker sidecar. The box-level security group
governs the **whole box**, and the box must egress to connector hosts for the broker — so an SG
**cannot** separate agent traffic from broker traffic (`docs/model-egress.md`). The real
agent-confinement floor is a **network namespace** whose only route is the broker, plus the
broker's **hostname-allowlisted model proxy**. An SG-only drift check would therefore miss the
layer that actually confines the agent. The standard covers both:

| Layer | `layer` value | Source of truth | What it confines |
|---|---|---|---|
| Security group | `sg` | CDK synth template (`infra/cdk.out/SafeAgents-Network-<env>.template.json`) | what the **box** may reach |
| netns + model-proxy | `netns_proxy` | `safe_agents/arms/<arm>/bootstrap/scripts/agent-netns-setup.sh` (veth /30 forwarding hop; since sa#97 the netns no longer blackholes the default route — confinement is the host SG). `ec2` also runs a co-located `model-proxy-stub.py` (`DEFAULT_ALLOWLIST=api.anthropic.com`, port 8443); `rhel-openshell` forwards to the external broker service with no on-box proxy. | what the **agent** may reach |

## Canonical source of truth

The **committed snapshot** is authoritative: `infra/snapshots/<arm>.json`, one per arm
(`rhel-openshell`, `ec2`). It is **machine-generated, never hand-maintained**, by
`infra/scripts/gen-egress-snapshot.py`, which parses the synth template for the SG layer and the
bootstrap scripts for the netns/proxy layer. Regenerate after any `cdk synth` or any change to the
confinement scripts, then commit:

```
cd infra && npx cdk synth -c environment=development   # refresh the SG template
python3 infra/scripts/gen-egress-snapshot.py            # rewrite infra/snapshots/*.json
```

That check belongs in CI: re-run `cdk synth` and the generator on every change, and fail on any
`git diff` in `infra/snapshots/`, so the committed snapshot cannot silently lag the synth template
or the bootstrap scripts. This repository ships no workflow of its own, so run the two commands
above by hand until you have wired the check into yours. The snapshot rules are normalised
to a region-independent,
human-meaningful form (`sg:broker`, `prefixlist:s3`, `cidr:0.0.0.0/0`) rather than raw
CloudFormation refs, so the same canonical rule is comparable to a live `DescribeSecurityGroupRules`
result. The `allowAllOutbound:false` `255.255.255.255/32` placeholder CDK emits is excluded — it
represents the *absence* of egress, not a path.

## Drift categories and severities

Drift is a **symmetric diff** of committed vs live, with canonical-key equality (field reordering
is not drift). Each drifted rule is classified per its layer; the finding's overall severity is the
highest among its items.

### Layer 1 — security group (`layer: sg`)

| Drift | Severity | Why |
|---|---|---|
| Extra **outbound** rule in live, not in git | **critical** | potential egress bypass — the box can reach something git never authorised |
| Rule in git but **missing** in live | warning | tighter than expected; may break broker connectivity but is not a safety regression |
| Extra/changed **inbound** rule in live | warning | monitored, but ingress is not the confinement mechanism |

### Layer 2 — netns + model proxy (`layer: netns_proxy`)

| Drift | Severity | Why |
|---|---|---|
| Proxy allowlist **widened** (any host beyond `api.anthropic.com`) | **critical** | the agent can now reach a host the model carve-out never blessed |
| Blackhole default route **missing or altered** (incl. an added non-blackhole default) | **critical** | the agent netns has a route it must not — direct egress becomes possible |
| veth /30 topology altered (reachable peer changed) | **critical** | the agent's only-reachable-peer invariant is broken |
| Allowlisted model host **missing** from live | warning | the model may be unreachable; not an egress widening |

The mapping is the sa#52 SG model (extra-live-egress → critical, missing → warning, inbound →
warning) extended to layer 2, where "extra reachable host/route" is the critical analogue of an
extra outbound SG rule.

## Detection mechanism (out of scope here: sa#26)

The off-substrate auditor (sa#26) constructs a **live** `EgressPolicySource` and calls
`check_egress_drift(source)`. For the SG layer the live source is
`DescribeSecurityGroupRules` on the arm's agent/broker/endpoint SGs (read-only IAM:
`ec2:DescribeSecurityGroupRules`); for the netns/proxy layer the live source is the on-box
confinement smoke (`smoke-egress.sh` assertions, reported as `netns_proxy` rules). Building that
live source is **sa#26's scope, not this work-item** — this standard defines *what to diff and the
severity mapping*; the auditor does the diffing and the alarm routing. The watchdog is read-only:
it detects and reports; it never reverts a rule (remediation is a human action).

## Alarm routing

- **critical** drift must **page** — a `critical` `DriftItem` means a potential egress bypass or a
  broken confinement boundary on a live box.
- **warning** drift must **log a structured message** naming the rule, the SG (or netns/proxy
  expectation), the **arm**, and the **layer**. Each `DriftItem` carries `rule`, `presence`,
  `layer`, `severity`, and a human-readable `reason` so the auditor can format this without
  re-deriving it; the arm comes from which snapshot the auditor loaded.

Egress-policy drift (this) and audit-chain gaps (sa#26's other check) are **separate failure modes
with separate alarm channels** — co-located in the auditor, never conflated.

## Scope notes

- Per-agent connector allowlists are **not** here — the base standard covers the agent → broker (+
  model) confinement; consumer repos add their allowed connectors on the broker's side.
- Drift **remediation** (auto-reverting an SG rule) is explicitly out of scope: detect and alarm
  only.
- Both arms currently share the one Network stack and the identical netns + broker-proxy design, so
  their snapshots differ only in `arm`; each is still diffed against its own live box.
