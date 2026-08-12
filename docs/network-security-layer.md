# Network-security layer — the topological half of invariant #2

**Status: proven, then deliberately shelved (2026-07-07).** The full VPC topology described here was
built (sa#13, sa#83), deployed to `development` and `production`, and verified by the conformance
gate. It is now flag-gated behind `secureNetwork` and **ships OFF** for this platform's current
experiment floor. This document is the durable reference for the design so that turning it back on is
a deploy, not a rediscovery — and so the trade we accepted by turning it off is written down rather
than folklore.

## What the layer is

`ARCHITECTURE.md` invariant #2 says the agent's only egress is the broker, *enforced at the network
layer, never in code the agent runs* — "call the API directly" must not be a path that exists. That
sentence has two possible homes. One is code: a proxy the agent is asked to use, an SDK that routes
through the broker. The other is topology: a subnet the agent physically cannot leave except toward
the broker. Code guards are bypassable by a compromised agent; topology is not. The network-security
layer is the topological home — the resource set that makes "a compromised agent can still only ask"
true independent of any guard the agent runs, at the subnet-routing and security-group level.

`infra/README.md` frames it as **defense in depth across three independent layers**, so a misconfig in
one does not by itself open direct egress:

1. **Subnet routing** — the agent runs in a private subnet whose route table has no path to a NAT or
   internet gateway; its only reachable neighbour is the broker.
2. **Security groups** — the agent security group permits egress only to the broker security group;
   the broker security group carries the outbound reach to connector hosts.
3. **netns** (on the EC2 arms) — the agent process runs in a network namespace whose only route is the
   broker, isolating it even from other processes co-hosted on the same box.

This document covers the first two layers — the VPC topology owned by `infra/lib/network-stack.ts`.
The third (netns) is a per-arm run-path concern documented in `docs/model-egress.md`; it is unaffected
by the flag discussed here and remains the confinement mechanism on any co-hosted box.

## The proven resource set

### Three subnet tiers

The VPC spans two availability zones and defines three subnet groups, each with a distinct routing
posture that is the whole point of the tier:

- **`public`** (`SubnetType.PUBLIC`) — hosts the NAT gateway and nothing else. No agent or broker
  workload runs here. It exists only because CDK requires an explicit public subnet group to place a
  NAT gateway once `subnetConfiguration` is given by hand (the default config auto-adds one; an
  explicit config does not).
- **`agent`** (`SubnetType.PRIVATE_ISOLATED`) — where the agent runs. Its route table has **no default
  route**. Outbound egress is physically impossible at the subnet layer without a matching
  security-group rule to the broker. This is invariant #2 made topological.
- **`broker`** (`SubnetType.PRIVATE_WITH_EGRESS`) — where the broker runs. It routes through the single
  NAT gateway to reach external connector hosts, because the broker is the one component that legitimately
  needs to reach the outside world (it holds the credentials and makes the real connector calls).

A single NAT gateway serves the whole VPC, to minimise cost — NAT is the expensive part of this design
and one is enough for a broker that is not latency-bound on cross-AZ NAT hops.

### The ten interface endpoints

The agent subnet has no NAT route, so any AWS API the confined agent (or a host in its subnet) needs
must arrive over a **VPC interface endpoint** — a private ENI in the agent subnet with private DNS, so
ordinary SDK calls resolve to the private IP with no app-level change. The proven set is ten, each with
a concrete reason it is present:

- **SSM**, **SSM Messages**, **EC2 Messages** — SSM Session Manager and EC2 instance management for
  hosts in the isolated subnet (smoke tests, runbooks).
- **Secrets Manager** — the broker reads connector secrets from here.
- **KMS** — envelope decryption for those secrets and for the customer-managed keys on DynamoDB and S3.
- **ECR API** and **ECR Docker** — pulling the agent/broker container images from ECR into the isolated
  subnet.
- **CloudWatch Logs** — the agent task runs in the no-NAT isolated subnet, so its `awslogs` driver can
  only reach CloudWatch through this endpoint; without it the task fails at init. (The broker, in the
  NAT subnet, does not strictly need it, but the confined agent does.)
- **SQS** — the woken-EC2 box drains its inbound queue from the isolated subnet, so it reaches SQS here.
  (The airlock guardrail runs in Lambda outside the VPC and enqueues over the public SQS API; this
  endpoint is for the in-VPC box.)
- **EC2 API** — the woken-EC2 box self-stops (`ec2:StopInstances` on itself) when its queue drains, and
  from the no-NAT subnet that call needs this endpoint.

### The free gateway endpoints

**S3** and **DynamoDB** are reached through **gateway** endpoints, which are free and work at the
route-table level: they inject prefix-list routes into the named route tables rather than a default
route, so the agent subnet's no-default-route invariant is preserved. Both the agent (isolated) and
broker (NAT-egress) route tables receive these routes, so no subnet pays the NAT for S3/DynamoDB
traffic.

### The security-group topology

Three security groups express the egress shape:

- **Agent SG** — created with `allowAllOutbound: false`, which eliminates the implicit `0.0.0.0/0`
  egress rule CDK would otherwise add. The only egress that exists is what is added explicitly: to the
  broker SG, to the endpoint SG (TCP 443), and to the S3/DynamoDB gateway prefix lists (TCP 443).
- **Broker SG** — accepts inbound from the agent SG and allows all outbound, to reach connector hosts
  via NAT.
- **Endpoint SG** — the interface-endpoint ENIs sit behind this. It admits HTTPS (TCP 443) inbound only
  from the agent and broker SGs, and is created with `open: false` (see below).

## Hard-won lessons that must survive teardown

Three details in `network-stack.ts` cost real debugging and are the kind of thing that gets
re-broken the moment someone rebuilds the topology from memory.

**Gateway-endpoint traffic still hits security-group egress (the sa#83 bug).** It is tempting to
believe a gateway endpoint's route-table injection is the whole story. It is not: packets matching the
gateway prefix-list route are *also* evaluated against the agent SG's egress rules, and with
`allowAllOutbound: false` they are dropped before reaching the endpoint unless there is an explicit
egress rule to the managed prefix list. That was the live bug behind sa#83. The fix is the two
`CfnSecurityGroupEgress` rules granting the agent SG TCP 443 to the S3 and DynamoDB prefix lists. The
prefix-list IDs are AWS-owned and region-specific; the stack maps them by region in a static table
(`GATEWAY_PREFIX_LISTS`) rather than resolving at deploy time, because `AWS::EC2::VPCEndpoint` exposes
no prefix-list attribute and a `DescribeManagedPrefixLists` custom resource proved brittle. A static map
is deterministic and deploy-safe; adding a region means running the documented
`describe-managed-prefix-lists` command and pasting the two IDs.

**The CloudFormation SG dependency-cycle workaround.** Expressing "agent egresses to broker AND broker
ingresses from agent" as inline SG properties makes the two security groups mutually dependent, which
CloudFormation rejects as a dependency cycle (`cdk synth` tolerates it; `deploy` and
`Template.fromStack` do not). The stack therefore models every cross-SG rule as a **standalone**
`CfnSecurityGroupEgress` / `CfnSecurityGroupIngress` resource, which depends on both SGs without either
SG depending on the other. Every agent/broker/endpoint rule follows this pattern; the conformance test
reads the standalone resources, not inline properties, for exactly this reason.

**`open: false` on the interface endpoints.** CDK's default `open: true` adds an automatic "allow all
VPC traffic" ingress rule to the endpoint SG — broader than we want. Setting `open: false` suppresses
it, leaving the two explicit SG-scoped ingress rules (from agent, from broker) as the *only* ingress
the endpoints admit. The standalone `CfnSecurityGroupIngress` form is used here too, to avoid CDK's
connections-graph cycle detection adding an unwanted VPC-CIDR fallback rule.

## Cost profile — why it ships OFF

The topology's protection is real, and so is its bill. Interface endpoints are billed per-AZ-hour: ten
interface endpoints across two AZs at ~$0.01/hr is roughly **$146/mo per environment**. Add one NAT
gateway at ~$33/mo per environment. Deployed across both `development` and `production`, the measured
total was about **$375/mo**. The equivalent open-mode floor is about **$4/mo** — a single public IPv4
address for the 24/7 broker task.

For a platform that is at present an experiment carrying research and email agents — agents holding no
high-value credentials, whose worst-case exfiltration is low-stakes — $375/mo to enforce outbound
containment at the network layer is not warranted. That cost, against that risk, is the whole reason
the flag defaults to false.

## The two modes

The topology is gated behind a CDK context flag, `secureNetwork`:

- **`secureNetwork: true`** — the full topology above: three subnet tiers, the NAT gateway, all ten
  interface endpoints, the S3/DynamoDB gateway endpoints, and the three-SG egress shape.
- **`secureNetwork: false` (default) — "open" mode** — public subnets carrying the *same names* as
  before, no NAT gateway, no interface endpoints, tasks assigned public IPs (`assignPublicIp`). The
  security groups are kept, with their default-deny ingress intact. What is removed is the routing
  isolation and the private-endpoint plumbing that made outbound containment topological.

Both modes publish the **same six outputs** (`vpc-id`, `agent-subnet-ids`, `broker-subnet-ids`,
`agent-sg-id`, `broker-sg-id`, `endpoint-sg-id`) so every downstream stack imports the same keys
regardless of mode, plus a `network-mode` value (`secure` | `open`) that runtime provisioners read to
self-configure (e.g. whether a Fargate task needs a public IP).

This maps directly onto the friction doctrine (`docs/friction-doctrine.md`). The network-security layer
is a **valve**, not part of the tiny non-negotiable floor. The floor — the lethal-trifecta gates in the
broker's PDP — is always on and untunable. The network layer, by contrast, is per-consumer
risk-envelope configuration: it ships OFF for a low-risk consumer and gets turned ON for a high-risk one
(a trading agent moving real money through real broker credentials is the obvious `secureNetwork: true`
case). Framing it as a flag rather than deleting it is the doctrine's point 4 in practice — the valve
ships *with* the constraint, so a consumer who needs containment expresses it from configuration, never
a base PR.

## The trade we are accepting

Open mode gives up **outbound containment**. In the full topology a compromised agent physically cannot
reach the internet — its subnet has no route out. In open mode the agent runs in a public subnet with a
public IP; a compromised agent *could* exfiltrate data or reach an arbitrary host. That is the honest
cost, and it is why the flag exists rather than the topology being deleted.

Two things are **not** given up. First, **ingress posture is unchanged**: the security groups keep their
default-deny inbound, and nothing in this platform listens on an internet-reachable port, so open mode
opens no new inbound attack surface. Second, and more importantly, **the broker's code- and
credential-layer enforcement of invariant #2 remains fully on**: the agent still holds no connector
credentials (they live only in the broker's secret store), the broker still runs under a separate IAM
identity, and every tool call still routes through the broker's deterministic decision path with a
tamper-evident audit. Open mode removes the *network-layer* enforcement of egress containment; it does
not remove the enforcement that a compromised agent "can still only ask." The topological layer was
defense in depth over the code/credential layer, not a substitute for it.

## How to re-enable

Turning the topology back on is a deploy sequence, not a redesign:

1. Deploy the Network stacks with the flag on: `npx cdk deploy -c environment=<env> -c secureNetwork=true ...`.
   This recreates the three subnet tiers, the NAT gateway, and the endpoints, and republishes
   `network-mode=secure`.
2. Redeploy the Compute stack so tasks pick up the isolated subnets and the secure security-group
   placement (and drop their public IPs).
3. Re-provision any scheduled or long-running agent: the Fargate arm provisioner re-reads the subnet
   IDs, security-group IDs, and `network-mode` from SSM, so it self-configures once the outputs flip —
   no hardcoded values to chase.

Run the conformance gate (`cd infra && npm test`) before deploying; its Network checks assert the
isolated-subnet, no-open-egress, endpoint-SG, and gateway-prefix-list invariants against the synthesized
template, so a regression in the topology fails fast without touching AWS. And note the environment
rule: `development` may be flipped freely, but `production` is a real consumer's floor — coordinate
before deploying either mode there (`docs/environments.md`).
