/**
 * Conformance test-table (sa#11 · #16) — the verifier that licenses the foundation build loop.
 *
 * Encodes the `ARCHITECTURE.md` pre-deployment checklist (lines 103–121) as machine-checkable
 * assertions against *synthesized* CloudFormation. No AWS calls: the stacks are instantiated in
 * process and inspected via `Template.fromStack(...).toJSON()`. Each row names the invariant it
 * guards, so a failure says exactly which line of the checklist broke.
 *
 * Run: `npm test` (wired to `ts-node tests/conformance.ts`). Exits non-zero on any failure.
 */
import { App, Tags } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Environment } from '../lib/environment';
import { exportName, resourceName, stackName } from '../lib/naming';
import { NetworkStack } from '../lib/network-stack';
import { StateStack } from '../lib/state-stack';
import { IdentityStack } from '../lib/identity-stack';
import { ChannelsStack } from '../lib/channels-stack';
import { ComputeStack } from '../lib/compute-stack';

const ENV: Environment = 'development';

// Instantiate the foundation exactly as the app does, so we assert what actually deploys. The
// network flag is passed explicitly (not read from ambient context) so each mode is asserted
// deterministically. `templates.network` is the SECURE topology — every existing Network invariant
// runs against it; the open topology is synthesized separately below for the cost-guard checks.
const app = new App({ context: { environment: ENV } });
const network = new NetworkStack(app, stackName(ENV, 'Network'), {
  environment: ENV,
  secureNetwork: true,
});
const state = new StateStack(app, stackName(ENV, 'State'), { environment: ENV });
const identity = new IdentityStack(app, stackName(ENV, 'Identity'), { environment: ENV });
identity.addDependency(state);
// ChannelsStack with the default context (channelsDeployFunction defaults on) — the airlock
// function + API are asserted against this template. It imports State's exports.
const channels = new ChannelsStack(app, stackName(ENV, 'Channels'), { environment: ENV });
channels.addDependency(state);
Tags.of(app).add('Project', 'safe-agents');
Tags.of(app).add('Environment', ENV);

const templates = {
  network: Template.fromStack(network).toJSON() as CfnTemplate,
  state: Template.fromStack(state).toJSON() as CfnTemplate,
  identity: Template.fromStack(identity).toJSON() as CfnTemplate,
  channels: Template.fromStack(channels).toJSON() as CfnTemplate,
};

// The airlock stack synthesized with channelsDeployFunction=false (its own App to avoid a
// stack-name clash) — the first-phase bringup that lays down repo + queue + secret but no
// function or API. Asserted by the two-phase-skip check below.
const noFnApp = new App({ context: { environment: ENV, channelsDeployFunction: false } });
const channelsNoFn = new ChannelsStack(noFnApp, stackName(ENV, 'Channels'), { environment: ENV });
Tags.of(noFnApp).add('Project', 'safe-agents');
Tags.of(noFnApp).add('Environment', ENV);
const channelsNoFnTemplate = Template.fromStack(channelsNoFn).toJSON() as CfnTemplate;

// The airlock stack with the reference-screen model ARNs declared (its own App, same clash
// avoidance) — the screened-consumer shape. Asserted by the bedrock-scoping check: the role gains
// bedrock:InvokeModel on EXACTLY these ARNs, and only in this variant.
const SCREEN_MODEL_ARNS = [
  'arn:aws:bedrock:us-east-1:111122223333:inference-profile/example-profile',
  'arn:aws:bedrock:us-east-1::foundation-model/example-model',
];
const screenedApp = new App({
  context: { environment: ENV, channelsScreenModelArns: SCREEN_MODEL_ARNS.join(',') },
});
const channelsScreened = new ChannelsStack(screenedApp, stackName(ENV, 'Channels'), {
  environment: ENV,
});
Tags.of(screenedApp).add('Project', 'safe-agents');
Tags.of(screenedApp).add('Environment', ENV);
const channelsScreenedTemplate = Template.fromStack(channelsScreened).toJSON() as CfnTemplate;

// The airlock stack with the sender-verification keys pointer declared (channels/SIGNING.md's
// receiver-side verification) — its own App, same clash avoidance. Asserted by the verify-keys
// checks below; the default template above (`templates.channels`) stays the pointer-off shape.
const VERIFY_KEYS_ARN =
  'arn:aws:secretsmanager:us-east-1:111122223333:secret:example-verify-keys-AbCdEf';
const verifyKeysApp = new App({
  context: { environment: ENV, channelsVerifyKeysArn: VERIFY_KEYS_ARN },
});
const channelsVerifyKeys = new ChannelsStack(verifyKeysApp, stackName(ENV, 'Channels'), {
  environment: ENV,
});
Tags.of(verifyKeysApp).add('Project', 'safe-agents');
Tags.of(verifyKeysApp).add('Environment', ENV);
const channelsVerifyKeysTemplate = Template.fromStack(channelsVerifyKeys).toJSON() as CfnTemplate;

// IdentityStack with the standing checker role declared (#202) — its own App, same clash
// avoidance. The default identity template above stays the five-role shape (checker OFF), so
// absent-by-default is asserted against `templates.identity`.
const CHECKER_PRINCIPAL = 'arn:aws:iam::111122223333:user/example-checker';
const checkerApp = new App({
  context: { environment: ENV, checkerTrustedPrincipals: CHECKER_PRINCIPAL },
});
const identityChecker = new IdentityStack(checkerApp, stackName(ENV, 'Identity'), {
  environment: ENV,
});
Tags.of(checkerApp).add('Project', 'safe-agents');
Tags.of(checkerApp).add('Environment', ENV);
const identityCheckerTemplate = Template.fromStack(identityChecker).toJSON() as CfnTemplate;

// The identity stack with the demotion operator-trust gate ON (#192): the context ADDS the
// named principals to DemotionRole's trust ALONGSIDE the service principals (the deployment
// binding), unlike the checker's named-principals-only role. Off-by-default is asserted
// against `templates.identity`.
const DEMOTION_PRINCIPAL = 'arn:aws:iam::111122223333:user/example-operator';
const demotionApp = new App({
  context: { environment: ENV, demotionTrustedPrincipals: DEMOTION_PRINCIPAL },
});
const identityDemotion = new IdentityStack(demotionApp, stackName(ENV, 'Identity'), {
  environment: ENV,
});
Tags.of(demotionApp).add('Project', 'safe-agents');
Tags.of(demotionApp).add('Environment', ENV);
const identityDemotionTemplate = Template.fromStack(identityDemotion).toJSON() as CfnTemplate;

// The identity stack with the FULL operator plane ON: all four operator-trust contexts set at
// once (checker + demotion + promotion + maker + auditor). Asserts the gates compose — the
// boundary roles keep their shape, the gated roles/trusts all appear, and nothing else changes.
const OPERATOR_PRINCIPAL = 'arn:aws:iam::111122223333:user/example-operator';
const operatorApp = new App({
  context: {
    environment: ENV,
    checkerTrustedPrincipals: CHECKER_PRINCIPAL,
    demotionTrustedPrincipals: OPERATOR_PRINCIPAL,
    promotionTrustedPrincipals: OPERATOR_PRINCIPAL,
    makerTrustedPrincipals: OPERATOR_PRINCIPAL,
    auditorTrustedPrincipals: OPERATOR_PRINCIPAL,
  },
});
const identityOperator = new IdentityStack(operatorApp, stackName(ENV, 'Identity'), {
  environment: ENV,
});
Tags.of(operatorApp).add('Project', 'safe-agents');
Tags.of(operatorApp).add('Environment', ENV);
const identityOperatorTemplate = Template.fromStack(identityOperator).toJSON() as CfnTemplate;

// The channels stack with the drain worker enabled (sa#155): image tag + the two required
// image-baked env context keys. Asserted by the drain checks — the default template above stays
// the drain-off shape (repo only), so drain-off-by-default is asserted against `templates.channels`.
const DRAIN_MANIFEST_PATH = '/app/agents/drain-manifest.yaml';
const DRAIN_RECEIVER = 'example_pkg.receivers:ExampleReceiver';
const drainApp = new App({
  context: {
    environment: ENV,
    channelsDrainImageTag: 'drain-test-1',
    channelsDrainManifestPath: DRAIN_MANIFEST_PATH,
    channelsDrainReceiver: DRAIN_RECEIVER,
  },
});
const channelsDrain = new ChannelsStack(drainApp, stackName(ENV, 'Channels'), {
  environment: ENV,
});
Tags.of(drainApp).add('Project', 'safe-agents');
Tags.of(drainApp).add('Environment', ENV);
const channelsDrainTemplate = Template.fromStack(channelsDrain).toJSON() as CfnTemplate;

// The open (flag=false) network topology, synthesized in its own App to avoid a stack-name clash.
// Open mode trades away network-layer egress containment for the NAT + interface-endpoint spend, so
// it gets the COST GUARD checks (no NAT, no interface endpoints) rather than the confinement ones.
const openApp = new App({ context: { environment: ENV } });
const openNetwork = new NetworkStack(openApp, stackName(ENV, 'Network'), {
  environment: ENV,
  secureNetwork: false,
});
Tags.of(openApp).add('Project', 'safe-agents');
Tags.of(openApp).add('Environment', ENV);
const openNetworkTemplate = Template.fromStack(openNetwork).toJSON() as CfnTemplate;

// ComputeStack with the default (absent) `capabilityRoles` context — asserts sa#175's no-op default:
// no capability role, no sts:AssumeRole grant on the broker role, and (mechanically) the same shape
// the pre-#175 stack synthesized. Its own App to avoid a stack-name clash with the compute-with-
// capabilities variant below.
const computeApp = new App({ context: { environment: ENV } });
const computeDefault = new ComputeStack(computeApp, stackName(ENV, 'Compute'), {
  environment: ENV,
  secureNetwork: false,
});
Tags.of(computeApp).add('Project', 'safe-agents');
Tags.of(computeApp).add('Environment', ENV);
const computeDefaultTemplate = Template.fromStack(computeDefault).toJSON() as CfnTemplate;

// ComputeStack with one declared capability — asserts the scoped role, its trust policy, and the
// broker's matching (narrowly-scoped) sts:AssumeRole grant.
const CAPABILITY_SPEC = {
  tool: 's3',
  roleName: 'scoped-s3-reader-s3',
  actions: ['s3:GetObject'],
  resources: ['arn:aws:s3:::b/*'],
};
const computeCapApp = new App({
  context: { environment: ENV, capabilityRoles: JSON.stringify([CAPABILITY_SPEC]) },
});
const computeWithCapabilities = new ComputeStack(computeCapApp, stackName(ENV, 'Compute'), {
  environment: ENV,
  secureNetwork: false,
});
Tags.of(computeCapApp).add('Project', 'safe-agents');
Tags.of(computeCapApp).add('Environment', ENV);
const computeWithCapabilitiesTemplate = Template.fromStack(computeWithCapabilities).toJSON() as CfnTemplate;

// A production StateStack, synthesized to assert the env-aware removal polarity (#9-A): the same
// code with the environment flipped must yield durable (RETAIN) state in production. This also
// exercises promotion being code-identical (#9-B) — production synthesizes from the same source.
const prodApp = new App({ context: { environment: 'production' } });
const prodState = new StateStack(prodApp, stackName('production', 'State'), {
  environment: 'production',
});
const prodStateTemplate = Template.fromStack(prodState).toJSON() as CfnTemplate;

// ── tiny template helpers ──────────────────────────────────────────────────────────────────────
interface CfnResource {
  Type: string;
  Properties?: Record<string, unknown>;
  DeletionPolicy?: string;
}
interface CfnTemplate {
  Resources: Record<string, CfnResource>;
  Outputs?: Record<string, { Value?: unknown; Export?: { Name?: string } }>;
}

function resourcesOfType(tmpl: CfnTemplate, type: string): [string, CfnResource][] {
  return Object.entries(tmpl.Resources).filter(([, r]) => r.Type === type);
}

function refId(value: unknown): string | undefined {
  if (value && typeof value === 'object' && 'Ref' in value) {
    return (value as { Ref: string }).Ref;
  }
  return undefined;
}

function exportNames(tmpl: CfnTemplate): Set<string> {
  const names = new Set<string>();
  for (const out of Object.values(tmpl.Outputs ?? {})) {
    if (out.Export?.Name) names.add(out.Export.Name);
  }
  return names;
}

// ── checks: Network (#13) ────────────────────────────────────────────────────────────────────────
function agentSgLogicalId(): string {
  const sg = resourcesOfType(templates.network, 'AWS::EC2::SecurityGroup').find(([, r]) =>
    String(r.Properties?.GroupDescription ?? '').includes('Agent'),
  );
  if (!sg) throw new Error('agent security group not found');
  return sg[0];
}

/** True if a CloudFormation value (Ref or Fn::GetAtt) points at the given logical id. */
function referencesLogicalId(value: unknown, logicalId: string): boolean {
  if (!value || typeof value !== 'object') return false;
  if ('Ref' in value) return (value as { Ref: string }).Ref === logicalId;
  if ('Fn::GetAtt' in value) {
    const att = (value as { 'Fn::GetAtt': unknown })['Fn::GetAtt'];
    return Array.isArray(att) && att[0] === logicalId;
  }
  return false;
}

function isOpenEgress(rule: Record<string, unknown>): boolean {
  return rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0';
}

/** Standalone egress rule resources attached to the agent SG (the real egress is modelled here). */
function agentStandaloneEgress(): Record<string, unknown>[] {
  const id = agentSgLogicalId();
  return resourcesOfType(templates.network, 'AWS::EC2::SecurityGroupEgress')
    .filter(([, r]) => referencesLogicalId(r.Properties?.GroupId, id))
    .map(([, r]) => r.Properties ?? {});
}

function agentSgHasNoOpenEgress(): boolean {
  // Check both the inline egress (CDK's disallow-all placeholder lives here) and the standalone
  // rule resources — none may open 0.0.0.0/0 or ::/0.
  const inline = (templates.network.Resources[agentSgLogicalId()].Properties?.SecurityGroupEgress ??
    []) as Record<string, unknown>[];
  return !inline.some(isOpenEgress) && !agentStandaloneEgress().some(isOpenEgress);
}

function agentSgEgressTargetsBrokerSgOnly(): boolean {
  // Every standalone egress rule must target a security group or a managed prefix list;
  // raw CIDR (0.0.0.0/0) egress is forbidden. At least one rule must exist.
  const standalone = agentStandaloneEgress();
  return (
    standalone.length >= 1 &&
    standalone.every(
      (rule) => 'DestinationSecurityGroupId' in rule || 'DestinationPrefixListId' in rule,
    )
  );
}

function agentSgHasGatewayPrefixListEgress(): boolean {
  // Agent must have TCP 443 egress to the S3 and DynamoDB managed prefix lists (two rules).
  // DestinationPrefixListId is a deploy-time token resolved by an AwsCustomResource
  // (DescribeManagedPrefixLists) — we cannot match a concrete prefix list ID at synth time.
  // Assert: at least two TCP-443 rules with DestinationPrefixListId set, no raw CIDR source.
  const standalone = agentStandaloneEgress();
  const plRules = standalone.filter(
    (rule) =>
      'DestinationPrefixListId' in rule &&
      !('CidrIp' in rule) &&
      !('CidrIpv6' in rule) &&
      rule.IpProtocol === 'tcp' &&
      rule.FromPort === 443 &&
      rule.ToPort === 443,
  );
  return plRules.length >= 2;
}

function allDescriptionsAreAscii(): boolean {
  // Several AWS services reject non-ASCII in description fields at create time, and they disagree
  // on the exact charset (EC2 SecurityGroup.GroupDescription is strict ASCII; IAM Role.Description
  // allows only up to U+00FF; KMS is lenient). synth and the assertions library accept anything.
  // Enforce plain ASCII on every Description / GroupDescription across all stacks — the strict
  // common denominator — so a stray em-dash can't reach any deploy.
  // eslint-disable-next-line no-control-regex
  const nonAscii = /[^\x00-\x7F]/;
  const DESCRIPTION_KEYS = ['Description', 'GroupDescription'];
  return Object.values(templates).every((tmpl) =>
    Object.values(tmpl.Resources).every((r) =>
      DESCRIPTION_KEYS.every((k) => !nonAscii.test(String(r.Properties?.[k] ?? ''))),
    ),
  );
}

function agentSubnetsHaveNoDefaultRoute(): boolean {
  const t = templates.network;
  const agentSubnetIds = resourcesOfType(t, 'AWS::EC2::Subnet')
    .filter(([, r]) => {
      const tags = (r.Properties?.Tags ?? []) as { Key?: string; Value?: string }[];
      return tags.some((tag) => tag.Key === 'aws-cdk:subnet-name' && tag.Value === 'agent');
    })
    .map(([id]) => id);
  if (agentSubnetIds.length === 0) return false;

  const agentRouteTables = new Set<string>();
  for (const [, assoc] of resourcesOfType(t, 'AWS::EC2::SubnetRouteTableAssociation')) {
    const subnet = refId(assoc.Properties?.SubnetId);
    if (subnet && agentSubnetIds.includes(subnet)) {
      const rt = refId(assoc.Properties?.RouteTableId);
      if (rt) agentRouteTables.add(rt);
    }
  }

  for (const [, route] of resourcesOfType(t, 'AWS::EC2::Route')) {
    if (route.Properties?.DestinationCidrBlock !== '0.0.0.0/0') continue;
    const rt = refId(route.Properties?.RouteTableId);
    if (rt && agentRouteTables.has(rt)) return false; // a default route on an agent subnet → fail
  }
  return true;
}

// ── checks: VPC endpoints (#83) ───────────────────────────────────────────────────────────────

/**
 * CDK synthesizes interface endpoint service names as a Fn::Join token:
 *   { "Fn::Join": ["", ["com.amazonaws.", { "Ref": "AWS::Region" }, ".<service>"]] }
 * The last element of the inner array is the service suffix (e.g. ".ssm", ".s3").
 * Gateway endpoints follow the same pattern.
 */
function endpointServiceSuffix(r: CfnResource): string {
  const join = (r.Properties?.ServiceName as Record<string, unknown> | undefined)?.['Fn::Join'];
  if (!Array.isArray(join) || join.length < 2) return '';
  const parts = join[1];
  if (!Array.isArray(parts)) return '';
  const last = parts[parts.length - 1];
  return typeof last === 'string' ? last : '';
}

function endpointSgLogicalId(): string {
  const sg = resourcesOfType(templates.network, 'AWS::EC2::SecurityGroup').find(([, r]) =>
    String(r.Properties?.GroupDescription ?? '').includes('Endpoint SG'),
  );
  if (!sg) throw new Error('endpoint security group not found');
  return sg[0];
}

function gatewayEndpointsExist(): boolean {
  const gateways = resourcesOfType(templates.network, 'AWS::EC2::VPCEndpoint').filter(
    ([, r]) => r.Properties?.VpcEndpointType === 'Gateway',
  );
  return (
    gateways.some(([, r]) => endpointServiceSuffix(r) === '.s3') &&
    gateways.some(([, r]) => endpointServiceSuffix(r) === '.dynamodb')
  );
}

function interfaceEndpointsExist(): boolean {
  const ifaces = resourcesOfType(templates.network, 'AWS::EC2::VPCEndpoint').filter(
    ([, r]) => r.Properties?.VpcEndpointType === 'Interface',
  );
  const required = ['.ssm', '.ssmmessages', '.ec2messages', '.secretsmanager', '.kms'];
  return required.every((svc) => ifaces.some(([, r]) => endpointServiceSuffix(r) === svc));
}

/**
 * The endpoint SG must accept inbound 443 only from the agent and broker SGs.
 * CDK creates standalone CfnSecurityGroupIngress resources (with open:false on the endpoint
 * construct) — the endpoint SG itself carries no inline SecurityGroupIngress rules.
 */
function endpointSgAdmits443OnlyFromAgentAndBroker(): boolean {
  const endpointId = endpointSgLogicalId();
  const standaloneIngress = resourcesOfType(templates.network, 'AWS::EC2::SecurityGroupIngress')
    .filter(([, r]) => referencesLogicalId(r.Properties?.GroupId, endpointId))
    .map(([, r]) => r.Properties ?? {});
  // Must have exactly agent-SG and broker-SG ingress rules, both TCP 443, no CIDR source.
  if (standaloneIngress.length < 2) return false;
  return standaloneIngress.every(
    (rule) =>
      rule.IpProtocol === 'tcp' &&
      rule.FromPort === 443 &&
      rule.ToPort === 443 &&
      'SourceSecurityGroupId' in rule &&
      !('CidrIp' in rule) &&
      !('CidrIpv6' in rule),
  );
}

// ── checks: open network mode (cost guard) ───────────────────────────────────────────────────────
// Open mode drops the ~$375/mo NAT + interface-endpoint spend. These guard that the saving is real
// (nothing billable slipped back in) while ingress stays default-deny — asserted against the
// separately-synthesized open template.
const NETWORK_OUTPUT_KEYS = [
  'vpc-id',
  'agent-subnet-ids',
  'broker-subnet-ids',
  'agent-sg-id',
  'broker-sg-id',
  'endpoint-sg-id',
  'network-mode',
];

function networkOutputsPresent(tmpl: CfnTemplate): boolean {
  const names = exportNames(tmpl);
  return NETWORK_OUTPUT_KEYS.map((k) => `safe-agents-${ENV}-${k}`).every((n) => names.has(n));
}

function networkModeOutputValue(tmpl: CfnTemplate): unknown {
  const target = `safe-agents-${ENV}-network-mode`;
  for (const out of Object.values(tmpl.Outputs ?? {})) {
    if (out.Export?.Name === target) return out.Value;
  }
  return undefined;
}

function openNetworkHasNoNatGateway(): boolean {
  return resourcesOfType(openNetworkTemplate, 'AWS::EC2::NatGateway').length === 0;
}

function openNetworkHasNoInterfaceEndpoints(): boolean {
  // Gateway endpoints (S3/DynamoDB, free) must remain; only the billable Interface endpoints go.
  const ifaces = resourcesOfType(openNetworkTemplate, 'AWS::EC2::VPCEndpoint').filter(
    ([, r]) => r.Properties?.VpcEndpointType === 'Interface',
  );
  const gateways = resourcesOfType(openNetworkTemplate, 'AWS::EC2::VPCEndpoint').filter(
    ([, r]) => r.Properties?.VpcEndpointType === 'Gateway',
  );
  return ifaces.length === 0 && gateways.length >= 2;
}

/** No SG opens 0.0.0.0/0 (or ::/0) INBOUND — checked for inline and standalone ingress rules. */
function hasNoOpenIngress(tmpl: CfnTemplate): boolean {
  const inlineOpen = resourcesOfType(tmpl, 'AWS::EC2::SecurityGroup').some(([, r]) => {
    const rules = (r.Properties?.SecurityGroupIngress ?? []) as Record<string, unknown>[];
    return rules.some((rule) => rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0');
  });
  const standaloneOpen = resourcesOfType(tmpl, 'AWS::EC2::SecurityGroupIngress').some(([, r]) => {
    const p = r.Properties ?? {};
    return p.CidrIp === '0.0.0.0/0' || p.CidrIpv6 === '::/0';
  });
  return !inlineOpen && !standaloneOpen;
}

// ── checks: State (#14) ────────────────────────────────────────────────────────────────────────
function tables(): CfnResource[] {
  return resourcesOfType(templates.state, 'AWS::DynamoDB::Table').map(([, r]) => r);
}

function sixDurableTables(): boolean {
  // grants / counters / intents / agent-runs + the channels dedupe table (sa#152) + the MCP
  // admitted-tool registry (#174).
  return tables().length === 6;
}

function allTablesOnDemandWithPitr(): boolean {
  const ts = tables();
  if (ts.length !== 6) return false;
  return ts.every((r) => {
    const p = r.Properties ?? {};
    const pitr = (p.PointInTimeRecoverySpecification ?? {}) as {
      PointInTimeRecoveryEnabled?: boolean;
    };
    return p.BillingMode === 'PAY_PER_REQUEST' && pitr.PointInTimeRecoveryEnabled === true;
  });
}

// #334. This used to filter every bucket for `ObjectLockEnabled === true` and assert the count
// was 1 — which proved that SOME one bucket carried the flag, never which, and coupled the check
// to how many Object-Lock buckets the stack happens to have. Worse, it asserted the ENABLING FLAG
// and not the RETENTION: `ObjectLockEnabled` is true in development, where the bucket carries no
// default retention at all, so the gate was green in exactly the configuration where nothing is
// locked. Identify by NAME and assert the retention, in BOTH polarities — the lax configuration is
// deliberate in an ephemeral env, so a single-polarity assertion cannot be right in both places.
// MUTATION-TESTED 2026-07-29, because a gate that has only ever passed is indistinguishable from
// an absent gate — which is the very defect these two replace. Both were watched to fail, and to
// fail SELECTIVELY rather than together: flipping the durable retention to COMPLIANCE reddened
// only the prod row; giving development a retention reddened only the dev row. state-stack.ts was
// restored and verified byte-identical to HEAD afterwards.
const WORM_RETENTION_DAYS = 2557; // ~7 years; the durable-environment default in StateStack

function auditBucketOf(tmpl: CfnTemplate, env: Environment): CfnResource | undefined {
  const hit = resourcesOfType(tmpl, 'AWS::S3::Bucket').find(
    ([, r]) => r.Properties?.BucketName === resourceName(env, 'audit'),
  );
  return hit?.[1];
}

/** Development: Object Lock ENABLED (it cannot be turned on later) but deliberately NO retention. */
function auditBucketLockEnabledWithoutRetentionInDev(): boolean {
  const bucket = auditBucketOf(templates.state, ENV);
  if (!bucket) return false;
  const p = bucket.Properties ?? {};
  return p.ObjectLockEnabled === true && p.ObjectLockConfiguration === undefined;
}

/** Production: the same code must yield a real GOVERNANCE retention, not just the flag. */
function auditBucketHasGovernanceRetentionInProd(): boolean {
  const bucket = auditBucketOf(prodStateTemplate, 'production');
  if (!bucket) return false;
  const p = bucket.Properties ?? {};
  if (p.ObjectLockEnabled !== true) return false;
  const rule = (p.ObjectLockConfiguration as { Rule?: { DefaultRetention?: Record<string, unknown> } })
    ?.Rule?.DefaultRetention;
  if (!rule) return false;
  // GOVERNANCE, not COMPLIANCE — deliberate, so an admin holding
  // s3:BypassGovernanceRetention keeps an escape hatch (state-stack.ts:152-164). Pinned so a
  // silent downgrade to no-mode, or a silent upgrade nobody decided, both fail.
  return rule.Mode === 'GOVERNANCE' && rule.Days === WORM_RETENTION_DAYS;
}

function fourCustomerManagedKeys(): boolean {
  return resourcesOfType(templates.state, 'AWS::KMS::Key').length === 4;
}

function ledgerBucketVersionedWithoutWorm(): boolean {
  // The ledger bucket (sa#131) must be versioned but must NOT carry Object Lock: it is the
  // agent's ledger copy, not the audit chain — append-only is enforced via brokerRole IAM.
  const bucket = resourcesOfType(templates.state, 'AWS::S3::Bucket').find(
    ([, r]) => r.Properties?.BucketName === `safe-agents-${ENV}-ledger`,
  );
  if (!bucket) return false;
  const p = bucket[1].Properties ?? {};
  const versioning = (p.VersioningConfiguration ?? {}) as { Status?: string };
  return versioning.Status === 'Enabled' && p.ObjectLockEnabled === undefined;
}

function deletionPolicies(tmpl: CfnTemplate, type: string): (string | undefined)[] {
  return resourcesOfType(tmpl, type).map(([, r]) => r.DeletionPolicy);
}

function developmentStateIsEphemeral(): boolean {
  // In development every table is DeletionPolicy: Delete so the env tears down hands-off.
  const dp = deletionPolicies(templates.state, 'AWS::DynamoDB::Table');
  return dp.length === 6 && dp.every((p) => p === 'Delete');
}

function productionStateIsDurable(): boolean {
  // The same code with environment=production must RETAIN every table (durable polarity).
  const dp = deletionPolicies(prodStateTemplate, 'AWS::DynamoDB::Table');
  return dp.length === 6 && dp.every((p) => p === 'Retain');
}

function stateExportsPresent(): boolean {
  const names = exportNames(templates.state);
  const required = [
    'tables-key-arn',
    'audit-key-arn',
    'ledger-key-arn',
    'secrets-key-arn',
    'grants-table-arn',
    'counters-table-arn',
    'intents-table-arn',
    'agent-runs-table-arn',
    'channel-dedupe-table-name',
    'channel-dedupe-table-arn',
    'mcp-registry-table-name',
    'mcp-registry-table-arn',
    'audit-bucket-arn',
    'ledger-bucket-arn',
    'deploy-bucket-arn',
  ].map((k) => `safe-agents-${ENV}-${k}`);
  return required.every((n) => names.has(n));
}

function mcpRegistryTableExistsWithGenericKeySchemaAndCmk(): boolean {
  // TOOLDEF#/TOOLREC#/TOOLPROP# rows co-locate under the same generic (pk, sk) shape as the
  // grants table — mirrors GrantsTable's construction exactly (state-stack.ts), including reuse
  // of the shared tablesKey CMK rather than a new key estate for this table.
  const table = resourcesOfType(templates.state, 'AWS::DynamoDB::Table').find(
    ([, r]) => r.Properties?.TableName === `safe-agents-${ENV}-mcp-registry`,
  );
  if (!table) return false;
  const p = table[1].Properties ?? {};
  const keys = (p.KeySchema ?? []) as { AttributeName: string; KeyType: string }[];
  const hasGenericKeys =
    keys.length === 2 &&
    keys.some((k) => k.AttributeName === 'pk' && k.KeyType === 'HASH') &&
    keys.some((k) => k.AttributeName === 'sk' && k.KeyType === 'RANGE');
  const sse = (p.SSESpecification ?? {}) as {
    SSEEnabled?: boolean;
    SSEType?: string;
    KMSMasterKeyId?: unknown;
  };
  return (
    hasGenericKeys && sse.SSEEnabled === true && sse.SSEType === 'KMS' && sse.KMSMasterKeyId !== undefined
  );
}

// ── checks: Identity (#15) ───────────────────────────────────────────────────────────────────────
interface Statement {
  Effect: string;
  Action?: string | string[];
  Resource?: unknown;
  Condition?: unknown;
}

interface TrustStatement {
  Effect: string;
  Action?: string | string[];
  Principal?: { Service?: string | string[]; Federated?: unknown };
}

const ROLE_NAMES = ['AgentRole', 'BrokerRole', 'PromotionRole', 'DemotionRole'] as const;
const WATCHER_ROLE_NAME = 'WatcherRole';
const CAMPAIGN_WATCHER_ROLE_NAME = 'CampaignWatcherRole';
const KNOWN_ROLE_NAMES = [...ROLE_NAMES, WATCHER_ROLE_NAME, CAMPAIGN_WATCHER_ROLE_NAME] as const;
const DDB_WRITE_ACTIONS = [
  'dynamodb:PutItem',
  'dynamodb:UpdateItem',
  'dynamodb:DeleteItem',
  'dynamodb:BatchWriteItem',
];
// ssm:GetParameter is the #194 issuer verify-keys read: PUBLIC key material, deliberately
// Parameter Store so the watcher's no-Secrets-Manager rule stays absolute.
const WATCHER_ALLOWED_ACTIONS = [
  'dynamodb:Query',
  'dynamodb:Scan',
  'dynamodb:GetItem',
  'kms:Decrypt',
  'ssm:GetParameter',
];
// The sa#161 campaign watchdog's allowed surface: S3 read on the two channels audit prefixes +
// read-only CloudWatch Logs on the broker/airlock groups. No dynamodb, no kms, no secretsmanager.
const CAMPAIGN_WATCHER_ALLOWED_ACTIONS = [
  's3:GetObject',
  's3:ListBucket',
  'logs:FilterLogEvents',
  'logs:DescribeLogStreams',
  'logs:GetLogEvents',
];

/** The synthesized logical id of a role, matched by its construct-id prefix. */
function roleLogicalId(name: (typeof KNOWN_ROLE_NAMES)[number]): string {
  const found = resourcesOfType(templates.identity, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith(name),
  );
  if (!found) throw new Error(`role ${name} not found`);
  return found[0];
}

/** All policy statements attached to a role (via its AWS::IAM::Policy resources). */
function statementsForRole(name: (typeof KNOWN_ROLE_NAMES)[number]): Statement[] {
  const id = roleLogicalId(name);
  const stmts: Statement[] = [];
  for (const [, policy] of resourcesOfType(templates.identity, 'AWS::IAM::Policy')) {
    const roles = (policy.Properties?.Roles ?? []) as unknown[];
    if (roles.some((r) => refId(r) === id)) {
      const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
      for (const s of doc?.Statement ?? []) stmts.push(s);
    }
  }
  return stmts;
}

/** The role's trust-policy statements (AssumeRolePolicyDocument), for principal-type checks. */
function trustStatementsForRole(name: (typeof KNOWN_ROLE_NAMES)[number]): TrustStatement[] {
  const id = roleLogicalId(name);
  const role = templates.identity.Resources[id];
  const doc = role.Properties?.AssumeRolePolicyDocument as
    | { Statement?: TrustStatement[] }
    | undefined;
  return doc?.Statement ?? [];
}

function actionsOf(s: Statement): string[] {
  return Array.isArray(s.Action) ? s.Action : s.Action ? [s.Action] : [];
}
function resourceString(s: Statement): string {
  return JSON.stringify(s.Resource ?? '');
}

function roleWritesGrants(name: (typeof ROLE_NAMES)[number]): boolean {
  return statementsForRole(name).some(
    (s) =>
      actionsOf(s).some((a) => DDB_WRITE_ACTIONS.includes(a)) &&
      resourceString(s).includes('grants-table-arn'),
  );
}
function roleReadsSecrets(name: (typeof ROLE_NAMES)[number]): boolean {
  return statementsForRole(name).some((s) => actionsOf(s).some((a) => a.startsWith('secretsmanager:')));
}

function fourBoundaryRolesPlusWatcher(): boolean {
  // The four boundary roles must be present and distinct, AND the only additional roles may be
  // the two GitHub Actions OIDC watchers (sa#140 liveness/grants watcher, sa#161 campaign
  // watchdog) — no other surprise roles slip into IdentityStack.
  const roles = resourcesOfType(templates.identity, 'AWS::IAM::Role');
  const fourBoundaryRolesPresent = ROLE_NAMES.every((n) => roles.some(([id]) => id.startsWith(n)));
  const onlyKnownRoles = roles.every(([id]) => KNOWN_ROLE_NAMES.some((n) => id.startsWith(n)));
  return roles.length === 6 && fourBoundaryRolesPresent && onlyKnownRoles;
}

function agentRoleHasZeroAuthority(): boolean {
  // No policy is attached to the agent role at all — the strongest form of "holds nothing".
  return statementsForRole('AgentRole').length === 0;
}

function onlyPromotionAndDemotionWriteGrants(): boolean {
  return (
    roleWritesGrants('PromotionRole') &&
    roleWritesGrants('DemotionRole') &&
    !roleWritesGrants('BrokerRole') &&
    !roleWritesGrants('AgentRole')
  );
}

function secretStatementsForRole(name: (typeof ROLE_NAMES)[number]): Statement[] {
  return statementsForRole(name).filter((s) =>
    actionsOf(s).some((a) => a.startsWith('secretsmanager:')),
  );
}

function secretReadsAreNamespaceSplit(): boolean {
  // Refined from the earlier only-broker-reads-secrets row (Phase 4, #123), and again when the
  // demotion evaluator gained a signing key of its own: THREE disjoint namespaces, one per
  // signing/credential function. Broker reads ONLY */connectors/* (connector credentials),
  // promotion reads ONLY */issuer/* (the DSSE key for records that RAISE authority), demotion
  // reads ONLY */evaluator/* (the DSSE key for records that LOWER it — demotion and lapse), and
  // the agent role reads no secrets at all. No reader can reach another's namespace, so no
  // signing identity can forge another's record type.
  const brokerSecrets = secretStatementsForRole('BrokerRole');
  const promotionSecrets = secretStatementsForRole('PromotionRole');
  const demotionSecrets = secretStatementsForRole('DemotionRole');
  const confinedTo = (stmts: Statement[], ns: string) =>
    stmts.length > 0 &&
    stmts.every((s) => resourceString(s).includes(ns)) &&
    ['/connectors/', '/issuer/', '/evaluator/']
      .filter((other) => other !== ns)
      .every((other) => !stmts.some((s) => resourceString(s).includes(other)));
  return (
    confinedTo(brokerSecrets, '/connectors/') &&
    confinedTo(promotionSecrets, '/issuer/') &&
    confinedTo(demotionSecrets, '/evaluator/') &&
    !roleReadsSecrets('AgentRole')
  );
}

function evaluatorSigningIsSplitFromIssuer(): boolean {
  // The property the second signing identity exists for, stated in both directions and across
  // every role that holds a signing key: the deterministic demotion evaluator cannot mint a
  // record that raises authority, and the human-ratified promotion path cannot mint one that
  // claims a demotion trigger fired. Verification binds record type to signing role, so the two
  // PRIVATE key namespaces staying disjoint in IAM is what makes that structural rather than
  // conventional.
  //
  // CheckerRole is checked in the gated template because it is the ratifier that actually signs
  // when the operator plane is on; PromotionRole covers the seed/re-seed/tighten path.
  const demotionSecrets = secretStatementsForRole('DemotionRole');
  const promotionSecrets = secretStatementsForRole('PromotionRole');
  const checkerSecrets = statementsForRoleIn(identityCheckerTemplate, 'CheckerRole').filter((s) =>
    actionsOf(s).some((a) => a.startsWith('secretsmanager:')),
  );
  const evaluatorCannotSignPromotions =
    demotionSecrets.length > 0 &&
    demotionSecrets.every((s) => resourceString(s).includes('/evaluator/')) &&
    !demotionSecrets.some((s) => resourceString(s).includes('/issuer/'));
  const ratifiersCannotSignDemotions =
    promotionSecrets.length > 0 &&
    checkerSecrets.length > 0 &&
    ![...promotionSecrets, ...checkerSecrets].some((s) =>
      resourceString(s).includes('/evaluator/'),
    );

  // PUBLIC verify keys are the deliberate exception: an auditor must verify every record type it
  // walks, so both read-only identities read BOTH verify-key parameters — and sign nothing. The
  // watcher additionally reads no Secrets Manager at all, which is what keeps "verifying is not
  // signing" true by construction rather than by policy wording.
  //
  // BOTH is asserted, not "at least one", because one-sided is worse than none: the audit
  // resolves the other role's records to RECORD_ROLE_UNRESOLVED and reports findings, rather
  // than narrowing its scope. Dropping either ARN here is a red floor, not a smaller audit.
  const readsBothVerifyParams = (stmts: Statement[]) => {
    const ssm = stmts.filter((s) => actionsOf(s).includes('ssm:GetParameter'));
    const resources = ssm.map(resourceString).join('');
    return (
      ssm.length > 0 &&
      resources.includes('/issuer/verify-keys') &&
      resources.includes('/evaluator/verify-keys')
    );
  };
  const auditorsVerifyBoth =
    readsBothVerifyParams(statementsForRole(WATCHER_ROLE_NAME)) &&
    readsBothVerifyParams(statementsForRoleIn(identityOperatorTemplate, 'AuditorRole')) &&
    !roleReadsSecrets('AgentRole') &&
    !statementsForRole(WATCHER_ROLE_NAME).some((s) =>
      actionsOf(s).some((a) => a.startsWith('secretsmanager:')),
    );

  return evaluatorCannotSignPromotions && ratifiersCannotSignDemotions && auditorsVerifyBoth;
}

function brokerRoleMcpRegistryIsReadOnly(): boolean {
  // The McpHost's discovery-time read of TOOLDEF# rows must be structurally unable to write the
  // registry — mirrors "the broker cannot write grants" for the #174 admitted-tool store.
  const stmts = statementsForRole('BrokerRole').filter((s) =>
    resourceString(s).includes('mcp-registry-table-arn'),
  );
  return (
    stmts.length > 0 &&
    stmts.every((s) => actionsOf(s).every((a) => a === 'dynamodb:GetItem' || a === 'dynamodb:Query')) &&
    !stmts.some((s) => actionsOf(s).some((a) => DDB_WRITE_ACTIONS.includes(a)))
  );
}

// ── checker-role checks (#202) — against the checker-variant identity template ────────────────

/** Statements for a role in an arbitrary identity template (the checker variant). */
function statementsForRoleIn(template: CfnTemplate, prefix: string): Statement[] {
  const found = resourcesOfType(template, 'AWS::IAM::Role').find(([id]) => id.startsWith(prefix));
  if (!found) throw new Error(`role ${prefix} not found`);
  const stmts: Statement[] = [];
  for (const [, policy] of resourcesOfType(template, 'AWS::IAM::Policy')) {
    const roles = (policy.Properties?.Roles ?? []) as unknown[];
    if (roles.some((r) => refId(r) === found[0])) {
      const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
      for (const s of doc?.Statement ?? []) stmts.push(s);
    }
  }
  return stmts;
}

function checkerRoleAbsentByDefault(): boolean {
  // The default synth (no checkerTrustedPrincipals context) creates NO checker role — the
  // five-role shape is pinned byte-for-byte by identity/four-roles; this row names the gate.
  return !resourcesOfType(templates.identity, 'AWS::IAM::Role').some(([id]) =>
    id.startsWith('CheckerRole'),
  );
}

function checkerRoleTrustsOnlyNamedPrincipals(): boolean {
  // With the context set: CheckerRole exists and its trust policy names EXACTLY the declared
  // IAM principal ARNs — no service principals, no account root. The separation from the maker
  // is topological (a standing trust), not ceremonial (live IAM surgery per ratify).
  const found = resourcesOfType(identityCheckerTemplate, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('CheckerRole'),
  );
  if (!found) return false;
  const doc = found[1].Properties?.AssumeRolePolicyDocument as
    | { Statement?: { Principal?: { AWS?: unknown; Service?: unknown } }[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  return (
    stmts.length > 0 &&
    stmts.every(
      (s) =>
        s.Principal?.Service === undefined &&
        JSON.stringify(s.Principal?.AWS ?? '').includes(CHECKER_PRINCIPAL),
    )
  );
}

function checkerRoleIsRatifyShaped(): boolean {
  // Grants-table read/write + tables CMK + */issuer/* secrets + secrets CMK — and NOTHING
  // else: no */connectors/* and no */evaluator/* (the namespace split holds three ways — the
  // ratifier cannot sign a demotion or a lapse), no counters access (evidence assembly
  // belongs to the maker's propose), no S3, no ssm.
  const stmts = statementsForRoleIn(identityCheckerTemplate, 'CheckerRole');
  const writesGrants = stmts.some(
    (s) =>
      actionsOf(s).some((a) => DDB_WRITE_ACTIONS.includes(a)) &&
      resourceString(s).includes('grants-table-arn'),
  );
  const secretStmts = stmts.filter((s) =>
    actionsOf(s).some((a) => a.startsWith('secretsmanager:')),
  );
  const issuerOnly =
    secretStmts.length > 0 &&
    secretStmts.every((s) => resourceString(s).includes('/issuer/')) &&
    !secretStmts.some(
      (s) =>
        resourceString(s).includes('/connectors/') || resourceString(s).includes('/evaluator/'),
    );
  const noCounters = !stmts.some((s) => resourceString(s).includes('counters-table-arn'));
  const noOtherServices = stmts.every((s) =>
    actionsOf(s).every(
      (a) =>
        a.startsWith('dynamodb:') || a.startsWith('kms:') || a.startsWith('secretsmanager:'),
    ),
  );
  return writesGrants && issuerOnly && noCounters && noOtherServices;
}

function checkerVariantKeepsBoundaryRoles(): boolean {
  // The gated synth ADDS the checker (seven roles) without disturbing the six default roles.
  const roles = resourcesOfType(identityCheckerTemplate, 'AWS::IAM::Role');
  return (
    roles.length === 7 &&
    ROLE_NAMES.every((n) => roles.some(([id]) => id.startsWith(n))) &&
    roles.some(([id]) => id.startsWith(WATCHER_ROLE_NAME)) &&
    roles.some(([id]) => id.startsWith(CAMPAIGN_WATCHER_ROLE_NAME)) &&
    roles.some(([id]) => id.startsWith('CheckerRole'))
  );
}

function demotionTrustServiceOnlyByDefault(): boolean {
  // The default synth (no demotionTrustedPrincipals context): DemotionRole's trust policy
  // names ONLY service principals — no AWS (ArnPrincipal) entries anywhere.
  const found = resourcesOfType(templates.identity, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('DemotionRole'),
  );
  if (!found) return false;
  const doc = found[1].Properties?.AssumeRolePolicyDocument as
    | { Statement?: { Principal?: { AWS?: unknown; Service?: unknown } }[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  return stmts.length > 0 && stmts.every((s) => s.Principal?.AWS === undefined);
}

function demotionGatedTrustIsAdditive(): boolean {
  // With the context set: the trust policy carries BOTH the three service principals (the
  // deployment binding is never displaced) AND the named operator ARN.
  const found = resourcesOfType(identityDemotionTemplate, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('DemotionRole'),
  );
  if (!found) return false;
  const doc = JSON.stringify(found[1].Properties?.AssumeRolePolicyDocument ?? {});
  return (
    doc.includes(DEMOTION_PRINCIPAL) &&
    ['ec2.amazonaws.com', 'ecs-tasks.amazonaws.com', 'lambda.amazonaws.com'].every((svc) =>
      doc.includes(svc),
    )
  );
}

function demotionGatedPermissionsUnchanged(): boolean {
  // The gate touches TRUST only: the gated DemotionRole's policy statements are identical to
  // the default synth's. Operator assumability must never widen what the role can do.
  const stmtsOf = (tpl: CfnTemplate) =>
    JSON.stringify(statementsForRoleIn(tpl, 'DemotionRole'));
  return stmtsOf(identityDemotionTemplate) === stmtsOf(templates.identity);
}

function demotionGatedAddsNoRoles(): boolean {
  // Unlike the checker gate (which adds a sixth role), the demotion gate mints NO new
  // identity — the role count and names match the default synth exactly.
  const names = (tpl: CfnTemplate) =>
    resourcesOfType(tpl, 'AWS::IAM::Role')
      .map(([id]) => id)
      .sort();
  return JSON.stringify(names(identityDemotionTemplate)) === JSON.stringify(names(templates.identity));
}

function makerAuditorAbsentByDefault(): boolean {
  // The default synth (no operator contexts) creates neither MakerRole nor AuditorRole.
  return !resourcesOfType(templates.identity, 'AWS::IAM::Role').some(
    ([id]) => id.startsWith('MakerRole') || id.startsWith('AuditorRole'),
  );
}

function promotionTrustServiceOnlyByDefault(): boolean {
  // Default synth: PromotionRole trust names ONLY service principals (no ArnPrincipals).
  const found = resourcesOfType(templates.identity, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('PromotionRole'),
  );
  if (!found) return false;
  const doc = found[1].Properties?.AssumeRolePolicyDocument as
    | { Statement?: { Principal?: { AWS?: unknown } }[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  return stmts.length > 0 && stmts.every((s) => s.Principal?.AWS === undefined);
}

function promotionGatedTrustIsAdditive(): boolean {
  // With the context set: BOTH the service principals (deployment binding) AND the operator.
  const found = resourcesOfType(identityOperatorTemplate, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('PromotionRole'),
  );
  if (!found) return false;
  const doc = JSON.stringify(found[1].Properties?.AssumeRolePolicyDocument ?? {});
  return (
    doc.includes(OPERATOR_PRINCIPAL) &&
    ['ec2.amazonaws.com', 'ecs-tasks.amazonaws.com', 'lambda.amazonaws.com'].every((svc) =>
      doc.includes(svc),
    )
  );
}

function promotionGatedPermissionsUnchanged(): boolean {
  const stmtsOf = (tpl: CfnTemplate) =>
    JSON.stringify(statementsForRoleIn(tpl, 'PromotionRole'));
  return stmtsOf(identityOperatorTemplate) === stmtsOf(templates.identity);
}

function makerRoleTrustsOnlyNamedPrincipals(): boolean {
  // MakerRole (like CheckerRole) is operator-only: no service principals in its trust.
  const found = resourcesOfType(identityOperatorTemplate, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('MakerRole'),
  );
  if (!found) return false;
  const doc = found[1].Properties?.AssumeRolePolicyDocument as
    | { Statement?: { Principal?: { AWS?: unknown; Service?: unknown } }[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  return (
    stmts.length > 0 &&
    stmts.every(
      (s) =>
        s.Principal?.Service === undefined &&
        JSON.stringify(s.Principal?.AWS ?? '').includes(OPERATOR_PRINCIPAL),
    )
  );
}

function makerRoleIsProposeShaped(): boolean {
  // Grants read + UpdateItem (the PROPOSAL# item — the proposal store writes via CONDITIONAL
  // update_item, the ledger's append idiom) + counters GetItem + tables CMK — and NOTHING
  // else: no PutItem (unconditional overwrite), no secretsmanager AT ALL (the maker cannot
  // sign a record and cannot read connector credentials), no s3/ssm. The live first-use
  // propose was IAM-denied under a PutItem-shaped cut; this row pins the corrected shape.
  const stmts = statementsForRoleIn(identityOperatorTemplate, 'MakerRole');
  const actions = stmts.flatMap(actionsOf);
  const updatesGrants = stmts.some(
    (s) =>
      actionsOf(s).includes('dynamodb:UpdateItem') && resourceString(s).includes('grants-table-arn'),
  );
  const countersReadOnly = stmts
    .filter((s) => resourceString(s).includes('counters-table-arn'))
    .every((s) => actionsOf(s).every((a) => a === 'dynamodb:GetItem'));
  return (
    updatesGrants &&
    countersReadOnly &&
    !actions.includes('dynamodb:PutItem') &&
    !actions.some((a) => a.startsWith('secretsmanager:')) &&
    actions.every((a) => a.startsWith('dynamodb:') || a.startsWith('kms:'))
  );
}

function makerCannotMintAGrantRow(): boolean {
  // The #203 write split: EVERY UpdateItem the maker holds is confined by a LeadingKeys
  // condition to the proposal key space, so a GRANT#/TOOLDEF# upsert is refused by IAM
  // rather than by the store's ConditionExpression — prevention, not detection.
  //
  // Asserted as a property of every write statement, not the presence of one good one: an
  // unconditioned UpdateItem added alongside would re-open the hole silently, and a row
  // that only checks "some statement is scoped" would stay green through it.
  //
  // Reads must stay UNCONDITIONED — the maker legitimately reads the anchored grant, the
  // envelope, and the current registry row for the propose-time re-vet. This row fails if
  // a future edit scopes the reads too, because read-denied is not a stricter
  // write-denied; it breaks the ceremony.
  const stmts = statementsForRoleIn(identityOperatorTemplate, 'MakerRole');
  const tableStmts = stmts.filter(
    (s) =>
      resourceString(s).includes('grants-table-arn') ||
      resourceString(s).includes('mcp-registry-table-arn'),
  );
  const writeStmts = tableStmts.filter((s) => actionsOf(s).includes('dynamodb:UpdateItem'));
  const readStmts = tableStmts.filter((s) => !actionsOf(s).includes('dynamodb:UpdateItem'));

  const scopedToProposals = (s: Statement) => {
    const cond = JSON.stringify(s.Condition ?? '');
    return (
      cond.includes('ForAllValues:StringLike') &&
      cond.includes('dynamodb:LeadingKeys') &&
      (cond.includes('PROPOSAL#') || cond.includes('TOOLPROP#')) &&
      !cond.includes('GRANT#') &&
      !cond.includes('TOOLDEF#')
    );
  };
  const readsUnconditioned = (s: Statement) => s.Condition === undefined;

  return (
    writeStmts.length === 2 && // one per table; a third would be an unreviewed surface
    writeStmts.every(scopedToProposals) &&
    readStmts.length === 2 &&
    readStmts.every(readsUnconditioned)
  );
}

function makerCheckerMcpRegistryHasNoPutItem(): boolean {
  // Both admission-ceremony legs write the #174 registry via CONDITIONAL update_item — never
  // PutItem, which would authorize an unconditional overwrite (mirrors the grants
  // proposal/ratify statements' existing no-PutItem shape). Both roles are present together in
  // the full-operator-plane variant.
  const noPutItem = (stmts: Statement[]) =>
    stmts.length > 0 && !stmts.some((s) => actionsOf(s).includes('dynamodb:PutItem'));
  const makerStmts = statementsForRoleIn(identityOperatorTemplate, 'MakerRole').filter((s) =>
    resourceString(s).includes('mcp-registry-table-arn'),
  );
  const checkerStmts = statementsForRoleIn(identityOperatorTemplate, 'CheckerRole').filter((s) =>
    resourceString(s).includes('mcp-registry-table-arn'),
  );
  return noPutItem(makerStmts) && noPutItem(checkerStmts);
}

function auditorRoleTrustsOnlyNamedPrincipals(): boolean {
  const found = resourcesOfType(identityOperatorTemplate, 'AWS::IAM::Role').find(([id]) =>
    id.startsWith('AuditorRole'),
  );
  if (!found) return false;
  const doc = found[1].Properties?.AssumeRolePolicyDocument as
    | { Statement?: { Principal?: { AWS?: unknown; Service?: unknown } }[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  return (
    stmts.length > 0 &&
    stmts.every(
      (s) =>
        s.Principal?.Service === undefined &&
        JSON.stringify(s.Principal?.AWS ?? '').includes(OPERATOR_PRINCIPAL),
    )
  );
}

function auditorRoleIsReadOnlyPlusHmacKey(): boolean {
  // Read-only everywhere (no ddb writes, no kms:GenerateDataKey), and its ONLY secret is the
  // env-scoped broker HMAC key — no */connectors/*, and neither PRIVATE signing namespace
  // (*/issuer/*, */evaluator/*): the auditor verifies both record families from the PUBLIC
  // verify-key parameters in SSM and can sign neither.
  const stmts = statementsForRoleIn(identityOperatorTemplate, 'AuditorRole');
  const actions = stmts.flatMap(actionsOf);
  const secretStmts = stmts.filter((s) => actionsOf(s).some((a) => a.startsWith('secretsmanager:')));
  const hmacOnly =
    secretStmts.length > 0 &&
    secretStmts.every(
      (s) =>
        resourceString(s).includes('broker-hmac-key') &&
        !resourceString(s).includes('/connectors/') &&
        !resourceString(s).includes('/issuer/') &&
        !resourceString(s).includes('/evaluator/'),
    );
  return (
    hmacOnly &&
    !actions.some((a) => DDB_WRITE_ACTIONS.includes(a)) &&
    !actions.includes('kms:GenerateDataKey') &&
    actions.every(
      (a) =>
        a.startsWith('dynamodb:') ||
        a.startsWith('kms:') ||
        a.startsWith('secretsmanager:') ||
        a === 'ssm:GetParameter' ||
        // export-name → table-name resolution, the audit's documented interface
        a === 'cloudformation:ListExports',
    )
  );
}

function operatorPlaneComposes(): boolean {
  // All gates ON at once: the six default roles + checker + maker + auditor = nine roles,
  // and the boundary/watcher roles' policy statements are untouched relative to the default synth.
  const roles = resourcesOfType(identityOperatorTemplate, 'AWS::IAM::Role');
  const untouched = ['BrokerRole', 'AgentRole', 'WatcherRole', 'CampaignWatcherRole'].every(
    (name) =>
      JSON.stringify(statementsForRoleIn(identityOperatorTemplate, name)) ===
      JSON.stringify(statementsForRoleIn(templates.identity, name)),
  );
  return (
    roles.length === 9 &&
    ['CheckerRole', 'MakerRole', 'AuditorRole'].every((n) =>
      roles.some(([id]) => id.startsWith(n)),
    ) &&
    untouched
  );
}

function brokerCannotDeleteAudit(): boolean {
  return !statementsForRole('BrokerRole').some((s) =>
    actionsOf(s).some((a) => a === 's3:DeleteObject' || a === 's3:DeleteObjectVersion'),
  );
}

function brokerLedgerIsPutObjectOnly(): boolean {
  // Every broker statement touching the ledger bucket grants s3:PutObject and nothing else —
  // no Get/List/Delete/Acl. IAM is the ledger's ONLY append-only enforcement (no Object Lock).
  const stmts = statementsForRole('BrokerRole').filter((s) =>
    resourceString(s).includes('ledger-bucket-arn'),
  );
  return (
    stmts.length >= 1 &&
    stmts.every((s) =>
      actionsOf(s)
        .filter((a) => a.startsWith('s3:'))
        .every((a) => a === 's3:PutObject'),
    )
  );
}

function watcherRoleIsReadOnly(): boolean {
  // The watcher (sa#140 liveness + #62 grants audit + #194 verify-keys) is assumed via GitHub
  // Actions OIDC — a Federated principal, never a service principal — and its attached actions
  // must be exactly the read-only set WATCHER_ALLOWED_ACTIONS: no writes (the grants auditor
  // must be structurally unable to write the table it judges), no secrets access (the audit's
  // tamper rows need the broker HMAC key and are operator-run, never CI; the issuer verify keys
  // are PUBLIC and ride SSM, keeping the no-Secrets-Manager rule absolute), no
  // kms:GenerateDataKey.
  const trustStmts = trustStatementsForRole(WATCHER_ROLE_NAME);
  const trustIsOidcOnly =
    trustStmts.length >= 1 &&
    trustStmts.every((s) => {
      const actions = Array.isArray(s.Action) ? s.Action : s.Action ? [s.Action] : [];
      return (
        actions.includes('sts:AssumeRoleWithWebIdentity') &&
        s.Principal?.Federated !== undefined &&
        s.Principal?.Service === undefined
      );
    });

  const actions = statementsForRole(WATCHER_ROLE_NAME).flatMap(actionsOf);
  const onlyReadActions = actions.length >= 1 && actions.every((a) => WATCHER_ALLOWED_ACTIONS.includes(a));
  const noWrites = !actions.some((a) => DDB_WRITE_ACTIONS.includes(a));
  const noSecrets = !actions.some((a) => a.startsWith('secretsmanager:'));
  const noGenerateDataKey = !actions.includes('kms:GenerateDataKey');

  return trustIsOidcOnly && onlyReadActions && noWrites && noSecrets && noGenerateDataKey;
}

function campaignWatcherRoleIsReadOnly(): boolean {
  // The sa#161 campaign watchdog: same OIDC-only trust idiom as watcherRole, read-only S3 scoped
  // to exactly channels/drops/* + channels/verdicts/*, read-only Logs scoped to exactly the
  // broker + channels-airlock log groups, and structurally no secretsmanager/dynamodb/kms/write
  // action anywhere.
  const trustStmts = trustStatementsForRole(CAMPAIGN_WATCHER_ROLE_NAME);
  const trustIsOidcOnly =
    trustStmts.length >= 1 &&
    trustStmts.every((s) => {
      const actions = Array.isArray(s.Action) ? s.Action : s.Action ? [s.Action] : [];
      return (
        actions.includes('sts:AssumeRoleWithWebIdentity') &&
        s.Principal?.Federated !== undefined &&
        s.Principal?.Service === undefined
      );
    });

  const stmts = statementsForRole(CAMPAIGN_WATCHER_ROLE_NAME);
  const actions = stmts.flatMap(actionsOf);
  const onlyReadActions =
    actions.length >= 1 && actions.every((a) => CAMPAIGN_WATCHER_ALLOWED_ACTIONS.includes(a));
  const noWrites = !actions.some((a) => DDB_WRITE_ACTIONS.includes(a));
  const noSecrets = !actions.some((a) => a.startsWith('secretsmanager:'));
  const noDynamo = !actions.some((a) => a.startsWith('dynamodb:'));
  const noKms = !actions.some((a) => a.startsWith('kms:'));

  const s3GetStmt = stmts.find((s) => actionsOf(s).includes('s3:GetObject'));
  const s3Scoped =
    s3GetStmt !== undefined &&
    resourceString(s3GetStmt).includes('channels/drops/') &&
    resourceString(s3GetStmt).includes('channels/verdicts/') &&
    !resourceHasWildcard(s3GetStmt.Resource);

  const listStmt = stmts.find((s) => actionsOf(s).includes('s3:ListBucket'));
  const listCondition = JSON.stringify(listStmt?.Condition ?? '');
  const listScopedByPrefixCondition =
    listStmt !== undefined &&
    listCondition.includes('channels/drops/') &&
    listCondition.includes('channels/verdicts/');

  const logsStmt = stmts.find((s) => actionsOf(s).includes('logs:FilterLogEvents'));
  const logsScoped =
    logsStmt !== undefined &&
    resourceString(logsStmt).includes('/broker:') &&
    resourceString(logsStmt).includes('/channels-airlock:') &&
    !resourceHasWildcard(logsStmt.Resource);

  return (
    trustIsOidcOnly &&
    onlyReadActions &&
    noWrites &&
    noSecrets &&
    noDynamo &&
    noKms &&
    s3Scoped &&
    listScopedByPrefixCondition &&
    logsScoped
  );
}

function identityExportsPresent(): boolean {
  const names = exportNames(templates.identity);
  return [
    'agent-role-arn',
    'broker-role-arn',
    'promotion-role-arn',
    'demotion-role-arn',
    'watcher-role-arn',
    'campaign-watcher-role-arn',
  ]
    .map((k) => `safe-agents-${ENV}-${k}`)
    .every((n) => names.has(n));
}

// ── checks: Channels airlock (sa#152) ────────────────────────────────────────────────────────────
// The airlock is a COMPONENT stack: it fronts untrusted external input, so it must sit OUTSIDE the
// VPC, expose exactly one throttled POST /inbound route, hold a least-privilege (no-wildcard) role,
// and skip the function/API entirely in the first bringup phase. The dedupe table is CMK-encrypted
// state that lives in StateStack.

function channelsResourcesOfType(type: string): [string, CfnResource][] {
  return resourcesOfType(templates.channels, type);
}

function airlockLambdaHasNoVpcConfig(): boolean {
  // Exactly one airlock function, and it declares no VpcConfig — it is external-facing, not agent
  // egress, so it never joins the confined VPC.
  const fns = channelsResourcesOfType('AWS::Lambda::Function');
  return fns.length === 1 && fns.every(([, r]) => r.Properties?.VpcConfig === undefined);
}

function resourceHasWildcard(resource: unknown): boolean {
  if (resource === '*') return true;
  if (Array.isArray(resource)) return resource.some((r) => r === '*');
  return false;
}

function channelsNoWildcardResource(): boolean {
  // No IAM policy statement in the stack may use Resource '*'. Scan both standalone AWS::IAM::Policy
  // documents and any inline role policies; the airlock role's grants are all ARN-scoped, and the
  // explicit log group means even logs perms carry a concrete resource (no CreateLogGroup wildcard).
  const statements: Statement[] = [];
  for (const [, policy] of channelsResourcesOfType('AWS::IAM::Policy')) {
    const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
    for (const s of doc?.Statement ?? []) statements.push(s);
  }
  for (const [, role] of channelsResourcesOfType('AWS::IAM::Role')) {
    const inline = (role.Properties?.Policies ?? []) as {
      PolicyDocument?: { Statement?: Statement[] };
    }[];
    for (const p of inline) for (const s of p.PolicyDocument?.Statement ?? []) statements.push(s);
  }
  return statements.length >= 1 && statements.every((s) => !resourceHasWildcard(s.Resource));
}

function iamStatementsOf(template: CfnTemplate): Statement[] {
  const statements: Statement[] = [];
  for (const [, policy] of resourcesOfType(template, 'AWS::IAM::Policy')) {
    const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
    for (const s of doc?.Statement ?? []) statements.push(s);
  }
  for (const [, role] of resourcesOfType(template, 'AWS::IAM::Role')) {
    const inline = (role.Properties?.Policies ?? []) as {
      PolicyDocument?: { Statement?: Statement[] };
    }[];
    for (const p of inline) for (const s of p.PolicyDocument?.Statement ?? []) statements.push(s);
  }
  return statements;
}

function statementActions(s: Statement): string[] {
  return Array.isArray(s.Action) ? (s.Action as string[]) : [s.Action as string];
}

function channelsNoBedrockByDefault(): boolean {
  // The screen ships OFF, and an OFF control's authority must not sit in the role: the default
  // synth (no channelsScreenModelArns context) carries no bedrock action anywhere in the stack.
  return iamStatementsOf(templates.channels).every((s) =>
    statementActions(s).every((a) => !a.startsWith('bedrock:')),
  );
}

function airlockSecretsManagerStatements(tmpl: CfnTemplate): Statement[] {
  return iamStatementsOf(tmpl).filter((s) => actionsOf(s).some((a) => a.startsWith('secretsmanager:')));
}

function verifyKeysOffByDefault(): boolean {
  // No channelsVerifyKeysArn context: exactly one secretsmanager statement in the whole stack
  // (the airlock's webhook secret), and no BROKER_VERIFY_KEYS_SECRET_ARN env var — the pointer
  // contributes nothing at all when unset.
  const fns = channelsResourcesOfType('AWS::Lambda::Function');
  if (fns.length !== 1) return false;
  const vars =
    (fns[0][1].Properties?.Environment as { Variables?: Record<string, unknown> } | undefined)
      ?.Variables ?? {};
  return (
    !('BROKER_VERIFY_KEYS_SECRET_ARN' in vars) &&
    airlockSecretsManagerStatements(templates.channels).length === 1
  );
}

function verifyKeysWiredWhenSet(): boolean {
  // With channelsVerifyKeysArn declared: the airlock env carries BROKER_VERIFY_KEYS_SECRET_ARN
  // pointing at exactly the declared ARN (the env name safe_agents/channels/keys.py reads), and
  // the role gains exactly one additional secretsmanager statement — GetSecretValue only (the
  // airlock only ever calls get_secret_value), scoped to exactly that ARN, never a wildcard.
  const fns = resourcesOfType(channelsVerifyKeysTemplate, 'AWS::Lambda::Function');
  if (fns.length !== 1) return false;
  const vars =
    (fns[0][1].Properties?.Environment as { Variables?: Record<string, unknown> } | undefined)
      ?.Variables ?? {};
  if (vars.BROKER_VERIFY_KEYS_SECRET_ARN !== VERIFY_KEYS_ARN) return false;
  const secretStmts = airlockSecretsManagerStatements(channelsVerifyKeysTemplate);
  const verifyStmt = secretStmts.find((s) => resourceString(s).includes(VERIFY_KEYS_ARN));
  return (
    secretStmts.length === 2 &&
    verifyStmt !== undefined &&
    JSON.stringify(actionsOf(verifyStmt)) === JSON.stringify(['secretsmanager:GetSecretValue']) &&
    !resourceHasWildcard(verifyStmt.Resource)
  );
}

function channelsScreenModelArnsScoped(): boolean {
  // With channelsScreenModelArns declared, exactly one statement grants bedrock:InvokeModel, its
  // resources are exactly the declared ARNs (no widening, no wildcard), and nothing else changes
  // about the bedrock surface.
  const bedrock = iamStatementsOf(channelsScreenedTemplate).filter((s) =>
    statementActions(s).some((a) => a.startsWith('bedrock:')),
  );
  if (bedrock.length !== 1) return false;
  const s = bedrock[0];
  if (statementActions(s).join(',') !== 'bedrock:InvokeModel') return false;
  const resources = Array.isArray(s.Resource) ? (s.Resource as string[]) : [s.Resource as string];
  return (
    resources.length === SCREEN_MODEL_ARNS.length &&
    SCREEN_MODEL_ARNS.every((arn) => resources.includes(arn))
  );
}

// ── checks: Channels drain worker (sa#155) ───────────────────────────────────────────────────────
function drainOffByDefault(): boolean {
  // No channelsDrainImageTag → no drain function, no event source mapping; only the drain ECR
  // repo (push-before-tag bringup) exists. The default template must synthesize exactly one
  // Lambda (the airlock).
  const fns = resourcesOfType(templates.channels, 'AWS::Lambda::Function');
  const mappings = resourcesOfType(templates.channels, 'AWS::Lambda::EventSourceMapping');
  const drainRepos = resourcesOfType(templates.channels, 'AWS::ECR::Repository').filter(([, r]) =>
    String(r.Properties?.RepositoryName ?? '').includes('channels-drain'),
  );
  return fns.length === 1 && mappings.length === 0 && drainRepos.length === 1;
}

function drainWiredWhenEnabled(): boolean {
  // With the tag set: a second Lambda exists, outside any VPC, arm64, 60 s, carrying the two
  // image-baked drain vars plus the broker backend posture (read-only grant load, store-loaded
  // envelope), consuming the accepted queue at batchSize 1 with partial-batch failures reported.
  const fns = resourcesOfType(channelsDrainTemplate, 'AWS::Lambda::Function');
  const drain = fns.find(
    ([, r]) => (r.Properties?.Timeout as number | undefined) === 60,
  );
  if (fns.length !== 2 || !drain) return false;
  const props = drain[1].Properties ?? {};
  if (props.VpcConfig !== undefined) return false;
  if (JSON.stringify(props.Architectures) !== JSON.stringify(['arm64'])) return false;
  const env = (props.Environment as { Variables?: Record<string, unknown> } | undefined)
    ?.Variables;
  if (
    env?.CHANNELS_DRAIN_MANIFEST !== DRAIN_MANIFEST_PATH ||
    env?.CHANNELS_DRAIN_RECEIVER !== DRAIN_RECEIVER ||
    env?.BROKER_STORE !== 'dynamo' ||
    env?.BROKER_GRANT_LOAD !== 'read' ||
    env?.BROKER_ENVELOPE_LOAD !== 'store'
  ) {
    return false;
  }
  const mappings = resourcesOfType(channelsDrainTemplate, 'AWS::Lambda::EventSourceMapping');
  if (mappings.length !== 1) return false;
  const m = mappings[0][1].Properties ?? {};
  return (
    m.BatchSize === 1 &&
    JSON.stringify(m.FunctionResponseTypes) === JSON.stringify(['ReportBatchItemFailures']) &&
    referencesLogicalId(m.FunctionName, drain[0])
  );
}

function drainConfigGuardThrows(): boolean {
  // channelsDrainImageTag without the manifest/receiver context keys must fail the SYNTH, not
  // deploy a drain that fails every invocation at runtime (channels/DRAIN.md D6).
  const badApp = new App({
    context: { environment: ENV, channelsDrainImageTag: 'drain-test-1' },
  });
  try {
    new ChannelsStack(badApp, stackName(ENV, 'Channels'), { environment: ENV });
    return false;
  } catch {
    return true;
  }
}

function drainFunction(): CfnResource | undefined {
  // The drain is the 60 s Lambda in the drain-enabled template (the airlock runs at a different
  // timeout); shared by the checks below.
  const fns = resourcesOfType(channelsDrainTemplate, 'AWS::Lambda::Function');
  return fns.find(([, r]) => (r.Properties?.Timeout as number | undefined) === 60)?.[1];
}

function drainHmacKeyFromSecretsManager(): boolean {
  // The drain must fetch the grant-integrity HMAC key at cold start from the same Secrets
  // Manager secret the broker service uses — a drain running the dev fallback key quarantines
  // every production-seeded grant under BROKER_GRANT_LOAD=read. Asserted: the ARN env points at
  // broker-hmac-key, an IAM statement grants GetSecretValue on that one secret, and NO env var
  // carries the key material itself (no secretsmanager dynamic reference anywhere in the env).
  const vars =
    (drainFunction()?.Properties?.Environment as
      | { Variables?: Record<string, unknown> }
      | undefined)?.Variables ?? {};
  const arnEnv = JSON.stringify(vars.BROKER_HMAC_KEY_SECRET_ARN ?? '');
  if (!arnEnv.includes('broker-hmac-key')) return false;
  if (JSON.stringify(vars).includes('{{resolve:secretsmanager')) return false;
  const hmacStatements = iamStatementsOf(channelsDrainTemplate).filter((s) =>
    JSON.stringify(s.Resource).includes('broker-hmac-key'),
  );
  return (
    hmacStatements.length === 1 &&
    JSON.stringify(hmacStatements[0].Action).includes('secretsmanager:GetSecretValue')
  );
}

function drainAuditChainIsolated(): boolean {
  // The drain's audit chain must never share the broker service's default 'audit/' prefix, and
  // only one drain runtime may resume it at a time (reserved concurrency 1) — otherwise two
  // writers fork the tamper-evident chain.
  const props = drainFunction()?.Properties ?? {};
  const vars = (props.Environment as { Variables?: Record<string, unknown> } | undefined)
    ?.Variables;
  return (
    vars?.BROKER_AUDIT_PREFIX === 'audit-drain/' && props.ReservedConcurrentExecutions === 1
  );
}

function drainLedgerWriteOnly(): boolean {
  // The drain role mirrors the brokerRole's ledger posture: PutObject ONLY on the ledger bucket
  // (append-only via IAM — no Get/List/Delete) plus GenerateDataKey+Encrypt on the ledger CMK.
  const statements = iamStatementsOf(channelsDrainTemplate);
  const ledgerPut = statements.find(
    (s) =>
      JSON.stringify(s.Resource).includes('ledger-bucket-arn') &&
      JSON.stringify(s.Action) === JSON.stringify('s3:PutObject'),
  );
  const ledgerKms = statements.find(
    (s) =>
      JSON.stringify(s.Resource).includes('ledger-key-arn') &&
      JSON.stringify(s.Action) === JSON.stringify(['kms:GenerateDataKey', 'kms:Encrypt']),
  );
  return ledgerPut !== undefined && ledgerKms !== undefined;
}

function drainSecretsScopedToEnv(): boolean {
  // The connector-secret statement is scoped to THIS environment's namespace
  // (secret:safe-agents/{env}/connectors/*) — never the cross-env 'secret:*/connectors/*'.
  // (Other GetSecretValue statements exist — e.g. the airlock's webhook secret — so this asserts
  // on connector-namespace statements specifically, plus a template-wide no-'secret:*' floor.)
  const statements = iamStatementsOf(channelsDrainTemplate);
  const connectorStatements = statements.filter((s) =>
    JSON.stringify(s.Resource).includes('/connectors/'),
  );
  return (
    connectorStatements.length >= 1 &&
    connectorStatements.every((s) =>
      JSON.stringify(s.Resource).includes(`secret:safe-agents/${ENV}/connectors/`),
    ) &&
    statements.every((s) => !JSON.stringify(s.Resource).includes('secret:*'))
  );
}

function drainQueueVisibilityCoversTimeout(): boolean {
  // Queue visibility must be >= the drain's 60 s timeout (6x per AWS guidance) or the event
  // source mapping is rejected at deploy. Asserted on the DEFAULT template too — the queue
  // exists before the drain does, and resizing visibility later would strand in-flight messages.
  return [templates.channels, channelsDrainTemplate].every((t) =>
    resourcesOfType(t, 'AWS::SQS::Queue').every(
      ([, r]) => r.Properties?.VisibilityTimeout === 360,
    ),
  );
}

function drainPhaseOneComboThrows(): boolean {
  // channelsDrainImageTag together with channelsDeployFunction=false must fail the synth: the
  // drain lives on the phase-2 path, and the combination would silently deploy no drain at all.
  const badApp = new App({
    context: {
      environment: ENV,
      channelsDeployFunction: false,
      channelsDrainImageTag: 'drain-test-1',
      channelsDrainManifestPath: DRAIN_MANIFEST_PATH,
      channelsDrainReceiver: DRAIN_RECEIVER,
    },
  });
  try {
    new ChannelsStack(badApp, stackName(ENV, 'Channels'), { environment: ENV });
    return false;
  } catch {
    return true;
  }
}

function drainNoWildcardResource(): boolean {
  // The drain role's authority is entirely ARN-scoped (the connector-secret namespace prefix is
  // a scoped prefix pattern, not '*') — the airlock's no-wildcard invariant holds with the drain on.
  const statements = iamStatementsOf(channelsDrainTemplate);
  return statements.length >= 1 && statements.every((s) => !resourceHasWildcard(s.Resource));
}

function airlockStageHasExplicitThrottle(): boolean {
  // Exactly one stage, and it carries explicit route throttling (10 rps / 20 burst) rather than
  // relying on the account default.
  const stages = channelsResourcesOfType('AWS::ApiGatewayV2::Stage');
  if (stages.length !== 1) return false;
  const drs = stages[0][1].Properties?.DefaultRouteSettings as
    | { ThrottlingRateLimit?: number; ThrottlingBurstLimit?: number }
    | undefined;
  return drs?.ThrottlingRateLimit === 10 && drs?.ThrottlingBurstLimit === 20;
}

function airlockHasSingleInboundRoute(): boolean {
  const routes = channelsResourcesOfType('AWS::ApiGatewayV2::Route');
  return routes.length === 1 && routes[0][1].Properties?.RouteKey === 'POST /inbound';
}

function acceptedQueueHasSse(): boolean {
  const queues = channelsResourcesOfType('AWS::SQS::Queue');
  return queues.length === 1 && queues[0][1].Properties?.SqsManagedSseEnabled === true;
}

function dedupeTableCmkWithTtl(): boolean {
  // The dedupe table lives in StateStack: CMK-encrypted (SSEType KMS + a key) and TTL on `ttl`.
  const table = resourcesOfType(templates.state, 'AWS::DynamoDB::Table').find(
    ([, r]) => r.Properties?.TableName === `safe-agents-${ENV}-channel-dedupe`,
  );
  if (!table) return false;
  const p = table[1].Properties ?? {};
  const sse = (p.SSESpecification ?? {}) as {
    SSEEnabled?: boolean;
    SSEType?: string;
    KMSMasterKeyId?: unknown;
  };
  const ttl = (p.TimeToLiveSpecification ?? {}) as { AttributeName?: string; Enabled?: boolean };
  return (
    sse.SSEEnabled === true &&
    sse.SSEType === 'KMS' &&
    sse.KMSMasterKeyId !== undefined &&
    ttl.AttributeName === 'ttl' &&
    ttl.Enabled === true
  );
}

function channelsNoFnHasNoLambdaOrApi(): boolean {
  // The first-phase (channelsDeployFunction=false) template lays down repo + queue + secret only —
  // no function and no API can exist before the image does.
  const fns = resourcesOfType(channelsNoFnTemplate, 'AWS::Lambda::Function');
  const apis = resourcesOfType(channelsNoFnTemplate, 'AWS::ApiGatewayV2::Api');
  return fns.length === 0 && apis.length === 0;
}

const ALWAYS_ON_CHANNELS_ENV = [
  'CHANNELS_DEDUPE_TABLE',
  'CHANNELS_DROP_BUCKET',
  'CHANNELS_DROP_PREFIX',
  'CHANNELS_ACCEPTED_QUEUE_URL',
  'CHANNELS_WEBHOOK_SECRET_ARN',
];

function airlockEnvHasAlwaysOnAndNoManifest(): boolean {
  // The five always-on CHANNELS_* vars are set; CHANNELS_MANIFEST is absent (no channelsManifestPath
  // context here — the base image bakes nothing in).
  const fns = channelsResourcesOfType('AWS::Lambda::Function');
  if (fns.length !== 1) return false;
  const envBlock = fns[0][1].Properties?.Environment as
    | { Variables?: Record<string, unknown> }
    | undefined;
  const vars = envBlock?.Variables ?? {};
  return ALWAYS_ON_CHANNELS_ENV.every((k) => k in vars) && !('CHANNELS_MANIFEST' in vars);
}

function airlockErrorAlarmsWired(): boolean {
  // sa#153 — the two silent-failure log events (handler_error / screen_error) each carry a metric
  // filter and an alarm; the alarms notify the one SNS alert topic and treat missing data as
  // notBreaching (no data = no failures, not an alarm).
  const filters = channelsResourcesOfType('AWS::Logs::MetricFilter');
  const alarms = channelsResourcesOfType('AWS::CloudWatch::Alarm');
  const topics = channelsResourcesOfType('AWS::SNS::Topic');
  if (filters.length !== 2 || alarms.length !== 2 || topics.length !== 1) return false;
  const patterns = filters.map(([, r]) => r.Properties?.FilterPattern as string);
  const bothEvents = ['handler_error', 'screen_error'].every((e) =>
    patterns.some((p) => typeof p === 'string' && p.includes(e)),
  );
  return (
    bothEvents &&
    alarms.every(([, r]) => {
      const p = r.Properties ?? {};
      const actions = (p.AlarmActions ?? []) as { Ref?: string }[];
      return (
        p.TreatMissingData === 'notBreaching' &&
        actions.length === 1 &&
        typeof actions[0]?.Ref === 'string' &&
        actions[0].Ref === topics[0][0]
      );
    })
  );
}

function channelsNoFnHasNoAlarms(): boolean {
  // The phase-1 (channelsDeployFunction=false) template has no function, hence no log group and no
  // alarm surface — alarms on a stack with nothing to fail would be noise.
  return (
    resourcesOfType(channelsNoFnTemplate, 'AWS::Logs::MetricFilter').length === 0 &&
    resourcesOfType(channelsNoFnTemplate, 'AWS::CloudWatch::Alarm').length === 0 &&
    resourcesOfType(channelsNoFnTemplate, 'AWS::SNS::Topic').length === 0
  );
}

function channelsExportsPresent(): boolean {
  const names = exportNames(templates.channels);
  return [
    'channel-accepted-queue-url',
    'channel-accepted-queue-arn',
    'airlock-ecr-uri',
    'channels-webhook-secret-arn',
    'airlock-url',
    'channels-airlock-alerts-topic-arn',
  ]
    .map((k) => `safe-agents-${ENV}-${k}`)
    .every((n) => names.has(n));
}

// ── checks: Compute per-capability IAM scoping (sa#175) ─────────────────────────────────────────
function computeCapabilityRolesOfType(tmpl: CfnTemplate, type: string): [string, CfnResource][] {
  return resourcesOfType(tmpl, type);
}

function capabilityNoRoleByDefault(): boolean {
  // ComputeStack's default synth already has CDK's auto-created Fargate task-execution role, so
  // assert the absence of the DECLARED capability role specifically, by name, rather than a raw
  // IAM::Role count of zero.
  const roles = computeCapabilityRolesOfType(computeDefaultTemplate, 'AWS::IAM::Role');
  return !roles.some(([, r]) => r.Properties?.RoleName === CAPABILITY_SPEC.roleName);
}

function capabilityNoAssumeRoleGrantByDefault(): boolean {
  // Stronger than "no sts:AssumeRole": the default (no capabilityRoles context) must import the
  // broker role IMMUTABLE, so CDK attaches NO inline policy to it at all — not the #175 assume
  // grant, and not the ECS-managed logs/ssmmessages task-role policy that an immutable import
  // silently drops. So assert there is no broker-role Policy resource whatsoever in the default
  // template (a regression guard for the conditional-mutability flip).
  for (const [id, policy] of resourcesOfType(computeDefaultTemplate, 'AWS::IAM::Policy')) {
    if (id.startsWith('BrokerRole')) return false;
    const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
    for (const s of doc?.Statement ?? []) {
      if (actionsOf(s).includes('sts:AssumeRole')) return false;
    }
  }
  return true;
}

function capabilityRoleHasExactScope(): boolean {
  const roles = computeCapabilityRolesOfType(computeWithCapabilitiesTemplate, 'AWS::IAM::Role');
  const capRole = roles.find(([, r]) => r.Properties?.RoleName === CAPABILITY_SPEC.roleName);
  if (!capRole) return false;
  const [id] = capRole;
  const stmts: Statement[] = [];
  for (const [, policy] of resourcesOfType(computeWithCapabilitiesTemplate, 'AWS::IAM::Policy')) {
    const roles2 = (policy.Properties?.Roles ?? []) as unknown[];
    if (roles2.some((r) => refId(r) === id)) {
      const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
      for (const s of doc?.Statement ?? []) stmts.push(s);
    }
  }
  // Exactly one statement: exactly the declared action, on exactly the declared resource — no
  // s3:*, no Resource: '*'.
  return (
    stmts.length === 1 &&
    stmts[0].Effect === 'Allow' &&
    actionsOf(stmts[0]).length === 1 &&
    actionsOf(stmts[0])[0] === CAPABILITY_SPEC.actions[0] &&
    resourceString(stmts[0]) === JSON.stringify(CAPABILITY_SPEC.resources[0])
  );
}

function capabilityRoleTrustsOnlyBrokerRole(): boolean {
  const roles = computeCapabilityRolesOfType(computeWithCapabilitiesTemplate, 'AWS::IAM::Role');
  const capRole = roles.find(([, r]) => r.Properties?.RoleName === CAPABILITY_SPEC.roleName);
  if (!capRole) return false;
  const [, resource] = capRole;
  const doc = resource.Properties?.AssumeRolePolicyDocument as
    | { Statement?: TrustStatement[] }
    | undefined;
  const stmts = doc?.Statement ?? [];
  if (stmts.length !== 1) return false;
  const principal = stmts[0].Principal as { AWS?: unknown; Service?: unknown } | undefined;
  // Not a service principal (ecs-tasks.amazonaws.com etc), not '*' — an AWS-principal reference to
  // the broker role's arn (an Fn::ImportValue token at synth time, since ComputeStack imports it).
  return principal !== undefined && principal.Service === undefined && principal.AWS !== undefined;
}

function capabilityBrokerRoleGetsScopedAssumeRole(): boolean {
  const roles = computeCapabilityRolesOfType(computeWithCapabilitiesTemplate, 'AWS::IAM::Role');
  const capRole = roles.find(([, r]) => r.Properties?.RoleName === CAPABILITY_SPEC.roleName);
  if (!capRole) return false;
  const [capRoleId] = capRole;
  for (const [, policy] of resourcesOfType(computeWithCapabilitiesTemplate, 'AWS::IAM::Policy')) {
    const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
    for (const s of doc?.Statement ?? []) {
      if (!actionsOf(s).includes('sts:AssumeRole')) continue;
      const resourceJson = resourceString(s);
      // Scoped to the capability role's GetAtt Arn (never a literal '*').
      if (resourceJson.includes(capRoleId) && !resourceJson.includes('"*"')) return true;
    }
  }
  return false;
}

// ── checks: Compute client task (#42) ─────────────────────────────────────────────────────────
// The client task plays the agent, so its whole point is that it holds the agent's authority and
// nothing more: were it given a secret or the broker's role, the demonstration would show a broker
// deciding for a caller that could have acted without it. Located by FAMILY, not logical id, so a
// construct rename cannot make these vacuously pass on a missing resource (each throws instead).
const CLIENT_TASK_FAMILY = resourceName(ENV, 'client');

function clientTaskDef(): [string, CfnResource] {
  const found = resourcesOfType(computeDefaultTemplate, 'AWS::ECS::TaskDefinition').filter(
    ([, r]) => r.Properties?.Family === CLIENT_TASK_FAMILY,
  );
  if (found.length !== 1) {
    throw new Error(`expected one task definition with family ${CLIENT_TASK_FAMILY}, found ${found.length}`);
  }
  return found[0];
}

function clientTaskHasNoSecrets(): boolean {
  const [, taskDef] = clientTaskDef();
  const containers = (taskDef.Properties?.ContainerDefinitions ?? []) as Record<string, unknown>[];
  if (containers.length === 0) throw new Error('client task definition has no containers');
  for (const c of containers) {
    const secrets = (c.Secrets ?? []) as { Name?: string }[];
    if (secrets.length > 0) {
      throw new Error(`client container ${String(c.Name)} carries secrets: ${secrets.map((x) => x.Name).join(', ')}`);
    }
  }
  return true;
}

function clientTaskRoleIsAgentRole(): boolean {
  const [, taskDef] = clientTaskDef();
  const roleArn = JSON.stringify(taskDef.Properties?.TaskRoleArn);
  const agentImport = JSON.stringify({ 'Fn::ImportValue': exportName(ENV, 'agent-role-arn') });
  if (roleArn !== agentImport) {
    throw new Error(`client task role is ${roleArn}, expected the imported agent role ${agentImport}`);
  }
  return true;
}

function clientTaskIsNotAService(): boolean {
  const [clientId] = clientTaskDef();
  for (const [id, svc] of resourcesOfType(computeDefaultTemplate, 'AWS::ECS::Service')) {
    if (refId(svc.Properties?.TaskDefinition) === clientId) {
      throw new Error(`service ${id} runs the client task definition`);
    }
  }
  return true;
}

function clientExecutionRoleOnlyPullsAndLogs(): boolean {
  // The execution role is the one identity on this task that touches AWS before the container
  // starts, and a secret on the task definition would be fetched by it. So it must be the client's
  // own (never the broker's, which holds GetSecretValue on the HMAC key) and hold only ECR pull and
  // log writes, with no managed policy riding along.
  const [, taskDef] = clientTaskDef();
  const execArn = taskDef.Properties?.ExecutionRoleArn as { 'Fn::GetAtt'?: [string, string] } | undefined;
  const execRoleId = execArn?.['Fn::GetAtt']?.[0];
  if (!execRoleId) throw new Error(`client execution role is not a role in this stack: ${JSON.stringify(execArn)}`);
  const execRole = computeDefaultTemplate.Resources[execRoleId];
  if (execRole.Properties?.ManagedPolicyArns) {
    throw new Error(`client execution role carries managed policies: ${JSON.stringify(execRole.Properties.ManagedPolicyArns)}`);
  }
  let statements = 0;
  for (const [, policy] of resourcesOfType(computeDefaultTemplate, 'AWS::IAM::Policy')) {
    const roles = (policy.Properties?.Roles ?? []) as unknown[];
    if (!roles.some((r) => refId(r) === execRoleId)) continue;
    const doc = policy.Properties?.PolicyDocument as { Statement?: Statement[] } | undefined;
    for (const st of doc?.Statement ?? []) {
      statements += 1;
      const stray = actionsOf(st).filter((a) => !a.startsWith('ecr:') && !a.startsWith('logs:'));
      if (stray.length > 0) throw new Error(`client execution role grants ${stray.join(', ')}`);
    }
  }
  if (statements === 0) throw new Error('client execution role has no policy statements (cannot pull its image)');
  return true;
}

// ── the conformance table ──────────────────────────────────────────────────────────────────────
interface Row {
  id: string; // checklist reference
  group: string;
  desc: string;
  check: () => boolean;
}

const ROWS: Row[] = [
  // Network (#13) — invariant #2 made topological.
  {
    id: 'egress/agent-no-open',
    group: 'Network',
    desc: 'agent SG has no 0.0.0.0/0 (or ::/0) egress',
    check: agentSgHasNoOpenEgress,
  },
  {
    id: 'egress/agent-to-broker-only',
    group: 'Network',
    desc: 'agent SG egress targets only security groups or managed prefix lists (no open CIDR)',
    check: agentSgEgressTargetsBrokerSgOnly,
  },
  {
    id: 'egress/agent-subnet-isolated',
    group: 'Network',
    desc: 'agent subnets have no default route to NAT/IGW',
    check: agentSubnetsHaveNoDefaultRoute,
  },
  {
    id: 'all/descriptions-ascii',
    group: 'Network',
    desc: 'all resource descriptions are ASCII-only (EC2/IAM reject non-ASCII)',
    check: allDescriptionsAreAscii,
  },
  // VPC endpoints (#83) — confined-subnet private AWS access, no NAT/IGW.
  {
    id: 'endpoints/gateway',
    group: 'Network',
    desc: 'S3 and DynamoDB gateway endpoints exist (route-table-level; free)',
    check: gatewayEndpointsExist,
  },
  {
    id: 'endpoints/interface',
    group: 'Network',
    desc: 'ssm/ssmmessages/ec2messages/secretsmanager/kms interface endpoints exist',
    check: interfaceEndpointsExist,
  },
  {
    id: 'endpoints/sg-inbound',
    group: 'Network',
    desc: 'endpoint SG admits TCP 443 only from agent and broker SGs (no CIDR ingress)',
    check: endpointSgAdmits443OnlyFromAgentAndBroker,
  },
  {
    id: 'endpoints/agent-gateway-egress',
    group: 'Network',
    desc: 'agent SG has two TCP 443 prefix-list egress rules (S3 + DynamoDB, no raw CIDR)',
    check: agentSgHasGatewayPrefixListEgress,
  },
  {
    id: 'network/secure-no-open-ingress',
    group: 'Network',
    desc: 'secure mode: no SG admits 0.0.0.0/0 (or ::/0) inbound',
    check: () => hasNoOpenIngress(templates.network),
  },
  {
    id: 'network/secure-outputs',
    group: 'Network',
    desc: 'secure mode publishes the six network outputs + network-mode',
    check: () => networkOutputsPresent(templates.network),
  },
  {
    id: 'network/secure-mode-value',
    group: 'Network',
    desc: "secure mode's network-mode output is 'secure'",
    check: () => networkModeOutputValue(templates.network) === 'secure',
  },
  // Open network mode (cost guard) — the flag=false topology trades network-layer egress containment
  // for the NAT + interface-endpoint spend; ingress stays default-deny and the outputs are identical.
  {
    id: 'open/no-nat',
    group: 'Open Network',
    desc: 'open mode has zero NAT gateways',
    check: openNetworkHasNoNatGateway,
  },
  {
    id: 'open/no-interface-endpoints',
    group: 'Open Network',
    desc: 'open mode has zero interface endpoints (gateway endpoints still present)',
    check: openNetworkHasNoInterfaceEndpoints,
  },
  {
    id: 'open/no-open-ingress',
    group: 'Open Network',
    desc: 'open mode: no SG admits 0.0.0.0/0 (or ::/0) inbound',
    check: () => hasNoOpenIngress(openNetworkTemplate),
  },
  {
    id: 'open/outputs',
    group: 'Open Network',
    desc: 'open mode publishes the same six network outputs + network-mode',
    check: () => networkOutputsPresent(openNetworkTemplate),
  },
  {
    id: 'open/mode-value',
    group: 'Open Network',
    desc: "open mode's network-mode output is 'open'",
    check: () => networkModeOutputValue(openNetworkTemplate) === 'open',
  },
  // State (#14) — durable, external, tamper-resistant.
  {
    id: 'state/six-tables',
    group: 'State',
    desc: 'grants/counters/intents/agent-runs + channel-dedupe + mcp-registry all present',
    check: sixDurableTables,
  },
  {
    id: 'state/mcp-registry-shape',
    group: 'State',
    desc: 'mcp-registry table (#174) mirrors grants: generic (pk,sk) key schema + the shared tablesKey CMK',
    check: mcpRegistryTableExistsWithGenericKeySchemaAndCmk,
  },
  {
    id: 'state/on-demand-pitr',
    group: 'State',
    desc: 'every table is PAY_PER_REQUEST with PITR enabled',
    check: allTablesOnDemandWithPitr,
  },
  {
    id: 'state/audit-worm-dev-no-retention',
    group: 'State',
    desc: 'audit bucket: Object Lock enabled but NO default retention in development (deliberate)',
    check: auditBucketLockEnabledWithoutRetentionInDev,
  },
  {
    id: 'state/audit-worm-prod-retention',
    group: 'State',
    desc: 'audit bucket: GOVERNANCE retention of 2557 days in production (the actual WORM property)',
    check: auditBucketHasGovernanceRetentionInProd,
  },
  {
    id: 'state/cmk-estate',
    group: 'State',
    desc: 'four customer-managed KMS keys (tables/audit/ledger/secrets)',
    check: fourCustomerManagedKeys,
  },
  {
    id: 'state/ledger-no-worm',
    group: 'State',
    desc: 'ledger bucket is versioned WITHOUT Object Lock (append-only via IAM, not WORM)',
    check: ledgerBucketVersionedWithoutWorm,
  },
  {
    id: 'state/exports',
    group: 'State',
    desc: 'table/bucket/key ARNs exported for IdentityStack',
    check: stateExportsPresent,
  },
  {
    id: 'state/dev-ephemeral',
    group: 'State',
    desc: 'development tables are DeletionPolicy:Delete (hands-off teardown)',
    check: developmentStateIsEphemeral,
  },
  {
    id: 'state/prod-durable',
    group: 'State',
    desc: 'production tables are DeletionPolicy:Retain (durable polarity)',
    check: productionStateIsDurable,
  },
  // Identity (#15) — invariants #1 and #3: the agent holds nothing; the broker is a separate
  // identity that cannot promote itself; only the grant-lifecycle roles write grants.
  {
    id: 'identity/four-roles',
    group: 'Identity',
    desc: 'agent/broker/promotion/demotion are four distinct boundary roles; watcher + campaign-watcher (sa#161) are the only additional roles (six total)',
    check: fourBoundaryRolesPlusWatcher,
  },
  {
    id: 'identity/agent-zero-authority',
    group: 'Identity',
    desc: 'agent role has no attached policy (zero AWS authority)',
    check: agentRoleHasZeroAuthority,
  },
  {
    id: 'identity/grants-writers',
    group: 'Identity',
    desc: 'only promotion + demotion write grants (not agent, not broker)',
    check: onlyPromotionAndDemotionWriteGrants,
  },
  {
    id: 'identity/secret-reader',
    group: 'Identity',
    desc: 'secret reads namespace-split: broker only */connectors/*, promotion only */issuer/*, demotion only */evaluator/*, agent none',
    check: secretReadsAreNamespaceSplit,
  },
  {
    id: 'identity/evaluator-signing-split',
    group: 'Identity',
    desc: 'the two signing identities are disjoint: demotion holds */evaluator/* and not */issuer/*, promotion+checker hold */issuer/* and not */evaluator/* (neither can mint the other\'s record type); watcher+auditor read BOTH PUBLIC verify-key params and sign nothing',
    check: evaluatorSigningIsSplitFromIssuer,
  },
  {
    id: 'identity/audit-immutable',
    group: 'Identity',
    desc: 'broker cannot delete audit objects (PutObject-only)',
    check: brokerCannotDeleteAudit,
  },
  {
    id: 'identity/ledger-append-only',
    group: 'Identity',
    desc: 'broker ledger-bucket statements grant s3:PutObject only (IAM-enforced append-only)',
    check: brokerLedgerIsPutObjectOnly,
  },
  {
    id: 'identity/mcp-registry-broker-read-only',
    group: 'Identity',
    desc: 'broker reads the mcp-registry table (#174) read-only (GetItem/Query only, no write verbs) — mirrors "the broker cannot write grants"',
    check: brokerRoleMcpRegistryIsReadOnly,
  },
  {
    id: 'identity/watcher-read-only',
    group: 'Identity',
    desc: 'watcher role (sa#140 + #62 audit + #194 verify-keys) is OIDC-assumed and read-only: {dynamodb:Query, dynamodb:Scan, dynamodb:GetItem, kms:Decrypt, ssm:GetParameter} only',
    check: watcherRoleIsReadOnly,
  },
  {
    id: 'identity/campaign-watcher-read-only',
    group: 'Identity',
    desc: 'campaign watcher role (sa#161) is OIDC-assumed and read-only: S3 scoped to channels/drops+verdicts, Logs scoped to broker+airlock groups, no secretsmanager/dynamodb/kms',
    check: campaignWatcherRoleIsReadOnly,
  },
  {
    id: 'identity/exports',
    group: 'Identity',
    desc: 'the six role ARNs are exported',
    check: identityExportsPresent,
  },
  // Standing checker role (#202) — OFF by default; when declared, topological maker≠checker.
  {
    id: 'identity/checker-off-by-default',
    group: 'Identity',
    desc: 'no CheckerRole in the default synth (checkerTrustedPrincipals context unset)',
    check: checkerRoleAbsentByDefault,
  },
  {
    id: 'identity/checker-trusts-named-principals',
    group: 'Identity',
    desc: 'gated CheckerRole trusts exactly the declared IAM principal ARNs (no service principals)',
    check: checkerRoleTrustsOnlyNamedPrincipals,
  },
  {
    id: 'identity/checker-ratify-shaped',
    group: 'Identity',
    desc: 'CheckerRole = grants r/w + tables CMK + */issuer/* secrets + secrets CMK, nothing else (no connectors, no counters)',
    check: checkerRoleIsRatifyShaped,
  },
  {
    id: 'identity/checker-additive',
    group: 'Identity',
    desc: 'the gated synth adds the checker (seven roles) without disturbing the six default roles',
    check: checkerVariantKeepsBoundaryRoles,
  },
  {
    id: 'identity/demotion-operator-off-by-default',
    group: 'Identity',
    desc: 'DemotionRole trust is service-principals-only in the default synth (demotionTrustedPrincipals unset)',
    check: demotionTrustServiceOnlyByDefault,
  },
  {
    id: 'identity/demotion-operator-trust-additive',
    group: 'Identity',
    desc: 'gated DemotionRole trust carries the service principals AND the named operator ARNs (deployment binding never displaced)',
    check: demotionGatedTrustIsAdditive,
  },
  {
    id: 'identity/demotion-operator-permissions-unchanged',
    group: 'Identity',
    desc: 'the demotion operator-trust gate changes TRUST only — policy statements identical to the default synth',
    check: demotionGatedPermissionsUnchanged,
  },
  {
    id: 'identity/demotion-operator-adds-no-roles',
    group: 'Identity',
    desc: 'the demotion gate mints no new identity — role count/names match the default synth',
    check: demotionGatedAddsNoRoles,
  },
  {
    id: 'identity/maker-auditor-off-by-default',
    group: 'Identity',
    desc: 'no MakerRole or AuditorRole in the default synth (operator contexts unset)',
    check: makerAuditorAbsentByDefault,
  },
  {
    id: 'identity/promotion-operator-off-by-default',
    group: 'Identity',
    desc: 'PromotionRole trust is service-principals-only in the default synth (promotionTrustedPrincipals unset)',
    check: promotionTrustServiceOnlyByDefault,
  },
  {
    id: 'identity/promotion-operator-trust-additive',
    group: 'Identity',
    desc: 'gated PromotionRole trust carries the service principals AND the named operator ARNs',
    check: promotionGatedTrustIsAdditive,
  },
  {
    id: 'identity/promotion-operator-permissions-unchanged',
    group: 'Identity',
    desc: 'the promotion operator-trust gate changes TRUST only — policy statements identical to the default synth',
    check: promotionGatedPermissionsUnchanged,
  },
  {
    id: 'identity/maker-trusts-named-principals',
    group: 'Identity',
    desc: 'gated MakerRole trusts exactly the declared IAM principal ARNs (no service principals)',
    check: makerRoleTrustsOnlyNamedPrincipals,
  },
  {
    id: 'identity/maker-propose-shaped',
    group: 'Identity',
    desc: 'MakerRole = grants read+conditional-UpdateItem + counters GetItem + tables CMK, nothing else (no PutItem, no secretsmanager at all)',
    check: makerRoleIsProposeShaped,
  },
  {
    id: 'identity/mcp-registry-maker-checker-no-putitem',
    group: 'Identity',
    desc: 'MakerRole and CheckerRole touch the mcp-registry table (#174) via conditional UpdateItem only — neither ever gets PutItem',
    check: makerCheckerMcpRegistryHasNoPutItem,
  },
  {
    id: 'identity/maker-cannot-mint-a-grant-row',
    group: 'Identity',
    desc: 'MakerRole UpdateItem is LeadingKeys-confined to PROPOSAL#/TOOLPROP# on both tables while its reads stay unconditioned (#203) — a GRANT#/TOOLDEF# upsert is refused by IAM, not by the store condition',
    check: makerCannotMintAGrantRow,
  },
  {
    id: 'identity/auditor-trusts-named-principals',
    group: 'Identity',
    desc: 'gated AuditorRole trusts exactly the declared IAM principal ARNs (no service principals)',
    check: auditorRoleTrustsOnlyNamedPrincipals,
  },
  {
    id: 'identity/auditor-readonly-plus-hmac',
    group: 'Identity',
    desc: 'AuditorRole is read-only (no ddb writes, no GenerateDataKey) and its only secret is the env-scoped broker HMAC key',
    check: auditorRoleIsReadOnlyPlusHmacKey,
  },
  {
    id: 'identity/operator-plane-composes',
    group: 'Identity',
    desc: 'all operator gates ON compose: 9 roles, boundary/watcher-role policies untouched',
    check: operatorPlaneComposes,
  },
  // Channels airlock (sa#152) — the untrusted-input edge: outside the VPC, one throttled route,
  // least-privilege role, CMK-encrypted dedupe state, and a clean two-phase-bringup skip.
  {
    id: 'channels/airlock-no-vpc',
    group: 'Channels',
    desc: 'airlock Lambda has no VpcConfig (external-facing, not agent egress)',
    check: airlockLambdaHasNoVpcConfig,
  },
  {
    id: 'channels/no-wildcard-resource',
    group: 'Channels',
    desc: 'no IAM policy statement in the stack uses Resource "*"',
    check: channelsNoWildcardResource,
  },
  {
    id: 'channels/stage-throttle',
    group: 'Channels',
    desc: 'HTTP API stage has explicit throttling (10 rps / 20 burst)',
    check: airlockStageHasExplicitThrottle,
  },
  {
    id: 'channels/single-route',
    group: 'Channels',
    desc: 'exactly one route and it is POST /inbound',
    check: airlockHasSingleInboundRoute,
  },
  {
    id: 'channels/queue-sse',
    group: 'Channels',
    desc: 'accepted-event queue has SSE-SQS encryption enabled',
    check: acceptedQueueHasSse,
  },
  {
    id: 'channels/dedupe-cmk-ttl',
    group: 'Channels',
    desc: 'dedupe table is CMK-encrypted with TTL enabled (in StateStack)',
    check: dedupeTableCmkWithTtl,
  },
  {
    id: 'channels/two-phase-skip',
    group: 'Channels',
    desc: 'channelsDeployFunction=false yields no Lambda function or API',
    check: channelsNoFnHasNoLambdaOrApi,
  },
  {
    id: 'channels/env-vars',
    group: 'Channels',
    desc: 'airlock env has the five always-on CHANNELS_* vars and no CHANNELS_MANIFEST',
    check: airlockEnvHasAlwaysOnAndNoManifest,
  },
  {
    id: 'channels/exports',
    group: 'Channels',
    desc: 'queue/ecr/secret/url exports are published',
    check: channelsExportsPresent,
  },
  {
    id: 'channels/no-bedrock-by-default',
    group: 'Channels',
    desc: 'screen ships OFF: the default role carries no bedrock action at all',
    check: channelsNoBedrockByDefault,
  },
  {
    id: 'channels/screen-model-arns-scoped',
    group: 'Channels',
    desc: 'channelsScreenModelArns grants bedrock:InvokeModel on exactly the declared ARNs',
    check: channelsScreenModelArnsScoped,
  },
  {
    id: 'channels/airlock-error-alarms',
    group: 'Channels',
    desc: 'handler_error + screen_error metric filters/alarms wired to the alert topic (sa#153)',
    check: airlockErrorAlarmsWired,
  },
  {
    id: 'channels/verify-keys-off-by-default',
    group: 'Channels',
    desc: 'no channelsVerifyKeysArn context: no BROKER_VERIFY_KEYS_SECRET_ARN env, exactly one secretsmanager statement (the webhook secret)',
    check: verifyKeysOffByDefault,
  },
  {
    id: 'channels/verify-keys-wired-when-set',
    group: 'Channels',
    desc: 'channelsVerifyKeysArn sets BROKER_VERIFY_KEYS_SECRET_ARN and grants exactly one scoped GetSecretValue statement on that ARN',
    check: verifyKeysWiredWhenSet,
  },
  // Channels drain worker (sa#155) — the accepted-queue → broker-turn binding.
  {
    id: 'channels/drain-off-by-default',
    group: 'Channels',
    desc: 'no channelsDrainImageTag → no drain Lambda or event source; only the drain ECR repo',
    check: drainOffByDefault,
  },
  {
    id: 'channels/drain-wired-when-enabled',
    group: 'Channels',
    desc: 'drain Lambda (no VPC, arm64, 60s, drain+broker env) consumes the accepted queue at batchSize 1 with ReportBatchItemFailures',
    check: drainWiredWhenEnabled,
  },
  {
    id: 'channels/drain-config-guard',
    group: 'Channels',
    desc: 'channelsDrainImageTag without manifest/receiver context fails the synth (DRAIN.md D6)',
    check: drainConfigGuardThrows,
  },
  {
    id: 'channels/drain-no-wildcard-resource',
    group: 'Channels',
    desc: 'with the drain enabled, no IAM policy statement uses Resource "*"',
    check: drainNoWildcardResource,
  },
  {
    id: 'channels/drain-hmac-from-secrets-manager',
    group: 'Channels',
    desc: 'drain fetches the HMAC key at cold start: BROKER_HMAC_KEY_SECRET_ARN env + scoped GetSecretValue, no key material in env',
    check: drainHmacKeyFromSecretsManager,
  },
  {
    id: 'channels/drain-audit-chain-isolated',
    group: 'Channels',
    desc: 'drain audit chain uses its own audit-drain/ prefix and reserved concurrency 1 (no chain forks)',
    check: drainAuditChainIsolated,
  },
  {
    id: 'channels/drain-ledger-write-only',
    group: 'Channels',
    desc: 'drain role carries the brokerRole ledger posture: s3:PutObject only + ledger-CMK encrypt',
    check: drainLedgerWriteOnly,
  },
  {
    id: 'channels/drain-secrets-env-scoped',
    group: 'Channels',
    desc: 'drain connector-secret IAM is scoped to secret:safe-agents/{env}/connectors/* (no cross-env wildcard)',
    check: drainSecretsScopedToEnv,
  },
  {
    id: 'channels/drain-queue-visibility',
    group: 'Channels',
    desc: 'accepted queue visibility is 360s (>= 6x the drain 60s timeout, required by the event source)',
    check: drainQueueVisibilityCoversTimeout,
  },
  {
    id: 'channels/drain-phase1-combo-throws',
    group: 'Channels',
    desc: 'channelsDrainImageTag with channelsDeployFunction=false fails the synth (no silent no-op)',
    check: drainPhaseOneComboThrows,
  },
  {
    id: 'channels/alarm-two-phase-skip',
    group: 'Channels',
    desc: 'channelsDeployFunction=false yields no filters, alarms, or alert topic',
    check: channelsNoFnHasNoAlarms,
  },
  // Compute per-capability IAM scoping (sa#175)
  {
    id: 'compute/capability-no-role-by-default',
    group: 'Compute',
    desc: 'no capabilityRoles context yields no per-capability IAM role',
    check: capabilityNoRoleByDefault,
  },
  {
    id: 'compute/capability-no-assume-role-by-default',
    group: 'Compute',
    desc: 'no capabilityRoles context yields no sts:AssumeRole grant on the broker role',
    check: capabilityNoAssumeRoleGrantByDefault,
  },
  {
    id: 'compute/capability-role-exact-scope',
    group: 'Compute',
    desc: 'a declared capability role has exactly one statement: the declared action on the declared resource (no wildcards)',
    check: capabilityRoleHasExactScope,
  },
  {
    id: 'compute/capability-role-trusts-only-broker',
    group: 'Compute',
    desc: "a capability role's trust policy principal is the broker role ARN, not a service principal or '*'",
    check: capabilityRoleTrustsOnlyBrokerRole,
  },
  {
    id: 'compute/capability-broker-gets-scoped-assume-role',
    group: 'Compute',
    desc: 'the broker role gains sts:AssumeRole scoped to exactly the capability role (not Resource: *)',
    check: capabilityBrokerRoleGetsScopedAssumeRole,
  },
  // Compute client task (#42)
  {
    id: 'compute/client-task-no-secrets',
    group: 'Compute',
    desc: 'the client task definition injects no secrets',
    check: clientTaskHasNoSecrets,
  },
  {
    id: 'compute/client-task-role-is-agent-role',
    group: 'Compute',
    desc: "the client task's role is the imported zero-authority agent role, not the broker role",
    check: clientTaskRoleIsAgentRole,
  },
  {
    id: 'compute/client-task-not-a-service',
    group: 'Compute',
    desc: 'no ECS service runs the client task definition (it is run on demand with run-task)',
    check: clientTaskIsNotAService,
  },
  {
    id: 'compute/client-execution-role-pull-and-logs-only',
    group: 'Compute',
    desc: "the client's execution role is its own and grants only ECR pull and log writes",
    check: clientExecutionRoleOnlyPullsAndLogs,
  },
];

// ── runner ─────────────────────────────────────────────────────────────────────────────────────
let failures = 0;
let currentGroup = '';
for (const row of ROWS) {
  if (row.group !== currentGroup) {
    currentGroup = row.group;
    console.log(`\n${currentGroup}`);
  }
  let passed = false;
  let detail = '';
  try {
    passed = row.check();
  } catch (err) {
    detail = ` (${err instanceof Error ? err.message : String(err)})`;
  }
  if (!passed) failures += 1;
  console.log(`  ${passed ? 'PASS' : 'FAIL'}  ${row.id} — ${row.desc}${detail}`);
}

console.log(
  `\n${failures === 0 ? 'CONFORMANCE: ALL PASS' : `CONFORMANCE: ${failures} FAILURE(S)`} ` +
    `(${ROWS.length} checks)`,
);
process.exit(failures === 0 ? 0 : 1);
