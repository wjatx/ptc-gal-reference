import { Stack, Token } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import { Effect, PolicyStatement, Role } from 'aws-cdk-lib/aws-iam';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Secret as SmSecret } from 'aws-cdk-lib/aws-secretsmanager';
import { PrivateDnsNamespace } from 'aws-cdk-lib/aws-servicediscovery';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { Environment, isEphemeral, removalPolicyFor } from './environment';
import { NetworkModeStackProps } from './foundation-props';
import { importValue, publish, resourceName, ssmParameterName } from './naming';
import { CapabilityRoles, CapabilitySpec } from './capability-roles';

// valueFromLookup returns this sentinel prefix before the SSM lookup is cached (fresh synth / CI
// with no context). We swap in a syntactically valid placeholder so synth produces a well-formed
// template rather than an id CloudFormation would reject. See lookupNetworkId below.
const LOOKUP_DUMMY_PREFIX = 'dummy-value-for-';

/**
 * Resolve a NetworkStack output at SYNTH time via an SSM context lookup instead of Fn.importValue.
 *
 * Rationale: CloudFormation locks an export's value for as long as any stack imports it, which would
 * block the secure->open network cutover — you cannot change a subnet or SG id that Compute has
 * imported via Fn::ImportValue without first tearing down Compute. valueFromLookup resolves the id
 * to a concrete string during synth, so Compute holds NO CFN import lock on NetworkStack and the two
 * stacks can be rolled independently. It also lets us split the comma-joined subnet-ids in TS (the
 * value is concrete at synth) rather than with Fn.split + a fixed assumedLength.
 *
 * Before the value is cached, valueFromLookup returns `dummy-value-for-<param>`; we substitute a
 * valid placeholder so synth doesn't emit a malformed id.
 */
function lookupNetworkId(
  scope: Construct,
  env: Environment,
  key: string,
  placeholder: string,
): string {
  // A credential-less synth (CI's egress-snapshot job; any shell with no resolvable AWS
  // account) leaves the stack env-agnostic, and env-agnostic stacks cannot run context
  // providers at all — valueFromLookup aborts the whole synth with
  // StackAccountRegionNotSpecified instead of returning its dummy. Treat that case
  // exactly like a cold lookup cache and substitute the placeholder: the snapshot job
  // only parses the Network template, and a deploy always has a concrete account.
  if (Token.isUnresolved(Stack.of(scope).account)) {
    return placeholder;
  }
  const value = StringParameter.valueFromLookup(scope, ssmParameterName(env, key));
  return value.startsWith(LOOKUP_DUMMY_PREFIX) ? placeholder : value;
}

/**
 * ComputeStack — the AWS Fargate arm (sa#36 Phase B): the ECS substrate plus the persistent broker
 * ECS service. The broker holds the keys and is the sole egress path (invariants #1/#3); this stack
 * gives it a durable home on Fargate, discoverable by agents at `broker.safe-agents.local`.
 *
 * It owns NO state, NO identities, and NO network topology — those live in State (#14),
 * Identity (#15), and Network (#13). Everything is imported by the cross-stack export keys those
 * stacks publish (`naming.ts` convention), so this stack adds no wildcards and re-derives nothing.
 *
 * Gates on Network + State + Identity (dependency wired in the entrypoint):
 *   - Network → VPC, broker subnets, broker/endpoint SGs (where the task runs + how it reaches AWS)
 *   - State   → the grants/counters/intents tables + audit bucket (the broker's runtime stores)
 *   - Identity → brokerRole (the task role; the broker's separate IAM identity)
 *
 * Phase C (image push) and Phase D (real grant flow) consume this stack's exports.
 */
export class ComputeStack extends Stack {
  constructor(scope: Construct, id: string, props: NetworkModeStackProps) {
    super(scope, id, props);

    const env = props.environment;
    const secure = props.secureNetwork;

    // Two broker subnets (NetworkStack maxAzs=2, one broker subnet per AZ). Used to slice the AZ list
    // fromVpcAttributes needs to match against the looked-up subnet ids below.
    const BROKER_SUBNET_COUNT = 2;

    // Container ports — broker tool-call API + model proxy. Both served by the image's default
    // entrypoint (broker-entrypoint.sh runs the broker server AND the model-proxy in one container).
    const TOOL_API_PORT = 8080;
    const MODEL_PROXY_PORT = 8443;

    // Cloud Map private DNS zone; the broker registers as `broker` → broker.safe-agents.local.
    const NAMESPACE_NAME = 'safe-agents.local';
    const SERVICE_DISCOVERY_NAME = 'broker';

    // Secrets Manager id prefix, environment-namespaced like the rest of infra (so dev/staging/prod
    // secrets never collide in a shared account). BROKER_SECRET_PREFIX drives the connector secret
    // ids (github → `safe-agents/{env}/connectors/github`, still matched by brokerRole's
    // `*/connectors/*` grant); the HMAC key is injected via the execution role. Values are seeded
    // out of band (see prerequisites). Referenced by name only — never a literal.
    const SECRET_PREFIX = `safe-agents/${env}`;
    const HMAC_SECRET_NAME = `${SECRET_PREFIX}/broker-hmac-key`;

    // Optional context: -c brokerGrantClasses=github.whoami,alpaca.read — a development-bringup
    // harness knob (see the environment block below). Never bake a value in here.
    const grantClassesOverride = this.node.tryGetContext('brokerGrantClasses') as
      | string
      | undefined;

    // Optional context: -c brokerManifestPath=/app/agents/broker-manifest.yaml — the in-image
    // path of the CONSUMER's AgentManifest (the consumer-image-layer pattern: a consumer builds
    // FROM the base broker image, COPYs its manifests in, and points the broker at one here).
    // Unset, the broker falls back to its checked-in example manifest — fine for smoke/dev
    // bringups, never right for a real consumer's durable environment (wrong principal, wrong
    // connectors). Never bake a consumer path in here (base stays agent-agnostic, sa#139).
    const brokerManifestPath = this.node.tryGetContext('brokerManifestPath') as
      | string
      | undefined;

    // Optional context: -c capabilityRoles='[{"tool":"s3.read","roleName":"...","actions":[...],
    // "resources":[...]}]' — a JSON array of CapabilitySpec (either a JSON string, as CLI context
    // arrives, or an already-parsed array when passed programmatically). Each entry provisions one
    // per-capability IAM role (sa#175, the deploy half of the #173 `assumed_role` CredentialProvider
    // strategy): assumable ONLY by brokerRole, scoped to EXACTLY that entry's actions+resources.
    // Unset/empty = no roles created (this stack's default synth output is unchanged).
    const capabilityRolesCtx = this.node.tryGetContext('capabilityRoles') as
      | string
      | CapabilitySpec[]
      | undefined;
    const capabilities: CapabilitySpec[] =
      typeof capabilityRolesCtx === 'string'
        ? (JSON.parse(capabilityRolesCtx) as CapabilitySpec[])
        : (capabilityRolesCtx ?? []);

    // Optional context: -c reuseComputeArtifacts=true — reference the ECR repos and broker log
    // group by name instead of creating them. Needed when RE-creating this stack in a durable
    // (RETAIN-polarity) environment: the repos and log group survive stack deletion by design
    // (images are the deployment artifact; see removalPolicyFor), so a fresh CREATE collides on
    // their names. First-time bringup in a clean account leaves this off.
    const reuseArtifactsCtx = this.node.tryGetContext('reuseComputeArtifacts');
    const reuseArtifacts = reuseArtifactsCtx === true || reuseArtifactsCtx === 'true';

    // ── Import Network (synth-time SSM lookup, not Fn.importValue) ─────────────────────────────────
    // The broker runs in the broker subnets with the broker SG (agent→broker ingress + outbound) and
    // endpoint SG (HTTPS to interface endpoints) attached. In secure mode the broker subnets are
    // PRIVATE_WITH_EGRESS (NAT egress) and the task takes no public IP; in open mode they are PUBLIC
    // and the task needs a public IP to reach the internet via the IGW (no NAT). Both modes publish
    // the same broker-subnet-ids key, so the mode only changes which fromVpcAttributes slot the ids
    // fill and whether a public IP is assigned.
    //
    // These four ids come from valueFromLookup (see lookupNetworkId) rather than Fn.importValue so
    // Compute holds no CFN import lock that would block the secure↔open network cutover. The subnet
    // ids are concrete at synth, so we split them in TS.
    const vpcId = lookupNetworkId(this, env, 'vpc-id', 'vpc-0000000000000dead');
    const brokerSubnetIds = lookupNetworkId(
      this,
      env,
      'broker-subnet-ids',
      'subnet-00000000000000aa1,subnet-00000000000000aa2',
    ).split(',');

    // fromVpcAttributes only needs enough to place an ECS task: vpcId, the AZ list, and the broker
    // subnet ids. The AZ list must match the broker subnet count; the concrete AZ values are
    // irrelevant for ECS placement (Fargate uses the subnet ids directly), so slice the stack AZs to
    // the count. In secure mode the ids are private subnets; in open mode they are public subnets —
    // fill the matching slot so vpc.privateSubnets / vpc.publicSubnets returns them below.
    const vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', {
      vpcId,
      availabilityZones: Stack.of(this).availabilityZones.slice(0, BROKER_SUBNET_COUNT),
      ...(secure ? { privateSubnetIds: brokerSubnetIds } : { publicSubnetIds: brokerSubnetIds }),
    });
    const brokerSubnets = secure ? vpc.privateSubnets : vpc.publicSubnets;

    // mutable:false — these SGs are owned by NetworkStack; this stack only references them and must
    // not mutate their rules (the agent→broker / broker→endpoint topology is the invariant).
    const brokerSg = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      'BrokerSg',
      lookupNetworkId(this, env, 'broker-sg-id', 'sg-00000000000000bb1'),
      { mutable: false },
    );
    const endpointSg = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      'EndpointSg',
      lookupNetworkId(this, env, 'endpoint-sg-id', 'sg-00000000000000bb2'),
      { mutable: false },
    );

    // ── Import Identity ───────────────────────────────────────────────────────────────────────────
    // The task role IS the broker's separate IAM identity (brokerRole). Its baseline authority is
    // still defined once in IdentityStack (#15) — this stack never touches that.
    //
    // Mutability is CONDITIONAL on capabilities being declared. With mutable:true, CDK doesn't only
    // let us attach the #175 sts:AssumeRole grant — it ALSO attaches the ECS service's managed
    // logs/ssmmessages task-role policy it silently DROPS on an immutable imported role. So flipping
    // unconditionally would broaden the broker role even with no capabilityRoles context. Gating on
    // `capabilities.length > 0` keeps the default path importing the role immutable — byte-for-byte
    // the pre-#175 synth (no BrokerRolePolicy at all) — and only opts into mutability (and the
    // benign ECS exec/logging perms that ride along) when a consumer actually declares scoped roles.
    const brokerRole = Role.fromRoleArn(this, 'BrokerRole', importValue(env, 'broker-role-arn'), {
      mutable: capabilities.length > 0,
    });

    // ── Per-capability IAM roles (sa#175) ─────────────────────────────────────────────────────────
    // No-op when `capabilityRoles` context is unset (the default) — creates nothing and leaves
    // brokerRole's policy untouched. When set, each capability gets its own scoped role (trust side,
    // in the construct); the broker also needs the identity-side half of the assume-role grant,
    // added below, scoped to exactly the roles just created (never Resource: '*').
    const capabilityRoles = new CapabilityRoles(this, 'CapabilityRoles', {
      environment: env,
      brokerRole,
      capabilities,
    });
    const capabilityRoleArns = Object.values(capabilityRoles.roles).map((role) => role.roleArn);
    if (capabilityRoleArns.length > 0) {
      brokerRole.addToPrincipalPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['sts:AssumeRole'],
          resources: capabilityRoleArns,
        }),
      );
    }

    // ── ECR repository (broker image) ─────────────────────────────────────────────────────────────
    // Phase C pushes the broker image here; the service pulls `latest` from it. Lifecycle rule keeps
    // the last 10 images so the repo does not grow unbounded. emptyOnDelete cleans up in dev; only
    // used for ephemeral (development) environments where removal policy is DESTROY.
    const repo = reuseArtifacts
      ? ecr.Repository.fromRepositoryName(this, 'BrokerRepo', resourceName(env, 'broker'))
      : new ecr.Repository(this, 'BrokerRepo', {
          repositoryName: resourceName(env, 'broker'),
          imageScanOnPush: true,
          removalPolicy: removalPolicyFor(env),
          ...(isEphemeral(env) && { emptyOnDelete: true }),
          lifecycleRules: [{ maxImageCount: 10, description: 'Keep the last 10 broker images' }],
        });

    // ── ECR repository (agent image) ──────────────────────────────────────────────────────────────
    // The confined agent image (safe_agents/arms/fargate/Containerfile.agent, sa#36 C2a) is pushed here and
    // run as a task in the PRIVATE_ISOLATED subnet — same lifecycle/removal pattern as the broker repo.
    // emptyOnDelete cleans up in dev; only used for ephemeral (development) environments.
    const agentRepo = reuseArtifacts
      ? ecr.Repository.fromRepositoryName(this, 'AgentRepo', resourceName(env, 'agent'))
      : new ecr.Repository(this, 'AgentRepo', {
          repositoryName: resourceName(env, 'agent'),
          imageScanOnPush: true,
          removalPolicy: removalPolicyFor(env),
          ...(isEphemeral(env) && { emptyOnDelete: true }),
          lifecycleRules: [{ maxImageCount: 10, description: 'Keep the last 10 agent images' }],
        });

    // ── ECS cluster (Fargate) ─────────────────────────────────────────────────────────────────────
    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      clusterName: resourceName(env, 'cluster'),
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    // ── Cloud Map private DNS namespace ───────────────────────────────────────────────────────────
    const namespace = new PrivateDnsNamespace(this, 'Namespace', {
      name: NAMESPACE_NAME,
      vpc,
      description: `safe-agents ${env} - private service discovery (broker.${NAMESPACE_NAME})`,
    });

    // ── Log group ─────────────────────────────────────────────────────────────────────────────────
    const logGroup = reuseArtifacts
      ? LogGroup.fromLogGroupName(this, 'BrokerLogs', `/safe-agents/${env}/broker`)
      : new LogGroup(this, 'BrokerLogs', {
          logGroupName: `/safe-agents/${env}/broker`,
          retention: RetentionDays.TWO_WEEKS,
          removalPolicy: removalPolicyFor(env),
        });

    // ── Task definition (arm64) ───────────────────────────────────────────────────────────────────
    // arm64 matches the local broker image (sa#36); cpu 256 / mem 512 is the smallest Fargate size
    // and is ample for the broker's decision-and-proxy workload. Execution role is left to CDK: it
    // auto-creates one with AmazonECSTaskExecutionRolePolicy and grants ECR pull, log writes, and
    // GetSecretValue on the HMAC secret below — that is the standard ECS execution identity.
    const taskDef = new ecs.FargateTaskDefinition(this, 'BrokerTask', {
      cpu: 256,
      memoryLimitMiB: 512,
      taskRole: brokerRole,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    // HMAC key injected from Secrets Manager (referenced by name; value seeded out of band). Using
    // ecs.Secret grants the execution role GetSecretValue automatically.
    const hmacSecret = SmSecret.fromSecretNameV2(this, 'BrokerHmacKey', HMAC_SECRET_NAME);

    const container = taskDef.addContainer('broker', {
      // Default entrypoint (broker-entrypoint.sh) runs the broker server + model-proxy.
      image: ecs.ContainerImage.fromEcrRepository(repo, 'latest'),
      logging: ecs.LogDrivers.awsLogs({ logGroup, streamPrefix: 'broker' }),
      environment: {
        // AWS mode per safe_agents/arms/fargate/BROKER_ENV.md.
        BROKER_STORE: 'dynamo',
        BROKER_GRANTS_TABLE: importValue(env, 'grants-table-name'),
        MCP_REGISTRY_TABLE_NAME: importValue(env, 'mcp-registry-table-name'),
        BROKER_COUNTERS_TABLE: importValue(env, 'counters-table-name'),
        BROKER_INTENTS_TABLE: importValue(env, 'intents-table-name'),
        BROKER_AUDIT_BUCKET: importValue(env, 'audit-bucket-name'),
        BROKER_SECRETS: 'secretsmanager',
        BROKER_SECRET_PREFIX: SECRET_PREFIX,
        BROKER_HOST: '0.0.0.0',
        AWS_DEFAULT_REGION: this.region,
        // Flush stdout to CloudWatch line-by-line; Python block-buffers when piped, which would
        // otherwise hide the broker's startup backend lines + per-decision logs behind the buffer.
        PYTHONUNBUFFERED: '1',
        // brokerRole has READ-ONLY access to the grants table (IdentityStack #15), so the broker
        // READS pre-seeded grants rather than writing its own (the local arm's 'seed' mode). The
        // seed step (`python -m broker.prototype.seed_grants`, run out-of-band with write creds —
        // the promotion path's stand-in) MUST have populated the grants table first; a class whose
        // grant is absent/quarantined is omitted fail-closed. See safe_agents/arms/fargate/BROKER_ENV.md.
        BROKER_GRANT_LOAD: 'read',
        // The in-force risk envelope is LOADED from the DynamoDB envelope store (co-located in
        // the grants table), not the manifest — so a live envelope change is a store re-seed, not
        // an image rebuild (sa#136 Slice B). The envelope MUST be seeded out-of-band first
        // (`python -m broker.prototype.seed_envelope`, run BEFORE seed_grants so grants stamp the
        // matching envelope hash); a missing envelope fails the broker's boot fast, fail-closed —
        // the same posture BROKER_GRANT_LOAD='read' takes on a missing grant.
        BROKER_ENVELOPE_LOAD: 'store',
        // Optional harness override of the served action classes (broker_server.py's
        // BROKER_GRANT_CLASSES). Used by development bringups so the arm capstones' brokered
        // calls (e.g. github.whoami) are actually served; unset (the default, and always in
        // durable environments) = the broker's built-in principal defaults. Seed grants with the
        // SAME override or the extra classes quarantine-omit on read. Interim until sa#113 gives
        // the broker a real connector/grant injection path.
        ...(grantClassesOverride ? { BROKER_GRANT_CLASSES: grantClassesOverride } : {}),
        // The consumer's AgentManifest path inside the (consumer-layered) image — see the
        // brokerManifestPath context note above. Unset = the base image's example manifest.
        ...(brokerManifestPath ? { BROKER_MANIFEST: brokerManifestPath } : {}),
      },
      secrets: {
        BROKER_HMAC_KEY: ecs.Secret.fromSecretsManager(hmacSecret),
      },
    });
    container.addPortMappings(
      { containerPort: TOOL_API_PORT, protocol: ecs.Protocol.TCP },
      { containerPort: MODEL_PROXY_PORT, protocol: ecs.Protocol.TCP },
    );

    // ── Broker service ────────────────────────────────────────────────────────────────────────────
    // Placed in the broker subnets with the broker + endpoint SGs. Registers in Cloud Map so it
    // resolves at broker.safe-agents.local. Placement is mode-aware:
    //   secure: PRIVATE_WITH_EGRESS broker subnets, no public IP — egress is via NAT + VPC endpoints.
    //   open:   PUBLIC broker subnets, assignPublicIp true — the task reaches the internet (image
    //           pulls, connector hosts) through the IGW since there is no NAT and no endpoints.
    // desiredCount is context-driven so the first deploy can run at 0 (service created, no tasks →
    // stabilizes immediately) BEFORE the image + HMAC secret exist; then push the image and scale to
    // 1. circuitBreaker(rollback) makes a bad rollout fail fast instead of CloudFormation waiting
    // ~hours for a service that can never reach steady state.
    const desiredCount = Number(this.node.tryGetContext('brokerDesiredCount') ?? 1);
    new ecs.FargateService(this, 'BrokerService', {
      cluster,
      taskDefinition: taskDef,
      serviceName: resourceName(env, 'broker'),
      desiredCount,
      assignPublicIp: !secure,
      vpcSubnets: { subnets: brokerSubnets },
      securityGroups: [brokerSg, endpointSg],
      circuitBreaker: { rollback: true },
      enableExecuteCommand: true,
      cloudMapOptions: {
        name: SERVICE_DISCOVERY_NAME,
        cloudMapNamespace: namespace,
      },
    });

    // ── Cross-stack outputs ───────────────────────────────────────────────────────────────────────
    // Phase C (image push) + later arms consume these.
    publish(this, env, 'cluster-name', cluster.clusterName);
    publish(this, env, 'cluster-arn', cluster.clusterArn);
    publish(this, env, 'broker-service-dns', `${SERVICE_DISCOVERY_NAME}.${NAMESPACE_NAME}`);
    publish(this, env, 'ecr-broker-repo-uri', repo.repositoryUri);
    publish(this, env, 'ecr-broker-repo-name', repo.repositoryName);
    publish(this, env, 'ecr-agent-repo-uri', agentRepo.repositoryUri);
    publish(this, env, 'ecr-agent-repo-name', agentRepo.repositoryName);
    publish(this, env, 'cloudmap-namespace-name', namespace.namespaceName);
  }
}
