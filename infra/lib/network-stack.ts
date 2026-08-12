import { Fn, Stack, Token } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';
import { NetworkModeStackProps } from './foundation-props';
import { publish } from './naming';

/**
 * NetworkStack — VPC, subnets, route tables, security groups, NAT: the *topological* half of
 * invariant #2 ("agent egress = broker only").
 *
 * The stack builds one of two topologies, selected by `props.secureNetwork` (sa#… network-flag),
 * and publishes the SAME six outputs either way so ComputeStack consumes it identically:
 *
 *   secure (flag true) — the confined topology and the original sa#13 behaviour, EXACTLY unchanged:
 *     an isolated agent subnet with no default route, one NAT gateway for the broker's egress, and
 *     interface endpoints for private AWS access. Agent egress is contained at the subnet + SG layer,
 *     independent of any code-level guard.
 *
 *   open (flag false, the default) — a flat two-group public VPC with NO NAT and NO interface
 *     endpoints. This trades away the network-layer half of invariant #2: egress containment falls
 *     back entirely to the broker's code/credential layer (the agent still holds no connector creds
 *     and its only *useful* egress is the broker). Ingress stays default-deny in BOTH modes — no SG
 *     ever opens 0.0.0.0/0 inbound. Open mode drops the ~$375/mo NAT + interface-endpoint spend; use
 *     it wherever the code/credential layer alone is an acceptable containment floor.
 *
 * The S3 + DynamoDB gateway endpoints (free, route-table-level) are kept in both modes.
 * Parallelizable with StateStack — no dependency between them.
 */
export class NetworkStack extends Stack {
  constructor(scope: Construct, id: string, props: NetworkModeStackProps) {
    super(scope, id, props);

    const secure = props.secureNetwork;

    // ── VPC ─────────────────────────────────────────────────────────────────────────────────────
    // secure: agent subnets (PRIVATE_ISOLATED — no NAT/IGW default route) + broker subnets
    // (PRIVATE_WITH_EGRESS — NAT egress to connector hosts). One NAT gateway to minimise cost. A
    // PUBLIC subnet group is required to host the NAT gateway whenever subnetConfiguration is given
    // explicitly (CDK only auto-adds it under the default config). No workload runs there; the agent
    // subnet stays isolated with no route to it.
    //
    // open: two PUBLIC subnet groups named 'agent' and 'broker' (keeping the published subnet-id
    // semantics), cidrMask 24 each, natGateways 0. No isolated subnet, no NAT — tasks reach the
    // internet directly through the IGW. The 'agent'/'broker' names are preserved so the outputs and
    // ComputeStack's group-based selection work identically across modes.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: secure ? 1 : 0,
      subnetConfiguration: secure
        ? [
            {
              // Hosts the NAT gateway only — no agent or broker workload here.
              name: 'public',
              subnetType: ec2.SubnetType.PUBLIC,
              cidrMask: 26,
            },
            {
              // Agent runs here. The route table has NO default route — outbound egress is physically
              // impossible at the subnet layer without a matching security-group rule to the broker.
              name: 'agent',
              subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
              cidrMask: 24,
            },
            {
              // Broker runs here. Routes through the NAT gateway to reach external connector hosts.
              name: 'broker',
              subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
              cidrMask: 24,
            },
          ]
        : [
            // Open mode: agent + broker both public, no NAT. Same group names so the subnet-id
            // outputs keep their meaning; the workloads get IGW egress and public IPs.
            { name: 'agent', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
            { name: 'broker', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
          ],
    });

    // ── Security groups (all three exist in BOTH modes) ─────────────────────────────────────────
    // The SGs are free and the outputs must exist regardless of mode, so both topologies create all
    // three. Ingress is default-deny in both modes — no SG ever admits 0.0.0.0/0.

    // Broker SG: accepts traffic from the agent SG; full outbound (to connector hosts via NAT in
    // secure mode, directly via the IGW in open mode). Identical construction in both modes.
    const brokerSg = new ec2.SecurityGroup(this, 'BrokerSg', {
      vpc,
      description: 'Broker SG - inbound from agent SG; outbound to connector hosts via NAT',
      allowAllOutbound: true,
    });

    // Agent SG.
    //   secure: allowAllOutbound false eliminates the implicit 0.0.0.0/0 egress rule; the only egress
    //           that exists is the explicit rule to the broker SG below (invariant #2).
    //   open:   allowAllOutbound true — no broker-only / prefix-list egress rules. Network-layer
    //           egress containment is intentionally traded away; the broker's code/credential layer is
    //           the containment floor. (No ingress in either mode.)
    const agentSg = new ec2.SecurityGroup(this, 'AgentSg', {
      vpc,
      description: secure
        ? 'Agent SG - egress to broker SG only; no default egress (invariant #2)'
        : 'Agent SG - open mode; allow-all egress (network-layer containment traded to the broker)',
      allowAllOutbound: !secure,
    });

    // Broker ← agent ingress, expressed as a standalone rule resource rather than an inline SG
    // property. Inline cross-references (agent egress → broker AND broker ingress ← agent) make the
    // two SGs mutually dependent, which CloudFormation rejects as a dependency cycle (cdk synth
    // tolerates it; deploy and Template.fromStack do not). A standalone Ingress resource depends on
    // both SGs without either SG depending on the other, breaking the cycle. Present in both modes so
    // the broker still admits the agent regardless of the agent SG's egress posture.
    new ec2.CfnSecurityGroupIngress(this, 'BrokerFromAgentIngress', {
      groupId: brokerSg.securityGroupId,
      ipProtocol: '-1',
      sourceSecurityGroupId: agentSg.securityGroupId,
      description: 'Broker ingress from agent SG',
    });

    // Endpoint SG: interface endpoint ENIs accept HTTPS from the agent and broker SGs only.
    // allowAllOutbound: false — VPC endpoints are stateful; they respond on the same connection so no
    // explicit outbound rule is required. In open mode there are no interface endpoints, so this SG is
    // an unused (but free) resource kept so the endpoint-sg-id output still resolves; its SG-scoped
    // ingress rules are harmless with nothing attached.
    const endpointSg = new ec2.SecurityGroup(this, 'EndpointSg', {
      vpc,
      description: 'Endpoint SG - HTTPS inbound from agent and broker SGs only',
      allowAllOutbound: false,
    });
    // Standalone CfnSecurityGroupIngress (matching the agent/broker pattern) avoids CDK's
    // connections-graph cycle detection, which would otherwise add an unwanted VPC-CIDR fallback rule
    // in addition to the SG-scoped rules.
    new ec2.CfnSecurityGroupIngress(this, 'EndpointFromAgentIngress', {
      groupId: endpointSg.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 443,
      toPort: 443,
      sourceSecurityGroupId: agentSg.securityGroupId,
      description: 'HTTPS from agent SG',
    });
    new ec2.CfnSecurityGroupIngress(this, 'EndpointFromBrokerIngress', {
      groupId: endpointSg.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 443,
      toPort: 443,
      sourceSecurityGroupId: brokerSg.securityGroupId,
      description: 'HTTPS from broker SG',
    });

    // ── S3 + DynamoDB gateway endpoints (free; both modes) ──────────────────────────────────────
    // Gateway endpoints work at the route-table level: they inject prefix-list routes into the
    // specified route tables rather than a default route, so the secure agent subnet's no-default-
    // route invariant (#2) is preserved. They cost nothing, so both modes keep them.
    //   secure: injected into the isolated (agent) + NAT (broker) route tables so all subnets avoid
    //           the NAT gateway for S3/DynamoDB traffic.
    //   open:   injected into the public subnet route tables.
    const gatewaySubnets: ec2.SubnetSelection[] = secure
      ? [
          { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
          { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        ]
      : [{ subnetType: ec2.SubnetType.PUBLIC }];
    vpc.addGatewayEndpoint('S3GatewayEndpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: gatewaySubnets,
    });
    vpc.addGatewayEndpoint('DynamoDbGatewayEndpoint', {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
      subnets: gatewaySubnets,
    });

    if (secure) {
      // ── Secure-only: SG egress rules + interface endpoints (sa#83) ────────────────────────────

      // Agent → broker, standalone rule (same cycle-breaking rationale as BrokerFromAgentIngress).
      new ec2.CfnSecurityGroupEgress(this, 'AgentToBrokerEgress', {
        groupId: agentSg.securityGroupId,
        ipProtocol: '-1', // all traffic; the broker decides which ports it exposes
        destinationSecurityGroupId: brokerSg.securityGroupId,
        description: 'Agent egress to broker SG only (invariant #2)',
      });

      // Agent SG egress to the S3 and DynamoDB gateway-endpoint managed prefix lists (TCP 443).
      // IMPORTANT: gateway-endpoint traffic IS also subject to security-group egress evaluation. The
      // route-table injection alone is not enough — without these rules, packets matching the gateway
      // prefix-list route are dropped by the agent SG before reaching the endpoint (the live bug that
      // triggered sa#83). Open mode does not need them: the agent SG is allowAllOutbound there.
      //
      // AWS-managed gateway-endpoint prefix lists (com.amazonaws.<region>.s3 / .dynamodb) are stable,
      // AWS-owned, and region-specific. We map them by region rather than resolving at deploy time:
      // AWS::EC2::VPCEndpoint exposes no PrefixListId attribute (getAtt fails), and a DescribeManaged-
      // PrefixLists AwsCustomResource proved brittle (Invalid PhysicalResourceId / response-field
      // extraction). A static map is deterministic and deploy-safe. Add a region by running:
      //   aws ec2 describe-managed-prefix-lists \
      //     --filters Name=prefix-list-name,Values=com.amazonaws.<region>.s3,com.amazonaws.<region>.dynamodb
      const GATEWAY_PREFIX_LISTS: Record<string, { s3: string; dynamodb: string }> = {
        'us-east-1': { s3: 'pl-63a5400a', dynamodb: 'pl-02cd2c6b' },
      };
      const region = Stack.of(this).region;
      // Resolved + mapped → use it. Unresolved (environment-agnostic synth, e.g. the conformance
      // test) → fall back to us-east-1 so synth/tests work. Resolved + unmapped → fail fast.
      const prefixLists =
        GATEWAY_PREFIX_LISTS[region] ??
        (Token.isUnresolved(region) ? GATEWAY_PREFIX_LISTS['us-east-1'] : undefined);
      if (!prefixLists) {
        throw new Error(
          `No S3/DynamoDB managed prefix-list IDs mapped for region '${region}'. ` +
            'Add it to GATEWAY_PREFIX_LISTS (see the describe-managed-prefix-lists command above).',
        );
      }

      new ec2.CfnSecurityGroupEgress(this, 'AgentToS3GatewayEgress', {
        groupId: agentSg.securityGroupId,
        ipProtocol: 'tcp',
        fromPort: 443,
        toPort: 443,
        destinationPrefixListId: prefixLists.s3,
        description: 'Agent egress to S3 gateway endpoint prefix list (TCP 443)',
      });
      new ec2.CfnSecurityGroupEgress(this, 'AgentToDynamoDbGatewayEgress', {
        groupId: agentSg.securityGroupId,
        ipProtocol: 'tcp',
        fromPort: 443,
        toPort: 443,
        destinationPrefixListId: prefixLists.dynamodb,
        description: 'Agent egress to DynamoDB gateway endpoint prefix list (TCP 443)',
      });

      // Agent needs an explicit 443 egress to the endpoint SG so it can reach the interface endpoint
      // ENIs. Standalone resource avoids an inline cross-reference that would cycle with endpointSg.
      new ec2.CfnSecurityGroupEgress(this, 'AgentToEndpointEgress', {
        groupId: agentSg.securityGroupId,
        ipProtocol: 'tcp',
        fromPort: 443,
        toPort: 443,
        destinationSecurityGroupId: endpointSg.securityGroupId,
        description: 'Agent egress to VPC endpoint SG for private AWS API access',
      });

      // Interface endpoints — ENIs placed in the agent (isolated) subnets. Private DNS is enabled by
      // default so AWS SDK calls resolve to the private ENI IP without any app-level change. The
      // broker subnets reach these endpoints via the VPC local route + private DNS.
      //
      // open: false suppresses CDK's automatic VPC-CIDR ingress rule on the endpoint SG (the default
      // open:true behavior adds "allow all VPC traffic" inline, which is broader than we want). The
      // two explicit CfnSecurityGroupIngress rules above are the only ingress allowed.
      const endpointSubnets: ec2.SubnetSelection = {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      };
      const ifaceEndpointProps = {
        vpc,
        securityGroups: [endpointSg],
        subnets: endpointSubnets,
        open: false,
      };

      // SSM, SSM Messages, EC2 Messages — required for SSM Session Manager and EC2 instance
      // management on hosts in the isolated subnet (smoke tests, runbooks).
      new ec2.InterfaceVpcEndpoint(this, 'SsmEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.SSM,
      });
      new ec2.InterfaceVpcEndpoint(this, 'SsmMessagesEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      });
      new ec2.InterfaceVpcEndpoint(this, 'Ec2MessagesEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      });

      // Secrets Manager — broker reads connector secrets. KMS — envelope decryption for those
      // secrets and for DynamoDB/S3 customer-managed keys.
      new ec2.InterfaceVpcEndpoint(this, 'SecretsManagerEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      });
      new ec2.InterfaceVpcEndpoint(this, 'KmsEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.KMS,
      });

      // ECR — for pulling agent/broker container images from ECR in the isolated subnet.
      new ec2.InterfaceVpcEndpoint(this, 'EcrApiEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.ECR,
      });
      new ec2.InterfaceVpcEndpoint(this, 'EcrDkrEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
      });

      // CloudWatch Logs — the agent task runs in the PRIVATE_ISOLATED subnet (no NAT), so its
      // awslogs driver can only reach CloudWatch through this endpoint. Without it the task fails at
      // init ("cannot find the log group / connection issue"). The broker doesn't need it (it runs in
      // the NAT subnet), but the confined agent does.
      new ec2.InterfaceVpcEndpoint(this, 'CloudWatchLogsEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      });

      // SQS — the ec2-woken box drains its inbound queue from the isolated agent subnet (no NAT), so
      // it reaches SQS through this interface endpoint. The airlock guardrail (in Lambda, outside the
      // VPC) still enqueues over the public SQS API; this endpoint is for the in-VPC box.
      new ec2.InterfaceVpcEndpoint(this, 'SqsEndpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.SQS,
      });

      // EC2 API — the ec2-woken box self-stops (ec2:StopInstances on itself) when its queue is
      // drained. From the no-NAT isolated subnet that EC2 API call needs this interface endpoint.
      new ec2.InterfaceVpcEndpoint(this, 'Ec2Endpoint', {
        ...ifaceEndpointProps,
        service: ec2.InterfaceVpcEndpointAwsService.EC2,
      });
    }

    // ── Outputs (identical six keys + network-mode in BOTH modes) ───────────────────────────────
    // Component stacks import without hardcoding resource IDs. In open mode the agent/broker subnet-id
    // outputs point at the (public) 'agent'/'broker' groups, keeping their meaning. The extra
    // network-mode output lets consumers (ComputeStack, runbooks) see which topology is deployed.
    const agentSubnets = secure
      ? vpc.isolatedSubnets
      : vpc.selectSubnets({ subnetGroupName: 'agent' }).subnets;
    const brokerSubnets = secure
      ? vpc.privateSubnets
      : vpc.selectSubnets({ subnetGroupName: 'broker' }).subnets;

    publish(this, props.environment, 'vpc-id', vpc.vpcId);
    publish(this, props.environment, 'agent-subnet-ids', Fn.join(',', agentSubnets.map((s) => s.subnetId)));
    publish(this, props.environment, 'broker-subnet-ids', Fn.join(',', brokerSubnets.map((s) => s.subnetId)));
    publish(this, props.environment, 'agent-sg-id', agentSg.securityGroupId);
    publish(this, props.environment, 'broker-sg-id', brokerSg.securityGroupId);
    publish(this, props.environment, 'endpoint-sg-id', endpointSg.securityGroupId);
    publish(this, props.environment, 'network-mode', secure ? 'secure' : 'open');
  }
}
