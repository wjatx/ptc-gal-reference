#!/usr/bin/env node
import { App, Tags } from 'aws-cdk-lib';
import { resolveEnvironment } from '../lib/environment';
import { stackName } from '../lib/naming';
import { NetworkStack } from '../lib/network-stack';
import { StateStack } from '../lib/state-stack';
import { IdentityStack } from '../lib/identity-stack';
import { ComputeStack } from '../lib/compute-stack';
import { ChannelsStack } from '../lib/channels-stack';

const app = new App();

// Resolve + validate the target environment once; every stack and export derives from it.
const environment = resolveEnvironment(app);

// Network posture, resolved from CDK context: `-c secureNetwork=true` builds the confined topology
// (isolated agent subnet + NAT + interface endpoints); the default (false) builds the flat public
// VPC that trades network-layer egress containment back to the broker for the NAT + endpoint spend.
// Threaded to Network AND Compute so the topology and the broker's placement agree on one flag.
const secureNetworkCtx = app.node.tryGetContext('secureNetwork');
const secureNetwork = secureNetworkCtx === true || secureNetworkCtx === 'true';

// Account/region come from the ambient CLI credentials at deploy time. Left env-agnostic at
// synth so `cdk synth -c environment=development` works with no AWS credentials configured.
const env =
  process.env.CDK_DEFAULT_ACCOUNT !== undefined
    ? { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION }
    : undefined;

const network = new NetworkStack(app, stackName(environment, 'Network'), {
  environment,
  env,
  secureNetwork,
});
const state = new StateStack(app, stackName(environment, 'State'), { environment, env });
const identity = new IdentityStack(app, stackName(environment, 'Identity'), { environment, env });
const compute = new ComputeStack(app, stackName(environment, 'Compute'), {
  environment,
  env,
  secureNetwork,
});
const channels = new ChannelsStack(app, stackName(environment, 'Channels'), { environment, env });

// Deploy order is Network → State → Identity, but only Identity has a hard dependency: it scopes
// its role policies to State's exported ARNs. Network and State are independent (parallelizable).
identity.addDependency(state);

// ComputeStack (sa#36 Fargate arm) imports from all three foundation layers: Network (VPC/subnets/
// SGs), State (tables/audit bucket), Identity (brokerRole). It deploys last.
compute.addDependency(network);
compute.addDependency(state);
compute.addDependency(identity);

// ChannelsStack (sa#152 airlock) imports only State (dedupe table, audit bucket + CMKs) — it owns
// its own execution role and runs outside the VPC, so it touches neither Network nor Identity.
channels.addDependency(state);

// App-wide tags so every synthesized resource is traceable to the project + environment.
Tags.of(app).add('Project', 'safe-agents');
Tags.of(app).add('Environment', environment);
