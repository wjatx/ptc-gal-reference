import { StackProps } from 'aws-cdk-lib';
import { Environment } from './environment';

/**
 * Props shared by every foundation stack. The `environment` is resolved and validated once in
 * the app entrypoint and threaded through so each stack names its resources and exports
 * consistently via the helpers in `naming.ts`.
 */
export interface FoundationStackProps extends StackProps {
  readonly environment: Environment;
}

/**
 * Props for the two stacks whose shape depends on the network posture — NetworkStack (which builds
 * the topology) and ComputeStack (which places the broker service into it). `secureNetwork` gates
 * the network-layer half of invariant #2 ("agent egress = broker only"):
 *   - true  → the confined topology (isolated agent subnet with no default route, one NAT for the
 *             broker, interface endpoints for private AWS access). Egress containment is topological.
 *   - false → a flat public-subnet VPC (no NAT, no interface endpoints) that trades the network-layer
 *             containment back to the broker's code/credential layer to save the NAT + endpoint spend.
 * Resolved once from CDK context in the app entrypoint and threaded to both stacks so a single flag
 * keeps the topology and the broker's placement in agreement.
 */
export interface NetworkModeStackProps extends FoundationStackProps {
  readonly secureNetwork: boolean;
}
