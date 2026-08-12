import { Duration } from 'aws-cdk-lib';
import { ArnPrincipal, Effect, IRole, PolicyStatement, Role } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { Environment } from './environment';
import { publish } from './naming';

/**
 * One capability's declared IAM scope — the deploy-side mirror of the runtime's
 * `capability_iam: {tool: {actions, resources}}` manifest block (safe-agents #175). The broker's
 * `assumed_role` CredentialProvider strategy STS-assumes this role at execute time, so the blast
 * radius of a compromised tool call is exactly `actions` on exactly `resources` — nothing else.
 */
export interface CapabilitySpec {
  /** The manifest tool name (e.g. `s3.read`), used only for construct ids / descriptions / exports. */
  readonly tool: string;
  /**
   * Deterministic IAM role name. NOT CDK-generated: the consumer's manifest carries this role's ARN
   * (via `role_arn` in `capability_iam`), so the name must be stable across redeploys.
   */
  readonly roleName: string;
  /** The exact actions the capability may take. No wildcards added here — use what the spec carries. */
  readonly actions: string[];
  /** The exact resource ARNs the capability may act on. No wildcards added here. */
  readonly resources: string[];
  /** Optional `sts:ExternalId` the broker must present when assuming this role. */
  readonly externalId?: string;
}

export interface CapabilityRolesProps {
  readonly environment: Environment;
  /** The broker's task role — the ONLY principal ever trusted to assume a capability role. */
  readonly brokerRole: IRole;
  readonly capabilities: CapabilitySpec[];
}

/**
 * CapabilityRoles — provisions one IAM role per declared capability, each scoped to EXACTLY its
 * spec's actions+resources and assumable ONLY by the broker's task role (safe-agents #175, the
 * deploy half of the `assumed_role` CredentialProvider strategy landed in #173).
 *
 * With no capabilities (the default: no `capabilityRoles` context), this construct creates nothing
 * — a no-op that must not change any existing stack's synth output.
 */
export class CapabilityRoles extends Construct {
  /** The created roles, keyed by tool name, for callers that need the ARNs (e.g. the broker policy). */
  public readonly roles: Record<string, Role> = {};

  constructor(scope: Construct, id: string, props: CapabilityRolesProps) {
    super(scope, id);

    const { environment, brokerRole, capabilities } = props;

    for (const spec of capabilities) {
      if (spec.actions.length === 0) {
        throw new Error(
          `CapabilityRoles: capability '${spec.tool}' declares no actions — a scoped role with no ` +
            'actions is a no-op; either declare the intended actions or drop the capability entirely.',
        );
      }
      if (spec.resources.length === 0) {
        throw new Error(
          `CapabilityRoles: capability '${spec.tool}' declares no resources — an action with no ` +
            'resource scope is effectively a wildcard; declare the exact resource ARNs it may act on.',
        );
      }

      const trustPrincipal = spec.externalId
        ? new ArnPrincipal(brokerRole.roleArn).withConditions({
            StringEquals: { 'sts:ExternalId': spec.externalId },
          })
        : new ArnPrincipal(brokerRole.roleArn);

      const role = new Role(this, constructIdFor(spec.tool), {
        roleName: spec.roleName,
        assumedBy: trustPrincipal,
        description:
          `safe-agents ${environment} - per-capability scoped role for ${spec.tool} ` +
          '(blast radius = declared IAM)',
        maxSessionDuration: Duration.hours(1),
      });

      // ONE inline statement, exactly the declared scope — this statement IS the blast radius.
      role.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: spec.actions,
          resources: spec.resources,
        }),
      );

      this.roles[spec.tool] = role;
      publish(this, environment, `capability-role-${spec.tool}-arn`, role.roleArn);
    }
  }
}

/** Construct id segments must be alphanumeric; turn a dotted/kebab tool name into PascalCase. */
function constructIdFor(tool: string): string {
  return tool
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}
