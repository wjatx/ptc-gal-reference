import { App, RemovalPolicy } from 'aws-cdk-lib';

/**
 * The only valid environment names. Exactly `development` / `staging` / `production` —
 * never `dev` / `prod` / `stage`. CloudFormation exports, stack names, and tags interpolate
 * `${Environment}`; a single-character difference silently breaks cross-stack `ImportValue`.
 */
export const ENVIRONMENTS = ['development', 'staging', 'production'] as const;

export type Environment = (typeof ENVIRONMENTS)[number];

function isEnvironment(value: unknown): value is Environment {
  return typeof value === 'string' && (ENVIRONMENTS as readonly string[]).includes(value);
}

/**
 * Resolve and validate the target environment from CDK context.
 * Pass it at synth/deploy: `cdk synth -c environment=development`.
 * Throws a clear, actionable error for a missing or misspelled value rather than
 * silently synthesizing the wrong stack.
 */
export function resolveEnvironment(app: App): Environment {
  const raw = app.node.tryGetContext('environment');

  if (raw === undefined || raw === null || raw === '') {
    throw new Error(
      "Missing required context 'environment'. " +
        'Pass it explicitly, e.g. `cdk synth -c environment=development` ' +
        `(one of: ${ENVIRONMENTS.join(', ')}).`,
    );
  }

  if (!isEnvironment(raw)) {
    throw new Error(
      `Invalid environment '${raw}'. Must be exactly one of: ${ENVIRONMENTS.join(', ')} ` +
        "— never 'dev' / 'prod' / 'stage' (cross-stack ImportValue interpolates the literal name).",
    );
  }

  return raw;
}

/**
 * Whether an environment is ephemeral (disposable) vs durable. Only `development` is ephemeral:
 * its stateful resources are torn down and redeployed hands-off. `staging` and `production` are
 * durable — their state, audit, and keys survive a stack teardown.
 */
export function isEphemeral(env: Environment): boolean {
  return env === 'development';
}

/**
 * The removal policy for stateful resources, derived from the environment. DESTROY in the
 * ephemeral environment so `cdk destroy` actually removes resources (no fixed-name collisions on
 * redeploy); RETAIN in durable environments so authority, budgets, held intents, run history, and
 * audit are never lost to a teardown.
 */
export function removalPolicyFor(env: Environment): RemovalPolicy {
  return isEphemeral(env) ? RemovalPolicy.DESTROY : RemovalPolicy.RETAIN;
}
