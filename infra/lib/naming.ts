import { CfnOutput, Fn, Stack } from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { Environment } from './environment';

/**
 * The cross-stack export / import convention every foundation stack follows.
 *
 * A published value is written in two forms so component stacks can consume it either way:
 *   1. a CloudFormation **export** (for `Fn.importValue` / `importValue()` below), and
 *   2. an **SSM parameter** at a deterministic path (for tools, runbooks, and non-CFN readers).
 *
 * Names are derived deterministically from (environment, key) so producers and consumers never
 * have to agree on a literal string — they agree on a `key` and call the same helper.
 */
const PREFIX = 'safe-agents';

/** A resource's logical name, e.g. `safe-agents-development-grants`. */
export function resourceName(env: Environment, base: string): string {
  return `${PREFIX}-${env}-${base}`;
}

/** The CloudFormation stack name for a foundation layer, e.g. `SafeAgents-Network-development`. */
export function stackName(env: Environment, layer: string): string {
  return `SafeAgents-${layer}-${env}`;
}

/** The CloudFormation export name for a published value, e.g. `safe-agents-development-vpc-id`. */
export function exportName(env: Environment, key: string): string {
  return `${PREFIX}-${env}-${key}`;
}

/** The SSM parameter path for a published value, e.g. `/safe-agents/development/vpc-id`. */
export function ssmParameterName(env: Environment, key: string): string {
  return `/${PREFIX}/${env}/${key}`;
}

/** Construct id segments must be alphanumeric; turn a kebab key into PascalCase. */
function constructIdFor(key: string): string {
  return key
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

/**
 * Publish a value as both a CloudFormation export and an SSM parameter.
 * Call this from a producing stack (Network / State / Identity) for every output a
 * downstream stack needs.
 */
export function publish(scope: Construct, env: Environment, key: string, value: string): void {
  const id = constructIdFor(key);
  new CfnOutput(scope, `Export${id}`, {
    value,
    exportName: exportName(env, key),
    description: `safe-agents ${env} :: ${key}`,
  });
  new StringParameter(scope, `Param${id}`, {
    parameterName: ssmParameterName(env, key),
    stringValue: value,
  });
}

/** Consume a value published by {@link publish} from another stack via CloudFormation import. */
export function importValue(env: Environment, key: string): string {
  return Fn.importValue(exportName(env, key));
}

/** Consume a published value via SSM at synth time (token resolved during deploy). */
export function importFromSsm(scope: Construct, env: Environment, key: string): string {
  return StringParameter.valueForStringParameter(scope, ssmParameterName(env, key));
}

/** Convenience: a stack's environment, read back from the tag we set app-wide. */
export function environmentOf(stack: Stack): string | undefined {
  return stack.tags.tagValues().Environment;
}
