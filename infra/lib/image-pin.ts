import { Annotations, Stack } from 'aws-cdk-lib';

/**
 * Image pinning: the one place a container image reference is chosen.
 *
 * Every image this app deploys is named by DIGEST. A digest is the hash of the image manifest, so
 * the thing that runs is the thing that was reviewed. A tag is a pointer that can be moved after
 * the review, and a default tag such as `latest` moves on every push. Neither is accepted here
 * without an explicit override, and the override is recorded.
 *
 * The rules, per image:
 *   - `-c <x>ImageDigest=sha256:<64 lowercase hex>` is the normal path.
 *   - `-c <x>ImageTag=<tag>` is honoured only together with `-c allowMutableImageTags=true`. It
 *     adds a synth warning and records the image on the stack tag `safe-agents:mutable-image-tags`,
 *     which is visible on the deployed stack and in the CloudTrail record of the deploy.
 *   - Both keys for one image, a malformed digest, or a tag without the allow flag: synth throws.
 *   - Neither key, for an image the stack deploys: an error on that stack. There is no default.
 *
 * Why the missing-key case is a stack error and the others throw: all five stacks are
 * instantiated by every `cdk` command, so a throw here would make `cdk deploy` of the Network
 * stack, or `cdk destroy` of anything, demand an image digest it does not use. An error
 * annotation is scoped to the stack it sits on: `cdk synth`, `cdk diff` and `cdk deploy` refuse
 * any selection that includes that stack, and leave the other stacks alone. The reference the
 * template carries in that case is UNPINNED_PLACEHOLDER, a digest no image can have, so a
 * template deployed around the refusal (`--ignore-errors`, or by hand from `cdk.out`) fails at
 * the pull instead of running something. The other three cases are wrong input the operator
 * typed, and nothing is gained by deferring them.
 */

/** Context key of the override. One flag covers every image in the app. */
export const ALLOW_MUTABLE_TAGS_KEY = 'allowMutableImageTags';

/** Stack tag that records which images a stack deploys by tag. Absent when there are none. */
export const MUTABLE_IMAGE_TAGS_STACK_TAG = 'safe-agents:mutable-image-tags';

/**
 * Rendered when a required image has no key. Syntactically a digest, so the template stays
 * well formed, and all zeros, which is not the SHA-256 of any manifest.
 */
export const UNPINNED_PLACEHOLDER = `sha256:${'0'.repeat(64)}`;

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
// The OCI distribution tag grammar.
const TAG_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
// CloudFormation rejects a tag value longer than this at deploy; fail at synth instead.
const STACK_TAG_VALUE_MAX = 256;

export interface ImagePinSpec {
  /** Short name used in messages and in the stack tag, e.g. `broker`. */
  readonly image: string;
  /** Context key that carries the digest, e.g. `brokerImageDigest`. */
  readonly digestKey: string;
  /** Context key that carries a tag under the override, e.g. `brokerImageTag`. */
  readonly tagKey: string;
  /** ECR repository name, used only to make the "how to read a digest" hint copyable. */
  readonly repositoryName: string;
}

function howToGetADigest(spec: ImagePinSpec): string {
  return (
    'Read the digest back after pushing the image: ' +
    '`podman push --digestfile <file> <image> <repository-uri>:<unique tag>` writes it to ' +
    `<file>, or \`aws ecr describe-images --repository-name ${spec.repositoryName} ` +
    "--image-ids imageTag=<tag> --query 'imageDetails[0].imageDigest' --output text` prints it."
  );
}

function overrideFlags(spec: ImagePinSpec): string {
  return `-c ${spec.tagKey}=<tag> -c ${ALLOW_MUTABLE_TAGS_KEY}=true`;
}

const OVERRIDE_IS_RECORDED =
  'The override prints a warning on every synth and is recorded on the stack as the tag ' +
  `${MUTABLE_IMAGE_TAGS_STACK_TAG}.`;

function recordMutableTag(stack: Stack, spec: ImagePinSpec, tag: string): void {
  // Accumulate: one stack can deploy several images by tag, and the tag must list all of them.
  const prior = stack.tags.tagValues()[MUTABLE_IMAGE_TAGS_STACK_TAG];
  const entry = `${spec.image}=${tag}`;
  const value = prior ? `${prior} ${entry}` : entry;
  if (value.length > STACK_TAG_VALUE_MAX) {
    throw new Error(
      `The ${MUTABLE_IMAGE_TAGS_STACK_TAG} stack tag would be ${value.length} characters, over ` +
        `the ${STACK_TAG_VALUE_MAX} CloudFormation allows, so the override could not be ` +
        'recorded. Use shorter image tags, or pin more of these images by digest.',
    );
  }
  stack.tags.setTag(MUTABLE_IMAGE_TAGS_STACK_TAG, value);
}

/**
 * Resolve the `tagOrDigest` string for one image from CDK context.
 *
 * Returns undefined only when `required` is false and neither key is set (a drain whose phase
 * gate is closed). A key that is present but empty is malformed input, never "unset": an empty
 * shell variable must not quietly close a gate.
 */
export function resolveImagePin(stack: Stack, spec: ImagePinSpec, required: true): string;
export function resolveImagePin(
  stack: Stack,
  spec: ImagePinSpec,
  required: boolean,
): string | undefined;
export function resolveImagePin(
  stack: Stack,
  spec: ImagePinSpec,
  required: boolean,
): string | undefined {
  const digest: unknown = stack.node.tryGetContext(spec.digestKey);
  const tag: unknown = stack.node.tryGetContext(spec.tagKey);

  if (digest !== undefined && tag !== undefined) {
    throw new Error(
      `Both ${spec.digestKey} and ${spec.tagKey} are set for the ${spec.image} image. Pass ` +
        `exactly one: -c ${spec.digestKey}=sha256:<64 lowercase hex characters> (the normal ` +
        `path), or -c ${spec.tagKey}=<tag> with -c ${ALLOW_MUTABLE_TAGS_KEY}=true.`,
    );
  }

  if (digest !== undefined) {
    if (typeof digest !== 'string' || !DIGEST_PATTERN.test(digest)) {
      throw new Error(
        `${spec.digestKey} is not an image digest: got ${JSON.stringify(digest)}. A digest is ` +
          '"sha256:" followed by exactly 64 lowercase hexadecimal characters. ' +
          howToGetADigest(spec),
      );
    }
    return digest;
  }

  if (tag !== undefined) {
    const allowCtx: unknown = stack.node.tryGetContext(ALLOW_MUTABLE_TAGS_KEY);
    const allowed = allowCtx === true || allowCtx === 'true';
    if (!allowed) {
      throw new Error(
        `${spec.tagKey}=${JSON.stringify(tag)} names the ${spec.image} image by tag, and a tag ` +
          'can be moved to a different image after it was reviewed. Pass ' +
          `-c ${spec.digestKey}=sha256:<64 lowercase hex characters> instead. ` +
          `${howToGetADigest(spec)} To deploy by tag anyway, pass ${overrideFlags(spec)}. ` +
          OVERRIDE_IS_RECORDED,
      );
    }
    if (typeof tag !== 'string' || !TAG_PATTERN.test(tag)) {
      throw new Error(
        `${spec.tagKey} is not an image tag: got ${JSON.stringify(tag)}. A tag is 1 to 128 ` +
          'characters from letters, digits, "_", "." and "-", and does not start with "." or ' +
          `"-". A digest (sha256:...) goes in ${spec.digestKey}.`,
      );
    }
    Annotations.of(stack).addWarning(
      `The ${spec.image} image is deployed by tag "${tag}" (${spec.tagKey} with ` +
        `${ALLOW_MUTABLE_TAGS_KEY}=true). A tag can be moved, so what runs may not be what was ` +
        `reviewed. Recorded on this stack as the tag ${MUTABLE_IMAGE_TAGS_STACK_TAG}. Redeploy ` +
        `with -c ${spec.digestKey}=sha256:<digest> to pin it.`,
    );
    recordMutableTag(stack, spec, tag);
    return tag;
  }

  if (!required) {
    return undefined;
  }
  Annotations.of(stack).addError(
    `No image is pinned for the ${spec.image} image, and there is no default. Pass ` +
      `-c ${spec.digestKey}=sha256:<64 lowercase hex characters>, the digest of the image you ` +
      `reviewed. ${howToGetADigest(spec)} Before any image exists (a first bringup), pass ` +
      `${overrideFlags(spec)}. ${OVERRIDE_IS_RECORDED}`,
  );
  return UNPINNED_PLACEHOLDER;
}
