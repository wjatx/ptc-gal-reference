# arms/ec2/ami — base AMI bakery + S3 agent-code delivery

This directory owns the **prebuilt-AMI bootstrap model** for the always-on EC2 arm.

## Why prebuilt AMI instead of cloud-init internet bootstrap

The deployed instance runs in a subnet with **no internet egress** — only an S3 gateway endpoint
and the broker VPC endpoints are open. A cloud-init bootstrap that downloads Claude Code or
`git clone`s the agent repo at boot is incompatible with this constraint. Instead:

- The **base AMI** is baked in CI (where internet egress exists). It pre-installs the toolchain
  and the Claude Code CLI, so the deployed instance starts ready to run.
- **Agent code** is delivered via the S3 deploy bucket, not git clone. CI bundles the agent package
  and uploads it; the instance pulls from the bucket at boot via the S3 gateway endpoint.

## Layout

```
ami/
├── bundle.py                     # agent-code bundling + S3 upload script
└── image-builder/
    ├── component-base.yaml       # AWSTOE component (toolchain + Claude Code CLI)
    ├── recipe-base.json          # Image Builder recipe (AL2023 arm64)
    ├── infra-config.json         # Image Builder infrastructure configuration (build instance)
    ├── dist-config.json          # Image Builder distribution configuration (AMI tags)
    └── pipeline.json             # Image Builder pipeline (ties them together)
```

## What the component bakes

`component-base.yaml` installs, on arm64 Amazon Linux 2023:

- **`dnf` packages**: git, python3, python3-pip, unzip, python3-pyyaml, iptables-nft.
- **AWS CLI v2**, from its pinned aarch64 release archive.
- **boto3**, into `/opt/boto3-venv`, with `pip install --require-hashes`.
- **Claude Code CLI** (the native binary), the sole HARNESS-COUPLING step. It also writes
  `DISABLE_UPDATES=1` into `/etc/claude-code/managed-settings.json`, so the baked binary
  never updates itself.

The image carries **no Node.js**. Claude Code needs none and nothing else on the box uses
it, and the validate phase fails the bake if `node` or `npm` is present.

### Every download is pinned

The AWS CLI archive and the Claude Code binary are lines of
`safe_agents/arms/toolchain/artifacts.lock`, fetched with the inline form that directory's
README defines: an exact version, checked against a SHA-256, with no fallback. A mismatch
or a removed URL fails the bake. The boto3 requirement lines are a copy of
`safe_agents/arms/toolchain/boto3-venv.txt`, and `safe_agents/arms/ec2/tests/test_ec2_arm.py`
fails if the two differ. `dnf` installs named packages from Amazon Linux's signed repositories.

Move a pin with `scripts/update-artifact-pin.py`, which rewrites the component. A changed
component needs a new `--semantic-version`, and the recipe's `componentArn` to match,
before Image Builder will take it. The component and the recipe are both at 2.0.0.

This form of the component has not been baked. The `VerifyInstalls` step runs the Claude
Code binary, so a file that cannot execute on the build instance fails the bake.

## AMI tagging convention

Every baked AMI carries these tags (set by `dist-config.json`):

| Tag | Value |
|---|---|
| `safe-agents:ami` | `base` |
| `safe-agents:ami-version` | UTC build timestamp (`YYYYMMDDTHHMMSSZ`) |
| `Project` | `safe-agents` |
| `ManagedBy` | `safe-agents-image-builder` |

`provision.py` selects the **newest base AMI** by filtering on `safe-agents:ami=base` and sorting
by `CreationDate`. The `safe-agents:ami-version` tag doubles as a human-readable build stamp.

## S3 deploy bucket + bundle key convention

| Item | Value |
|---|---|
| Bucket | `safe-agents-<env>-deploy` |
| Current bundle key | `agents/<name>/current/bundle.tar.gz` |
| Versioned bundle key | `agents/<name>/<version>/bundle.tar.gz` |

`<version>` defaults to a compact UTC timestamp (`YYYYMMDDTHHMMSSZ`) when not supplied. The
current key is overwritten on every deploy; the versioned key is immutable (used for rollback and
audit). Both S3 keys must remain in sync with `provision.py` and the boot script.

The bucket itself is **created and owned by the State stack** (`StateStack DeployBucket`) — it is
shared floor infrastructure (every arm reads its bundles), so it comes up with `cdk deploy` and is
removed by `cdk destroy` (dev auto-deletes objects). `bake_teardown` never deletes it; it only cleans
its own `image-builder-logs/` objects. `<name>` is the manifest `name`, which may differ from the
package directory — see the `--manifest` note below.

## Baking the base AMI

### One-time setup (done once per AWS account)

Deploy the Image Builder resources in order using the JSON/YAML files in `image-builder/`. Replace
`${AWS_REGION}`, `${AWS_ACCOUNT_ID}`, and other `${...}` placeholders with real values. The
`IMAGE_BUILDER_INSTANCE_PROFILE` must be the name of the IAM instance profile granted to the build
instance (see IAM requirements below).

```sh
# 1. Create the AWSTOE component
aws imagebuilder create-component \
  --name safe-agents-base \
  --semantic-version 2.0.0 \
  --platform Linux \
  --supported-os-versions '["Amazon Linux 2023"]' \
  --data file://image-builder/component-base.yaml \
  --region "$AWS_REGION"

# 2. Create the infrastructure configuration
# (substitute ${BUILD_SECURITY_GROUP_ID}, ${BUILD_SUBNET_ID}, ${ENVIRONMENT} first)
aws imagebuilder create-infrastructure-configuration \
  --cli-input-json file://image-builder/infra-config.json

# 3. Create the distribution configuration (substitute ${AWS_REGION}, ${AWS_ACCOUNT_ID})
aws imagebuilder create-distribution-configuration \
  --cli-input-json file://image-builder/dist-config.json

# 4. Create the recipe (substitute ${AWS_REGION}, ${AWS_ACCOUNT_ID}; resolve parentImage ARN)
aws imagebuilder create-image-recipe \
  --cli-input-json file://image-builder/recipe-base.json

# 5. Create the pipeline (substitute ARNs for recipe, infra, distribution)
aws imagebuilder create-image-pipeline \
  --cli-input-json file://image-builder/pipeline.json
```

**Resolving the AL2023 arm64 parent image ARN:** Image Builder managed parent images follow the
pattern `arn:aws:imagebuilder:<region>:aws:image/amazon-linux-2023-arm64/x.x.x/1`. Look up the
current version in the Image Builder console or with the command below.

The `x.x.x` in the recipe's `parentImage` is deliberate. It takes the newest Amazon Linux 2023
image at bake time, and `dnf update` then takes the newest packages, so the operating system
is whatever Amazon published on the day of the bake. That content is pinned by the bake's
output: the AMI id is the pin, and it does not change after the bake.

```sh
aws imagebuilder list-images \
  --owner Amazon \
  --filters "name=name,values=Amazon Linux 2023 (arm64)" \
  --query 'imageVersionList[0].arn'
```

### Triggering a bake in CI

```sh
# Start a one-off pipeline execution (returns a build ARN)
aws imagebuilder start-image-pipeline-execution \
  --image-pipeline-arn <PIPELINE_ARN>
```

### The weekly schedule ships off

`pipeline.json` carries a weekly schedule (Sunday 02:00 UTC, when AL2023 updates are
available) and `"status": "DISABLED"`, so a pipeline created from it never bakes on a
timer. A bake is a deliberate act. Provisioning
launches from the newest AMI carrying the bake tag, so a scheduled bake would change what the
next provision picks up without anyone having decided that it should.

Run a bake by hand with the command above. `start-image-pipeline-execution` starts a build
whether the pipeline is enabled or disabled (AWS documents this in the Image Builder API
reference for `StartImagePipelineExecution`). To turn the schedule on for an account, set
`"status": "ENABLED"` in the deployed pipeline with `aws imagebuilder update-image-pipeline`;
the copy in this repository stays `DISABLED`, and
`safe_agents/arms/tests/test_image_builder_definitions.py` fails if it does not.

## Bundling and uploading agent code

Use `bundle.py` to package an agent directory and push it to the deploy bucket. The script runs
in CI; it never runs on the deployed instance.

Prefer `--manifest`: it derives the S3 key from the manifest `name` and the source dir from
`agent_package`, so the upload always matches what the box pulls. Setting `--agent-name` to the
package directory instead of the manifest `name` is a footgun — when they differ (e.g.
`smoke-rhel-openshell` packages the `test-stub` fixture) the box 404s at boot.

```sh
cd /path/to/safe-agents

# Preferred: derive name + package from the manifest
python -m safe_agents.arms.ec2.ami.bundle \
  --manifest agents/smoke-rhel-openshell.yaml \
  --environment development

# Explicit form — --agent-name MUST equal the manifest `name`, not the package dir
python -m safe_agents.arms.ec2.ami.bundle \
  --agent-dir agents/test-stub \
  --agent-name test-stub \
  --environment development

# Pin a specific version (default is a UTC timestamp)
python -m safe_agents.arms.ec2.ami.bundle \
  --manifest agents/test-stub.yaml \
  --environment production \
  --version 20260628T120000Z
```

### In a CI job (GitHub Actions sketch)

```yaml
- name: Bundle and upload agent code
  run: |
    python -m safe_agents.arms.ec2.ami.bundle \
      --manifest agents/${{ matrix.agent }}.yaml \
      --environment ${{ env.ENVIRONMENT }} \
      --version ${{ github.sha }}
  env:
    AWS_ROLE_ARN: ${{ vars.CI_DEPLOY_ROLE_ARN }}   # OIDC role — no long-lived keys
```

The CI role needs only `s3:PutObject` on `arn:aws:s3:::safe-agents-*-deploy/agents/*`.

## IAM requirements

### Build instance profile (used by the Image Builder build instance)

Attach AWS managed policy `EC2InstanceProfileForImageBuilder` plus SSM core actions for console
access. The build instance needs internet egress for `dnf`, the pinned release downloads and
the hashed `pip` install. It does
NOT need access to the agent S3 bucket, DynamoDB, or Secrets Manager.

### CI deploy role (used by the bundle upload script)

Minimal inline policy:

```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject"],
  "Resource": "arn:aws:s3:::safe-agents-*-deploy/agents/*"
}
```

### Image Builder pipeline service role

The pipeline itself needs `imagebuilder:*` plus the EC2 permissions to launch, stop, and snapshot
the build instance. Use the AWS managed policy `AWSImageBuilderFullAccess` or a scoped equivalent.
The infra CDK stack (`infra/`) will own these roles when the Image Builder resources are integrated
there.

## HARNESS-COUPLING note

The `ClaudeCodeCLI` step in `component-base.yaml` is the **only** place this bake process couples
to Claude Code. All other steps are harness-neutral. To swap harnesses: replace only that step and
update the `ClaudeCodeCLI` step in the component. The bundle script, key conventions, and S3
delivery mechanism are entirely harness-neutral.
