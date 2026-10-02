# arms/rhel_openshell/ami — prebuilt RHEL 9 base-AMI bakery

This directory owns the **prebuilt-AMI bootstrap model** for the `rhel-openshell`
arm. It mirrors the EC2 arm's bakery (`arms/ec2/ami`), adapted for RHEL 9 x86_64.

## Why prebuilt AMI instead of boot-time internet install

The RHEL two-box arm places the box in the **isolated agent subnet** — no NAT, no
internet route; only the S3 gateway endpoint and the broker/AWS interface endpoints are
reachable. But RHEL's `user-data.sh.tmpl` + `bootstrap.sh` install their toolchain at boot
over the internet (SSM agent, AWS CLI, `dnf` core tools, and pinned release downloads such
as the Claude Code binary, none of which is S3-backed). A fresh box in the isolated subnet
therefore cannot complete bootstrap.

Baking the toolchain into the base AMI (in CI, where internet + RHUI egress exist) makes the
box **config-only**, exactly like the EC2 arm: it boots ready to run with no internet.

## What the bake differs on vs. the EC2 bakery

| Aspect | EC2 arm | rhel-openshell arm |
|---|---|---|
| Parent image | AL2023 arm64 (managed IB parent ARN) | **RHEL 9 x86_64 marketplace AMI** (`${RHEL9_PARENT_AMI}`) |
| Architecture | arm64 | **x86_64** (OpenShell is x86_64 only) |
| Root device | `/dev/xvda` | **`/dev/sda1`** |
| Package manager | `dnf` (AL2023) | `dnf` (RHEL 9 + EPEL/CRB) |
| NAT firewall tool | `iptables-nft` (baked) | **`nftables`** (already on the RHEL AMI — **do NOT bake iptables**) |
| AWS CLI installer | pinned `awscli-exe-linux-aarch64-<version>.zip` | pinned `awscli-exe-linux-x86_64-<version>.zip` |
| SSM agent | present on AL2023 | **baked** (RHEL AMIs omit it), and kept only because the recipe sets `uninstallAfterBuild: false` |
| AMI tag | `safe-agents:ami=base` | `safe-agents:ami=base-rhel` |
| IB resource prefix | `safe-agents-base` | `safe-agents-base-rhel` |

**SELinux stays Enforcing.** RHEL AMIs run SELinux and the arm relies on `restorecon`; the
component's `validate` phase asserts `getenforce == Enforcing` so a bake can never silently
disable it.

## What the component bakes

The `component-base.yaml` build phase bakes the exact internet-dependent toolchain the box
installs at boot today (`user-data.sh.tmpl` root essentials + `bootstrap.sh` autonomous
"always" steps):

- **SSM agent** — `user-data.sh.tmpl` step 1 (RHEL AMIs omit it).
- **AWS CLI v2** (x86_64 release archive) — `user-data.sh.tmpl` step 4.
- **Core `dnf` toolchain** — `bootstrap/scripts/install-tools.sh` (git, jq, tar, gcc, tmux,
  buildah/skopeo, the `-devel` set), plus htop from EPEL.
- **bat, ripgrep and `gh`** — `bootstrap/scripts/install-tools.sh`, from their release
  archives.
- **uv + ruff** — `bootstrap/scripts/install-python-env.sh`.
- **python3-pyyaml** — the conformance harness imports `yaml` on the system `python3`.
- **Claude Code CLI** (the native binary) — the sole HARNESS-COUPLING step, mirroring
  `bootstrap/scripts/setup-claude.sh`. It also writes `DISABLE_UPDATES=1` into
  `/etc/claude-code/managed-settings.json`, so the baked binary never updates itself.

The image carries **no Node.js**. Claude Code needs none, and the validate phase fails the
bake if `node` or `npm` is present. The interactive profile installs Node.js at boot.

### Every download is pinned

Each file the component downloads is a line of `safe_agents/arms/toolchain/artifacts.lock`,
fetched with the inline form that directory's README defines: an exact version, checked
against a SHA-256, with no fallback. A mismatch or a removed URL fails the bake. `dnf`
installs named packages from RHEL's signed repositories and htop from EPEL, which is added
from its pinned release RPM.

The component and the boot scripts install each tool from the same pin by the same
commands, and `tests/test_rhel_ami.py` fails if the two sets of pins differ. Move a pin with
`scripts/update-artifact-pin.py`, which rewrites both. A changed component needs a new
`--semantic-version` (and the recipe's `componentArn` to match) before Image Builder will
take it. The component is at 2.0.0 and the recipe is at 2.0.1.

Component 2.0.0 has been baked once: on 2026-10-02, in us-east-1, on an `m7i.large` build
instance, from parent `RHEL-9.8.0_HVM-20260908-x86_64-0-Hourly2-GP3`, created from an S3
upload with `--uri`. Every build step ran and the validate phase passed
(`ValidateDirectoryLayout`, `ValidatePinnedHarness`, `ValidateSelinuxAndNft`), so SELinux was
still Enforcing at the end of the build. The `VerifyInstalls` step runs each pinned binary. It
printed `2.1.285 (Claude Code)`, `aws-cli/2.37.8` (reporting `exe/x86_64.rhel.9`), `bat 0.26.1`,
`ripgrep 15.2.0`, `gh version 2.102.0`, `uv 0.12.22` and `ruff 0.15.20`, and found `htop` and
`nft`. In that build the x86_64 Claude Code binary executed on RHEL 9, and the hashed
`pip install` of ruff worked on the system Python 3.9 (pip 21.3.1, which printed an upgrade
notice and nothing else). That is one build on one day.

**That AMI had no SSM agent**, and the bake did not show it. A RHEL parent has no agent, so
Image Builder installs its own to run the build. The component's `InstallSSMAgent` step then
finds the package present and does nothing, and Image Builder removes the agent it installed
before it creates the AMI. An instance launched from that image on 2026-10-02 never registered
with Systems Manager. The boot-path test below used the same image, and the fallback in
`user-data.sh.tmpl` step 1 is what made its instance reachable: finding no agent, it installed
the pinned RPM at boot, which needs egress. Recipe 2.0.1 sets
`additionalInstanceConfiguration.systemsManagerAgent.uninstallAfterBuild` to `false`, which
leaves the agent in the image. The agent a bake keeps is
the one Image Builder installed, at whatever version it installs that day; the component's
pinned RPM is used only when none is present. Nothing inside a bake can check this, because
the removal happens after the component's last step. Launch an instance from a new AMI and
confirm it registers before relying on it.

That check was run for recipe 2.0.1 on 2026-10-02. The build's sanitize step logged "Uninstall
after build set to false...Skip Uninstall ssm agent", and an instance launched from the
resulting image with no agent install in its user data registered with Systems Manager, agent
version 3.3.5390.0. The first image, the one without the agent, was deregistered.

The bake runs the component and nothing else, so it says nothing about the boot path. That was
tested separately, once.

### The boot path, tested once

On 2026-10-02, in us-east-1, one `m7i.large` was launched from that image in a subnet with
internet egress. The image is RHEL 9.8, built from component 2.0.0 and recipe 2.0.0, so it had
no SSM agent.

`user-data.sh.tmpl` step 1 ran verbatim as the instance's user data and took its fallback
branch. The inline verified fetch of the pinned SSM agent RPM (3.3.5390.0) matched its hash,
`dnf -y install /tmp/amazon-ssm-agent.rpm` installed it, `systemctl enable --now` started it,
and the instance registered with Systems Manager. That was the first run of the fallback on a
host.

Steps 2, 3, 7 and 8 were then reproduced by a test harness over Systems Manager. The template
did not run them. The harness set the cgroup delegation, created the `dev` user with
passwordless sudo, unpacked the rhel-bootstrap bundle to `/home/dev/rhel-bootstrap`, ran
`loginctl enable-linger dev`, and ran `bootstrap.sh` as `dev` with `SA_PROFILE=interactive`.
The bundle was built by `bundle_rhel_bootstrap()` from commit `6ed1291` and fetched by
presigned URL, because the test instance had no read access to the deploy bucket.

`bootstrap.sh` exited 0. In order:

- `install-tools.sh`, `install-python-env.sh` and `setup-claude.sh` each found its tools baked
  and skipped its downloads. `setup-claude.sh` printed `2.1.285 (Claude Code)` and, with no
  `SA_OAUTH_TOKEN_SECRET`, skipped the token check.
- The systemd service and timer for the agent name were written and the timer was enabled. No
  unit failed.
- `install-openshell.sh` fetched the three pinned OpenShell 0.1.2 RPMs (`openshell`,
  `openshell-gateway`, `openshell-prover`, each `-1.fc44.x86_64`) with `fetch_verified`,
  installed them with `dnf`, and enabled and started the gateway user service. The packages are
  built for Fedora; they installed and ran on RHEL 9.8. `openshell gateway add` printed "Gateway
  is not reachable ... Verify the gateway is running" and then "Gateway 'openshell' added and
  set as active". The first of those lines is expected at that point and is not a failure. The
  script's poll then saw `Status: Connected`, `Authentication: Authenticated (mTLS transport)`
  and `Version: 0.1.2`, and `systemctl --user is-active openshell-gateway` printed `active`.
- `install-languages.sh` installed Go 1.27.1, Rust 1.99.0 (rustc and cargo) and Node v22.23.3
  with npm 10.9.9, from their pins.
- `install-k8s-tools.sh` installed oc 4.22.15 (kubectl v1.35.2, from the same archive), helm
  v4.3.0, argocd v3.5.3, terraform v1.16.4, yq v4.54.1 and gitleaks 8.30.1 (in `~/bin`), from
  their pins. Its AWS CLI presence check passed (2.37.8).
- The shell configuration overlay and the Remote Control unit were installed. The unit was not
  enabled, which is the design.

Afterwards each tool, run as `dev`, printed the version above. `getenforce` printed
`Enforcing`, and `/etc/claude-code/managed-settings.json` contained
`{"env": {"DISABLE_UPDATES": "1"}}`.

One OpenShell sandbox round-trip worked.
`openshell sandbox create --name bootpath --no-tty -- sh -c "echo SANDBOX_OK; uname -m; id -u"`
printed `SANDBOX_OK`, `x86_64` and `1000` and exited 0. `openshell sandbox list` showed the
sandbox `Completed`, and `openshell sandbox delete bootpath` was accepted and left the list
empty. The sandbox used the default image the OpenShell CLI chooses, and no policy file was
passed.

That is one run, on one day, on one RHEL minor release. It left the following untested:

- **The autonomous profile's boot path.** The netns setup, `run-brokered.sh`, the broker wiring
  and a brokered run did not run. Only the three always-steps that profile shares with the
  interactive one did.
- **The download branches of `install-tools.sh`, `install-python-env.sh` and `setup-claude.sh`
  on a host.** The tools were baked, so the branches were skipped. A boot from a marketplace
  image, where they would run, is untested for the same reason.
- **`user-data.sh.tmpl` end to end.** Step 4 was not exercised: the AWS CLI was already baked,
  so the fallback had nothing to install, and the only check of the CLI was the presence check
  in `install-k8s-tools.sh`. Steps 5 and 6, the agent and platform-contract bundle pulls from
  S3, did not run. Step 7's bundle arrived by presigned URL, so its S3 pull did not run either.
- **Anything in a subnet without egress.**
- **`run-agent-sandbox.sh`, and OpenShell with this arm's own policy.**
- **Remote Control.**

## AMI tagging convention

Every baked AMI carries these tags (set by `dist-config.json`):

| Tag | Value |
|---|---|
| `safe-agents:ami` | `base-rhel` |
| `safe-agents:ami-version` | UTC build timestamp (`{{imagebuilder:buildDate}}`) |
| `Project` | `safe-agents` |
| `ManagedBy` | `safe-agents-image-builder` |

`rhel_openshell_provision` launches the AMI the operator names by id: `--ami-id ami-...` on the
pipeline CLI, `image_id=` in code. It has no default. With no id the provision refuses before any
AWS call, and a dry run fails the same way. The id is the output of the bake. Read it from the
finished build:

```sh
aws imagebuilder get-image --image-build-version-arn <BUILD_ARN> \
  --query 'image.outputResources.amis[0].image' --output text
```

or list this bakery's AMIs and take the one you reviewed:

```sh
aws ec2 describe-images --owners self \
  --filters "Name=tag:safe-agents:ami,Values=base-rhel" \
  --query 'Images[].[ImageId,CreationDate,Name]' --output table
```

The tags above identify a bake; on the normal path they do not choose an AMI. They choose one only
under the override `--allow-newest-ami` (`allow_newest_ami=True`), implemented by
`resolve_base_ami`:

1. It takes the self-owned AMI tagged `safe-agents:ami=base-rhel` with the latest `CreationDate`.
2. Only when that lookup returns nothing (a fresh account, or before the first bake), it falls back
   to the RHEL 9 marketplace AMI: owner `309956199498` (Red Hat), name
   `RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3`, and among those the highest RHEL release read from the
   name (`RHEL-<major>.<minor>.<patch>_HVM-<yyyymmdd>-...`). A tie goes to the later build date in
   the name, then to the later `CreationDate`. `CreationDate` alone does not order releases,
   because Red Hat rebuilds older minor releases after newer ones ship (the listing under
   "Resolve the RHEL 9 x86_64 parent AMI first" shows one). A matching AMI whose name does not
   have that form cannot be ranked, and it stops the run. The fallback is the behavior before the
   prebuilt AMI, and it only completes bootstrap in a subnet with egress.

The two steps are different trust statements. The first launches an image this account baked; the
second launches an image Red Hat published. The override logs the AMI it chose and the rule that
chose it at WARNING, records the same line in the pipeline plan, and marks the second case
`MARKETPLACE FALLBACK`. An AWS error in the first lookup stops the run. It is never read as "no
bake", so a throttled or denied call cannot cause the fallback. The override is a per-run flag;
nothing reads it from the manifest or the environment.

## Baking the base AMI

### Resolve the RHEL 9 x86_64 parent AMI first

The recipe's `parentImage` is a `${RHEL9_PARENT_AMI}` placeholder. RHEL is a marketplace AMI,
so there is no AWS-managed Image Builder parent. List the RHEL 9 x86_64 AMIs Red Hat publishes
(the owner and name filter `provision.py` uses for its fallback), choose the release you mean to
build on, and substitute its id:

```sh
aws ec2 describe-images --owners 309956199498 \
  --filters "Name=name,Values=RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3" \
  --query "sort_by(Images, &CreationDate)[].[ImageId,Name,CreationDate]" \
  --output table
```

Read the release from the name. The last line by creation date is not necessarily the newest
release, because Red Hat rebuilds older minor releases after newer ones ship. On 2026-10-02 the
listing ended with these three:

```
ami-07006ea0a33e11e4e  RHEL-9.6.0_HVM-20260811-x86_64-0-Hourly2-GP3  2026-08-11
ami-0fec1400d2a5313ec  RHEL-9.8.0_HVM-20260908-x86_64-0-Hourly2-GP3  2026-09-10
ami-0b07d2bc8152a1d84  RHEL-9.6.0_HVM-20260922-x86_64-0-Hourly2-GP3  2026-09-22
```

The last line is a rebuild of RHEL 9.6. The newest release among them is 9.8, one line up.

### One-time setup (done once per AWS account)

Substitute `${AWS_REGION}`, `${AWS_ACCOUNT_ID}`, `${RHEL9_PARENT_AMI}`,
`${IMAGE_BUILDER_INSTANCE_PROFILE}`, `${BUILD_SECURITY_GROUP_ID}`, `${BUILD_SUBNET_ID}`, and
`${ENVIRONMENT}` first. The build instance profile is the one described under "IAM requirements"
in `safe_agents/arms/ec2/ami/README.md`, including write access to the log prefix
`image-builder-logs/`: this arm's `infra-config.json` logs to the same place.

Step 1 uploads the component and creates it from the upload. `create-component` accepts at most
16,000 characters through `--data`, and this file is larger, so it is passed with `--uri` (the EC2
arm's component is under the limit and its runbook passes it inline). The object goes in the
environment's deploy bucket, the one `infra-config.json` already logs to, under a prefix of its
own. Its key carries the component version and moves with `--semantic-version`.

```sh
# 1. Component: upload the file, then create the component from the upload
COMPONENT_URI="s3://safe-agents-${ENVIRONMENT}-deploy/image-builder-components/safe-agents-base-rhel-2.0.0.yaml"
aws s3 cp image-builder/component-base.yaml "$COMPONENT_URI"
aws imagebuilder create-component \
  --name safe-agents-base-rhel \
  --semantic-version 2.0.0 \
  --platform Linux \
  --supported-os-versions '["Red Hat Enterprise Linux 9"]' \
  --uri "$COMPONENT_URI" \
  --region "$AWS_REGION"

# 2. Infrastructure configuration
aws imagebuilder create-infrastructure-configuration \
  --cli-input-json file://image-builder/infra-config.json

# 3. Distribution configuration
aws imagebuilder create-distribution-configuration \
  --cli-input-json file://image-builder/dist-config.json

# 4. Recipe (resolve ${RHEL9_PARENT_AMI} first)
aws imagebuilder create-image-recipe \
  --cli-input-json file://image-builder/recipe-base.json

# 5. Pipeline
aws imagebuilder create-image-pipeline \
  --cli-input-json file://image-builder/pipeline.json
```

An account that already has the pipeline from an earlier component version keeps that pipeline.
After creating the new component and recipe (steps 1 and 4), move it with
`aws imagebuilder update-image-pipeline --image-pipeline-arn <PIPELINE_ARN> --image-recipe-arn <new recipe ARN> ...`.
The `...` is every other setting in `pipeline.json`. AWS documents, in the Image Builder API
reference for `UpdateImagePipeline`, that the call replaces the pipeline's whole configuration: a
setting left out is removed or reset to its default, and the default status is `ENABLED`. Pass the
infrastructure and distribution configuration ARNs, the schedule and `--status DISABLED` again.

### Triggering a bake

```sh
aws imagebuilder start-image-pipeline-execution \
  --image-pipeline-arn <PIPELINE_ARN>
```

A bake runs roughly **20–35 minutes** (RHEL `dnf update` + the full toolchain install + the
validate phase).

### The weekly schedule ships off

`pipeline.json` carries a weekly schedule (Sunday 03:00 UTC, when RHEL updates are
available) and `"status": "DISABLED"`, so a pipeline created from it never bakes on a
timer. A bake is a deliberate act. Provisioning launches the AMI the operator names with
`--ami-id`, so a scheduled bake does not change what a normal provision launches. It changes
what a provision run under `--allow-newest-ami` picks up, and it adds images nobody reviewed
to the set the bake tag lists.

Run a bake by hand with the command above. `start-image-pipeline-execution` starts a build
whether the pipeline is enabled or disabled (AWS documents this in the Image Builder API
reference for `StartImagePipelineExecution`). To turn the schedule on for an account, set
`"status": "ENABLED"` in the deployed pipeline with `aws imagebuilder update-image-pipeline`
(which replaces the whole pipeline configuration; see the note under one-time setup);
the copy in this repository stays `DISABLED`, and
`safe_agents/arms/tests/test_image_builder_definitions.py` fails if it does not.

## Tearing down bake artifacts

The teardown engine is shared with the EC2 arm (`bake_teardown`); the RHEL wrapper
(`teardown.py`) supplies the `safe-agents-base-rhel` prefix + `safe-agents:ami=base-rhel` tag.
Drive it via the generalized CLI:

```sh
cd core && .venv/bin/python bin/destroy-image --arm rhel-openshell [--env development] [--dry-run]
```

It removes the RHEL AMIs + snapshots, the RHEL Image Builder resources, the RHEL IB IAM
role+profile, and this bake's `image-builder-logs/` objects. It **never** deletes the shared
deploy bucket or the infra stacks. It does not remove the component file uploaded under
`image-builder-components/` in one-time setup; delete that object by hand.

## HARNESS-COUPLING note

The `ClaudeCodeCLI` step in `component-base.yaml` is the **only** place this bake couples to
Claude Code. To swap harnesses, replace only that step.
