# arms/rhel_openshell/ami — prebuilt RHEL 9 base-AMI bakery

This directory owns the **prebuilt-AMI bootstrap model** (sa#109) for the `rhel-openshell`
arm. It mirrors the EC2 arm's bakery (`arms/ec2/ami`), adapted for RHEL 9 x86_64.

## Why prebuilt AMI instead of boot-time internet install

The RHEL two-box arm places the box in the **isolated agent subnet** (sa#35) — no NAT, no
internet route; only the S3 gateway endpoint and the broker/AWS interface endpoints are
reachable. But RHEL's `user-data.sh.tmpl` + `bootstrap.sh` install their toolchain at boot
over the internet (SSM agent, AWS CLI, `dnf` core tools, Node.js, and `claude` via **npm** —
which is **not** S3-backed). A fresh box in the isolated subnet therefore cannot complete
bootstrap.

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
| AWS CLI installer | `awscli-exe-linux-aarch64.zip` | `awscli-exe-linux-x86_64.zip` |
| SSM agent | present on AL2023 | **baked** (RHEL AMIs omit it) |
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
- **AWS CLI v2** (x86_64 installer) — `user-data.sh.tmpl` step 4.
- **Core `dnf` toolchain** — `bootstrap/scripts/install-tools.sh` (git, jq, tar, gcc, tmux,
  buildah/skopeo, the `-devel` set, plus EPEL htop/bat/ripgrep and `gh`).
- **Node.js 20.x** (NodeSource) — required by the Claude Code CLI.
- **uv + ruff** — `bootstrap/scripts/install-python-env.sh`.
- **python3-pyyaml** — the conformance harness imports `yaml` on the system `python3`.
- **Claude Code CLI** (`@anthropic-ai/claude-code` via npm) — the sole HARNESS-COUPLING step,
  mirroring `bootstrap/scripts/setup-claude.sh`.

## AMI tagging convention

Every baked AMI carries these tags (set by `dist-config.json`):

| Tag | Value |
|---|---|
| `safe-agents:ami` | `base-rhel` |
| `safe-agents:ami-version` | UTC build timestamp (`{{imagebuilder:buildDate}}`) |
| `Project` | `safe-agents` |
| `ManagedBy` | `safe-agents-image-builder` |

`rhel_openshell_provision` selects the **newest self-owned AMI** tagged
`safe-agents:ami=base-rhel` (via `_resolve_base_ami`). When no bake exists it falls back to the
RHEL 9 marketplace AMI (Red Hat owner `309956199498` + name filter) — the pre-sa#109 behavior,
which only completes bootstrap in a subnet with egress.

## Baking the base AMI

### Resolve the RHEL 9 x86_64 parent AMI first

The recipe's `parentImage` is a `${RHEL9_PARENT_AMI}` placeholder — RHEL is a marketplace AMI,
so there is no AWS-managed Image Builder parent. Resolve the current RHEL 9 x86_64 AMI ID (the
same lookup `provision.py` uses) and substitute it:

```sh
aws ec2 describe-images --owners 309956199498 \
  --filters "Name=name,Values=RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3" \
  --query "sort_by(Images, &CreationDate)[-1].{id:ImageId,name:Name}" \
  --output table
```

### One-time setup (done once per AWS account)

Substitute `${AWS_REGION}`, `${AWS_ACCOUNT_ID}`, `${RHEL9_PARENT_AMI}`,
`${IMAGE_BUILDER_INSTANCE_PROFILE}`, `${BUILD_SECURITY_GROUP_ID}`, `${BUILD_SUBNET_ID}`, and
`${ENVIRONMENT}` first.

```sh
# 1. Component
aws imagebuilder create-component \
  --name safe-agents-base-rhel \
  --semantic-version 1.0.0 \
  --platform Linux \
  --supported-os-versions '["Red Hat Enterprise Linux 9"]' \
  --data file://image-builder/component-base.yaml \
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

### Triggering a bake

```sh
aws imagebuilder start-image-pipeline-execution \
  --image-pipeline-arn <PIPELINE_ARN>
```

A bake runs roughly **20–35 minutes** (RHEL `dnf update` + the full toolchain install + the
validate phase). The pipeline also runs weekly (Sunday 03:00 UTC) when RHEL component updates
are available.

## Tearing down bake artifacts

The teardown engine is shared with the EC2 arm (`bake_teardown`); the RHEL wrapper
(`teardown.py`) supplies the `safe-agents-base-rhel` prefix + `safe-agents:ami=base-rhel` tag.
Drive it via the generalized CLI:

```sh
cd core && .venv/bin/python bin/destroy-image --arm rhel-openshell [--env development] [--dry-run]
```

It removes the RHEL AMIs + snapshots, the RHEL Image Builder resources, the RHEL IB IAM
role+profile, and this bake's `image-builder-logs/` objects. It **never** deletes the shared
deploy bucket or the infra stacks.

## HARNESS-COUPLING note

The `ClaudeCodeCLI` step in `component-base.yaml` is the **only** place this bake couples to
Claude Code. To swap harnesses, replace only that step.
