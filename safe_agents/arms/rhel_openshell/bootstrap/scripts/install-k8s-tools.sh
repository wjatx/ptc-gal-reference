#!/bin/bash
# install-k8s-tools.sh — Kubernetes/OpenShift and DevOps tools.
# Faithful snapshot from a development harness (scripts/install-k8s-tools.sh).
#
# GATED: only run in SA_PROFILE=interactive (called by bootstrap.sh under the
# SA_PROFILE check). The autonomous agent profile has no need for k8s/DevOps
# tooling; excluding them keeps the autonomous footprint lean.
#
# Tools: oc/kubectl, Helm, ArgoCD CLI, Terraform, yq, gitleaks.
# Hard-won lessons preserved:
#   - Helm: download the tarball directly rather than piping to get-helm-3 (the
#     installer script's post-install PATH verification fails in non-interactive
#     login shells even though it writes to /usr/local/bin)
#   - Terraform: HashiCorp DNF repo uses RHEL version paths that don't exist for
#     AL2023 (e.g. 2023.12.YYYYMMDD), so install via direct binary download
#
# Pinned downloads (safe_agents/arms/toolchain/README.md):
#   - Each tool is one pinned release file, fetched with fetch_verified. No tool's version
#     is looked up at run time. A hash mismatch or a pruned URL stops the script; there is
#     no fallback.
#   - AWS CLI v2 is not installed here. user-data installs it from its pinned archive
#     before bootstrap.sh runs (the bundle pull needs it), and the prebuilt AMI bakes the
#     same archive, so a second install procedure here would be a third copy.
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# The rhel-bootstrap bundle carries the helper beside scripts/ (the bundle builder,
# safe_agents/arms/ec2/ami/bundle.py, copies it from safe_agents/arms/toolchain/). A bundle
# without it stops here, on the missing file.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=../../../toolchain/fetch-verified.sh
. "${SCRIPT_DIR}/../toolchain/fetch-verified.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# OpenShift CLI (oc and kubectl)
log "Installing OpenShift CLI..."
if ! command -v oc &>/dev/null; then
    fetch_verified \
        https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/4.22.15/openshift-client-linux-4.22.15.tar.gz \
        106732249c301f477905e043c45141b147886af2d8179ae5da7cf5e839c8ce41 \
        "${WORK}/oc.tar.gz"
    mkdir -p "${WORK}/oc"
    tar -xzf "${WORK}/oc.tar.gz" -C "${WORK}/oc" oc
    $SUDO install -m 0755 "${WORK}/oc/oc" /usr/local/bin/oc
    # kubectl is a hard link to oc in the archive; oc acts as kubectl under that name.
    $SUDO ln -f /usr/local/bin/oc /usr/local/bin/kubectl
    log "oc $(oc version --client 2>/dev/null | head -1) installed"
else
    log "oc already installed: $(oc version --client 2>/dev/null | head -1)"
fi

# Helm — download the tarball directly (see note above about get-helm-3 PATH issue).
log "Installing Helm..."
if ! command -v helm &>/dev/null; then
    fetch_verified \
        https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz \
        86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb \
        "${WORK}/helm.tar.gz"
    mkdir -p "${WORK}/helm"
    tar -xzf "${WORK}/helm.tar.gz" -C "${WORK}/helm" --strip-components=1
    $SUDO install -m 0755 "${WORK}/helm/helm" /usr/local/bin/helm
    log "Helm $(/usr/local/bin/helm version --short) installed"
else
    log "Helm already installed: $(helm version --short)"
fi

# ArgoCD CLI
log "Installing ArgoCD CLI..."
if ! command -v argocd &>/dev/null; then
    fetch_verified \
        https://github.com/argoproj/argo-cd/releases/download/v3.5.3/argocd-linux-amd64 \
        b860f73f57cbddd993cd446f5236d797c1b1ac8554857b2683d2669f17e765b4 \
        "${WORK}/argocd"
    $SUDO install -m 555 "${WORK}/argocd" /usr/local/bin/argocd
    log "ArgoCD CLI $(argocd version --client 2>/dev/null | head -1) installed"
else
    log "ArgoCD CLI already installed: $(argocd version --client 2>/dev/null | head -1)"
fi

# Terraform (direct binary — HashiCorp repo has RHEL version path issues, see note above)
log "Installing Terraform..."
if ! command -v terraform &>/dev/null && ! test -x /usr/local/bin/terraform; then
    fetch_verified \
        https://releases.hashicorp.com/terraform/1.16.4/terraform_1.16.4_linux_amd64.zip \
        dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df \
        "${WORK}/terraform.zip"
    unzip -q "${WORK}/terraform.zip" terraform -d "${WORK}/terraform"
    $SUDO install -m 0755 "${WORK}/terraform/terraform" /usr/local/bin/terraform
    log "Terraform $(/usr/local/bin/terraform version | head -1) installed"
else
    log "Terraform already installed: $(/usr/local/bin/terraform version 2>/dev/null | head -1 || terraform version | head -1)"
fi

# AWS CLI v2: installed by user-data or baked into the AMI (see the header). Confirm it.
if command -v aws &>/dev/null || test -x /usr/local/bin/aws; then
    log "AWS CLI present: $(/usr/local/bin/aws --version 2>&1 || aws --version 2>&1)"
else
    log "ERROR: AWS CLI not found. user-data.sh.tmpl installs it before bootstrap.sh runs."
    exit 1
fi

# yq
log "Installing yq..."
if ! command -v yq &>/dev/null && ! test -x /usr/local/bin/yq; then
    fetch_verified \
        https://github.com/mikefarah/yq/releases/download/v4.54.1/yq_linux_amd64 \
        8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f \
        "${WORK}/yq"
    $SUDO install -m 0755 "${WORK}/yq" /usr/local/bin/yq
    log "yq $(/usr/local/bin/yq --version) installed"
else
    log "yq already installed: $(/usr/local/bin/yq --version 2>/dev/null || yq --version)"
fi

# gitleaks
log "Installing gitleaks..."
if ! [ -f ~/bin/gitleaks ]; then
    mkdir -p ~/bin "${WORK}/gitleaks"
    fetch_verified \
        https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
        551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb \
        "${WORK}/gitleaks.tar.gz"
    tar -xzf "${WORK}/gitleaks.tar.gz" -C "${WORK}/gitleaks" gitleaks
    install -m 0755 "${WORK}/gitleaks/gitleaks" ~/bin/gitleaks
    log "gitleaks installed to ~/bin"
else
    log "gitleaks already installed"
fi

log "K8s/DevOps tools installation complete!"
