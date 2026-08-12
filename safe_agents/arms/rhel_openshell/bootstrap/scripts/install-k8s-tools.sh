#!/bin/bash
# install-k8s-tools.sh — Kubernetes/OpenShift and DevOps tools.
# Faithful snapshot from a development harness (scripts/install-k8s-tools.sh).
#
# GATED: only run in SA_PROFILE=interactive (called by bootstrap.sh under the
# SA_PROFILE check). The autonomous agent profile has no need for k8s/DevOps
# tooling; excluding them keeps the autonomous footprint lean.
#
# Tools: oc/kubectl, Helm, ArgoCD CLI, Terraform, AWS CLI, yq, uv, gitleaks.
# Hard-won lessons preserved:
#   - Helm: download the tarball directly rather than piping to get-helm-3 (the
#     installer script's post-install PATH verification fails in non-interactive
#     login shells even though it writes to /usr/local/bin)
#   - Terraform: HashiCorp DNF repo uses RHEL version paths that don't exist for
#     AL2023 (e.g. 2023.12.YYYYMMDD), so install via direct binary download
#   - AWS CLI: RHEL 9 AMI may ship a pre-installed copy at /usr/local/aws-cli/v2/current
#     (not yet in PATH); use --update so the installer is idempotent
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# OpenShift CLI (oc and kubectl)
log "Installing OpenShift CLI..."
if ! command -v oc &>/dev/null; then
    OC_VERSION="4.17.0"
    curl -LO "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/${OC_VERSION}/openshift-client-linux.tar.gz"
    tar xzf openshift-client-linux.tar.gz
    $SUDO mv oc kubectl /usr/local/bin/
    rm -f openshift-client-linux.tar.gz README.md
    log "oc $(oc version --client 2>/dev/null | head -1) installed"
else
    log "oc already installed: $(oc version --client 2>/dev/null | head -1)"
fi

# Helm — download the tarball directly (see note above about get-helm-3 PATH issue).
log "Installing Helm..."
if ! command -v helm &>/dev/null; then
    HELM_VERSION=$(curl -fsSL https://api.github.com/repos/helm/helm/releases/latest \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])")
    log "Downloading Helm ${HELM_VERSION}..."
    curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o helm.tar.gz
    tar xzf helm.tar.gz
    $SUDO mv linux-amd64/helm /usr/local/bin/
    rm -rf linux-amd64 helm.tar.gz
    log "Helm $(/usr/local/bin/helm version --short) installed"
else
    log "Helm already installed: $(helm version --short)"
fi

# ArgoCD CLI
log "Installing ArgoCD CLI..."
if ! command -v argocd &>/dev/null; then
    curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
    $SUDO install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
    rm argocd-linux-amd64
    log "ArgoCD CLI $(argocd version --client 2>/dev/null | head -1) installed"
else
    log "ArgoCD CLI already installed: $(argocd version --client 2>/dev/null | head -1)"
fi

# Terraform (direct binary — HashiCorp repo has RHEL version path issues, see note above)
log "Installing Terraform..."
if ! command -v terraform &>/dev/null && ! test -x /usr/local/bin/terraform; then
    TF_VERSION=$(curl -fsSL https://api.releases.hashicorp.com/v1/releases/terraform/latest \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])")
    log "Downloading Terraform ${TF_VERSION}..."
    curl -fsSL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip" \
        -o terraform.zip
    unzip -q terraform.zip
    $SUDO mv terraform /usr/local/bin/
    rm terraform.zip
    log "Terraform $(/usr/local/bin/terraform version | head -1) installed"
else
    log "Terraform already installed: $(/usr/local/bin/terraform version 2>/dev/null | head -1 || terraform version | head -1)"
fi

# AWS CLI v2 (idempotent --update handles both fresh install and update)
log "Installing AWS CLI..."
if ! command -v aws &>/dev/null && ! test -x /usr/local/bin/aws; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    $SUDO ./aws/install --update
    rm -rf aws awscliv2.zip
    log "AWS CLI $(/usr/local/bin/aws --version 2>&1) installed"
else
    log "AWS CLI already installed: $(/usr/local/bin/aws --version 2>&1 || aws --version 2>&1)"
fi

# yq
log "Installing yq..."
if ! command -v yq &>/dev/null && ! test -x /usr/local/bin/yq; then
    YQ_VERSION="v4.44.1"
    curl -LO "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
    chmod +x yq_linux_amd64
    $SUDO mv yq_linux_amd64 /usr/local/bin/yq
    log "yq $(/usr/local/bin/yq --version) installed"
else
    log "yq already installed: $(/usr/local/bin/yq --version 2>/dev/null || yq --version)"
fi

# gitleaks
log "Installing gitleaks..."
if ! [ -f ~/bin/gitleaks ]; then
    mkdir -p ~/bin
    GITLEAKS_VERSION="8.18.4"
    curl -LO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    tar xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks
    mv gitleaks ~/bin/
    rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    log "gitleaks installed to ~/bin"
else
    log "gitleaks already installed"
fi

log "K8s/DevOps tools installation complete!"
