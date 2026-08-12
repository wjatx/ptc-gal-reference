#!/bin/bash
# install-tools.sh — System packages and core CLI tools.
# Faithful snapshot from a development harness (scripts/install-tools.sh).
# Hard-won lessons preserved:
#   - EPEL must be added before htop/bat/ripgrep (they live in EPEL, not BaseOS/AppStream)
#   - CRB (CodeReady Builder) required by some EPEL packages on RHEL 9; both
#     RHUI and standard names are tried
#   - --allowerasing avoids the curl-minimal conflict (RHEL 9 ships curl-minimal by default)
#   - bat and ripgrep fall back to direct binary download if not in repos
#   - tmux is required by run-agent-sandbox.sh for the flock concurrency gate
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

log "Installing system packages..."

# Offline guard (sa#109): the prebuilt AMI bakes the whole core toolchain (the
# devel libs ride along with these command-providing packages), and the box sits
# in the isolated no-NAT subnet where dnf/EPEL are unreachable — even the EPEL
# repolist probe can hang or fail there. Only touch the repos + dnf when one of
# the core binaries is actually missing (marketplace AMI with egress).
_CORE_CMDS="git jq unzip tar curl wget buildah skopeo tree tmux vim make gcc g++"
_MISSING_CMDS=""
for _cmd in $_CORE_CMDS; do
    command -v "$_cmd" &>/dev/null || _MISSING_CMDS="${_MISSING_CMDS} ${_cmd}"
done

if [ -z "$_MISSING_CMDS" ]; then
    log "Core CLI tools already present (baked AMI) — skipping EPEL/CRB setup and dnf core install"
else
    log "Missing core tools:${_MISSING_CMDS} — installing via dnf (requires egress)"

    # EPEL (RHEL 9): htop and several CLI tools below live in EPEL, not base/AppStream.
    # Well-supported on RHEL 9 (the AWS AMI's RHUI provides base/AppStream without a
    # subscription); EPEL itself is a one-line add.
    # Check both the RPM and the active repo list — stale RPM db state can make the
    # rpm -q pass while the repo isn't actually configured.
    if ! rpm -q epel-release >/dev/null 2>&1 || ! $SUDO dnf repolist 2>/dev/null | grep -q "^epel"; then
        $SUDO dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
    fi

    # CRB (CodeReady Builder) is required by some EPEL packages on RHEL 9.
    # Enable preemptively — benign no-op if a package doesn't need it.
    # On RHUI-backed AMIs the repo is named with the -rhui- infix.
    $SUDO dnf config-manager --set-enabled codeready-builder-for-rhel-9-rhui-rpms 2>/dev/null \
        || $SUDO dnf config-manager --set-enabled crb 2>/dev/null \
        || log "Note: CRB repo not found under known names — skipping (may not be needed)"

    # Core system packages (all in BaseOS / AppStream — no EPEL needed).
    # --allowerasing: both RHEL 9 and AL2023 ship `curl-minimal`; installing full `curl`
    # conflicts, so this lets dnf swap them instead of aborting.
    # tmux: required by run-agent-sandbox.sh for the flock-based concurrency gate.
    $SUDO dnf install -y --allowerasing \
        git \
        jq \
        unzip \
        tar \
        curl \
        wget \
        buildah \
        skopeo \
        tree \
        tmux \
        vim \
        make \
        gcc \
        gcc-c++ \
        openssl-devel \
        bzip2-devel \
        libffi-devel \
        zlib-devel \
        readline-devel \
        sqlite-devel \
        xz-devel
fi

# htop lives in EPEL (installed above); install it after EPEL is confirmed active.
log "Installing htop..."
if ! command -v htop &>/dev/null; then
    $SUDO dnf install -y htop 2>/dev/null || log "Warning: htop not available — skipping"
fi

# Try to install from EPEL/repos first, fall back to manual binary install.
log "Installing bat..."
if ! command -v bat &>/dev/null; then
    $SUDO dnf install -y bat 2>/dev/null || {
        log "bat not in repos, downloading binary..."
        BAT_VERSION="0.24.0"
        curl -LO "https://github.com/sharkdp/bat/releases/download/v${BAT_VERSION}/bat-v${BAT_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
        tar xzf "bat-v${BAT_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
        $SUDO mv "bat-v${BAT_VERSION}-x86_64-unknown-linux-gnu/bat" /usr/local/bin/
        rm -rf "bat-v${BAT_VERSION}-x86_64-unknown-linux-gnu" "bat-v${BAT_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
    }
fi

log "Installing ripgrep..."
if ! command -v rg &>/dev/null; then
    $SUDO dnf install -y ripgrep 2>/dev/null || {
        log "ripgrep not in repos, downloading binary..."
        RG_VERSION="14.1.0"
        curl -LO "https://github.com/BurntSushi/ripgrep/releases/download/${RG_VERSION}/ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl.tar.gz"
        tar xzf "ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl.tar.gz"
        $SUDO mv "ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl/rg" /usr/local/bin/
        rm -rf "ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl" "ripgrep-${RG_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    }
fi

log "Installing GitHub CLI..."
if ! command -v gh &>/dev/null; then
    $SUDO dnf install -y 'dnf-command(config-manager)'
    $SUDO dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
    $SUDO dnf install -y gh
fi

log "Installing Node.js (20.x LTS)..."
if ! command -v node &>/dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | $SUDO bash -
    $SUDO dnf install -y nodejs
fi

log "System tools installation complete!"
