#!/bin/bash
# install-tools.sh — System packages and core CLI tools.
# Faithful snapshot from a development harness (scripts/install-tools.sh).
# Hard-won lessons preserved:
#   - htop lives in EPEL, not BaseOS/AppStream, so EPEL must be added before it
#   - CRB (CodeReady Builder) required by some EPEL packages on RHEL 9; both
#     RHUI and standard names are tried
#   - --allowerasing avoids the curl-minimal conflict (RHEL 9 ships curl-minimal by default)
#   - tmux is required by run-agent-sandbox.sh for the flock concurrency gate
#
# Pinned downloads (safe_agents/arms/toolchain/README.md):
#   - Every file fetched here is a line of toolchain/artifacts.lock, fetched with
#     fetch_verified. A hash mismatch or a pruned URL stops the bootstrap; there is no
#     fallback to another source.
#   - EPEL is added from its pinned release RPM and is used for htop alone. bat, ripgrep
#     and gh come from their pinned release archives, not from a third-party dnf repo.
#   - Node.js is not installed here. Claude Code is a native binary and needs none, so the
#     autonomous profile has no Node. The interactive profile gets it from
#     install-languages.sh.
#   - This arm is x86_64 only, and so is every pin below.
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

# install_from_tarball ARCHIVE MEMBER NAME: unpack a .tar.gz that holds one top-level
# directory and install MEMBER, a path inside that directory, as /usr/local/bin/NAME.
install_from_tarball() {
    local unpacked="${WORK}/$3"
    mkdir -p "$unpacked"
    tar -xzf "$1" -C "$unpacked" --strip-components=1
    $SUDO install -m 0755 "${unpacked}/$2" "/usr/local/bin/$3"
}

log "Installing system packages..."

# Offline guard: the prebuilt AMI bakes the whole core toolchain (the
# devel libs ride along with these command-providing packages), and the box sits
# in the isolated no-NAT subnet where dnf is unreachable. Only touch dnf when one of
# the core binaries is actually missing (marketplace AMI with egress).
_CORE_CMDS="git jq unzip tar curl wget buildah skopeo tree tmux vim make gcc g++"
_MISSING_CMDS=""
for _cmd in $_CORE_CMDS; do
    command -v "$_cmd" &>/dev/null || _MISSING_CMDS="${_MISSING_CMDS} ${_cmd}"
done

if [ -z "$_MISSING_CMDS" ]; then
    log "Core CLI tools already present (baked AMI) — skipping the dnf core install"
else
    log "Missing core tools:${_MISSING_CMDS} — installing via dnf (requires egress)"

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

# htop has no upstream binary release to pin, so it comes from EPEL. EPEL is added from
# its pinned release RPM: the repo definition and the EPEL signing key are inside that
# file, so the hash covers both, and dnf then checks htop's signature against that key.
log "Installing htop..."
if ! command -v htop &>/dev/null; then
    # Check both the RPM and the active repo list — stale RPM db state can make the
    # rpm -q pass while the repo isn't actually configured.
    if ! rpm -q epel-release >/dev/null 2>&1 || ! $SUDO dnf repolist 2>/dev/null | grep -q "^epel"; then
        fetch_verified \
            https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/e/epel-release-9-11.el9.noarch.rpm \
            b434245bffd8b40ea486157e72363d08b36e38145c8f917c5c00adfca3f2101b \
            "${WORK}/epel-release.rpm"
        $SUDO dnf install -y "${WORK}/epel-release.rpm"
    fi

    # CRB (CodeReady Builder) is required by some EPEL packages on RHEL 9.
    # Enable preemptively — benign no-op if a package doesn't need it.
    # On RHUI-backed AMIs the repo is named with the -rhui- infix.
    $SUDO dnf config-manager --set-enabled codeready-builder-for-rhel-9-rhui-rpms 2>/dev/null \
        || $SUDO dnf config-manager --set-enabled crb 2>/dev/null \
        || log "Note: CRB repo not found under known names — skipping (may not be needed)"

    $SUDO dnf install -y htop
fi

log "Installing bat..."
if ! command -v bat &>/dev/null; then
    fetch_verified \
        https://github.com/sharkdp/bat/releases/download/v0.26.1/bat-v0.26.1-x86_64-unknown-linux-gnu.tar.gz \
        726f04c8f576a7fd18b7634f1bbf2f915c43494c1c0f013baa3287edb0d5a2a3 \
        "${WORK}/bat.tar.gz"
    install_from_tarball "${WORK}/bat.tar.gz" bat bat
fi

log "Installing ripgrep..."
if ! command -v rg &>/dev/null; then
    fetch_verified \
        https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz \
        33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c \
        "${WORK}/ripgrep.tar.gz"
    install_from_tarball "${WORK}/ripgrep.tar.gz" rg rg
fi

log "Installing GitHub CLI..."
if ! command -v gh &>/dev/null; then
    fetch_verified \
        https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_linux_amd64.tar.gz \
        bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386 \
        "${WORK}/gh.tar.gz"
    install_from_tarball "${WORK}/gh.tar.gz" bin/gh gh
fi

log "System tools installation complete!"
