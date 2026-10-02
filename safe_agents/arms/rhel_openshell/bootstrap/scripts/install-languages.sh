#!/bin/bash
# install-languages.sh — Go, Rust and Node.js installation.
# Faithful snapshot from a development harness (scripts/install-languages.sh).
#
# GATED: only run in SA_PROFILE=interactive (called by bootstrap.sh under the
# SA_PROFILE check). The autonomous agent profile has no need for Go, Rust or Node.js;
# excluding them keeps the autonomous footprint lean. Claude Code is a native binary, so
# no profile needs Node.js to run it.
#
# Pinned downloads (safe_agents/arms/toolchain/README.md):
#   - Each toolchain is one pinned release archive, fetched with fetch_verified. A hash
#     mismatch or a pruned URL stops the script; there is no fallback.
#   - Rust is the standalone toolchain archive, installed under /usr/local. rustup is not
#     installed: its job is to download toolchains, and none of those would be pinned.
#   - Node.js is the nodejs.org release archive, not a NodeSource repo or a dnf module.
#
# Ran once on a host, on 2026-10-02 (RHEL 9.8, launched from the baked image, in a subnet
# with egress, interactive profile; see ami/README.md). The three downloads below ran, and
# the tools then reported Go 1.27.1, Rust 1.99.0 (rustc and cargo) and Node v22.23.3 with
# npm 10.9.9. That is one run on one day.
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

# /usr/local/bin is where Rust and Node.js land; RHEL login shells omit it.
export PATH="/usr/local/bin:$PATH"

# Go
log "Installing Go..."

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    log "Go already installed: ${CURRENT_GO}"
else
    fetch_verified \
        https://go.dev/dl/go1.27.1.linux-amd64.tar.gz \
        63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445 \
        "${WORK}/go.tar.gz"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "${WORK}/go.tar.gz"
    # Ensure PATH is set (will be in bashrc.template)
    export PATH=$PATH:/usr/local/go/bin
    log "Go $(go version) installed"
fi

mkdir -p ~/go/{bin,src,pkg}

# Rust
log "Installing Rust..."

if command -v rustc &>/dev/null; then
    log "Rust already installed: $(rustc --version)"
else
    fetch_verified \
        https://static.rust-lang.org/dist/rust-1.99.0-x86_64-unknown-linux-gnu.tar.xz \
        891c6366d7100feda0bca4c03ce63f3c9ac827cbebbc283e7433061d42c6a376 \
        "${WORK}/rust.tar.xz"
    mkdir -p "${WORK}/rust"
    tar -xJf "${WORK}/rust.tar.xz" -C "${WORK}/rust" --strip-components=1
    # install.sh is part of the verified archive and copies only what the archive holds:
    # rustc, cargo and the standard library, under the prefix. It downloads nothing. The
    # offline HTML docs are most of the archive's size and are left out.
    $SUDO sh "${WORK}/rust/install.sh" --prefix=/usr/local --without=rust-docs
    log "Rust $(rustc --version) installed"
fi

# Node.js
log "Installing Node.js..."

if command -v node &>/dev/null; then
    log "Node.js already installed: $(node --version)"
else
    fetch_verified \
        https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.gz \
        1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af \
        "${WORK}/node.tar.gz"
    # Unpacked over /usr/local, the layout the archive is built for: bin/, lib/, include/
    # and share/. A global package install then lands in /usr/local too.
    $SUDO tar -xzf "${WORK}/node.tar.gz" -C /usr/local --strip-components=1 --no-same-owner
    log "Node.js $(node --version) installed"
fi

log "Languages installation complete!"
log "Go: $(go version 2>/dev/null || echo 'not in PATH yet')"
log "Rust: $(rustc --version 2>/dev/null || echo 'not in PATH yet')"
log "Node.js: $(node --version 2>/dev/null || echo 'not in PATH yet')"
