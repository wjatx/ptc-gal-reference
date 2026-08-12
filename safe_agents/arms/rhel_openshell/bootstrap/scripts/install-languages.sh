#!/bin/bash
# install-languages.sh — Go and Rust installation.
# Faithful snapshot from a development harness (scripts/install-languages.sh).
#
# GATED: only run in SA_PROFILE=interactive (called by bootstrap.sh under the
# SA_PROFILE check). The autonomous agent profile has no need for Go or Rust
# build chains; excluding them keeps the autonomous footprint lean.
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Go
GO_VERSION="1.23.4"
log "Installing Go ${GO_VERSION}..."

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    log "Go already installed: ${CURRENT_GO}"
else
    log "Downloading Go ${GO_VERSION}..."
    curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
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
    log "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    log "Rust $(rustc --version) installed"
fi

log "Languages installation complete!"
log "Go: $(go version 2>/dev/null || echo 'not in PATH yet')"
log "Rust: $(rustc --version 2>/dev/null || echo 'not in PATH yet')"
