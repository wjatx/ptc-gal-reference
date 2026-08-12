#!/bin/bash
# install-python-env.sh — Python environment setup.
# Faithful snapshot from a development harness (scripts/install-python-env.sh), adapted:
#   - No requirements.txt install: the bootstrap bundle is platform-only, not
#     project-specific. Agent-specific packages are delivered via the agent bundle.
#   - Miniconda install is gated: it's heavy (hundreds of MB) and not needed for
#     the autonomous agent profile; it remains here for the interactive profile.
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

log "Setting up Python environment..."

# AL2023 and RHEL 9 ship Python 3.x; ensure pip is present.
# Offline guard (sa#109): when pip is already there (baked AMI), touch neither dnf
# nor PyPI — the isolated no-NAT subnet can reach neither, and an unconditional
# `pip install --upgrade pip` aborts the whole bootstrap under `set -e`.
if python3 -m pip --version &>/dev/null; then
    log "pip already present — skipping install/upgrade (offline-safe on the baked AMI)"
else
    log "pip not found — installing python3-pip via dnf (requires egress)..."
    $SUDO dnf install -y python3-pip
    log "Upgrading pip..."
    python3 -m pip install --upgrade pip
fi

PYTHON_VERSION=$(python3 --version 2>/dev/null | awk '{print $2}')
log "Python version: ${PYTHON_VERSION}"

# Install uv (fast Python package manager — used by ruff and agent tools).
log "Installing uv..."
if ! command -v uv &>/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="${HOME}/.local/bin:$PATH"
    log "uv installed"
else
    log "uv already installed: $(uv --version 2>/dev/null || echo 'installed')"
fi

# Install ruff (linter — used in pre-commit and agent workflows).
# Offline guard (sa#109): skip when already baked in. If it is missing AND the box
# has no egress, warn loudly but do NOT abort — ruff is lint tooling, not part of
# the autonomous run path, and failing here would kill bootstrap before the netns
# confinement units install.
log "Installing ruff..."
if command -v ruff &>/dev/null; then
    log "ruff already installed: $(ruff --version 2>/dev/null || echo 'installed')"
elif command -v uv &>/dev/null; then
    uv tool install ruff 2>/dev/null || pip install --user ruff \
        || log "WARNING: ruff install failed (no egress?) — continuing; ruff is not required for the autonomous run path"
else
    pip install --upgrade ruff \
        || log "WARNING: ruff install failed (no egress?) — continuing; ruff is not required for the autonomous run path"
fi

log "Python environment setup complete!"
log "Python: ${PYTHON_VERSION}"
