#!/bin/bash
# install-python-env.sh — Python environment setup.
# Faithful snapshot from a development harness (scripts/install-python-env.sh), adapted:
#   - No requirements.txt install: the bootstrap bundle is platform-only, not
#     project-specific. Agent-specific packages are delivered via the agent bundle.
#   - Miniconda install is gated: it's heavy (hundreds of MB) and not needed for
#     the autonomous agent profile; it remains here for the interactive profile.
#
# Pinned downloads (safe_agents/arms/toolchain/README.md):
#   - uv is its pinned release archive, fetched with fetch_verified. No installer script.
#   - ruff installs from toolchain/python-tools.txt, a hash lock, with --require-hashes.
#     pip refuses any file whose hash the lock does not list.
#   - pip is the python3-pip package dnf ships. It is not upgraded from PyPI.
#   - A failed fetch or a hash mismatch stops the bootstrap; there is no fallback.
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# The rhel-bootstrap bundle carries the helper and the Python lock beside scripts/ (the
# bundle builder, safe_agents/arms/ec2/ami/bundle.py, copies both from
# safe_agents/arms/toolchain/). A bundle without them stops here, on the missing file.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=../../../toolchain/fetch-verified.sh
. "${SCRIPT_DIR}/../toolchain/fetch-verified.sh"
PYTHON_TOOLS_LOCK="${SCRIPT_DIR}/../toolchain/python-tools.txt"
# A root-owned virtualenv, so the tools are isolated from the distro's Python packages.
PYTHON_TOOLS_VENV=/opt/safe-agents/python-tools

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "Setting up Python environment..."

# AL2023 and RHEL 9 ship Python 3.x; ensure pip is present.
# Offline guard: when pip is already there (baked AMI), do not touch dnf. The isolated
# no-NAT subnet cannot reach it.
if python3 -m pip --version &>/dev/null; then
    log "pip already present — skipping install (offline-safe on the baked AMI)"
else
    log "pip not found — installing python3-pip via dnf (requires egress)..."
    $SUDO dnf install -y python3-pip
fi

PYTHON_VERSION=$(python3 --version 2>/dev/null | awk '{print $2}')
log "Python version: ${PYTHON_VERSION}"

# Install uv (fast Python package manager — used by agent tools).
log "Installing uv..."
if ! command -v uv &>/dev/null; then
    fetch_verified \
        https://github.com/astral-sh/uv/releases/download/0.12.22/uv-x86_64-unknown-linux-gnu.tar.gz \
        b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b \
        "${WORK}/uv.tar.gz"
    mkdir -p "${WORK}/uv"
    tar -xzf "${WORK}/uv.tar.gz" -C "${WORK}/uv" --strip-components=1
    # The archive holds two executables and nothing else: uv, and the alias for its
    # run-a-tool subcommand. Both go to /usr/local/bin, as the upstream installer put them.
    $SUDO install -m 0755 "${WORK}"/uv/* /usr/local/bin/
    log "uv installed: $(uv --version)"
else
    log "uv already installed: $(uv --version 2>/dev/null || echo 'installed')"
fi

# Install ruff (linter — used in pre-commit and agent workflows).
# Offline guard: skip when already baked in. When it is missing, the install needs PyPI,
# and a failure here stops the bootstrap like any other failed install.
log "Installing ruff..."
if command -v ruff &>/dev/null; then
    log "ruff already installed: $(ruff --version 2>/dev/null || echo 'installed')"
else
    [ -r "$PYTHON_TOOLS_LOCK" ] || {
        log "ERROR: ${PYTHON_TOOLS_LOCK} is missing; the rhel-bootstrap bundle must carry it"
        exit 1
    }
    $SUDO python3 -m venv "$PYTHON_TOOLS_VENV"
    $SUDO "${PYTHON_TOOLS_VENV}/bin/python" -m pip install --no-cache-dir --require-hashes -r "$PYTHON_TOOLS_LOCK"
    $SUDO ln -sf "${PYTHON_TOOLS_VENV}/bin/ruff" /usr/local/bin/ruff
    log "ruff installed: $(ruff --version)"
fi

log "Python environment setup complete!"
log "Python: ${PYTHON_VERSION}"
