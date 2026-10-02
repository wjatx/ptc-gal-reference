#!/bin/bash
# setup-claude.sh — Claude Code CLI install and bootstrap-time oauth check.
# Adapted from a development harness (scripts/setup-claude.sh) for the S3 delivery model:
# no git repo available on the box; no bin/ to copy.
#
# This script is ONE OF ONLY TWO places safe-agents couples to Claude Code
# specifically (the other is the memory SessionStart loader). All other
# bootstrap, two-identity split, run-record wiring, and broker sidecar code
# is harness-neutral.
#
# To swap harnesses: replace ONLY this script. Everything else in bootstrap.sh
# and user-data.sh.tmpl stays.

# ── ── HARNESS-COUPLING BLOCK START ──────────────────────────────────────────
# What this block does:
#   1. Install the Claude Code native binary from its pinned release
#      (safe_agents/arms/toolchain/README.md, "Claude Code"). It is one self-contained
#      executable and needs no Node.js. It is never installed with npm.
#   2. Set DISABLE_UPDATES=1 in the managed settings, so the binary never updates itself
#      past the pin.
#   3. Verify the OAuth token is reachable from Secrets Manager (bootstrap-time check).
#      The token is NOT persisted here — run-agent.sh fetches it fresh at each invocation.
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

MANAGED_SETTINGS=/etc/claude-code/managed-settings.json

log "Setting up Claude Code environment..."

# /usr/local/bin must be on PATH — RHEL login shells omit it; claude is installed there.
export PATH="/usr/local/bin:$HOME/.local/bin:$PATH"
# The pin holds for this script's own run of the CLI too, before any settings file is read.
export DISABLE_UPDATES=1

if ! command -v claude &>/dev/null; then
    # x86_64 only, like the arm. The binary at this pin ran on RHEL 9 in the component bake
    # of 2026-10-02 (ami/README.md). This script's own download and install has not run on
    # a host in this form.
    fetch_verified \
        https://downloads.claude.ai/claude-code-releases/2.1.285/linux-x64/claude \
        33dad1ec615a2e08cc78b494f05c110e49916de2c79d78ec8799ebf46b233d29 \
        "${WORK}/claude"
    $SUDO install -m 0755 "${WORK}/claude" /usr/local/bin/claude
    log "Claude Code binary installed to /usr/local/bin/claude"
else
    log "Claude Code already installed (baked AMI)"
fi

# Managed settings apply to every user on the box and cannot be overridden by a user's own
# settings. Anything already in the file is kept; only env.DISABLE_UPDATES is set. Written
# on every run, so a box baked before this setting existed gets it at boot.
$SUDO install -d -m 0755 /etc/claude-code
$SUDO python3 - "$MANAGED_SETTINGS" <<'PY'
import json, pathlib, sys

path = pathlib.Path(sys.argv[1])
settings = json.loads(path.read_text()) if path.exists() else {}
settings.setdefault("env", {})["DISABLE_UPDATES"] = "1"
path.write_text(json.dumps(settings, indent=2) + "\n")
PY
$SUDO chmod 0644 "$MANAGED_SETTINGS"

# Run it once. A binary that cannot execute on this host stops the bootstrap here, not at
# the first agent turn.
CLAUDE_VERSION="$(claude --version)"
log "Claude Code version: ${CLAUDE_VERSION}"

mkdir -p ~/bin ~/.claude ~/claude-agents/logs ~/claude-agents/results

# Bootstrap-time oauth token check (agentRole: agent's own oauth_token path only).
# Connector credentials are NOT fetched here; those are broker-only territory.
# SA_OAUTH_TOKEN_SECRET is set by user-data.sh.tmpl before calling bootstrap.sh.
if [ -n "${SA_OAUTH_TOKEN_SECRET:-}" ]; then
    log "Verifying oauth token is reachable (Secrets Manager: ${SA_OAUTH_TOKEN_SECRET})"
    TOKEN=$(aws secretsmanager get-secret-value \
        --secret-id "${SA_OAUTH_TOKEN_SECRET}" \
        --query SecretString \
        --output text 2>/dev/null) || {
        log "WARNING: could not fetch oauth token from ${SA_OAUTH_TOKEN_SECRET}"
        log "  The agent will fail at run time if this is not resolved."
        TOKEN=""
    }
    if [ -n "$TOKEN" ]; then
        log "oauth token reachable (length: ${#TOKEN})"
    fi
    unset TOKEN
else
    log "SA_OAUTH_TOKEN_SECRET not set — skipping oauth token check"
fi

log "Claude Code setup complete."
log ""
log "Auth notes:"
log " - Autonomous agents: oauth token fetched from Secrets Manager at each run by run-agent.sh."
log " - Remote Control (interactive profile only): run 'claude' then /login (claude.ai) ONCE."
log "   Do NOT set CLAUDE_CODE_OAUTH_TOKEN — Remote Control rejects the setup-token."
# ── HARNESS-COUPLING BLOCK END ────────────────────────────────────────────────
