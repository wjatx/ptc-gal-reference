#!/bin/bash
# setup-claude.sh — Claude Code CLI install and bootstrap-time oauth check.
# Adapted from a development harness (scripts/setup-claude.sh) for the S3 delivery model:
# no git repo available on the box; no bin/ to copy.
#
# This script is ONE OF ONLY TWO places safe-agents couples to Claude Code
# specifically (the other is the memory SessionStart loader, #71). All other
# bootstrap, two-identity split, run-record wiring, and broker sidecar code
# is harness-neutral.
#
# To swap harnesses: replace ONLY this script. Everything else in bootstrap.sh
# and user-data.sh.tmpl stays.

# ── ── HARNESS-COUPLING BLOCK START ──────────────────────────────────────────
# What this block does:
#   1. Install the @anthropic-ai/claude-code CLI via npm (Node.js from install-tools.sh).
#   2. Verify the OAuth token is reachable from Secrets Manager (bootstrap-time check).
#      The token is NOT persisted here — run-agent.sh fetches it fresh at each invocation.
set -euo pipefail

log() { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*"; }

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

log "Setting up Claude Code environment..."

# /usr/local/bin must be on PATH — RHEL login shells omit it; claude is installed there.
export PATH="/usr/local/bin:$HOME/.local/bin:$PATH"

# `npm install -g` writes to the system npm prefix (/usr/lib/node_modules) which
# requires root when node was installed via dnf.
if ! command -v claude &>/dev/null; then
    $SUDO npm install -g @anthropic-ai/claude-code
    log "Claude Code installed: $(claude --version 2>/dev/null || echo 'installed')"
else
    log "Claude Code already installed: $(claude --version 2>/dev/null)"
fi

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
