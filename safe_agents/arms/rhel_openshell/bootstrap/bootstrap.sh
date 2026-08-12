#!/bin/bash
# bootstrap.sh — RHEL+OpenShell arm box bootstrap (safe-agents).
# Snapshot-then-own from a development harness (bootstrap.sh) per safe-agents/CLAUDE.md.
#
# Runs AS the non-root 'dev' user; sudo is used where needed. Invoked by
# cloud-init user-data.sh.tmpl after the root pre-bootstrap essentials and S3
# bundle pull. The bootstrap bundle is already extracted; SCRIPT_DIR resolves
# to its location on disk.
#
# Required env vars (exported by user-data before calling this script):
#   SA_AGENT_NAME         — agent short name (e.g. "smoke-rhel-openshell")
#   SA_OAUTH_TOKEN_SECRET — Secrets Manager secret id for the oauth token
#   SA_ENVIRONMENT        — deployment environment (development|staging|production)
#   SA_ARM                — arm identifier ("rhel-openshell")
#
# SA_PROFILE controls the install footprint (default: autonomous):
#   autonomous — core tools + python + claude + the systemd system-service run
#                path ONLY. No OpenShell, no k8s, no Go/Rust, no Remote Control.
#                Egress confinement is the netns that FORWARDS to the broker SERVICE
#                (two-box model, sa#35 Option A), NOT OpenShell — the confined turn is
#                run-brokered.sh (a real brokered round-trip), so no sandbox runtime here.
#   interactive — the full development-harness toolchain on top of autonomous: OpenShell sandbox
#                 runtime, k8s, Go, Rust, Remote Control — the dev-box / travel-coding
#                 use case where the x86_64+RHEL environment supports OpenShell.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${HOME}/safe-agents-bootstrap.log"
SA_PROFILE="${SA_PROFILE:-autonomous}"

log()   { echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $*" | tee -a "$LOG"; }
error() { log "ERROR: $*"; exit 1; }

[ "$EUID" -eq 0 ] && error "Do not run as root. Run as the 'dev' user (sudo is used where needed)."

log "=============================================="
log "safe-agents RHEL bootstrap — profile=${SA_PROFILE}"
log "  agent:   ${SA_AGENT_NAME:-<unset>}"
log "  arm:     ${SA_ARM:-<unset>}"
log "  env:     ${SA_ENVIRONMENT:-<unset>}"
log "=============================================="
chmod +x "${SCRIPT_DIR}/scripts/"*.sh 2>/dev/null || true

# ── Step 1: System packages + core CLI tools ──────────────────────────────────
log "Step 1/3 (always): system packages + core CLI tools"
"${SCRIPT_DIR}/scripts/install-tools.sh" 2>&1 | tee -a "$LOG"

# ── Step 2: Python environment ────────────────────────────────────────────────
log "Step 2/3 (always): Python environment"
"${SCRIPT_DIR}/scripts/install-python-env.sh" 2>&1 | tee -a "$LOG"

# ── Step 3: Claude Code CLI ── HARNESS-COUPLING BLOCK ────────────────────────
# Installs the claude CLI via npm and verifies the oauth token is reachable.
# This is one of exactly two places safe-agents couples to Claude Code specifically.
log "Step 3/3 (always): Claude Code CLI (HARNESS-COUPLING BLOCK)"
"${SCRIPT_DIR}/scripts/setup-claude.sh" 2>&1 | tee -a "$LOG"

# OpenShell is NOT installed here. The autonomous profile's egress confinement is the
# netns + broker-proxy model (docs/model-egress.md, sa#35), not the OpenShell sandbox.
# OpenShell installs only under SA_PROFILE=interactive (the dev-box arm) — see below.

# ── Agent directory ───────────────────────────────────────────────────────────
AGENT_DIR="/opt/agents/${SA_AGENT_NAME}"
sudo mkdir -p "${AGENT_DIR}"
sudo chown -R dev:dev "${AGENT_DIR}"

# Which executable the systemd run service ExecStarts (set per profile below).
RUN_EXEC=""

if [ "${SA_PROFILE}" = "autonomous" ]; then
    # ── Autonomous egress confinement: netns forwards to the broker SERVICE (sa#35, Option A) ──
    # Converged TWO-BOX model: the agent runs inside a network namespace that FORWARDS to the
    # external broker SERVICE (broker.safe-agents.local), NOT a co-located model-proxy stub. The
    # confined turn does a REAL brokered round-trip (claude -p via the broker proxy + a brokered
    # github.whoami) and writes a run record — run-brokered.sh, with a host/netns split (oauth
    # fetch + run record on the HOST, the confined turn via `ip netns exec`). There is NO on-box
    # proxy any more — the broker is its own service. Scope: NETWORK confinement only (fs is sa#95).
    log "[autonomous] installing netns + broker-service wiring (sa#35)"

    # Platform executables live under /opt so the root system services can exec them without
    # tripping SELinux init_t/203-EXEC (the bundle itself lands under /home/dev).
    sudo mkdir -p /opt/safe-agents/bin
    sudo install -m 0755 "${SCRIPT_DIR}/scripts/agent-netns-setup.sh" /opt/safe-agents/bin/agent-netns-setup.sh
    sudo install -m 0755 "${SCRIPT_DIR}/scripts/smoke-egress.sh"      /opt/safe-agents/bin/smoke-egress.sh
    sudo install -m 0755 "${SCRIPT_DIR}/box/run-brokered.sh"          /opt/safe-agents/bin/run-brokered.sh
    sudo restorecon -F /opt/safe-agents/bin/agent-netns-setup.sh \
        /opt/safe-agents/bin/smoke-egress.sh /opt/safe-agents/bin/run-brokered.sh 2>/dev/null || true

    # Env contract consumed by run-brokered.sh (both its host + netns phases). The oauth token is
    # referenced by SECRET ID (resolved at RUN time via the box's own GetSecretValue grant) — never
    # written here as plaintext. Also read by an on-demand SSM invocation of run-brokered.sh.
    sudo install -d /etc/safe-agents
    _ENV_TMP=$(mktemp)
    cat > "$_ENV_TMP" <<AGENTENV
AGENT_NAME=${SA_AGENT_NAME}
SA_BROKER_DNS=${SA_BROKER_DNS}
SA_MODEL_PROXY_PORT=8443
SA_TOOL_API_PORT=8080
AGENT_RUNS_TABLE=${SA_AGENT_RUNS_TABLE}
AWS_DEFAULT_REGION=${SA_REGION}
SA_OAUTH_SECRET_ID=${SA_OAUTH_TOKEN_SECRET}
SA_NETNS_NAME=agent-ns
AGENT_RUN_USER=dev
SA_PROFILE=${SA_PROFILE}
AGENTENV
    sudo mv "$_ENV_TMP" /etc/safe-agents/agent.env
    sudo chmod 0644 /etc/safe-agents/agent.env
    sudo restorecon -F /etc/safe-agents/agent.env 2>/dev/null || true

    # netns-setup oneshot — creates + forwards agent-ns BEFORE the agent run service.
    _NETNS_TMP=$(mktemp)
    cat > "$_NETNS_TMP" <<'NETNSUNIT'
[Unit]
Description=safe-agents agent netns setup (sa#35)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/safe-agents/bin/agent-netns-setup.sh up
ExecStop=/opt/safe-agents/bin/agent-netns-setup.sh down

[Install]
WantedBy=multi-user.target
NETNSUNIT
    sudo mv "$_NETNS_TMP" /etc/systemd/system/agent-netns-setup.service
    sudo chmod 644 /etc/systemd/system/agent-netns-setup.service
    sudo restorecon -F /etc/systemd/system/agent-netns-setup.service  # see SELinux note below
    sudo systemctl daemon-reload
    sudo systemctl enable --now agent-netns-setup.service

    RUN_EXEC="/opt/safe-agents/bin/run-brokered.sh"
else
    # ── Interactive (dev-box): OpenShell confines; run.sh runs directly via run-agent.sh ──
    # run-agent.sh fetches the oauth token at each invocation (run time, not bootstrap time) in the
    # host root netns, then execs run.sh from the agent code bundle. Re-generated on each deploy.
    cat > "${AGENT_DIR}/run-agent.sh" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# run-agent.sh — rhel-openshell interactive adapter. Generated by bootstrap.sh. Do not edit.
set -euo pipefail
export PATH="/usr/local/bin:/usr/sbin:/sbin:$PATH"  # RHEL omits /usr/local/bin from the service PATH
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Claude Code oauth token (agentRole: agent's own oauth_token path only).
# Connector credentials are NOT fetched here; those are broker-only.
export CLAUDE_CODE_OAUTH_TOKEN
CLAUDE_CODE_OAUTH_TOKEN=$(aws secretsmanager get-secret-value \
    --secret-id "${OAUTH_TOKEN_SECRET}" \
    --query SecretString \
    --output text)
exec "${SCRIPT_DIR}/run.sh"
WRAPPER_EOF
    chmod +x "${AGENT_DIR}/run-agent.sh"
    RUN_EXEC="${AGENT_DIR}/run-agent.sh"
fi

# ── Systemd service + timer ───────────────────────────────────────────────────
log "Writing systemd service + timer for ${SA_AGENT_NAME}"

# Profile-conditional confinement (sa#35): the autonomous service runs as root so run-brokered.sh
# can `ip netns exec` into the confined namespace (it drops to the dev user inside); it reads the
# env contract from /etc/safe-agents/agent.env and orders after the netns-setup unit. The
# interactive service runs run-agent.sh directly as dev (OpenShell confines it).
if [ "${SA_PROFILE}" = "autonomous" ]; then
    _SVC_USER=""  # root — required for `ip netns exec`; run-brokered.sh drops to dev inside the netns
    _SVC_DEPS="Requires=agent-netns-setup.service
After=agent-netns-setup.service"
    _SVC_ENV="EnvironmentFile=/etc/safe-agents/agent.env"
else
    _SVC_USER="User=dev"
    _SVC_DEPS=""
    _SVC_ENV=""
fi

_UNIT_TMP=$(mktemp)
cat > "$_UNIT_TMP" <<UNIT
[Unit]
Description=safe-agents run: ${SA_AGENT_NAME} (${SA_ARM})
After=network-online.target
Wants=network-online.target
${_SVC_DEPS}

[Service]
Type=oneshot
${_SVC_USER}
ExecStart=${RUN_EXEC}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SA_AGENT_NAME}
Environment=SA_AGENT_NAME=${SA_AGENT_NAME}
Environment=SA_ENVIRONMENT=${SA_ENVIRONMENT}
Environment=SA_ARM=${SA_ARM}
Environment=OAUTH_TOKEN_SECRET=${SA_OAUTH_TOKEN_SECRET}
${_SVC_ENV}
UNIT
sudo mv "$_UNIT_TMP" "/etc/systemd/system/${SA_AGENT_NAME}.service"
sudo chmod 644 "/etc/systemd/system/${SA_AGENT_NAME}.service"

_TIMER_TMP=$(mktemp)
cat > "$_TIMER_TMP" <<TIMER
[Unit]
Description=Timer for safe-agents run: ${SA_AGENT_NAME} (${SA_ARM})

[Timer]
OnCalendar=*-*-* 06:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
TIMER
sudo mv "$_TIMER_TMP" "/etc/systemd/system/${SA_AGENT_NAME}.timer"
sudo chmod 644 "/etc/systemd/system/${SA_AGENT_NAME}.timer"

# SELinux (RHEL): files moved from /tmp keep the tmp_t context, and systemd (PID 1)
# refuses to load units it cannot read in that context — it reports "Unit file does
# not exist" even though the file is present. Restore the correct context before reload.
sudo restorecon -F \
    "/etc/systemd/system/${SA_AGENT_NAME}.service" \
    "/etc/systemd/system/${SA_AGENT_NAME}.timer"

sudo systemctl daemon-reload
sudo systemctl enable --now "${SA_AGENT_NAME}.timer"

# ── Broker sidecar stub (sa#12) ───────────────────────────────────────────────
# The broker binary is sa#12. This installs the stub unit so the service exists
# and can be inspected; actual binary deployed separately under brokerRole.
sudo mkdir -p /opt/broker

_BROKER_TMP=$(mktemp)
cat > "$_BROKER_TMP" <<BROKER
[Unit]
Description=safe-agents broker sidecar: ${SA_AGENT_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/broker/broker-sidecar --agent ${SA_AGENT_NAME} --env ${SA_ENVIRONMENT}
Environment=AWS_SHARED_CREDENTIALS_FILE=/opt/broker/credentials
StandardOutput=journal
StandardError=journal
SyslogIdentifier=broker-${SA_AGENT_NAME}
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
BROKER
sudo mv "$_BROKER_TMP" "/etc/systemd/system/broker-${SA_AGENT_NAME}.service"
sudo chmod 644 "/etc/systemd/system/broker-${SA_AGENT_NAME}.service"
sudo restorecon -F "/etc/systemd/system/broker-${SA_AGENT_NAME}.service"  # see SELinux note above
sudo systemctl daemon-reload
sudo systemctl enable "broker-${SA_AGENT_NAME}.service" || true

# ── Interactive profile: extra tooling ────────────────────────────────────────
# The scripts below are present in the bundle for snapshot completeness, but
# are NOT run in the default autonomous profile. Set SA_PROFILE=interactive
# to activate the full development-harness experience (OpenShell sandbox runtime,
# k8s/DevOps tools, Go, Rust, Remote Control).
if [ "${SA_PROFILE}" = "interactive" ]; then
    # OpenShell sandbox runtime (LIVE-VERIFIED #93): rootless podman + OpenShell
    # gateway (systemd --user service; installer registers it on :17670). This is
    # the dev-box confinement mechanism — autonomous agents use netns instead.
    log "[interactive] installing OpenShell sandbox runtime"
    "${SCRIPT_DIR}/scripts/install-openshell.sh" 2>&1 | tee -a "$LOG"

    log "[interactive] installing languages (Go, Rust)"
    "${SCRIPT_DIR}/scripts/install-languages.sh" 2>&1 | tee -a "$LOG"

    log "[interactive] installing k8s/DevOps tools"
    "${SCRIPT_DIR}/scripts/install-k8s-tools.sh" 2>&1 | tee -a "$LOG"

    # Shell configuration overlay (bashrc + aliases + tmux.conf)
    cp "${SCRIPT_DIR}/config/bashrc.template" ~/.bashrc.toolbox
    if ! grep -q "bashrc.toolbox" ~/.bashrc 2>/dev/null; then
        printf '\n# safe-agents interactive configuration\nsource ~/.bashrc.toolbox\n' >> ~/.bashrc
        log "[interactive] linked toolbox config into ~/.bashrc"
    fi
    [ -f "${SCRIPT_DIR}/config/aliases.sh" ] && \
        mkdir -p ~/.config/toolbox && \
        cp "${SCRIPT_DIR}/config/aliases.sh" ~/.config/toolbox/aliases.sh
    [ -f "${SCRIPT_DIR}/config/tmux.conf" ] && cp "${SCRIPT_DIR}/config/tmux.conf" ~/.tmux.conf

    # Remote Control systemd user service.
    # NOT auto-enabled — requires a one-time interactive 'claude /login' first:
    #   claude          # then /login -> claude.ai (browser/device flow)
    #   systemctl --user enable --now claude-remote-control
    mkdir -p ~/.config/systemd/user
    cp "${SCRIPT_DIR}/systemd/claude-remote-control.service" ~/.config/systemd/user/
    systemctl --user daemon-reload 2>/dev/null || true
    log "[interactive] Remote Control service installed (NOT enabled — run 'claude /login' first)"
fi

log ""
log "=============================================="
log "Bootstrap complete — profile=${SA_PROFILE}"
log "=============================================="
log "Verify: claude --version; systemctl status ${SA_AGENT_NAME}.timer"
if [ "${SA_PROFILE}" = "interactive" ]; then
    log "Verify (interactive): openshell status; go version; rustc --version; oc version --client"
fi

# Final statement MUST exit 0: under `set -e`, a bare `[ x = y ] && …` as the last
# command makes the whole script inherit the test's exit status. On the autonomous
# profile that test is false → exit 1 → cloud-init marks user-data failed even
# though bootstrap fully succeeded. The explicit success keeps the exit code honest.
exit 0
