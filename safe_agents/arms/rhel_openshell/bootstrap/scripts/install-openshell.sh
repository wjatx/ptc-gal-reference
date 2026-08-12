#!/bin/bash
# install-openshell.sh — OpenShell sandbox runtime for RHEL 9.
# LIVE-VERIFIED (#93): this exact sequence was verified end-to-end on a live
# RHEL 9.8 box (gateway Connected, sandbox create/exec/delete working).
#
# Three load-bearing details that must NOT be changed without re-verifying:
#
#   1. DEV-USER CONTEXT: OpenShell sandboxes run via the dev user's ROOTLESS
#      podman, and the gateway is a `systemctl --user openshell-gateway` service.
#      This script runs AS dev (called from bootstrap.sh which runs as dev), so
#      the XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS env vars must be set
#      for `systemctl --user` to connect to the user's bus.
#
#   2. INSTALLER OWNS THE GATEWAY: the native installer's start_user_gateway()
#      installs the openshell-gateway RPM, enables the systemd --user service,
#      and registers the local gateway on https://127.0.0.1:17670 (mtls) ITSELF.
#      Do NOT run `openshell gateway add` manually — the real port is 17670, not
#      8080, and a manual add produces a mis-registered duplicate entry.
#
#   3. DO NOT PIN A VERSION: pinning (e.g. OPENSHELL_VERSION=0.0.71) caused a
#      release-asset 404 the moment upstream churned to 0.0.72. OpenShell moves
#      fast and prunes/retags assets. The native installer takes the current latest.
#      (sa#86: pin + mirror assets once OpenShell stabilizes.)
#
# Caller (bootstrap.sh) already runs as the 'dev' user with NOPASSWD sudo.
set -euo pipefail

log() { echo "[$(date +%H:%M:%S)] openshell: $*"; }

# User bus is required for `systemctl --user`. Under `sudo -u dev` the runtime
# dir is allocated by systemd-logind at first login, and XDG_RUNTIME_DIR is not
# inherited from the root shell that called sudo. Set it explicitly.
# (linger alone is not enough — without these vars `systemctl --user` fails with
# "Failed to connect to bus: No such file or directory")
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus

# Rootless podman: OpenShell uses it as its container driver. /usr/local/bin must
# be on PATH (RHEL login shells omit it; claude and openshell are installed there).
export PATH="/usr/local/bin:$HOME/.local/bin:$PATH"

if ! command -v podman >/dev/null 2>&1; then
    log "installing podman"
    sudo dnf install -y podman
fi

# loginctl enable-linger: lets the user's systemd manager persist between logins
# so the rootless podman socket + openshell-gateway survive logout.
sudo loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user enable --now podman.socket 2>/dev/null \
    || log "WARN: failed to enable rootless podman.socket — may need linger or relogin"

# OpenShell CLI + gateway via the native installer (unpinned, gateway auto-registered).
if ! command -v openshell >/dev/null 2>&1; then
    log "installing OpenShell (native installer, no version pin)"
    curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
else
    log "OpenShell already installed: $(openshell --version 2>/dev/null || echo present)"
fi

# Verify the gateway came up. The installer's start_user_gateway() registers on
# :17670 (mtls). A non-Connected status here means the user manager wasn't reachable
# (XDG/DBUS vars not set). This is a warning, not a fatal error — the box may still
# be usable once the gateway starts asynchronously.
openshell status 2>&1 | head -6 \
    || log "WARN: openshell status not Connected — check openshell-gateway user service (#93)"

log "done — verify with: openshell sandbox list"
