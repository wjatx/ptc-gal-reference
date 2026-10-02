#!/bin/bash
# install-openshell.sh — OpenShell sandbox runtime for RHEL 9.
#
# OBSERVED ONCE ON RHEL AT THIS PIN. On 2026-10-02, in us-east-1, this script ran on one
# m7i.large launched from the baked RHEL 9.8 image, in a subnet with internet egress. It was
# called by bootstrap.sh, run as dev with SA_PROFILE=interactive by a test harness over
# Systems Manager (user-data.sh.tmpl step 8 did not start it). In that run:
#
#   - The three pinned 0.1.2 RPMs (openshell, openshell-gateway, openshell-prover, each
#     `-1.fc44.x86_64`) were fetched by fetch_verified and installed by dnf. They are built
#     for Fedora, and they installed and ran on RHEL 9.8.
#   - The gateway user service was enabled and started, and
#     `systemctl --user is-active openshell-gateway` printed `active`.
#   - `openshell gateway add` printed "Gateway is not reachable ... Verify the gateway is
#     running" and then "Gateway 'openshell' added and set as active". The first line is
#     EXPECTED OUTPUT here. Do not read it as a failure: the gateway starts
#     asynchronously, and the poll at the end of this script is the check.
#   - That poll saw `Status: Connected`, `Authentication: Authenticated (mTLS transport)`
#     and `Version: 0.1.2`.
#   - Afterwards, outside this script, one sandbox round-trip worked:
#     `openshell sandbox create --name bootpath --no-tty -- sh -c "echo SANDBOX_OK; uname -m; id -u"`
#     printed `SANDBOX_OK`, `x86_64` and `1000` and exited 0, `openshell sandbox list`
#     showed it `Completed`, and `openshell sandbox delete bootpath` was accepted and left
#     the list empty.
#
# NOT COVERED BY THAT RUN:
#
#   - This arm's own policy. The sandbox used the default image the OpenShell CLI chooses
#     and no policy file. openshell_policy.py and run-agent-sandbox.sh did not run.
#   - A subnet without egress. This script downloads, so it needs egress wherever the
#     packages are not already installed.
#   - A boot started by user-data.sh.tmpl, and a boot from a marketplace image.
#   - More than one run, one day and one RHEL minor release.
#
# An earlier, unpinned form of this script (the upstream installer piped to a shell, taking
# whatever release was newest) was verified end-to-end on a live RHEL 9.8 box. That was a
# different install path, and it pinned no release.
#
# Load-bearing details:
#
#   1. DEV-USER CONTEXT: OpenShell sandboxes run via the dev user's ROOTLESS
#      podman, and the gateway is a `systemctl --user openshell-gateway` service.
#      This script runs AS dev (called from bootstrap.sh which runs as dev), so
#      the XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS env vars must be set
#      for `systemctl --user` to connect to the user's bus.
#
#   2. ONE GATEWAY REGISTRATION, ON :17670: the local gateway listens on
#      https://127.0.0.1:17670 (mtls). The real port is 17670, not 8080. When the upstream
#      installer ran here it registered the gateway itself, and a manual
#      `openshell gateway add` on top of that produced a mis-registered duplicate entry.
#      The upstream installer is no longer run (see 3), so this script registers the
#      gateway itself, exactly once, with the endpoint and flags the installer uses. Do
#      not add a second registration.
#
#   3. PINNED RELEASE RPMs, NO INSTALLER: the three packages the upstream installer
#      selects on an RPM host (openshell, openshell-gateway, openshell-prover) are fetched
#      here as pinned, hash-verified files and installed with dnf. The installer script is
#      not run: it downloads those packages itself and checks them only against a checksum
#      file it fetches from the same release, which is not a hash this repository holds.
#      After the install, this script does what the installer does on an RPM host: reload
#      the user manager, enable and restart the gateway service, register the gateway.
#
#      A pin can go stale. Upstream pruned the 0.0.71 release assets the moment 0.0.72
#      shipped, and a pinned install then failed with a 404. With a pin that failure is
#      the intended outcome: the script stops, and the fix is to move the pin
#      (scripts/update-artifact-pin.py) or to mirror the assets (#65).
#
# Caller (bootstrap.sh) already runs as the 'dev' user with NOPASSWD sudo.
set -euo pipefail

log() { echo "[$(date +%H:%M:%S)] openshell: $*"; }

# The rhel-bootstrap bundle carries the helper beside scripts/ (the bundle builder,
# safe_agents/arms/ec2/ami/bundle.py, copies it from safe_agents/arms/toolchain/). A bundle
# without it stops here, on the missing file.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=../../../toolchain/fetch-verified.sh
. "${SCRIPT_DIR}/../toolchain/fetch-verified.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The endpoint the gateway service listens on, and the one name it is registered under.
GATEWAY_ENDPOINT="https://127.0.0.1:17670"
# How long to wait for the gateway to report connected, in seconds (the upstream default).
GATEWAY_WAIT_SECONDS=30

# User bus is required for `systemctl --user`. Under `sudo -u dev` the runtime
# dir is allocated by systemd-logind at first login, and XDG_RUNTIME_DIR is not
# inherited from the root shell that called sudo. Set it explicitly.
# (linger alone is not enough — without these vars `systemctl --user` fails with
# "Failed to connect to bus: No such file or directory")
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus

# Rootless podman: OpenShell uses it as its container driver. /usr/local/bin must
# be on PATH (RHEL login shells omit it; claude is installed there).
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

# OpenShell CLI + gateway + prover from the pinned 0.1.2 release RPMs (x86_64).
if ! command -v openshell >/dev/null 2>&1; then
    log "installing OpenShell 0.1.2 from pinned release RPMs"
    fetch_verified \
        https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/openshell-0.1.2-1.fc44.x86_64.rpm \
        fd30a8340c0208559e874e86382c488b85d4f19b50932b97d1dede98a690141f \
        "${WORK}/openshell.rpm"
    fetch_verified \
        https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/openshell-gateway-0.1.2-1.fc44.x86_64.rpm \
        bc79d2addf34abbd1a17d5e7eb326025120c07d1e4d95ff7330c29e968872810 \
        "${WORK}/openshell-gateway.rpm"
    fetch_verified \
        https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/openshell-prover-0.1.2-1.fc44.x86_64.rpm \
        158d40ddaaee002949274eb683143ef35d4da48b75595e1ab6cba7d09841d093 \
        "${WORK}/openshell-prover.rpm"
    sudo dnf install -y \
        "${WORK}/openshell.rpm" \
        "${WORK}/openshell-gateway.rpm" \
        "${WORK}/openshell-prover.rpm"

    # Bring the gateway up as the upstream installer does on an RPM host, then register it.
    # This is the one registration (see 2 above). `gateway add` prints "Gateway is not
    # reachable ... Verify the gateway is running" before "Gateway 'openshell' added and set
    # as active" (2026-10-02 run). That first line is expected here and is not a failure;
    # the poll below is the check.
    systemctl --user daemon-reload
    systemctl --user enable openshell-gateway
    systemctl --user restart openshell-gateway
    log "registering the gateway; a 'Gateway is not reachable' notice from this step is expected, the status poll below is the check"
    openshell gateway add "$GATEWAY_ENDPOINT" --local --name openshell
else
    log "OpenShell already installed: $(openshell --version 2>/dev/null || echo present)"
fi

# Verify the gateway came up. It starts asynchronously, so poll for the connected status
# (a report carrying a `Version:` line) before giving up. A non-Connected status here means
# the user manager wasn't reachable (XDG/DBUS vars not set) or the gateway did not start.
# This is a warning, not a fatal error: the box may still be usable once the gateway is up.
_status=""
for (( _waited = 0; _waited < GATEWAY_WAIT_SECONDS; _waited++ )); do
    _status="$(NO_COLOR=1 openshell status 2>&1 || true)"
    case "$_status" in
        *"Version:"*) break ;;
    esac
    sleep 1
done
printf '%s\n' "$_status" | head -6 || true
case "$_status" in
    *"Version:"*) ;;
    *) log "WARN: openshell status not Connected — check openshell-gateway user service (#93)" ;;
esac

log "done — verify with: openshell sandbox list"
