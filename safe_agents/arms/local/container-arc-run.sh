#!/usr/bin/env bash
# container-arc-run.sh — host-side driver for the #249 container drill.
#
#   ./safe_agents/arms/local/container-arc-run.sh          # build + run
#   SKIP_BUILD=1 ./safe_agents/arms/local/container-arc-run.sh   # reuse images
#
# Builds the base broker image and the missileer consumer image on top of it (the
# consumer build is itself part of the proof — it is what shows the arbitrary-UID
# hardening stayed back-compatible with the `COPY --chown=broker:broker` +
# `USER broker` lineage a consumer agent's production image also uses), then runs
# container-arc.sh inside the consumer image as an arbitrary high UID.
#
# Two podman flags carry the whole SCC fidelity of this drill:
#
#   --user 1000740000:0  an arbitrary high UID in GID 0, the way OpenShift's
#                        default SCC actually launches a pod. `USER broker` in the
#                        image is ignored, exactly as the SCC ignores it.
#   --passwd=false       runs WITHOUT an /etc/passwd entry for the UID.
#
# CORRECTION (2026-07-27, from the first real pod — see safe_agents/arms/openshift/).
# This header used to claim that `--passwd=false` is what makes the drill honest,
# because podman synthesizes a passwd entry "the drill silently tests a condition
# CRI-O does not create". CRI-O creates it too: a pod under `restricted-v2` gets
# `1000850000:x:1000850000:0:1000850000 user:/home/broker:/sbin/nologin`. So the
# flag makes this drill STRICTER than the platform, not more faithful to it.
#
# It is kept anyway, deliberately. Working without a passwd entry is a superset of
# working with one, and the flag is the only way to hold the image to that stronger
# property on a machine with no cluster. What changed is the claim, not the flag:
# do not cite it as evidence about what OpenShift does.
set -euo pipefail

cd "$(dirname "$0")/../../.."
REPO="$PWD"
BASE_TAG="${BASE_TAG:-safe-agents-broker:arc}"
CONSUMER_TAG="${CONSUMER_TAG:-safe-agents-missileer:arc}"
ARBITRARY_UID="${ARBITRARY_UID:-1000740000}"
PLATFORM="${PLATFORM:-linux/arm64}"

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "[arc] building base broker image ($PLATFORM) ..."
  podman build --platform "$PLATFORM" -t "$BASE_TAG" \
    -f safe_agents/arms/local/Containerfile.broker .
  echo "[arc] building missileer CONSUMER image on that base ..."
  podman build --platform "$PLATFORM" -t "$CONSUMER_TAG" \
    -f examples/restricted_mcp_server/Containerfile.broker \
    --build-arg BASE_IMAGE="$BASE_TAG" .
fi

# Secrets as a mounted DIRECTORY, one file per leaf (#248). Mode 0644 deliberately:
# that is what a projected Kubernetes Secret volume defaults to, so the drill
# exercises the real thing rather than a mode the platform will not produce.
SECRETS_DIR="$(mktemp -d)/secrets"
mkdir -p "$SECRETS_DIR"
trap 'rm -rf "$(dirname "$SECRETS_DIR")"' EXIT
# The manifest's connector_secrets leaves. The toy MCP server needs no credential,
# but the Doer resolves one for EVERY connector before dispatch, so the leaf must
# exist — an empty placeholder is the honest value.
printf '' > "$SECRETS_DIR/ledger-mcp-placeholder"
printf '' > "$SECRETS_DIR/peer-mcp-example"
chmod 0644 "$SECRETS_DIR"/*

# Preflight: under ROOTLESS podman, `--user` names a UID inside the container's own
# user namespace, and that namespace is only as large as the CUMULATIVE COUNT of IDs
# mapped to you in /etc/subuid — it has nothing to do with where those IDs sit on the
# host. So a UID above that count is unmappable no matter how high a host range you
# add, and crun reports it as `cannot setresuid to <uid>: Invalid argument`, which
# names neither the namespace nor the fix and sends you inspecting the image.
#
# (Learned the expensive way: a first fix added a high host range, watched
# /etc/subuid gain exactly the requested entry, and failed identically — because the
# ceiling is the SUM of range sizes, not their position. A Mac never shows this at
# all: podman machine's VM maps the full space, so this only bites on a Linux host.)
if [ -r /etc/subuid ] && command -v podman >/dev/null 2>&1; then
  MAPPED=$(awk -F: -v u="$(id -un)" '$1 == u { s += $3 } END { print s + 0 }' /etc/subuid)
  if [ "$MAPPED" -gt 0 ] && [ "$ARBITRARY_UID" -gt "$MAPPED" ]; then
    echo "[arc] uid $ARBITRARY_UID exceeds this user's rootless UID namespace (~$MAPPED ids)." >&2
    echo "[arc] Rootless podman cannot map it; crun will fail with 'cannot setresuid'." >&2
    echo "[arc] Set ARBITRARY_UID to a value <= $MAPPED. See the note below on what that" >&2
    echo "[arc] does and does not still prove." >&2
    exit 1
  fi
fi

# On ARBITRARY_UID and what its magnitude is worth. The property under test is
# "the image works as a UID it was not built for": not the image's own USER, no
# /etc/passwd entry, GID 0. That property is fully exercised at ANY such UID —
# the number itself is not the control. The default is OpenShift-shaped because
# that is what the SCC actually assigns and costs nothing on a Mac; a constrained
# rootless Linux host (CI) lowers it and still tests the same property, losing
# only the incidental coverage of a >2^30 UID. Recorded rather than silently
# defaulted, because "CI runs it at a different UID" is exactly the kind of
# detail that later reads as if CI proved what the Mac proved.
echo "[arc] running the arc as uid $ARBITRARY_UID (gid 0), no passwd entry ..."
exec podman run --rm \
  --user "${ARBITRARY_UID}:0" \
  --passwd=false \
  --network none \
  -v "$SECRETS_DIR:/run/secrets:ro" \
  -v "$REPO/safe_agents/arms/local/container-arc.sh:/app/container-arc.sh:ro" \
  -e BROKER_SECRETS_DIR=/run/secrets \
  --entrypoint bash \
  "$CONSUMER_TAG" /app/container-arc.sh
