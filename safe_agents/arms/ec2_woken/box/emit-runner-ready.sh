#!/usr/bin/env bash
# emit-runner-ready.sh — readiness signal for the ec2-woken box (sa#34 seam, sa#98 loop).
#
# Runs ON the EC2 agent box after the airlock Lambda wakes it (ec2:StartInstances), as the
# drain service's ExecStartPre (and again at the top of drain.sh, best-effort). It publishes a
# single readiness marker so an observer / the drain knows the box is up and about to work.
#
# It does NOT drain the queue or run the agent — that is drain.sh's job (sa#98). This script
# performs NO egress and holds NO connector credentials; it only touches the local ready marker.
# Agent-agnostic + agent-name-parameterized: all specifics come from the environment (installed
# by box_provision.py into /etc/safe-agents/agent.env), never hardcoded.
set -euo pipefail

: "${AGENT_NAME:?AGENT_NAME must be set (the agent this box serves)}"

READY_MARKER="${SA_READY_MARKER:-/run/safe-agents/${AGENT_NAME}.ready}"
mkdir -p "$(dirname "$READY_MARKER")"
: > "$READY_MARKER"

echo "{\"event\":\"runner-ready\",\"agent\":\"${AGENT_NAME}\",\"marker\":\"${READY_MARKER}\"}"
