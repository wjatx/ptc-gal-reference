#!/usr/bin/env bash
# self-stop-on-timeout.sh — box-side hard lifetime cap for the ec2-woken box (sa#98 belt-and-suspenders).
#
# The drain loop (drain.sh) already self-stops the box when its SQS queue goes idle. THIS is the
# belt-and-suspenders for the case where the drain loop hangs and never reaches that self-stop:
# a systemd timer (self-stop-on-timeout.timer, OnBootSec=3h) fires this script, which stops the
# instance unconditionally. It bounds a hung box's cost even if the operator's out-of-band alerter
# (observability/hung-ec2-alert) is missed.
#
# It reuses the box's EXISTING authority: the box role already grants ec2:StopInstances on
# instances tagged as THIS agent's box (the drain loop's SelfStop statement), and the box already
# reaches the EC2 endpoint from its subnet. No new IAM. This script performs NO other egress and
# holds NO connector credentials — it only stops itself.
#
# Agent-agnostic + agent-name-parameterized: config comes from /etc/safe-agents/agent.env
# (AWS_DEFAULT_REGION), never hardcoded.
set -euo pipefail

# IMDSv2: fetch a token, then this box's own instance id.
IMDS="http://169.254.169.254/latest"
token="$(curl -sS -X PUT "${IMDS}/api/token" \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
instance_id="$(curl -sS -H "X-aws-ec2-metadata-token: ${token}" \
  "${IMDS}/meta-data/instance-id")"

: "${instance_id:?could not resolve own instance id from IMDS}"

echo "{\"event\":\"self-stop-on-timeout\",\"instance_id\":\"${instance_id}\",\"reason\":\"lifetime-cap\"}"

# Stop (not terminate) — the box is meant to sleep and be woken again by the airlock.
aws ec2 stop-instances --instance-ids "${instance_id}"
