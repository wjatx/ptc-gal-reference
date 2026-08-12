#!/bin/bash
# fetch-secrets.sh — Pull a JSON secret from AWS Secrets Manager via the instance
# role and write it as ~/.secrets.env (shell `export` lines, mode 600).
# Faithful snapshot from a development harness (scripts/fetch-secrets.sh).
#
# Hard-won lesson (from _pipeline-lib.sh): send box-side scripts base64-encoded
# when using SSM RunShellScript — raw heredocs hit SSM/JSON quoting bugs.
# This script avoids that by being delivered as a file in the bootstrap bundle.
#
# Nothing is ever committed; the only plaintext is this transient, gitignored,
# 0600 file. Used by the interactive profile; the autonomous profile fetches
# its single oauth token directly via run-agent.sh.
#
# Usage:
#   SA_SECRET_ID=my-agent/runner-keys scripts/fetch-secrets.sh
#   source ~/.secrets.env
set -euo pipefail

SECRET_ID="${SA_SECRET_ID:?set SA_SECRET_ID to the Secrets Manager secret id}"
# Optional: unset means the AWS CLI resolves the region itself (on EC2 that is
# IMDS). A literal default would silently point a non-us-east-1 host at us-east-1.
REGION_ARG=""
if [ -n "${AWS_REGION:-}" ]; then
  REGION_ARG="--region ${AWS_REGION}"
fi
OUT="${HOME}/.secrets.env"

JSON="$(aws secretsmanager get-secret-value \
    --secret-id "$SECRET_ID" \
    ${REGION_ARG} \
    --query SecretString \
    --output text)"

umask 077
printf '%s' "$JSON" | python3 -c '
import sys, json, shlex
data = json.load(sys.stdin)
for k, v in data.items():
    print("export %s=%s" % (k, shlex.quote(str(v))))
' > "$OUT"
chmod 600 "$OUT"
echo "wrote $OUT ($(grep -c . "$OUT") vars). Load with: source ~/.secrets.env"
