#!/usr/bin/env bash
# run-local.sh — the local/Mac arm: confined agent + broker box + DynamoDB Local, on a private
# network (the #98 separate-broker topology, realized locally; start of the #39 arm).
#
#   dynamodb-local           — DynamoDB Local: the broker's real store backend (same code as AWS)
#   broker box  (sa-broker)  — container: :8443 model-proxy + :8080 tool-call API; stores -> DynamoDB
#   agent box                — confined container whose ONLY egress is the broker box; runs claude -p
#
# Usage:
#   safe_agents/arms/local/run-local.sh
#   STORE=memory safe_agents/arms/local/run-local.sh        # skip DynamoDB (in-memory fakes)
#   CLAUDE_CODE_OAUTH_TOKEN=... safe_agents/arms/local/run-local.sh
set -uo pipefail
cd "$(dirname "$0")/../../.."   # repo root

NET="${LOCAL_NET:-safe-agents-local}"
BROKER_IMG="${LOCAL_BROKER_IMAGE:-safe-agents-local-broker:dev}"
AGENT_IMG="${LOCAL_AGENT_IMAGE:-safe-agents-local-agent:dev}"
DDB_IMG="${DDB_IMAGE:-docker.io/amazon/dynamodb-local:latest}"
STORE="${STORE:-dynamo}"
TABLE="${BROKER_TABLE:-safe-agents-broker-local}"

podman image exists "$BROKER_IMG" 2>/dev/null || \
  { echo "[local] building $BROKER_IMG ..."; podman build -t "$BROKER_IMG" -f safe_agents/arms/local/Containerfile.broker .; }
podman image exists "$AGENT_IMG" 2>/dev/null || \
  { echo "[local] building $AGENT_IMG ..."; podman build -t "$AGENT_IMG" -f safe_agents/arms/local/Containerfile safe_agents/arms/local/; }

# Required, with no default: this is BASE source, and a default naming a real
# consumer secret is both a boundary leak and a disclosure of that account's
# layout (#302). Region is left to the AWS CLI's own resolution unless AWS_REGION
# says otherwise — a literal us-east-1 silently pointed every other region's
# operator at the wrong one.
# NB no apostrophe in the :? message — bash quote-processes the word in
# ${VAR:?word}, so a lone ' opens an unterminated quote and breaks the whole file.
OAUTH_SECRET_ID="${OAUTH_SECRET_ID:?set it to the agent claude-oauth-token secret id, or export CLAUDE_CODE_OAUTH_TOKEN directly}"
if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  echo "[local] fetching oauth token from AWS ($OAUTH_SECRET_ID) ..."
  REGION_ARG=""
  if [ -n "${AWS_REGION:-}" ]; then
    REGION_ARG="--region ${AWS_REGION}"
  fi
  CLAUDE_CODE_OAUTH_TOKEN="$(aws secretsmanager get-secret-value ${REGION_ARG} \
    --secret-id "$OAUTH_SECRET_ID" --query SecretString --output text)"
fi
export CLAUDE_CODE_OAUTH_TOKEN
[ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || { echo "[local] no oauth token"; exit 1; }

cleanup() {
  podman rm -f sa-broker dynamodb-local >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "${SECRETS_DIR:-}" "${AUDIT_DIR:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
podman network create "$NET" >/dev/null 2>&1 || true

# --- Broker secrets file: the REAL GitHub token, host-side from the macOS Keychain ------------
# The broker (not the agent) holds connector credentials. We materialize them into a 0600 JSON
# file and mount it read-only into the broker box; the broker's LocalFileSecretsProvider reads it
# and injects the token into the github connector. Source of truth: Keychain item
# 'safe-agents-broker-github'; fallback: the gh CLI's own token. Stored to:
#   security add-generic-password -s safe-agents-broker-github -a "$USER" -w <token>
SECRETS_DIR="$(mktemp -d)"
SECRETS_FILE="$SECRETS_DIR/broker.json"
GH_TOKEN="$(security find-generic-password -s safe-agents-broker-github -w 2>/dev/null || true)"
[ -n "$GH_TOKEN" ] || GH_TOKEN="$(gh auth token 2>/dev/null || true)"
[ -n "$GH_TOKEN" ] || echo "[local] WARNING: no GitHub token (Keychain 'safe-agents-broker-github' or 'gh auth token'); github.whoami will fail"
( umask 077; printf '{"github": "%s"}' "$GH_TOKEN" > "$SECRETS_FILE" )
chmod 600 "$SECRETS_FILE"

# --- Audit tape: a host dir for the broker's hash-chained FileAuditSink -----------------------
AUDIT_DIR="$(mktemp -d)"

# Broker store backend + (when dynamo) the DynamoDB Local container.
# HMAC key for grant tamper-evidence (the broker writes + reads grants with this same key);
# the secrets file + audit dir are mounted into the broker box for the real connector + tape.
BROKER_ENV=(
  -e BROKER_STORE="$STORE"
  # #205: on the dynamo arm the broker refuses every defaulted authority-shaping
  # value, so this harness NAMES them all explicitly — the manifest (the checked-in
  # example, at its baked-in-image path), the HMAC key (the dev key VALUE, named
  # here rather than silently defaulted broker-side), the audit tape, the secrets
  # file. Operator-named or refuse; the values are the same dev values as before.
  -e BROKER_MANIFEST="${BROKER_MANIFEST:-/app/safe_agents/broker/prototype/example_manifest.yaml}"
  -e BROKER_HMAC_KEY="${BROKER_HMAC_KEY:-safe-agents-dev-hmac-key}"
  -e BROKER_SECRETS_FILE=/run/secrets/broker.json
  -e BROKER_AUDIT_PATH=/data/audit.jsonl
  # Grant only github.whoami here: the one class whose credential THIS harness
  # provisions (the Keychain token above), so the smoke run has a real allow path.
  # The broker's default (a consumer agent's alpaca.read/notify.send) needs Alpaca/
  # Telegram credentials that never exist locally and would only ever deny/fail.
  -e BROKER_GRANT_CLASSES=github.whoami
)
BROKER_MOUNTS=(
  -v "$SECRETS_FILE:/run/secrets/broker.json:ro,Z"
  -v "$AUDIT_DIR:/data:Z"
)
if [ "$STORE" = "dynamo" ]; then
  echo "[local] starting DynamoDB Local ..."
  podman run -d --name dynamodb-local --network "$NET" "$DDB_IMG" >/dev/null
  BROKER_ENV+=(
    -e AWS_ENDPOINT_URL_DYNAMODB=http://dynamodb-local:8000
    -e AWS_ACCESS_KEY_ID=local -e AWS_SECRET_ACCESS_KEY=local
    # DynamoDB Local: the region is arbitrary but required by boto, and the
    # credentials beside it are fake — not a deployment region.
    -e AWS_DEFAULT_REGION=us-east-1 -e BROKER_TABLE="$TABLE"
  )
fi

echo "[local] starting broker box (store=$STORE) ..."
podman run -d --name sa-broker --network "$NET" \
  "${BROKER_ENV[@]}" "${BROKER_MOUNTS[@]}" "$BROKER_IMG" >/dev/null
BROKER_IP="$(podman inspect -f "{{ (index .NetworkSettings.Networks \"$NET\").IPAddress }}" sa-broker)"
[ -n "$BROKER_IP" ] || { echo "[local] no broker IP"; podman logs sa-broker 2>&1 | tail; exit 1; }

# Poll the tool-call API instead of sleeping: :8080 answering /registry means the
# runtime is fully built (table init done, grants seeded) — :8443 starts before it.
ready=0
for _ in $(seq 1 30); do
  if podman exec sa-broker python3 -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/registry", timeout=2)' \
    >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" -eq 1 ] || { echo "[local] broker :8080 never became ready"; podman logs sa-broker 2>&1 | tail; exit 1; }
echo "[local] broker box at $BROKER_IP  (:8443 model-proxy, :8080 tool-call API)"

echo "[local] running confined agent box ..."
podman run --rm --network "$NET" --cap-add NET_ADMIN --user root \
  -e CLAUDE_CODE_OAUTH_TOKEN -e SA_BROKER_HOST="$BROKER_IP" \
  -v "$PWD/safe_agents/arms/local/confine-and-run.sh:/confine.sh:ro,Z" \
  "$AGENT_IMG" bash /confine.sh
agent_rc=$?

if [ "$STORE" = "dynamo" ]; then
  echo "[local] === proof: items the broker wrote to DynamoDB ==="
  podman exec -i sa-broker python3 - <<PY
import boto3, os
t = boto3.resource("dynamodb").Table(os.environ["BROKER_TABLE"])
items = t.scan().get("Items", [])
for it in sorted(items, key=lambda x: x["pk"]):
    extra = {k: v for k, v in it.items() if k not in ("pk", "sk")}
    print(f"  {it['pk']:<28} sk={it['sk']:<4} {extra}")
print(f"  ({len(items)} items — COUNTER# proves the cap counter incremented, IDEM# proves dedup)")
PY
fi

echo "[local] === proof: the broker's hash-chained audit tape (FileAuditSink) ==="
verify_rc=0
if [ -s "$AUDIT_DIR/audit.jsonl" ]; then
  echo "[local] audit.jsonl: $(wc -l < "$AUDIT_DIR/audit.jsonl" | tr -d ' ') record(s) at $AUDIT_DIR/audit.jsonl"
  # Verify the chain inside the broker box (it has broker installed + /data mounted).
  podman exec -i sa-broker python3 - <<'PY' || verify_rc=1
from safe_agents.broker.audit import FileAuditSink, verify_chain
records = FileAuditSink.resuming("/data/audit.jsonl").records()
verify_chain(records)
print(f"  verify_chain: OK over {len(records)} record(s) "
      f"(decisions: {[r.decision for r in records]})")
PY
else
  # The agent's brokered calls MUST have produced audit records; an empty tape
  # means the run proved nothing.
  echo "[local] FAIL: no audit records at $AUDIT_DIR/audit.jsonl"; verify_rc=1
fi
echo "[local] broker box log:"; podman logs sa-broker 2>&1 | tail -6

if [ "$agent_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; then
  echo "[local] RESULT: FAILED (agent rc=$agent_rc, audit-chain rc=$verify_rc)"; exit 1
fi
echo "[local] RESULT: OK — confinement, brokered-call outcomes, and the audit chain all verified"
