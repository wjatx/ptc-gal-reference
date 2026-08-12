#!/usr/bin/env bash
# container-arc.sh — the #247 local ceremony arc, re-run INSIDE a Linux container
# as an arbitrary UID, with no AWS anything (#249, the openshift epic's Phase 1).
#
# Runs *inside* the container; `container-arc-run.sh` is the host-side driver that
# builds the images, makes the mounts and invokes this. What it proves, in order:
#
#   0. no AWS credentials RESOLVE (asserted through botocore's real resolution
#      chain, not merely unset — a drill that believes it ran credential-free but
#      silently picked up an ambient profile proves nothing, and that failure is
#      invisible because the drill passes)
#   1. the ceremony writes to a durable sqlite store the arbitrary UID can own
#   2. maker != checker is refused, then satisfied by two distinct local roles
#   3. a FRESH broker process serves what the ceremony wrote
#   4. an admitted MCP tool EXECUTES — a real stdio child of the broker process
#   5. the declared-but-unadmitted sibling is refused (two-key admission: the
#      image-baked manifest is key #1, the ratified registry row key #2)
#
# Secrets arrive as a mounted DIRECTORY (#248's dir arm) and the issuer key is
# generated per-drill at 0600 inside the container, then destroyed with it.
#
# Deliberately NOT parameterized beyond the manifest: this is a drill, and a drill
# whose posture is configurable is a drill whose posture can be configured wrong.
set -euo pipefail

MANIFEST="${DRILL_MANIFEST:-/app/examples/restricted_mcp_server/manifest.yaml}"
SERVER_ID="${DRILL_SERVER_ID:-ledger}"
ADMIT_TOOL="${DRILL_ADMIT_TOOL:-get_entry}"
REFUSE_TOOL="${DRILL_REFUSE_TOOL:-list_entries}"
WORK="${HOME}/drill"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die() { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

say "0. runtime identity"
printf '   uid=%s gid=%s  HOME=%s\n' "$(id -u)" "$(id -g)" "$HOME"
getent passwd "$(id -u)" >/dev/null 2>&1 \
  && printf '   passwd entry: present\n' \
  || printf '   passwd entry: ABSENT (the OpenShift SCC condition)\n'
[ "$(id -u)" != "0" ] || die "running as root — the drill must run unprivileged"
ok "unprivileged, uid $(id -u)"

mkdir -p "$WORK" || die "cannot write \$HOME — the image is not arbitrary-UID safe"
ok "\$HOME is writable by this UID"

say "0b. ASSERT no AWS credentials resolve"
python3 - <<'PY' || die "AWS credentials resolved — the no-AWS claim would be a lie"
import sys
import botocore.session
creds = botocore.session.get_session().get_credentials()
if creds is not None:
    print(f"   credentials RESOLVED via {creds.method}", file=sys.stderr)
    sys.exit(1)
PY
ok "botocore's full resolution chain yields nothing"

# --- the drill workspace: per-drill issuer key, destroyed with the container ---
python3 - "$WORK/issuer.pem" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
with open(sys.argv[1], "wb") as fh:
    fh.write(key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
PY
chmod 600 "$WORK/issuer.pem"

export BROKER_STORE=sqlite
export BROKER_SQLITE_PATH="$WORK/broker.db"
export BROKER_HMAC_KEY="${BROKER_HMAC_KEY:-container-drill-hmac-key}"
export BROKER_MANIFEST="$MANIFEST"
export BROKER_SECRETS=dir
export BROKER_SECRETS_DIR="${BROKER_SECRETS_DIR:-/run/secrets}"
export BROKER_AUDIT_PATH="$WORK/audit.jsonl"
export BROKER_GRANT_LOAD=read
export ISSUER_SIGNING_KEY_FILE="$WORK/issuer.pem"
export ISSUER_SIGNING_KEY_ID=container-drill-issuer-1
export ISSUER_SIGNING_ZONE=local

say "1. seed — manifest-driven floor grants into the sqlite store"
BROKER_LOCAL_IDENTITY=maker python3 -m safe_agents.broker.grants.commands seed
ok "grants seeded"

say "2. snapshot — pre-admission discovery (spawns the MCP stdio child)"
python3 -m safe_agents.broker.mcp.commands snapshot \
  --manifest "$MANIFEST" --server-id "$SERVER_ID" --out "$WORK/snapshot.json" 2>&1 | tail -1
ok "live tool set captured"

say "3. admit-propose (maker)"
PROPOSAL_ID=$(BROKER_LOCAL_IDENTITY=maker python3 -m safe_agents.broker.mcp.commands admit-propose \
  --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" \
  --from-snapshot "$WORK/snapshot.json" --ttl-hours 1 \
  | tee /dev/stderr | sed -n 's/.*proposal_id=\([0-9a-f-]*\).*/\1/p')
[ -n "$PROPOSAL_ID" ] || die "no proposal id parsed"
ok "proposal $PROPOSAL_ID"

say "4. NEGATIVE PROOF — the maker cannot ratify its own proposal"
# NB capture-then-match, never `cmd | grep -q`: a refusal exits NON-ZERO, and under
# `set -o pipefail` that sinks the whole pipeline regardless of what grep found — so
# the piped form reports the refusal (the PASS condition) as a failure. A negative
# proof whose success looks like failure is worse than no negative proof at all.
set +e
SELF_RATIFY_OUT=$(BROKER_LOCAL_IDENTITY=maker python3 -m safe_agents.broker.mcp.commands \
  admit-ratify --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" \
  --proposal-id "$PROPOSAL_ID" 2>&1)
SELF_RATIFY_RC=$?
set -e
printf '   %s\n' "$SELF_RATIFY_OUT" | head -2
[ "$SELF_RATIFY_RC" -ne 0 ] || die "maker's self-ratify EXITED 0 — it was not refused"
printf '%s' "$SELF_RATIFY_OUT" | grep -q "REFUSED" \
  || die "maker's self-ratify failed, but not with the M7 refusal"
ok "self-admission refused (M7), exit $SELF_RATIFY_RC"

say "5. admit-ratify (checker) — burn the proposal, sign the record, write the row"
BROKER_LOCAL_IDENTITY=checker python3 -m safe_agents.broker.mcp.commands admit-ratify \
  --server-id "$SERVER_ID" --tool-name "$ADMIT_TOOL" --proposal-id "$PROPOSAL_ID"
ok "$SERVER_ID/$ADMIT_TOOL ADMITTED"

say "6. a FRESH broker process serves what the ceremony wrote"
python3 - "$MANIFEST" "$SERVER_ID" "$ADMIT_TOOL" "$REFUSE_TOOL" <<'PY'
import logging
import sys

logging.disable(logging.CRITICAL)
from safe_agents.broker.api import AgentRequest, build_runtime, load_agent_manifest

manifest_path, server_id, admit_tool, refuse_tool = sys.argv[1:5]
runtime, _ = build_runtime(load_agent_manifest(manifest_path))
failures = []
try:
    admitted = runtime.handle_request(AgentRequest(
        tool=server_id, op=admit_tool,
        args={"entry_id": "L-001"}, idempotency_key="container-drill-admitted"))
    print(f"   {server_id}.{admit_tool} -> {admitted.decision_kind}")
    if admitted.decision_kind != "allow" or admitted.result is None:
        failures.append(f"{admit_tool} did not execute: {admitted.decision_kind} {admitted.reason}")
    else:
        print(f"   result: {str(admitted.result)[:100]}")

    refused = runtime.handle_request(AgentRequest(
        tool=server_id, op=refuse_tool,
        args={"limit": 5}, idempotency_key="container-drill-refused"))
    print(f"   {server_id}.{refuse_tool} -> {refused.decision_kind} (declared, never admitted)")
    if refused.result is not None:
        failures.append(f"{refuse_tool} RETURNED A RESULT — two-key admission is not holding")
finally:
    runtime.close()

if failures:
    for f in failures:
        print(f"   {f}", file=sys.stderr)
    sys.exit(1)
PY
ok "admitted tool executed; unadmitted sibling produced no result"

say "7. the audit tape"
python3 - "$WORK/audit.jsonl" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1])]
print(f"   {len(records)} hash-chained records")
for r in records:
    print(f"   seq={r['seq']} {r['tool']}.{r['op']:12s} decision={r['decision']:6s} "
          f"outcome={r['outcome']}")
    if r.get("error"):
        print(f"          error: {r['error'][:110]}")
PY

printf '\n\033[32mCONTAINER ARC: PASS\033[0m — ceremony, fresh-process boot, executed MCP call,\n'
printf 'unadmitted refusal, all inside a container as uid %s with zero AWS credentials.\n' "$(id -u)"
