#!/usr/bin/env bash
# drain.sh — the on-wake SQS drain loop for the ec2-woken box (sa#98).
#
# The lifecycle: the airlock Lambda wakes the box (ec2:StartInstances) → systemd starts
# responsive-agent-ready.service → this drain runs → the box self-stops (sleeps) when idle.
#
# Loop shape (poll → run → delete → idle-sleep):
#   1. long-poll the airlock SQS inbound queue (aws sqs receive-message, up to 20s).
#   2. parse the message via drain_logic.py:
#        valid   → run it as a confined + brokered turn (run-brokered.sh with the message text
#                  as DATA + a RUN_ID derived from the message id), then delete-after-attempt.
#        poison  → a present-but-malformed body: delete it (never reprocess) and keep draining.
#        empty   → increment the idle counter.
#   3. when IDLE_POLLS consecutive polls come back empty, SELF-STOP: read the own instance id
#      from IMDSv2 and `aws ec2 stop-instances` it. The box sleeps until the next wake.
#
# Robustness: a failing run is logged but the message is STILL deleted (delete-after-attempt) so
# a poison / repeatedly-failing message can never wedge the box in an infinite loop. There is no
# dead-letter queue wired here; delete-after-attempt + a loud log is the chosen policy.
#
# Confinement: the box holds NO connector creds; its only egress is the broker. The AWS control
# plane (SQS, EC2 stop, IMDS) is reached DIRECTLY — every aws call strips HTTPS_PROXY (the broker
# allowlist is the model API only), and IMDS is never proxied.
#
# Env contract (from /etc/safe-agents/agent.env, installed by box_provision.py — do NOT rename):
#   INBOUND_QUEUE_URL     the airlock SQS queue the box drains
#   SA_BROKER_DNS         broker DNS (passed through to run-brokered.sh)
#   AGENT_RUNS_TABLE      the agent-runs DynamoDB table (passed through to run-brokered.sh)
#   AGENT_NAME            agent id
#   AWS_DEFAULT_REGION    region for the aws CLI
#   IDLE_POLLS            consecutive empty polls before self-stop (default 3)
#   SA_SQS_WAIT_SECONDS   SQS long-poll seconds (default 20, the SQS max)
set -uo pipefail

: "${INBOUND_QUEUE_URL:?INBOUND_QUEUE_URL must be set}"
: "${SA_BROKER_DNS:?SA_BROKER_DNS must be set}"
: "${AGENT_RUNS_TABLE:?AGENT_RUNS_TABLE must be set}"
: "${AGENT_NAME:?AGENT_NAME must be set}"
: "${AWS_DEFAULT_REGION:?AWS_DEFAULT_REGION must be set}"

BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_BROKERED="${SA_RUN_BROKERED:-${BIN_DIR}/run-brokered.sh}"
DRAIN_LOGIC="${SA_DRAIN_LOGIC:-${BIN_DIR}/drain_logic.py}"
READY_EMITTER="${SA_READY_EMITTER:-${BIN_DIR}/emit-runner-ready.sh}"

IDLE_POLLS="${IDLE_POLLS:-3}"
WAIT_SECONDS="${SA_SQS_WAIT_SECONDS:-20}"

log() { echo "{\"event\":\"box-drain\",\"agent\":\"${AGENT_NAME}\",\"msg\":\"$1\"}"; }

# Every aws call strips the broker proxy: SQS / EC2-stop / IMDS go DIRECT via the VPC endpoints,
# not through the broker (whose allowlist is the model API only).
aws_direct() { env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy aws "$@"; }

# Publish the readiness marker (best-effort; the systemd unit also runs this as ExecStartPre).
if [ -x "$READY_EMITTER" ]; then
    "$READY_EMITTER" || true
fi

log "drain-start queue=${INBOUND_QUEUE_URL} idle_polls=${IDLE_POLLS}"

empty_polls=0
while [ "$empty_polls" -lt "$IDLE_POLLS" ]; do
    msg="$(aws_direct sqs receive-message \
        --queue-url "$INBOUND_QUEUE_URL" \
        --wait-time-seconds "$WAIT_SECONDS" \
        --max-number-of-messages 1 \
        --output json 2>/dev/null || echo '{}')"

    # drain_logic.py extract: exit 0 = valid (fields on stdout), 1 = empty, 2 = poison (receipt only).
    if fields="$(printf '%s' "$msg" | python3 "$DRAIN_LOGIC" extract 2>/dev/null)"; then
        empty_polls=0
        message_id="$(printf '%s\n' "$fields" | awk -F'\t' '$1=="MESSAGE_ID"{print $2}')"
        receipt="$(printf '%s\n' "$fields" | awk -F'\t' '$1=="RECEIPT"{print $2}')"
        text_b64="$(printf '%s\n' "$fields" | awk -F'\t' '$1=="TEXT_B64"{print $2}')"
        task_text="$(printf '%s' "$text_b64" | base64 --decode)"
        run_id="$(python3 "$DRAIN_LOGIC" run_id "$message_id")"

        log "processing message=${message_id} run=${run_id}"
        # stdbuf line-buffers the child so its logs survive an abrupt stop. The message text is
        # passed as DATA via TASK_TEXT (never as instructions to the drain).
        if RUN_ID="$run_id" MESSAGE_ID="$message_id" TASK_TEXT="$task_text" \
           stdbuf -oL -eL "$RUN_BROKERED"; then
            log "run ok message=${message_id}"
        else
            log "run FAILED message=${message_id} (deleting anyway — no poison reprocessing)"
        fi
        # Delete-after-attempt: exactly one attempt per message, whatever the outcome.
        aws_direct sqs delete-message --queue-url "$INBOUND_QUEUE_URL" \
            --receipt-handle "$receipt" >/dev/null 2>&1 || true
    else
        rc=$?
        if [ "$rc" -eq 2 ]; then
            # Poison: a present message with a malformed body. drain_logic printed its receipt;
            # delete it so it cannot wedge the queue, then keep draining (not an idle poll).
            receipt="$(printf '%s\n' "$fields" | awk -F'\t' '$1=="RECEIPT"{print $2}')"
            if [ -n "$receipt" ]; then
                aws_direct sqs delete-message --queue-url "$INBOUND_QUEUE_URL" \
                    --receipt-handle "$receipt" >/dev/null 2>&1 || true
            fi
            log "dropped malformed message"
            empty_polls=0
        else
            empty_polls=$((empty_polls + 1))
            log "empty poll ${empty_polls}/${IDLE_POLLS}"
        fi
    fi
done

log "idle after ${IDLE_POLLS} empty polls — self-stopping"

# ── Self-stop: read the own instance id from IMDSv2 (never proxied) and stop this instance. ──
imds_token="$(curl -sS -m5 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || true)"
instance_id="$(curl -sS -m5 -H "X-aws-ec2-metadata-token: ${imds_token}" \
    "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || true)"

if [ -n "$instance_id" ]; then
    if aws_direct ec2 stop-instances --instance-ids "$instance_id" >/dev/null 2>&1; then
        log "stop requested instance=${instance_id}"
    else
        log "WARNING: self-stop failed for instance=${instance_id}"
    fi
else
    log "WARNING: could not resolve own instance id from IMDSv2; not stopping"
fi
