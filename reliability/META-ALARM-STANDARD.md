# Meta-alarm / page-semantics standard

**sa#29 · reliability package · agent-agnostic**

A paging watchdog that exits 1 on failure is indistinguishable from a broken
watchdog process. This document codifies the rule that separates the two signals
so that a real dead-man's-switch alert can never be masked by a broken workflow.

---

## The problem

When a watchdog process exits 1, CI turns red. That is the correct behavior for
two very different situations:

| Situation | Desired outcome |
|---|---|
| The watchdog itself crashed (config error, dependency failure, OOM) | Red CI; ops investigates the watchdog |
| The watchdog ran correctly and detected a real condition | Page fires; CI stays green |

If both situations produce exit 1, they are indistinguishable. A broken watchdog
suppresses all future content alarms. A fired content alarm causes unnecessary CI
red. Neither is acceptable.

---

## The two signals

### META-alarm — "the watchdog is broken"

The meta-alarm fires when the watchdog process itself cannot function. It is a
health signal for the watchdog, not for the system under observation.

**Properties:**
- Exit code 1 (red CI, human investigates the watchdog process)
- Written to stderr as a structured JSON record
- Does NOT trigger a content page — the condition is unknown, not detected
- Channel: monitoring infrastructure that expects a regular heartbeat from the
  watchdog. Absence of the heartbeat triggers this alarm without any code
  running inside the watchdog.

**When to use:** the watchdog encountered an internal error — a crash, a missing
config, a broken dependency — that prevents it from completing its detection run.

### Content alarm — "the watchdog fired"

The content alarm fires when the watchdog ran correctly and detected a real
condition (e.g., a chain gap, egress drift, budget overage).

**Properties:**
- Exit code 0 (CI green; the watchdog did its job)
- Written to stdout as a structured JSON record
- notify_fn is called first, delivering the page before the record is written
- Channel: a separate alert channel (SNS topic, PagerDuty endpoint, etc.)
  configured by the consumer repo

**When to use:** the watchdog successfully ran and found a condition that warrants
a page.

### Heartbeat — "the watchdog is alive"

The heartbeat is a liveness pulse emitted once per watchdog run, before any
detection work. It feeds the monitoring channel that backs the meta-alarm: if
heartbeats stop arriving (because the watchdog process died), the monitoring
channel fires the meta-alarm automatically — without requiring any code to run.

**Properties:**
- No exit (returns normally)
- Written to stdout as a structured JSON record
- heartbeat_fn (optional) delivers the pulse to the monitoring channel (e.g.,
  a CloudWatch `PutMetricData` call)

---

## The channels must be separate

The two alarm types MUST be delivered to different channels and MUST NOT share
an exit code as their sole discriminator. The reason:

1. **Exit code alone is ambiguous.** Both a broken watchdog (exit 1) and a
   healthy watchdog that exits before detecting anything (exit 0) can look like
   "no alarm." The heartbeat channel makes liveness explicit.

2. **A single alarm channel conflates cause and effect.** If both "watchdog died"
   and "condition detected" go to the same channel, on-call receives pages that
   require human triage to distinguish. A separate meta-alarm channel gets
   silence (healthy watchdog) or fires exactly when the watchdog process is broken.

3. **The dead-man's-switch invariant requires separation.** A dead-man's switch
   (DMS) fires when the signal stops. For the heartbeat DMS to work, the heartbeat
   must go to a channel that is otherwise silent. If content alarms and heartbeats
   share a channel, the DMS cannot distinguish "watchdog alive but quiet" from
   "watchdog dead."

---

## Reference implementation (CloudWatch)

The base platform provides channel-agnostic primitives. Consumer repos wire them
to concrete channels.

```python
import boto3
from reliability import emit_heartbeat, emit_meta_alarm, emit_content_alarm

cloudwatch = boto3.client("cloudwatch")
sns = boto3.client("sns")

NAMESPACE = "SafeAgents/Watchdog"
ALARM_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:chain-gap-alarm"

def heartbeat_pulse():
    cloudwatch.put_metric_data(
        Namespace=NAMESPACE,
        MetricData=[{
            "MetricName": "WatchdogHeartbeat",
            "Dimensions": [{"Name": "Watchdog", "Value": "chain-gap"}],
            "Value": 1,
            "Unit": "Count",
        }],
    )

def notify_alarm(msg: str):
    sns.publish(TopicArn=ALARM_TOPIC_ARN, Message=msg)

# --- Main watchdog run ---

emit_heartbeat(component="chain-gap-watcher", heartbeat_fn=heartbeat_pulse)

try:
    gap = detect_chain_gap()
except Exception as exc:
    emit_meta_alarm(str(exc), component="chain-gap-watcher")  # exits 1

if gap > THRESHOLD:
    emit_content_alarm(
        f"Chain gap: {gap} blocks",
        notify_fn=notify_alarm,
        component="chain-gap-watcher",
    )  # calls notify_alarm, writes stdout, returns — exit 0
```

### CloudWatch alarm configuration

Two alarms, two channels:

1. **Meta-alarm** — `WatchdogHeartbeat` metric missing for N periods (e.g., 3
   consecutive 5-minute periods). Alarm action: page ops. This fires automatically
   when the watchdog process dies, without any code running inside it.

2. **Content alarm** — separate metric (e.g., `ChainGapBlocks`) exceeds threshold.
   Alarm action: page on-call. This fires on detection, independently of whether
   the heartbeat is present.

Consumer repos may substitute any monitoring channel (SNS, PagerDuty, OpsGenie,
Slack) for both; the base platform does not mandate a provider.

---

## Implementation (this package)

`reliability.meta_alarm` provides the three primitives. Import from the package:

```python
from reliability import emit_heartbeat, emit_meta_alarm, emit_content_alarm
```

The exit-code contract is enforced by the primitives:
- `emit_meta_alarm` calls `sys.exit(1)` — no return
- `emit_content_alarm` calls `notify_fn`, writes stdout, returns — no `sys.exit`
- `emit_heartbeat` returns — no `sys.exit`

Tests in `tests/test_meta_alarm.py` verify that the exit codes are distinct and
that the two alarms write to different output streams.

---

## Mandate

Any base-platform watchdog or auditor that runs on a schedule MUST implement both
signals:

- A heartbeat that feeds a monitoring channel capable of firing a meta-alarm on
  absence (the channel is configured per deployment, not hardcoded here)
- A content alarm delivered to a separate channel when a real condition is detected

Sharing a channel or using exit code as the sole discriminator is a latent safety
bug: a broken watchdog becomes invisible to the system it is supposed to guard.
