"""
meta_alarm — page-semantics helpers for watchdog processes.

Implements the sa#29 standard: a watchdog that exits 1 on failure is
indistinguishable from a broken watchdog process unless the two signals
are explicitly separated. This module codifies that separation.

Three primitives:
    emit_heartbeat(...)      — liveness pulse; absence triggers the meta-alarm
    emit_meta_alarm(...)     — the watchdog itself is broken → stderr + exit 1
    emit_content_alarm(...)  — the watchdog fired correctly → notify + stdout + return

Exit-code contract (load-bearing):
    emit_meta_alarm  → sys.exit(1)   # red CI; the watchdog process died or errored
    emit_content_alarm → returns     # exit 0; the watchdog ran; it simply found a condition

The two signals MUST be delivered to different channels and MUST NOT share an
exit code as their sole discriminator. See META-ALARM-STANDARD.md for the rationale.
"""

import datetime
import json
import sys
from typing import Any, Callable


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def emit_heartbeat(
    *,
    component: str = "reliability.meta_alarm",
    heartbeat_fn: Callable[[], None] | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Publish a liveness pulse.

    Call once per watchdog run, before doing any detection work.
    If heartbeat_fn is provided (e.g., a CloudWatch put-metric call), it is
    invoked to deliver the pulse to the monitoring channel. Absence of the
    pulse over N heartbeat periods triggers the meta-alarm via that channel —
    without requiring any code to call emit_meta_alarm.

    Returns normally. The heartbeat is never a page; its absence is.

    Example:
        emit_heartbeat(
            component="chain-gap-watcher",
            heartbeat_fn=lambda: cloudwatch.put_metric_data(...),
        )
    """
    if heartbeat_fn is not None:
        heartbeat_fn()
    record: dict[str, Any] = {
        "level": "HEARTBEAT",
        "signal": "watchdog_alive",
        "component": component,
        "ts": _now_utc(),
    }
    if extra:
        record.update(extra)
    print(json.dumps(record))


def emit_meta_alarm(
    msg: str,
    *,
    component: str = "reliability.meta_alarm",
    extra: dict[str, Any] | None = None,
) -> None:
    """The watchdog itself is broken. Publish the META-alarm.

    Use this when the watchdog process encounters an internal error — a crash,
    a dependency failure, a configuration problem — that prevents it from
    running correctly. This is NOT a detection; it is a health failure of the
    watchdog process itself.

    Writes a structured JSON record to stderr and calls sys.exit(1). In CI,
    this is a red build. The meta-alarm channel (e.g., a CloudWatch alarm on
    missing heartbeats) handles the paging; this function documents the failure.

    Do NOT call this when the watchdog detected a real condition. For that,
    use emit_content_alarm.

    Example:
        try:
            gap = detect_chain_gap(chain)
        except Exception as exc:
            emit_meta_alarm(str(exc), component="chain-gap-watcher")
        # never reached
    """
    record: dict[str, Any] = {
        "level": "META_ALARM",
        "signal": "watchdog_broken",
        "msg": msg,
        "component": component,
        "ts": _now_utc(),
    }
    if extra:
        record.update(extra)
    print(json.dumps(record), file=sys.stderr)
    sys.exit(1)


def emit_content_alarm(
    msg: str,
    *,
    notify_fn: Callable[[str], None],
    component: str = "reliability.meta_alarm",
    extra: dict[str, Any] | None = None,
) -> None:
    """The watchdog detected a real condition. Deliver the content alarm.

    The watchdog ran correctly; it detected a condition that warrants a page.
    Calls notify_fn(msg) to deliver the alert via the configured channel (e.g.,
    CloudWatch, SNS, PagerDuty — consumer-repo configuration). Then writes a
    structured JSON record to stdout and returns normally.

    Exit code 0 (implicit return) means "the watchdog ran correctly." Do not
    confuse this with "nothing bad happened" — the alarm fired; the watchdog
    did its job. Exit 0 ensures CI stays green while the page is in flight.

    notify_fn MUST be called before returning. If notify_fn raises, let the
    exception propagate — that becomes an uncaught error and the watchdog exits
    non-zero (a meta-alarm condition), which is correct.

    Example:
        emit_content_alarm(
            f"Chain gap: {gap} blocks",
            notify_fn=lambda m: sns.publish(TopicArn=ALARM_TOPIC, Message=m),
            component="chain-gap-watcher",
        )
    """
    notify_fn(msg)
    record: dict[str, Any] = {
        "level": "ALARM",
        "signal": "content_detected",
        "msg": msg,
        "component": component,
        "ts": _now_utc(),
    }
    if extra:
        record.update(extra)
    print(json.dumps(record))
