"""
campaign_runner — reference scheduled runner for the sa#161 input-poisoning
campaign watchdog (channels/WATCHDOG.md).

**Reference-tier** (docs/contract-vs-reference.md): one instantiation of the
pure `safe_agents.watcher.campaign.analyze()` engine (the contract-tier
piece), mirroring `safe_agents.watcher.liveness`'s idiom (sa#38) — small
orchestration functions taking injected reader callables, with boto3
constructed only inside `main()`/the `make_*` factory helpers, so every other
function is exercisable with hand-rolled fakes and no AWS.

Sweeps `channels/drops/` DropRecords (`safe_agents.channels.stores.S3DropSink`
key layout: `{prefix}YYYY/MM/DD/{iso-ts}-{uuid}.json`) over the UTC day
prefixes spanning the correlation window, plus, optionally, the broker's
`approval_queue_flood` CloudWatch Logs signal (`safe_agents/broker/runtime/
pep.py`). It deliberately does **not** read `channels/verdicts/` ScreenRecords:
every screen refusal that produces a `screen_refused` DropRecord ALSO produces
a ScreenRecord at the same gate (`safe_agents/channels/dispatch.py` gate 7 —
both are written from the same `if not passed:` branch), so reading both
sinks would double-count the identical event under the engine's attribution
table.

Satisfies the sa#29 meta-alarm standard (`reliability/META-ALARM-STANDARD.md`,
`reliability.meta_alarm`) exactly:
    heartbeat_fn      → emitted once, before any detection work
    any runner-internal failure (an unreachable bucket/log group, a bad
        --min-attempts/--window-seconds config)
                      → emit_meta_alarm  (stderr JSON, sys.exit(1))
    campaigns found   → emit_content_alarm per campaign (stdout JSON, notify_fn
        called, returns), plus the full CampaignReport list as JSON
    zero campaigns    → a plain stdout line, clean return (exit 0)

A single malformed/unparseable drop object under an otherwise-healthy sweep is
NOT a runner failure — see `sweep_drops`.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from reliability import emit_content_alarm, emit_heartbeat, emit_meta_alarm
from safe_agents.channels.trust_map import DropRecord
from safe_agents.watcher.campaign import (
    CampaignReport,
    CampaignThresholds,
    FloodEvent,
    ObservedEvent,
    analyze,
)

COMPONENT = "campaign-watchdog"

# The exact marker the broker's approval_queue_flood log line carries
# (safe_agents/broker/runtime/pep.py) — used both as the CloudWatch Logs
# filter pattern and as the defensive re-check on each parsed line.
FLOOD_EVENT_MARKER = "approval_queue_flood"

DEFAULT_DROPS_PREFIX = "channels/drops/"


# ---------------------------------------------------------------------------
# Window -> day prefixes
# ---------------------------------------------------------------------------


def day_prefixes(window_start: datetime, now: datetime, *, base_prefix: str) -> list[str]:
    """UTC day prefixes spanning `[window_start, now]`, inclusive of both civil dates.

    Both arguments must be tz-aware. `base_prefix` is the S3 "directory" the
    drop sink writes under (`S3DropSink`'s default `channels/drops/`); each
    UTC civil date in the span contributes one `{base_prefix}YYYY/MM/DD/`
    prefix. A window that spans a UTC midnight boundary yields two (or more)
    prefixes — the caller lists/fetches under each independently.
    """
    if window_start.tzinfo is None or now.tzinfo is None:
        raise ValueError("day_prefixes requires tz-aware datetimes")
    if window_start > now:
        raise ValueError(f"window_start {window_start!r} is after now {now!r}")

    prefixes: list[str] = []
    day: date = window_start.date()
    last: date = now.date()
    while day <= last:
        prefixes.append(f"{base_prefix}{day:%Y/%m/%d}/")
        day += timedelta(days=1)
    return prefixes


# ---------------------------------------------------------------------------
# DropRecord -> ObservedEvent
# ---------------------------------------------------------------------------


def parse_drop_record(key: str, body: bytes) -> ObservedEvent:
    """Map one S3-stored DropRecord JSON object to an ObservedEvent.

    `source_ref` is set to the S3 key, so a CampaignReport's `corpus_refs`
    point back at the exact record (WATCHDOG.md's PII-safe source_refs).
    Legacy records written before sa#161 Phase A1 (no `chain_verified`/
    `signer_key_id`) parse cleanly to the DropRecord/ObservedEvent defaults
    (False/None) — both models declare the same defaults, so no explicit
    back-fill is needed here.

    Raises on malformed/invalid JSON or a schema violation; callers (
    `sweep_drops`) are responsible for catching and counting rather than
    letting one bad object abort the sweep.
    """
    record = DropRecord.model_validate_json(body)
    return ObservedEvent(
        channel_type=record.channel_type,
        identity_digest=record.identity_digest,
        reason=record.reason,
        detail=record.detail,
        ts=datetime.fromisoformat(record.ts),
        chain_verified=record.chain_verified,
        signer_key_id=record.signer_key_id,
        source_ref=key,
    )


def sweep_drops(
    list_keys: Callable[[str], Sequence[str]],
    get_object: Callable[[str], bytes],
    prefixes: Sequence[str],
) -> tuple[list[ObservedEvent], list[str]]:
    """List and fetch every drop record under `prefixes`, mapping to ObservedEvents.

    Returns `(events, malformed_keys)`. A per-key failure — the object body is
    not valid DropRecord JSON, or fetching it raises — is caught, the key is
    appended to `malformed_keys`, and the sweep continues over the remaining
    keys: one corrupt or transiently-unfetchable object must never blind the
    watchdog to every other record in the window. `list_keys(prefix)` itself
    is NOT caught here — a prefix listing failure (e.g. the bucket is
    unreachable) means the sweep cannot see a whole day's records at all,
    which is a runner-internal failure the caller routes to `emit_meta_alarm`
    rather than a "some records were malformed" finding.
    """
    events: list[ObservedEvent] = []
    malformed: list[str] = []
    for prefix in prefixes:
        for key in list_keys(prefix):
            try:
                body = get_object(key)
                events.append(parse_drop_record(key, body))
            except Exception:  # noqa: BLE001 — one bad object must not abort the sweep
                malformed.append(key)
    return events, malformed


# ---------------------------------------------------------------------------
# approval_queue_flood CloudWatch Logs signal -> FloodEvent
# ---------------------------------------------------------------------------


def parse_flood_log_line(message: str, ts: datetime) -> FloodEvent | None:
    """Parse one CloudWatch Logs message into a FloodEvent, or None.

    The CloudWatch filter pattern already narrows the sweep to lines
    containing the marker, but this re-checks defensively (a coincidental
    substring match, or a line that isn't the exact structured JSON the
    broker emits, degrades to "skip this line" — never a crash or a
    fabricated event).
    """
    try:
        payload = json.loads(message)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("event") != FLOOD_EVENT_MARKER:
        return None
    try:
        return FloodEvent(
            agent_id=payload["agentId"],
            op=payload["op"],
            cap=payload["cap"],
            ts=ts,
        )
    except Exception:  # noqa: BLE001 — a malformed flood line is skipped, not fatal
        return None


def fetch_flood_events(
    filter_log_events: Callable[[str, int, int], Sequence[dict[str, Any]]],
    log_group: str,
    window_start: datetime,
    now: datetime,
) -> list[FloodEvent]:
    """Fetch `approval_queue_flood` log lines from `log_group` over `[window_start, now]`.

    `filter_log_events(log_group, start_ms, end_ms) -> events` is injected —
    each `events[i]` is a CloudWatch Logs event dict with at least `message`
    and `timestamp` (epoch milliseconds) — so tests drive a fake with no
    botocore, and `main()` wires the real paginated
    `logs.filter_log_events(filterPattern=...)` call via `make_cloudwatch_filter`.
    Each event's own `timestamp` drives the resulting FloodEvent.ts (never a
    fresh clock read here), so ordering matches what the broker actually logged.
    """
    if window_start.tzinfo is None or now.tzinfo is None:
        raise ValueError("fetch_flood_events requires tz-aware datetimes")
    start_ms = int(window_start.timestamp() * 1000)
    end_ms = int(now.timestamp() * 1000)

    floods: list[FloodEvent] = []
    for event in filter_log_events(log_group, start_ms, end_ms):
        ts = datetime.fromtimestamp(event["timestamp"] / 1000, tz=timezone.utc)
        flood = parse_flood_log_line(event.get("message", ""), ts)
        if flood is not None:
            floods.append(flood)
    return floods


# ---------------------------------------------------------------------------
# AWS-backed reader factories — boto3 constructed here only
# ---------------------------------------------------------------------------


def make_s3_readers(
    s3_client: Any, bucket: str
) -> tuple[Callable[[str], list[str]], Callable[[str], bytes]]:
    """Build `(list_keys, get_object)` backed by a real (or fake) S3 client."""

    def list_keys(prefix: str) -> list[str]:
        keys: list[str] = []
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
        return keys

    def get_object(key: str) -> bytes:
        return s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()

    return list_keys, get_object


def make_cloudwatch_filter(logs_client: Any) -> Callable[[str, int, int], list[dict[str, Any]]]:
    """Build a `filter_log_events(log_group, start_ms, end_ms)` backed by CloudWatch Logs."""

    def filter_log_events(log_group: str, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        paginator = logs_client.get_paginator("filter_log_events")
        for page in paginator.paginate(
            logGroupName=log_group,
            startTime=start_ms,
            endTime=end_ms,
            filterPattern=f'"{FLOOD_EVENT_MARKER}"',
        ):
            events.extend(page.get("events", []))
        return events

    return filter_log_events


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def campaign_summary(report: CampaignReport) -> str:
    """One-line, PII-safe summary for the content-alarm notify channel.

    Carries exactly campaign_id/basis/attribution_key/total/throttle_eligible
    — the same fields WATCHDOG.md names as safe to page on. `attribution_key`
    is already PII-safe by construction (a signer key id, a
    `channel_type#identity_digest` digest pair, or an `agent_id#op` pair —
    never raw sender identity or content; see `campaign.py`'s attribution
    table).
    """
    return (
        f"campaign watchdog: campaign_id={report.campaign_id} "
        f"basis={report.basis} attribution_key={report.attribution_key} "
        f"total={report.total} throttle_eligible={report.throttle_eligible}"
    )


def default_notify_fn(msg: str) -> None:
    """The base ships no alert channel (friction doctrine: thresholds and the
    schedule are consumer policy; a notify channel is consumer infrastructure
    same as the meta-alarm's own heartbeat channel). This default makes that
    visible on stderr rather than silently no-op-ing — a consumer wires a
    real `notify_fn` (SNS, PagerDuty, Slack) in their own runner invocation."""
    print(f"campaign_runner: NOTIFY (no channel configured): {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def execute(
    *,
    now: datetime,
    min_attempts: int,
    window_seconds: int,
    list_keys: Callable[[str], Sequence[str]],
    get_object: Callable[[str], bytes],
    drops_prefix: str = DEFAULT_DROPS_PREFIX,
    filter_log_events: Callable[[str, int, int], Sequence[dict[str, Any]]] | None = None,
    flood_log_group: str | None = None,
    notify_fn: Callable[[str], None] = default_notify_fn,
    heartbeat_fn: Callable[[], None] | None = None,
    json_out: Path | str | None = None,
) -> list[CampaignReport]:
    """One watchdog run: heartbeat, sweep, correlate, alarm. Meta-alarm-wrapped.

    `emit_meta_alarm` calls `sys.exit(1)` — this function does not return in
    that case. On success (with or without campaigns found) it returns the
    list of `CampaignReport`s (possibly empty) after emitting content alarms
    and writing output, per the sa#29 standard's exit-code contract.
    """
    emit_heartbeat(component=COMPONENT, heartbeat_fn=heartbeat_fn)

    try:
        thresholds = CampaignThresholds(min_attempts=min_attempts, window_seconds=window_seconds)
        window_start = now - timedelta(seconds=thresholds.window_seconds)

        prefixes = day_prefixes(window_start, now, base_prefix=drops_prefix)
        events, malformed = sweep_drops(list_keys, get_object, prefixes)
        for key in malformed:
            print(f"campaign_runner: malformed drop record at {key}", file=sys.stderr)

        floods: list[FloodEvent] = []
        if flood_log_group is not None and filter_log_events is not None:
            floods = fetch_flood_events(filter_log_events, flood_log_group, window_start, now)

        reports = analyze(events, floods, thresholds, now)
    except Exception as exc:  # noqa: BLE001 — any runner-internal failure is a meta-alarm
        emit_meta_alarm(str(exc), component=COMPONENT)
        raise AssertionError("unreachable — emit_meta_alarm always exits")  # pragma: no cover

    if not reports:
        print(
            f"campaign watchdog: no campaigns detected "
            f"({len(events)} drop events, {len(floods)} flood events swept, "
            f"{len(malformed)} malformed objects) in the {thresholds.window_seconds}s "
            f"window ending {now.isoformat()}"
        )
        return reports

    for report in reports:
        emit_content_alarm(
            campaign_summary(report),
            notify_fn=notify_fn,
            component=COMPONENT,
            extra={"campaign_id": report.campaign_id, "basis": report.basis},
        )

    full_json = json.dumps([r.model_dump(mode="json") for r in reports], indent=2)
    print(full_json)
    if json_out is not None:
        Path(json_out).write_text(full_json, encoding="utf-8")

    return reports


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="campaign_runner",
        description=(
            "Reference scheduled runner for the sa#161 input-poisoning campaign "
            "watchdog (channels/WATCHDOG.md). Sweeps channels/drops/ DropRecords "
            "(and, optionally, the approval_queue_flood CloudWatch Logs signal) "
            "over a correlation window and reports attributed campaigns."
        ),
    )
    parser.add_argument(
        "--bucket", required=True, metavar="BUCKET",
        help="S3 bucket holding channels/drops/ (the airlock's audit bucket).",
    )
    parser.add_argument(
        "--min-attempts", type=int, required=True, metavar="N",
        help="CampaignThresholds.min_attempts — no base default (consumer policy).",
    )
    parser.add_argument(
        "--window-seconds", type=int, required=True, metavar="S",
        help="CampaignThresholds.window_seconds — no base default (consumer policy).",
    )
    parser.add_argument(
        "--drops-prefix", default=DEFAULT_DROPS_PREFIX, metavar="PREFIX",
        help=f"S3 key prefix for DropRecords (default: {DEFAULT_DROPS_PREFIX!r}).",
    )
    parser.add_argument(
        "--flood-log-group", default=None, metavar="LOG_GROUP",
        help="CloudWatch Logs group carrying approval_queue_flood lines. Unset "
        "(default) skips flood correlation entirely.",
    )
    parser.add_argument(
        "--json-out", default=None, metavar="PATH",
        help="Also write the full CampaignReport list JSON to this path.",
    )
    args = parser.parse_args()

    try:
        import boto3  # noqa: PLC0415 — lazy: no creds needed at import time
    except ImportError:
        emit_meta_alarm(
            "boto3 is not installed. Install the aws extra to run the live watchdog.",
            component=COMPONENT,
        )
        return  # pragma: no cover — emit_meta_alarm always exits

    s3_client = boto3.client("s3")
    list_keys, get_object = make_s3_readers(s3_client, args.bucket)

    filter_log_events = None
    if args.flood_log_group:
        logs_client = boto3.client("logs")
        filter_log_events = make_cloudwatch_filter(logs_client)

    def heartbeat_fn() -> None:
        cloudwatch = boto3.client("cloudwatch")
        cloudwatch.put_metric_data(
            Namespace="SafeAgents/Watchdog",
            MetricData=[{
                "MetricName": "WatchdogHeartbeat",
                "Dimensions": [{"Name": "Watchdog", "Value": COMPONENT}],
                "Value": 1,
                "Unit": "Count",
            }],
        )

    now = datetime.now(timezone.utc)

    execute(
        now=now,
        min_attempts=args.min_attempts,
        window_seconds=args.window_seconds,
        list_keys=list_keys,
        get_object=get_object,
        drops_prefix=args.drops_prefix,
        filter_log_events=filter_log_events,
        flood_log_group=args.flood_log_group,
        notify_fn=default_notify_fn,
        heartbeat_fn=heartbeat_fn,
        json_out=args.json_out,
    )


if __name__ == "__main__":
    main()
