"""
External liveness watcher — daily check that each agent wrote a run record
within its expected window (sa#38).

Off-substrate by design: runs in GitHub Actions, survives any single arm dying.
Discovers agents by globbing agents/*.yaml; no hardcoded agent names.

Monitoring is opt-in (sa#140): only agents whose manifest declares
`liveness.monitored: true` are checked, scoped to `liveness.environments`
and, if declared, `liveness.calendar`. Fixture/smoke manifests without a
`liveness` block are never monitored.

Calendar pre-flight: if a monitored agent declares liveness.calendar, the
watcher calls the registered calendar check before alerting (avoids weekend/
holiday false alarms). The specific calendar implementation is a registered
hook, not hardcoded logic.

DynamoDB table: safe-agents-<env>-agent-runs  (CDK resourceName(env, "agent-runs"))
  agentId (HASH)  = <agent-name>
  runId   (RANGE) = "sched-<ISO-UTC>"  for scheduled runs (e.g. sched-2026-07-07T201608Z)
  attrs: status ("ok" | "skipped-closed" | "fail"), arm, ts (ISO-8601 UTC), results

The reader Queries for a civil date's scheduled runs
(runId begins_with "sched-<YYYY-MM-DD>") and takes the latest by `ts`.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml

# ---------------------------------------------------------------------------
# Calendar registry
# ---------------------------------------------------------------------------
# Each calendar function takes a date string (YYYY-MM-DD) and returns True if
# the agent should have run on that date. Return False → skip alarm (not a
# scheduled day). Extend here; do not hardcode logic in the watcher loop.
CALENDARS: dict[str, Callable[[str], bool]] = {}

# Statuses that count as a healthy scheduled run. Anything else — "fail", an
# unexpected value, or a missing record — raises a liveness alarm.
HEALTHY_STATUSES: frozenset[str] = frozenset({"ok", "skipped-closed"})


def register_calendar(name: str, fn: Callable[[str], bool]) -> None:
    """Register a named calendar check. Idempotent."""
    CALENDARS[name] = fn


# Built-in Mon-Fri calendar (sa#140): a plain base convenience, not a market/
# holiday calendar. Weekday holidays are still run-days here — a consumer
# whose agent has its own closed days should write "skipped-closed" itself
# (a healthy record) rather than needing a holiday table; only weekends
# suppress the check. Consumers needing real holiday nuance register their
# own calendar via register_calendar() instead.
register_calendar(
    "weekday",
    lambda d: date.fromisoformat(d).weekday() < 5,
)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class LivenessAlarm:
    agent: str
    environment: str
    expected_date: str
    last_seen_status: Optional[str]   # None → record missing entirely
    reason: str


# ---------------------------------------------------------------------------
# Manifest reader
# ---------------------------------------------------------------------------

def load_agent_manifests(agents_dir: Path) -> list[dict]:
    """
    Glob agents/*.yaml and parse each as a YAML dict.
    Silently skips files that cannot be parsed — validate-manifest CI catches those.
    """
    manifests: list[dict] = []
    for path in sorted(agents_dir.glob("*.yaml")):
        try:
            with path.open(encoding="utf-8") as fh:
                m = yaml.safe_load(fh)
            if isinstance(m, dict):
                m["_source_path"] = str(path)
                manifests.append(m)
        except Exception:
            pass
    return manifests


# ---------------------------------------------------------------------------
# Calendar pre-flight
# ---------------------------------------------------------------------------

def should_run_on(calendar_name: Optional[str], date: str) -> bool:
    """
    Return True if the agent should have run on `date` given its declared calendar.

    If no calendar is declared, the agent is assumed to run daily.
    If the calendar name is not registered, default to True (alert; safe side).
    """
    if not calendar_name:
        return True
    fn = CALENDARS.get(calendar_name)
    if fn is None:
        # Unknown calendar — conservatively assume the agent should have run.
        return True
    return fn(date)


# ---------------------------------------------------------------------------
# Liveness check
# ---------------------------------------------------------------------------

def monitored_targets(
    agents_dir: Path,
    environments: list[str],
    date: str,
) -> list[tuple[str, str]]:
    """The (agent, environment) pairs this watcher would actually check on `date`.

    Extracted so the watcher can say HOW MANY things it looked at, not only
    whether any of them alarmed. An empty result means the watcher is monitoring
    nothing — which is a completely different statement from "everything is
    healthy" and used to be indistinguishable from it: `main` printed "Liveness
    OK — all agents have run records" over an empty set and exited 0, daily
    (found 2026-07-29, sa#38).

    ONE selector, shared with check_liveness, deliberately. Two functions
    deciding independently what counts as monitored is how a watcher ends up
    reporting a count it did not check.

    Selection is opt-in and unchanged: `liveness.monitored: true`, not `arm:
    local`, due on this date per `liveness.calendar`, and restricted to the
    intersection of `liveness.environments` with the environments asked for.
    """
    targets: list[tuple[str, str]] = []
    for m in load_agent_manifests(agents_dir):
        name = m.get("name")
        liveness_cfg = m.get("liveness") or {}

        if not name:
            continue
        if m.get("arm", "") == "local":
            # Local arm: the run record lives on disk, not in DynamoDB.
            continue
        if not liveness_cfg.get("monitored"):
            # Opt-in scope: manifests without liveness.monitored: true are
            # not watcher targets (e.g. the arm-conformance smoke fixtures).
            continue
        if not should_run_on(liveness_cfg.get("calendar"), date):
            continue

        declared_envs = set(liveness_cfg.get("environments") or environments)
        targets.extend((name, env) for env in environments if env in declared_envs)
    return targets


def check_liveness(
    agents_dir: Path,
    environments: list[str],
    date: str,
    record_reader: Callable[[str, str, str], Optional[dict]],
) -> list[LivenessAlarm]:
    """
    Check each discovered agent × each environment for a run record on `date`.

    record_reader(agent_name, env, date) → Optional[dict]
        Returns the record dict (at minimum {"status": ...}) or None if missing.

    Monitoring is opt-in: an agent is only checked if its manifest declares
    `liveness.monitored: true`. Fixtures and other manifests without that
    block are silently skipped — no alarm, even with no record. A monitored
    agent's `liveness.calendar` (if any) feeds the calendar pre-flight, and
    its `liveness.environments` (if declared) restricts the check to the
    intersection with `environments` (e.g. a production-only agent is never
    checked against staging). Agents with arm: local are also skipped (no
    cloud run record expected).

    Healthy statuses are "ok" and "skipped-closed"; "fail" (or any unexpected
    status, or a missing record) alarms.
    """
    alarms: list[LivenessAlarm] = []

    for name, env in monitored_targets(agents_dir, environments, date):
        record = record_reader(name, env, date)
        if record is None:
            alarms.append(LivenessAlarm(
                agent=name,
                environment=env,
                expected_date=date,
                last_seen_status=None,
                reason=f"no run record found for {date} in {env}",
            ))
            continue

        status = record.get("status")
        if status in HEALTHY_STATUSES:
            # "ok" and "skipped-closed" are both healthy.
            continue

        if status == "fail":
            reason = f"run record for {date} in {env} has status=fail"
        else:
            reason = (
                f"run record for {date} in {env} has unexpected "
                f"status={status!r}"
            )
        alarms.append(LivenessAlarm(
            agent=name,
            environment=env,
            expected_date=date,
            last_seen_status=status,
            reason=reason,
        ))

    return alarms


# ---------------------------------------------------------------------------
# Record readers
# ---------------------------------------------------------------------------

def make_fixture_reader(
    fixtures: dict[str, Optional[dict]],
) -> Callable[[str, str, str], Optional[dict]]:
    """
    Build a record_reader backed by an in-memory fixture dict.
    Key format: "{agent_name}:{env}:{date}" → record dict or None.
    """
    def reader(agent_name: str, env: str, date: str) -> Optional[dict]:
        return fixtures.get(f"{agent_name}:{env}:{date}")
    return reader


def make_dynamodb_reader(
    dynamodb_client,
    table_prefix: str = "safe-agents",
    table_suffix: str = "agent-runs",
) -> Callable[[str, str, str], Optional[dict]]:
    """
    Build a record_reader backed by DynamoDB.

    Reads from the CDK-provisioned table `{table_prefix}-{env}-{table_suffix}`
    (production → `safe-agents-production-agent-runs`), keyed
    agentId (HASH) / runId (RANGE). Requires `dynamodb:Query`.

    For a given civil date it Queries that day's SCHEDULED runs
    (`runId begins_with "sched-<date>"`, which excludes manual/proof runs via
    the sort key — no scan) and returns the latest by the ISO-8601 `ts`
    attribute, flattened to a plain dict, or None if there are no such runs.
    """
    def reader(agent_name: str, env: str, date: str) -> Optional[dict]:
        table_name = f"{table_prefix}-{env}-{table_suffix}"
        try:
            resp = dynamodb_client.query(
                TableName=table_name,
                KeyConditionExpression="agentId = :a AND begins_with(runId, :p)",
                ExpressionAttributeValues={
                    ":a": {"S": agent_name},
                    ":p": {"S": f"sched-{date}"},
                },
            )
            items = resp.get("Items") or []
            if not items:
                return None
            # Flatten DynamoDB typed dicts → plain Python dicts, then pick the
            # latest scheduled run of the day by ISO-8601 `ts` (lexical == chrono).
            flat = [
                {k: list(v.values())[0] for k, v in item.items()}
                for item in items
            ]
            return max(flat, key=lambda r: r.get("ts", ""))
        except Exception as exc:
            # A Query error (e.g. AccessDenied) still collapses to the same
            # None as "no scheduled run", so the caller raises a missing-record
            # alarm rather than a distinct "watchdog error" — the two causes
            # remain indistinguishable to check_liveness. Logged here so a
            # permissions misconfig is at least visible in the workflow log
            # instead of silently masquerading as a missing-record alarm.
            # Separating the two properly needs a richer reader return
            # contract (#140).
            print(
                f"liveness: reader error for {agent_name}/{env}: {exc}",
                file=sys.stderr,
            )
            return None
    return reader


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _today_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="liveness",
        description=(
            "External liveness watcher — checks that each agent wrote a run record "
            "within its expected window. Runs in GitHub Actions against DynamoDB, "
            "or locally against a fixture for CI dry-runs."
        ),
    )
    parser.add_argument(
        "--agents-dir",
        default="agents",
        metavar="DIR",
        help="Directory containing agents/*.yaml (default: agents/)",
    )
    parser.add_argument(
        "--environments",
        nargs="+",
        default=["staging", "production"],
        metavar="ENV",
        help="Environments to check (default: staging production)",
    )
    parser.add_argument(
        "--date",
        default=None,
        metavar="YYYY-MM-DD",
        help="Logical date to check (default: today UTC)",
    )
    parser.add_argument(
        "--require-targets",
        action="store_true",
        help=(
            "Exit 2 when the watcher has NOTHING to monitor. Ships OFF so a fresh "
            "consumer with no agents yet is not permanently red; set it on a "
            "SCHEDULED run, where a silently-empty target set means the watcher "
            "has been quietly watching nothing."
        ),
    )
    parser.add_argument(
        "--fixture",
        default=None,
        metavar="FILE",
        help=(
            "Path to a JSON fixture file for CI dry-run mode. "
            "No AWS credentials required. "
            'Keys: "{name}:{env}:{date}" → {"status": ...} or null for missing.'
        ),
    )
    args = parser.parse_args(argv)

    # The workflow cron now fires at 22:00 UTC, after the day's ~20:15 UTC
    # scheduled run window (#140), so today-UTC is the correct civil date to
    # check by the time this runs.
    date = args.date or _today_utc()
    agents_dir = Path(args.agents_dir)

    if args.fixture:
        with open(args.fixture, encoding="utf-8") as fh:
            fixtures = json.load(fh)
        reader = make_fixture_reader(fixtures)
    else:
        try:
            import boto3  # noqa: PLC0415
            ddb = boto3.client("dynamodb")
        except ImportError:
            print(
                "ERROR: boto3 is not installed. "
                "Use --fixture for CI dry-run mode or install boto3 for live mode.",
                file=sys.stderr,
            )
            sys.exit(2)
        reader = make_dynamodb_reader(ddb)

    targets = monitored_targets(agents_dir, args.environments, date)

    # Said BEFORE any health claim, because "nothing alarmed" over an empty set
    # is not health. Until 2026-07-29 this path printed "Liveness OK — all agents
    # have run records" with zero agents monitored, and exited 0 on a daily cron:
    # a positive signal emitted by a watcher watching nothing.
    if not targets:
        print(
            f"NOT MONITORING: 0 agent x environment targets for {date} in "
            f"{args.environments}. No manifest in {agents_dir} sets "
            "liveness.monitored: true (or none is due on this date). This run "
            "checked NOTHING — it is not a health result.",
            file=sys.stderr,
        )
        sys.exit(2 if args.require_targets else 0)

    alarms = check_liveness(agents_dir, args.environments, date, reader)

    if not alarms:
        print(
            f"Liveness OK — {len(targets)} target(s) checked, all have run "
            f"records for {date}."
        )
        sys.exit(0)

    print(f"LIVENESS ALARMS for {date}:", file=sys.stderr)
    for alarm in alarms:
        print(
            f"  ALARM: {alarm.agent} / {alarm.environment}: {alarm.reason}",
            file=sys.stderr,
        )
    sys.exit(1)


if __name__ == "__main__":
    main()
