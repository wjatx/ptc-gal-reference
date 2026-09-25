"""
Tests for the external liveness watcher (sa#38, sa#140).

Covers:
  1. load_agent_manifests: discovers test-stub.yaml from agents/ dir
  2. "ok" record → no alarm
  3. Missing record → alarm with agent name and env in reason
  4. "fail" record → alarm with status=fail in reason
  5. arm:local agent is skipped
  6. Two agents in agents_dir: one ok, one missing → only the missing one alarms
  7. Market-closed calendar → no alarm fires
  8. Unknown calendar → defaults to True (alarm fires)
  9. make_fixture_reader and make_dynamodb_reader are importable
 10. check_liveness returns empty list when no manifests in agents_dir
 11. DynamoDB reader Queries sched-<date> runs; latest-by-ts drives the verdict
 12. Opt-in scope (sa#140): no liveness.monitored: true → never checked
 13. liveness.environments scoping: declared [production] agent not checked in staging
 14. weekday calendar: weekend date skipped; weekday date alarms
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from safe_agents.watcher.liveness import (
    check_liveness,
    load_agent_manifests,
    main,
    monitored_targets,
    make_dynamodb_reader,
    make_fixture_reader,
    register_calendar,
    CALENDARS,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"

TEST_DATE = "2026-06-28"
TEST_ENV = "staging"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_agent_manifest(
    agents_dir: Path,
    name: str,
    arm: str = "ec2",
    monitored: bool = True,
    liveness_environments: list[str] | None = None,
    calendar: str | None = None,
) -> Path:
    """
    Write a minimal agent YAML into agents_dir and return its path.

    Defaults to liveness.monitored: true so existing tests exercise the
    watcher's default checked path (sa#140's opt-in scope). Pass
    monitored=False to test the unmonitored/opt-out path.
    """
    liveness: dict = {"monitored": monitored}
    if liveness_environments is not None:
        liveness["environments"] = liveness_environments
    if calendar is not None:
        liveness["calendar"] = calendar

    path = agents_dir / f"{name}.yaml"
    path.write_text(yaml.dump({
        "name": name,
        "repo": f"git@github.com:Third-Ralph/{name}.git",
        "deploy_key_secret": f"{name}/deploy-key",
        "arm": arm,
        "policy": f"policies/{name}.yaml",
        "secrets": {"runner_keys": f"{name}/runner-keys"},
        "smoke": {
            "read_only": True,
            "prompt": "What does this agent do?",
            "expect_substring": "agent",
        },
        "envelope": {"polarity": "abstain"},
        "liveness": liveness,
    }), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. load_agent_manifests discovers test-stub.yaml
# ---------------------------------------------------------------------------

def test_load_agent_manifests_discovers_test_stub() -> None:
    """load_agent_manifests must discover agents/test-stub.yaml."""
    manifests = load_agent_manifests(AGENTS_DIR)
    names = [m.get("name") for m in manifests]
    assert "test-stub" in names, (
        f"Expected 'test-stub' in discovered manifests; found: {names}"
    )


# ---------------------------------------------------------------------------
# 2. "ok" record → no alarm
# ---------------------------------------------------------------------------

def test_ok_record_produces_no_alarm(tmp_path: Path) -> None:
    """An agent with status='ok' must not generate an alarm."""
    _write_agent_manifest(tmp_path, "alpha")
    reader = make_fixture_reader({
        f"alpha:{TEST_ENV}:{TEST_DATE}": {"status": "ok"},
    })
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert alarms == [], f"Expected no alarms; got: {alarms}"


def test_skipped_closed_record_produces_no_alarm(tmp_path: Path) -> None:
    """status='skipped-closed' (nothing to do, e.g. market closed) is healthy."""
    _write_agent_manifest(tmp_path, "alpha")
    reader = make_fixture_reader({
        f"alpha:{TEST_ENV}:{TEST_DATE}": {"status": "skipped-closed"},
    })
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert alarms == [], f"Expected no alarms; got: {alarms}"


# ---------------------------------------------------------------------------
# 3. Missing record → alarm with agent name and env in reason
# ---------------------------------------------------------------------------

def test_missing_record_produces_alarm(tmp_path: Path) -> None:
    """A missing run record must produce an alarm naming the agent and env."""
    _write_agent_manifest(tmp_path, "beta")
    reader = make_fixture_reader({})  # no records
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert len(alarms) == 1
    alarm = alarms[0]
    assert alarm.agent == "beta"
    assert alarm.environment == TEST_ENV
    assert "beta" in alarm.reason or "beta" in alarm.agent
    assert alarm.last_seen_status is None


# ---------------------------------------------------------------------------
# 4. "fail" record → alarm
# ---------------------------------------------------------------------------

def test_failed_record_produces_alarm(tmp_path: Path) -> None:
    """A run record with status='fail' must produce an alarm."""
    _write_agent_manifest(tmp_path, "gamma")
    reader = make_fixture_reader({
        f"gamma:{TEST_ENV}:{TEST_DATE}": {"status": "fail"},
    })
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert len(alarms) == 1
    alarm = alarms[0]
    assert alarm.agent == "gamma"
    assert alarm.last_seen_status == "fail"
    assert "fail" in alarm.reason


def test_unexpected_status_produces_alarm(tmp_path: Path) -> None:
    """An unrecognized status is not treated as healthy — it must alarm."""
    _write_agent_manifest(tmp_path, "gamma")
    reader = make_fixture_reader({
        f"gamma:{TEST_ENV}:{TEST_DATE}": {"status": "ran"},  # old vocab, now unknown
    })
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert len(alarms) == 1
    assert alarms[0].last_seen_status == "ran"
    assert "unexpected" in alarms[0].reason


# ---------------------------------------------------------------------------
# 5. arm:local agent is skipped
# ---------------------------------------------------------------------------

def test_local_arm_is_skipped(tmp_path: Path) -> None:
    """Agents with arm:local must not generate alarms (no DynamoDB record)."""
    _write_agent_manifest(tmp_path, "local-agent", arm="local")
    reader = make_fixture_reader({})  # would alarm if local arm wasn't excluded
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert alarms == [], f"Expected no alarms for local arm; got: {alarms}"


# ---------------------------------------------------------------------------
# 6. Two agents: one ok, one missing → only the missing one alarms
# ---------------------------------------------------------------------------

def test_two_agents_one_missing_one_ran(tmp_path: Path) -> None:
    """With two agents, only the one without a run record should alarm."""
    _write_agent_manifest(tmp_path, "agent-ok")
    _write_agent_manifest(tmp_path, "agent-missing")
    reader = make_fixture_reader({
        f"agent-ok:{TEST_ENV}:{TEST_DATE}": {"status": "ok"},
        # agent-missing has no record
    })
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    alarmed_names = [a.agent for a in alarms]
    assert "agent-missing" in alarmed_names, (
        f"Expected 'agent-missing' to alarm; got: {alarmed_names}"
    )
    assert "agent-ok" not in alarmed_names, (
        f"'agent-ok' should not alarm; got: {alarmed_names}"
    )


# ---------------------------------------------------------------------------
# 7. Market-closed calendar → no alarm fires
# ---------------------------------------------------------------------------

def test_calendar_closed_day_no_alarm(tmp_path: Path) -> None:
    """When a registered calendar returns False, no alarm is raised."""
    calendar_name = "test-market-closed"
    # Register a calendar that always says "not a run day"
    register_calendar(calendar_name, lambda date: False)

    try:
        _write_agent_manifest(tmp_path, "cal-agent", calendar=calendar_name)

        reader = make_fixture_reader({})  # no records — would alarm if calendar not respected
        alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
        assert alarms == [], (
            f"Expected no alarms on a closed calendar day; got: {alarms}"
        )
    finally:
        CALENDARS.pop(calendar_name, None)


# ---------------------------------------------------------------------------
# 8. Unknown calendar → defaults to True (alarm fires)
# ---------------------------------------------------------------------------

def test_unknown_calendar_defaults_to_alarm(tmp_path: Path) -> None:
    """An unknown calendar name must default to True (conservative; alarm fires)."""
    # Ensure the calendar is definitely not registered
    CALENDARS.pop("no-such-calendar-xyz", None)

    _write_agent_manifest(
        tmp_path, "unknown-cal-agent", calendar="no-such-calendar-xyz",
    )

    reader = make_fixture_reader({})  # no records
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    alarmed_names = [a.agent for a in alarms]
    assert "unknown-cal-agent" in alarmed_names, (
        f"Expected unknown calendar to default to alarm; got: {alarmed_names}"
    )


# ---------------------------------------------------------------------------
# 9. make_fixture_reader and make_dynamodb_reader are importable
# ---------------------------------------------------------------------------

def test_reader_factories_importable() -> None:
    """Verify that the record reader factories import and construct cleanly."""
    reader = make_fixture_reader({"a:staging:2026-01-01": {"status": "ok"}})
    assert reader("a", "staging", "2026-01-01") == {"status": "ok"}
    assert reader("a", "staging", "2026-01-02") is None

    # make_dynamodb_reader takes a client object; just verify it's importable and callable
    assert callable(make_dynamodb_reader)


# ---------------------------------------------------------------------------
# 10. check_liveness returns empty list when no manifests in agents_dir
# ---------------------------------------------------------------------------

def test_no_manifests_no_alarms(tmp_path: Path) -> None:
    """An empty agents_dir produces no alarms."""
    reader = make_fixture_reader({})
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert alarms == []


# ---------------------------------------------------------------------------
# 11. DynamoDB reader Queries sched-<date> runs; latest-by-ts drives the verdict
# ---------------------------------------------------------------------------

class _FakeDynamoClient:
    """
    Minimal DynamoDB client stub. Records the last Query and returns preset
    typed Items for the queried agentId, filtered by the sched-<date> prefix —
    exactly what the real client would return for
    `agentId = :a AND begins_with(runId, :p)`.
    """

    def __init__(self, items_by_agent: dict[str, list[dict]]) -> None:
        self._items_by_agent = items_by_agent
        self.last_query: dict | None = None

    def query(self, **kwargs) -> dict:  # noqa: N802 (boto3 casing)
        self.last_query = kwargs
        eav = kwargs["ExpressionAttributeValues"]
        agent = eav[":a"]["S"]
        prefix = eav[":p"]["S"]
        items = [
            it for it in self._items_by_agent.get(agent, [])
            if it["runId"]["S"].startswith(prefix)
        ]
        return {"Items": items}


def test_query_reader_latest_by_ts_drives_verdict(tmp_path: Path) -> None:
    """
    The DynamoDB reader Queries a day's sched-<date> runs and lets the LATEST
    by `ts` decide the verdict, regardless of insertion order. Guards the new
    query semantics (repointed table + Query + latest-by-ts).
    """
    _write_agent_manifest(tmp_path, "delta")

    def item(hhmmss: str, status: str) -> dict:
        stamp = f"{TEST_DATE}T{hhmmss}Z"
        return {
            "agentId": {"S": "delta"},
            "runId": {"S": f"sched-{stamp}"},
            "status": {"S": status},
            "ts": {"S": stamp},
            "arm": {"S": "fargate"},
        }

    # Latest ts (20:16) is healthy → no alarm, even though earlier runs failed.
    healthy = [item("080000", "fail"), item("201600", "ok"), item("120000", "fail")]
    reader_ok = make_dynamodb_reader(_FakeDynamoClient({"delta": healthy}))
    assert check_liveness(tmp_path, ["production"], TEST_DATE, reader_ok) == []

    # Latest ts (20:16) is a failure → alarm, even though an earlier run was ok.
    unhealthy = [item("080000", "ok"), item("201600", "fail")]
    client = _FakeDynamoClient({"delta": unhealthy})
    reader_bad = make_dynamodb_reader(client)
    alarms = check_liveness(tmp_path, ["production"], TEST_DATE, reader_bad)
    assert [a.last_seen_status for a in alarms] == ["fail"]

    # The reader targeted the CDK table via Query with the sched-<date> prefix.
    assert client.last_query["TableName"] == "safe-agents-production-agent-runs"
    assert client.last_query["ExpressionAttributeValues"][":p"]["S"] == f"sched-{TEST_DATE}"


# ---------------------------------------------------------------------------
# 12. Opt-in scope (sa#140): no liveness.monitored: true → never checked
# ---------------------------------------------------------------------------

def test_unmonitored_agent_is_never_checked(tmp_path: Path) -> None:
    """An agent without liveness.monitored: true must not alarm, even with no record."""
    _write_agent_manifest(tmp_path, "unmonitored", monitored=False)
    reader = make_fixture_reader({})  # no records — would alarm if monitoring weren't opt-in
    alarms = check_liveness(tmp_path, [TEST_ENV], TEST_DATE, reader)
    assert alarms == [], f"Expected no alarms for an unmonitored agent; got: {alarms}"


# ---------------------------------------------------------------------------
# 13. liveness.environments scoping: declared [production] agent not
#     checked in staging
# ---------------------------------------------------------------------------

def test_environments_scoping_restricts_to_declared_envs(tmp_path: Path) -> None:
    """
    A monitored agent declared for liveness.environments: [production] must
    not be checked (and so never alarms) against staging, even with no
    record — but still alarms in production.
    """
    _write_agent_manifest(
        tmp_path, "prod-only", liveness_environments=["production"],
    )
    reader = make_fixture_reader({})  # no records anywhere

    staging_alarms = check_liveness(tmp_path, ["staging"], TEST_DATE, reader)
    assert staging_alarms == [], (
        f"Expected no alarms in staging for a production-only agent; "
        f"got: {staging_alarms}"
    )

    prod_alarms = check_liveness(tmp_path, ["production"], TEST_DATE, reader)
    alarmed_names = [a.agent for a in prod_alarms]
    assert "prod-only" in alarmed_names, (
        f"Expected 'prod-only' to alarm when checked in production; "
        f"got: {alarmed_names}"
    )


# ---------------------------------------------------------------------------
# 14. weekday calendar: weekend date skipped; weekday date alarms
# ---------------------------------------------------------------------------

def test_weekday_calendar_skips_weekend(tmp_path: Path) -> None:
    """A Saturday date must be skipped (no alarm) even with no run record."""
    _write_agent_manifest(tmp_path, "weekday-agent", calendar="weekday")
    reader = make_fixture_reader({})  # no records
    saturday = "2026-07-04"  # confirmed Saturday
    alarms = check_liveness(tmp_path, [TEST_ENV], saturday, reader)
    assert alarms == [], f"Expected no alarms on a Saturday; got: {alarms}"


def test_weekday_calendar_alarms_on_weekday(tmp_path: Path) -> None:
    """A weekday date with no run record must still alarm."""
    _write_agent_manifest(tmp_path, "weekday-agent", calendar="weekday")
    reader = make_fixture_reader({})  # no records
    monday = "2026-07-06"  # confirmed Monday
    alarms = check_liveness(tmp_path, [TEST_ENV], monday, reader)
    alarmed_names = [a.agent for a in alarms]
    assert "weekday-agent" in alarmed_names, (
        f"Expected 'weekday-agent' to alarm on a weekday with no record; "
        f"got: {alarmed_names}"
    )


# ---------------------------------------------------------------------------
# Monitoring nothing is not health (sa#38, found 2026-07-29)
# ---------------------------------------------------------------------------
#
# The watcher ran daily against a repo where no manifest sets
# `liveness.monitored: true`. It queried an empty set, printed "Liveness OK — all
# agents have run records", and exited 0. A green meaning "I found nothing to
# check" is indistinguishable from "every monitored agent ran healthy", and it is
# the kind of signal that later gets cited as "we have liveness monitoring".


def test_monitored_targets_is_empty_when_nothing_opts_in(tmp_path):
    (tmp_path / "a.yaml").write_text("name: unmonitored\narm: fargate\n", encoding="utf-8")

    assert monitored_targets(tmp_path, ["staging", "production"], "2026-07-29") == []


def test_monitored_targets_lists_each_agent_environment_pair(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "name: watched\narm: fargate\nliveness:\n  monitored: true\n", encoding="utf-8"
    )

    targets = monitored_targets(tmp_path, ["staging", "production"], "2026-07-29")

    assert sorted(targets) == [("watched", "production"), ("watched", "staging")]


def test_monitored_targets_honours_declared_environments(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "name: prodonly\narm: fargate\nliveness:\n  monitored: true\n"
        "  environments: [production]\n", encoding="utf-8"
    )

    targets = monitored_targets(tmp_path, ["staging", "production"], "2026-07-29")

    assert targets == [("prodonly", "production")]


def test_monitored_targets_skips_the_local_arm(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "name: onbox\narm: local\nliveness:\n  monitored: true\n", encoding="utf-8"
    )

    assert monitored_targets(tmp_path, ["staging"], "2026-07-29") == []


def test_the_selector_is_shared_with_check_liveness(tmp_path):
    """One selector, or the watcher reports a count it did not check.

    An agent that IS a target must alarm when its record is missing; an agent
    that is NOT a target must not — and both answers come from the same function.
    """
    (tmp_path / "watched.yaml").write_text(
        "name: watched\narm: fargate\nliveness:\n  monitored: true\n", encoding="utf-8"
    )
    (tmp_path / "ignored.yaml").write_text("name: ignored\narm: fargate\n", encoding="utf-8")

    targets = monitored_targets(tmp_path, ["staging"], "2026-07-29")
    alarms = check_liveness(tmp_path, ["staging"], "2026-07-29", lambda *_: None)

    assert targets == [("watched", "staging")]
    assert [a.agent for a in alarms] == ["watched"]


def test_empty_target_set_is_reported_and_never_claims_health(tmp_path, capsys):
    """The regression. The old code printed a health claim here and exited 0."""
    (tmp_path / "a.yaml").write_text("name: unmonitored\narm: fargate\n", encoding="utf-8")
    fixture = tmp_path / "f.json"
    fixture.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main([
            "--agents-dir", str(tmp_path),
            "--environments", "staging",
            "--fixture", str(fixture),
        ])

    err = capsys.readouterr().err
    assert exc.value.code == 0  # not an alarm: nothing is broken
    assert "NOT MONITORING" in err
    assert "checked NOTHING" in err
    # The specific false claim that used to be emitted here.
    assert "all agents have run records" not in err


def test_require_targets_makes_an_empty_set_a_failure(tmp_path):
    """Ships OFF so a fresh consumer is not permanently red; a consumer with a
    SCHEDULED run sets it, because a silently-empty target set there means the
    watcher has been watching nothing."""
    (tmp_path / "a.yaml").write_text("name: unmonitored\narm: fargate\n", encoding="utf-8")
    fixture = tmp_path / "f.json"
    fixture.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main([
            "--agents-dir", str(tmp_path),
            "--environments", "staging",
            "--fixture", str(fixture),
            "--require-targets",
        ])

    assert exc.value.code == 2
