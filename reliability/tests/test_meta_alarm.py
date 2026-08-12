"""Tests for reliability.meta_alarm — emit_heartbeat, emit_meta_alarm, emit_content_alarm.

The core invariant being tested: "watchdog broken" and "watchdog fired"
produce different exit codes and different output streams. They must not be
indistinguishable.
"""

import json
import pytest

from reliability.meta_alarm import emit_content_alarm, emit_heartbeat, emit_meta_alarm


# ---------------------------------------------------------------------------
# emit_meta_alarm — watchdog broken → exit 1, stderr JSON
# ---------------------------------------------------------------------------

def test_meta_alarm_exits_1(capsys):
    """Watchdog broken must exit 1 so CI sees a red build."""
    with pytest.raises(SystemExit) as exc_info:
        emit_meta_alarm("heartbeat loop crashed", component="test.watchdog")
    assert exc_info.value.code == 1


def test_meta_alarm_writes_to_stderr(capsys):
    """META-alarm must go to stderr, not stdout."""
    with pytest.raises(SystemExit):
        emit_meta_alarm("dependency failed", component="test.watchdog")

    captured = capsys.readouterr()
    assert captured.err.strip() != ""
    # stdout must be empty — meta-alarm is not a content signal
    assert captured.out.strip() == ""


def test_meta_alarm_record_is_valid_json(capsys):
    """The stderr output must be a single parseable JSON line."""
    with pytest.raises(SystemExit):
        emit_meta_alarm("configuration error", component="test.watchdog")

    captured = capsys.readouterr()
    lines = [ln for ln in captured.err.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected 1 JSON line, got {len(lines)}"
    record = json.loads(lines[0])
    assert record["level"] == "META_ALARM"
    assert record["signal"] == "watchdog_broken"
    assert record["msg"] == "configuration error"
    assert record["component"] == "test.watchdog"
    assert "ts" in record


def test_meta_alarm_ts_is_utc_iso8601(capsys):
    import datetime

    with pytest.raises(SystemExit):
        emit_meta_alarm("ts check", component="test.ts")

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    ts = datetime.datetime.fromisoformat(record["ts"])
    assert ts.tzinfo is not None


def test_meta_alarm_extra_fields_are_included(capsys):
    with pytest.raises(SystemExit):
        emit_meta_alarm("extended failure", component="test.ext", extra={"run_id": "abc123"})

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["run_id"] == "abc123"


# ---------------------------------------------------------------------------
# emit_content_alarm — watchdog fired correctly → notify called, exit 0
# ---------------------------------------------------------------------------

def test_content_alarm_does_not_exit(capsys):
    """Content alarm must return normally — the watchdog ran correctly."""
    notifications = []
    emit_content_alarm(
        "chain gap: 5 blocks",
        notify_fn=lambda m: notifications.append(m),
        component="test.watchdog",
    )
    # If we reach here, no SystemExit was raised — exit code will be 0.
    assert True


def test_content_alarm_calls_notify_fn(capsys):
    """notify_fn must be called with the alarm message."""
    notifications = []
    emit_content_alarm(
        "egress drift detected",
        notify_fn=lambda m: notifications.append(m),
        component="test.watchdog",
    )
    assert notifications == ["egress drift detected"]


def test_content_alarm_writes_to_stdout(capsys):
    """Content alarm record goes to stdout, not stderr."""
    emit_content_alarm(
        "budget threshold crossed",
        notify_fn=lambda _: None,
        component="test.watchdog",
    )
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    assert captured.err.strip() == ""


def test_content_alarm_record_is_valid_json(capsys):
    emit_content_alarm(
        "anomaly detected",
        notify_fn=lambda _: None,
        component="test.watchdog",
    )
    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["level"] == "ALARM"
    assert record["signal"] == "content_detected"
    assert record["msg"] == "anomaly detected"
    assert record["component"] == "test.watchdog"
    assert "ts" in record


def test_content_alarm_extra_fields(capsys):
    emit_content_alarm(
        "gap found",
        notify_fn=lambda _: None,
        component="test.ext",
        extra={"gap_blocks": 7},
    )
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["gap_blocks"] == 7


def test_content_alarm_notify_fn_called_before_return(capsys):
    """notify_fn must be called — not deferred — before the function returns."""
    order = []
    def notify(msg):
        order.append("notify")

    emit_content_alarm("test ordering", notify_fn=notify, component="test")
    order.append("returned")
    assert order == ["notify", "returned"]


# ---------------------------------------------------------------------------
# The key discriminant: exit codes are different
# ---------------------------------------------------------------------------

META_CASES = [
    ("watchdog process crashed",    "test.meta"),
    ("config file missing",         "test.meta"),
    ("boto3 credentials invalid",   "test.meta"),
]

CONTENT_CASES = [
    ("chain gap: 3 blocks",         "test.content"),
    ("egress drift: +12%",          "test.content"),
    ("budget: 95% consumed",        "test.content"),
]


@pytest.mark.parametrize("msg,component", META_CASES)
def test_meta_alarm_always_exits_1(msg, component, capsys):
    with pytest.raises(SystemExit) as exc_info:
        emit_meta_alarm(msg, component=component)
    assert exc_info.value.code == 1


@pytest.mark.parametrize("msg,component", CONTENT_CASES)
def test_content_alarm_never_exits(msg, component, capsys):
    # Will raise SystemExit if it exits non-zero; if it returns, assert passes.
    emit_content_alarm(msg, notify_fn=lambda _: None, component=component)


def test_meta_and_content_produce_different_exit_codes(capsys):
    """
    The canonical discriminant test.

    meta_alarm  → SystemExit(1)   (watchdog broken)
    content_alarm → no SystemExit (watchdog fired, paged, exit 0)
    """
    # META-alarm exits 1
    with pytest.raises(SystemExit) as exc_info:
        emit_meta_alarm("process died", component="test.discriminant")
    assert exc_info.value.code == 1

    # Content alarm does not exit
    notifications = []
    emit_content_alarm(
        "condition detected",
        notify_fn=notifications.append,
        component="test.discriminant",
    )
    assert len(notifications) == 1


# ---------------------------------------------------------------------------
# emit_heartbeat — liveness pulse, no exit
# ---------------------------------------------------------------------------

def test_heartbeat_does_not_exit():
    emit_heartbeat(component="test.heartbeat")


def test_heartbeat_calls_heartbeat_fn():
    pulses = []
    emit_heartbeat(component="test.hb", heartbeat_fn=lambda: pulses.append(True))
    assert len(pulses) == 1


def test_heartbeat_writes_to_stdout(capsys):
    emit_heartbeat(component="test.hb")
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    assert captured.err.strip() == ""


def test_heartbeat_record_is_valid_json(capsys):
    emit_heartbeat(component="test.hb")
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["level"] == "HEARTBEAT"
    assert record["signal"] == "watchdog_alive"
    assert record["component"] == "test.hb"
    assert "ts" in record
