"""Tests for reliability.smoke — forced-failure smoke-test base harness (sa#28).

Acceptance criteria verified here:
  1. Harness runs a set of checks and aggregates results without exiting mid-run.
  2. A forced failure is detected and reported as a failure (not a crash).
  3. A passing check reports pass.
  4. conclude() follows the meta-alarm exit semantics (sa#29):
       no checks   → exit 1 (meta_alarm)
       all passed  → exit 0 / returns (heartbeat)
       any failed  → exit 0 / returns (content_alarm, notify_fn called)
  5. Forced-failure smoke scenario is demonstrated end-to-end.
"""

import json

import pytest

from reliability.smoke import SmokeHarness


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_harness(**kwargs) -> SmokeHarness:
    """Return a development-environment harness, overridable via kwargs."""
    kwargs.setdefault("component", "test.smoke")
    kwargs.setdefault("environment", "development")
    return SmokeHarness(**kwargs)


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------

def test_production_environment_is_refused():
    with pytest.raises(ValueError, match="refuses environment='production'"):
        SmokeHarness(environment="production")


def test_invalid_environment_is_refused():
    with pytest.raises(ValueError, match="refuses environment"):
        SmokeHarness(environment="prod")


def test_development_environment_is_accepted():
    h = SmokeHarness(environment="development")
    assert h is not None


def test_staging_environment_is_accepted():
    h = SmokeHarness(environment="staging")
    assert h is not None


# ---------------------------------------------------------------------------
# check() — non-exiting pass/fail accumulation
# ---------------------------------------------------------------------------

PASS_FAIL_CASES = [
    # (predicate,       label,             expected_passed)
    (True,             "row written",       True),
    (False,            "row written",       False),
    (lambda: True,     "bucket reachable",  True),
    (lambda: False,    "bucket reachable",  False),
]


@pytest.mark.parametrize("predicate, label, expected_passed", PASS_FAIL_CASES)
def test_check_records_result(predicate, label, expected_passed):
    """check() records the result without calling sys.exit()."""
    h = make_harness()
    returned = h.check(predicate, label)
    assert returned == expected_passed
    assert len(h.results) == 1
    assert h.results[0].label == label
    assert h.results[0].passed == expected_passed


def test_check_does_not_exit_on_failure():
    """A failing check must NOT call sys.exit() — it only records a failure."""
    h = make_harness()
    h.check(False, "deny signal present")
    h.check(False, "audit record written")
    h.check(True,  "intent record in DynamoDB")
    # If any check called sys.exit() we would not reach this assertion.
    assert len(h.results) == 3


def test_multiple_checks_aggregate_in_order():
    """Results appear in insertion order."""
    h = make_harness()
    h.check(True,  "first")
    h.check(False, "second")
    h.check(True,  "third")
    labels = [r.label for r in h.results]
    assert labels == ["first", "second", "third"]


def test_check_detail_is_stored():
    h = make_harness()
    h.check(False, "deny signal", detail="probe found no DynamoDB item")
    assert h.results[0].detail == "probe found no DynamoDB item"


def test_check_returns_bool_for_callable():
    h = make_harness()
    result = h.check(lambda: 42, "truthy int")  # non-bool truthy
    assert result is True
    assert h.results[0].passed is True


# ---------------------------------------------------------------------------
# forced_failure_check() — trigger + probe pattern
# ---------------------------------------------------------------------------

def test_forced_failure_check_passes_when_probe_finds_signal():
    """Trigger fires; probe finds the signal → check passes."""
    fired = []

    def trigger():
        fired.append("denied")  # simulates broker deny

    def probe():
        return len(fired) > 0  # signal was recorded

    h = make_harness()
    result = h.forced_failure_check(trigger, probe, "deny signal written")
    assert result is True
    assert h.results[0].passed is True


def test_forced_failure_check_fails_when_probe_finds_nothing():
    """Trigger fires; probe finds nothing → check fails (alert path broken)."""
    def trigger():
        pass  # trigger ran but downstream signal was silently swallowed

    def probe():
        return False  # no signal found

    h = make_harness()
    result = h.forced_failure_check(trigger, probe, "deny signal written")
    assert result is False
    assert h.results[0].passed is False


def test_forced_failure_check_calls_trigger_before_probe():
    """trigger_fn is always called before probe_fn."""
    order = []
    h = make_harness()
    h.forced_failure_check(
        trigger_fn=lambda: order.append("trigger"),
        probe_fn=lambda: order.append("probe") or True,
        label="ordering check",
    )
    assert order == ["trigger", "probe"]


def test_forced_failure_check_does_not_exit_on_probe_failure():
    """A failing probe must not call sys.exit — the harness continues."""
    h = make_harness()
    h.forced_failure_check(lambda: None, lambda: False, "broken alert path")
    h.forced_failure_check(lambda: None, lambda: True,  "working alert path")
    assert len(h.results) == 2


def test_forced_failure_check_detail_is_stored():
    h = make_harness()
    h.forced_failure_check(
        lambda: None,
        lambda: False,
        "intent record in DynamoDB",
        detail="table: intents, key: intent#001",
    )
    assert h.results[0].detail == "table: intents, key: intent#001"


# ---------------------------------------------------------------------------
# Introspection helpers
# ---------------------------------------------------------------------------

def test_failed_property_returns_only_failures():
    h = make_harness()
    h.check(True,  "a")
    h.check(False, "b")
    h.check(False, "c")
    h.check(True,  "d")
    assert [r.label for r in h.failed] == ["b", "c"]


def test_all_passed_true_when_all_checks_pass():
    h = make_harness()
    h.check(True, "x")
    h.check(True, "y")
    assert h.all_passed is True


def test_all_passed_false_when_any_check_fails():
    h = make_harness()
    h.check(True,  "x")
    h.check(False, "y")
    assert h.all_passed is False


def test_all_passed_false_when_no_checks_recorded():
    """An empty harness is not "all passed" — that would be a false positive."""
    h = make_harness()
    assert h.all_passed is False


def test_report_structure():
    h = make_harness(component="test.report")
    h.check(True,  "alpha")
    h.check(False, "beta", detail="not found")
    rpt = h.report()
    assert rpt["total"] == 2
    assert rpt["passed"] == 1
    assert rpt["failed"] == 1
    assert rpt["component"] == "test.report"
    assert rpt["environment"] == "development"
    assert rpt["checks"][0] == {"label": "alpha", "passed": True}
    assert rpt["checks"][1] == {"label": "beta", "passed": False, "detail": "not found"}


def test_report_omits_detail_key_when_not_set():
    h = make_harness()
    h.check(True, "no detail")
    rpt = h.report()
    assert "detail" not in rpt["checks"][0]


# ---------------------------------------------------------------------------
# conclude() — meta-alarm exit semantics (sa#29)
# ---------------------------------------------------------------------------

def test_conclude_meta_alarm_when_no_checks(capsys):
    """No checks → harness is misconfigured → meta_alarm → exit 1."""
    h = make_harness()
    with pytest.raises(SystemExit) as exc_info:
        h.conclude()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["level"] == "META_ALARM"
    assert "no checks recorded" in record["msg"]


def test_conclude_heartbeat_when_all_passed(capsys):
    """All checks passed → heartbeat → returns normally (exit 0)."""
    h = make_harness()
    h.check(True, "deny signal")
    h.check(True, "intent record")
    h.conclude()  # must return without raising SystemExit
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["level"] == "HEARTBEAT"
    assert record["signal"] == "watchdog_alive"
    assert record["component"] == "test.smoke"
    assert "smoke_summary" in record


def test_conclude_heartbeat_calls_heartbeat_fn(capsys):
    """heartbeat_fn is invoked when all checks pass."""
    pulses = []
    h = make_harness()
    h.check(True, "all good")
    h.conclude(heartbeat_fn=lambda: pulses.append(True))
    assert len(pulses) == 1


def test_conclude_content_alarm_when_any_failed(capsys):
    """Any failure → content_alarm → notify_fn called → returns (exit 0)."""
    notifications = []
    h = make_harness()
    h.check(True,  "probe A")
    h.check(False, "probe B")
    h.conclude(notify_fn=notifications.append)
    # content_alarm returns normally — no SystemExit
    assert len(notifications) == 1
    msg = notifications[0]
    assert "probe B" in msg
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["level"] == "ALARM"
    assert record["signal"] == "content_detected"


def test_conclude_content_alarm_summary_includes_failure_count(capsys):
    notifications = []
    h = make_harness()
    h.check(True,  "ok")
    h.check(False, "broken-a")
    h.check(False, "broken-b")
    h.conclude(notify_fn=notifications.append)
    assert "2/3" in notifications[0]


def test_conclude_content_alarm_without_notify_fn_still_returns(capsys):
    """No notify_fn — alarm still emits to stdout and returns without exit."""
    h = make_harness()
    h.check(False, "silent failure")
    h.conclude()  # no notify_fn — must not raise
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["level"] == "ALARM"


def test_conclude_meta_alarm_writes_stderr_not_stdout(capsys):
    """Meta-alarm goes to stderr; stdout stays clean."""
    h = make_harness()
    with pytest.raises(SystemExit):
        h.conclude()
    captured = capsys.readouterr()
    assert captured.err.strip() != ""
    assert captured.out.strip() == ""


def test_conclude_content_alarm_writes_stdout_not_stderr(capsys):
    """Content alarm goes to stdout; stderr stays clean."""
    h = make_harness()
    h.check(False, "broken path")
    h.conclude()
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    assert captured.err.strip() == ""


# ---------------------------------------------------------------------------
# End-to-end forced-failure smoke scenario
#
# Demonstrates the full pattern a consumer repo would use:
#   1. Set up a "system under test" with a known deny-path.
#   2. Trigger the deny scenario.
#   3. Probe for the downstream signal.
#   4. Conclude — the harness emits heartbeat (all paths verified) or
#      content alarm (broken path detected).
#
# This scenario uses an in-process fake "broker" and "audit log" so no
# external infrastructure is needed. The same pattern applies against a
# real development-environment broker stack.
# ---------------------------------------------------------------------------

class _FakeBroker:
    """Minimal stand-in for a broker that records deny decisions to an audit log."""

    def __init__(self):
        self._audit: list[dict] = []

    def submit(self, call: dict) -> str:
        """Return 'deny' for any call targeting 'restricted_tool'; else 'allow'."""
        if call.get("tool") == "restricted_tool":
            self._audit.append({"decision": "deny", "tool": call["tool"]})
            return "deny"
        self._audit.append({"decision": "allow", "tool": call["tool"]})
        return "allow"

    def has_deny_record(self, tool: str) -> bool:
        return any(
            r["decision"] == "deny" and r["tool"] == tool for r in self._audit
        )


def test_forced_failure_smoke_scenario_full_pass(capsys):
    """
    End-to-end forced-failure scenario: broker has correct deny policy.

    Steps:
      1. Submit a call that the deny policy must reject.
      2. Probe: did the deny decision appear in the audit log?
      3. conclude() → heartbeat (the alert path was verified as working).
    """
    broker = _FakeBroker()  # deny policy is wired correctly

    harness = SmokeHarness(component="smoke.scenario.deny", environment="development")
    harness.emit_heartbeat_and_check_deny_path(broker)  # see helper below

    # Direct forced_failure_check call — equivalent to what a consumer would write:
    harness2 = SmokeHarness(component="smoke.scenario.deny2", environment="development")
    harness2.forced_failure_check(
        trigger_fn=lambda: broker.submit({"tool": "restricted_tool"}),
        probe_fn=lambda: broker.has_deny_record("restricted_tool"),
        label="deny signal written to audit log",
    )
    harness2.conclude()

    captured = capsys.readouterr()
    # conclude() on all-pass emits heartbeat to stdout
    record = json.loads(captured.out.strip())
    assert record["level"] == "HEARTBEAT"
    assert record["signal"] == "watchdog_alive"


def test_forced_failure_smoke_scenario_misconfigured_deny(capsys):
    """
    End-to-end forced-failure scenario: broker's deny policy is misconfigured.

    The broker silently allows the restricted tool (policy bug). The probe
    finds no deny record. The harness detects the broken alert path and fires
    a content alarm (exit 0, but notify_fn is called).
    """
    class _PermissiveBroker(_FakeBroker):
        def submit(self, call: dict) -> str:
            # Bug: always allows, never records deny — alert path is broken.
            self._audit.append({"decision": "allow", "tool": call["tool"]})
            return "allow"

    broker = _PermissiveBroker()
    notifications = []

    harness = SmokeHarness(component="smoke.scenario.misconfigured", environment="development")
    harness.forced_failure_check(
        trigger_fn=lambda: broker.submit({"tool": "restricted_tool"}),
        probe_fn=lambda: broker.has_deny_record("restricted_tool"),
        label="deny signal written to audit log",
    )
    harness.conclude(notify_fn=notifications.append)

    # conclude() returns normally (exit 0) — the watchdog ran and detected the fault.
    assert len(notifications) == 1
    assert "deny signal written to audit log" in notifications[0]

    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["level"] == "ALARM"
    assert record["signal"] == "content_detected"
    assert "misconfigured" in record["component"]


# Helper used by the full-pass scenario test to avoid inline lambda sprawl.
# Placed after the test to keep the test readable.

def _emit_heartbeat_and_check_deny_path(self: SmokeHarness, broker: _FakeBroker) -> None:
    self.forced_failure_check(
        trigger_fn=lambda: broker.submit({"tool": "restricted_tool"}),
        probe_fn=lambda: broker.has_deny_record("restricted_tool"),
        label="deny signal written to audit log",
    )


# Attach as method — avoids importing a bare function in the test body.
SmokeHarness.emit_heartbeat_and_check_deny_path = _emit_heartbeat_and_check_deny_path  # type: ignore[attr-defined]
