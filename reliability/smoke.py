"""
smoke — reusable forced-failure smoke-test base harness (sa#6 / sa#28).

Purpose
-------
Verify that alert paths *actually fire*, not merely that the broker decides
correctly. A forced-failure smoke test deliberately triggers a deny/alarm
scenario and asserts the downstream signal (audit record, CloudWatch metric,
SNS event, DynamoDB intent record) was actually delivered. This tests
"the alarm works," not "the broker decided correctly."

Design
------
Checks are non-exiting: each call to check() or forced_failure_check()
records a CheckResult without calling sys.exit(). Only conclude() applies
meta-alarm exit semantics after all results are gathered.

Consumer repos subclass or configure the harness with their own probe
functions. This module contains no broker, connector, or domain-specific
logic — only the aggregation and exit-semantics machinery.

Exit-code contract (sa#29 meta-alarm semantics)
------------------------------------------------
conclude() with no checks recorded  → emit_meta_alarm  → sys.exit(1)
conclude() with all checks passed   → emit_heartbeat   → returns (exit 0)
conclude() with any check failed    → emit_content_alarm → notify_fn + returns (exit 0)

The distinction between "all passed" and "some failed" both produce exit 0
because the watchdog ran to completion in both cases. A non-zero exit (1)
signals only that the harness itself could not run — a meta-alarm condition.

Forced-failure pattern
----------------------
The forced-failure fixture triggers a scenario that SHOULD produce an alert
signal, then probes for that signal:

    probe_fn returns True  → check PASSES  (alert path works)
    probe_fn returns False → check FAILS   (alert path broken → content alarm)

Consumer receives one notify_fn call summarising which probes found nothing.

Example (consumer repo)
-----------------------
    harness = SmokeHarness(component="example-agent.smoke")

    harness.forced_failure_check(
        trigger_fn=lambda: submit_denied_call(broker_client),
        probe_fn=lambda: dynamodb_item_exists("audit", {"pk": {"S": "deny#001"}}),
        label="deny signal written to audit table",
    )
    harness.forced_failure_check(
        trigger_fn=lambda: submit_approval_call(broker_client),
        probe_fn=lambda: dynamodb_item_exists("intents", {"pk": {"S": "intent#001"}}),
        label="intent record written to DynamoDB",
    )

    harness.conclude(notify_fn=my_pager_fn)
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable

from reliability.meta_alarm import emit_content_alarm, emit_heartbeat, emit_meta_alarm


@dataclasses.dataclass
class CheckResult:
    """Result of a single smoke check."""

    label: str
    passed: bool
    detail: str | None = None


class SmokeHarness:
    """
    In-process check aggregator for alert-path smoke tests.

    Checks record pass/fail results without calling sys.exit(). Only
    conclude() applies the meta-alarm exit semantics once all checks
    have been gathered.

    The harness is intentionally environment-gated: smoke suites must not
    run in production. Pass environment='development' (default) or 'staging'.
    """

    _ALLOWED_ENVIRONMENTS = frozenset({"development", "staging"})

    def __init__(
        self,
        component: str = "smoke.harness",
        *,
        environment: str = "development",
    ) -> None:
        if environment not in self._ALLOWED_ENVIRONMENTS:
            # Includes "production" — smoke suites must never run there.
            raise ValueError(
                f"smoke harness refuses environment={environment!r}; "
                f"allowed: {sorted(self._ALLOWED_ENVIRONMENTS)}"
            )
        self._component = component
        self._environment = environment
        self._results: list[CheckResult] = []

    # ------------------------------------------------------------------
    # Non-exiting check primitives
    # ------------------------------------------------------------------

    def check(
        self,
        predicate: bool | Callable[[], bool],
        label: str,
        *,
        detail: str | None = None,
    ) -> bool:
        """Record a pass/fail result. Never calls sys.exit().

        predicate — bool or zero-arg callable returning bool.
        label     — human-readable invariant name.
        detail    — optional context (e.g., observed value).

        Returns True on pass, False on fail. The harness continues running
        regardless of the result — failures are aggregated, not fatal.
        """
        if callable(predicate):
            result = bool(predicate())
        else:
            result = bool(predicate)
        self._results.append(CheckResult(label=label, passed=result, detail=detail))
        return result

    def forced_failure_check(
        self,
        trigger_fn: Callable[[], Any],
        probe_fn: Callable[[], bool],
        label: str,
        *,
        detail: str | None = None,
    ) -> bool:
        """Forced-failure fixture: trigger a scenario, then probe for the signal.

        trigger_fn — callable that performs the action designed to produce a
                     deny/alarm (e.g., submit a BrokeredCall the policy must
                     deny). Its return value is ignored.
        probe_fn   — callable that checks whether the downstream signal was
                     emitted (e.g., an audit record, CloudWatch metric, or
                     DynamoDB intent row). Must return truthy on success.
        label      — human-readable invariant name.
        detail     — optional context.

        Semantics:
            probe_fn → True  : check PASSES  — the alert path fired correctly.
            probe_fn → False : check FAILS   — the alert path is broken.

        Exceptions from trigger_fn or probe_fn propagate to the caller.
        Catch them outside and call conclude() to emit the meta-alarm if the
        harness setup itself crashed.
        """
        trigger_fn()
        result = bool(probe_fn())
        self._results.append(CheckResult(label=label, passed=result, detail=detail))
        return result

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def results(self) -> list[CheckResult]:
        """All recorded results, in order."""
        return list(self._results)

    @property
    def failed(self) -> list[CheckResult]:
        """Subset of results that did not pass."""
        return [r for r in self._results if not r.passed]

    @property
    def all_passed(self) -> bool:
        """True if at least one check was recorded and every check passed."""
        return bool(self._results) and all(r.passed for r in self._results)

    def report(self) -> dict[str, Any]:
        """Return a structured summary dict. Does not call sys.exit() or emit alarms."""
        return {
            "component": self._component,
            "environment": self._environment,
            "total": len(self._results),
            "passed": sum(1 for r in self._results if r.passed),
            "failed": sum(1 for r in self._results if not r.passed),
            "checks": [
                {
                    "label": r.label,
                    "passed": r.passed,
                    **({"detail": r.detail} if r.detail is not None else {}),
                }
                for r in self._results
            ],
        }

    # ------------------------------------------------------------------
    # Meta-alarm exit semantics (sa#29)
    # ------------------------------------------------------------------

    def conclude(
        self,
        *,
        notify_fn: Callable[[str], None] | None = None,
        heartbeat_fn: Callable[[], None] | None = None,
    ) -> None:
        """Apply meta-alarm exit semantics. Call once, after all checks.

        Exit-code mapping (sa#29 — load-bearing):

            No checks recorded → emit_meta_alarm  → sys.exit(1)
                (harness misconfigured; the watchdog ran nothing)

            All checks passed  → emit_heartbeat + returns normally
                (watchdog alive; alert paths verified)

            Any check failed   → emit_content_alarm → notify_fn(summary) + returns
                (exit 0: watchdog ran and detected a broken alert path)

        notify_fn   — called with a summary string when any check fails.
                      Pass None to suppress notification (signal still emitted
                      to stdout per content-alarm semantics).
        heartbeat_fn — optional pulse for the monitoring channel on full pass.
        """
        if not self._results:
            emit_meta_alarm(
                "smoke harness concluded with no checks recorded — misconfigured suite",
                component=self._component,
            )
            return  # pragma: no cover — emit_meta_alarm exits 1

        if self.all_passed:
            emit_heartbeat(
                component=self._component,
                heartbeat_fn=heartbeat_fn,
                extra={"smoke_summary": self.report()},
            )
            return

        # Some checks failed: the watchdog detected a broken alert path.
        failed_labels = [r.label for r in self.failed]
        msg = (
            f"smoke: {len(self.failed)}/{len(self._results)} checks failed "
            f"in {self._component}: {failed_labels}"
        )
        _notify = notify_fn if notify_fn is not None else lambda _: None
        emit_content_alarm(msg, notify_fn=_notify, component=self._component)
