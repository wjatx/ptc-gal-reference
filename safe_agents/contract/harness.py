"""
Runner-contract conformance harness.

Tests a candidate agent directory against the eight checks derived from
core/RUNNER-CONTRACT.md. Each check produces a named violation so that CI
output is unambiguous about which element or clause failed.

Usage:
    python3 harness.py <agent-dir>

Or import and call run_harness(agent_dir) from pytest tests.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Violation names — one per check, printed verbatim on failure.
# ---------------------------------------------------------------------------

ELEMENT_1_HEADLESS_ENTRYPOINT = "ELEMENT_1_HEADLESS_ENTRYPOINT"
ELEMENT_2_SECRETS_FROM_ENV    = "ELEMENT_2_SECRETS_FROM_ENV"
ELEMENT_3_PREFLIGHT_GATE      = "ELEMENT_3_PREFLIGHT_GATE"
ELEMENT_4_OUTPUT_SINK         = "ELEMENT_4_OUTPUT_SINK"
ELEMENT_5_RUN_RECORD          = "ELEMENT_5_RUN_RECORD"
ELEMENT_6_NOTIFICATION_SEAM   = "ELEMENT_6_NOTIFICATION_SEAM"
ELEMENT_7_LIVENESS_SIGNAL     = "ELEMENT_7_LIVENESS_SIGNAL"
CLAUSE_8_BROKER_CO_PLACEMENT  = "CLAUSE_8_BROKER_CO_PLACEMENT"

# Element 4: valid output sink values
VALID_OUTPUT_SINKS = {"git_push", "notification", "approval_queue"}

# Element 2: connector-credential env-var patterns. Any declared agent env var
# whose name matches one of these patterns (case-insensitive) is a violation
# unless it appears in NON_CONNECTOR_EXCEPTIONS.
CONNECTOR_CRED_PATTERNS = (
    "_API_KEY",
    "_SECRET_KEY",
    "_ACCESS_TOKEN",
    "_PRIVATE_KEY",
    "_CLIENT_SECRET",
    "_ACCOUNT_KEY",
)
# Non-connector exceptions: model inference token and run-record write creds
# are legitimate agent-env secrets under the broker model.
NON_CONNECTOR_EXCEPTIONS: frozenset[str] = frozenset({
    "SA_MODEL_TOKEN",
    "SA_RUN_RECORD_WRITE_CREDS",
})

# Fields required in every run record (element 5).
REQUIRED_RUN_RECORD_FIELDS = frozenset({
    "status", "job", "logical_date", "run_id", "arm",
    "started_at", "ended_at", "summary",
    "artifact_refs", "policy_version", "action_dispositions",
})

VALID_RUN_STATUSES = frozenset({"ran", "nothing-to-do", "failed"})


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str    # violation name / check id (always one of the constants above)
    passed: bool
    reason: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_manifest(agent_dir: Path) -> tuple[Optional[dict], Optional[str]]:
    """Return (manifest_dict, error_string). error_string is None on success."""
    mf = agent_dir / "manifest.yaml"
    if not mf.exists():
        return None, f"manifest.yaml not found in {agent_dir}"
    try:
        with mf.open() as f:
            return yaml.safe_load(f), None
    except yaml.YAMLError as exc:
        return None, f"manifest.yaml parse error: {exc}"


def _sanitised_env(extra: dict[str, str], *, unset_aws: bool = True) -> dict[str, str]:
    """
    Build an environment dict for subprocess invocations.
    Strips AWS_* variables when unset_aws=True so that element-5 tests run
    cleanly with the local-file fallback even when credentials are present
    in the parent process environment.
    """
    env = os.environ.copy()
    if unset_aws:
        for key in list(env):
            if key.startswith("AWS_"):
                del env[key]
    env.update(extra)
    return env


def _run_script(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess:
    """subprocess.run that converts crashes into failed results.

    A missing/non-executable script or a hung script is a CONTRACT FAILURE, not
    an infrastructure crash (sa#130): both are returned as a synthetic non-zero
    CompletedProcess so every caller's existing returncode handling reports a
    failed check instead of the whole harness dying mid-pipeline.
    """
    try:
        return subprocess.run(
            argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=argv, returncode=127, stdout="",
            stderr=f"{argv[0]} not runnable: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=argv, returncode=124, stdout="",
            stderr=f"{argv[0]} timed out after {timeout}s: {exc}",
        )


def _run_sh(
    agent_dir: Path,
    extra_env: dict[str, str],
    *,
    unset_aws: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Invoke run.sh inside agent_dir with a sanitised environment."""
    return _run_script(
        [str(agent_dir / "run.sh")],
        cwd=str(agent_dir),
        env=_sanitised_env(extra_env, unset_aws=unset_aws),
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# The eight checks
# ---------------------------------------------------------------------------

def check_element_1(agent_dir: Path) -> CheckResult:
    """
    Element 1 — One headless entrypoint with correct exit-code contract.
    Checks: run.sh exists, is executable, and exits 0 on a normal run.
    """
    run_sh = agent_dir / "run.sh"
    if not run_sh.exists():
        return CheckResult(ELEMENT_1_HEADLESS_ENTRYPOINT, False, "run.sh does not exist")
    if not os.access(run_sh, os.X_OK):
        return CheckResult(ELEMENT_1_HEADLESS_ENTRYPOINT, False, "run.sh is not executable")

    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_sh(agent_dir, {"SA_RUN_RECORD_DIR": tmpdir, "SA_ARM": "local"})

    if result.returncode != 0:
        return CheckResult(
            ELEMENT_1_HEADLESS_ENTRYPOINT, False,
            f"run.sh exited {result.returncode}; stderr: {result.stderr[:300]}",
        )
    return CheckResult(
        ELEMENT_1_HEADLESS_ENTRYPOINT, True,
        "run.sh exists, is executable, exits 0",
    )


def check_element_2(agent_dir: Path) -> CheckResult:
    """
    Element 2 — Secrets via environment, not files; no connector creds in the
    agent env.
    Checks:
      - manifest.yaml carries env.connector_creds_in_agent: false (the explicit
        machine-checkable assertion that the developer is responsible for).
      - No declared env var matches a connector-credential naming pattern
        (unless it appears in NON_CONNECTOR_EXCEPTIONS).
    """
    manifest, err = _load_manifest(agent_dir)
    if manifest is None:
        return CheckResult(ELEMENT_2_SECRETS_FROM_ENV, False, err)

    env_section = manifest.get("env") or {}
    if env_section.get("connector_creds_in_agent") is not False:
        return CheckResult(
            ELEMENT_2_SECRETS_FROM_ENV, False,
            "manifest.yaml missing env.connector_creds_in_agent: false — "
            "the developer must explicitly assert that no connector creds are in the agent env",
        )

    all_declared: list[str] = (
        list(env_section.get("required") or [])
        + list(env_section.get("optional") or [])
    )
    offenders = [
        v for v in all_declared
        if any(pat in v.upper() for pat in CONNECTOR_CRED_PATTERNS)
        and v not in NON_CONNECTOR_EXCEPTIONS
    ]
    if offenders:
        return CheckResult(
            ELEMENT_2_SECRETS_FROM_ENV, False,
            f"connector-credential-pattern env vars found in declared agent env: {offenders}; "
            "these must live in the broker, not the agent",
        )

    return CheckResult(
        ELEMENT_2_SECRETS_FROM_ENV, True,
        "connector_creds_in_agent: false asserted; no connector-pattern env vars declared",
    )


def check_element_3(agent_dir: Path) -> CheckResult:
    """
    Element 3 — Cheap pre-flight gate.
    Checks: running run.sh with SA_PREFLIGHT_ONLY=1 exits 0 and produces a
    run record with status=nothing-to-do.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_sh(
            agent_dir,
            {"SA_RUN_RECORD_DIR": tmpdir, "SA_ARM": "local", "SA_PREFLIGHT_ONLY": "1"},
        )
        if result.returncode != 0:
            return CheckResult(
                ELEMENT_3_PREFLIGHT_GATE, False,
                f"pre-flight run exited {result.returncode}; stderr: {result.stderr[:300]}",
            )

        record_file = Path(tmpdir) / "run_record.json"
        if not record_file.exists():
            return CheckResult(
                ELEMENT_3_PREFLIGHT_GATE, False,
                "pre-flight run produced no run_record.json",
            )
        with record_file.open() as f:
            record = json.load(f)
        if record.get("status") != "nothing-to-do":
            return CheckResult(
                ELEMENT_3_PREFLIGHT_GATE, False,
                f"pre-flight run record status={record.get('status')!r}, expected 'nothing-to-do'",
            )

    return CheckResult(
        ELEMENT_3_PREFLIGHT_GATE, True,
        "pre-flight exits 0 and produces a nothing-to-do run record",
    )


def check_element_4(agent_dir: Path) -> CheckResult:
    """
    Element 4 — Self-owned, declared output persistence.
    Checks: manifest.yaml.output_sink is one of git_push / notification / approval_queue.
    """
    manifest, err = _load_manifest(agent_dir)
    if manifest is None:
        return CheckResult(ELEMENT_4_OUTPUT_SINK, False, err)

    sink = manifest.get("output_sink")
    if not sink:
        return CheckResult(
            ELEMENT_4_OUTPUT_SINK, False,
            "manifest.yaml missing output_sink declaration",
        )
    if sink not in VALID_OUTPUT_SINKS:
        return CheckResult(
            ELEMENT_4_OUTPUT_SINK, False,
            f"manifest.yaml output_sink={sink!r} not one of {sorted(VALID_OUTPUT_SINKS)}",
        )
    return CheckResult(ELEMENT_4_OUTPUT_SINK, True, f"output_sink declared as {sink!r}")


def check_element_5(agent_dir: Path) -> CheckResult:
    """
    Element 5 — Machine-readable run record; DynamoDB or local-file fallback.
    Checks (with NO AWS credentials): run.sh produces a valid structured run
    record at SA_RUN_RECORD_DIR/run_record.json. The job must never fail
    because the run-record store is unreachable.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run_sh(
            agent_dir,
            {"SA_RUN_RECORD_DIR": tmpdir, "SA_ARM": "local"},
            unset_aws=True,  # simulate CI — no AWS credentials
        )
        if result.returncode != 0:
            return CheckResult(
                ELEMENT_5_RUN_RECORD, False,
                f"run.sh failed (exit {result.returncode}) with no AWS creds — "
                "the job must not fail because DynamoDB is unreachable",
            )

        record_file = Path(tmpdir) / "run_record.json"
        if not record_file.exists():
            return CheckResult(
                ELEMENT_5_RUN_RECORD, False,
                "no run_record.json produced with no AWS creds (local-file fallback absent)",
            )
        try:
            with record_file.open() as f:
                record = json.load(f)
        except json.JSONDecodeError as exc:
            return CheckResult(
                ELEMENT_5_RUN_RECORD, False,
                f"run_record.json is not valid JSON: {exc}",
            )

        missing = REQUIRED_RUN_RECORD_FIELDS - set(record.keys())
        if missing:
            return CheckResult(
                ELEMENT_5_RUN_RECORD, False,
                f"run record missing required fields: {sorted(missing)}",
            )
        if record["status"] not in VALID_RUN_STATUSES:
            return CheckResult(
                ELEMENT_5_RUN_RECORD, False,
                f"run record status={record['status']!r} not in {sorted(VALID_RUN_STATUSES)}",
            )

    return CheckResult(
        ELEMENT_5_RUN_RECORD, True,
        "local-file run record produced with all required fields (no AWS creds needed)",
    )


def check_element_6(agent_dir: Path) -> CheckResult:
    """
    Element 6 — Notification seam.
    Checks: notify.sh exists, is executable, and calling it without a channel
    configured exits 0 (no-op).
    """
    notify_sh = agent_dir / "notify.sh"
    if not notify_sh.exists():
        return CheckResult(ELEMENT_6_NOTIFICATION_SEAM, False, "notify.sh does not exist")
    if not os.access(notify_sh, os.X_OK):
        return CheckResult(ELEMENT_6_NOTIFICATION_SEAM, False, "notify.sh is not executable")

    env = _sanitised_env({})
    env.pop("SA_NOTIFY_CHANNEL", None)  # no channel → must be a no-op
    result = _run_script(
        [str(notify_sh), "test notification"],
        cwd=str(agent_dir),
        env=env,
        timeout=10,
    )
    if result.returncode != 0:
        return CheckResult(
            ELEMENT_6_NOTIFICATION_SEAM, False,
            f"notify.sh exited {result.returncode} with no channel set; "
            f"stderr: {result.stderr[:300]}",
        )
    return CheckResult(
        ELEMENT_6_NOTIFICATION_SEAM, True,
        "notify.sh exists, executable, exits 0 with no channel (no-op)",
    )


def check_element_7(agent_dir: Path) -> CheckResult:
    """
    Element 7 — Liveness signal.
    Checks:
      - manifest.yaml declares liveness.push_ping_env_var.
      - Running run.sh with that env var absent exits 0 (no-op, not a failure).
    """
    manifest, err = _load_manifest(agent_dir)
    if manifest is None:
        return CheckResult(ELEMENT_7_LIVENESS_SIGNAL, False, err)

    liveness = manifest.get("liveness") or {}
    if not liveness:
        return CheckResult(
            ELEMENT_7_LIVENESS_SIGNAL, False,
            "manifest.yaml missing liveness declaration",
        )
    ping_var = liveness.get("push_ping_env_var")
    if not ping_var:
        return CheckResult(
            ELEMENT_7_LIVENESS_SIGNAL, False,
            "manifest.yaml liveness.push_ping_env_var not declared",
        )

    # Run without the liveness URL set — must succeed (no-op, not a crash).
    with tempfile.TemporaryDirectory() as tmpdir:
        extra = {"SA_RUN_RECORD_DIR": tmpdir, "SA_ARM": "local"}
        env = _sanitised_env(extra)
        env.pop(ping_var, None)  # explicitly absent
        result = _run_script(
            [str(agent_dir / "run.sh")],
            cwd=str(agent_dir),
            env=env,
            timeout=30,
        )

    if result.returncode != 0:
        return CheckResult(
            ELEMENT_7_LIVENESS_SIGNAL, False,
            f"run.sh failed (exit {result.returncode}) when {ping_var} is unset — "
            "liveness must be a no-op when unconfigured",
        )
    return CheckResult(
        ELEMENT_7_LIVENESS_SIGNAL, True,
        f"liveness declared (push_ping_env_var={ping_var!r}); "
        "run succeeds with ping URL absent (no-op)",
    )


def check_clause_8(agent_dir: Path) -> CheckResult:
    """
    Clause 8 — Broker co-placement invariant.
    Any arm adapter or manifest that skips the broker sidecar FAILS with the
    named violation CLAUSE_8_BROKER_CO_PLACEMENT.
    Checks:
      - manifest.yaml.broker.sidecar is true
      - manifest.yaml.broker.egress_confined is true
    """
    manifest, err = _load_manifest(agent_dir)
    if manifest is None:
        return CheckResult(CLAUSE_8_BROKER_CO_PLACEMENT, False, err)

    broker = manifest.get("broker") or {}
    if not broker:
        return CheckResult(
            CLAUSE_8_BROKER_CO_PLACEMENT, False,
            "manifest.yaml missing broker declaration — "
            "arm adapter that skips broker sidecar FAILS this check",
        )
    if not broker.get("sidecar"):
        return CheckResult(
            CLAUSE_8_BROKER_CO_PLACEMENT, False,
            f"manifest.yaml broker.sidecar={broker.get('sidecar')!r} — "
            "must be true; broker must be co-placed for every arm",
        )
    if not broker.get("egress_confined"):
        return CheckResult(
            CLAUSE_8_BROKER_CO_PLACEMENT, False,
            "manifest.yaml broker.egress_confined must be true — "
            "agent egress must be confined to the broker at the network layer",
        )
    return CheckResult(
        CLAUSE_8_BROKER_CO_PLACEMENT, True,
        "broker declared: sidecar=true, egress_confined=true",
    )


# ---------------------------------------------------------------------------
# Harness runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_element_1,
    check_element_2,
    check_element_3,
    check_element_4,
    check_element_5,
    check_element_6,
    check_element_7,
    check_clause_8,
]


def run_harness(agent_dir: Path) -> list[CheckResult]:
    """Run all 8 checks against agent_dir. Returns results in order."""
    return [check(agent_dir) for check in ALL_CHECKS]


def print_results(results: list[CheckResult]) -> None:
    """Print a results table to stdout."""
    print()
    print("Runner-contract conformance results")
    print("=" * 60)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.name}")
        if not r.passed:
            print(f"         reason: {r.reason}")
    print("=" * 60)
    failures = [r for r in results if not r.passed]
    if failures:
        print(f"FAILED — {len(failures)} violation(s):")
        for f in failures:
            print(f"  VIOLATION: {f.name}")
            print(f"    {f.reason}")
    else:
        print("All 8 checks passed.")
    print()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Runner-contract conformance harness. "
            "Tests a candidate agent directory against core/RUNNER-CONTRACT.md."
        )
    )
    parser.add_argument("agent_dir", help="Path to the agent directory to check")
    args = parser.parse_args()

    agent_dir = Path(args.agent_dir).resolve()
    if not agent_dir.is_dir():
        print(f"ERROR: {agent_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    results = run_harness(agent_dir)
    print_results(results)
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
