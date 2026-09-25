"""
Pytest conformance tests for the runner-contract harness.

Acceptance criteria (sa#31):
  1. The reference test-stub (agents/test-stub/) passes all 8 checks.
  2. A deliberately broken stub triggers a named violation and the harness
     exits non-zero — demonstrated for multiple elements.
  3. Runs with NO AWS credentials (element 5 uses the local-file fallback).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from safe_agents.contract.harness import (
    CLAUSE_8_BROKER_CO_PLACEMENT,
    ELEMENT_1_HEADLESS_ENTRYPOINT,
    ELEMENT_2_SECRETS_FROM_ENV,
    ELEMENT_3_PREFLIGHT_GATE,
    ELEMENT_4_OUTPUT_SINK,
    ELEMENT_5_RUN_RECORD,
    ELEMENT_6_NOTIFICATION_SEAM,
    ELEMENT_7_LIVENESS_SIGNAL,
    CheckResult,
    check_clause_8,
    check_element_1,
    check_element_2,
    check_element_3,
    check_element_4,
    check_element_5,
    check_element_6,
    check_element_7,
    run_harness,
)

# The harness executes the agent's run.sh and notify.sh directly, as a Linux
# container runtime would. On Windows every executing check would fail for want of
# a POSIX exec, and the broken-stub tests would then pass for the wrong reason.
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="runner-contract harness execs POSIX shell scripts (run.sh, notify.sh); "
    "Windows cannot",
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent
TEST_STUB = REPO_ROOT / "agents" / "test-stub"
CONTRACT_DIR = Path(__file__).parent

# Ordered pairs of (check_fn, violation_name) — the canonical ordering from
# RUNNER-CONTRACT.md.
CHECKS = [
    (check_element_1, ELEMENT_1_HEADLESS_ENTRYPOINT),
    (check_element_2, ELEMENT_2_SECRETS_FROM_ENV),
    (check_element_3, ELEMENT_3_PREFLIGHT_GATE),
    (check_element_4, ELEMENT_4_OUTPUT_SINK),
    (check_element_5, ELEMENT_5_RUN_RECORD),
    (check_element_6, ELEMENT_6_NOTIFICATION_SEAM),
    (check_element_7, ELEMENT_7_LIVENESS_SIGNAL),
    (check_clause_8, CLAUSE_8_BROKER_CO_PLACEMENT),
]


# ---------------------------------------------------------------------------
# Acceptance criterion 1 + 3: reference stub passes all 8 checks, no AWS creds
# ---------------------------------------------------------------------------

class TestReferenceStubPasses:
    """The test-stub must pass every individual check (criterion 1 + 3)."""

    @pytest.mark.parametrize(
        "check_fn,check_name",
        CHECKS,
        ids=[name for _, name in CHECKS],
    )
    def test_individual_check_passes(self, check_fn, check_name):
        result: CheckResult = check_fn(TEST_STUB)
        assert result.passed, f"CHECK {result.name} FAILED: {result.reason}"

    def test_full_harness_passes_all_eight(self):
        """
        Run the entire harness in one shot. AWS_* vars are stripped inside
        _run_sh (unset_aws=True), satisfying criterion 3.
        """
        results = run_harness(TEST_STUB)
        failures = [r for r in results if not r.passed]
        assert not failures, (
            "Some checks failed:\n"
            + "\n".join(f"  {r.name}: {r.reason}" for r in failures)
        )

    def test_harness_cli_exits_zero(self):
        """Full end-to-end: harness.py exits 0 for the test-stub."""
        proc = subprocess.run(
            [sys.executable, str(CONTRACT_DIR / "harness.py"), str(TEST_STUB)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"harness.py exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
        assert "All 8 checks passed" in proc.stdout


# ---------------------------------------------------------------------------
# Acceptance criterion 2: named failures for broken stubs
# ---------------------------------------------------------------------------

class TestNamedFailures:
    """
    Simulate violations and verify the harness names the failed element.
    Each test breaks exactly one check in an isolated copy of the test-stub.
    """

    @staticmethod
    def _copy_stub(tmp_path: Path) -> Path:
        dest = tmp_path / "broken-stub"
        shutil.copytree(TEST_STUB, dest)
        return dest

    @staticmethod
    def _patch_manifest(stub: Path, **removals) -> None:
        """Remove named top-level keys from manifest.yaml."""
        mf = stub / "manifest.yaml"
        with mf.open(encoding="utf-8") as f:
            manifest = yaml.safe_load(f)
        for key in removals:
            manifest.pop(key, None)
        with mf.open("w", encoding="utf-8") as f:
            yaml.dump(manifest, f)

    # --- Clause 8 -----------------------------------------------------------

    def test_missing_broker_declaration(self, tmp_path):
        """
        Removing the broker section must produce CLAUSE_8_BROKER_CO_PLACEMENT
        and the CLI harness must exit non-zero.
        """
        stub = self._copy_stub(tmp_path)
        self._patch_manifest(stub, broker=None)

        result = check_clause_8(stub)
        assert not result.passed, "Expected failure for missing broker"
        assert result.name == CLAUSE_8_BROKER_CO_PLACEMENT

        # CLI harness must exit non-zero and name the violation
        proc = subprocess.run(
            [sys.executable, str(CONTRACT_DIR / "harness.py"), str(stub)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0, "Harness must exit non-zero for broken stub"
        assert CLAUSE_8_BROKER_CO_PLACEMENT in proc.stdout, (
            f"Expected {CLAUSE_8_BROKER_CO_PLACEMENT!r} in output:\n{proc.stdout}"
        )

    def test_broker_sidecar_false(self, tmp_path):
        """broker.sidecar=false must trigger CLAUSE_8_BROKER_CO_PLACEMENT."""
        stub = self._copy_stub(tmp_path)
        mf = stub / "manifest.yaml"
        with mf.open(encoding="utf-8") as f:
            manifest = yaml.safe_load(f)
        manifest["broker"]["sidecar"] = False
        with mf.open("w", encoding="utf-8") as f:
            yaml.dump(manifest, f)

        result = check_clause_8(stub)
        assert not result.passed
        assert result.name == CLAUSE_8_BROKER_CO_PLACEMENT

    # --- Element 1 ----------------------------------------------------------

    def test_missing_run_sh(self, tmp_path):
        """Removing run.sh must produce ELEMENT_1_HEADLESS_ENTRYPOINT."""
        stub = self._copy_stub(tmp_path)
        (stub / "run.sh").unlink()

        result = check_element_1(stub)
        assert not result.passed
        assert result.name == ELEMENT_1_HEADLESS_ENTRYPOINT

    # --- Element 3 ----------------------------------------------------------

    def test_missing_run_sh_fails_element_3_without_crashing(self, tmp_path):
        """sa#130: element 3 EXECUTES run.sh — a missing script must produce a
        failed ELEMENT_3_PREFLIGHT_GATE check, not an unhandled FileNotFoundError
        that kills the whole harness (and the pipeline smoke phase with it)."""
        stub = self._copy_stub(tmp_path)
        (stub / "run.sh").unlink()

        result = check_element_3(stub)
        assert not result.passed
        assert result.name == ELEMENT_3_PREFLIGHT_GATE
        assert "run.sh not runnable" in result.reason

        # The full harness must also survive and report, not raise.
        results = run_harness(stub)
        assert any(not r.passed for r in results)

    # --- Element 2 ----------------------------------------------------------

    def test_missing_connector_creds_assertion(self, tmp_path):
        """Omitting connector_creds_in_agent must produce ELEMENT_2_SECRETS_FROM_ENV."""
        stub = self._copy_stub(tmp_path)
        mf = stub / "manifest.yaml"
        with mf.open(encoding="utf-8") as f:
            manifest = yaml.safe_load(f)
        # Remove the explicit assertion
        manifest.get("env", {}).pop("connector_creds_in_agent", None)
        with mf.open("w", encoding="utf-8") as f:
            yaml.dump(manifest, f)

        result = check_element_2(stub)
        assert not result.passed
        assert result.name == ELEMENT_2_SECRETS_FROM_ENV

    # --- Element 4 ----------------------------------------------------------

    def test_missing_output_sink(self, tmp_path):
        """Removing output_sink must produce ELEMENT_4_OUTPUT_SINK."""
        stub = self._copy_stub(tmp_path)
        self._patch_manifest(stub, output_sink=None)

        result = check_element_4(stub)
        assert not result.passed
        assert result.name == ELEMENT_4_OUTPUT_SINK

    # --- Element 6 ----------------------------------------------------------

    def test_missing_notify_sh(self, tmp_path):
        """Removing notify.sh must produce ELEMENT_6_NOTIFICATION_SEAM."""
        stub = self._copy_stub(tmp_path)
        (stub / "notify.sh").unlink()

        result = check_element_6(stub)
        assert not result.passed
        assert result.name == ELEMENT_6_NOTIFICATION_SEAM

    # --- Element 7 ----------------------------------------------------------

    def test_missing_liveness_declaration(self, tmp_path):
        """Removing liveness from manifest must produce ELEMENT_7_LIVENESS_SIGNAL."""
        stub = self._copy_stub(tmp_path)
        self._patch_manifest(stub, liveness=None)

        result = check_element_7(stub)
        assert not result.passed
        assert result.name == ELEMENT_7_LIVENESS_SIGNAL
