"""
Tests for manifest extended validation (sa#41).

Covers:
  1. Valid manifest (with polarity, broker_connector_keys) passes
  2. Missing polarity fails with "envelope.polarity" in error
  3. Invalid polarity fails with the value named
  4. tools non-empty + missing broker_connector_keys fails
  5. tools empty + no broker_connector_keys passes
  6. Valid policy file (no IPs) passes
  7. Policy file with connector IP in agent_egress fails
  8. Missing policy file fails
  9. validate_phase(): valid manifest → phase passes
 10. validate_phase(): missing polarity → phase fails with named field
 11. run_pipeline() pre-flight: valid manifest aborts at provision (fargate), not preflight
 12. run_pipeline() pre-flight: missing polarity manifest aborts at preflight
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import yaml

import pytest

from safe_agents.pipeline import FakeAWS, ManifestError, load_manifest
from safe_agents.pipeline.manifest import Schedule
from safe_agents.pipeline.validate import validate_manifest_extended
from safe_agents.pipeline.phases import validate_phase
from safe_agents.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"
TEST_STUB_MANIFEST = AGENTS_DIR / "test-stub.yaml"


def _write_manifest(tmp_path: Path, content: dict, name: str = "agent.yaml") -> Path:
    """Write a manifest dict as YAML and return the path."""
    p = tmp_path / name
    p.write_text(yaml.dump(content), encoding="utf-8")
    return p


def _base_manifest() -> dict:
    """Return a minimal valid manifest dict with polarity set."""
    return {
        "name": "test-agent",
        "repo": "git@github.com:Third-Ralph/test-agent.git",
        "deploy_key_secret": "test-agent/deploy-key",
        "arm": "ec2",
        "policy": "policies/test-agent.yaml",
        "secrets": {
            "runner_keys": "test-agent/runner-keys",
            "broker_connector_keys": "test-agent/broker-keys",
        },
        "smoke": {
            "read_only": True,
            "prompt": "What does this agent do?",
            "expect_substring": "agent",
        },
        "envelope": {
            "polarity": "abstain",
        },
    }


# ---------------------------------------------------------------------------
# 1. Valid manifest passes
# ---------------------------------------------------------------------------

def test_valid_manifest_passes(tmp_path: Path) -> None:
    """A manifest with polarity and broker_connector_keys produces no errors."""
    data = _base_manifest()
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors == [], f"Expected no errors; got: {errors}"


# ---------------------------------------------------------------------------
# 2. Missing polarity fails
# ---------------------------------------------------------------------------

def test_missing_polarity_fails(tmp_path: Path) -> None:
    """Manifest with no envelope.polarity must fail with a named error."""
    data = _base_manifest()
    del data["envelope"]
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors, "Expected at least one error"
    combined = " ".join(errors)
    assert "envelope.polarity" in combined, (
        f"Error must name 'envelope.polarity'; got: {combined}"
    )


def test_missing_polarity_from_empty_envelope(tmp_path: Path) -> None:
    """Envelope present but polarity key missing."""
    data = _base_manifest()
    data["envelope"] = {}
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors
    assert "envelope.polarity" in " ".join(errors)


# ---------------------------------------------------------------------------
# 3. Invalid polarity fails with value named
# ---------------------------------------------------------------------------

def test_invalid_polarity_fails(tmp_path: Path) -> None:
    """Unknown polarity value must be named in the error message."""
    data = _base_manifest()
    data["envelope"]["polarity"] = "trust_me"
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors, "Expected an error for invalid polarity"
    combined = " ".join(errors)
    assert "trust_me" in combined, (
        f"Error must name the invalid polarity value; got: {combined}"
    )


def test_valid_polarity_act(tmp_path: Path) -> None:
    """polarity: act is also valid."""
    data = _base_manifest()
    data["envelope"]["polarity"] = "act"
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors == []


# ---------------------------------------------------------------------------
# 4. tools non-empty + missing broker_connector_keys fails
# ---------------------------------------------------------------------------

def test_tools_nonempty_missing_broker_keys_fails(tmp_path: Path) -> None:
    """Non-empty allowlists.tools requires secrets.broker_connector_keys."""
    data = _base_manifest()
    del data["secrets"]["broker_connector_keys"]
    data["envelope"]["allowlists"] = {"tools": ["some_tool"]}
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    assert errors, "Expected an error when tools non-empty and broker_connector_keys missing"
    combined = " ".join(errors)
    assert "broker_connector_keys" in combined


# ---------------------------------------------------------------------------
# 5. tools empty + no broker_connector_keys passes
# ---------------------------------------------------------------------------

def test_tools_empty_no_broker_keys_passes(tmp_path: Path) -> None:
    """Empty tools allowlist does not require broker_connector_keys."""
    data = _base_manifest()
    del data["secrets"]["broker_connector_keys"]
    data["envelope"]["allowlists"] = {"tools": []}
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest)
    # Polarity is set, tools empty — no connector needed
    assert errors == [], f"Expected no errors; got: {errors}"


# ---------------------------------------------------------------------------
# 6. Valid policy file (no IPs) passes
# ---------------------------------------------------------------------------

def test_valid_policy_file_passes(tmp_path: Path) -> None:
    """A policy file with agent_egress and no raw IPs produces no errors."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy_path = policy_dir / "test-agent.yaml"
    policy_path.write_text(textwrap.dedent("""\
        agent_egress:
          allow_hosts:
            - api.anthropic.com
          deny_by_default: true
    """), encoding="utf-8")

    data = _base_manifest()
    data["policy"] = "policies/test-agent.yaml"
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest, repo_root=tmp_path)
    assert errors == [], f"Expected no errors for clean policy; got: {errors}"


# ---------------------------------------------------------------------------
# 7. Policy file with connector IP in agent_egress fails
# ---------------------------------------------------------------------------

def test_policy_with_connector_ip_fails(tmp_path: Path) -> None:
    """An IP address in agent_egress must be flagged."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy_path = policy_dir / "test-agent.yaml"
    policy_path.write_text(textwrap.dedent("""\
        agent_egress:
          allow_hosts:
            - api.anthropic.com
            - 10.0.1.42          # connector IP — must NOT appear here
          deny_by_default: true
    """), encoding="utf-8")

    data = _base_manifest()
    data["policy"] = "policies/test-agent.yaml"
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest, repo_root=tmp_path)
    assert errors, "Expected an error for raw IP in agent_egress"
    combined = " ".join(errors)
    assert "10.0.1.42" in combined, (
        f"Error must name the offending IP; got: {combined}"
    )


# ---------------------------------------------------------------------------
# 8. Missing policy file fails
# ---------------------------------------------------------------------------

def test_missing_policy_file_fails(tmp_path: Path) -> None:
    """If the declared policy file does not exist, report an error."""
    data = _base_manifest()
    data["policy"] = "policies/does-not-exist.yaml"
    manifest = load_manifest(_write_manifest(tmp_path, data))
    errors = validate_manifest_extended(manifest, repo_root=tmp_path)
    assert errors, "Expected an error for missing policy file"
    combined = " ".join(errors)
    assert "does-not-exist.yaml" in combined or "not found" in combined


# ---------------------------------------------------------------------------
# 9. validate_phase(): valid manifest → phase passes
# ---------------------------------------------------------------------------

def test_validate_phase_valid_manifest(tmp_path: Path) -> None:
    """validate_phase returns a passing PhaseResult for a valid manifest."""
    manifest = load_manifest(_write_manifest(tmp_path, _base_manifest()))
    result = validate_phase(manifest)
    assert result.success, f"Expected success; error: {result.error}"
    assert result.phase == "preflight"


# ---------------------------------------------------------------------------
# 10. validate_phase(): missing polarity → phase fails with named field
# ---------------------------------------------------------------------------

def test_validate_phase_missing_polarity(tmp_path: Path) -> None:
    """validate_phase surfaces the missing polarity as a preflight failure."""
    data = _base_manifest()
    del data["envelope"]
    manifest = load_manifest(_write_manifest(tmp_path, data))
    result = validate_phase(manifest)
    assert not result.success
    assert result.phase == "preflight"
    assert result.error is not None
    assert "envelope.polarity" in result.error, (
        f"Error must name the missing field; got: {result.error}"
    )


# ---------------------------------------------------------------------------
# 11. run_pipeline() pre-flight: valid manifest with fargate arm aborts at provision
# ---------------------------------------------------------------------------

def test_run_pipeline_preflight_passes_aborts_at_provision(tmp_path: Path) -> None:
    """
    A valid manifest (polarity set) with arm=fargate should pass pre-flight and
    then abort at 'provision' (fargate unimplemented), not at 'preflight'.
    """
    data = _base_manifest()
    data["arm"] = "fargate"
    manifest_path = _write_manifest(tmp_path, data)
    fake_aws = FakeAWS()

    result = run_pipeline(
        manifest_path,
        dry_run=False,
        aws=fake_aws,
    )
    assert not result.success
    assert result.aborted_at == "provision", (
        f"Expected abort at 'provision'; got aborted_at={result.aborted_at!r}"
    )


# ---------------------------------------------------------------------------
# 12. run_pipeline() pre-flight: missing polarity aborts at preflight
# ---------------------------------------------------------------------------

def test_run_pipeline_missing_polarity_aborts_at_preflight(tmp_path: Path) -> None:
    """A manifest with no envelope.polarity aborts the pipeline at 'preflight'."""
    data = _base_manifest()
    del data["envelope"]
    manifest_path = _write_manifest(tmp_path, data)
    fake_aws = FakeAWS()

    result = run_pipeline(
        manifest_path,
        dry_run=False,
        aws=fake_aws,
    )
    assert not result.success
    assert result.aborted_at == "preflight", (
        f"Expected abort at 'preflight'; got aborted_at={result.aborted_at!r}"
    )
    # The preflight result should be in phase_results
    assert len(result.phase_results) == 1
    assert result.phase_results[0].phase == "preflight"


# ---------------------------------------------------------------------------
# 13. schedule block (sa#115)
# ---------------------------------------------------------------------------

def test_no_schedule_key_loads_fine_with_schedule_none(tmp_path: Path) -> None:
    """A manifest with no 'schedule:' key loads fine; manifest.schedule is None
    (backward compat — every pre-sa#115 manifest)."""
    data = _base_manifest()
    manifest = load_manifest(_write_manifest(tmp_path, data))
    assert manifest.schedule is None


def test_full_schedule_block_loads_into_schedule(tmp_path: Path) -> None:
    """A full schedule: block loads into a Schedule with those exact values."""
    data = _base_manifest()
    data["schedule"] = {
        "expression": "cron(15 15 * * ? *)",
        "timezone": "America/Chicago",
        "state": "ENABLED",
    }
    manifest = load_manifest(_write_manifest(tmp_path, data))
    assert manifest.schedule == Schedule(
        expression="cron(15 15 * * ? *)",
        timezone="America/Chicago",
        state="ENABLED",
    )


def test_schedule_invalid_state_raises_manifest_error(tmp_path: Path) -> None:
    """schedule.state must be one of ENABLED/DISABLED; an invalid value raises."""
    data = _base_manifest()
    data["schedule"] = {"state": "banana"}
    manifest_path = _write_manifest(tmp_path, data)
    with pytest.raises(ManifestError, match="banana"):
        load_manifest(manifest_path)


def test_schedule_block_omitting_state_defaults_disabled(tmp_path: Path) -> None:
    """A schedule: block that omits state defaults to Schedule.state == 'DISABLED'."""
    data = _base_manifest()
    data["schedule"] = {
        "expression": "cron(15 15 * * ? *)",
        "timezone": "America/Chicago",
    }
    manifest = load_manifest(_write_manifest(tmp_path, data))
    assert manifest.schedule.state == "DISABLED"
