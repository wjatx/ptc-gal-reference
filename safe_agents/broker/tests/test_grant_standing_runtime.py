"""Issuer standing as build_runtime wires it (GAL-41, #179).

  * the source, its authority keys and its maximum age come from the deploy
    environment; a per-agent age may only shorten the deploy-bound one, and a
    longer one refuses at load;
  * the document's age lowers the level and never refuses a decision; its
    as-of and the horizon ride on the decision's audit record (#176);
  * with no source configured the broker is unchanged.
"""

from __future__ import annotations

import datetime
import json
import logging

import pytest

from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants import key_standing as ks
from safe_agents.broker.grants.grant_standing import FALL_NOT_ESTABLISHED, RECORD_SIGNING_EPOCH_ENV
from safe_agents.broker.grants.record_signing import ISSUER_ROLE
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime.input_age import INPUT_PAST_MAX_AGE_REASON
from safe_agents.broker.tests.test_input_age import T0, _call, _Clock, _manifest
from safe_agents.broker.tests.test_key_standing import keypair

SEC = datetime.timedelta(seconds=1)
DEPLOY_AGE = 3600


@pytest.fixture(autouse=True)
def _memory_arm_and_clean_signing_env(monkeypatch):
    for var in ("BROKER_STORE", "BROKER_AUDIT_BUCKET", "BROKER_AUDIT_PATH", "BROKER_SECRETS",
                "BROKER_GRANT_LOAD", "BROKER_ENVELOPE_LOAD", RECORD_SIGNING_EPOCH_ENV):
        monkeypatch.delenv(var, raising=False)
    for role_env in issuer_keys.ALL_ROLE_ENVS:
        for name in issuer_keys.role_env_names(role_env):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def deployed(tmp_path, monkeypatch):
    """An issuer document issued at T0 and the authority's key, bound by env."""
    authority, authority_pem = keypair("authority-1")
    _, issuer_pem = keypair("issuer-a")
    document = ks.next_document(
        None, role=ISSUER_ROLE, keys=ks.add_key({}, "issuer-a", issuer_pem),
        issued_at=T0, signer=authority,
    )
    doc_file = tmp_path / "issuer-standing.json"
    doc_file.write_text(ks.sign_standing_document(document, authority), encoding="utf-8")
    authority_file = tmp_path / "authority.json"
    authority_file.write_text(json.dumps({"authority-1": authority_pem}), encoding="utf-8")
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_FILE_ENV, str(doc_file))
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV, str(DEPLOY_AGE))
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV, str(authority_file))
    return doc_file


def test_a_longer_per_agent_age_is_refused_at_load(deployed):
    manifest = _manifest(input_max_age_seconds={"issuer_standing": DEPLOY_AGE + 1})
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="may only shorten"):
        build_runtime(manifest, clock=_Clock())


def test_a_per_agent_age_with_no_source_is_refused_at_load():
    manifest = _manifest(input_max_age_seconds={"issuer_standing": 60})
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="no ISSUER_STANDING"):
        build_runtime(manifest, clock=_Clock())


def test_the_age_lowers_rides_on_the_record_and_never_refuses(deployed, monkeypatch, caplog):
    # The memory arm keeps no ledger, so with an epoch before the seeded grants'
    # ts no record licenses them and their standing is not established: the
    # decision depends on the document, and its as-of rides on the record.
    monkeypatch.setenv(RECORD_SIGNING_EPOCH_ENV, "2026-01-01T00:00:00+00:00")
    clock = _Clock(T0 + 30 * SEC)
    manifest = _manifest(input_max_age_seconds={"issuer_standing": 60})
    runtime, sink = build_runtime(manifest, clock=clock)
    clock.now = T0 + 600 * SEC  # past the shortened 60s age, far inside the deploy age
    with caplog.at_level(logging.WARNING):
        response = _call(runtime)
    assert not (response.reason or "").startswith(INPUT_PAST_MAX_AGE_REASON)
    record = sink.records()[-1]
    assert record.inputsAsOf["issuer_standing"] == T0.isoformat()
    assert record.horizon == (T0 + 60 * SEC).isoformat(), "the per-agent age shortened it"
    lowered = [r for r in caplog.records if "lowered by issuer standing" in r.getMessage()]
    assert len(lowered) == 1, "the fall is surfaced once per request"
    assert FALL_NOT_ESTABLISHED in lowered[0].getMessage()


def test_with_no_source_the_broker_is_unchanged(monkeypatch):
    monkeypatch.setenv(RECORD_SIGNING_EPOCH_ENV, "2026-01-01T00:00:00+00:00")
    runtime, sink = build_runtime(_manifest(), clock=_Clock())
    _call(runtime)
    assert "issuer_standing" not in (sink.records()[-1].inputsAsOf or {})
