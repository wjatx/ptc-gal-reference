"""test_sqlite_broker_boot.py — the sqlite arm boots the broker (product-wrapper Phase 1).

Before the grants-sqlite slice, ``BROKER_STORE=sqlite`` served the ceremony
CLI's MCP stores only and ``build_runtime`` refused it outright: falling
through to the memory branch would have booted dev-fallback grant/intent
stores under an operator who NAMED a durable arm (the #197/#199 shape). Now
the arm constructs real sqlite counters/intents/grants (and the store-mode
envelope) on one named ``broker.db``, so the refusal is gone and these tests pin
what replaced it:

  - a fully-named sqlite boot succeeds and reports the sqlite store label;
  - every F1–F3 durable-arm refusal still fires here (the arm is durable, so
    a defaulted manifest / dev HMAC key / memory audit sink / fake secrets are
    all refused exactly as on dynamo — covered in test_config_refusals.py);
  - F5: ``BROKER_GRANT_LOAD=seed`` refuses BEFORE the database file is even
    created (fail toward touching nothing);
  - grants written by a ceremony-shaped writer survive a process restart and
    are served read-only — the durability property the whole arm exists for;
  - the boot sweep deletes expired intents (bounded-lag privacy, sa#213) and
    a sweep failure never blocks the boot.

AWS-free by construction: no boto3 call, no credentials, one tmp_path db.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import (
    BrokerConfigError,
    build_runtime,
)
from safe_agents.broker.schemas import AgentManifest

_ENV_VARS = (
    "BROKER_STORE",
    "BROKER_SQLITE_PATH",
    "BROKER_MANIFEST",
    "BROKER_HMAC_KEY",
    "BROKER_GRANT_CLASSES",
    "BROKER_GRANT_LOAD",
    "BROKER_SKIP_GRANT_LOAD",
    "BROKER_ENVELOPE_LOAD",
    "BROKER_AUDIT_BUCKET",
    "BROKER_AUDIT_PATH",
    "BROKER_SECRETS",
    "BROKER_SECRETS_FILE",
)

HMAC_KEY = b"named-sqlite-test-key"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    if "_MANIFEST" in vars(broker_server):
        monkeypatch.delattr(broker_server, "_MANIFEST")
    yield


def _manifest() -> AgentManifest:
    return AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain", "caps": {"actions_per_utc_day": 7}},
            "principal": {
                "agentId": "sqlite-boot-agent",
                "skill": "t",
                "user": "u",
                "tier": "B",
            },
            "grant_classes": ["search.query", "notify.send"],
            "connectors": ["github", "search"],
            "tool_ops": [
                {"tool": "search", "op": "query", "effect": "read", "external": True},
                {
                    "tool": "notify",
                    "op": "send",
                    "effect": "write",
                    "external": True,
                    "reversible": True,
                },
            ],
        }
    )


def _name_sqlite_arm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, db_name: str = "broker.db"
) -> Path:
    """Name every value a durable arm requires (F1–F3) plus the db path."""
    secrets = tmp_path / "secrets.json"
    secrets.write_text(json.dumps({"github": "cred-github", "search": "cred-search"}), encoding="utf-8")
    db_path = tmp_path / db_name
    monkeypatch.setenv("BROKER_STORE", "sqlite")
    monkeypatch.setenv("BROKER_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("BROKER_HMAC_KEY", HMAC_KEY.decode())
    monkeypatch.setenv("BROKER_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BROKER_SECRETS_FILE", str(secrets))
    return db_path


class TestSqliteArmBoots:
    def test_named_sqlite_arm_builds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
    ) -> None:
        db_path = _name_sqlite_arm(monkeypatch, tmp_path)
        monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")
        runtime, sink = build_runtime(_manifest())
        assert runtime is not None and sink is not None
        assert runtime.served_registry() == []  # skip mode serves nothing
        assert f"sqlite ({db_path})" in capsys.readouterr().out

    def test_seed_mode_refuses_before_creating_the_database(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # F5 fires ahead of store construction, so the named db file must not
        # exist afterwards — fail toward touching nothing.
        db_path = _name_sqlite_arm(monkeypatch, tmp_path)
        monkeypatch.setenv("BROKER_GRANT_LOAD", "seed")
        with pytest.raises(BrokerConfigError, match="BROKER_GRANT_LOAD=seed"):
            build_runtime(_manifest())
        assert not db_path.exists()

    def test_read_mode_serves_ceremony_written_grants_across_a_restart(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The durability property the arm exists for: grants written by a
        separate (ceremony-shaped) process are served by a later boot, with no
        seeding anywhere in the boot path."""
        from safe_agents.broker.grants.sqlite_store import SqliteGrantStore

        db_path = _name_sqlite_arm(monkeypatch, tmp_path)
        manifest = _manifest()
        principal = manifest.principal
        envelope_hash = broker_server.compute_envelope_hash(manifest.envelope)

        # A distinct store instance (its own connection) stands in for the
        # out-of-band ceremony writer.
        writer = SqliteGrantStore(HMAC_KEY, db_path)
        for action_class in ("search.query", "notify.send"):
            writer.put_grant(
                broker_server._make_grant(action_class, principal, envelope_hash), None
            )
        writer.close()

        monkeypatch.setenv("BROKER_GRANT_LOAD", "read")
        runtime, _ = build_runtime(manifest)
        # served_registry() returns the capability-scoped ToolOps the loaded
        # grants unlock (pep.py:311) — an op present here means its grant was
        # read back from the file intact.
        served = {f"{op.tool}.{op.op}" for op in runtime.served_registry()}
        assert served == {"search.query", "notify.send"}

    def test_read_mode_omits_a_grant_written_under_a_different_hmac_key(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Fail-closed: a quarantined grant (wrong key ⇒ hash mismatch) is
        omitted from the served registry, never served as authoritative."""
        from safe_agents.broker.grants.sqlite_store import SqliteGrantStore

        db_path = _name_sqlite_arm(monkeypatch, tmp_path)
        manifest = _manifest()
        envelope_hash = broker_server.compute_envelope_hash(manifest.envelope)

        wrong_key_writer = SqliteGrantStore(b"a-different-key", db_path)
        wrong_key_writer.put_grant(
            broker_server._make_grant("search.query", manifest.principal, envelope_hash),
            None,
        )
        wrong_key_writer.close()

        monkeypatch.setenv("BROKER_GRANT_LOAD", "read")
        runtime, _ = build_runtime(manifest)
        assert runtime.served_registry() == []


class TestBootSweep:
    def test_boot_sweeps_expired_intents_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from safe_agents.broker.approval.sqlite_store import SqliteIntentStore
        from safe_agents.broker.schemas import Intent
        from safe_agents.broker.tests.test_core_store_differential import make_call

        db_path = _name_sqlite_arm(monkeypatch, tmp_path)
        now = datetime.datetime.now(datetime.UTC)

        def _intent(intent_id: str, expiry: datetime.datetime) -> Intent:
            return Intent(
                id=intent_id,
                materializedRequest=make_call(),
                renderedForHuman="transfer 100 to acct-xyz",
                status="pending",
                expiry=expiry.isoformat(),
                ts=now.isoformat(),
            )

        writer = SqliteIntentStore(db_path, hmac_key=HMAC_KEY)
        writer.put_intent(_intent("stale", now - datetime.timedelta(hours=1)))
        writer.put_intent(_intent("fresh", now + datetime.timedelta(hours=1)))
        writer.close()

        monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")
        build_runtime(_manifest())

        reader = SqliteIntentStore(db_path, hmac_key=HMAC_KEY)
        assert reader.get_intent("stale") is None
        assert reader.get_intent("fresh") is not None
        reader.close()

    def test_sweep_failure_does_not_block_the_boot(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Hygiene never gates authority: expiry is a predicate at use, so an
        unswept row cannot widen it — a broken sweep must warn, not refuse."""
        from safe_agents.broker.approval import sqlite_store as approval_sqlite

        _name_sqlite_arm(monkeypatch, tmp_path)
        monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")

        def _boom(self, now=None):
            raise RuntimeError("sweep exploded")

        monkeypatch.setattr(approval_sqlite.SqliteIntentStore, "sweep_expired", _boom)
        runtime, _ = build_runtime(_manifest())
        assert runtime is not None
