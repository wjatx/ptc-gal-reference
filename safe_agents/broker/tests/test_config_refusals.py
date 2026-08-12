"""test_config_refusals.py — #205: named-config-or-refuse at the broker boot seam.

Doctrine (docs/config-provenance.md; the #197/#199 lesson): authority-shaping
config must be operator-NAMED; the machine refuses instead of defaulting or
warn-and-continuing, and every refusal fails toward running nothing / less
authority. Four seams, each pinned by a refusing-defaulted case and a passing
named-config case:

  F1  BROKER_MANIFEST unset  → example-manifest fallback honored ONLY on the
      local/memory arm; BROKER_STORE=dynamo refuses at boot (and the grants
      ceremony's manifest-mode ``_MANIFEST`` access refuses too).
  F2  BROKER_HMAC_KEY unset  → dev key honored only on the memory arm; dynamo
      refuses (read/write symmetry with the ceremony's write-side refusal).
  F3  BROKER_STORE=dynamo + memory audit / fake secrets → was warn-and-continue;
      now refuses at boot.
  F4  granted write-effect classes with no envelope caps.actions_per_utc_day →
      was a silent 100/day default; now refuses at build_runtime.
  F5  BROKER_GRANT_LOAD=seed on the sqlite arm → refuses (seed-at-boot into a
      durable local trust store is an unceremonied authority mint; dynamo+seed
      stays legal because the real floor's IAM confines it to DynamoDB Local).

F1–F3 key on the DURABLE-arm predicate (dynamo or sqlite alike) since the
grants-sqlite slice; each sqlite case below pins that the refusal fires there
too and that the memory-arm fallback survives untouched.

All tests are AWS-free: every dynamo-arm case refuses BEFORE any store call, and
the one dynamo-arm passing build uses BROKER_GRANT_LOAD=skip + lazy stores.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import (
    BrokerConfigError,
    _get_manifest,
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


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate from ambient BROKER_* env AND from a module-level ``_MANIFEST``
    another test may have left behind (monkeypatch.setattr materializes it)."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    if "_MANIFEST" in vars(broker_server):
        monkeypatch.delattr(broker_server, "_MANIFEST")
    yield


def _manifest(**overrides) -> AgentManifest:
    base: dict = {
        "envelope": {"polarity": "abstain", "caps": {"actions_per_utc_day": 7}},
        "principal": {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"},
        "grant_classes": ["search.query", "notify.send"],
        "connectors": ["github", "search"],
        "tool_ops": [
            {"tool": "search", "op": "query", "effect": "read", "external": True},
            {"tool": "notify", "op": "send", "effect": "write", "external": True,
             "reversible": True},
        ],
    }
    base.update(overrides)
    return AgentManifest.model_validate(base)


def _name_real_backends(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Name a durable audit sink + real-shaped secrets file so a dynamo-arm build
    clears the F3 gate without AWS."""
    secrets = tmp_path / "secrets.json"
    secrets.write_text(json.dumps({"github": "cred-github"}))
    monkeypatch.setenv("BROKER_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BROKER_SECRETS_FILE", str(secrets))


# ---------------------------------------------------------------------------
# F1 — manifest fallback
# ---------------------------------------------------------------------------

class TestManifestFallback:
    def test_memory_arm_unset_manifest_falls_back_to_example(self) -> None:
        # Byte-for-byte the old local behavior: the checked-in example loads.
        manifest = _get_manifest()
        assert manifest.principal is not None
        assert manifest.principal.agentId == "example-advisor"

    def test_dynamo_arm_unset_manifest_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        with pytest.raises(BrokerConfigError, match="BROKER_MANIFEST is unset"):
            _get_manifest()

    def test_dynamo_arm_named_manifest_loads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        monkeypatch.setenv(
            "BROKER_MANIFEST", str(broker_server._DEFAULT_MANIFEST_PATH)
        )
        manifest = _get_manifest()
        assert manifest.principal is not None
        assert manifest.principal.agentId == "example-advisor"

    def test_dynamo_arm_server_boot_refuses_defaulted_manifest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        monkeypatch.setattr(broker_server, "_RUNTIME", None)
        monkeypatch.setattr(broker_server, "_SINK", None)
        with pytest.raises(BrokerConfigError, match="BROKER_MANIFEST is unset"):
            broker_server._server_runtime()

    def test_ceremony_manifest_resolution_refuses_when_defaulted_on_dynamo(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The grants-ceremony shape: manifest-mode ceremonies call
        ``resolve_manifest()`` explicitly (store mode never resolves it), and on
        the dynamo arm a defaulted manifest refuses with a clean error —
        surfaced by commands.main as exit 2, never a traceback."""
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        with pytest.raises(BrokerConfigError, match="BROKER_MANIFEST is unset"):
            broker_server.resolve_manifest()
        # The module attribute is the same seam — access refuses too, and the
        # refusal caches NOTHING (a later fixed env resolves fresh).
        with pytest.raises(BrokerConfigError, match="BROKER_MANIFEST is unset"):
            _ = broker_server._MANIFEST
        assert "_MANIFEST" not in vars(broker_server)

    def test_memory_arm_manifest_attribute_is_real_and_load_once(self) -> None:
        manifest = broker_server._MANIFEST
        assert manifest.principal.agentId == "example-advisor"
        # Load-once: the first successful resolution materializes ONE object that
        # every later import/access (and monkeypatch.setattr) sees.
        assert vars(broker_server)["_MANIFEST"] is manifest
        assert broker_server.resolve_manifest() is manifest


# ---------------------------------------------------------------------------
# F2 — dev HMAC key
# ---------------------------------------------------------------------------

class TestHmacKeyRefusal:
    def test_memory_arm_unset_hmac_uses_dev_key(self) -> None:
        # The memory arm keeps the dev-key fallback: the build succeeds.
        runtime, _ = build_runtime(_manifest())
        assert runtime is not None

    def test_dynamo_arm_unset_hmac_refuses(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        _name_real_backends(monkeypatch, tmp_path)
        with pytest.raises(BrokerConfigError, match="BROKER_HMAC_KEY is unset"):
            build_runtime(_manifest())

    def test_dynamo_arm_named_hmac_builds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Named key + named audit/secrets + skip grant load = a full dynamo-arm
        # build with no AWS call (stores are lazy). Doubles as F3's passing case.
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        monkeypatch.setenv("BROKER_HMAC_KEY", "named-test-key")
        monkeypatch.setenv("BROKER_GRANT_LOAD", "skip")
        _name_real_backends(monkeypatch, tmp_path)
        runtime, _ = build_runtime(_manifest())
        assert runtime.served_registry() == []


# ---------------------------------------------------------------------------
# F3 — dynamo store with memory audit / fake secrets
# ---------------------------------------------------------------------------

class TestUnsafeBackendComboRefusal:
    def test_dynamo_with_memory_audit_and_fake_secrets_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        monkeypatch.setenv("BROKER_HMAC_KEY", "named-test-key")
        with pytest.raises(
            BrokerConfigError, match="audit=memory, secrets=fake"
        ):
            build_runtime(_manifest())

    def test_dynamo_with_durable_audit_but_fake_secrets_refuses(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        monkeypatch.setenv("BROKER_HMAC_KEY", "named-test-key")
        monkeypatch.setenv("BROKER_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        with pytest.raises(BrokerConfigError, match="secrets=fake"):
            build_runtime(_manifest())

    def test_memory_arm_keeps_memory_audit_and_fake_secrets(self) -> None:
        # The AWS-free smoke combination stays legal on the memory arm.
        runtime, sink = build_runtime(_manifest())
        assert runtime is not None and sink is not None


# ---------------------------------------------------------------------------
# F4 — silent default counter cap for granted writes
# ---------------------------------------------------------------------------

class TestWriteCapRefusal:
    def test_granted_write_without_cap_refuses(self) -> None:
        with pytest.raises(
            BrokerConfigError,
            match=r"write-effect.*\['notify\.send'\].*actions_per_utc_day",
        ):
            build_runtime(_manifest(envelope={"polarity": "abstain"}))

    def test_granted_write_with_empty_caps_block_refuses(self) -> None:
        with pytest.raises(BrokerConfigError, match="actions_per_utc_day"):
            build_runtime(_manifest(envelope={"polarity": "abstain", "caps": {}}))

    def test_granted_write_with_named_cap_builds(self) -> None:
        runtime, _ = build_runtime(
            _manifest(
                envelope={"polarity": "abstain", "caps": {"actions_per_utc_day": 100}}
            )
        )
        assert runtime._counter_cap == 100.0

    def test_read_only_grants_keep_platform_default(self) -> None:
        runtime, _ = build_runtime(
            _manifest(envelope={"polarity": "abstain"}, grant_classes=["search.query"])
        )
        assert runtime._counter_cap == broker_server._DEFAULT_COUNTER_CAP

    def test_unclassified_grant_is_inert_not_refused(self) -> None:
        # A granted class with no tool_ops entry is PEP-denied anyway; it must not
        # trip the write-cap refusal (it has no known effect).
        runtime, _ = build_runtime(
            _manifest(
                envelope={"polarity": "abstain"},
                grant_classes=["mystery.op"],
                tool_ops=[],
                connectors=["github"],
            )
        )
        assert runtime._counter_cap == broker_server._DEFAULT_COUNTER_CAP

    def test_store_loaded_envelope_without_cap_refuses_with_reseed_remedy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R3 — a STORE-loaded envelope seeded without the cap must refuse with a
        remedy that fits store mode: re-seed via seed_envelope, NOT 'set it in
        the manifest' (the broker isn't reading the envelope from the manifest)."""
        from safe_agents.broker.schemas import Envelope

        class _FakeEnvelopeStore:
            def get_envelope(self, principal):
                return Envelope.model_validate({"polarity": "abstain"})

        monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
        with pytest.raises(BrokerConfigError) as exc_info:
            build_runtime(_manifest(), envelope_store=_FakeEnvelopeStore())
        message = str(exc_info.value)
        assert "seed_envelope" in message
        assert "BROKER_ENVELOPE_LOAD=store" in message
        assert "in the manifest" not in message

    def test_manifest_envelope_without_cap_refusal_names_the_manifest_remedy(
        self,
    ) -> None:
        with pytest.raises(BrokerConfigError) as exc_info:
            build_runtime(_manifest(envelope={"polarity": "abstain"}))
        message = str(exc_info.value)
        assert "in the manifest" in message
        assert "seed_envelope" not in message


# ---------------------------------------------------------------------------
# R2 — BROKER_STORE is a CLOSED set: a typo must refuse, not boot the dev arm
# ---------------------------------------------------------------------------

class TestStoreArmClosedSet:
    @pytest.mark.parametrize("value", ["dynamodb", "Dynamo", "prod", " memory"])
    def test_unknown_store_value_refuses_at_boot(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", value)
        with pytest.raises(BrokerConfigError, match="not a recognized store arm"):
            build_runtime(_manifest())

    def test_unknown_store_value_refuses_manifest_resolution_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "dynamodb")
        with pytest.raises(BrokerConfigError, match="Valid values"):
            broker_server.resolve_manifest()

    @pytest.mark.parametrize("value", [None, "memory"])
    def test_valid_memory_values_boot(
        self, monkeypatch: pytest.MonkeyPatch, value: str | None
    ) -> None:
        if value is not None:
            monkeypatch.setenv("BROKER_STORE", value)
        runtime, _ = build_runtime(_manifest())
        assert runtime is not None


# ---------------------------------------------------------------------------
# The sqlite arm (product-wrapper Phase 1): a recognized member of the closed set that
# serves the MCP ceremony stores only — the broker service refuses to boot on
# it (falling through to memory dev fallbacks would be the #197/#199 shape),
# and its db path is NAMED, resolved in boot_config and only there.
# ---------------------------------------------------------------------------

class TestSqliteArm:
    def test_sqlite_is_a_recognized_arm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from safe_agents.broker.prototype.boot_config import resolve_store_arm

        monkeypatch.setenv("BROKER_STORE", "sqlite")
        assert resolve_store_arm() == "sqlite"

    def test_sqlite_arm_bare_build_refuses_before_any_store_write(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A bare sqlite build refuses at the FIRST unnamed durable-arm value
        # (the HMAC key) — the arm never reaches store construction with dev
        # fallbacks in force.
        monkeypatch.setenv("BROKER_STORE", "sqlite")
        with pytest.raises(BrokerConfigError, match="BROKER_HMAC_KEY is unset"):
            build_runtime(_manifest())

    def test_resolve_sqlite_db_path_refuses_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from safe_agents.broker.prototype.boot_config import resolve_sqlite_db_path

        with pytest.raises(BrokerConfigError, match="BROKER_SQLITE_PATH"):
            resolve_sqlite_db_path()

    def test_resolve_sqlite_db_path_returns_named_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from safe_agents.broker.prototype.boot_config import resolve_sqlite_db_path

        monkeypatch.setenv("BROKER_SQLITE_PATH", str(tmp_path / "broker.db"))
        assert resolve_sqlite_db_path() == tmp_path / "broker.db"


# ---------------------------------------------------------------------------
# The durable-arm predicate (grants-sqlite slice): F1–F3 fire on sqlite exactly
# as on dynamo — a durable local store under dev fallbacks is the same
# unnamed-authority shape whatever the backend — and F5 refuses seed-at-boot
# grant minting on sqlite specifically.
# ---------------------------------------------------------------------------

class TestDurableArmPredicate:
    def test_is_durable_arm_classification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from safe_agents.broker.prototype.boot_config import (
            is_durable_arm,
            is_dynamo_arm,
        )

        assert is_durable_arm() is False  # memory default
        monkeypatch.setenv("BROKER_STORE", "sqlite")
        assert is_durable_arm() is True
        assert is_dynamo_arm() is False  # sqlite is durable but NOT dynamo
        monkeypatch.setenv("BROKER_STORE", "dynamo")
        assert is_durable_arm() is True
        assert is_dynamo_arm() is True

    def test_sqlite_arm_unset_manifest_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_STORE", "sqlite")
        with pytest.raises(BrokerConfigError, match="BROKER_MANIFEST is unset"):
            _get_manifest()

    def test_sqlite_arm_unset_hmac_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from safe_agents.broker.prototype.boot_config import resolve_hmac_key

        monkeypatch.setenv("BROKER_STORE", "sqlite")
        with pytest.raises(BrokerConfigError, match="BROKER_HMAC_KEY is unset"):
            resolve_hmac_key()

    def test_sqlite_arm_memory_audit_or_fake_secrets_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from safe_agents.broker.prototype.boot_config import (
            require_named_real_backends,
        )

        monkeypatch.setenv("BROKER_STORE", "sqlite")
        with pytest.raises(BrokerConfigError, match="audit=memory"):
            require_named_real_backends("memory", "fake")
        with pytest.raises(BrokerConfigError, match="secrets=fake"):
            require_named_real_backends("file (/tmp/audit.jsonl)", "fake")
        # Named durable audit + real-shaped secrets clear the gate.
        require_named_real_backends("file (/tmp/audit.jsonl)", "file (/tmp/s.json)")


class TestGrantSeedRefusalOnSqlite:
    def test_seed_on_sqlite_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from safe_agents.broker.prototype.boot_config import (
            require_sanctioned_grant_load,
        )

        monkeypatch.setenv("BROKER_STORE", "sqlite")
        with pytest.raises(BrokerConfigError, match="BROKER_GRANT_LOAD=seed"):
            require_sanctioned_grant_load("seed")

    @pytest.mark.parametrize("mode", ["read", "skip"])
    def test_read_and_skip_stay_legal_on_sqlite(
        self, monkeypatch: pytest.MonkeyPatch, mode: str
    ) -> None:
        from safe_agents.broker.prototype.boot_config import (
            require_sanctioned_grant_load,
        )

        monkeypatch.setenv("BROKER_STORE", "sqlite")
        require_sanctioned_grant_load(mode)

    @pytest.mark.parametrize("arm", [None, "memory", "dynamo"])
    def test_seed_stays_legal_on_every_other_arm(
        self, monkeypatch: pytest.MonkeyPatch, arm: str | None
    ) -> None:
        from safe_agents.broker.prototype.boot_config import (
            require_sanctioned_grant_load,
        )

        if arm is not None:
            monkeypatch.setenv("BROKER_STORE", arm)
        require_sanctioned_grant_load("seed")
