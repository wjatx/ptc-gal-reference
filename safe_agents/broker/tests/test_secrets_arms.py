"""test_secrets_arms.py — #248: the BROKER_SECRETS closed catalog + the `dir` arm.

Two things land together here, and the second is why the first was a prerequisite:

  * **The catalog.** Before #248 there was no validation at all — two independent
    sites tested ``BROKER_SECRETS == "secretsmanager"`` and fell through to
    BROKER_SECRETS_FILE and then to FAKE CREDENTIALS. One typo booted green on
    fakes while the operator believed Secrets Manager was in force, which is the
    silent-downgrade shape ``resolve_store_arm`` already refuses for BROKER_STORE.
    Adding an arm to a bare equality check multiplies that surface, so the catalog
    comes first.
  * **The `dir` arm.** One file per secret leaf — the shape a Kubernetes/OpenShift
    mounted Secret, a CSI Secrets Store volume, Podman's /run/secrets and systemd
    credentials all project. The prerequisite for the openshift epic's Phase 1
    container floor (#249).

Every test is AWS-free: the secretsmanager arm is only ever *selected* here, never
fetched from (LazyBotoSecretsProvider does not import boto3 until first fetch).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from safe_agents.broker.mcp.commands import _resolve_secrets_provider
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.boot_config import (
    BrokerConfigError,
    resolve_secrets_arm,
    resolve_secrets_dir,
    resolve_secrets_file,
)
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime.secrets import (
    DirSecretsProvider,
    FakeSecretsProvider,
    LazyBotoSecretsProvider,
    LocalFileSecretsProvider,
)
from safe_agents.broker.schemas import AgentManifest

_ENV_VARS = (
    "BROKER_STORE",
    "BROKER_SQLITE_PATH",
    "BROKER_MANIFEST",
    "BROKER_HMAC_KEY",
    "BROKER_GRANT_CLASSES",
    "BROKER_GRANT_LOAD",
    "BROKER_ENVELOPE_LOAD",
    "BROKER_AUDIT_BUCKET",
    "BROKER_AUDIT_PATH",
    "BROKER_SECRETS",
    "BROKER_SECRETS_FILE",
    "BROKER_SECRETS_DIR",
    "BROKER_SECRET_PREFIX",
)


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
                "agentId": "secrets-arm-agent",
                "skill": "t",
                "user": "u",
                "tier": "B",
            },
            "grant_classes": ["search.query"],
            "connectors": ["github", "search"],
            "tool_ops": [
                {"tool": "search", "op": "query", "effect": "read", "external": True},
            ],
        }
    )


def _secrets_dir(tmp_path: Path, **leaves: str) -> Path:
    """A mount-shaped directory: one file per secret leaf, no trailing newline —
    exactly what a projected Kubernetes Secret volume looks like."""
    root = tmp_path / "secrets"
    root.mkdir(exist_ok=True)
    for leaf, value in leaves.items():
        (root / leaf).write_text(value, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# DirSecretsProvider — the arm itself
# ---------------------------------------------------------------------------

class TestDirSecretsProvider:
    def test_reads_one_file_per_leaf(self, tmp_path: Path) -> None:
        root = _secrets_dir(tmp_path, github="cred-github", search="cred-search")
        provider = DirSecretsProvider(str(root))
        assert provider.fetch_secret("github") == "cred-github"
        assert provider.fetch_secret("search") == "cred-search"

    def test_missing_leaf_raises_filenotfound_like_the_file_provider(
        self, tmp_path: Path
    ) -> None:
        # FileNotFoundError (not a bespoke error) is load-bearing: `_is_missing_secret`
        # already treats it as "no such secret", so the overlay fallback and every
        # existing miss path apply to this arm unchanged.
        provider = DirSecretsProvider(str(_secrets_dir(tmp_path)))
        with pytest.raises(FileNotFoundError):
            provider.fetch_secret("absent")

    @pytest.mark.parametrize(
        ("written", "expected"),
        [
            ("cred", "cred"),                    # projected Secret: no newline
            ("cred\n", "cred"),                  # `echo cred > file`
            ("cred\r\n", "cred"),                # a CRLF-writing editor
            ("cred\n\n", "cred\n"),              # only ONE newline is stripped
            ("cred\r\n\r\n", "cred\r\n"),        # ...and only one CRLF
            ("cred\r", "cred\r"),                # a lone CR is not a line ending here
            ("cred ", "cred "),                  # other whitespace is the credential
            (" cred", " cred"),
            ("head\nbody", "head\nbody"),        # internal newlines survive (PEM, JSON)
            ("head\r\nbody", "head\r\nbody"),    # ...byte for byte, CRLF included
            ("a\rb", "a\rb"),                    # an interior CR is credential material
            ('{"k": "v"}\n', '{"k": "v"}'),      # a JSON-shaped credential
            ("", ""),                            # an empty file is an empty credential
        ],
    )
    def test_strips_exactly_one_trailing_newline(
        self, tmp_path: Path, written: str, expected: str
    ) -> None:
        # write_bytes, never write_text: text mode on Windows turns every "\n" into
        # "\r\n", so the file would not hold the bytes this case names.
        root = _secrets_dir(tmp_path)
        (root / "leaf").write_bytes(written.encode("utf-8"))
        assert DirSecretsProvider(str(root)).fetch_secret("leaf") == expected

    @pytest.mark.parametrize("value", ["head\nbody", "head\r\nbody", "a\rb", "cred"])
    def test_store_then_fetch_round_trips_verbatim(
        self, tmp_path: Path, value: str
    ) -> None:
        # A rotated credential is written by store_secret and read back by
        # fetch_secret; neither side may translate line endings on any platform.
        provider = DirSecretsProvider(str(_secrets_dir(tmp_path)))
        provider.store_secret("leaf", value)
        assert (_secrets_dir(tmp_path) / "leaf").read_bytes() == value.encode("utf-8")
        assert provider.fetch_secret("leaf") == value

    @pytest.mark.parametrize(
        "raw",
        [
            "﻿cred".encode("utf-16-le"),   # Windows PowerShell 5.1 `echo cred > f`
            "﻿cred".encode("utf-16-be"),
            b"\xef\xbb\xbfcred",                # UTF-8 with a byte-order mark
        ],
    )
    def test_byte_order_mark_refuses_loudly(self, tmp_path: Path, raw: bytes) -> None:
        # A BOM is never part of a credential, and silently keeping it would surface
        # as an opaque 401 from the remote API. ValueError, deliberately NOT a
        # "missing secret" error, so no dev-stub fallback can absorb it.
        root = _secrets_dir(tmp_path)
        (root / "leaf").write_bytes(raw)
        with pytest.raises(ValueError, match="byte-order mark"):
            DirSecretsProvider(str(root)).fetch_secret("leaf")

    @pytest.mark.parametrize(
        "name", ["../outside", "a/b", "..", ".", "", "a\\b", "/etc/passwd"]
    )
    def test_non_leaf_names_refuse_rather_than_resolve(
        self, tmp_path: Path, name: str
    ) -> None:
        # ValueError, deliberately NOT KeyError/FileNotFoundError: those two mean
        # "no such secret" to `_is_missing_secret`, so raising one of them would
        # turn a traversal attempt into a silent dev-stub credential.
        provider = DirSecretsProvider(str(_secrets_dir(tmp_path)))
        with pytest.raises(ValueError, match="is not a leaf"):
            provider.fetch_secret(name)

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="drive-qualified names are ordinary leaves on POSIX; the escape is Windows-only",
    )
    @pytest.mark.parametrize("name", ["Q:outside", "a:b"])
    def test_drive_qualified_names_refuse_on_windows(
        self, tmp_path: Path, name: str
    ) -> None:
        # No separator, so the leaf checks pass, yet on Windows joining "Q:x" to the
        # root yields "Q:x" and discards the root. The parent check is what holds.
        # (A name on the root's own drive resolves inside it, so these use drives a
        # temp directory will not be on.)
        provider = DirSecretsProvider(str(_secrets_dir(tmp_path)))
        with pytest.raises(ValueError, match="directly under the secrets directory"):
            provider.fetch_secret(name)

    def test_traversal_refusal_is_not_a_missing_secret(self, tmp_path: Path) -> None:
        from safe_agents.broker.prototype.broker_server import _is_missing_secret

        try:
            DirSecretsProvider(str(_secrets_dir(tmp_path))).fetch_secret("../x")
        except ValueError as exc:
            assert not _is_missing_secret(exc)
        else:  # pragma: no cover - the call above must raise
            pytest.fail("expected a refusal")

    def test_is_read_through_so_a_rotated_projection_is_seen(
        self, tmp_path: Path
    ) -> None:
        """The load-bearing difference from LocalFileSecretsProvider.

        The kubelet refreshes a projected Secret volume IN PLACE, so a provider
        that caches for its own lifetime serves a rotated-away credential for as
        long as the process lives — tolerable for a ceremony CLI, wrong for the
        long-lived gateway this arm exists for."""
        root = _secrets_dir(tmp_path, github="old-cred")
        provider = DirSecretsProvider(str(root))
        assert provider.fetch_secret("github") == "old-cred"
        (root / "github").write_text("rotated-cred", encoding="utf-8")
        assert provider.fetch_secret("github") == "rotated-cred"

    def test_file_provider_caches_by_contrast(self, tmp_path: Path) -> None:
        """Pins the behaviour the dir arm deliberately does NOT share, so a future
        change to either one cannot silently converge them."""
        path = tmp_path / "secrets.json"
        path.write_text(json.dumps({"github": "old-cred"}), encoding="utf-8")
        provider = LocalFileSecretsProvider(str(path))
        assert provider.fetch_secret("github") == "old-cred"
        path.write_text(json.dumps({"github": "rotated-cred"}), encoding="utf-8")
        assert provider.fetch_secret("github") == "old-cred"  # cached for its lifetime


# ---------------------------------------------------------------------------
# resolve_secrets_arm — the closed catalog
# ---------------------------------------------------------------------------

class TestSecretsArmCatalog:
    @pytest.mark.parametrize("arm", ["file", "dir", "secretsmanager", "fake"])
    def test_every_catalog_value_resolves_to_itself(
        self, monkeypatch: pytest.MonkeyPatch, arm: str
    ) -> None:
        monkeypatch.setenv("BROKER_SECRETS", arm)
        assert resolve_secrets_arm() == arm

    @pytest.mark.parametrize(
        "typo", ["secretmanager", "secrets-manager", "SecretsManager", "dirs", "keychain"]
    )
    def test_unrecognized_value_refuses(
        self, monkeypatch: pytest.MonkeyPatch, typo: str
    ) -> None:
        # The regression this catalog exists for: pre-#248 each of these fell
        # through to the file provider or, with no file named, to FAKE credentials.
        monkeypatch.setenv("BROKER_SECRETS", typo)
        with pytest.raises(BrokerConfigError, match="not a recognized secrets arm"):
            resolve_secrets_arm()

    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            ({}, "fake"),
            ({"BROKER_SECRETS_FILE": "/tmp/s.json"}, "file"),
            ({"BROKER_SECRETS_DIR": "/run/secrets"}, "dir"),
            # Both named: the dir arm wins. Documented rather than incidental —
            # a container mount is the more specific declaration of intent.
            (
                {"BROKER_SECRETS_FILE": "/tmp/s.json", "BROKER_SECRETS_DIR": "/run/secrets"},
                "dir",
            ),
        ],
    )
    def test_unset_keeps_the_pre_248_implicit_resolution(
        self, monkeypatch: pytest.MonkeyPatch, env: dict, expected: str
    ) -> None:
        """Back-compat: the path variable selects the arm, so run-local.sh, both
        CDK stacks and the Fargate BROKER_ENV contract are all unchanged."""
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        assert resolve_secrets_arm() == expected

    def test_named_dir_arm_without_a_root_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_SECRETS", "dir")
        with pytest.raises(BrokerConfigError, match="BROKER_SECRETS_DIR is unset"):
            resolve_secrets_dir()

    def test_named_file_arm_without_a_path_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_SECRETS", "file")
        with pytest.raises(BrokerConfigError, match="BROKER_SECRETS_FILE is unset"):
            resolve_secrets_file()


# ---------------------------------------------------------------------------
# Both resolution sites switch on the ONE catalog
# ---------------------------------------------------------------------------

class TestBrokerBootSelectsTheArm:
    def test_dir_arm_is_selected_and_labelled(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
    ) -> None:
        root = _secrets_dir(tmp_path, github="cred-github", search="cred-search")
        monkeypatch.setenv("BROKER_SECRETS", "dir")
        monkeypatch.setenv("BROKER_SECRETS_DIR", str(root))
        runtime, _ = build_runtime(_manifest())
        assert runtime is not None
        assert f"secrets: dir ({root})" in capsys.readouterr().out

    def test_typo_refuses_at_boot_instead_of_booting_on_fakes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BROKER_SECRETS", "secretmanager")
        with pytest.raises(BrokerConfigError, match="not a recognized secrets arm"):
            build_runtime(_manifest())

    def test_memory_arm_default_is_unchanged(
        self, capsys, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The friendly dev default survives #248 byte-for-byte."""
        runtime, _ = build_runtime(_manifest())
        assert runtime is not None
        assert "secrets: fake" in capsys.readouterr().out


class TestMcpCommandsSelectTheSameArm:
    """The second resolution site. Pre-#248 it re-derived the arm with its own
    `== "secretsmanager"` test; the two sites disagreeing about which backend is
    in force is exactly what the catalog prevents."""

    def test_dir_arm_resolves_a_real_credential(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = _secrets_dir(tmp_path, alpaca="cred-alpaca")
        monkeypatch.setenv("BROKER_SECRETS", "dir")
        monkeypatch.setenv("BROKER_SECRETS_DIR", str(root))
        provider = _resolve_secrets_provider()
        assert isinstance(provider, DirSecretsProvider)
        assert provider.fetch_secret("alpaca") == "cred-alpaca"

    def test_dir_arm_ignores_broker_secret_prefix(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The mount root plays the prefix's role. Composing `_PrefixedLeafSecrets`
        here would build `<prefix>/connectors/alpaca`, which is no longer a leaf —
        DirSecretsProvider would refuse it."""
        root = _secrets_dir(tmp_path, alpaca="cred-alpaca")
        monkeypatch.setenv("BROKER_SECRETS", "dir")
        monkeypatch.setenv("BROKER_SECRETS_DIR", str(root))
        monkeypatch.setenv("BROKER_SECRET_PREFIX", "safe-agents/development")
        assert _resolve_secrets_provider().fetch_secret("alpaca") == "cred-alpaca"

    @pytest.mark.parametrize(
        ("env", "expected_type"),
        [
            ({"BROKER_SECRETS": "fake"}, FakeSecretsProvider),
            ({}, FakeSecretsProvider),
            ({"BROKER_SECRETS": "secretsmanager"}, LazyBotoSecretsProvider),
        ],
    )
    def test_other_arms_are_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, env: dict, expected_type: type
    ) -> None:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        assert isinstance(_resolve_secrets_provider(), expected_type)

    def test_file_arm_is_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        path = tmp_path / "secrets.json"
        path.write_text(json.dumps({"alpaca": "cred-alpaca"}), encoding="utf-8")
        monkeypatch.setenv("BROKER_SECRETS_FILE", str(path))
        provider = _resolve_secrets_provider()
        assert isinstance(provider, LocalFileSecretsProvider)
        assert provider.fetch_secret("alpaca") == "cred-alpaca"

    def test_typo_refuses_here_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BROKER_SECRETS", "secretmanager")
        with pytest.raises(BrokerConfigError, match="not a recognized secrets arm"):
            _resolve_secrets_provider()
