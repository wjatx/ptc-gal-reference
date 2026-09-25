"""Secrets provider — the seam between the broker and the credential store.

The broker fetches connector credentials at execute time, never at import time.
The agent process never receives or sees the credential value; only the Doer
calls fetch_secret(), and the Doer is the only component the PEP delegates
connector execution to.

Exports:
    SecretsProvider       — Protocol the Doer depends on.
    RotatableSecretsProvider — the write-capable variant a rotating credential
                              needs (#238); a strictly larger authority, so it is
                              a separate protocol arms opt into.
    FakeSecretsProvider   — deterministic in-memory map; AWS-free for tests.
    LocalFileSecretsProvider — reads credentials from a 0600 JSON file on disk;
                              the local arm's real provider (no AWS, no boto3).
    DirSecretsProvider    — reads each credential from its OWN file under a
                            directory; the shape every container platform
                            projects (#248).
    LazyBotoSecretsProvider — lazy boto3 Secrets Manager impl for deployment;
                              boto3 is not imported until the first fetch call.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretsProvider(Protocol):
    """Minimal credential fetch interface used by the Doer at execute time.

    The Doer is the only component that calls fetch_secret(). The agent process
    has no path to this object — invariant 1: the agent holds no connector credentials.
    """

    def fetch_secret(self, secret_name: str) -> str:
        """Return the credential value for a named secret (opaque string)."""
        ...


@runtime_checkable
class RotatableSecretsProvider(Protocol):
    """A SecretsProvider that can also WRITE a leaf back — the capability a
    rotating credential requires (#238).

    Deliberately a SEPARATE protocol, not a method on ``SecretsProvider``: writing
    is a strictly larger authority than reading, most arms neither need nor should
    have it, and a broker that can rewrite its own secret store is a different
    blast radius from one that can only read it. A caller tests for this protocol
    and fails LOUDLY when it is absent rather than degrading — see
    ``OAuthRefresh``, where a rotation that cannot be persisted has already
    destroyed the stored credential and silence would strand the chain.
    """

    def fetch_secret(self, secret_name: str) -> str:
        """Return the credential value for a named secret (opaque string)."""
        ...

    def store_secret(self, secret_name: str, value: str) -> None:
        """Replace the named leaf's value. Must be durable before it returns."""
        ...


class FakeSecretsProvider:
    """Deterministic in-memory secrets provider for tests.

    Maps secret names to credential values. Raises KeyError on unknown names.
    No AWS required; boto3 is never imported.
    """

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = dict(secrets)

    def fetch_secret(self, secret_name: str) -> str:
        if secret_name not in self._secrets:
            raise KeyError(f"unknown secret: {secret_name!r}")
        return self._secrets[secret_name]

    def store_secret(self, secret_name: str, value: str) -> None:
        """Writable so the rotating-credential path is testable without a disk."""
        self._secrets[secret_name] = value


class LocalFileSecretsProvider:
    """Reads connector credentials from a JSON file on disk — the local arm's real
    provider, the honest stand-in for AWS Secrets Manager.

    The file is a flat ``{secret_name: value}`` JSON object and is expected to be mode
    0600 (owner read/write only) and mounted read-only into the broker container. On
    the host, run-local.sh populates it from the macOS Keychain.

    The file is read lazily on the first fetch_secret() call and cached for the life of
    the provider, so the broker never holds the credential map until it actually needs
    a credential. boto3 is never imported.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._secrets: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._secrets is None:
            with open(self._path, encoding="utf-8") as handle:
                self._secrets = json.load(handle)
        return self._secrets

    def fetch_secret(self, secret_name: str) -> str:
        secrets = self._load()
        if secret_name not in secrets:
            raise KeyError(f"unknown secret: {secret_name!r} (not in {self._path})")
        return secrets[secret_name]


# A BOM is refused rather than stripped. Windows PowerShell 5.1's
# `echo value > file` writes UTF-16LE with the first mark here.
_BYTE_ORDER_MARKS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe", "UTF-16 little-endian"),
    (b"\xfe\xff", "UTF-16 big-endian"),
    (b"\xef\xbb\xbf", "UTF-8"),
)


class DirSecretsProvider:
    """Reads each credential from its OWN file under a directory — one file per
    secret leaf, the shape every container platform projects (#248).

    A Kubernetes/OpenShift mounted ``Secret``, a CSI Secrets Store volume, Podman's
    ``/run/secrets`` and systemd credentials all present exactly this layout: the
    secret's keys become filenames under one directory, each file holding one value.
    So this arm needs no adapter and — importantly — publishes no naming FORMAT of
    its own: the filename IS the existing secret leaf (``connector_secrets``, sa#164),
    the same leaf the Secrets Manager arm resolves under ``<prefix>/connectors/``.
    The mount directory plays the prefix's role, which is why this arm ignores
    BROKER_SECRET_PREFIX rather than composing with ``_PrefixedSecrets``.

    Three deliberate behaviours:

    * **Read-through, never cached.** Every fetch re-reads the file. The kubelet
      refreshes a projected Secret volume *in place* (~60s after the underlying
      object changes), so a provider that caches for its own lifetime — as
      ``LocalFileSecretsProvider`` does — would serve a rotated-away credential for
      as long as the process lives. That is tolerable for a ceremony CLI and wrong
      for a long-lived gateway, which is the consumer this arm exists for.
    * **One trailing newline is stripped.** A projected Secret carries no trailing
      newline but ``echo secret > file`` adds one, and a stray ``\\n`` on a bearer
      token surfaces as an opaque 401 from the remote API rather than as a local
      error. Exactly one trailing ``\\n`` (or ``\\r\\n``) is removed; every other
      byte, including an interior CR, is part of the credential and is preserved.
      A file starting with a byte-order mark is refused with ValueError.
    * **Leaves only.** A secret name containing a path separator, or equal to
      ``.``/``..``, is REFUSED rather than resolved — a name is a leaf under the
      mount root, never a path out of it. This raises ValueError, deliberately NOT
      KeyError/FileNotFoundError: those two mean "no such secret" to
      ``_is_missing_secret`` and would fall through to a dev-stub fallback, turning
      a traversal attempt into a silent stub credential.

    File mode is deliberately NOT checked. The issuer signing key refuses a
    group/other-readable file (``grants/issuer_keys.py``) because a signing key
    readable by anyone else is not a private key; a connector credential's boundary
    here is the container and its mount, not the mode bits — and projected Secret
    volumes default to ``0644``, so a mode check would refuse a stock mount in the
    exact venue this arm was built for. ``example-wrapper posture`` is where that limit is
    stated, not this class.

    Raises FileNotFoundError when a leaf has no file, matching
    ``LocalFileSecretsProvider``'s miss semantics so the same overlay fallback and
    the same ``_is_missing_secret`` predicate apply unchanged.
    """

    def __init__(self, root: str) -> None:
        self._root = Path(root)

    def _resolve(self, secret_name: str) -> Path:
        if (
            not secret_name
            or "/" in secret_name
            or "\\" in secret_name
            or secret_name in (".", "..")
        ):
            raise ValueError(
                f"secret name {secret_name!r} is not a leaf — refusing to resolve it "
                f"against the secrets directory {self._root}: a name is a single "
                "filename under the mount root, never a path out of it."
            )
        candidate = self._root / secret_name
        # Separator checks alone are POSIX-complete but not Windows-complete: there
        # a name like "D:x" carries a DRIVE, and joining it discards the root
        # entirely. Requiring the joined path to sit directly under the root closes
        # that on every platform, and on POSIX it can never fire after the checks
        # above.
        if candidate.parent != self._root:
            raise ValueError(
                f"secret name {secret_name!r} does not resolve to a file directly "
                f"under the secrets directory {self._root} — refusing it."
            )
        return candidate

    def fetch_secret(self, secret_name: str) -> str:
        path = self._resolve(secret_name)
        # Bytes, never read_text: text mode's universal newlines rewrite every
        # "\r\n" and lone "\r" to "\n" on EVERY platform, which alters an interior
        # CR in the credential and leaves the "\r\n" strip below unreachable.
        data = path.read_bytes()
        bom = next((name for mark, name in _BYTE_ORDER_MARKS if data.startswith(mark)), None)
        if bom is not None:
            raise ValueError(
                f"secret file {path} starts with a {bom} byte-order mark, which is "
                "never part of a credential. Re-save it as UTF-8 without a BOM (in "
                "PowerShell: Set-Content -NoNewline -Encoding utf8NoBOM, or "
                "[IO.File]::WriteAllText)."
            )
        raw = data.decode("utf-8")
        if raw.endswith("\r\n"):
            return raw[:-2]
        if raw.endswith("\n"):
            return raw[:-1]
        return raw

    def store_secret(self, secret_name: str, value: str) -> None:
        """Replace the leaf ATOMICALLY — write a temp file in the same directory,
        then ``os.replace`` it over the target.

        Atomicity is the whole point here, not tidiness. This path exists for
        rotating credentials, where the value being replaced has ALREADY been
        invalidated by the authorization server: a torn or partial write does not
        lose an update, it strands the chain and costs a human re-authorization.
        ``os.replace`` is atomic within a filesystem, and the temp file is created
        in the same directory to guarantee that.

        No trailing newline is written, matching what ``fetch_secret`` strips.

        NB a projected Kubernetes Secret volume is READ-ONLY, so this will raise
        there — correctly. A rotating credential and an immutable projection are
        genuinely incompatible, and that belongs in the operator's face at the
        first rotation rather than hidden behind a fallback.
        """
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        target = self._resolve(secret_name)
        fd, tmp = tempfile.mkstemp(dir=str(self._root), prefix=".rotate-")
        try:
            # newline="": write the value verbatim. Text mode on Windows would turn
            # an interior "\n" into "\r\n", and fetch_secret returns bytes as-is.
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            # mkstemp already creates the file owner-only on POSIX; this restates it
            # rather than relying on that. On Windows chmod can only toggle the
            # read-only flag, so it is a no-op for privacy there: the file inherits
            # the ACL of the secrets directory, which is where that boundary lives.
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


class LazyBotoSecretsProvider:
    """Lazy boto3 Secrets Manager implementation for deployment.

    boto3 is imported on the first fetch_secret() call, keeping the module
    importable in test environments where boto3 is not installed. The client is
    initialized once and reused across calls.

    The broker IAM role must have secretsmanager:GetSecretValue on the relevant
    secret ARNs. The agent IAM role must NOT have this permission (invariant 1).
    """

    def __init__(self, region_name: str | None = None) -> None:
        """`region_name=None` defers to boto3's own resolution chain.

        The default used to be the literal "us-east-1", which is worse than no
        default at all: deployed anywhere else it silently talks to the WRONG
        region rather than failing. Left as None, boto3 resolves AWS_REGION,
        AWS_DEFAULT_REGION, the shared config and then the instance/task
        metadata, and raises NoRegionError when none of them answer — the
        named-or-refuse posture of #205, using the SDK's own mechanism rather
        than a second one bolted on top.
        """
        self._region_name = region_name
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3  # noqa: PLC0415
            self._client = boto3.client("secretsmanager", region_name=self._region_name)
        return self._client

    def fetch_secret(self, secret_name: str) -> str:
        client = self._get_client()
        response = client.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
