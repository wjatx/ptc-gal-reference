"""LedgerConnector — the durable brief/ledger sink for the ledger.append grant (sa#131).

The first shared *durable-write* connector: "persist this artifact durably" is
domain-invariant (identical for a trading agent and a dashboard agent), so it lives
in the base per the base/per-agent split. It appends briefs (markdown) and ledger
deltas (jsonl) as individual S3 objects — one object per record, never overwritten.

The broker injects the credential — the connector never sources it. The credential
is a JSON string ('{"bucket": ..., "prefix": ...}') fetched from the SecretsProvider
(secret name resolves to "<prefix>/connectors/ledger"). The destination bucket and
key prefix are deliberately NOT caller-supplied args — a compromised agent can ask
to append but can never choose where the artifact lands. This is TelegramConnector's
non-redirectable-target pattern: security-relevant facts come from code/config,
never the model. Callers DO name `agent` / `run_id` key *segments*, which is safe
because they only select a path under the credential's prefix (charset-validated so
they cannot traverse out of it), never a bucket or prefix.

Supported op: "append" — PutObject with args:
    kind          "brief" | "digest" | "ledger_delta"  (selects layout + extension)
    logical_date  "YYYY-MM-DD"              (the run's trading/business date)
    content       non-empty str             (the artifact body)
    agent         optional key segment      (default "default"; e.g. "example-agent")
    run_id        optional key segment, ledger_delta only — a run can emit several
                  deltas per logical_date, so a per-run id keeps them distinct;
                  falls back to logical_date when absent. Ignored for briefs and
                  digests (one of each per logical_date is the contract).

A "digest" is the short human-facing condensation of a brief — small enough for a
notification channel's message limit — kept as its own kind so a downstream sender
(e.g. an untainted one-shot digest-sender task) can locate it at a deterministic
key without parsing the full brief.

Key layout: <prefix><agent>/briefs/<logical_date>.md
            <prefix><agent>/digests/<logical_date>.md
            <prefix><agent>/deltas/<run_id or logical_date>.jsonl

Append-only invariant: every put is conditional (IfNoneMatch="*"), which S3 enforces
with s3:PutObject alone — no Get/Head/List needed, matching the brokerRole's
PutObject-only IAM on the ledger bucket. If the target key already exists the
connector retries once at a content-hash-suffixed key; if THAT exists too, the
identical content is already durable (the suffix is derived from the content), so
the call is a no-op reported as deduplicated. Nothing is ever overwritten.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# "digest" is the short human-facing condensation of a brief (must fit a
# notification channel's message limit); it gets its own subdir so a same-day
# brief and digest never collide into each other's content-hash fallback keys.
_VALID_KINDS = {
    "brief": ("briefs", ".md"),
    "digest": ("digests", ".md"),
    "ledger_delta": ("deltas", ".jsonl"),
}
_LOGICAL_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Caller-supplied key segments (agent, run_id) must stay INSIDE the credential's
# prefix: no "/", no leading ".", so neither traversal nor hidden keys are possible.
_KEY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH_SUFFIX_LEN = 12  # sha256 hex prefix — enough to key distinct contents apart


def _is_precondition_failed(exc: Exception) -> bool:
    """True when ``exc`` is S3's 412 for a failed IfNoneMatch conditional put.

    Matched by inspecting the response dict (like broker_server's missing-secret
    check) so botocore need not be importable to reason about the shape.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code") == "PreconditionFailed"
    return False


class LedgerConnector:
    """Real S3 ledger-sink connector. Only the Doer holds an instance of this."""

    def __init__(self) -> None:
        self._client = None  # lazily initialized on first execute()

    def _s3(self):
        if self._client is None:
            import boto3  # noqa: PLC0415 — intentional lazy import (SDK stays AWS-free)

            self._client = boto3.client("s3")
        return self._client

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        """Append one artifact to the ledger bucket named by the credential.

        Supported op:
            "append" -> conditional PutObject of args["content"] at the key derived
                        from kind/agent/logical_date(/run_id).
                        Returns {"key": str, "deduplicated": bool}.

        Raises ValueError for any other op or malformed args. S3 failures propagate
        to the Doer, which redacts the credential before the message can reach the
        audit tape or a log.
        """
        if op != "append":
            raise ValueError(
                f"LedgerConnector supports only the 'append' op, got {op!r}"
            )
        if not isinstance(args, dict):
            raise ValueError("LedgerConnector 'append' requires a dict of args")

        kind = args.get("kind")
        if kind not in _VALID_KINDS:
            raise ValueError(
                f"LedgerConnector 'append' kind must be one of "
                f"{sorted(_VALID_KINDS)}, got {kind!r}"
            )
        logical_date = args.get("logical_date")
        if not isinstance(logical_date, str) or not _LOGICAL_DATE_RE.match(logical_date):
            raise ValueError(
                f"LedgerConnector 'append' logical_date must be 'YYYY-MM-DD', "
                f"got {logical_date!r}"
            )
        content = args.get("content")
        if not isinstance(content, str) or not content:
            raise ValueError("LedgerConnector 'append' requires a non-empty str 'content'")

        agent = args.get("agent", "default")
        if not _KEY_SEGMENT_RE.match(agent):
            raise ValueError(f"LedgerConnector 'append' agent segment invalid: {agent!r}")
        run_id = args.get("run_id")
        if run_id is not None and not _KEY_SEGMENT_RE.match(run_id):
            raise ValueError(f"LedgerConnector 'append' run_id segment invalid: {run_id!r}")

        # The destination comes ONLY from the broker-injected credential. Any
        # bucket/prefix/key the caller smuggles into args is simply never read.
        creds = json.loads(credential)
        bucket = creds["bucket"]
        prefix = creds.get("prefix", "").lstrip("/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        subdir, ext = _VALID_KINDS[kind]
        stem = (run_id or logical_date) if kind == "ledger_delta" else logical_date
        key = f"{prefix}{agent}/{subdir}/{stem}{ext}"
        body = content.encode()

        # First try the natural key; on collision retry once at a content-hash key.
        # Both puts are conditional, so the append-only invariant holds even against
        # a concurrent writer — S3 arbitrates, not a read-then-write race.
        try:
            self._put_no_overwrite(bucket, key, body)
            return {"key": key, "deduplicated": False}
        except Exception as exc:  # noqa: BLE001 — only the 412 is handled; rest re-raised
            if not _is_precondition_failed(exc):
                raise

        digest = hashlib.sha256(body).hexdigest()[:_HASH_SUFFIX_LEN]
        hashed_key = f"{prefix}{agent}/{subdir}/{stem}.{digest}{ext}"
        try:
            self._put_no_overwrite(bucket, hashed_key, body)
            return {"key": hashed_key, "deduplicated": False}
        except Exception as exc:  # noqa: BLE001 — same narrow 412 handling
            if not _is_precondition_failed(exc):
                raise
        # The hash-suffixed key exists, and its suffix is derived from THIS content —
        # so byte-identical content is already durable. Idempotent success, no put.
        return {"key": hashed_key, "deduplicated": True}

    def _put_no_overwrite(self, bucket: str, key: str, body: bytes) -> None:
        """Conditional PutObject — fails with 412 if the key already exists.

        IfNoneMatch="*" makes S3 itself enforce append-only using s3:PutObject alone,
        matching the brokerRole's PutObject-only IAM (no Get/Head/List, no Delete).
        The ledger bucket has no Object Lock (that is the audit bucket's job), so
        this conditional write IS the no-overwrite mechanism.
        """
        content_type = "text/markdown" if key.endswith(".md") else "application/jsonl"
        self._s3().put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
            IfNoneMatch="*",
        )
