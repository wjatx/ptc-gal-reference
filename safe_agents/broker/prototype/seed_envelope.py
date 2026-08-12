"""seed_envelope.py — out-of-band envelope seed for the broker's DynamoDB read
seam (Phase 3 Slice A of the broker-destub epic, sa#136).

Mirrors seed_grants.py's out-of-band seeding pattern (sa#36 Phase C1): with
Slice B wired, build_runtime only ever READS its in-force envelope
(`load_inforce_envelope`) when BROKER_ENVELOPE_LOAD=store — never writes it — so
this script is the one write path, and must run BEFORE seed_grants and the broker. It is co-located in the SAME DynamoDB table as grants (the
envelope is a distinct "ENVELOPE#" item type there; see
broker/envelope/store.py for why no new table or IAM policy is needed), so run
it with the SAME writer credentials seed_grants.py needs — an admin or
promotion-equivalent identity, NOT brokerRole (brokerRole is read-only on that
table).

Config-as-code stays the authorship source: this script reads a given
agents/<name>.yaml's `envelope:` block, validates it, and writes the
canonicalized Envelope keyed by principal so the broker can read it back.

Required env:
  BROKER_GRANTS_TABLE       DynamoDB table to write (the grants table; the
                            envelope is co-located there, no separate table).
  BROKER_ENVELOPE_MANIFEST  Path to the agents/<name>.yaml to seed from.

The store-key principal is derived from the SAME manifest the envelope is read
from — its `principal:` block (#197). When that manifest has no `principal:`
block (pipeline-style agents/*.yaml), BROKER_MANIFEST must be set explicitly
and supplies it. When BOTH name a principal and they differ, the seed REFUSES:
a split-brain env is operator error, and writing under either guess mints a
wrong-keyed envelope row. There is no default principal.

Standard boto3 env also applies: AWS_DEFAULT_REGION / AWS_REGION, AWS_*
credentials, AWS_ENDPOINT_URL_DYNAMODB (Local).

Usage:
  BROKER_GRANTS_TABLE=safe-agents-development-grants \
      BROKER_ENVELOPE_MANIFEST=agents/smoke-fargate.yaml \
      python -m safe_agents.broker.prototype.seed_envelope
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

# broker_server no longer builds a runtime at import time; keep grant loading
# forced into the no-op skip path as belt-and-braces — this script does its own
# envelope seeding below, explicitly, and must never touch grants as a side effect.
# Scoped, not a bare setdefault: a module-level leak poisoned later same-process
# callers (#210).
from safe_agents.broker.prototype.boot_config import grant_load_suppressed  # noqa: E402

with grant_load_suppressed():
    from safe_agents.broker.envelope.seed import (  # noqa: E402
        EnvelopeSeedError,
        seed_envelope,
    )
    from safe_agents.broker.envelope.store import DynamoDBEnvelopeStore  # noqa: E402
    from safe_agents.broker.prototype.broker_server import (  # noqa: E402
        _require_principal,
        load_agent_manifest,
    )
    from safe_agents.broker.schemas.common import Principal  # noqa: E402


class SeedPrincipalError(ValueError):
    """Raised when no unambiguous store-key principal can be derived (#197)."""


def _envelope_manifest_principal(manifest_path: Path) -> Principal | None:
    """The `principal:` block of the envelope manifest itself, if it has one.

    A minimal yaml.safe_load, not AgentManifest validation — the envelope
    manifest may be a pipeline-style agents/*.yaml (extra fields, no principal),
    which is fine: absent means None, but a PRESENT block that fails Principal
    validation is refused, never skipped.
    """
    if not manifest_path.exists():
        raise SeedPrincipalError(f"Manifest not found: {manifest_path}")
    try:
        raw = yaml.safe_load(manifest_path.read_text())
    except yaml.YAMLError as exc:
        raise SeedPrincipalError(f"Manifest parse error in {manifest_path}: {exc}") from exc
    block = raw.get("principal") if isinstance(raw, dict) else None
    if block is None:
        return None
    try:
        return Principal.model_validate(block)
    except ValidationError as exc:
        raise SeedPrincipalError(
            f"'principal:' block in {manifest_path} is not a valid Principal: {exc}"
        ) from exc


def _resolve_seed_principal(manifest_path: Path) -> Principal:
    """The store-key principal, derived from the SAME manifest the envelope is
    read from (#197) — never from a default.

    BROKER_MANIFEST, when explicitly set, is cross-checked: a mismatch between
    the two manifests' principals is a split-brain env and is REFUSED rather
    than guessed. When the envelope manifest carries no `principal:` block
    (pipeline-style yaml), an explicitly-set BROKER_MANIFEST supplies it; bare
    invocation with no principal anywhere refuses — fail toward not-writing.
    """
    envelope_principal = _envelope_manifest_principal(manifest_path)

    broker_manifest_env = os.environ.get("BROKER_MANIFEST")
    broker_principal: Principal | None = None
    if broker_manifest_env:
        try:
            broker_principal = _require_principal(
                load_agent_manifest(Path(broker_manifest_env))
            )
        except (OSError, ValueError) as exc:
            raise SeedPrincipalError(
                f"BROKER_MANIFEST={broker_manifest_env} did not yield a principal: {exc}"
            ) from exc

    if envelope_principal is not None:
        if broker_principal is not None and broker_principal != envelope_principal:
            raise SeedPrincipalError(
                f"split-brain env: BROKER_ENVELOPE_MANIFEST ({manifest_path}) names "
                f"principal {envelope_principal.agentId!r} but BROKER_MANIFEST "
                f"({broker_manifest_env}) names {broker_principal.agentId!r} — refusing "
                "to guess which one keys the envelope. Point both at the same "
                "consumer, or unset BROKER_MANIFEST to key by the envelope manifest."
            )
        return envelope_principal
    if broker_principal is not None:
        return broker_principal
    raise SeedPrincipalError(
        f"no principal to key the envelope by: {manifest_path} has no 'principal:' "
        "block and BROKER_MANIFEST is unset. Set BROKER_MANIFEST to the manifest "
        "whose principal this envelope belongs to — there is no default principal."
    )


def main() -> int:
    table_name = os.environ.get("BROKER_GRANTS_TABLE")
    if not table_name:
        print(
            "ERROR: BROKER_GRANTS_TABLE is required (the grants table the envelope "
            "is co-located in).",
            file=sys.stderr,
        )
        return 2

    manifest_env = os.environ.get("BROKER_ENVELOPE_MANIFEST")
    if not manifest_env:
        print(
            "ERROR: BROKER_ENVELOPE_MANIFEST is required (path to the agents/<name>.yaml "
            "whose envelope: block should be seeded).",
            file=sys.stderr,
        )
        return 2
    manifest_path = Path(manifest_env)

    # The envelope is keyed by the principal of the SAME manifest it is read from
    # (#197), cross-checked against BROKER_MANIFEST when set — never a default.
    try:
        principal = _resolve_seed_principal(manifest_path)
    except SeedPrincipalError as exc:
        print(f"[seed] REFUSED {exc}", file=sys.stderr)
        return 2

    store = DynamoDBEnvelopeStore(table_name=table_name)
    print(
        f"[seed] table={table_name} manifest={manifest_path} principal={principal.agentId}"
    )

    try:
        envelope = seed_envelope(store, manifest_path, principal)
    except EnvelopeSeedError as exc:
        print(f"[seed] FAIL {exc}", file=sys.stderr)
        return 1

    readback = store.get_envelope(principal)
    if readback is None:
        print("[seed] FAIL: absent after write (read returned no envelope)", file=sys.stderr)
        return 1
    if readback != envelope:
        print(
            "[seed] FAIL: read back after write did not match what was seeded",
            file=sys.stderr,
        )
        return 1

    print(
        f"[seed] OK polarity={envelope.polarity!r} high_stakes={envelope.high_stakes} "
        "written and read back."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
