"""
Manifest extended validation — envelope + policy checks (sa#41, sa#135).

Structural checks implementable without the broker registry:
  - envelope parses against the typed Envelope schema (broker/schemas/envelope.py),
    which enforces envelope.polarity is present and exactly 'abstain' or 'act'.
    Missing polarity is a CI failure, never a silent default.
  - secrets.broker_connector_keys is present whenever
    envelope.allowlists.tools is non-empty.
  - policy file exists at repo_root/policy_path (when repo_root given).
  - agent_egress section of the policy file contains no direct IPv4 addresses.

Broker-dependent checks (action-class resolution against registry) are gated on
sa#12 and are not implemented here. --offline skips them when they are added.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from safe_agents.broker.schemas.manifest import AgentManifest

from .manifest import DeploymentManifest, ManifestError

_IPV4_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


def _format_envelope_errors(exc: ValidationError) -> list[str]:
    """Convert a pydantic ValidationError over the AgentManifest into manifest-error strings.

    The envelope is now validated as the `envelope` block of an AgentManifest, so
    error locs are nested under `envelope` (e.g. ("envelope", "polarity")). The
    inner path below `envelope` is what CI/tests key off of: `polarity` is
    special-cased to preserve the existing, specifically-worded errors (missing vs
    invalid value); every other envelope field error falls back to a generic
    `envelope.<path>: <msg>` line. Non-envelope blocks (principal/budgets/…) render
    as `<path>: <msg>`.
    """
    errors: list[str] = []
    for err in exc.errors():
        loc_parts = [str(p) for p in err["loc"]]
        in_envelope = loc_parts[:1] == ["envelope"]
        inner = ".".join(loc_parts[1:]) if in_envelope else ".".join(loc_parts)
        if in_envelope and inner == "polarity" and err["type"] == "missing":
            errors.append(
                "envelope.polarity is missing — must be 'abstain' or 'act'; "
                "a missing polarity is a latent safety bug, not a silent default"
            )
        elif in_envelope and inner == "polarity":
            errors.append(
                f"envelope.polarity={err.get('input')!r} is not valid; "
                "must be one of ['abstain', 'act']"
            )
        elif in_envelope:
            field = f"envelope.{inner}" if inner else "envelope"
            errors.append(f"{field}: {err['msg']}")
        else:
            field = inner if inner else "manifest"
            errors.append(f"{field}: {err['msg']}")
    return errors


def _collect_strings(obj) -> list[str]:
    """Recursively collect all string values from a nested YAML structure."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        results = []
        for v in obj.values():
            results.extend(_collect_strings(v))
        return results
    if isinstance(obj, list):
        results = []
        for item in obj:
            results.extend(_collect_strings(item))
        return results
    return []


def validate_manifest_extended(
    manifest: DeploymentManifest,
    *,
    repo_root: Optional[Path] = None,
    offline: bool = True,
) -> list[str]:
    """
    Run extended structural checks on a loaded manifest.

    Returns a list of error strings (empty list = valid).
    Does not raise; let the caller decide.

    Parameters
    ----------
    manifest:
        A manifest already loaded by load_manifest().
    repo_root:
        When provided, the policy file is resolved relative to repo_root and
        its content is checked. When None, the policy file check is skipped.
    offline:
        If True (default), broker-dependent checks (action-class resolution)
        are skipped. Set to False once sa#12 broker registry lands.
    """
    errors: list[str] = []
    envelope_raw = manifest.envelope or {}

    # -- Manifest schema validation -------------------------------------------
    # Validates the broker-facing blocks against the typed AgentManifest
    # (broker/schemas/manifest.py). `envelope` is required and enforces polarity
    # presence/value via a Literal — a missing polarity is a latent safety bug,
    # never a silent default. The other blocks are optional today (P2 requires
    # them) and are sourced from manifest.raw when present.
    am_raw: dict = {"envelope": envelope_raw}
    for key in ("principal", "grant_classes", "budgets", "connectors"):
        val = manifest.raw.get(key)
        if val is not None:
            am_raw[key] = val

    am: Optional[AgentManifest] = None
    try:
        am = AgentManifest.model_validate(am_raw)
    except ValidationError as exc:
        errors.extend(_format_envelope_errors(exc))

    # -- Broker connector keys vs tools allowlist ----------------------------
    # Only checkable once the manifest itself parses cleanly.
    if am is not None:
        env = am.envelope
        tools = env.allowlists.tools if env.allowlists is not None else []
        if tools and not manifest.secrets.broker_connector_keys:
            errors.append(
                "secrets.broker_connector_keys is required when "
                "envelope.allowlists.tools is non-empty — "
                "connector credentials must be seeded into the broker's store"
            )

    # -- Policy file checks (only when repo_root is provided) ----------------
    if repo_root is not None:
        policy_path = repo_root / manifest.policy
        if not policy_path.exists():
            errors.append(
                f"policy file {manifest.policy!r} not found at {policy_path}"
            )
        else:
            try:
                with policy_path.open(encoding="utf-8") as fh:
                    policy = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                errors.append(f"policy file {policy_path} parse error: {exc}")
                policy = None

            if isinstance(policy, dict):
                agent_egress = policy.get("agent_egress")
                if agent_egress is None:
                    errors.append(
                        f"policy file {manifest.policy!r} missing 'agent_egress' section — "
                        "the agent-facing egress allowlist must be declared"
                    )
                else:
                    # No direct IPv4 addresses in the agent-facing egress block.
                    # Connector IPs must not appear here; all connector traffic routes
                    # through the broker.
                    for s in _collect_strings(agent_egress):
                        for ip in _IPV4_RE.findall(s):
                            errors.append(
                                f"non-broker IP address {ip!r} found in agent_egress "
                                f"section of policy file {manifest.policy!r} — "
                                "connector IPs must not appear in the agent-facing egress policy; "
                                "all connector traffic must route through the broker"
                            )

    # offline=True: skip broker-dependent checks (sa#12 not yet landed)
    # offline=False: (future) resolve action classes against the broker registry

    return errors


def validate_manifest(
    manifest_path: Path,
    *,
    repo_root: Optional[Path] = None,
    offline: bool = True,
) -> None:
    """
    Load and fully validate a manifest. Raises ManifestError on any failure.

    Combines load_manifest() (structural YAML checks) with
    validate_manifest_extended() (envelope + policy checks).
    """
    from .manifest import load_manifest  # noqa: PLC0415

    manifest = load_manifest(manifest_path)
    errors = validate_manifest_extended(manifest, repo_root=repo_root, offline=offline)
    if errors:
        raise ManifestError(
            f"Manifest validation failed for {manifest_path}:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
