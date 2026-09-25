"""Envelope seed — canonicalizes an agent yaml's `envelope:` block into the
EnvelopeStore (Phase 3 Slice A of the broker-destub epic, sa#136).

Config-as-code (agents/<name>.yaml) stays the authorship source; this module
is the seed step that turns the authored `envelope:` block into the validated
Envelope artifact and writes it to the store keyed by principal. Slice B is now
wired: build_runtime reads what this writes via `load_inforce_envelope` (read.py)
when BROKER_ENVELOPE_LOAD=store. This module still does not touch the running
broker — it is the out-of-band write path that must run before the broker boots.

The broker package must NOT import `safe_agents.pipeline` (layering — see this
repo's CLAUDE.md base/per-agent split). `pipeline/manifest.py::load_manifest`
already parses the full deployment manifest including `envelope:`, but pulling
it in here would import the whole pipeline layer into the broker for one
sub-dict. `load_envelope_block` below does the minimal local yaml.safe_load
instead.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.common import Principal

from .store import EnvelopeStore


class EnvelopeSeedError(ValueError):
    """Raised when an agent yaml is missing, malformed, or has no envelope: block."""


def load_envelope_block(manifest_path: Path) -> dict:
    """Read just the `envelope:` sub-dict out of an agents/<name>.yaml.

    Deliberately minimal — a local yaml.safe_load, not a call into
    safe_agents.pipeline.manifest.load_manifest — so the broker package never
    depends on the pipeline layer.
    """
    if not manifest_path.exists():
        raise EnvelopeSeedError(f"Manifest not found: {manifest_path}")

    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise EnvelopeSeedError(f"Manifest parse error in {manifest_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise EnvelopeSeedError(
            f"Manifest must be a YAML mapping; got {type(raw).__name__} in {manifest_path}"
        )

    envelope_block = raw.get("envelope")
    if envelope_block is None:
        raise EnvelopeSeedError(f"No 'envelope:' block found in {manifest_path}")
    if not isinstance(envelope_block, dict):
        raise EnvelopeSeedError(
            f"'envelope:' must be a YAML mapping in {manifest_path}; "
            f"got {type(envelope_block).__name__}"
        )
    return envelope_block


def seed_envelope(
    store: EnvelopeStore,
    manifest_path: Path,
    principal: Principal,
    *,
    session: object = None,
) -> Envelope:
    """Read manifest_path's `envelope:` block, validate it, and write it to store.

    Raises EnvelopeSeedError if the yaml is missing/malformed/has no envelope
    block, or pydantic.ValidationError if the block fails Envelope validation
    (e.g. a missing polarity — never silently defaulted).

    Returns the validated Envelope so callers (e.g. the seed CLI) can log or
    verify it without a second store read.
    """
    envelope_block = load_envelope_block(manifest_path)
    envelope = Envelope.model_validate(envelope_block)
    store.put_envelope(principal, envelope, session=session)
    return envelope
