"""broker.taint.propagation — input-trust map type and convenience factory.

The InputTrustMap is the per-agent configuration that decides which ingestion
sources are trusted. The base provides the marking and propagation mechanism;
the per-agent source list is NOT baked in — it is injected at construction.

Taint decisions are purely static: trust_map(source) is a deterministic config
lookup, never an LLM judgment.
"""

from __future__ import annotations

from typing import Callable

# Per-agent input-trust map: maps source identifier → trusted (True) or untrusted (False).
# Injected by the per-agent harness; the base never supplies a default mapping.
InputTrustMap = Callable[[str], bool]


def build_trust_map(trusted_prefixes: list[str]) -> InputTrustMap:
    """Build a prefix-based trust map from an explicit allowlist.

    Sources whose identifier starts with a trusted prefix are considered trusted;
    all others are untrusted and will taint the turn on ingestion.

    This is a convenience factory for tests and minimal examples. Per-agent
    deployments should inject their own InputTrustMap callable with the full
    per-agent policy.
    """

    def is_trusted(source: str) -> bool:
        return any(source.startswith(prefix) for prefix in trusted_prefixes)

    return is_trusted
