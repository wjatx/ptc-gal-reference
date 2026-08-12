"""grants.reviewers — reference-tier evidence reviewers for the checker seam (sa#58).

**Reference-tier** per docs/contract-vs-reference.md. The normative contract is
`CheckerProtocol` in grants/ceremony.py (findings-attach-NEVER-gate); the
concrete reviewers a consumer may wire live *here*, never in a contract doc —
no contract text names a vendor or model. The ceremony commands opt one in by
naming its `kind` (GRANTS_REVIEWER_KIND); enabling remains config-only and the
catalog is CLOSED — the env var selects from this image-baked registry, it can
never name an import path (docs/config-provenance.md).

Importing this package is the single, explicit point that populates
`REVIEWER_REGISTRY` — the ceremony commands lazily import it only when a
reviewer is configured, so the OFF path (the default) imports nothing here.
Registration is centralized in this file rather than scattered as per-module
import side effects: the registry's full contents stay greppable in one place,
and each reviewer module stays a pure implementation with no dependency on the
registry it lands in.
"""

from collections.abc import Callable

from safe_agents.broker.grants.ceremony import CheckerProtocol

from . import bedrock_reviewer

# kind -> factory(params dict) -> reviewer. The CLOSED reviewer catalog.
REVIEWER_REGISTRY: dict[str, Callable[[dict], CheckerProtocol]] = {
    bedrock_reviewer.KIND: bedrock_reviewer.build,
}

__all__ = ["REVIEWER_REGISTRY", "bedrock_reviewer"]
