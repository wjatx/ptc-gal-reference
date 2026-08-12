"""channels.screens — reference-tier injection screens for gate 7 (sa#152).

**Reference-tier** per docs/contract-vs-reference.md. The normative screening
contract is channels/SCREENING.md and the typed seam is `channels.screening`;
the concrete screens a consumer may wire live *here*, never in a contract doc —
no contract text names a vendor or classifier. A manifest opts one in by naming
its `kind` (channels/manifest.py `ScreenConfig`); enabling remains config-only.

Importing this package is the single, explicit point that populates
`SCREEN_REGISTRY` — `build_airlock` lazily imports it only when a screen is
configured, so the OFF path (the default) imports nothing here. Registration is
centralized in this file rather than scattered as per-module import side effects:
the registry's full contents stay greppable in one place, and each screen module
stays a pure implementation with no dependency on the registry it lands in.
"""

from safe_agents.channels.manifest import SCREEN_REGISTRY

from . import bedrock_classifier

SCREEN_REGISTRY[bedrock_classifier.KIND] = bedrock_classifier.build

__all__ = ["bedrock_classifier"]
