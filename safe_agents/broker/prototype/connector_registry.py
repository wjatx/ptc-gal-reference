"""connector_registry.py — the by-name connector seam (broker-debaking P2, sa#113).

The manifest carries connector NAMES only (`connectors: [github, alpaca, ...]`);
this module is where a name resolves to a base connector implementation. Before
P2 the connectors were a hardcoded ``connectors = {...}`` dict inside
``build_runtime``; moving the map here is the "de-bake" — the runtime no longer
holds the wiring, it asks the registry.

**This is the ONE sanctioned injection seam (sa#141).** A manifest may supply its
own connector implementation via ``connector_providers`` — a name → dotted provider
path (``"pkg.module:ClassName"``) mapping consumed here through the ``providers``
argument. Provider paths are honored ONLY from the image-baked manifest file: the
envelope store loads an ``Envelope`` (which has no provider/import-path field), so
nothing store-loaded can ever reach this seam. A provider entry overrides a base
name; anything neither provided nor in the base registry fails closed
(``UnknownConnectorError``) rather than silently serving an empty capability. A
provider that cannot be imported, instantiated zero-arg, or that does not satisfy
the ``Connector`` protocol fails closed too (``ConnectorProviderError``).

Each entry is a zero-arg factory so a connector is constructed only when a manifest
actually names it (a manifest granting a subset does not instantiate the rest).
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Mapping
from typing import Callable

from safe_agents.broker.runtime.connector import Connector
from safe_agents.connectors import (  # shared, from the SDK
    GitHubConnector,
    LedgerConnector,
    PeerConnector,
    SearchConnector,
    TelegramConnector,
)

# name → zero-arg factory for the base's known connectors. The names are the
# manifest vocabulary (``connectors:`` list); the classes are the base
# implementations. All are domain-invariant: github (a harmless already-proven
# live capability), notify/ledger/search (shared connectors), and peer
# (peer.publish — our own A2A transport to our own airlock, #172). Domain
# connectors like alpaca are NOT base — they are consumer-injected via
# ``connector_providers`` (a consumer agent's broker image carries AlpacaConnector).
_BASE_CONNECTORS: dict[str, Callable[[], Connector]] = {
    "github": GitHubConnector,
    "notify": TelegramConnector,
    "ledger": LedgerConnector,
    "search": SearchConnector,
    "peer": PeerConnector,
}


class UnknownConnectorError(KeyError):
    """Raised when a manifest names a connector the base registry does not know.

    Fail closed rather than silently omit — a manifest asking for a capability the
    broker cannot wire is a configuration error the operator must see, not a
    quietly-empty registry. (Consumer-supplied implementations resolve through
    ``connector_providers`` — a name absent from BOTH is genuinely unresolvable.)
    """


class ConnectorProviderError(Exception):
    """Raised when a manifest-declared provider path cannot yield a usable Connector.

    Covers: unimportable module, missing class attribute, a class that is not
    zero-arg instantiable, and an instance that does not satisfy the ``Connector``
    protocol. Always names the offending path — a broken provider is an operator
    error to fix, never something to paper over with a base fallback.
    """


def known_connector_names() -> tuple[str, ...]:
    """The connector names the base registry can resolve (for error messages/tests)."""
    return tuple(_BASE_CONNECTORS)


def _load_provider(name: str, path: str) -> Connector:
    """Import + instantiate + protocol-check one provider path; fail closed loudly."""
    module_name, _, class_name = path.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ConnectorProviderError(
            f"connector {name!r} provider {path!r}: module {module_name!r} "
            f"cannot be imported ({exc})"
        ) from exc
    try:
        provider_class = getattr(module, class_name)
    except AttributeError:
        raise ConnectorProviderError(
            f"connector {name!r} provider {path!r}: module {module_name!r} "
            f"has no attribute {class_name!r}"
        ) from None
    try:
        instance = provider_class()
    except Exception as exc:
        raise ConnectorProviderError(
            f"connector {name!r} provider {path!r}: {class_name!r} is not "
            f"zero-arg instantiable ({exc})"
        ) from exc
    if not isinstance(instance, Connector):
        raise ConnectorProviderError(
            f"connector {name!r} provider {path!r}: {class_name!r} does not "
            "satisfy the Connector protocol (missing execute(tool, op, args, "
            "credential))"
        )
    return instance


def resolve_connectors(
    names: Iterable[str],
    providers: Mapping[str, str] | None = None,
) -> dict[str, Connector]:
    """Resolve manifest connector NAMES to constructed connector instances.

    Returns a ``{name: connector}`` dict suitable for ``Doer(connectors=...)``.
    Per name, resolution order is: ``providers`` (manifest ``connector_providers``,
    a dotted ``"pkg.module:ClassName"`` path — imported, zero-arg instantiated, and
    protocol-checked; any failure raises ``ConnectorProviderError``), else the base
    registry, else ``UnknownConnectorError`` — fail closed on the FIRST bad name,
    listing the known names so the misconfiguration is obvious. ``providers`` must
    only ever come from the image-baked manifest (see module docstring). Order and
    duplicates follow the input; a repeated name resolves once per occurrence
    (harmless — same key overwrites).
    """
    provider_paths = dict(providers or {})
    resolved: dict[str, Connector] = {}
    for name in names:
        if name in provider_paths:
            resolved[name] = _load_provider(name, provider_paths[name])
            continue
        try:
            factory = _BASE_CONNECTORS[name]
        except KeyError:
            raise UnknownConnectorError(
                f"manifest names unknown connector {name!r}; the base registry "
                f"knows {sorted(_BASE_CONNECTORS)} and the manifest provides "
                f"{sorted(provider_paths)}. A connector must be a base name or "
                "carry a connector_providers entry in the image-baked manifest."
            ) from None
        resolved[name] = factory()
    return resolved
