"""Moved: the stdio gateway client lives in `safe_agents.broker.client`.

The clients are a published tier of their own, "what a consumer asks with"
(`safe_agents/broker/client/__init__.py`), and importing that tier does not load
the broker runtime. This path cannot offer that: importing anything under
`safe_agents.broker.gateway` runs the package's `__init__`, which loads the
surface and, through it, the runtime.

The names are kept here so an import of the old path still resolves. This path was
never public (the consumer-boundary guard has always flagged it), so nothing new
should be written against it.
"""

from safe_agents.broker.client._frames import (
    DEFAULT_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    GatewayClientError,
    result_text,
)
from safe_agents.broker.client.stdio import (
    BROKER_ENV_VARS,
    GATEWAY_MODULE,
    GatewayClient,
    env_without_broker_config,
)

__all__ = [
    "BROKER_ENV_VARS",
    "DEFAULT_TIMEOUT_SECONDS",
    "GATEWAY_MODULE",
    "PROTOCOL_VERSION",
    "GatewayClient",
    "GatewayClientError",
    "env_without_broker_config",
    "result_text",
]
