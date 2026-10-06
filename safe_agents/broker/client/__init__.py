"""broker.client — what a consumer ASKS WITH.

The third of the three tiers a consumer may import, beside what it fills
(`safe_agents.broker.schemas`) and what it runs (`safe_agents.broker.api`). The
tiers and the ruling behind them are stated once, in `safe_agents/broker/api.py`.

Two clients, one for each way the broker's MCP gateway is served:

===========================  ======================================================
Client                       Reaches the gateway
===========================  ======================================================
``GatewayClient``            as a child process, over stdio. The client starts it.
``NetworkGatewayClient``     over the network MCP mouth (streamable HTTP), started
                             by someone else, presenting the launch token.
===========================  ======================================================

Both make the same three calls (`initialize`, `list_tools`, `call_tool`), raise
the same `GatewayClientError`, and hand back the same `tools/call` result, which
`result_text` reads. A refused or held call is not an error here: it comes back
as a result with `isError` true and the broker's own reason as its text.

## Why a tier of its own

A client holds nothing and decides nothing. It carries frames to a gateway and
reports what came back, which is the position of the agent itself. Whoever
holds one can ask and can do nothing else, so publishing it gives a consumer no
way around a decision.

That makes it a different kind of thing from `broker.api`, which hands a
consumer the runtime. It also has a different cost. Importing `broker.api`
loads the runtime: the decision path, the stores, the connectors. A process that
only asks, such as an agent inside a sandbox, should not have to load any of
that. So this package imports the standard library and its own modules, and
nothing else from the base. `tests/test_client_tier.py` holds it to that in a
fresh interpreter.

The clients live here, and not under `safe_agents.broker.gateway`, for the same
reason: importing anything under that package runs its `__init__`, which loads
the surface and, through it, the runtime.
"""

from safe_agents.broker.client._frames import GatewayClientError, result_text
from safe_agents.broker.client.network import NetworkGatewayClient
from safe_agents.broker.client.stdio import GatewayClient

__all__ = [
    # Over stdio: the gateway as a child process.
    "GatewayClient",
    # Over the network MCP mouth, with the launch token.
    "NetworkGatewayClient",
    # What both raise, and how to read what both return.
    "GatewayClientError",
    "result_text",
]
