"""channels.drain — the accepted-queue drain worker (sa#155); see channels/DRAIN.md."""

# NOTE: the Lambda entrypoint is deliberately NOT re-exported here — a
# `from .handler import handler` would shadow the `drain.handler` submodule
# with the function. Infra references the full module path:
#   safe_agents.channels.drain.handler.handler
from .handler import DrainConfigError
from .receiver import Receiver, ReceiverProviderError, load_receiver

__all__ = [
    "DrainConfigError",
    "Receiver",
    "ReceiverProviderError",
    "load_receiver",
]
