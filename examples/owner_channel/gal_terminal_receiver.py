"""gal_terminal_receiver.py — the GAL terminal-proof FRESH principal's drain Receiver.

The sa#4 epic close requires the full grant lifecycle drilled on a grant with NO
drill-scarred history (GAL §12 claims "from bootstrap"; a fresh principal is the
only honest way to make that claim). This receiver is byte-for-byte the
owner-channel reference receiver with one override: the principal segment. It is
selected by the deploy-time ``CHANNELS_DRAIN_RECEIVER`` dotted path
(``examples.owner_channel.gal_terminal_receiver:GalTerminalReceiver``) alongside
``drain-manifest-gal-terminal.yaml`` — the same image, a different consumer
binding, per the config-provenance lattice (both values image/deploy-plane).
"""

from __future__ import annotations

from safe_agents.channels.drain.receiver import Receiver

from .owner_command_receiver import OwnerCommandReceiver


class GalTerminalReceiver(OwnerCommandReceiver):
    """The fresh GAL terminal-proof principal — segment override only."""

    agent_segment = "gal-terminal-agent"


assert isinstance(GalTerminalReceiver(), Receiver)
