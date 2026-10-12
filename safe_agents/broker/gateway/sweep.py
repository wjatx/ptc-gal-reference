"""The gateway's expiry sweep, run beside its mouths on the same loop (#163).

An approval that expires undecided is an event the broker records (PTC §6.12),
found by a sweep rather than on the next touch. The gateway is the long-lived host
of the local store arm, so it runs that sweep on a schedule. ``SweepTask`` has the
shape of a mouth (``serve`` and ``request_stop``) so ``serve_until_any_stops`` and
the stop signals treat it like one; it never returns on its own, so it never stops
the mouths beside it.

It enters the runtime through the ``SerializedSurface`` every call takes, on the
loop thread that built the runtime, so a sweep never overlaps a call. A sweep that
finds the runtime busy, or fails, is logged by the sweeper and retried at the next
interval; expiry is still a predicate at use, so a missed pass delays a record and
never lets an expired intent execute.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from safe_agents.broker.approval.expiry import (
    DEFAULT_SWEEP_INTERVAL_SECONDS,
    ExpirySweeper,
)


class SweepTask:
    """Run ``surface.sweep_expired_intents`` now and then once per interval until stopped."""

    def __init__(
        self, surface: Any, *, interval_seconds: float = DEFAULT_SWEEP_INTERVAL_SECONDS
    ) -> None:
        self._sweeper = ExpirySweeper(
            surface.sweep_expired_intents, interval_seconds=interval_seconds
        )
        self._stop_requested = False
        self._stopped: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def serve(self) -> None:
        # The event before the loop: `request_stop` reads them in the other order.
        self._stopped = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        while not self._stop_requested:
            self._sweeper.maybe_sweep()
            try:
                await asyncio.wait_for(
                    self._stopped.wait(), timeout=self._sweeper.interval_seconds
                )
            except asyncio.TimeoutError:
                continue
            return

    def request_stop(self) -> None:
        """Ask `serve()` to return. Safe from a signal handler, before or during serving."""
        self._stop_requested = True
        loop, stopped = self._loop, self._stopped
        if loop is not None and stopped is not None:
            with contextlib.suppress(RuntimeError):  # the loop has already closed
                loop.call_soon_threadsafe(stopped.set)
