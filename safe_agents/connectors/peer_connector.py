"""peer_connector.py — the BASE reference `peer` connector (peer.publish, #172).

`peer.publish` speaks our OWN protocol to our OWN airlock (EventTrigger,
`/inbound`, the provenance chain — all base), so its transport is platform
mechanism, not domain code. Shipping the canonical peer connector makes
`stamp_outbound` non-bypassable by construction: there is no consumer-authored
transport that could skip the broker-side stamp. Stamping stays floor
(broker-side); this is the base reference transport nobody reimplements.

It is the sending mirror of the receiver's `SignedWebhookAdapter`
(safe_agents/channels/webhook.py): it POSTs a broker-stamped `EventTrigger` to a
peer agent's airlock as a JSON body, proving transport authenticity with the
shared secret-token header the receiver's `verify_token` (gate 1) checks.

It is **pure transport**. It does NOT construct provenance and does NOT decide
taint: the envelope it transports was already stamped broker-side by
``stamp_outbound`` from the sending turn (PUBLISH.md P3). The connector validates
only that the payload parses as a well-formed EventTrigger — it refuses to POST
garbage — and never edits it. The peer endpoint URL and shared secret are the
broker-fetched credential facts the agent never holds (PUBLISH.md P1); the agent
supplied only the envelope's intent.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from safe_agents.channels.schemas import EventTrigger

# The ONLY safe-agents imports a consumer connector needs: the public connector
# surface and the public channels schema — never safe_agents.broker internals.
from safe_agents.connectors import Connector

# Bounded, deterministic — a peer airlock either accepts fast or the send fails
# closed (the broker records the failure; the abstain-safe emitter treats a
# non-delivery as the safe outcome).
_TIMEOUT_SECONDS = 10


class PeerConnector:
    """POST a broker-stamped EventTrigger to a peer agent's airlock.

    Zero-arg instantiable and satisfying the ``Connector`` protocol
    (``execute(tool, op, args, credential)``). The ``credential`` is the
    broker-fetched peer descriptor — JSON ``{"url", "token_header", "token"}`` —
    used to address and authenticate to the peer, never logged or returned.
    """

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        if op != "publish":
            raise ValueError(f"peer connector serves only op 'publish', got {op!r}")

        try:
            desc = json.loads(credential)
            url = desc["url"]
            token_header = desc["token_header"]
            token = desc["token"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            # Never echo the credential in the failure message.
            raise ValueError("peer credential must be JSON {url, token_header, token}") from exc

        # The envelope was stamped broker-side by stamp_outbound; the connector only
        # transports it. Re-validate parse/shape so a malformed body never crosses
        # the wire — but never touch provenance (PUBLISH.md P3: broker-stamped).
        envelope = EventTrigger.model_validate((args or {}).get("envelope"))
        body = envelope.model_dump_json().encode("utf-8")

        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"content-type": "application/json", token_header: token},
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            http_status = response.status

        return {
            "status": "published",
            "event_id": envelope.event_id,
            "principal": envelope.principal,
            "http_status": http_status,
        }


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(PeerConnector(), Connector)
