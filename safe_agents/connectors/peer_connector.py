"""peer_connector.py — the BASE reference `peer` connector (peer.publish).

`peer.publish` speaks our OWN protocol to our OWN airlock (EventTrigger,
`/inbound`, the provenance chain — all base), so its transport is platform
mechanism, not domain code. Shipping the canonical peer connector makes
`stamp_outbound` non-bypassable by construction: there is no consumer-authored
transport that could skip the broker-side stamp. Stamping stays floor
(broker-side); this is the base reference transport nobody reimplements.

It is the sending mirror of the receiver's `SignedWebhookAdapter`
(safe_agents/channels/webhook.py): it POSTs a broker-stamped `EventTrigger` to a
peer agent's airlock as a JSON body, proving transport authenticity with the
sender's own secret token, in the header the receiver's `verify_token` (gate 1)
checks. The receiver binds that token to one sender identity, so the envelope's
`sender.channel_identity` must be the identity the token names.

It is **pure transport**. It does NOT construct provenance and does NOT decide
taint: the envelope it transports was already stamped broker-side by
``stamp_outbound`` from the sending turn (PUBLISH.md P3). The connector validates
only that the payload parses as a well-formed EventTrigger — it refuses to POST
garbage — and never edits it. The peer endpoint URL and the token are the
broker-fetched credential facts the agent never holds (PUBLISH.md P1); the agent
supplied only the envelope's intent.

It reads the airlock's answer from the response BODY, never the status: the
airlock answers status 200 on every path (channels/ADAPTERS.md §"What the
sender is told"). `{"ok": true}` is reported `published`, which is all an
acceptance, a screen refusal, a replay, any refusal toward a sender the airlock
has not mapped, and a failure inside the airlock while it handled the request
can look like from here. `{"ok": false, "refusal": X}` is reported `refused`
with that `refusal` (`permanent` or `transient`). Any other body is reported
`unknown`, never `published`. The connector does not retry: whether to send
again after a `transient` refusal is the sending consumer's decision.
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

# The airlock's answer is one of three short JSON bodies, so a read is capped
# well above the longest of them and anything larger is an unreadable answer.
_MAX_ANSWER_BYTES = 1024

_PUBLISHED = "published"
_REFUSED = "refused"
_UNKNOWN = "unknown"
_REFUSAL_CLASSES = ("permanent", "transient")


def _read_answer(raw: bytes) -> tuple[str, str | None]:
    """Map the airlock's response body to (status, refusal class)."""
    try:
        answer = json.loads(raw)
    except ValueError:
        return _UNKNOWN, None
    if not isinstance(answer, dict):
        return _UNKNOWN, None
    # `is True` / `is False`, not `==`: 1 == True, and `{"ok": 1}` is not an answer.
    if set(answer) == {"ok"} and answer["ok"] is True:
        return _PUBLISHED, None
    if (
        set(answer) == {"ok", "refusal"}
        and answer["ok"] is False
        and answer["refusal"] in _REFUSAL_CLASSES
    ):
        return _REFUSED, answer["refusal"]
    return _UNKNOWN, None


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
        body = envelope.to_wire().encode("ascii")

        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"content-type": "application/json", token_header: token},
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            http_status = response.status
            raw = response.read(_MAX_ANSWER_BYTES + 1)

        status, refusal = (
            (_UNKNOWN, None) if len(raw) > _MAX_ANSWER_BYTES else _read_answer(raw)
        )
        result = {
            "status": status,
            "event_id": envelope.event_id,
            "principal": envelope.principal,
            "http_status": http_status,
        }
        if status == _REFUSED:
            result["refusal"] = refusal
        return result


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(PeerConnector(), Connector)
