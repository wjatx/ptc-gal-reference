"""peer-receiver.py — the peer airlock endpoint `peer.publish` posts to (#250 Phase 5).

Runs from the drill ConfigMap on the SAME image every other leg uses, so it adds no
second build path. Stdlib only apart from the channels schema, which is present
because the image carries the SDK.

WHAT IT IS, precisely, because the audience this epic is aimed at will ask. It is a
**bare receiving endpoint**: it checks the shared transport token and validates that
the body parses as a well-formed `EventTrigger`, then prints the provenance chain and
returns 200. It is NOT the inbound airlock — no trust map, no sender-class mapping, no
dedupe, no screening. Those are `examples/webhook_peer` and the channels epic owns
them; none of them is what demonstration 2 is about.

Demonstration 2's claim is about the BROKER'S VERDICT on `peer.publish` — allow on a
clean turn, `require_approval` on a tainted one. The receiver exists so the allowed
branch actually lands somewhere, because an allow that quietly fails to execute is
indistinguishable in effect from a deny, and the contrast would be fake.

WHAT THE CHAIN IT PRINTS DOES *NOT* PROVE (#315). On the `POST /call` path the agent
supplies `args.envelope` and `PeerConnector` transports it unmodified — correctly, it
is pure transport. `stamp_outbound`, the seam that would derive the hop's label from
the broker-held turn's taint, has **no runtime caller**. So the chain printed below is
AGENT-AUTHORED, and this receiver deliberately does not present it as evidence of
anything. It is echoed so the gap is visible rather than implied.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from safe_agents.channels.schemas import EventTrigger

TOKEN_HEADER = os.environ.get("PEER_TOKEN_HEADER", "x-peer-token")
TOKEN = os.environ.get("PEER_TOKEN", "")
PORT = int(os.environ.get("PEER_PORT", "8081"))


def log(message: str) -> None:
    print(f"[peer] {message}", flush=True)


class _Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 — readiness only
        self._json(200, {"ok": True}) if self.path == "/healthz" else self._json(404, {})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/inbound":
            self._json(404, {"error": f"no such path: {self.path}"})
            return
        # Gate 1, and the only gate here: the shared transport token. Authenticity is
        # NOT content trust — an admitted sender's payload is still whatever it is.
        if TOKEN and self.headers.get(TOKEN_HEADER) != TOKEN:
            log("REFUSED: bad or missing transport token")
            self._json(401, {"error": "bad token"})
            return
        raw = self.rfile.read(int(self.headers.get("content-length", 0)) or 0)
        try:
            envelope = EventTrigger.model_validate_json(raw)
        except Exception as exc:  # noqa: BLE001 — a peer sent us garbage; say so, stay up
            log(f"REFUSED: body is not a well-formed EventTrigger: {exc}")
            self._json(400, {"error": "malformed envelope"})
            return

        log(f"ACCEPTED event_id={envelope.event_id} principal={envelope.principal}")
        log(f"  payload: {json.dumps(envelope.payload)[:160]}")
        for hop in envelope.provenance:
            log(f"  hop: zone={hop.zone} source={hop.source} label={hop.label}")
        # Said every time, not once in a README: this chain arrived from the agent.
        log("  NB the chain above is AGENT-AUTHORED — the /call path does not call")
        log("     stamp_outbound (#315), so it is echoed, never trusted.")
        self._json(200, {"status": "accepted", "event_id": envelope.event_id})

    def log_message(self, fmt, *args) -> None:
        log(f"{self.address_string()} {fmt % args}")


def main() -> None:
    if not TOKEN:
        # Fail loudly rather than accept anything: a receiver that silently drops its
        # only gate would make the allowed branch look identical to a broken one.
        print("[peer] FATAL: PEER_TOKEN is empty — refusing to run an ungated receiver",
              file=sys.stderr)
        raise SystemExit(1)
    log(f"listening on :{PORT}/inbound (token header {TOKEN_HEADER})")
    HTTPServer(("0.0.0.0", PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
