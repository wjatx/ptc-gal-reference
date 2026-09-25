"""call_client.py — send named brokered calls and print what the broker decided (#42).

    python -m safe_agents.broker.prototype.call_client \\
        --call search.query '{"query": "broker"}' \\
        --call notify.send '{"to": "ops", "body": "hi"}'

The deterministic counterpart to ``fake_agent``: that script walks a fixed tour of
the example manifest's ops, while this one sends exactly the calls named on argv,
so the same code drives any manifest. It is what the Compute stack's client task
runs, which is why it is stdlib-only and prints machine-readable lines — an
evaluator reading CloudWatch should not have to parse prose to see a decision.

Output is JSON lines on stdout: the registry first (what this principal may even
SEE), then one line per call carrying ``decision_kind``, ``result``, ``reason``,
``intent_id`` and ``idempotent``.

A deny is a successful run. The client's job is to get the broker to decide, not
to get an allow; exit 0 means every call received a broker decision. Exit 1 means
the broker could not be reached or answered with an HTTP error, and stops at the
first such call — a later call's decision would be read without the failure that
preceded it. Exit 2 is a usage error (argparse's convention).

Like ``fake_agent`` it holds nothing: no credential, no store, no audit writer.
It can only ask.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BROKER_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT_SECONDS = 30.0

EXIT_OK = 0
EXIT_BROKER_FAILURE = 1

#: The BrokerResponse fields the wire carries (broker_server._Handler.do_POST).
_RESPONSE_FIELDS = ("decision_kind", "result", "reason", "intent_id", "idempotent")


class BrokerUnavailable(Exception):
    """The broker did not return a decision: unreachable, or an HTTP error."""


def parse_call(coordinate: str, raw_args: str) -> tuple[str, str, dict[str, Any]]:
    """Split ``TOOL.OP`` and parse its JSON args object, or raise ValueError.

    Splits on the FIRST dot, matching how action classes are written
    (``search.query``); an op name carries no dot in any shipped manifest.
    """
    tool, sep, op = coordinate.partition(".")
    if not sep or not tool or not op:
        raise ValueError(f"{coordinate!r} is not TOOL.OP (e.g. search.query)")
    try:
        args = json.loads(raw_args)
    except json.JSONDecodeError as exc:
        raise ValueError(f"args for {coordinate} are not valid JSON: {exc}") from exc
    if not isinstance(args, dict):
        raise ValueError(
            f"args for {coordinate} must be a JSON object, got {type(args).__name__}"
        )
    return tool, op, args


def _request(req: urllib.request.Request, timeout: float) -> Any:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        # The broker answers malformed requests with 400 and unexpected faults with
        # a generic 500, both with a JSON {"error": ...} body. Neither is a decision.
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise BrokerUnavailable(f"HTTP {exc.code} from {req.full_url}: {body}") from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise BrokerUnavailable(f"cannot reach {req.full_url}: {reason}") from exc
    except json.JSONDecodeError as exc:
        raise BrokerUnavailable(f"{req.full_url} returned non-JSON: {exc}") from exc


def fetch_registry(base_url: str, timeout: float) -> list[dict[str, str]]:
    return _request(urllib.request.Request(f"{base_url}/registry"), timeout)


def send_call(
    base_url: str,
    tool: str,
    op: str,
    args: dict[str, Any],
    timeout: float,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    body = json.dumps(
        {"tool": tool, "op": op, "args": args, "idempotency_key": idempotency_key}
    ).encode()
    req = urllib.request.Request(
        f"{base_url}/call",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    return _request(req, timeout)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.prototype.call_client",
        description=(
            "Send brokered calls and print each decision as a JSON line. "
            "The broker URL comes from BROKER_URL "
            f"(default {DEFAULT_BROKER_URL})."
        ),
    )
    parser.add_argument(
        "--call",
        nargs=2,
        action="append",
        default=[],
        metavar=("TOOL.OP", "JSON_ARGS"),
        help="a call to send, e.g. --call search.query '{\"query\": \"broker\"}'; repeatable",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-request timeout in seconds (default {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    ns = parser.parse_args(argv)
    try:
        calls = [parse_call(coordinate, raw) for coordinate, raw in ns.call]
    except ValueError as exc:
        parser.error(str(exc))  # exits 2

    base_url = os.environ.get("BROKER_URL", DEFAULT_BROKER_URL).rstrip("/")

    try:
        registry = fetch_registry(base_url, ns.timeout)
        print(json.dumps({"broker_url": base_url, "registry": registry}), flush=True)
        for tool, op, args in calls:
            resp = send_call(base_url, tool, op, args, ns.timeout)
            line = {"call": f"{tool}.{op}"}
            line.update({field: resp.get(field) for field in _RESPONSE_FIELDS})
            print(json.dumps(line), flush=True)
    except BrokerUnavailable as exc:
        print(f"BROKER UNAVAILABLE: {exc}", file=sys.stderr)
        return EXIT_BROKER_FAILURE
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover — process entry point
    sys.exit(main())
