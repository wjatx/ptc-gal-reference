#!/usr/bin/env python3
"""
drain_logic.py — pure, testable helpers for the ec2-woken box drain loop (sa#98).

The drain loop (drain.sh) is deliberately thin bash; every decision that benefits from being
deterministic and unit-testable lives here as a pure function, mirroring how the airlock's
`process_inbound` factors its decision logic out of I/O (arms/ec2_woken/airlock/handler.py).

Two seams:
  - message parsing: SQS `receive-message` envelope → the first message → the normalized
    {owner, message_id, text} event body. Malformed at either level is reported distinctly
    (empty poll vs. poison message) so the drain can idle-count vs. drop-and-continue.
  - idle-exit predicate: the box sleeps once N consecutive polls come back empty.

CLI (called by drain.sh):
    drain_logic.py extract        # stdin = receive-message JSON; prints TSV fields
    drain_logic.py run_id <id>    # prints the deterministic run id for a message id

`extract` exit codes are the drain's branch predicate:
    0  a valid normalized message — prints MESSAGE_ID / RECEIPT / OWNER / TEXT_B64 (tab-separated)
    1  no message (empty poll) — the drain increments its idle counter
    2  a message is present but its body is malformed (poison) — prints RECEIPT so the drain can
       delete it; the drain drops it and keeps going (never reprocesses a poison message)
"""
from __future__ import annotations

import base64
import json
import sys

EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_POISON = 2
EXIT_USAGE = 64


def parse_receive(raw: str) -> dict | None:
    """Return the first SQS message dict ({Body, ReceiptHandle, ...}) or None if empty/invalid.

    None means "no message" (an empty long-poll): either the envelope did not parse, was not a
    dict, or carried no Messages. The drain treats None as an idle poll.
    """
    try:
        envelope = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(envelope, dict):
        return None
    messages = envelope.get("Messages")
    if not messages or not isinstance(messages, list):
        return None
    first = messages[0]
    return first if isinstance(first, dict) else None


def parse_normalized(body: str) -> dict | None:
    """Parse the normalized {owner, message_id, text} event body. None if malformed.

    Mirrors the airlock's `normalized_from_body` contract: owner and message_id must be
    non-empty; text must be present (empty text is allowed). message_id / owner are coerced
    to str so an integer id survives.
    """
    try:
        event = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(event, dict):
        return None
    owner = event.get("owner")
    message_id = event.get("message_id")
    text = event.get("text")
    if not owner or message_id in (None, "") or text is None:
        return None
    return {"owner": str(owner), "message_id": str(message_id), "text": str(text)}


def run_id_for(message_id: str) -> str:
    """Deterministic run id (run-record SK) derived from a message id.

    Non-alphanumeric characters are collapsed to '-' so the id is a safe DynamoDB key and a
    safe idempotency-key fragment; the same message id always maps to the same run id.
    """
    safe = "".join(c if (c.isalnum() or c in "-_") else "-" for c in str(message_id))
    return f"woken-{safe}"


def should_self_stop(empty_polls: int, idle_polls: int) -> bool:
    """The drain sleeps the box once `empty_polls` consecutive empty polls are seen.

    This is the loop's exit predicate: a deterministic counter, not a judgment call.
    """
    return empty_polls >= idle_polls


def _cmd_extract(raw: str) -> int:
    message = parse_receive(raw)
    if message is None:
        return EXIT_EMPTY
    receipt = message.get("ReceiptHandle", "")
    event = parse_normalized(message.get("Body", ""))
    if event is None:
        # A message is present but its body is malformed → poison. Emit the receipt so the
        # drain can delete it (and not wedge the queue) without ever running it.
        print(f"RECEIPT\t{receipt}")
        return EXIT_POISON
    text_b64 = base64.b64encode(event["text"].encode()).decode()
    print(f"MESSAGE_ID\t{event['message_id']}")
    print(f"RECEIPT\t{receipt}")
    print(f"OWNER\t{event['owner']}")
    print(f"TEXT_B64\t{text_b64}")
    return EXIT_OK


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: drain_logic.py {extract|run_id <message_id>}", file=sys.stderr)
        return EXIT_USAGE
    command = argv[1]
    if command == "extract":
        return _cmd_extract(sys.stdin.read())
    if command == "run_id":
        if len(argv) < 3:
            print("usage: drain_logic.py run_id <message_id>", file=sys.stderr)
            return EXIT_USAGE
        print(run_id_for(argv[2]))
        return EXIT_OK
    print(f"drain_logic: unknown command {command!r}", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
