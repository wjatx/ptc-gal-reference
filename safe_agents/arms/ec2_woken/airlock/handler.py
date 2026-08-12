"""
Inbound airlock guardrail Lambda (ec2-woken arm, sa#34).

The untrusted-input taint boundary for waking a sleeping EC2 agent box. It carries
NO connector credentials — it only screens, dedupes, and wakes. A fully compromised
airlock "can still only ask" (here: can only wake the box).

The airlock is agent-agnostic: it sees ONLY a normalized event shape

    {"owner": <opaque owner id>, "message_id": <str>, "text": <str>}

The channel adapter that turns a concrete channel message into this shape lives in a
consuming agent's manifest inbound: block — it is out of scope here.

Steps, in order (prompt sa#34):
  (a) constant-time verify the shared-token request header      → 401 on mismatch
  (b) parse the normalized JSON body                            → 400 if malformed
  (c) allow-list the owner against OWNER_ALLOW_LIST             → 403 if not listed
  (d) dedup on message_id (conditional PutItem)                 → 200 no-op if seen
  (e) injection-screen text against INJECTION_SCREEN_PATTERN    → DROP (log, no enqueue)
  (f) classify intent via env-driven INTENT_MODEL/INTENT_PROMPT → thin, swappable stub
  (g) on pass: SendMessage to SQS + StartInstances + 200

Design: the guardrail decision logic (token, parse, allow-list, injection, dedup, the
full ordered flow) is PURE — `process_inbound()` takes an injected `Effects` bundle for
the three side effects (dedup put, enqueue, wake), so the whole path is unit-testable
with no AWS. `handler()` only wires the real boto3-backed effects and reads config from
the environment.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Outcome labels (machine-stable; logged + asserted in tests)
# ---------------------------------------------------------------------------

UNAUTHORIZED = "unauthorized"        # bad/missing token
MALFORMED = "malformed"              # body is not the normalized shape
FORBIDDEN_OWNER = "forbidden_owner"  # owner not on the allow-list
DUPLICATE = "duplicate"              # message_id already seen (idempotent no-op)
INJECTION_DROP = "injection_drop"    # injection pattern matched — dropped, not enqueued
ACCEPTED = "accepted"                # enqueued + box woken

_STATUS = {
    UNAUTHORIZED: 401,
    MALFORMED: 400,
    FORBIDDEN_OWNER: 403,
    DUPLICATE: 200,
    INJECTION_DROP: 200,
    ACCEPTED: 200,
}


# ---------------------------------------------------------------------------
# Config + effects (injected — no globals in the pure path)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GuardrailConfig:
    token: str
    token_header: str
    allow_list: list[str]
    injection_pattern: str
    intent_model: str
    intent_prompt: str
    runner_instance_id: str


@dataclass
class Effects:
    """The three side-effecting steps, injected so the flow is testable without AWS.

    record_message: (message_id) -> True if this id is NEW (first sighting), False if a
                    duplicate. Backed by a conditional DynamoDB PutItem in production.
    enqueue:        (normalized_event: dict) -> None. SQS SendMessage in production.
    wake:           (runner_instance_id) -> None. ec2:StartInstances in production.
    """
    record_message: Callable[[str], bool]
    enqueue: Callable[[dict], None]
    wake: Callable[[str], None]


@dataclass
class Response:
    status_code: int
    outcome: str
    owner: Optional[str] = None
    message_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Pure guardrail primitives (no AWS, no globals — each unit-testable directly)
# ---------------------------------------------------------------------------

def constant_time_token_ok(provided: Optional[str], expected: str) -> bool:
    """Constant-time compare of the presented token against the expected secret.

    hmac.compare_digest avoids leaking the token length/prefix via timing. A missing
    header (provided is None) is a mismatch. An empty expected token is treated as a
    misconfiguration and always fails closed.
    """
    if not expected or provided is None:
        return False
    return hmac.compare_digest(provided, expected)


def header_value(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup (API Gateway lowercases keys, but be robust)."""
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return None


def normalized_from_body(raw_body: Optional[str]) -> Optional[dict]:
    """Parse the normalized event {owner, message_id, text}. None if malformed.

    All three fields are required; owner/message_id must be non-empty strings, text is
    coerced to a string (may be empty). Anything else is malformed (the adapter, not the
    airlock, owns producing a well-formed shape — a bad shape is a caller error).
    """
    try:
        body = json.loads(raw_body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    owner = body.get("owner")
    message_id = body.get("message_id")
    if not isinstance(owner, str) or not owner:
        return None
    if not isinstance(message_id, (str, int)) or message_id == "":
        return None
    text = body.get("text", "")
    if not isinstance(text, str):
        return None
    return {"owner": owner, "message_id": str(message_id), "text": text}


def owner_is_allowed(owner: str, allow_list: list[str]) -> bool:
    """True iff owner is on the allow-list. An empty allow-list denies everyone."""
    return owner in (allow_list or [])


def is_injection(text: str, pattern: str) -> bool:
    """True if the injection screen pattern matches the text (→ drop).

    An empty pattern screens nothing (matches nothing). A malformed regex fails CLOSED
    (treated as a match / drop) so a bad pattern never silently disables screening.
    """
    if not pattern:
        return False
    try:
        return re.search(pattern, text or "", re.IGNORECASE) is not None
    except re.error:
        return True


def classify_intent(text: str, *, model: str, prompt: str) -> str:
    """Env-driven intent classifier — a thin, swappable stub.

    The model id and prompt come from config (INTENT_MODEL / INTENT_PROMPT), never
    hardcoded. This deterministic stub returns a single label; a real classifier would
    send `text` as DATA (never as instructions) to the box's brokered model proxy. The
    airlock's guardrails do not depend on the label today — it is a wired, swappable seam.
    """
    _ = (model, prompt, text)  # referenced so the env-driven contract is explicit
    return "actionable"


# ---------------------------------------------------------------------------
# The ordered flow — pure w.r.t. the injected Effects
# ---------------------------------------------------------------------------

def process_inbound(
    headers: dict,
    raw_body: Optional[str],
    config: GuardrailConfig,
    effects: Effects,
) -> Response:
    """Run the full guardrail flow. No AWS here — side effects go through `effects`.

    Returns a Response(status_code, outcome, ...). Ordering matches sa#34:
    token → parse → allow-list → dedup → injection → classify → enqueue+wake.
    """
    # (a) shared-token header
    presented = header_value(headers, config.token_header)
    if not constant_time_token_ok(presented, config.token):
        return Response(_STATUS[UNAUTHORIZED], UNAUTHORIZED)

    # (b) normalized body
    event = normalized_from_body(raw_body)
    if event is None:
        return Response(_STATUS[MALFORMED], MALFORMED)
    owner, message_id, text = event["owner"], event["message_id"], event["text"]

    # (c) owner allow-list
    if not owner_is_allowed(owner, config.allow_list):
        return Response(_STATUS[FORBIDDEN_OWNER], FORBIDDEN_OWNER, owner, message_id)

    # (d) dedup — a re-delivered message_id is an idempotent no-op
    if not effects.record_message(message_id):
        return Response(_STATUS[DUPLICATE], DUPLICATE, owner, message_id)

    # (e) injection screen — matched → DROP (logged, NOT enqueued, NOT woken)
    if is_injection(text, config.injection_pattern):
        return Response(_STATUS[INJECTION_DROP], INJECTION_DROP, owner, message_id)

    # (f) intent classify — env-driven, swappable; does not gate acceptance today
    classify_intent(text, model=config.intent_model, prompt=config.intent_prompt)

    # (g) accept — enqueue the normalized event and wake the box
    effects.enqueue(event)
    effects.wake(config.runner_instance_id)
    return Response(_STATUS[ACCEPTED], ACCEPTED, owner, message_id)


# ---------------------------------------------------------------------------
# Lambda wiring — config from env, effects from boto3 (only touched at runtime)
# ---------------------------------------------------------------------------

def _log(outcome: str, **fields) -> None:
    print(json.dumps({"event": "airlock", "outcome": outcome, **fields}))


def _config_from_env() -> GuardrailConfig:
    return GuardrailConfig(
        token=os.environ.get("INBOUND_CHANNEL_TOKEN", ""),
        token_header=os.environ.get("INBOUND_TOKEN_HEADER", "x-safe-agents-inbound-token"),
        allow_list=json.loads(os.environ.get("OWNER_ALLOW_LIST", "[]")),
        injection_pattern=os.environ.get("INJECTION_SCREEN_PATTERN", ""),
        intent_model=os.environ.get("INTENT_MODEL", "stub-intent-classifier"),
        intent_prompt=os.environ.get("INTENT_PROMPT", ""),
        runner_instance_id=os.environ.get("RUNNER_INSTANCE_ID", ""),
    )


# Lazy boto3 clients (created on first use; never imported at module load so the pure
# path stays importable — and unit-testable — with no boto3 installed).
_clients: dict = {}


def _client(name: str):
    if name not in _clients:
        import boto3  # noqa: PLC0415
        _clients[name] = boto3.client(name)
    return _clients[name]


def _record_message(message_id: str) -> bool:
    """Conditional PutItem — True if new, False if the id was already seen (dup)."""
    from botocore.exceptions import ClientError  # noqa: PLC0415

    ttl_days = int(os.environ.get("DEDUP_TTL_DAYS", "7"))
    expires_at = int(time.time()) + ttl_days * 86400
    try:
        _client("dynamodb").put_item(
            TableName=os.environ["DEDUP_TABLE"],
            Item={
                "message_id": {"S": message_id},
                "expires_at": {"N": str(expires_at)},
            },
            ConditionExpression="attribute_not_exists(message_id)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def _enqueue(event: dict) -> None:
    _client("sqs").send_message(
        QueueUrl=os.environ["INBOUND_QUEUE_URL"],
        MessageBody=json.dumps(event),
    )


def _wake(runner_instance_id: str) -> None:
    # Starting an already-running box is a safe no-op; the box long-polls SQS regardless.
    _client("ec2").start_instances(InstanceIds=[runner_instance_id])


def handler(event, context):  # noqa: ARG001 — Lambda signature
    """API Gateway (HTTP API) proxy entrypoint. Returns a proxy response dict."""
    config = _config_from_env()
    effects = Effects(record_message=_record_message, enqueue=_enqueue, wake=_wake)
    result = process_inbound(
        event.get("headers") or {}, event.get("body"), config, effects
    )
    _log(result.outcome, owner=result.owner, message_id=result.message_id)
    return {"statusCode": result.status_code, "body": result.outcome}
