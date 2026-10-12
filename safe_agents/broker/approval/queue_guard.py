"""Approval-queue de-amplification — the pure, deterministic mechanism.

The availability floor's second half. An attacker who forces abstention drives
calls into `require_approval`; each held intent pages a human, so a flood of
poisoned calls floods the human's attention. This module supplies the two pure
pieces the PEP wires at the require_approval chokepoint:

  * `dedup_intent_id` — a CONTENT-derived intent id (no timestamp, no turn id) so
    two identical re-submissions collapse onto the same pending intent. The PEP,
    when `Envelope.approval_queue.dedup` is on, materializes under this id and
    coalesces if one is already pending — pure de-amplification that never hides
    a genuinely distinct approval.
  * `is_flood` — a pure predicate over the per-op/day held-intent counter's
    within-cap result. Past the cap the PEP raises a flood ALARM but still holds
    the intent; it never sheds. Shedding under flood is a polarity decision (it is
    the DoS under act-safe polarity) and stays consumer-side, never a base default.

Both are pure functions of their arguments — no I/O, no clock, no model — so the
mechanism is deterministic and unit-testable in isolation. Nothing here reads
`polarity`.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from safe_agents.broker.schemas.harness_tool import HARNESS_TOOL

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import Principal

# Prefix distinguishes a content-derived dedup id from the default ts-based
# `intent-...` id (pdp/engine.py `_intent_id`), so the two id spaces never collide.
_DEDUP_PREFIX = "intent-dedup-"
_ID_HEX_LEN = 16


def dedup_intent_id(principal: "Principal", tool: str, op: str, args_digest: str) -> str:
    """Deterministic content-derived intent id for coalescing identical holds.

    Stable across timestamps and turns for identical (principal, tool, op, args):
    the SAME inputs always yield the SAME id, so a re-submission lands on the same
    pending intent instead of paging the human again. The principal key mirrors
    `enforcement.store.scoped_counter_key` exactly (agentId#skill#user#tier), so
    dedup is per-principal — one principal cannot coalesce onto another's intent.

    `args_digest` is the caller-supplied hash of the call args (the PEP passes
    `audit.hash_args(call.args)`), never the raw args — no PII enters the id.
    """
    principal_key = f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"
    raw = f"{principal_key}:{tool}.{op}:{args_digest}"
    return _DEDUP_PREFIX + hashlib.sha256(raw.encode()).hexdigest()[:_ID_HEX_LEN]


#: Prefix of the intent id a held harness tool call is frozen under (#168). A third
#: id space, disjoint from the ts-based `intent-...` and the dedup ids.
_HARNESS_HOLD_PREFIX = "intent-harness-"
_HARNESS_ID_HEX_LEN = 32


def harness_hold_intent_id(principal: "Principal", op: str, input_digest: str) -> str:
    """The intent id a held harness tool call is frozen under, derived from its content.

    A harness's own call held at the reserved coordinate `harness-tool` is
    released by the harness asking again, and a hook runs as a fresh process
    each time, so the request carries no intent id and could not be trusted to.
    The broker finds the approval itself: the id is a function of the
    authenticated principal, the coordinate's op and the request's input digest,
    so the same call asked again names the same intent, read with one get by
    key on every store and never a scan. Two consequences, both deliberate. A
    repeat request while the hold is pending coalesces onto it, as approval-queue
    dedup does. Once that intent has resolved (permitted, refused, rejected,
    expired), a new hold of the same call reuses the id, and the records of each
    hold are told apart by their storedCallDigest.

    128 bits of SHA-256, so two different inputs of one principal do not share
    an id; the runtime still checks the stored call's coordinate and input
    digest against the request before it releases anything.
    """
    principal_key = f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"
    raw = f"{principal_key}:{HARNESS_TOOL}.{op}:{input_digest}"
    return _HARNESS_HOLD_PREFIX + hashlib.sha256(raw.encode()).hexdigest()[:_HARNESS_ID_HEX_LEN]


def is_flood(within_cap: bool) -> bool:
    """Pure predicate: did this hold push the per-op/day queue past its cap?

    `within_cap` is the boolean returned by the atomic counter increment
    (`try_increment_counter`): True while at/under the cap, False once the cap
    would be exceeded. A flood is simply the negation — the counter refused to
    grow further. Kept as a named predicate so the flood semantics live in one
    place and the PEP wiring reads intentionally. This NEVER decides to shed; it
    only decides whether to raise the alarm.
    """
    return not within_cap
