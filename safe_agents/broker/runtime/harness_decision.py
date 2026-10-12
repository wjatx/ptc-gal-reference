"""harness_decision.py: the closed answer to a harness's own tool call, decided before it runs.

A harness's hook can ask the broker before the harness runs one of its own
tools (`broker/GATEWAY.md`, the decision mouth). The broker decides the call at
the reserved coordinate `harness-tool`, op `<tool_class>/<locality>`, and
answers with exactly one of two words: `permit` or `refuse`. This module holds
that answer, the fixed mapping from the PDP's five verbs to it, and the text a
refused call carries back to the model.

Every string a model can read here is base-owned. The text is one of two fixed
sentences, chosen by whether the call was held, followed by the broker's own
reason. Nothing in the request and nothing in the manifest can supply or alter
it. It never names the command that releases a hold.

Standard library only, so a mouth can import it without the runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from safe_agents.broker.schemas.harness_tool import HARNESS_TOOL

#: The two answers. A mouth answers with one of these and nothing else.
PERMIT = "permit"
REFUSE = "refuse"
Answer = Literal["permit", "refuse"]

#: The sentence a refused call carries back to the model (ruling (d), verbatim).
REFUSED_SENTENCE = (
    "Refused by policy. Do not attempt the same action another way. Tell the user "
    "what was refused, and continue with any part of the task this does not affect."
)

#: The sentence a held call carries back (ruling (d), verbatim). `{intent_id}` is
#: the only slot, filled with the broker-minted intent id.
HELD_SENTENCE = (
    "Held for approval by policy (intent {intent_id}). Do not attempt the same "
    "action another way. Tell the user it is waiting for approval; if it is "
    "approved, the same call will be allowed once."
)

#: Reasons the runtime writes on a harness decision, every one of them fixed.
#: The PDP's own reasons (a rule's reason, `no manifest entry for ...`) ride as
#: the PDP wrote them.
FAULT_REASON = "the broker could not decide this call; refused"
MALFORMED_REASON = "malformed decision request; refused"


def permitted_reason(op: str, *, intent_id: str | None = None) -> str:
    """The reason on a permitted record: the coordinate, as the manifest declared it.

    A reader sees a declaration, not an observation: the broker allowed a call at
    a coordinate whose facts the consumer declared, and the harness performs it.
    """
    coordinate = f"{HARNESS_TOOL}.{op}"
    if intent_id is None:
        return f"permitted at {coordinate} as declared by the manifest; performed by the harness"
    return (
        f"permitted once at {coordinate} on the approval of intent {intent_id}, "
        "as declared by the manifest; performed by the harness"
    )


def transform_reason(op: str) -> str:
    """The reason on a transform at the reserved coordinate: a configuration error."""
    return (
        f"configuration error: the PDP returned transform at {HARNESS_TOOL}.{op}, and "
        "the broker holds no safer op for a harness tool; refused"
    )


#: The causes a mouth may name when it refuses a decision request it could not
#: parse. A closed set: the runtime refuses any other code.
DECISION_REFUSAL_CAUSES = frozenset({"bad-method", "too-large", "bad-body", "bad-field"})


class TextKind(str, Enum):
    """Which of the two fixed sentences a refusal carries."""

    REFUSED = "refused"
    HELD = "held"


def refusal_text(kind: TextKind, *, reason: str, intent_id: str | None) -> str:
    """The model-facing text for a refusal: one fixed sentence, then the broker's reason.

    `reason` is the broker's (the PDP's, or one of the fixed reasons above) and
    `intent_id` is broker-minted. Nothing else reaches the text.
    """
    if kind is TextKind.HELD:
        if intent_id is None:
            raise ValueError("a held refusal carries the intent id it was held under")
        sentence = HELD_SENTENCE.format(intent_id=intent_id)
    else:
        sentence = REFUSED_SENTENCE
    return f"{sentence} Reason: {reason}"


@dataclass(frozen=True)
class HarnessDecision:
    """The broker's answer to one decision request.

    `answer` is `permit` or `refuse`. `decision_kind` is the PDP verb the
    runtime mapped from, or None when no decision was reached (a malformed
    request, a fault). `outcome` is the outcome of the record the decision
    wrote, or None when no record was written. `intent_id` is set on a hold.
    """

    answer: Answer
    reason: str
    intent_id: str | None = None
    decision_kind: str | None = None
    outcome: str | None = None

    def __post_init__(self) -> None:
        if self.answer not in (PERMIT, REFUSE):
            raise ValueError(f"answer must be {PERMIT!r} or {REFUSE!r}, got {self.answer!r}")
        if self.answer == PERMIT and self.decision_kind != "allow":
            raise ValueError("only an allow permits")

    @property
    def held(self) -> bool:
        return self.answer == REFUSE and self.intent_id is not None

    @property
    def text(self) -> str | None:
        """The model-facing text: None on a permit, a fixed sentence plus reason otherwise."""
        if self.answer == PERMIT:
            return None
        kind = TextKind.HELD if self.held else TextKind.REFUSED
        return refusal_text(kind, reason=self.reason, intent_id=self.intent_id)


def refused(reason: str, *, decision_kind: str | None = None, outcome: str | None = None,
            intent_id: str | None = None) -> HarnessDecision:
    """A refusal. Every path that cannot permit builds its answer here."""
    return HarnessDecision(
        answer=REFUSE,
        reason=reason,
        intent_id=intent_id,
        decision_kind=decision_kind,
        outcome=outcome,
    )


#: The fixed mapping from the PDP's five verbs to an answer. Only allow permits.
#: The runtime reads it; no mouth and no request can vary it.
VERB_ANSWER: dict[str, Answer] = {
    "allow": PERMIT,
    "deny": REFUSE,
    "abstain": REFUSE,
    "require_approval": REFUSE,
    "transform": REFUSE,
}
