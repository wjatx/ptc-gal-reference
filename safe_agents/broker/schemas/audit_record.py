"""AuditRecord schema — hash-chained, broker-emitted, append-only, external.

The writing role cannot delete it. Every decision is logged. Any later edit or deletion
breaks the chain; any gap in seq shows. See SCHEMAS.md §5 and broker/README.md §"Audit".
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from .common import Principal


class AuditRecord(BaseModel):
    """Hash-chained audit record emitted by the broker at the moment of each side effect.

    Invariants:
    - seq is int (monotonic — gaps are detectable; intent is documented here, enforcement
      is the responsibility of the storage layer).
    - argsDigest is a hash string, never raw args (PII discipline).
    - prevHash chains to the previous record; hash covers this record including prevHash.
    """

    model_config = ConfigDict(extra="forbid")

    # monotonic sequence number — a gap is detectable
    seq: int
    ts: str
    principal: Principal
    tool: str
    op: str
    # HASH of args, not raw args (PII discipline — the audit must not become a PII store)
    argsDigest: str
    # which of the five verbs was returned
    decision: Literal["allow", "deny", "transform", "require_approval", "abstain"]
    reason: str | None = None
    # the exact envelope in force when this was decided — ties the record to its authority
    envelopeHash: str
    # the authenticated human identity, for approved intents; copied from Intent.approvedBy
    approvedBy: str | None = None
    # held = intent awaiting approval; executed/denied/refused/failed are terminal.
    #
    # `refused` is the #281 member: a control REFUSED the call after the PDP
    # decided — two-key MCP admission is the first — so nothing was attempted.
    # It is distinct from `denied` (the PDP itself said no, before execution was
    # ever reached) and from `failed` (the execution step broke: the effect was
    # attempted, or its credential could not be resolved, #35 -- `error` says which).
    # Without it a two-key refusal is shape-identical to a network blip, and
    # anything counting refusals counts none of them.
    outcome: Literal["executed", "denied", "held", "refused", "failed"]
    error: str | None = None
    # committed randomization seed, where allocation was randomized (auditable randomness);
    # allows "why not engage that one?" to have a reconstructable answer in the log
    seed: str | None = None
    # #198 gap A: stamped on the hold record and its approve-release records; joins a
    # hold to its release across the intent TTL. None == pre-receipts record or a
    # non-approval decision.
    intentId: str | None = None
    # #198 gap A: digest of the frozen Intent.materializedRequest (the full BrokeredCall,
    # canonical JSON). Stamped at hold time from the call being frozen and INDEPENDENTLY
    # recomputed at release time from the stored bytes — equal digests make
    # executed==approved byte-provable from durable state alone.
    storedCallDigest: str | None = None
    # #198 gap B: broker-written digest of the connector's opaque response (the effect
    # receipt). Digest only, never raw content (PII discipline, the argsDigest precedent).
    resultDigest: str | None = None
    # chains to the previous record (hash-chain integrity)
    prevHash: str
    # hash over this record including prevHash — any later edit is detectable
    hash: str
