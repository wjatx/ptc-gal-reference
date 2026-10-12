"""InheritanceRecord -- one row of the taint inheritance ledger (PTC-51, #177).

When an op whose image-baked ``ToolOp`` declares ``causes_context`` is about to
run, the causing broker writes one of these BEFORE it calls the connector. The
record is keyed by the target principal. Every runtime reads the unexpired
records for its own principal when it mints a turn, and ingests the sources they
carry under a floor its trust map cannot lift. That is Biba's invocation
property in its low-water-mark form: a context the agent causes starts no
cleaner than the turn that caused it (``broker/TAINT.md``).

The record is a store row, not one of the seven base schemas. It carries no
hash or signature: like every other broker-written row, its integrity rests on
who may write the store. The agent holds no store credential, and on DynamoDB
the broker's write is confined to the ``INHERIT#`` key space by IAM. A record
grants nothing. IAM confines the key, not the operation: only broker code makes
the write create-only.

``taint`` is the causing call's own frozen ``Taint``, copied whole. A call
released from an approval hold carries the taint the hold froze, so a released
call writes the same record an inline call would: approval does not
declassify. Source ids are the originals; the record itself says where they
came from, so no lineage prefix is added.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .brokered_call import Taint
from .common import Principal


def parse_aware_instant(value: str) -> datetime:
    """Parse an ISO-8601 instant that states its offset, or refuse.

    A naive instant compares differently under two brokers' local zones, so a
    record's lifetime would depend on which broker read it. ``Z`` is accepted.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{value!r} states no UTC offset")
    return parsed


class InheritanceRecord(BaseModel):
    """One inheritance row: the causing turn's taint, owed to a target principal."""

    model_config = ConfigDict(extra="forbid")

    # Broker-minted id, unique per record. Several records for one target coexist.
    id: str
    # The principal whose turns inherit: the causing principal itself for a
    # "self" declaration, else the declared child. Never read from a call.
    target: Principal
    # Who caused the context, and in which turn.
    causingPrincipal: Principal
    causingTurnId: str
    # The causing call's frozen taint, whole. Sources keep their original ids.
    taint: Taint
    # The op coordinate that caused the context.
    tool: str
    op: str
    # When the causing broker wrote the record, and the instant after which it
    # no longer taints anything. Both ISO-8601 with an offset; notAfter is later.
    issuedAt: str
    notAfter: str

    @field_validator("issuedAt", "notAfter")
    @classmethod
    def _instants_state_an_offset(cls, value: str) -> str:
        parse_aware_instant(value)
        return value

    @model_validator(mode="after")
    def _not_after_follows_issued_at(self) -> "InheritanceRecord":
        """A record born expired would never taint anything; refuse it at write.

        The write refusing means the cause op does not run, which is the
        direction toward less authority.
        """
        if parse_aware_instant(self.notAfter) <= parse_aware_instant(self.issuedAt):
            raise ValueError(
                f"notAfter {self.notAfter} is not after issuedAt {self.issuedAt}; "
                "an inheritance record must be live when it is written"
            )
        return self

    def live_at(self, now: datetime) -> bool:
        """True while ``now`` is before ``notAfter``. Expiry is a predicate at use."""
        return now < parse_aware_instant(self.notAfter)
