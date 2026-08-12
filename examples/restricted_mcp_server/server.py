"""restricted_mcp_server — the missileer archetype for MCP hosts (#174).

A deliberately small MCP server: a read-only ledger surface exposing EXACTLY two
tools, `get_entry` and `list_entries`. There is no append, no delete, no admin
tool — the dangerous op is ABSENT, not merely denied. Restrict-by-construction:
the strongest control on a high-blast surface is a smaller server, not a tighter
gate (broker/MCP-HOST.md §"Restrict-by-construction — the missileer archetype").

The two tools it DOES expose return STRUCTURED data (typed models, not free
text), so a consumer may legally trust one via Envelope.trusted_read_sources — a
free-text tool could not be trusted, that being injection surface. They are still
declared, admitted, hashed, and taint-tracked like any other MCP tool; absence
removes a capability from existence, the registry governs the ones that remain.

Run:  python -m examples.restricted_mcp_server.server   (stdio transport)
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

mcp = FastMCP("ledger")

# A tiny in-memory, read-only ledger. Illustrative only — a real deployment would
# back get/list with a genuine read-only store. The point is the SHAPE of the
# surface (what tools exist), not the data behind it.
_ENTRIES: dict[str, dict[str, str]] = {
    "L-001": {"account": "cash", "memo": "opening balance", "amount": "1000.00"},
    "L-002": {"account": "supplies", "memo": "paper", "amount": "-42.00"},
    "L-003": {"account": "cash", "memo": "invoice #7", "amount": "500.00"},
}


class LedgerEntry(BaseModel):
    """One structured ledger row — typed, schema-bounded output (not free text)."""

    entry_id: str
    account: str
    memo: str
    amount: str


class LedgerPage(BaseModel):
    """A bounded page of entry ids — structured output for list_entries."""

    entry_ids: list[str]
    total: int


@mcp.tool()
def get_entry(entry_id: str) -> LedgerEntry:
    """Return one ledger entry by id. Read-only; structured output."""
    row = _ENTRIES.get(entry_id)
    if row is None:
        raise ValueError(f"no ledger entry {entry_id!r}")
    return LedgerEntry(entry_id=entry_id, **row)


@mcp.tool()
def list_entries(limit: int) -> LedgerPage:
    """Return up to `limit` ledger entry ids (oldest first). Read-only; structured."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    ids = sorted(_ENTRIES)[:limit]
    return LedgerPage(entry_ids=ids, total=len(_ENTRIES))


# There is deliberately NO append_entry, NO delete_entry, NO post_adjustment, NO
# admin tool. Those capabilities are ABSENT from this server, so there is nothing
# for the broker to admit, quarantine, or deny — the missileer has no launch key
# on the console. Adding one here is a code-reviewed change to the server itself,
# not something a compromised agent or a swapped store row can reach. See
# broker/MCP-HOST.md §"Restrict-by-construction — the missileer archetype".

if __name__ == "__main__":
    mcp.run()
