"""credentialed_mcp_server — a toy MCP server that genuinely REQUIRES a key (#251, #253).

Every other toy in this repo ignores its environment, which made a whole class of
claim unprovable. Two of them, specifically:

* **#253 (relocation).** A credential moved out of a harness config into the
  product wrapper's store is only relocated if it still ARRIVES. Against a
  server that ignores its environment, a wrap that delivered nothing would pass
  every assertion — the
  manifest would carry an `env_map`, the config would be clean, and the server
  would work exactly as well as if the whole mechanism were a no-op.
* **#298 (carried config).** The same hole one hop earlier: `McpServerDecl.env`
  was proven to the manifest and never to the child.

So this server does two things no other toy here does. It **refuses to start**
without its key — reproducing the real-world failure that makes most servers
unwrappable today — and it **reports a fingerprint** of the key it received, so
a test can prove the child got the RIGHT value rather than merely some value.

The fingerprint is a truncated SHA-256, never the key. A toy that echoed its
credential in a tool result would be a bad example in a repository whose subject
is credential handling, and the fingerprint proves identity just as well.

Run:  LEDGER_API_KEY=... python -m examples.credentialed_mcp_server.server
"""
from __future__ import annotations

import hashlib
import os
import sys

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

#: The variable a wrapped copy of this server must be given at spawn. Named
#: innocuously on purpose: the wrapper's classification prompt must not be
#: passable by a `*_KEY`/`*_TOKEN` name heuristic, which is exactly the shortcut
#: `configvalues.py` refuses to take.
API_KEY_VAR = "LEDGER_API_KEY"

_API_KEY = os.environ.get(API_KEY_VAR, "")
if not _API_KEY:
    # Fail at STARTUP, not at first call. This is what a real credentialed
    # server does, and it is why an unwrapped one fails during the wrapper's
    # snapshot step — before review, before admission. Exiting non-zero with a
    # legible reason is also what lets the wrapper report a useful diagnostic instead
    # of the SDK's "unhandled errors in a TaskGroup (1 sub-exception)".
    print(
        f"{API_KEY_VAR} is not set — refusing to start. This server requires a "
        "credential in its environment.",
        file=sys.stderr,
    )
    raise SystemExit(2)

mcp = FastMCP("ledger")

_ENTRIES: dict[str, dict[str, str]] = {
    "L-001": {"account": "cash", "memo": "opening balance", "amount": "1000.00"},
    "L-002": {"account": "supplies", "memo": "paper", "amount": "-42.00"},
}


def fingerprint(value: str) -> str:
    """A stable, non-reversing identifier for a credential value.

    Truncated to 12 hex characters: enough for a test to assert the child got
    the exact value the operator relocated, short enough to be obviously not a
    credential if it ever lands in a log or a terminal.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


class CredentialReport(BaseModel):
    """What the server can say about the credential it started with."""

    variable: str
    received: bool
    fingerprint: str


class LedgerEntry(BaseModel):
    entry_id: str
    account: str
    memo: str
    amount: str


@mcp.tool()
def whoami() -> CredentialReport:
    """Report which credential this server started with. Read-only; structured.

    Returns a FINGERPRINT, never the credential. Structured output so a consumer
    may legally trust it via `Envelope.trusted_read_sources` — free text could
    not be trusted, being injection surface (broker/MCP-HOST.md).
    """
    return CredentialReport(
        variable=API_KEY_VAR, received=True, fingerprint=fingerprint(_API_KEY)
    )


@mcp.tool()
def get_entry(entry_id: str) -> LedgerEntry:
    """Return one ledger entry by id. Read-only; structured output."""
    row = _ENTRIES.get(entry_id)
    if row is None:
        raise ValueError(f"no ledger entry {entry_id!r}")
    return LedgerEntry(entry_id=entry_id, **row)


if __name__ == "__main__":
    mcp.run()
