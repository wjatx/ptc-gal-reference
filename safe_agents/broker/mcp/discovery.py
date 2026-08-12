"""discovery.py — the connect-time two-key admission gate as a PURE function (#174).

Discovery is untrusted input: an MCP server names its own tools and can change
any of them between connections (MCP-HOST.md). This module decides, for every
tool the server currently advertises, whether the agent may call it — and it
does so as a pure function of three inputs, with NO I/O, NO clock, and NO writes:

  1. `manifest_decl`   — the image-baked namespace (`AgentManifest.mcp_servers`),
                          key #1 of the two-key admission.
  2. `registry_reads`  — the store rows a human admitted + their integrity flags,
                          key #2, ALREADY READ by the caller (the store is the
                          registry's only reader; this evaluator never touches it).
  3. `advertised`      — the live `McpToolDef` list the server just returned.

Per-tool verdict (MCP-HOST.md lifecycle + conformance M2–M6):

  * ACTIVE       declared + admitted row + row not quarantined + live hash ==
                 admitted `def_hash`  -> CALLABLE (still per-call PDP-gated).
  * DECLARED     declared but no admitted row yet -> uncallable, NO finding
                 (a normal not-yet-admitted state, not drift).
  * DRIFTED      declared + admitted, live hash != admitted hash (M2: a
                 description-only change counts) -> uncallable + finding.
  * UNLISTED     advertised but the manifest never declared it (M3/M4: a store
                 row cannot mint it) -> uncallable + finding.
  * QUARANTINED  the store served the row quarantined — an HMAC-integrity failure
                 or a QUARANTINED status (M6/M13) -> uncallable + finding.
  * WITHDRAWN    an admitted tool the server STOPPED advertising -> uncallable +
                 finding (absence is drift of the admitted set).
  * DUPLICATE    the SAME `(server_id, tool_name)` advertised more than once in
                 one response -> uncallable regardless of any hash match + finding.
                 Duplication is itself the attack signature: a compromised server
                 could otherwise advertise one byte-identical entry (-> ACTIVE) and
                 one poisoned entry (-> DRIFTED), leaving the tool callable while a
                 drifted definition is live and reducing M2's fail-closed refusal to
                 a log line. A well-behaved server never duplicates, so we fail closed
                 BEFORE per-entry classification.

Drift quarantine is COMPUTED here, never written — the admission ceremony is the
registry's only writer (MCP-HOST.md). The findings are a per-pass snapshot the
host caches for the session; the caller logs each ERROR once (M5).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict

from safe_agents.broker.schemas.mcp_registry import (
    McpServerDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)


class ToolState(str, Enum):
    """The computed per-tool verdict. Only ACTIVE is callable; the five surfaced
    states (DRIFTED/UNLISTED/QUARANTINED/WITHDRAWN/DUPLICATE) each raise exactly one
    finding. DECLARED is uncallable but unremarkable (not yet admitted)."""

    ACTIVE = "active"
    DECLARED = "declared"
    DRIFTED = "drifted"
    UNLISTED = "unlisted"
    QUARANTINED = "quarantined"
    WITHDRAWN = "withdrawn"
    DUPLICATE = "duplicate"


# States that fail closed AND deserve a loud, distinctive surface (M5). DECLARED
# is uncallable but silent; ACTIVE is callable.
_SURFACED_STATES: frozenset[ToolState] = frozenset(
    {
        ToolState.DRIFTED,
        ToolState.UNLISTED,
        ToolState.QUARANTINED,
        ToolState.WITHDRAWN,
        ToolState.DUPLICATE,
    }
)


class RegistryRead(BaseModel):
    """One store read for a `(server_id, tool_name)`, as the caller obtained it.

    `row` is the admitted registry row (None if no row exists yet).
    `hmac_quarantined` mirrors `GrantReadResult.quarantined`: the store sets it
    when the row's stored HMAC did not verify (M13) — the row is still returned
    for audit but is NEVER authoritative. A row whose `status` is QUARANTINED is
    treated identically. The evaluator does NOT read the store; the caller passes
    these in (registry.py owns the store binding).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    row: Optional[RegisteredTool] = None
    hmac_quarantined: bool = False


class ToolVerdict(BaseModel):
    """The per-tool result of a discovery pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str
    tool_name: str
    state: ToolState
    is_callable: bool
    live_hash: Optional[str] = None  # sha256 of the advertised def (when computed)
    admitted_hash: Optional[str] = None  # the hash a human admitted (when a row exists)
    detail: Optional[str] = None


class DiscoveryFinding(BaseModel):
    """One distinctive, structured surface for a failed-closed tool (M5).

    Exactly one per `(server_id, tool_name)` per pass — the evaluator visits each
    coordinate once. `reason` is the surfaced `ToolState`; the caller logs one
    ERROR per finding (no per-call flood — findings are a cached snapshot).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str
    tool_name: str
    reason: ToolState
    detail: str


class DiscoveryResult(BaseModel):
    """The snapshot the host caches for the session: every tool's verdict, the
    surfaced findings, and the callable set (the only tools the agent may call)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdicts: list[ToolVerdict]
    findings: list[DiscoveryFinding]
    callable_tools: frozenset[tuple[str, str]]

    def is_callable(self, server_id: str, tool_name: str) -> bool:
        return (server_id, tool_name) in self.callable_tools


def _classify_advertised(
    tool_def: McpToolDef,
    server_decl: Optional[McpServerDecl],
    read: Optional[RegistryRead],
) -> ToolVerdict:
    """Verdict for ONE advertised tool. Pure; no I/O."""
    server_id, tool_name = tool_def.server_id, tool_def.tool_name

    declared = server_decl is not None and any(
        t.tool_name == tool_name for t in server_decl.tools
    )
    if not declared:
        # M3/M4: undeclared in the image-baked manifest — a store row can never
        # mint it, so it is uncallable even if `read` names it.
        return ToolVerdict(
            server_id=server_id,
            tool_name=tool_name,
            state=ToolState.UNLISTED,
            is_callable=False,
            detail="advertised tool is not declared in AgentManifest.mcp_servers",
        )

    if read is not None and (
        read.hmac_quarantined
        or (read.row is not None and read.row.status is RegistryStatus.QUARANTINED)
    ):
        # M13/M6: a row the store served quarantined is never authoritative.
        # Checked BEFORE row-presence: since #246 an HMAC-quarantined read
        # carries row=None (tampered bytes are never parsed), and it must still
        # surface as QUARANTINED, never blur into DECLARED.
        return ToolVerdict(
            server_id=server_id,
            tool_name=tool_name,
            state=ToolState.QUARANTINED,
            is_callable=False,
            admitted_hash=read.row.def_hash if read.row is not None else None,
            detail="registry row is quarantined (integrity failure or quarantined status)",
        )

    if read is None or read.row is None:
        # Declared but never admitted — uncallable, but not drift (no finding).
        return ToolVerdict(
            server_id=server_id,
            tool_name=tool_name,
            state=ToolState.DECLARED,
            is_callable=False,
            detail="declared but no admitted registry row",
        )

    row = read.row

    live_hash = compute_tool_def_hash(tool_def)
    if live_hash != row.def_hash:
        # M2: any of the four signed fields changed — including description alone.
        return ToolVerdict(
            server_id=server_id,
            tool_name=tool_name,
            state=ToolState.DRIFTED,
            is_callable=False,
            live_hash=live_hash,
            admitted_hash=row.def_hash,
            detail="live definition hash differs from the admitted hash (drift)",
        )

    return ToolVerdict(
        server_id=server_id,
        tool_name=tool_name,
        state=ToolState.ACTIVE,
        is_callable=True,
        live_hash=live_hash,
        admitted_hash=row.def_hash,
    )


def evaluate_discovery(
    manifest_decl: dict[str, McpServerDecl],
    registry_reads: dict[tuple[str, str], RegistryRead],
    advertised: list[McpToolDef],
) -> DiscoveryResult:
    """Compute every advertised tool's verdict + the drift-of-the-set findings.

    Two disjoint passes, so each `(server_id, tool_name)` is visited exactly once
    and no finding is ever duplicated (M5):

      1. every advertised coordinate    -> DUPLICATE (advertised more than once)
                                           / ACTIVE / DECLARED / DRIFTED /
                                           UNLISTED / QUARANTINED
      2. every admitted row NOT in the advertised set -> WITHDRAWN (or a still-
         surfaced QUARANTINED, if that row was already quarantined)

    Duplicate detection precedes per-entry classification: a coordinate the server
    advertises more than once is UNCALLABLE regardless of any hash match, so a
    compromised server cannot pair a byte-identical entry (which would classify
    ACTIVE) with a poisoned one (DRIFTED) to keep the tool callable while a drifted
    definition is live. Duplication itself is the attack signature — fail closed.
    """
    verdicts: list[ToolVerdict] = []
    findings: list[DiscoveryFinding] = []
    callable_tools: set[tuple[str, str]] = set()

    # Coordinates advertised more than once in this one response — the duplicate
    # attack surface. A well-behaved server never duplicates a (server_id,
    # tool_name), so any repeat fails closed before classification.
    seen_counts: dict[tuple[str, str], int] = {}
    for d in advertised:
        k = (d.server_id, d.tool_name)
        seen_counts[k] = seen_counts.get(k, 0) + 1
    duplicate_keys = {k for k, n in seen_counts.items() if n > 1}
    advertised_keys = set(seen_counts)

    # Pass 1 — the live advertised set. One verdict + one finding per coordinate.
    emitted: set[tuple[str, str]] = set()
    for tool_def in advertised:
        key = (tool_def.server_id, tool_def.tool_name)

        if key in duplicate_keys:
            # Uncallable regardless of hash match; surface exactly once per
            # coordinate even though the entry appears multiple times.
            if key in emitted:
                continue
            emitted.add(key)
            verdicts.append(
                ToolVerdict(
                    server_id=tool_def.server_id,
                    tool_name=tool_def.tool_name,
                    state=ToolState.DUPLICATE,
                    is_callable=False,
                    detail="advertised more than once in one discovery response; "
                    "uncallable regardless of any hash match",
                )
            )
            findings.append(
                DiscoveryFinding(
                    server_id=tool_def.server_id,
                    tool_name=tool_def.tool_name,
                    reason=ToolState.DUPLICATE,
                    detail="advertised more than once in one discovery response; "
                    "uncallable regardless of any hash match",
                )
            )
            continue

        verdict = _classify_advertised(
            tool_def, manifest_decl.get(tool_def.server_id), registry_reads.get(key)
        )
        verdicts.append(verdict)
        if verdict.is_callable:
            callable_tools.add(key)
        elif verdict.state in _SURFACED_STATES:
            findings.append(
                DiscoveryFinding(
                    server_id=verdict.server_id,
                    tool_name=verdict.tool_name,
                    reason=verdict.state,
                    detail=verdict.detail or verdict.state.value,
                )
            )

    # Pass 2 — admitted rows the server stopped advertising (absence is drift).
    # An HMAC-quarantined read carries row=None since #246, so quarantine keeps
    # a coordinate in this pass — only a genuinely-absent, unquarantined read
    # is skipped.
    for (server_id, tool_name), read in registry_reads.items():
        if (server_id, tool_name) in advertised_keys:
            continue
        if read.row is None and not read.hmac_quarantined:
            continue
        quarantined = read.hmac_quarantined or (
            read.row is not None and read.row.status is RegistryStatus.QUARANTINED
        )
        state = ToolState.QUARANTINED if quarantined else ToolState.WITHDRAWN
        detail = (
            "registry row is quarantined and no longer advertised"
            if quarantined
            else "admitted tool is no longer advertised by the server"
        )
        verdicts.append(
            ToolVerdict(
                server_id=server_id,
                tool_name=tool_name,
                state=state,
                is_callable=False,
                admitted_hash=read.row.def_hash if read.row is not None else None,
                detail=detail,
            )
        )
        findings.append(
            DiscoveryFinding(
                server_id=server_id, tool_name=tool_name, reason=state, detail=detail
            )
        )

    return DiscoveryResult(
        verdicts=verdicts,
        findings=findings,
        callable_tools=frozenset(callable_tools),
    )
