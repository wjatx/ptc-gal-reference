"""MCP tool-admission ceremony (#174) — the registry's only sanctioned writer.

    python -m safe_agents.broker.mcp.commands {admit-propose,admit-ratify} ...

admit-propose  the maker: hashes the EXACT advertised McpToolDef the operator
               names, and stores a single-shot expiring proposal binding the full
               definition + its def_hash. Nothing is admitted yet. The definition
               comes from EXACTLY ONE of --tool-def-json (hand-authored JSON,
               the pre-#221-Phase-5 path) or --from-snapshot (a `snapshot`
               artifact — #221 Phase 5 item 4: deletes "Step 0" of re-vetting,
               hand-writing a byte-exact McpToolDef). Either way, the currently
               stored row (if any) is rendered against the proposed definition
               via `mcp/render.py` BEFORE the proposal is written — the review
               surface a maker actually reads, never a retyped schema.
admit-ratify   the checker: loads the integrity-verified proposal, enforces
               maker != checker (STS credential ARNs), expiry and single-shot,
               then appends the issuer-DSSE-signed admission record and writes the
               ACTIVE row at the admitted def_hash. A re-vet after drift is the
               SAME ceremony run against the NEW advertised definition.
admit-reject   the checker declines (#236): burns a pending proposal as
               'rejected', so a bad proposal has an exit other than expiry —
               "it expired" and "a checker said no" are different facts, and
               only one is evidence. Narrowing-only, so NOT maker != checker
               gated and unsigned (it writes no row and no ledger record).
snapshot       PURE discovery, pre-admission: capture a NAMED server's full live
               advertised tool set to a file (#221 Phase 5 prerequisite). Touches
               no registry (no read, no write) and needs neither the HMAC key nor
               a registry table — server config comes from an operator-named
               image-baked AgentManifest, never a store. The artifact feeds
               `show`/`diff` and `admit-propose --from-snapshot` (both later
               items) and is the mechanical core of the #231 vendor intake probe.
show           READ-ONLY: print one stored registry row, human-readable. Reads
               the registry the same way admit-ratify does (NAMED HMAC key +
               table, #205); writes nothing.
diff           READ-ONLY: compare a `snapshot` artifact against the stored rows
               for that snapshot's server_id (taken from the artifact itself,
               never a flag) and render NEW/WITHDRAWN/unchanged/DRIFT per tool
               (`mcp/render.py` — the actual deliverable; classification stays
               here only as coordination). The registry store exposes no
               server-wide listing (no role grants `dynamodb:Scan`, and the
               partition key embeds `server_id` so `Query` can't substitute
               either), so the tool-name universe to check comes from
               `--manifest`'s declared namespace (same image-baked source
               `snapshot` uses) unioned with the live snapshot's own names —
               a row orphaned by a later manifest dropping its tool is a known,
               accepted display gap (see `diff_command`'s docstring), not a
               safety gap: two-key admission already makes it uncallable.
               Drift is COMPUTED here exactly as it is at broker read time
               (`registry.py:13-16`) — `diff` writes no row, no record, no
               quarantine, ever. It is an inspection tool, not a gate: exit 0
               whenever it ran, regardless of what it found.

This MIRRORS grants/commands.py: identity is DERIVED from STS GetCallerIdentity
(no --as; maker != checker compares actual credential identities, so
self-admission is structurally impossible — M7), the ceremony refuses toward
writing nothing, and the record is written BEFORE the row (a record-without-row
outcome holds LESS authority — the tool is uncallable — never more).

Signing is required, not optional: an admission mints callability, which is
authority, so — like the grant `acknowledge` ceremony — a missing issuer key
REFUSES rather than degrading to an unsigned record (M8). A half-configured
issuer key (key_id without the ARN, or vice versa) also refuses, surfaced by
issuer_keys.resolve_record_signer (the #201 refuse-on-half-configured discipline).

Store construction is PER-COMMAND (not a shared `main()` prelude): `snapshot` is
pre-admission discovery and must work before any registry row — or even a
registry table — exists, so it builds no store at all. `admit-propose`/
`admit-ratify` keep byte-for-byte their pre-existing refuse-hard behavior
(missing `BROKER_HMAC_KEY`/table name -> exit 2).
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from safe_agents.broker.grants.issuer_keys import (
    IssuerSigningConfigError,
    resolve_record_signer,
)
from safe_agents.broker.grants.proposals import proposal_expired
from safe_agents.broker.grants.record_signing import RecordSigner
from safe_agents.broker.mcp.client import connect_stdio, connect_streamable_http
from safe_agents.broker.mcp.proposals import (
    CEREMONY_KINDS,
    KIND_ADMISSION,
    KIND_REVET,
    AdmissionProposalStore,
    DynamoAdmissionProposalStore,
    McpAdmissionProposal,
    ProposalConsumedError,
    ProposalIntegrityError,
)
from safe_agents.broker.mcp.registry import (
    DynamoToolRegistry,
    QuarantinedToolRowError,
    RecordAlreadyExistsError,
    ToolReadResult,
    ToolRegistryStore,
    ToolRowConflictError,
)
from safe_agents.broker.mcp.render import (
    VERBATIM_METADATA_FIELDS,
    DriftKind,
    ToolDiffResult,
    render_diff_summary,
    render_registered_tool,
    render_tool_diff,
)
from safe_agents.broker.mcp.signing import (
    McpAdmissionRecord,
    sign_admission_record,
)
from safe_agents.broker.mcp.sqlite_stores import (
    SqliteAdmissionProposalStore,
    SqliteToolRegistry,
)
from safe_agents.broker.ceremony_identity import (
    SOLO_ATTESTATION_NOTICE,
    attestation_for,
    is_local_identity,
    is_same_operator,
    resolve_ceremony_identity,
)
from safe_agents.broker.prototype.boot_config import (
    BrokerConfigError,
    load_agent_manifest,
    resolve_secrets_arm,
    resolve_secrets_dir,
    resolve_secrets_file,
    resolve_sqlite_db_path,
    sqlite_grants_open_options,
    resolve_store_arm,
)
from safe_agents.broker.prototype.mcp_construction import (
    compose_child_env,
    compose_headers,
)
from safe_agents.broker.runtime.credentials import StaticSecret, build_credential_strategies
from safe_agents.broker.runtime.secrets import (
    DirSecretsProvider,
    FakeSecretsProvider,
    LazyBotoSecretsProvider,
    LocalFileSecretsProvider,
    SecretsProvider,
)
from safe_agents.broker.schemas import AgentManifest, McpServerDecl
from safe_agents.broker.schemas.mcp_registry import (
    McpServerSnapshot,
    McpSnapshotEntry,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)


def _caller_identity(session: object = None) -> str:
    """This ceremony's operator identity — the STS Arn, or the local arm (#226).

    A thin delegate to the ONE resolver in ``broker.ceremony_identity``, shared
    with the grant ceremony: extending only one copy would silently leave the
    other ceremony without the local arm. Monkeypatched in tests (no real STS).
    """
    return resolve_ceremony_identity(session)


def _utc_now(now: datetime.datetime | None) -> datetime.datetime:
    return now or datetime.datetime.now(datetime.UTC)


# ---------------------------------------------------------------------------
# admit-propose — the maker
# ---------------------------------------------------------------------------


def _resolve_tool_def_from_snapshot(
    args: argparse.Namespace,
) -> tuple[McpToolDef | None, str | None]:
    """Resolve the McpToolDef for (--server-id, --tool-name) from a `snapshot`
    artifact (#221 Phase 5 item 4) — the alternative to hand-authoring one.

    Returns (tool_def, None) on success or (None, message) on refusal. Every
    refusal here is an artifact-integrity problem, never a runtime one, so the
    caller maps it to exit 2 (mirrors `snapshot`/`diff`'s own refuse-clean
    convention): the snapshot file is malformed, its `server_id` does not
    match `--server-id` (a mismatched artifact is an operator error worth
    catching loudly, not silently reinterpreting), the named tool is absent
    from it, or its recorded `def_hash` fails to recompute — a hand-edited or
    corrupted snapshot, which defeats the entire point of this path (nobody
    should be hand-writing definitions).
    """
    try:
        snapshot = McpServerSnapshot.model_validate_json(Path(args.from_snapshot).read_text())
    except (OSError, ValidationError) as exc:
        return None, f"REFUSED: --from-snapshot {args.from_snapshot} is unusable: {exc}"

    if snapshot.server_id != args.server_id:
        return None, (
            f"REFUSED: --from-snapshot {args.from_snapshot} was captured for "
            f"server_id {snapshot.server_id!r} but the ceremony targets "
            f"{args.server_id!r} — a mismatched snapshot artifact is refused, "
            "never silently reinterpreted"
        )

    entry = next(
        (e for e in snapshot.entries if e.tool_def.tool_name == args.tool_name), None
    )
    if entry is None:
        available = sorted(e.tool_def.tool_name for e in snapshot.entries)
        return None, (
            f"REFUSED: --from-snapshot {args.from_snapshot} has no tool "
            f"{args.tool_name!r} for server {args.server_id!r} (captured: {available})"
        )

    recomputed = compute_tool_def_hash(entry.tool_def)
    if recomputed != entry.def_hash:
        return None, (
            f"REFUSED: --from-snapshot {args.from_snapshot} entry for "
            f"{args.server_id}/{args.tool_name} fails its own integrity check "
            f"(recorded def_hash={entry.def_hash} recomputed={recomputed}) — a "
            "hand-edited or corrupted snapshot, OR a snapshot captured under an "
            "older signed-set basis (#223 widened it); either way, re-snapshot "
            "the live server — the whole point of --from-snapshot is that "
            "nobody hand-writes definitions"
        )

    return entry.tool_def, None


def _active_row_from_proposal(
    proposal: McpAdmissionProposal, caller: str, ts: str
) -> RegisteredTool:
    """Build the ACTIVE row a ratification writes, from the proposal's bound
    definition. The row pins what was ratified STRUCTURALLY since #246: the
    proposal's `tool_def` is nested whole — no per-field carry to drift — and
    both ceremony paths (single and bulk) share this one constructor."""
    return RegisteredTool(
        tool_def=proposal.tool_def,
        def_hash=proposal.def_hash,
        status=RegistryStatus.ACTIVE,
        admitted_by=caller,
        admitted_at=ts,
    )


def _render_propose_preview(
    server_id: str, tool_name: str, stored: RegisteredTool | None, tool_def: McpToolDef
) -> str:
    """The review surface printed before a proposal is written: admitted (if
    any) vs. proposed, reusing `mcp/render.py`'s classification/rendering
    (NEW/DRIFT/UNCHANGED) — never a second renderer. Shown for BOTH
    `--from-snapshot` and `--tool-def-json`; the value is in reviewing, not
    in the source format.

    `render_tool_diff`'s NEW branch (no stored row) omits the schema/
    description text — reasonable for `diff`, where the point is drift, but
    a maker approving a FIRST admission still needs to see exactly what they
    are about to propose, so that case additionally prints it verbatim.
    """
    live_entry = McpSnapshotEntry(
        tool_def=tool_def, def_hash=compute_tool_def_hash(tool_def)
    )
    result = render_tool_diff(tool_name, stored, live_entry)
    lines = [result.rendered]
    if stored is None:
        lines += [
            "  --- proposed definition (verbatim; no prior admission to compare against) ---",
            f"  input_schema: {tool_def.input_schema!r}",
            "  description:",
            tool_def.description,
        ]
    return "\n".join(lines)


def admit_propose_command(
    args: argparse.Namespace,
    *,
    store: ToolRegistryStore,
    proposal_store: AdmissionProposalStore,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Store a single-shot expiring proposal binding the exact advertised def.

    The definition comes from exactly one of --tool-def-json (hand-authored
    McpToolDef JSON) or --from-snapshot (a `snapshot` artifact, #221 Phase 5
    item 4); argparse enforces the mutual exclusion. Either way its
    server_id/tool_name must match the named coordinate (a mismatch is
    refused, never guessed). The def_hash is computed here — the checker
    ratifies exactly these bytes. Before the proposal is written, the
    currently stored row (if any) is rendered against the proposed
    definition — the review surface (`_render_propose_preview`).
    """
    if args.kind not in CEREMONY_KINDS:
        print(f"REFUSED: --kind must be one of {list(CEREMONY_KINDS)}, got {args.kind!r}")
        return 1

    if args.from_snapshot is not None:
        tool_def, refusal = _resolve_tool_def_from_snapshot(args)
        if refusal is not None:
            print(refusal)
            return 2
    else:
        try:
            tool_def = McpToolDef.model_validate_json(Path(args.tool_def_json).read_text())
        except (OSError, ValidationError) as exc:
            print(f"REFUSED: --tool-def-json {args.tool_def_json} is unusable: {exc}")
            return 1

    if tool_def.server_id != args.server_id or tool_def.tool_name != args.tool_name:
        print(
            f"REFUSED: the tool definition names {tool_def.server_id}/{tool_def.tool_name} "
            f"but the ceremony targets {args.server_id}/{args.tool_name} — admit the "
            "definition the server actually advertises for this coordinate"
        )
        return 1

    existing = store.get_tool(args.server_id, args.tool_name)
    print("--- review: admitted (if any) vs. proposed ---")
    print(_render_propose_preview(args.server_id, args.tool_name, existing.tool, tool_def))
    print("--- end review ---")

    caller = _caller_identity(session)
    proposal_id = str(uuid.uuid4())
    expires_at = (_utc_now(now) + datetime.timedelta(hours=args.ttl_hours)).isoformat()
    proposal = McpAdmissionProposal(
        proposal_id=proposal_id,
        expires_at=expires_at,
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        kind=args.kind,
        proposed_by=caller,
    )
    proposal_store.put_proposal(proposal, session)
    print(
        f"proposal stored: proposal_id={proposal_id} kind={args.kind} "
        f"{args.server_id}/{args.tool_name} def_hash={proposal.def_hash} "
        f"expires_at={expires_at}"
    )
    print(f"proposedBy={caller}")
    return 0


# ---------------------------------------------------------------------------
# admit-ratify — the checker
# ---------------------------------------------------------------------------


def admit_ratify_command(
    args: argparse.Namespace,
    *,
    store: ToolRegistryStore,
    proposal_store: AdmissionProposalStore,
    signer: RecordSigner | None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Run the maker-checker ceremony: burn the proposal, append the signed
    admission record, then write the ACTIVE row.

    Refuses up front — before the proposal is loaded — when no issuer signer is
    configured, so a refusal provably writes nothing (M8: an admission record
    mints callability, so it must be issuer-signed).
    """
    if signer is None:
        print(
            "REFUSED: issuer signing key not configured — an admission record "
            "mints callability, so it must be issuer-signed (M8). Configure "
            "ISSUER_SIGNING_KEY_SECRET_ARN/ISSUER_SIGNING_KEY_ID and a zone "
            "(--zone or ISSUER_SIGNING_ZONE). Nothing was written."
        )
        return 1

    caller = _caller_identity(session)
    try:
        loaded = proposal_store.get_proposal(
            args.server_id, args.tool_name, args.proposal_id, session=session
        )
    except ProposalIntegrityError as exc:
        print(f"REFUSED: {exc}")
        return 1
    if loaded is None:
        print(
            f"REFUSED: no admission proposal {args.proposal_id} for "
            f"{args.server_id}/{args.tool_name}"
        )
        return 1
    proposal, status = loaded
    if status != "pending":
        print(
            f"REFUSED: proposal {args.proposal_id} is {status!r}, not pending — "
            "a consumed proposal can never be ratified"
        )
        return 1

    effective_now = _utc_now(now)
    if proposal_expired(proposal.expires_at, effective_now):
        print(
            f"REFUSED: proposal {args.proposal_id} expired at {proposal.expires_at} — "
            "re-propose against the current advertised definition"
        )
        return 1

    if is_same_operator(proposal.proposed_by, caller):
        print(
            "REFUSED: maker == checker — the same ceremony identity "
            f"({caller}) proposed and is ratifying this admission. Admission "
            "requires two distinct identities (M7); self-admission is refused."
        )
        return 1

    # M6: a store-tampered (HMAC-quarantined) row is NEVER re-vetted through the
    # ceremony — an incident, not a ceremony (mirrors reseed_command). A
    # discovery-drift row (status QUARANTINED, HMAC intact) is resolvable, so it
    # is NOT refused here; admit_tool overwrites it.
    existing = store.get_tool(args.server_id, args.tool_name)
    if existing.quarantined:
        print(
            f"REFUSED: the existing row for {args.server_id}/{args.tool_name} is "
            f"HMAC-quarantined ({existing.quarantine_reason}); an HMAC-tamper "
            "quarantine is never re-admitted — root-cause the tamper first (M6)."
        )
        return 1

    # Burn the proposal first (single-shot) so a failure past this point cannot
    # leave a re-ratifiable proposal behind; then record+row as ONE atomic unit.
    try:
        proposal_store.consume_proposal(
            args.server_id, args.tool_name, args.proposal_id, "ratified", session=session
        )
    except ProposalConsumedError as exc:
        print(f"REFUSED: {exc}")
        return 1

    ts = effective_now.isoformat()
    record = McpAdmissionRecord(
        recordType=proposal.kind,
        serverId=proposal.tool_def.server_id,
        toolName=proposal.tool_def.tool_name,
        defHash=proposal.def_hash,
        proposedBy=proposal.proposed_by,
        ratifiedBy=caller,
        ts=ts,
        attestation=attestation_for(caller),
    )
    envelope = sign_admission_record(record, signer)
    row = _active_row_from_proposal(proposal, caller, ts)
    try:
        # The guarded re-read above is the conditional write's baseline: the row
        # write commits only if the coordinate is still exactly what `existing`
        # saw (#190). Record + row commit as ONE atomic unit — a conflict on
        # EITHER leg cancels both writes, so a refusal here provably wrote
        # nothing (the old record-without-row artifact can no longer occur).
        store.admit_tool_with_record(
            record, row, session, signature=envelope, expected=existing
        )
    except (RecordAlreadyExistsError, QuarantinedToolRowError, ToolRowConflictError) as exc:
        print(f"REFUSED: {exc}")
        return 1

    print(f"ADMITTED: {proposal.kind} {args.server_id}/{args.tool_name} -> ACTIVE")
    print(
        f"record: recordType={record.recordType} def_hash={record.defHash} ts={ts} "
        f"proposedBy={record.proposedBy} ratifiedBy={record.ratifiedBy} "
        "signed=yes (issuer DSSE)"
    )
    if is_local_identity(caller):
        print(SOLO_ATTESTATION_NOTICE)
    return 0


# ---------------------------------------------------------------------------
# admit-reject — the checker declines (#236)
# ---------------------------------------------------------------------------


def admit_reject_command(
    args: argparse.Namespace,
    *,
    proposal_store: AdmissionProposalStore,
    session: object = None,
) -> int:
    """Burn a pending proposal as 'rejected' — the grants `reject` mirror.

    Without this, a maker's bad proposal could only be left to expire, and
    "it expired" and "a checker looked at it and said no" are different facts
    of which only one is evidence. The rejection is a real single-shot burn:
    a rejected proposal can never later be ratified.

    Deliberately NOT maker != checker gated. Rejection can only narrow what the
    ceremony authorizes — it destroys a path to admission and creates none —
    so requiring a second identity would leave a maker who spotted their own
    mistake unable to withdraw it, with expiry the only exit. That is the same
    polarity the grant ceremony applies to `tighten` and `reject`.

    No issuer signature either: the burn writes no ledger record and mints no
    callability. The proposal's own HMAC still gates the read, so a tampered
    proposal REFUSES here exactly as it would at ratify.
    """
    caller = _caller_identity(session)
    try:
        loaded = proposal_store.get_proposal(
            args.server_id, args.tool_name, args.proposal_id, session=session
        )
    except ProposalIntegrityError as exc:
        print(f"REFUSED: {exc}")
        return 1
    if loaded is None:
        print(
            f"REFUSED: no admission proposal {args.proposal_id} for "
            f"{args.server_id}/{args.tool_name}"
        )
        return 1
    _proposal, status = loaded
    if status != "pending":
        print(
            f"REFUSED: proposal {args.proposal_id} is {status!r}, not pending — "
            "it was already consumed"
        )
        return 1
    try:
        proposal_store.consume_proposal(
            args.server_id, args.tool_name, args.proposal_id, "rejected", session=session
        )
    except ProposalConsumedError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(
        f"REJECTED: proposal {args.proposal_id} for "
        f"{args.server_id}/{args.tool_name} rejectedBy={caller} — "
        "a rejected proposal can never be ratified"
    )
    return 0


# ---------------------------------------------------------------------------
# bulk-propose / bulk-ratify — the batch ceremony (#221 Phase 5, second slice)
#
# The SAME ceremony as admit-propose/admit-ratify, run over a whole server's
# tool set instead of one coordinate. Two commands, two invocations, two STS
# identities: `bulk-ratify` has no code path that creates a proposal, and there
# is deliberately NO combined "bulk-admit" — collapsing the two halves into one
# invocation would collapse maker != checker (M7), the invariant the ceremony
# exists for. Per-coordinate the write sequence and the conditional-write
# ordering are byte-for-byte the single-coordinate commands'.
#
# NO OPERATOR FILE SITS IN THE RATIFY TRUST PATH. `bulk-propose` writes no
# hand-off artifact and `bulk-ratify` reads none: the checker learns which
# coordinates exist from the IMAGE-BAKED manifest's declared namespace (layer 1
# of two-key admission) and learns their pending proposals by QUERYING each
# declared coordinate's partition (`AdmissionProposalStore.list_pending`). The
# proposal pk already embeds (server_id, tool_name), so a plain Query suffices —
# never a `dynamodb:Scan`, which no ceremony role is granted (a scan would pass
# every in-memory test here and be IAM-denied on the real floor).
#
# `bulk-propose`'s own enumeration stays the manifest-union idiom `diff` uses
# (declared namespace UNIONED with the live snapshot's names).
# ---------------------------------------------------------------------------


def _parse_utc(value: str) -> datetime.datetime | None:
    """Parse an ISO-8601 timestamp, REFUSING a naive one (returns None).

    A naive timestamp has no zone to compare against `now`, and guessing one
    would silently make a stale snapshot look fresh — fail toward refusing.
    """
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _load_snapshot_and_decl(
    snapshot_path: str, manifest_path: str
) -> tuple[McpServerSnapshot, McpServerDecl, str | None]:
    """Load the snapshot artifact + its server's image-baked declaration.

    Returns (snapshot, decl, None) or (…, refusal message) — the caller maps a
    refusal to exit 2. Mirrors `diff_command`'s prelude exactly: the server_id
    comes from the ARTIFACT, never a flag, and the declared namespace comes
    from an operator-NAMED image-baked manifest, never a store.
    """
    try:
        snapshot = McpServerSnapshot.model_validate_json(Path(snapshot_path).read_text())
    except (OSError, ValidationError) as exc:
        return None, None, f"REFUSED: --snapshot {snapshot_path} is unusable: {exc}"

    try:
        manifest = load_agent_manifest(Path(manifest_path))
    except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
        return None, None, f"REFUSED: --manifest {manifest_path} is unusable: {exc}"

    decl = manifest.mcp_servers.get(snapshot.server_id)
    if decl is None:
        return None, None, (
            f"REFUSED: manifest {manifest_path} declares no mcp server "
            f"{snapshot.server_id!r} (declared: {sorted(manifest.mcp_servers)})"
        )
    return snapshot, decl, None


def bulk_propose_command(
    args: argparse.Namespace,
    *,
    store: ToolRegistryStore,
    proposal_store: AdmissionProposalStore,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Maker half of the batch ceremony: one proposal per ACTIONABLE coordinate.

    Two phases, validate-all-before-write-any, so a validation refusal provably
    writes nothing (the same "refuse toward writing nothing" posture the
    single-coordinate ceremony takes).

    Phase 1 classifies every coordinate in the manifest-union and selects the
    actionable ones — DRIFT (a re-vet of moved bytes) and NEW (a first
    admission). UNCHANGED is skipped: there is nothing to re-admit. WITHDRAWN
    is REPORTED BUT NEVER PROPOSED — the server no longer advertises the tool,
    so there is no live definition to bind a def_hash to, and a proposal
    without live bytes is not a thing this ceremony can express.

    Phase 2 writes the proposals one at a time. A mid-loop failure STOPS and
    reports exactly which coordinates were written and which were not; no
    rollback is attempted, and none is needed — an unratified proposal is inert
    (it admits nothing on its own) and expires on its own TTL.
    """
    snapshot, decl, refusal = _load_snapshot_and_decl(args.snapshot, args.manifest)
    if refusal is not None:
        print(refusal)
        return 2

    # Snapshot age bound: a stale artifact describes a server as it WAS, and
    # proposing from it binds bytes the server may no longer advertise (the
    # ratified row would quarantine on the very next discovery). Pure timestamp
    # comparison — never a judgement about WHY the snapshot is old.
    captured_at = _parse_utc(snapshot.captured_at)
    if captured_at is None:
        print(
            f"REFUSED: snapshot captured_at {snapshot.captured_at!r} is not a "
            "timezone-aware ISO-8601 timestamp — its age cannot be bounded"
        )
        return 2
    age_minutes = (_utc_now(now) - captured_at).total_seconds() / 60
    if age_minutes > args.max_snapshot_age_minutes:
        print(
            f"REFUSED: snapshot is {age_minutes:.1f} minutes old, exceeding "
            f"--max-snapshot-age-minutes {args.max_snapshot_age_minutes} — "
            "re-run `snapshot` and propose against what the server advertises "
            "NOW. Nothing was written."
        )
        return 2

    live_by_name = {entry.tool_def.tool_name: entry for entry in snapshot.entries}
    declared_names = {t.tool_name for t in decl.tools}

    # --- Phase 1: classify + validate. No writes of any kind happen here. ---
    results: list = []
    actionable: list[tuple[str, McpSnapshotEntry, str]] = []
    withdrawn: list[str] = []
    undeclared: list[str] = []
    hash_failures: list[str] = []

    for name in sorted(declared_names | set(live_by_name)):
        stored_result = store.get_tool(snapshot.server_id, name)
        live_entry = live_by_name.get(name)
        if stored_result.tool is None and live_entry is None:
            continue  # declared but neither admitted nor live — nothing to do
        # transport/source from the snapshot artifact itself (#232), exactly
        # as `diff` passes them: a remote newly-required field must render as
        # a disclosure escalation on the maker's review surface too.
        result = render_tool_diff(
            name,
            stored_result.tool,
            live_entry,
            transport=snapshot.transport,
            source=snapshot.source,
        )
        results.append(result)

        if result.kind is DriftKind.WITHDRAWN:
            withdrawn.append(name)
            continue
        if result.kind is DriftKind.UNCHANGED:
            continue
        if name not in declared_names:
            # A live tool outside the image-baked namespace is rendered for
            # visibility (the M3/M4 unlisted surface) but NEVER proposed: the
            # store can select/tighten, never mint — a proposal for a
            # coordinate the manifest doesn't declare could never be ratified
            # (bulk-ratify enumerates the declared namespace) and admission
            # would refuse it anyway. Found at the first live N-large run:
            # 69 advertised vs 3 declared would have written 66 junk
            # proposals.
            undeclared.append(name)
            continue

        assert live_entry is not None  # NEW/DRIFT both require a live entry
        recomputed = compute_tool_def_hash(live_entry.tool_def)
        if recomputed != live_entry.def_hash:
            hash_failures.append(
                f"  {name}: recorded def_hash={live_entry.def_hash} "
                f"recomputed={recomputed}"
            )
            continue
        kind = KIND_REVET if result.kind is DriftKind.DRIFT else KIND_ADMISSION
        actionable.append((name, live_entry, kind))

    if hash_failures:
        print(
            f"REFUSED: {len(hash_failures)} snapshot entr(ies) fail their own "
            "integrity check — a hand-edited or corrupted snapshot, or one "
            "captured under an older signed-set basis (#223 widened it; "
            "re-snapshot the live server). Either defeats the entire point of "
            "proposing from one. NOTHING was written (the whole run is refused, "
            "not just the bad coordinates):"
        )
        for line in hash_failures:
            print(line)
        return 2

    for result in results:
        print(result.rendered)
        print()
    print(render_diff_summary(results))

    if withdrawn:
        print(
            f"NOT PROPOSABLE ({len(withdrawn)}): {sorted(withdrawn)} are WITHDRAWN "
            "— admitted but no longer advertised, so there is no live definition "
            "to bind a def_hash to. A dead tool is already uncallable; retiring "
            "its row is not this ceremony's job."
        )
    if undeclared:
        print(
            f"NOT PROPOSABLE ({len(undeclared)}): live but outside the image-baked "
            "declared namespace — admission requires the Layer-1 manifest "
            "declaration first (M4); declare the tool, rebuild the image, then "
            "propose. An undeclared tool is already uncallable."
        )
    if not actionable:
        print("nothing actionable: no DRIFT or NEW coordinate to propose.")

    # --- Phase 2: write. One proposal per actionable coordinate. ---
    caller = _caller_identity(session)
    expires_at = (_utc_now(now) + datetime.timedelta(hours=args.ttl_hours)).isoformat()
    written: list[str] = []
    for name, live_entry, kind in actionable:
        proposal = McpAdmissionProposal(
            proposal_id=str(uuid.uuid4()),
            expires_at=expires_at,
            tool_def=live_entry.tool_def,
            def_hash=live_entry.def_hash,
            kind=kind,
            proposed_by=caller,
        )
        try:
            proposal_store.put_proposal(proposal, session)
        except ProposalIntegrityError as exc:
            # A tamper surfacing mid-ceremony stops the run loudly and writes
            # nothing further; it is never folded into the generic failure path.
            print(f"REFUSED: {exc}")
            print(f"  proposed before the refusal ({len(written)}): {written}")
            return 1
        except Exception as exc:  # noqa: BLE001 — any store failure stops the run
            not_written = [n for n, _, _ in actionable[len(written):]]
            print(f"ERROR: storing the proposal for {name} failed: {exc}")
            print(f"  proposed ({len(written)}): {written}")
            print(f"  NOT proposed ({len(not_written)}): {not_written}")
            print(
                "  No rollback was attempted and none is needed: an unratified "
                "proposal is INERT (it admits nothing on its own) and expires at "
                f"{expires_at}. Re-run to propose the remainder."
            )
            return 1
        written.append(name)
        print(
            f"proposal stored: proposal_id={proposal.proposal_id} kind={kind} "
            f"{snapshot.server_id}/{name} def_hash={proposal.def_hash} "
            f"expires_at={expires_at}"
        )

    print(f"proposedBy={caller}")
    print(
        f"{len(written)} proposal(s) are now PENDING in the store. `bulk-ratify` "
        "discovers them itself from the image-baked manifest — no hand-off file "
        "is written, and none is needed."
    )
    return 0


@dataclass
class _RatifyCandidate:
    """One coordinate that passed bulk-ratify's read-side validation."""

    tool_name: str
    proposal: McpAdmissionProposal
    existing: ToolReadResult
    diff: ToolDiffResult


def bulk_ratify_command(
    args: argparse.Namespace,
    *,
    store: ToolRegistryStore,
    proposal_store: AdmissionProposalStore,
    signer: RecordSigner | None,
    session: object = None,
    now: datetime.datetime | None = None,
) -> int:
    """Checker half of the batch ceremony. Creates NO proposals, ever.

    There is deliberately no code path here that writes a proposal: this
    command only CONSUMES proposals a different identity already made. That,
    plus the per-coordinate maker != checker comparison below, is what keeps
    M7 structural rather than procedural.

    ENUMERATION takes no operator input. The universe of coordinates is the
    image-baked manifest's declared namespace, and each one's pending proposal
    is read straight from the store (`list_pending`, a coordinate-keyed Query).
    No file passes from maker to checker, so there is no artifact to tamper
    with, mis-name, or replay. A coordinate with no pending proposal is skipped
    silently; a coordinate with MORE than one is REFUSED rather than guessed at.

    THE RENDERING GATE. The pending set is bucketed and rendered in a fixed
    order of decreasing danger, because a batch review's real failure mode is
    reviewer complacency, not invisibility:

      1. `description` deltas FIRST, VERBATIM AND IN FULL. This is the
         model-facing injection vector — a swapped server rewrites a
         description to steer the agent while leaving the schema alone.
         Summarizing it would defeat the point of showing it.
      2. `input_schema` deltas, machine-summarized (a CONTRACT change).
      3. Everything else, collapsed to a COUNT — so cosmetic churn cannot
         bury the two classes above in output volume.

    CONFIRMATION asymmetry follows the same logic: `--yes` is one blanket
    confirmation covering the schema-only and cosmetic coordinates, but it can
    NEVER ratify a description change. Every description-delta coordinate
    additionally requires its own name passed via
    --acknowledge-description-change; unacknowledged, it is refused and
    skipped while the rest of the batch proceeds.
    """
    if signer is None:
        print(
            "REFUSED: issuer signing key not configured — an admission record "
            "mints callability, so it must be issuer-signed (M8). Configure "
            "ISSUER_SIGNING_KEY_SECRET_ARN/ISSUER_SIGNING_KEY_ID and a zone "
            "(--zone or ISSUER_SIGNING_ZONE). Nothing was written."
        )
        return 1

    try:
        manifest = load_agent_manifest(Path(args.manifest))
    except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
        print(f"REFUSED: --manifest {args.manifest} is unusable: {exc}")
        return 2
    decl = manifest.mcp_servers.get(args.server_id)
    if decl is None:
        print(
            f"REFUSED: manifest {args.manifest} declares no mcp server "
            f"{args.server_id!r} (declared: {sorted(manifest.mcp_servers)})"
        )
        return 2

    caller = _caller_identity(session)
    effective_now = _utc_now(now)
    # Layer 1 (MCP-HOST.md): the image-baked declared namespace is the only
    # universe a coordinate may be admitted into — and it is now the ONLY thing
    # enumerated, so a proposal outside it is not merely refused, it is never
    # even looked up. A store row cannot volunteer a coordinate into the batch.
    declared_names = {t.tool_name for t in decl.tools}

    candidates: list[_RatifyCandidate] = []
    refused: list[str] = []

    for name in sorted(declared_names):
        # A ProposalIntegrityError is a REFUSAL of the WHOLE run, never a
        # per-coordinate skip: a tampered proposal would launder a swapped tool
        # definition into a signed admission, and nothing may be written while
        # that is unresolved.
        try:
            pending = proposal_store.list_pending(args.server_id, name, session=session)
        except ProposalIntegrityError as exc:
            print(f"REFUSED: {exc}")
            print(
                "  The whole batch is refused and NOTHING was written. Root-cause "
                "the tamper before ratifying any coordinate on this server."
            )
            return 1
        if not pending:
            continue  # no pending proposal on this coordinate — nothing to do
        if len(pending) > 1:
            refused.append(
                f"{name}: {len(pending)} pending proposals "
                f"({sorted(p.proposal_id for p, _ in pending)}) — which one the "
                "checker is ratifying is AMBIGUOUS, and guessing would ratify "
                "bytes nobody chose. Reject the extras (or let them expire), "
                "then re-run"
            )
            continue
        proposal, _status = pending[0]
        if proposal_expired(proposal.expires_at, effective_now):
            refused.append(f"{name}: proposal expired at {proposal.expires_at}")
            continue
        # M7, re-derived PER COORDINATE — never one aggregate check for the
        # batch. A batch is not an identity; each admission is its own act.
        if is_same_operator(proposal.proposed_by, caller):
            refused.append(
                f"{name}: maker == checker ({caller}) — self-admission is "
                "refused (M7)"
            )
            continue
        existing = store.get_tool(args.server_id, name)
        if existing.quarantined:
            refused.append(
                f"{name}: the stored row is HMAC-quarantined "
                f"({existing.quarantine_reason}) — an HMAC-tamper quarantine is "
                "never re-admitted; root-cause the tamper first (M6)"
            )
            continue
        live_entry = McpSnapshotEntry(tool_def=proposal.tool_def, def_hash=proposal.def_hash)
        candidates.append(
            _RatifyCandidate(
                tool_name=name,
                proposal=proposal,
                existing=existing,
                diff=render_tool_diff(name, existing.tool, live_entry),
            )
        )

    # --- THE RENDERING GATE: four buckets, most dangerous first (#223: the
    # metadata fields are signed now, so their deltas are rendered at the
    # gate, not just counted — only first admissions and pure re-hash churn
    # remain count-only) ---
    def _schema_moved(c: _RatifyCandidate) -> bool:
        if c.existing.tool is None:
            return False
        admitted = c.existing.tool.tool_def  # nested since #246
        return admitted.input_schema != c.proposal.tool_def.input_schema or (
            admitted.output_schema != c.proposal.tool_def.output_schema
        )

    def _metadata_moved(c: _RatifyCandidate) -> list[str]:
        if c.existing.tool is None:
            return []
        admitted = c.existing.tool.tool_def  # nested since #246
        return [
            name
            for name in VERBATIM_METADATA_FIELDS
            if getattr(admitted, name) != getattr(c.proposal.tool_def, name)
        ]

    steering = [c for c in candidates if c.diff.description_changed]
    contract = [c for c in candidates if c not in steering and _schema_moved(c)]
    metadata = [
        c for c in candidates if c not in steering and c not in contract and _metadata_moved(c)
    ]
    cosmetic = [
        c for c in candidates if c not in steering and c not in contract and c not in metadata
    ]

    # Each listed candidate renders its FULL diff (`render_tool_diff` — the
    # same rendering `diff` shows), not just the field that routed it into
    # its bucket: the checker is a different human than the maker (M7), so
    # the ratify gate is their ONE look at what they are ratifying — a
    # candidate with both a schema delta and a metadata delta must show
    # both. The buckets order by danger and route the ack requirement; they
    # never truncate what is shown. (Found live in the #223 alpaca re-vet:
    # the fragmented rendering showed the output_schema half and silently
    # dropped the meta delta at the gate.)
    def _print_bucket(candidates_in_bucket: list[_RatifyCandidate]) -> None:
        if not candidates_in_bucket:
            print("  (none)")
        for candidate in candidates_in_bucket:
            print(candidate.diff.rendered)

    print("=== 1. DESCRIPTION deltas — the model-facing injection vector ===")
    _print_bucket(steering)
    print()
    print("=== 2. SCHEMA deltas — contract changes (input_schema / output_schema) ===")
    _print_bucket(contract)
    print()
    print("=== 3. SIGNED METADATA deltas (title/icons/annotations/meta/execution) ===")
    _print_bucket(metadata)
    print()
    print(f"=== 4. Other coordinates (first admissions / re-hash churn): {len(cosmetic)} === ")

    if not args.yes:
        print(
            f"REFUSED: {len(candidates)} coordinate(s) are ready to ratify but "
            "--yes was not passed. Nothing was written."
        )
        return 1

    acknowledged = set(args.acknowledge_description_change or [])

    # --- Per-coordinate write. One wedged row never aborts the batch. ---
    ratified: list[str] = []
    for candidate in candidates:
        name = candidate.tool_name
        # --yes is ONE blanket confirmation; it deliberately does not reach a
        # description change, which needs its own named acknowledgement.
        if candidate.diff.description_changed and name not in acknowledged:
            refused.append(
                f"{name}: description changed but was not acknowledged — pass "
                f"--acknowledge-description-change {name} after reading the "
                "verbatim delta above. --yes alone never ratifies a change to "
                "the model-facing injection vector."
            )
            continue

        proposal = candidate.proposal
        # The guarded re-read is the conditional write's baseline (#190): the
        # row must still be exactly what was evaluated above.
        existing = store.get_tool(args.server_id, name)
        try:
            proposal_store.consume_proposal(
                args.server_id, name, proposal.proposal_id, "ratified", session=session
            )
        except ProposalConsumedError as exc:
            refused.append(f"{name}: {exc}")
            continue

        ts = _utc_now(now).isoformat()
        record = McpAdmissionRecord(
            recordType=proposal.kind,
            serverId=proposal.tool_def.server_id,
            toolName=proposal.tool_def.tool_name,
            defHash=proposal.def_hash,
            proposedBy=proposal.proposed_by,
            ratifiedBy=caller,
            ts=ts,
            attestation=attestation_for(caller),
        )
        row = _active_row_from_proposal(proposal, caller, ts)
        try:
            store.admit_tool_with_record(
                record,
                row,
                session,
                signature=sign_admission_record(record, signer),
                expected=existing,
            )
        except (RecordAlreadyExistsError, QuarantinedToolRowError, ToolRowConflictError) as exc:
            # Record + row are ONE atomic write: a wedged coordinate cancels
            # both legs (no orphan record) and is reported while the batch
            # CONTINUES. One wedged row must not deny the whole set — the
            # step-over semantics are unchanged, they just no longer leave a
            # record behind.
            refused.append(f"{name}: {exc}")
            continue

        ratified.append(name)
        print(f"ADMITTED: {proposal.kind} {args.server_id}/{name} -> ACTIVE (signed)")

    print()
    print(
        f"bulk-ratify summary: ratified={len(ratified)} refused={len(refused)}"
    )
    for name in ratified:
        print(f"  RATIFIED {name}")
    for line in refused:
        print(f"  REFUSED  {line}")
    print(f"ratifiedBy={caller}")

    if refused or not candidates:
        return 1
    return 0


# ---------------------------------------------------------------------------
# snapshot — pure pre-admission discovery (#221 Phase 5 prerequisite)
# ---------------------------------------------------------------------------


class _PrefixedLeafSecrets:
    """Map a secret *leaf* to `<prefix>/connectors/<leaf>` (sa#164).

    The command-side twin of `broker_server._PrefixedSecrets` (not imported —
    pulling the server module into an operator CLI drags its whole boot
    surface). `connector_secrets` values are bare LEAVES; without this wrapper
    a snapshot run under `BROKER_SECRET_PREFIX` resolved the bare leaf and
    ResourceNotFound'd where the broker boot succeeds — found live in the #223
    re-vet (the alpaca leg's env_map fetch)."""

    def __init__(self, inner: SecretsProvider, prefix: str) -> None:
        self._inner = inner
        self._prefix = prefix.rstrip("/")

    def fetch_secret(self, secret_name: str) -> str:
        full = f"{self._prefix}/connectors/{secret_name}" if self._prefix else secret_name
        return self._inner.fetch_secret(full)


def _resolve_secrets_provider() -> SecretsProvider:
    """The same env-switched secrets posture `broker_server.py` boots with,
    minus the demo stub-fallback overlay (a snapshot run is an operator
    invocation, not a served runtime — an unresolvable credential should
    refuse loudly, not silently fall back to a dev stub).

    Since #248 the arm comes from `boot_config.resolve_secrets_arm` rather than
    from a second independent `== "secretsmanager"` test here: the two sites
    disagreeing about which backend is in force is exactly the failure the
    closed catalog exists to prevent. This site still composes its own wrappers
    (no overlay, and the leaf-prefixing variant above), which is the deliberate
    difference between an operator invocation and the served runtime.

    `secretsmanager` -> real Secrets Manager (honoring `BROKER_SECRET_PREFIX`
    exactly as the broker boot does); `dir` -> one file per secret leaf under
    BROKER_SECRETS_DIR; `file` -> the 0600 JSON blob; `fake` -> an empty
    in-memory provider (the credential-less/toy case, byte-for-byte cost-free)."""
    arm = resolve_secrets_arm()
    if arm == "secretsmanager":
        # No region argument: boto3 resolves it (AWS_REGION / AWS_DEFAULT_REGION
        # / config / task metadata) and fails loudly if nothing does. A literal
        # fallback here would silently target the wrong region off us-east-1.
        provider: SecretsProvider = LazyBotoSecretsProvider()
        prefix = os.environ.get("BROKER_SECRET_PREFIX", "")
        if prefix:
            provider = _PrefixedLeafSecrets(provider, prefix)
        return provider
    if arm == "dir":
        return DirSecretsProvider(str(resolve_secrets_dir()))
    if arm == "file":
        return LocalFileSecretsProvider(resolve_secrets_file())
    return FakeSecretsProvider({})


def _resolve_stdio_env(
    server_id: str, decl: McpServerDecl, manifest: AgentManifest
) -> dict[str, str] | None:
    """The child spawn environment for a stdio snapshot — the SAME two-halves
    seam `mcp_construction.build_mcp_connectors` uses at real spawn time
    (static `decl.env` + a credential resolved through the #173
    CredentialProvider catalog and delivered via `connector_auth.env_map`).
    An empty/absent `env_map` resolves NO credential at all (the toy-server
    case costs nothing); `None` return lets `connect_stdio` spawn with the
    SDK's untouched minimal default env. Never logs or returns the credential
    itself beyond the composed env dict, which the caller must not print."""
    auth = manifest.connector_auth.get(server_id)
    env_map = dict(auth.env_map) if auth else {}
    if not env_map:
        return dict(decl.env) or None
    strategies = build_credential_strategies(manifest.connector_auth)
    strategy = strategies.get(server_id) or StaticSecret()
    secret_name = manifest.connector_secrets.get(server_id, server_id)
    credential = strategy.resolve(
        secrets=_resolve_secrets_provider(), secret_name=secret_name
    )
    env = compose_child_env(server_id, decl.env, env_map, credential)
    return env or None


def _resolve_remote_headers(
    server_id: str, manifest: AgentManifest
) -> dict[str, str] | None:
    """The per-connect request headers for a remote snapshot — the SAME two-halves
    seam `mcp_construction.build_mcp_connectors` uses at real connect time
    (a credential resolved through the #173 CredentialProvider catalog and
    delivered via `connector_auth.header_map`, MCP-HOST.md M25 / CONNECTOR-AUTH
    C10). The exact remote mirror of `_resolve_stdio_env`.

    An empty/absent `header_map` resolves NO credential at all (the toy-server
    case costs nothing) and returns `None`, letting `connect_streamable_http`
    connect unauthenticated exactly as before. Never logs or returns the
    credential itself beyond the composed header dict, whose VALUES are
    secret-adjacent and which the caller must not print.
    """
    auth = manifest.connector_auth.get(server_id)
    header_map = dict(auth.header_map) if auth else {}
    if not header_map:
        return None
    strategies = build_credential_strategies(manifest.connector_auth)
    strategy = strategies.get(server_id) or StaticSecret()
    secret_name = manifest.connector_secrets.get(server_id, server_id)
    credential = strategy.resolve(
        secrets=_resolve_secrets_provider(), secret_name=secret_name
    )
    return compose_headers(server_id, header_map, credential) or None


async def _discover_tool_defs(
    server_id: str, decl: McpServerDecl, manifest: AgentManifest
) -> list[McpToolDef]:
    """Connect once and `tools/list` — the transport `decl` names, nothing else.

    Both transports resolve their credential half through the same two-halves
    seam the runtime uses: a stdio (`command`) decl via `_resolve_stdio_env`
    (spawn env, C9), a remote (`url`) decl via `_resolve_remote_headers`
    (per-connect headers, C10). Before #237 the remote arm had no credential
    delivery at all, which made every operator ceremony command that discovers
    from a remote server — `snapshot`, and through its artifact `diff`,
    `show` and `admit-propose --from-snapshot` — unusable against any
    vendor-hosted server that requires auth, i.e. every real one.
    """
    if decl.url is not None:
        headers = _resolve_remote_headers(server_id, manifest)
        async with connect_streamable_http(
            server_id, decl.url, headers=headers
        ) as client:
            return await client.list_tool_defs()
    env = _resolve_stdio_env(server_id, decl, manifest)
    async with connect_stdio(
        server_id, decl.command, decl.args, cwd=decl.cwd, env=env
    ) as client:
        return await client.list_tool_defs()


def snapshot_command(args: argparse.Namespace) -> int:
    """Capture `--server-id`'s full live advertised tool set to `--out`.

    PURE discovery: no registry read or write, no proposal/HMAC store touched
    at all — this must work before any registry row (or table) exists. Server
    config is resolved from `--manifest`, an operator-NAMED image-baked
    AgentManifest, never a store (#197/#199, docs/config-provenance.md:
    `mcp_servers` names code to spawn/connect, so it is image-baked-only power
    class). A server absent from the manifest, or declared namespace-only
    (neither `command` nor `url` — nothing live to connect to), refuses with
    exit 2 before any network/process activity.
    """
    try:
        manifest = load_agent_manifest(Path(args.manifest))
    except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
        print(f"REFUSED: --manifest {args.manifest} is unusable: {exc}")
        return 2

    decl = manifest.mcp_servers.get(args.server_id)
    if decl is None:
        print(
            f"REFUSED: manifest {args.manifest} declares no mcp server "
            f"{args.server_id!r} (declared: {sorted(manifest.mcp_servers)})"
        )
        return 2
    if decl.command is None and decl.url is None:
        print(
            f"REFUSED: mcp server {args.server_id!r} is a namespace-only "
            "declaration (no 'command' or 'url' in the manifest) — there is "
            "nothing live to connect to"
        )
        return 2

    try:
        defs = asyncio.run(_discover_tool_defs(args.server_id, decl, manifest))
    except Exception as exc:  # transport/spawn/credential failure — operational
        print(f"ERROR: could not discover tools from {args.server_id!r}: {exc}")
        return 1

    entries = [
        McpSnapshotEntry(tool_def=d, def_hash=compute_tool_def_hash(d)) for d in defs
    ]
    source = (
        decl.url
        if decl.url is not None
        else " ".join([decl.command, *decl.args])
    )
    snapshot = McpServerSnapshot(
        server_id=args.server_id,
        transport=decl.transport,
        source=source,
        captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
        entries=entries,
    )
    out_path = Path(args.out)
    out_path.write_text(snapshot.model_dump_json(indent=2) + "\n")
    print(
        f"snapshot written: {out_path} server_id={args.server_id} "
        f"transport={decl.transport} tools={len(entries)}"
    )
    return 0


# ---------------------------------------------------------------------------
# show — read-only, one stored row (#221 Phase 5 item 3)
# ---------------------------------------------------------------------------


def show_command(args: argparse.Namespace, *, store: ToolRegistryStore) -> int:
    """Print one stored registry row, human-readable. Read-only: a single
    `get_tool`, nothing else — never touches `admit_tool`/`put_record`."""
    result = store.get_tool(args.server_id, args.tool_name)
    print(render_registered_tool(args.server_id, args.tool_name, result))
    return 0 if result.tool is not None else 1


# ---------------------------------------------------------------------------
# diff — read-only, a snapshot vs. its server's stored rows (#221 Phase 5 item 3)
# ---------------------------------------------------------------------------


def diff_command(args: argparse.Namespace, *, store: ToolRegistryStore) -> int:
    """Compare a `snapshot` artifact's live tool set against the stored rows
    for that artifact's server_id (named by the artifact itself, never a
    flag — mirrors `snapshot`'s server config never coming from a store).

    Read-only: `store.get_tool` only, one coordinate at a time — the store
    exposes no server-wide listing (no IAM role grants `dynamodb:Scan`, and
    the row key puts `server_id` inside the partition key, so a `Query`
    can't substitute either; see registry.py's DynamoToolRegistry docstring).
    The tool-name universe to check therefore comes from `--manifest`'s
    declared namespace (`AgentManifest.mcp_servers[server_id].tools`) —
    same image-baked-only source `snapshot` already uses, no new injection
    surface — UNIONED with the live snapshot's own tool names (an
    undeclared live tool is still worth showing as NEW; two-key admission
    already makes it uncallable regardless).

    KNOWN LIMITATION, not solved here: a stored row whose tool was dropped
    from the declared namespace by a LATER image is an ORPHAN row this
    enumeration cannot find (it is outside both the manifest and the live
    snapshot). Such a row is already uncallable — it fails layer 1 of
    two-key admission — so this is a display gap, not a safety gap; finding
    it is the Phase-5 "registry rows in the grants auditor" rider's job
    (parallel to that rider's existing orphan-TOOLREC# gap), not `diff`'s.

    The rendering (NEW/WITHDRAWN/unchanged/DRIFT, the contract-vs-steering
    split, the unhashed-metadata caveat) lives in `mcp/render.py` — this
    function only resolves the two sides per tool coordinate and hands them
    to it.

    Exit code is 0 whenever the comparison ran, regardless of what it found
    — `diff` is an inspection tool for a human re-vetting decision, not a
    gate; a drift-found-implies-nonzero-exit convention was NOT implemented
    here (flag if that behavior is actually wanted).
    """
    try:
        snapshot = McpServerSnapshot.model_validate_json(Path(args.snapshot).read_text())
    except (OSError, ValidationError) as exc:
        print(f"REFUSED: --snapshot {args.snapshot} is unusable: {exc}")
        return 2

    try:
        manifest = load_agent_manifest(Path(args.manifest))
    except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
        print(f"REFUSED: --manifest {args.manifest} is unusable: {exc}")
        return 2

    decl = manifest.mcp_servers.get(snapshot.server_id)
    if decl is None:
        print(
            f"REFUSED: manifest {args.manifest} declares no mcp server "
            f"{snapshot.server_id!r} (declared: {sorted(manifest.mcp_servers)})"
        )
        return 2

    live_by_name = {entry.tool_def.tool_name: entry for entry in snapshot.entries}
    declared_names = {t.tool_name for t in decl.tools}

    results = []
    for name in sorted(declared_names | set(live_by_name)):
        stored_result = store.get_tool(snapshot.server_id, name)
        live_entry = live_by_name.get(name)
        if stored_result.tool is None and live_entry is None:
            # Declared (layer 1) but never admitted and not currently live —
            # nothing to compare or report; not a WITHDRAWN/NEW/DRIFT case.
            continue
        # transport/source from the snapshot artifact itself (#232): on a
        # streamable-http server a newly-required field renders as a
        # disclosure escalation naming the destination URL.
        result = render_tool_diff(
            name,
            stored_result.tool,
            live_entry,
            transport=snapshot.transport,
            source=snapshot.source,
        )
        if stored_result.quarantined:
            result.rendered += (
                f"\n  NOTE: the stored row is HMAC-quarantined "
                f"({stored_result.quarantine_reason}) — treat as untrusted, not "
                "as an authoritative baseline"
            )
        results.append(result)
        print(result.rendered)
        print()

    print(render_diff_summary(results))
    print(f"server_id={snapshot.server_id} snapshot_captured_at={snapshot.captured_at}")
    return 0


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def _add_coordinate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--server-id", required=True, help="the MCP server id")
    parser.add_argument("--tool-name", required=True, help="the advertised tool name")
    parser.add_argument(
        "--table-name",
        help="registry table (default: MCP_REGISTRY_TABLE_NAME env)",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.mcp.commands",
        description=(
            "MCP tool-admission ceremony (#174): the sanctioned mutation path for the "
            "admitted-tool registry. Runs under the caller's ambient credentials; "
            "identity is derived from STS, never asserted (maker != checker)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    propose = sub.add_parser(
        "admit-propose",
        help="maker: store a single-shot expiring proposal over the exact advertised def",
    )
    _add_coordinate_args(propose)
    propose_source = propose.add_mutually_exclusive_group(required=True)
    propose_source.add_argument(
        "--tool-def-json",
        metavar="PATH",
        help="path to the McpToolDef JSON the server currently advertises",
    )
    propose_source.add_argument(
        "--from-snapshot",
        metavar="PATH",
        help=(
            "path to an McpServerSnapshot JSON (from `snapshot`) to resolve the "
            "McpToolDef from, instead of hand-authoring one (#221 Phase 5 item 4)"
        ),
    )
    propose.add_argument(
        "--kind",
        choices=list(CEREMONY_KINDS),
        default=KIND_ADMISSION,
        help="admission (first) or re-vet (of a drifted definition); default admission",
    )
    propose.add_argument(
        "--ttl-hours", required=True, type=float, help="proposal expiry from now"
    )

    ratify = sub.add_parser(
        "admit-ratify", help="checker: burn the proposal, sign the record, write the ACTIVE row"
    )
    _add_coordinate_args(ratify)
    ratify.add_argument("--proposal-id", required=True)
    ratify.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )

    reject = sub.add_parser(
        "admit-reject",
        help="checker declines: burn a pending proposal as rejected (never ratifiable)",
    )
    _add_coordinate_args(reject)
    reject.add_argument("--proposal-id", required=True)

    bulk_propose = sub.add_parser(
        "bulk-propose",
        help="maker: propose every actionable (DRIFT/NEW) coordinate in a snapshot",
    )
    bulk_propose.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help="image-baked AgentManifest YAML declaring the snapshot's server",
    )
    bulk_propose.add_argument(
        "--snapshot",
        required=True,
        metavar="PATH",
        help="McpServerSnapshot JSON (from `snapshot`); server_id comes from it, never a flag",
    )
    bulk_propose.add_argument(
        "--ttl-hours", required=True, type=float, help="proposal expiry from now"
    )
    bulk_propose.add_argument(
        "--max-snapshot-age-minutes",
        type=float,
        default=60.0,
        help=(
            "refuse a snapshot older than this (default 60): proposing from a "
            "stale artifact binds bytes the server may no longer advertise"
        ),
    )
    bulk_propose.add_argument(
        "--table-name", help="registry table (default: MCP_REGISTRY_TABLE_NAME env)"
    )

    bulk_ratify = sub.add_parser(
        "bulk-ratify",
        help="checker: ratify the pending proposals for a server (creates none)",
    )
    bulk_ratify.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help=(
            "image-baked AgentManifest YAML — the declared namespace (layer 1), "
            "and the ONLY source of the coordinates this ceremony enumerates"
        ),
    )
    bulk_ratify.add_argument("--server-id", required=True, help="the MCP server id")
    bulk_ratify.add_argument(
        "--yes",
        action="store_true",
        help=(
            "confirm the schema-only and cosmetic coordinates. NEVER covers a "
            "description change — those need --acknowledge-description-change"
        ),
    )
    bulk_ratify.add_argument(
        "--acknowledge-description-change",
        action="append",
        metavar="TOOL_NAME",
        default=[],
        help=(
            "acknowledge ONE tool's description delta after reading it verbatim "
            "(repeatable). Required per-tool; --yes alone never ratifies one."
        ),
    )
    bulk_ratify.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )
    bulk_ratify.add_argument(
        "--table-name", help="registry table (default: MCP_REGISTRY_TABLE_NAME env)"
    )

    snapshot = sub.add_parser(
        "snapshot",
        help="pure pre-admission discovery: capture a server's full live tool set to a file",
    )
    snapshot.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help="path to the image-baked AgentManifest YAML naming the server",
    )
    snapshot.add_argument(
        "--server-id",
        required=True,
        help="the mcp_servers entry to connect to (must be in --manifest)",
    )
    snapshot.add_argument(
        "--out", required=True, metavar="PATH", help="path to write the McpServerSnapshot JSON"
    )

    show = sub.add_parser(
        "show", help="read-only: print one stored registry row, human-readable"
    )
    _add_coordinate_args(show)

    diff = sub.add_parser(
        "diff",
        help="read-only: compare a snapshot against the stored rows for its server",
    )
    diff.add_argument(
        "--snapshot",
        required=True,
        metavar="PATH",
        help="path to an McpServerSnapshot JSON (from `snapshot`); server_id comes from it",
    )
    diff.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help=(
            "path to the image-baked AgentManifest YAML declaring the snapshot's "
            "server (same manifest `snapshot` used) — names the declared tool "
            "namespace, the WITHDRAWN-detection universe (no server-wide store listing exists)"
        ),
    )
    diff.add_argument(
        "--table-name",
        help="registry table (default: MCP_REGISTRY_TABLE_NAME env)",
    )

    return parser.parse_args(argv)


def _resolve_table_name(table_name: str | None) -> str:
    """The registry table: explicit --table-name, else MCP_REGISTRY_TABLE_NAME.

    Refuses (BrokerConfigError → exit 2 via main) when neither is set — the
    ceremony writes to the real table, so a missing name is a clean operator
    refusal, never the raw KeyError DynamoToolRegistry would raise at first use.
    """
    resolved = table_name or os.environ.get("MCP_REGISTRY_TABLE_NAME")
    if not resolved:
        raise BrokerConfigError(
            "MCP registry table not set: pass --table-name or set "
            "MCP_REGISTRY_TABLE_NAME"
        )
    return resolved


def _resolve_hmac_key() -> bytes:
    """The store-integrity HMAC key from BROKER_HMAC_KEY — NAMED, never defaulted.

    The admission ceremony ALWAYS writes to the real registry table, so it must
    name the key (mirrors grants/_commands_common._build_proposal_store and
    runner._build_stores) — it must NOT route through the broker's read-side
    resolve_hmac_key, whose fixed dev-key fallback fires whenever BROKER_STORE is
    not 'dynamo'. That fallback would HMAC rows under the dev key while the
    ceremony writes the real table; the broker then quarantines them under its
    own key and the coordinate is wedged. Refuse instead (#205;
    docs/config-provenance.md)."""
    hmac_key = os.environ.get("BROKER_HMAC_KEY", "").encode()
    if not hmac_key:
        raise BrokerConfigError(
            "BROKER_HMAC_KEY is required for the MCP admission ceremony and must "
            "match the key the broker reads with (else every admitted row "
            "quarantines on read); refusing to fall back to a dev HMAC key"
        )
    return hmac_key


def _build_stores(
    table_name: str | None,
) -> tuple[ToolRegistryStore, AdmissionProposalStore]:
    """The row/record registry + the proposal store, both under the NAMED HMAC
    key and NAMED backend — the ceremony writes the real store, so each must be
    operator-named, never a dev fallback (#205; docs/config-provenance.md).

    Backend follows the BROKER_STORE profile seam (product-wrapper Phase 1): on the sqlite
    arm the pair is sqlite-backed at the boot_config-resolved db path (the ONE
    db-path seam); on every other arm the pair is DynamoDB at the named table,
    byte-for-byte the pre-sqlite behavior. The HMAC key stays ceremony-named on
    BOTH arms — a durable local store's tamper evidence is only as real as its
    key discipline."""
    hmac_key = _resolve_hmac_key()
    if resolve_store_arm() == "sqlite":
        # The pair straddles the #203 split: the registry owns TOOLDEF#/TOOLREC#
        # (checker-writable) while the proposal store owns TOOLPROP# (written by
        # BOTH halves — the checker proposes too), so they no longer share a
        # path. Their two writes were never one transaction (consume_proposal
        # and admit_tool_with_record are separate calls), so nothing is lost.
        return (
            SqliteToolRegistry(hmac_key, **sqlite_grants_open_options()),
            SqliteAdmissionProposalStore(hmac_key, resolve_sqlite_db_path()),
        )
    resolved_table = _resolve_table_name(table_name)
    return (
        DynamoToolRegistry(hmac_key=hmac_key, table_name=resolved_table),
        DynamoAdmissionProposalStore(hmac_key=hmac_key, table_name=resolved_table),
    )


def _build_registry_store(table_name: str | None) -> ToolRegistryStore:
    """The registry store alone (no proposal store) — for the read-only
    `show`/`diff` commands, which never touch a proposal. Same NAMED HMAC key
    / backend discipline as `_build_stores` (#205): both commands read the real
    registry store, so a missing name/key is a clean refusal, never a dev
    fallback."""
    hmac_key = _resolve_hmac_key()
    if resolve_store_arm() == "sqlite":
        return SqliteToolRegistry(hmac_key, **sqlite_grants_open_options())
    resolved_table = _resolve_table_name(table_name)
    return DynamoToolRegistry(hmac_key=hmac_key, table_name=resolved_table)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        # `snapshot` is pure pre-admission discovery — it builds NO store (no
        # HMAC key, no table name); admit-propose/admit-ratify build the store(s)
        # they need, per-command, byte-for-byte their pre-existing refuse-hard
        # behavior (a missing BROKER_HMAC_KEY/table name still exits 2 below).
        if args.command == "snapshot":
            return snapshot_command(args)
        if args.command == "show":
            return show_command(args, store=_build_registry_store(args.table_name))
        if args.command == "diff":
            return diff_command(args, store=_build_registry_store(args.table_name))
        if args.command == "admit-propose":
            store, proposal_store = _build_stores(args.table_name)
            return admit_propose_command(args, store=store, proposal_store=proposal_store)
        if args.command == "bulk-propose":
            store, proposal_store = _build_stores(args.table_name)
            return bulk_propose_command(args, store=store, proposal_store=proposal_store)
        if args.command == "bulk-ratify":
            store, proposal_store = _build_stores(args.table_name)
            return bulk_ratify_command(
                args,
                store=store,
                proposal_store=proposal_store,
                signer=resolve_record_signer(zone=args.zone),
            )
        if args.command == "admit-reject":
            # No registry store and no signer: rejection burns a proposal, it
            # never touches a row or the ledger.
            _store, proposal_store = _build_stores(args.table_name)
            return admit_reject_command(args, proposal_store=proposal_store)
        # admit-ratify
        store, proposal_store = _build_stores(args.table_name)
        return admit_ratify_command(
            args,
            store=store,
            proposal_store=proposal_store,
            signer=resolve_record_signer(zone=args.zone),
        )
    except (IssuerSigningConfigError, BrokerConfigError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
