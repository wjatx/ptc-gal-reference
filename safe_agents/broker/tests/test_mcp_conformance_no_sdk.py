"""SDK-free half of the MCP host conformance suite (#174, #219 Leg-1 rider).

MCP-HOST.md's conformance suite splits across two files. This module
holds the clauses with ZERO `mcp`-SDK dependency — the schema, registry,
ceremony, manifest, and taint-runtime seams — so they run even when the
optional `mcp` extra is not installed. The SDK-backed clauses (M2-M5, the
live-server half of M13, and the host/connector integration mechanics) stay in
`test_mcp_host.py`, gated behind its module-level `pytest.importorskip("mcp")`.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from contextlib import asynccontextmanager

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.record_signing import signer_from_pem
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.mcp import client as _client_mod
from safe_agents.broker.mcp import commands as _mcp_commands
from safe_agents.broker.mcp.commands import (
    _parse_args,
    admit_propose_command,
    admit_ratify_command,
)
from safe_agents.broker.mcp.discovery import RegistryRead, ToolState, evaluate_discovery
from safe_agents.broker.mcp.factory import McpChildDeathError
from safe_agents.broker.mcp.host import McpHost
from safe_agents.broker.mcp.proposals import KIND_ADMISSION, MemoryAdmissionProposalStore
from safe_agents.broker.mcp.registry import MemoryToolRegistry, QuarantinedToolRowError
from safe_agents.broker.mcp.signing import verify_admission_record, canonical_record_payload
from safe_agents.broker.prototype.mcp_construction import (
    McpConstructionError,
    build_mcp_connectors,
    compose_child_env,
    compose_headers,
    native_mcp_server_ids,
)
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
)
from safe_agents.broker.runtime.connector import AssumedRoleCredential
from safe_agents.broker.runtime.credentials import StaticSecret
from safe_agents.broker.schemas import (
    AgentManifest,
    ConnectorAuth,
    Envelope,
    HeaderSource,
    ToolOp,
)
from safe_agents.broker.schemas.mcp_registry import (
    McpServerDecl,
    McpToolDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
    run_threaded_turn,
)
from safe_agents.channels.keys import key_resolver_from_map
from safe_agents.connectors.mcp_connector import McpConnector

_SERVER_ID = "calc"
_ADMITTED_BY = "arn:aws:sts::000000000000:assumed-role/Admitter/test"
_ADMITTED_AT = "2026-07-17T00:00:00Z"

# Ceremony coordinate + identities (M7/M8) — distinct STS ARNs so maker != checker.
_MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/maker-session"
_CHECKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/checker-session"
_CEREMONY_TOOL = "add"


def _mcp_tool_def(description: str = "Add two integers.") -> McpToolDef:
    """A McpToolDef for the ceremony coordinate (no live server needed)."""
    return McpToolDef(
        server_id=_SERVER_ID,
        tool_name=_CEREMONY_TOOL,
        input_schema={"type": "object", "properties": {"a": {"type": "integer"}}},
        description=description,
    )


def _keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        sk.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv, pub


def _signer_and_resolver():
    priv, pub = _keypair()
    return signer_from_pem("issuer:A", "zone-a", priv), key_resolver_from_map({"issuer:A": pub})


def _set_caller(monkeypatch, arn: str) -> None:
    monkeypatch.setattr(_mcp_commands, "_caller_identity", lambda session=None: arn)


def _propose_argv(tool_def_path) -> list[str]:
    return _parse_args(
        [
            "admit-propose",
            "--server-id", _SERVER_ID,
            "--tool-name", _CEREMONY_TOOL,
            "--tool-def-json", str(tool_def_path),
            "--kind", KIND_ADMISSION,
            "--ttl-hours", "1",
        ]
    )


def _ratify_argv(proposal_id: str) -> list[str]:
    return _parse_args(
        [
            "admit-ratify",
            "--server-id", _SERVER_ID,
            "--tool-name", _CEREMONY_TOOL,
            "--proposal-id", proposal_id,
            "--zone", "zone-a",
        ]
    )


def _write_def(tmp_path, tool_def: McpToolDef):
    path = tmp_path / "tool_def.json"
    path.write_text(tool_def.model_dump_json())
    return path


def _run_propose(proposal_store, monkeypatch, tool_def_path, *, caller: str) -> str:
    _set_caller(monkeypatch, caller)
    before = set(proposal_store._items.keys())
    # `store` is read-only here: propose renders the admitted-vs-proposed review
    # diff before writing. A fresh empty registry renders the first-admission
    # branch, which is what these conformance rows exercise.
    assert admit_propose_command(
        _propose_argv(tool_def_path),
        store=MemoryToolRegistry(),
        proposal_store=proposal_store,
    ) == 0
    new = set(proposal_store._items.keys()) - before
    assert len(new) == 1
    return next(iter(new))[2]  # (server_id, tool_name, proposal_id)


# ---------------------------------------------------------------------------
# M9/M10 — full-runtime taint driver (real BrokerRuntime + PEP self-ingest).
# ---------------------------------------------------------------------------

_TAINT_READ_SOURCE = f"connector:{_SERVER_ID}.add"


class _FakeMcpTaintHost:
    """A stand-in McpHost the real ``McpConnector`` wraps: no live session, an
    async ``call`` that returns a value. The taint self-ingest keys on the
    (tool, op, external-read) coordinate, NOT the transport — so a fake host
    exercises the real M9 mechanism end-to-end without an MCP session that
    could not survive the sync runtime's per-call ``asyncio.run`` loop switch."""

    def __init__(self, server_id: str) -> None:
        self.server_id = server_id

    async def call(self, tool_name, arguments=None):
        return {"tool": tool_name, "args": arguments}


class _FakeWriteConnector:
    """A minimal external-write connector (notify.send) for the follow-on write."""

    def execute(self, tool: str, op: str, args, credential: str):
        return {"tool": tool, "op": op, "sent": True}


def _taint_runtime(sink, *, trusted_read_sources=None):
    """A BrokerRuntime whose optable classifies the MCP tool as an external READ
    and notify.send as an external WRITE, with the real ``McpConnector`` bound."""
    optable = ToolOpTable(
        [
            ToolOp(tool=_SERVER_ID, op="add", effect="read", external=True),
            ToolOp(tool="notify", op="send", effect="write", external=True, reversible=True),
        ]
    )
    doer = Doer(
        connectors={
            _SERVER_ID: McpConnector(_FakeMcpTaintHost(_SERVER_ID)),  # type: ignore[arg-type]
            "notify": _FakeWriteConnector(),
        },
        secrets=FakeSecretsProvider({_SERVER_ID: "", "notify": "test-notify-credential"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant(f"{_SERVER_ID}.add"), make_grant("notify.send")],
        optable=optable,
        doer=doer,
        pip=make_pip(grant_present=True),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
        trusted_read_sources=trusted_read_sources,
    )


# ---------------------------------------------------------------------------
# M1 — hash covers every advertised field (#223).
# ---------------------------------------------------------------------------


def test_m1_every_advertised_metadata_field_affects_the_hash():
    """M1 (#223): the signed set is every ADVERTISED field. Populating any
    metadata field — including the server's own danger claim in `annotations`,
    which pre-#223 was carried but NOT signed — must change the digest, so a
    metadata change (an annotation flip, a rewritten output schema) is drift
    and fails closed like a schema or description change."""
    bare = _mcp_tool_def()
    populated = bare.model_copy(
        update={
            "title": "Weather Forecast",
            "output_schema": {"type": "object", "properties": {"tempF": {"type": "number"}}},
            "icons": [{"src": "https://example.invalid/i.png"}],
            "annotations": {"readOnlyHint": False, "destructiveHint": True},
            "meta": {"vendorBuild": "2026.07.19"},
            "execution": {"mode": "sync"},
        }
    )
    assert compute_tool_def_hash(populated) != compute_tool_def_hash(bare)
    for field_name in ("title", "output_schema", "icons", "annotations", "meta", "execution"):
        single = bare.model_copy(update={field_name: getattr(populated, field_name)})
        assert compute_tool_def_hash(single) != compute_tool_def_hash(bare), field_name


def test_m1_hash_covers_exactly_the_advertised_fields():
    """M1 (#223): the discovery-hash is sha256 over canonical JSON (sorted
    keys, compact separators, ASCII) of every advertised field — a None
    (not-advertised) field contributes NOTHING to the preimage. Consequences,
    both deliberate: a definition advertising no metadata hashes byte-identically
    to the pre-#223 four-field basis (the far-jump falls only where new signed
    material exists), and future additive `McpToolDef` growth moves no hash
    until a server advertises the new field — while a field APPEARING is
    itself drift."""
    tool_def = _mcp_tool_def()
    # Recompute independently over the advertised set with the documented
    # canonicalization; equality proves both the field set and the encoding.
    canonical = json.dumps(
        {
            "server_id": tool_def.server_id,
            "tool_name": tool_def.tool_name,
            "input_schema": tool_def.input_schema,
            "description": tool_def.description,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # A metadata-less definition's preimage is exactly the four core keys —
    # the legacy-equivalence property.
    assert compute_tool_def_hash(tool_def) == expected

    # An advertised field joins the preimage: independent recompute with the
    # annotations included matches, proving nothing else rode along.
    annotated = tool_def.model_copy(update={"annotations": {"readOnlyHint": True}})
    canonical_annotated = json.dumps(
        {
            "server_id": tool_def.server_id,
            "tool_name": tool_def.tool_name,
            "input_schema": tool_def.input_schema,
            "description": tool_def.description,
            "annotations": {"readOnlyHint": True},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    assert (
        compute_tool_def_hash(annotated)
        == hashlib.sha256(canonical_annotated.encode("utf-8")).hexdigest()
    )

    # ASCII canonicalization — a non-ASCII description is escaped, not raw bytes.
    unicode_def = _mcp_tool_def(description="précis — sneaky")
    assert "\\u" in json.dumps(
        {"description": unicode_def.description}, ensure_ascii=True
    )
    assert compute_tool_def_hash(unicode_def) != compute_tool_def_hash(tool_def)


# ---------------------------------------------------------------------------
# M6 — a quarantined row is never auto-overwritten.
# ---------------------------------------------------------------------------


def test_m6_quarantined_row_never_auto_overwritten():
    """M6: once a registry row is HMAC-quarantined it is never silently
    re-admitted or written over; only a fresh human ceremony resolves it —
    admit_tool refuses (QuarantinedToolRowError)."""
    registry = MemoryToolRegistry()
    row = RegisteredTool(
        tool_def=_mcp_tool_def(),
        def_hash=compute_tool_def_hash(_mcp_tool_def()),
        status=RegistryStatus.ACTIVE,
        admitted_by=_ADMITTED_BY,
        admitted_at=_ADMITTED_AT,
    )
    registry.admit_tool(row)
    # Tamper the item-level rowHash (#246) -> the item reads back quarantined.
    registry._rows[(_SERVER_ID, _CEREMONY_TOOL)]["rowHash"] = "tampered"
    tampered_before = dict(registry._rows[(_SERVER_ID, _CEREMONY_TOOL)])

    # A second admit is refused — the tampered state is NEVER laundered under a
    # fresh valid HMAC.
    revet = row.model_copy(
        update={"tool_def": _mcp_tool_def(description="a re-vet attempt")}
    )
    with pytest.raises(QuarantinedToolRowError):
        registry.admit_tool(revet)
    # The item on disk is untouched by the refused write.
    assert registry._rows[(_SERVER_ID, _CEREMONY_TOOL)] == tampered_before


# ---------------------------------------------------------------------------
# M7 — admission requires two distinct credential identities.
# ---------------------------------------------------------------------------


def test_m7_admission_refuses_same_identity(monkeypatch, tmp_path):
    """M7: the admission ceremony compares the maker's and checker's actual
    credential identities (STS ARNs) and refuses when they are the same —
    self-admission is structurally impossible."""
    store = MemoryToolRegistry()
    proposal_store = MemoryAdmissionProposalStore()
    signer, _ = _signer_and_resolver()
    path = _write_def(tmp_path, _mcp_tool_def())

    proposal_id = _run_propose(proposal_store, monkeypatch, path, caller=_MAKER_ARN)
    _set_caller(monkeypatch, _MAKER_ARN)  # maker == checker
    rc = admit_ratify_command(
        _ratify_argv(proposal_id), store=store, proposal_store=proposal_store, signer=signer
    )
    assert rc == 1
    # Nothing minted: no row, and the proposal stays pending (never consumed).
    assert store.get_tool(_SERVER_ID, _CEREMONY_TOOL).tool is None
    _, status = proposal_store.get_proposal(_SERVER_ID, _CEREMONY_TOOL, proposal_id)
    assert status == "pending"


# ---------------------------------------------------------------------------
# M8 — admission record is DSSE-signed and verifiable.
# ---------------------------------------------------------------------------


def test_m8_admission_record_is_signed_and_verifiable(monkeypatch, tmp_path):
    """M8: each admission appends an append-only, issuer-DSSE-signed record
    binding admitter + (server_id, tool_name) + admitted-hash, verifiable against
    the issuer public key."""
    store = MemoryToolRegistry()
    proposal_store = MemoryAdmissionProposalStore()
    signer, resolver = _signer_and_resolver()
    tool_def = _mcp_tool_def()
    path = _write_def(tmp_path, tool_def)

    proposal_id = _run_propose(proposal_store, monkeypatch, path, caller=_MAKER_ARN)
    _set_caller(monkeypatch, _CHECKER_ARN)
    assert admit_ratify_command(
        _ratify_argv(proposal_id), store=store, proposal_store=proposal_store, signer=signer
    ) == 0

    records = store.list_records(_SERVER_ID, _CEREMONY_TOOL)
    assert len(records) == 1
    record = records[0]
    # Binds who + what + which admitted hash.
    assert record.serverId == _SERVER_ID and record.toolName == _CEREMONY_TOOL
    assert record.proposedBy == _MAKER_ARN and record.ratifiedBy == _CHECKER_ARN
    assert record.defHash == compute_tool_def_hash(tool_def)
    # The DSSE envelope verifies against the issuer public key.
    envelope = store.get_record_signature(_SERVER_ID, _CEREMONY_TOOL, record.ts)
    assert verify_admission_record(canonical_record_payload(record), envelope, resolver).ok
    # A different issuer key does NOT verify — the signature is genuinely bound.
    _, wrong_pub = _keypair()
    assert not verify_admission_record(
        canonical_record_payload(record), envelope, key_resolver_from_map({"issuer:A": wrong_pub})
    ).ok


def test_m8_admission_without_signer_is_refused(monkeypatch, tmp_path):
    """M8 (fail-closed half): an admission mints callability, so a missing issuer
    signer REFUSES rather than degrading to an unsigned record — nothing written."""
    store = MemoryToolRegistry()
    proposal_store = MemoryAdmissionProposalStore()
    path = _write_def(tmp_path, _mcp_tool_def())

    proposal_id = _run_propose(proposal_store, monkeypatch, path, caller=_MAKER_ARN)
    _set_caller(monkeypatch, _CHECKER_ARN)
    rc = admit_ratify_command(
        _ratify_argv(proposal_id), store=store, proposal_store=proposal_store, signer=None
    )
    assert rc == 1
    assert store.get_tool(_SERVER_ID, _CEREMONY_TOOL).tool is None
    assert store.list_records(_SERVER_ID, _CEREMONY_TOOL) == []


# ---------------------------------------------------------------------------
# M9 — response taints the turn by default.
# ---------------------------------------------------------------------------


def test_m9_response_taints_turn_by_default():
    """M9: an MCP tool response self-ingests as taint with source id
    connector:<server_id>.<tool_name>, so a later external write on the SAME turn
    rides the standing tainted_external_write cut (escalates to require_approval).

    Full-runtime level: real BrokerRuntime + real PEP self-ingest hook + real
    McpConnector dispatch; only the MCP transport is a fake host (the transport
    is not what M9 governs)."""
    sink = InMemorySink()
    runtime = _taint_runtime(sink)  # default: no trusted_read_sources

    read_resp, write_resp, ctx = run_threaded_turn(
        runtime,
        AgentRequest(tool=_SERVER_ID, op="add", args={"a": 1, "b": 2}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
        ingested_sources_1=None,  # the self-ingest hook is the ONLY taint source
    )

    assert read_resp.decision_kind == "allow"  # the MCP read executed normally
    assert write_resp.decision_kind == "require_approval"  # escalated by the taint
    assert ctx.tainted is True
    assert _TAINT_READ_SOURCE in ctx.to_taint().sources


# ---------------------------------------------------------------------------
# M10 — a trusted structured tool skips taint.
# ---------------------------------------------------------------------------


def test_m10_trusted_structured_tool_skips_taint():
    """M10: a trusted_read_sources entry for a tool declared structured_output:
    true suppresses that tool's response taint; the entry is honored only for
    structured tools.

    The trusted source is derived from a manifest that declares the tool
    structured_output=True — so this proves BOTH that a structured tool's trust
    survives manifest load (the structured-only gate, M11's converse) AND that it
    then suppresses the self-ingest at runtime."""
    manifest = AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain", "trusted_read_sources": [_TAINT_READ_SOURCE]},
            "tool_ops": [
                {"tool": _SERVER_ID, "op": "add", "effect": "read", "external": True},
                {"tool": "notify", "op": "send", "effect": "write",
                 "external": True, "reversible": True},
            ],
            "mcp_servers": {
                _SERVER_ID: {"tools": [{"tool_name": "add", "structured_output": True}]}
            },
        }
    )
    trusted = manifest.envelope.trusted_read_sources
    assert trusted == [_TAINT_READ_SOURCE]  # survived the structured-only gate

    sink = InMemorySink()
    runtime = _taint_runtime(sink, trusted_read_sources=trusted)

    read_resp, write_resp, ctx = run_threaded_turn(
        runtime,
        AgentRequest(tool=_SERVER_ID, op="add", args={"a": 1, "b": 2}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    )

    assert read_resp.decision_kind == "allow"
    # Trusted read did not taint -> the follow-on write is NOT escalated.
    assert write_resp.decision_kind == "allow"
    assert ctx.tainted is False
    assert _TAINT_READ_SOURCE not in ctx.to_taint().sources


# ---------------------------------------------------------------------------
# M11 — trust on a free-text tool is refused at load.
# ---------------------------------------------------------------------------


def test_m11_trust_on_free_text_tool_refused_at_load():
    """M11: a trusted_read_sources entry naming a tool without a structured
    output schema is rejected during manifest build, never at call time."""
    base = {
        "envelope": {"polarity": "abstain", "trusted_read_sources": [_TAINT_READ_SOURCE]},
        "tool_ops": [{"tool": _SERVER_ID, "op": "add", "effect": "read", "external": True}],
    }
    # Free-text tool (structured_output defaults False) -> refused at load.
    with pytest.raises(ValueError, match="structured_output=false"):
        AgentManifest.model_validate(
            {**base, "mcp_servers": {_SERVER_ID: {"tools": [{"tool_name": "add"}]}}}
        )
    # Control: the identical manifest with structured_output=True loads — proving
    # it is the free-text-ness, not the trust entry itself, that is refused.
    ok = AgentManifest.model_validate(
        {
            **base,
            "mcp_servers": {
                _SERVER_ID: {"tools": [{"tool_name": "add", "structured_output": True}]}
            },
        }
    )
    assert ok.envelope.trusted_read_sources == [_TAINT_READ_SOURCE]


# ---------------------------------------------------------------------------
# M12 — the response screen ships OFF (proven structurally, by absence).
# ---------------------------------------------------------------------------


def test_m12_response_screen_ships_off_structurally():
    """M12: with no screen configured, responses taint and nothing is screened;
    the screen is an Envelope knob defaulting off.

    No response-screen mechanism exists in code — it was deliberately not built.
    We prove the DEFAULT is off STRUCTURALLY (absence): no schema exposes an
    enabled-by-default screen field, and the host path takes no screen parameter,
    so there is nothing to perform a screening call. (The knob's future home is
    Envelope — see MCP-HOST.md; do NOT build a screen to satisfy this test.)"""
    # No screen field on the response/registry schemas...
    assert not any("screen" in f.lower() for f in Envelope.model_fields)
    assert not any("screen" in f.lower() for f in McpServerDecl.model_fields)
    assert not any("screen" in f.lower() for f in McpToolDecl.model_fields)
    assert not any("screen" in f.lower() for f in McpToolDef.model_fields)
    # ...and the host constructs no screen seam (no screen parameter to enable).
    host_params = inspect.signature(McpHost.__init__).parameters
    assert not any("screen" in p.lower() for p in host_params)
    # The consequence — "responses taint and nothing is screened" — is the M9
    # outcome: with nothing configured the response tainted the turn, unfiltered.


# ---------------------------------------------------------------------------
# M13 — registry rows are HMAC-integrity-protected (pure-gate half).
# ---------------------------------------------------------------------------


def test_m13_quarantined_read_is_uncallable_through_pure_gate():
    """M13 (seam): a RegistryRead flagged hmac_quarantined is rendered QUARANTINED
    and uncallable by the pure discovery gate — the store's HMAC verdict is what
    the evaluator honors, independent of the live transport."""
    tool_def = _mcp_tool_def()
    row = RegisteredTool(
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        status=RegistryStatus.ACTIVE,  # status is fine — only the HMAC failed
        admitted_by=_ADMITTED_BY,
        admitted_at=_ADMITTED_AT,
    )
    result = evaluate_discovery(
        manifest_decl={_SERVER_ID: McpServerDecl(tools=[McpToolDecl(tool_name=_CEREMONY_TOOL)])},
        registry_reads={
            (_SERVER_ID, _CEREMONY_TOOL): RegistryRead(row=row, hmac_quarantined=True)
        },
        advertised=[tool_def],
    )
    verdict = next(v for v in result.verdicts if v.tool_name == _CEREMONY_TOOL)
    assert verdict.state is ToolState.QUARANTINED
    assert not result.is_callable(_SERVER_ID, _CEREMONY_TOOL)


# ---------------------------------------------------------------------------
# M14-M16 — native construction + spawn-time env (#221)
# ---------------------------------------------------------------------------


def _spawnable_manifest_dict(**overrides) -> dict:
    """A manifest whose one MCP server declares native spawn config."""
    base = {
        "envelope": {"polarity": "abstain"},
        "connectors": [_SERVER_ID],
        "tool_ops": [
            {"tool": _SERVER_ID, "op": _CEREMONY_TOOL, "effect": "read", "external": True},
        ],
        "mcp_servers": {
            _SERVER_ID: {
                "tools": [{"tool_name": _CEREMONY_TOOL}],
                "command": "calc-mcp-server",
                "env": {"CALC_MODE": "safe"},
            }
        },
    }
    base.update(overrides)
    return base


class _CountingSecrets:
    """A secrets provider that counts fetches (and can serve one canned leaf)."""

    def __init__(self, value: str = "{}") -> None:
        self.fetches = 0
        self._value = value

    def fetch_secret(self, name: str) -> str:
        self.fetches += 1
        return self._value


def test_m14_spawn_config_is_image_baked_only():
    """M14: the spawn block is manifest-only — the store-loaded Envelope has no
    mcp/spawn-shaped field, and a poisoned envelope carrying one fails validation
    (extra=forbid) before it could reach anything."""
    forbidden = ("mcp", "command", "spawn")
    hits = [
        f for f in Envelope.model_fields if any(word in f.lower() for word in forbidden)
    ]
    assert not hits, (
        f"Envelope grew spawn-shaped fields {hits}; the store-loaded envelope must "
        "never carry code-execution config"
    )
    with pytest.raises(ValueError):
        Envelope.model_validate(
            {
                "polarity": "abstain",
                "mcp_servers": {"evil": {"command": "curl", "args": ["evil.sh"]}},
            }
        )


def test_m15_spawnable_not_wired_in_connectors_refuses():
    """M15: a spawn block nothing wires is dead config — refused at manifest load."""
    with pytest.raises(ValueError, match="not named in 'connectors'"):
        AgentManifest.model_validate(_spawnable_manifest_dict(connectors=[]))


def test_m15_spawnable_colliding_with_provider_refuses():
    """M15: two construction paths for one name is ambiguous — refused at load."""
    with pytest.raises(ValueError, match="two construction paths"):
        AgentManifest.model_validate(
            _spawnable_manifest_dict(
                connector_providers={_SERVER_ID: "pkg.module:CalcConnector"}
            )
        )


def test_m15_spawnable_without_registry_table_refuses(monkeypatch):
    """M15: no named admitted-tool registry -> refuse at build, never a dead
    connector (every tool would be DECLARED-only and uncallable)."""
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    manifest = AgentManifest.model_validate(_spawnable_manifest_dict())
    with pytest.raises(McpConstructionError, match="MCP_REGISTRY_TABLE_NAME"):
        build_mcp_connectors(
            manifest,
            secrets=_CountingSecrets(),
            credential_strategies={},
            secret_name_for=lambda tool: tool,
        )


def test_m15_construction_is_lazy_and_fetches_no_secret_at_build(monkeypatch):
    """M15/C9: with the registry named, construction succeeds AWS-free and
    resolves NO credential at build — spawn-time resolution is lazy (first
    dispatch on the connector's loop), so boot fetches nothing."""
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "test-mcp-registry")
    manifest = AgentManifest.model_validate(
        _spawnable_manifest_dict(
            connector_auth={_SERVER_ID: {"env_map": {"CALC_API_KEY": "KEY"}}}
        )
    )
    secrets = _CountingSecrets()
    connectors = build_mcp_connectors(
        manifest,
        secrets=secrets,
        credential_strategies={},
        secret_name_for=lambda tool: tool,
    )
    assert set(connectors) == {_SERVER_ID}
    assert isinstance(connectors[_SERVER_ID], McpConnector)
    assert secrets.fetches == 0, "construction must not resolve any credential"


def test_m15_namespace_only_manifest_builds_nothing(monkeypatch):
    """A namespace-only declaration (no command) is not native — pre-#221 shape."""
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    manifest = AgentManifest.model_validate(
        _spawnable_manifest_dict(
            connectors=[],
            mcp_servers={_SERVER_ID: {"tools": [{"tool_name": _CEREMONY_TOOL}]}},
        )
    )
    assert native_mcp_server_ids(manifest) == frozenset()
    assert (
        build_mcp_connectors(
            manifest,
            secrets=_CountingSecrets(),
            credential_strategies={},
            secret_name_for=lambda tool: tool,
        )
        == {}
    )


def test_m16_env_map_renames_and_allowlists():
    """M16: mapped fields are renamed to the declared child vars; UNMAPPED
    credential fields never reach the child (explicit allowlist)."""
    credential = json.dumps({"KEY": "k-123", "SECRET": "s-456", "EXTRA": "never"})
    env = compose_child_env(
        "calc",
        {"CALC_MODE": "safe"},
        {"CALC_API_KEY": "KEY", "CALC_SECRET_KEY": "SECRET"},
        credential,
    )
    assert env == {
        "CALC_MODE": "safe",
        "CALC_API_KEY": "k-123",
        "CALC_SECRET_KEY": "s-456",
    }
    assert "never" not in env.values()


def test_m16_missing_credential_field_refuses():
    with pytest.raises(McpConstructionError, match="no field 'KEY'"):
        compose_child_env("calc", {}, {"CALC_API_KEY": "KEY"}, json.dumps({"OTHER": "x"}))


def test_m16_non_json_credential_refuses():
    with pytest.raises(McpConstructionError, match="not valid JSON"):
        compose_child_env("calc", {}, {"CALC_API_KEY": "KEY"}, "not-json")


def test_m16_non_string_credential_bundle_refuses():
    """An assumed_role-style bundle has no env-injection shape — refuse, never
    coerce."""
    with pytest.raises(McpConstructionError, match="string credential"):
        compose_child_env("calc", {}, {"CALC_API_KEY": "KEY"}, object())


def test_m16_non_flat_credential_refuses():
    with pytest.raises(McpConstructionError, match="FLAT JSON string map"):
        compose_child_env(
            "calc", {}, {"CALC_API_KEY": "KEY"}, json.dumps({"KEY": {"nested": "x"}})
        )


def test_m16_collision_with_static_env_refuses_at_compose():
    """Belt: even bypassing the manifest validator, the pure compose refuses an
    env_map target already present in the static half."""
    with pytest.raises(McpConstructionError, match="collides"):
        compose_child_env(
            "calc", {"CALC_API_KEY": "static"}, {"CALC_API_KEY": "KEY"},
            json.dumps({"KEY": "k"}),
        )


def test_m16_halves_disjoint_at_manifest_load():
    """M16: the statically-checkable collision refuses at manifest load."""
    with pytest.raises(ValueError, match="must be disjoint"):
        AgentManifest.model_validate(
            _spawnable_manifest_dict(
                connector_auth={_SERVER_ID: {"env_map": {"CALC_MODE": "KEY"}}}
            )
        )


def test_m16_empty_env_map_resolves_no_credential():
    """With env_map absent the spawn env is the static half alone — no
    credential is resolved at all (a credential-less server costs nothing)."""
    env = compose_child_env("calc", {"CALC_MODE": "safe"}, {}, None)
    assert env == {"CALC_MODE": "safe"}


# ---------------------------------------------------------------------------
# M25 / C10 — per-connect header injection for a remote server (#237)
# ---------------------------------------------------------------------------


def test_m25_scheme_frames_a_bare_string_credential():
    """C10: the common shape — one bare-string credential framed by an
    auth-scheme. The scheme is a validated token, never a template, so the
    only thing interpolated into the header value is the credential itself."""
    headers = compose_headers(
        "quotes", {"Authorization": HeaderSource(scheme="Bearer")}, "tok-123"
    )
    assert headers == {"Authorization": "Bearer tok-123"}


def test_m25_absent_scheme_renders_the_credential_verbatim():
    """A server whose header carries the raw key (`X-API-Key: k-1`) must not
    have a scheme invented for it — an unrequested prefix would be delivered
    as part of the credential and fail at the vendor as an opaque 401."""
    headers = compose_headers("quotes", {"X-API-Key": HeaderSource()}, "k-1")
    assert headers == {"X-API-Key": "k-1"}


def test_m25_field_map_renames_and_allowlists():
    """C10's allowlist property, the exact mirror of C9's: a multi-key server
    needs no consumer code, and a credential field NO header names never
    leaves the broker — the map is what crosses, not the credential."""
    credential = json.dumps({"KEY": "k-123", "CLIENT": "c-456", "EXTRA": "never"})
    headers = compose_headers(
        "quotes",
        {
            "X-API-Key": HeaderSource(field="KEY"),
            "X-Client-Id": HeaderSource(field="CLIENT"),
        },
        credential,
    )
    assert headers == {"X-API-Key": "k-123", "X-Client-Id": "c-456"}
    assert not any("never" in value for value in headers.values())


def test_m25_missing_credential_field_refuses():
    """Fail toward NOT connecting: a half-populated header set authenticates
    as nothing and surfaces at the vendor as an opaque 401, so refuse here
    where the misconfiguration can be named."""
    with pytest.raises(McpConstructionError, match="no field 'KEY'"):
        compose_headers(
            "quotes", {"X-API-Key": HeaderSource(field="KEY")}, json.dumps({"OTHER": "x"})
        )


def test_m25_non_json_credential_under_field_map_refuses():
    with pytest.raises(McpConstructionError, match="not valid JSON"):
        compose_headers("quotes", {"X-API-Key": HeaderSource(field="KEY")}, "not-json")


def test_m25_non_string_credential_bundle_refuses():
    """An assumed_role bundle has no header-injection shape — refuse, never
    coerce it to a string (a `str()` of the bundle would put credential-shaped
    text on the wire)."""
    bundle = AssumedRoleCredential(
        access_key_id="AKIA-test", secret_access_key="secret", session_token="token"
    )
    with pytest.raises(McpConstructionError, match="string credential"):
        compose_headers("quotes", {"Authorization": HeaderSource(scheme="Bearer")}, bundle)


def test_m25_empty_header_map_renders_nothing():
    """An unauthenticated remote server costs nothing: with no map declared the
    pure renderer returns no headers and never touches the credential — which
    is what lets `build_mcp_connectors` skip resolution entirely."""
    assert compose_headers("quotes", {}, None) == {}


# ---------------------------------------------------------------------------
# M21 — native construction of remote (streamable-http) declarations (#221 P4)
# ---------------------------------------------------------------------------

_REMOTE_URL = "https://mcp.example.com/mcp"


def _remote_manifest_dict(**overrides) -> dict:
    """A manifest with one remote MCP server plus one namespace-only server."""
    base = {
        "envelope": {"polarity": "abstain"},
        "connectors": [_SERVER_ID],
        "tool_ops": [
            {"tool": _SERVER_ID, "op": _CEREMONY_TOOL, "effect": "read", "external": True},
            {"tool": "ns", "op": "lookup", "effect": "read", "external": True},
        ],
        "mcp_servers": {
            _SERVER_ID: {
                "transport": "streamable-http",
                "url": _REMOTE_URL,
                "tools": [{"tool_name": _CEREMONY_TOOL}],
            },
            "ns": {"tools": [{"tool_name": "lookup"}]},
        },
    }
    base.update(overrides)
    return base


def test_m21_native_ids_include_url_decl_and_exclude_namespace_only():
    """A url decl is natively constructed; a namespace-only decl (neither
    command nor url) stays the consumer's concern."""
    manifest = AgentManifest.model_validate(_remote_manifest_dict())
    assert native_mcp_server_ids(manifest) == frozenset({_SERVER_ID})


def test_m21_url_decl_builds_connector_that_connects_with_declared_url(monkeypatch):
    """M21: a url decl builds an McpConnector whose factory connects to the
    DECLARED url with headers=None and resolves NO credential — because this
    manifest declares no `header_map`. That is the unauthenticated remote case,
    and it must stay free: a server needing no credential must fetch no secret
    (the M25 counterpart is `test_m25_url_decl_with_header_map_...`). SDK-free:
    the fake `client.connect_streamable_http` records the connect args then
    dies, so nothing reaches the Dynamo-backed registry."""
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "test-mcp-registry")
    manifest = AgentManifest.model_validate(_remote_manifest_dict())
    secrets = _CountingSecrets()
    connectors = build_mcp_connectors(
        manifest,
        secrets=secrets,
        credential_strategies={},
        secret_name_for=lambda tool: tool,
    )
    assert set(connectors) == {_SERVER_ID}
    connector = connectors[_SERVER_ID]
    assert isinstance(connector, McpConnector)
    assert secrets.fetches == 0, "a remote decl must resolve no credential"

    connects: list[tuple] = []

    @asynccontextmanager
    async def fake_connect(server_id, url, *, headers=None):
        connects.append((server_id, url, headers))
        raise OSError("fake remote peer refused")
        yield  # pragma: no cover

    monkeypatch.setattr(_client_mod, "connect_streamable_http", fake_connect)

    async def scenario():
        with pytest.raises(McpChildDeathError):
            await connector._factory()

    asyncio.run(scenario())
    assert connects == [(_SERVER_ID, _REMOTE_URL, None)]


def test_m25_url_decl_with_header_map_connects_with_the_rendered_headers(monkeypatch):
    """M25/C10 end to end through construction: a manifest-declared header_map
    reaches the transport as RENDERED headers, resolved on the connector's own
    loop at connect. This is the clause the pure `compose_headers` tests cannot
    cover — a correct renderer wired to nothing delivers no credential, and the
    #221 drill's lesson is that a seam is proven per transport. SDK-free: the
    fake `client.connect_streamable_http` records the connect args then dies."""
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "test-mcp-registry")
    manifest = AgentManifest.model_validate(
        _remote_manifest_dict(
            connector_auth={
                _SERVER_ID: {"header_map": {"Authorization": {"scheme": "Bearer"}}}
            }
        )
    )
    connectors = build_mcp_connectors(
        manifest,
        secrets=FakeSecretsProvider({_SERVER_ID: "tok-123"}),
        credential_strategies={_SERVER_ID: StaticSecret()},
        secret_name_for=lambda tool: tool,
    )
    connects: list[tuple] = []

    @asynccontextmanager
    async def fake_connect(server_id, url, *, headers=None):
        connects.append((server_id, url, headers))
        raise OSError("fake remote peer refused")
        yield  # pragma: no cover

    monkeypatch.setattr(_client_mod, "connect_streamable_http", fake_connect)

    async def scenario():
        with pytest.raises(McpChildDeathError):
            await connectors[_SERVER_ID]._factory()

    asyncio.run(scenario())
    assert connects == [
        (_SERVER_ID, _REMOTE_URL, {"Authorization": "Bearer tok-123"})
    ]


def test_m25_remote_construction_is_lazy_and_fetches_no_secret_at_build(monkeypatch):
    """C10/M15: laziness holds on the remote path too — declaring a header_map
    must not pull the credential at boot. Per-CONNECT resolution is what makes
    a reconnect re-mint an expired token (M18); a build-time fetch would both
    break that and make an unused connector hold a live credential."""
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "test-mcp-registry")
    manifest = AgentManifest.model_validate(
        _remote_manifest_dict(
            connector_auth={
                _SERVER_ID: {"header_map": {"Authorization": {"scheme": "Bearer"}}}
            }
        )
    )
    secrets = _CountingSecrets("tok-123")
    connectors = build_mcp_connectors(
        manifest,
        secrets=secrets,
        credential_strategies={_SERVER_ID: StaticSecret()},
        secret_name_for=lambda tool: tool,
    )
    assert set(connectors) == {_SERVER_ID}
    assert isinstance(connectors[_SERVER_ID], McpConnector)
    assert secrets.fetches == 0, "a declared header_map must not resolve at build"


def test_m21_url_decl_without_registry_table_refuses(monkeypatch):
    """The M15 registry refusal fires for a url decl exactly as for stdio."""
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    manifest = AgentManifest.model_validate(_remote_manifest_dict())
    with pytest.raises(McpConstructionError, match="MCP_REGISTRY_TABLE_NAME"):
        build_mcp_connectors(
            manifest,
            secrets=_CountingSecrets(),
            credential_strategies={},
            secret_name_for=lambda tool: tool,
        )


def test_m21_belt_env_map_on_url_decl_refuses_at_build(monkeypatch):
    """Belt: even bypassing the manifest validator, construction refuses an
    env_map on a remote decl rather than silently dropping declared credential
    delivery (M21)."""
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "test-mcp-registry")
    manifest = AgentManifest.model_validate(_remote_manifest_dict())
    manifest.connector_auth = {_SERVER_ID: ConnectorAuth(env_map={"API_KEY": "KEY"})}
    with pytest.raises(McpConstructionError, match="remote"):
        build_mcp_connectors(
            manifest,
            secrets=_CountingSecrets(),
            credential_strategies={},
            secret_name_for=lambda tool: tool,
        )


# ---------------------------------------------------------------------------
# The /call wire boundary — a TYPED connector result must marshal to JSON.
# ---------------------------------------------------------------------------


def test_wire_result_marshals_typed_and_plain_results():
    """The MCP connector returns a pydantic-typed result (CallToolResult); the
    /call HTTP surface must marshal it to plain JSON — found live in the #221
    floor drill (the local proof drove handle_request in-process, so the wire
    had never carried an MCP result). SDK-free duck-typing: any model_dump-
    bearing result dumps; plain JSON values pass through unchanged."""
    from safe_agents.broker.prototype.broker_server import _wire_result

    typed = _mcp_tool_def()  # any pydantic model stands in for CallToolResult
    dumped = _wire_result(typed)
    assert dumped == typed.model_dump(mode="json")
    json.dumps(dumped)  # actually wire-serializable

    for plain in ({"a": 1}, ["x"], "s", 3, None, True):
        assert _wire_result(plain) is plain
