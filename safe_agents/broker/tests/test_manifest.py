"""Tests for broker.manifest — the ToolOpTable primitive + the CATALOG reference (#171).

Coverage:
  1. CATALOG load-time shape: validated ToolOp instances, exactly the five generic
     ops, no domain op.
  2. ToolOpTable construction + .entry lookup, including the duplicate-key guard.
  3. .served(principal, grants) capability scoping — removal over refusal.
  4. Reversibility/reads invariants over CATALOG.
  5. Rename-invariance conformance (#171 exit predicate): a consumer-invented op
     name gates identically to any other op with the same classification.
"""

import pytest

from safe_agents.broker.manifest import CATALOG, CATALOG_TABLE, ToolOpTable
from safe_agents.broker.schemas import AgentManifest, AutonomyLevel, Grant, Principal, ToolOp

# ---------------------------------------------------------------------------
# Helpers — minimal valid objects for nested schemas
# ---------------------------------------------------------------------------

_PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")


def _grant(action_class: str) -> Grant:
    """Return a minimal valid Grant for *action_class*."""
    return Grant(
        principal=_PRINCIPAL,
        actionClass=action_class,
        level=AutonomyLevel.in_loop,
        envelopeHash="sha256-envelope",
        promotedBy="admin",
        evidence="baseline-v1",
        ts="2026-01-01T00:00:00Z",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[],
        demotionReason=None,
        labelLatency="PT24H",
        ownerId="owner@example.com",
    )


# ---------------------------------------------------------------------------
# 1. CATALOG load-time shape
# ---------------------------------------------------------------------------


class TestCatalogShape:
    def test_catalog_is_list_of_tool_op_instances(self):
        assert isinstance(CATALOG, list)
        assert len(CATALOG) > 0
        for entry in CATALOG:
            assert isinstance(entry, ToolOp)

    def test_catalog_holds_exactly_the_generic_ops(self):
        """CATALOG holds ONLY the five domain-neutral ops — no more, no less."""
        action_classes = {(e.tool, e.op) for e in CATALOG}
        assert action_classes == {
            ("github", "whoami"),
            ("search", "query"),
            ("ledger", "append"),
            ("notify", "send"),
            ("peer", "publish"),
        }

    def test_catalog_holds_no_domain_op(self):
        """Domain ops (email/calendar/crm/payments/alpaca) were removed from the base."""
        domain_tools = {"email", "calendar", "crm", "payments", "alpaca"}
        catalog_tools = {e.tool for e in CATALOG}
        assert not (domain_tools & catalog_tools)


# ---------------------------------------------------------------------------
# 2. ToolOpTable construction + lookup
# ---------------------------------------------------------------------------


class TestToolOpTable:
    def test_entry_returns_known_pair(self):
        entry = CATALOG_TABLE.entry("github", "whoami")
        assert entry is not None
        assert entry.tool == "github"
        assert entry.op == "whoami"

    def test_entry_returns_none_for_unknown_pair(self):
        assert CATALOG_TABLE.entry("nonexistent", "op") is None

    def test_duplicate_key_raises_value_error(self):
        dup = [
            ToolOp(tool="widget", op="frobnicate", effect="write", external=False, reversible=True),
            ToolOp(tool="widget", op="frobnicate", effect="read", external=True),
        ]
        with pytest.raises(ValueError, match="widget.frobnicate"):
            ToolOpTable(dup)

    def test_len_reflects_entry_count(self):
        table = ToolOpTable(list(CATALOG))
        assert len(table) == len(CATALOG)

    def test_from_manifest_builds_table_from_tool_ops(self):
        from safe_agents.broker.schemas import AgentManifest

        manifest = AgentManifest.model_validate(
            {
                "envelope": {"polarity": "abstain"},
                "tool_ops": [
                    {"tool": "github", "op": "whoami", "effect": "read", "external": True},
                ],
            }
        )
        table = ToolOpTable.from_manifest(manifest)
        assert table.entry("github", "whoami") is not None
        assert table.entry("search", "query") is None


# ---------------------------------------------------------------------------
# 3. .served(principal, grants) — capability-scoped registry
# ---------------------------------------------------------------------------


class TestServed:
    def test_empty_grants_returns_empty(self):
        assert CATALOG_TABLE.served(_PRINCIPAL, grants=[]) == []

    def test_full_grants_returns_all_entries(self):
        grants = [_grant(f"{e.tool}.{e.op}") for e in CATALOG]
        visible = CATALOG_TABLE.served(_PRINCIPAL, grants)
        assert len(visible) == len(CATALOG)

    def test_only_granted_ops_are_visible(self):
        grants = [_grant("github.whoami")]
        visible = CATALOG_TABLE.served(_PRINCIPAL, grants)
        action_classes = {f"{e.tool}.{e.op}" for e in visible}
        assert action_classes == {"github.whoami"}

    def test_ungranted_op_is_absent_not_refused(self):
        grants = [_grant("github.whoami")]
        visible = CATALOG_TABLE.served(_PRINCIPAL, grants)
        tools = {e.tool for e in visible}
        assert "notify" not in tools

    def test_unknown_action_class_contributes_nothing(self):
        grants = [_grant("nonexistent.op")]
        assert CATALOG_TABLE.served(_PRINCIPAL, grants) == []

    def test_served_order_matches_table_insertion_order(self):
        # Grant in reverse order; result should still match table order.
        grants = [_grant("peer.publish"), _grant("github.whoami")]
        visible = CATALOG_TABLE.served(_PRINCIPAL, grants)
        ops = [f"{e.tool}.{e.op}" for e in visible]
        # github.whoami precedes peer.publish in CATALOG's construction order.
        assert ops.index("github.whoami") < ops.index("peer.publish")

    def test_duplicate_grants_do_not_duplicate_entries(self):
        grants = [_grant("github.whoami"), _grant("github.whoami")]
        visible = CATALOG_TABLE.served(_PRINCIPAL, grants)
        action_classes = [f"{e.tool}.{e.op}" for e in visible]
        assert action_classes.count("github.whoami") == 1


# ---------------------------------------------------------------------------
# 4. Reversibility/reads invariants over CATALOG
# ---------------------------------------------------------------------------


class TestCatalogInvariants:
    def test_reads_leave_reversible_unset(self):
        for entry in CATALOG:
            if entry.effect == "read":
                assert entry.reversible is None, (
                    f"{entry.tool}.{entry.op} is a read op but sets reversible={entry.reversible}"
                )

    def test_external_writes_declare_reversible(self):
        for entry in CATALOG:
            if entry.effect == "write" and entry.external:
                assert entry.reversible is not None, (
                    f"{entry.tool}.{entry.op} is an external write but reversible is unset"
                )


# ---------------------------------------------------------------------------
# 5. Rename-invariance conformance (#171 exit predicate)
# ---------------------------------------------------------------------------


class TestRenameInvariance:
    def test_consumer_invented_op_gates_identically_to_same_classification(self):
        """A consumer-invented op name (never seen by the base) must classify
        identically to any other op sharing its effect/external/reversible triple —
        the base gates on classification, never on the op's name."""
        invented = ToolOp(
            tool="widget", op="frobnicate", effect="write", external=True, reversible=False
        )
        reference = ToolOp(
            tool="payments", op="transfer", effect="write", external=True, reversible=False
        )
        table = ToolOpTable([invented])

        resolved = table.entry("widget", "frobnicate")
        assert resolved is not None
        assert resolved.effect == reference.effect
        assert resolved.external == reference.external
        assert resolved.reversible == reference.reversible


# ---------------------------------------------------------------------------
# 6. Remote (streamable-http) MCP wiring — the M21 manifest invariants (#221 P4)
# ---------------------------------------------------------------------------


def _remote_manifest_dict(**overrides) -> dict:
    """A manifest whose one MCP server is a remote streamable-http declaration."""
    base = {
        "envelope": {"polarity": "abstain"},
        "connectors": ["quotes"],
        "tool_ops": [
            {"tool": "quotes", "op": "get_quote", "effect": "read", "external": True},
        ],
        "mcp_servers": {
            "quotes": {
                "transport": "streamable-http",
                "url": "https://mcp.example.com/mcp",
                "tools": [{"tool_name": "get_quote"}],
            }
        },
    }
    base.update(overrides)
    return base


class TestRemoteMcpWiring:
    def test_wired_remote_decl_is_legal(self):
        manifest = AgentManifest.model_validate(_remote_manifest_dict())
        assert manifest.mcp_servers["quotes"].url == "https://mcp.example.com/mcp"

    def test_remote_decl_not_wired_in_connectors_refuses(self):
        """A remote server is natively constructed too — same wiring rule as a
        spawnable one: construction config nothing wires is dead config."""
        with pytest.raises(ValueError, match="not named in 'connectors'"):
            AgentManifest.model_validate(_remote_manifest_dict(connectors=[]))

    def test_remote_decl_colliding_with_provider_refuses(self):
        with pytest.raises(ValueError, match="two construction paths"):
            AgentManifest.model_validate(
                _remote_manifest_dict(
                    connector_providers={"quotes": "pkg.module:QuotesConnector"}
                )
            )

    def test_env_map_on_remote_decl_refuses(self):
        """env_map is spawn-time delivery; a remote server has no spawn to
        inject into, so the map is unsatisfiable config (MCP-HOST.md M21)."""
        with pytest.raises(ValueError, match="remote"):
            AgentManifest.model_validate(
                _remote_manifest_dict(
                    connector_auth={"quotes": {"env_map": {"API_KEY": "KEY"}}}
                )
            )

    def test_remote_decl_with_empty_env_map_is_legal(self):
        """A connector_auth entry WITHOUT env_map on a remote decl stays legal —
        only the spawn-time delivery mechanism is unsatisfiable, not the entry."""
        manifest = AgentManifest.model_validate(
            _remote_manifest_dict(connector_auth={"quotes": {}})
        )
        assert manifest.connector_auth["quotes"].env_map == {}


# ---------------------------------------------------------------------------
# 7. header_map — the remote credential half, invariant (d) (#237, C10/M25)
# ---------------------------------------------------------------------------


def _stdio_manifest_dict(**overrides) -> dict:
    """A manifest whose one MCP server is a spawned (stdio) declaration.

    The dual of `_remote_manifest_dict` — invariant (d) is a statement about
    the TRANSPORT, so testing it needs a manifest of each shape.
    """
    base = {
        "envelope": {"polarity": "abstain"},
        "connectors": ["quotes"],
        "tool_ops": [
            {"tool": "quotes", "op": "get_quote", "effect": "read", "external": True},
        ],
        "mcp_servers": {
            "quotes": {
                "tools": [{"tool_name": "get_quote"}],
                "command": "quotes-mcp-server",
            }
        },
    }
    base.update(overrides)
    return base


class TestHeaderMapWiring:
    """Invariant (d): header_map is legal ONLY on a remote decl.

    env_map and header_map are duals — each is the other transport's credential
    half — so the manifest must refuse each on the wrong transport. What makes
    that worth its own tests is the failure mode of NOT refusing: a header_map
    on a stdio decl would be silently ignored, and the operator would read a
    declared credential where none is delivered.
    """

    def test_header_map_on_remote_decl_is_legal(self):
        """The sanctioned shape — the remote transport's credential half."""
        manifest = AgentManifest.model_validate(
            _remote_manifest_dict(
                connector_auth={
                    "quotes": {"header_map": {"Authorization": {"scheme": "Bearer"}}}
                }
            )
        )
        source = manifest.connector_auth["quotes"].header_map["Authorization"]
        assert source.scheme == "Bearer"
        assert source.field is None

    def test_header_map_on_stdio_decl_refuses(self):
        """A spawned child has no request to carry a header, so the map could
        never be delivered — refuse it rather than drop it, exactly as the
        remote decl refuses env_map (MCP-HOST.md M25)."""
        with pytest.raises(ValueError, match="spawned"):
            AgentManifest.model_validate(
                _stdio_manifest_dict(
                    connector_auth={
                        "quotes": {"header_map": {"Authorization": {"scheme": "Bearer"}}}
                    }
                )
            )

    def test_header_map_on_non_mcp_tool_refuses(self):
        """Header injection is the streamable-HTTP delivery mechanism; on a tool
        that is no mcp_servers entry at all the map is dead config, and dead
        config is a masked misconfiguration."""
        with pytest.raises(ValueError, match="dead config"):
            AgentManifest.model_validate(
                _remote_manifest_dict(
                    connectors=["quotes", "github"],
                    connector_auth={
                        "github": {"header_map": {"Authorization": {"scheme": "Bearer"}}}
                    },
                )
            )

    def test_remote_decl_with_empty_header_map_is_legal(self):
        """An unauthenticated remote server is a real shape: the empty map means
        no credential is resolved at all, so the entry itself is never the
        refusal — only an UNDELIVERABLE map is."""
        manifest = AgentManifest.model_validate(
            _remote_manifest_dict(connector_auth={"quotes": {"header_map": {}}})
        )
        assert manifest.connector_auth["quotes"].header_map == {}
