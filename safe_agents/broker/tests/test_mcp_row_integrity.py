"""The registry row's integrity basis is the STORED BYTES (#246 re-shape A; MCP-HOST.md M22).

Successor to the #223 M22 suite. That suite pinned a VALUE-BASED basis
(`exclude_none` over the flat row's non-`hash` fields) whose whole purpose was
to keep parse-then-re-serialize verification stable under additive Optional
widening. #246 retires the workaround by removing its cause: the row nests the
ratified definition (`RegisteredTool.tool_def`), the in-payload `hash` slot is
gone, and the integrity slot is the item-level `rowHash` — an HMAC over the
stored `data` string verbatim (`canonical_row_payload`, the mcp/proposals.py /
grants/store.py idiom). Verification never re-serializes the model, so schema
evolution can never fire a tamper alarm — integrity indicts tampering, never
evolution.

NOTE: every golden row-HMAC value in this file is RE-PINNED DELIBERATELY — the
basis moved with #246 re-shape A (in-payload value-basis -> item-level
stored-bytes), so pre-#246 pinned literals do not carry over. A pre-#246 flat
row neither verifies (different basis) nor parses (different shape) under the
new code; the migration is the dev-floor re-vet (5 rows, per #246).
"""

from __future__ import annotations

import json

from safe_agents.broker.mcp.registry import (
    MemoryToolRegistry,
    ToolReadResult,
    _hmac_payload,
    canonical_row_payload,
    compute_row_hmac,
)
from safe_agents.broker.schemas.mcp_registry import (
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
)

HMAC_KEY = b"test-hmac-key"

# Golden pin over the NEW basis — RE-PINNED with #246 re-shape A (the basis
# moved from the flat row's exclude_none value dump to the stored bytes of the
# nested-row canonical payload). If this moves, every floor row quarantines:
# treat a diff here as a far-jump, not a test update.
GOLDEN_ROW_HMAC = "ee4e266d8515b6fc7237cffb0d66861a7c5d91da2ae4406d3803aa2ffe794258"


def _tool_def(**overrides) -> McpToolDef:
    base = dict(
        server_id="ledger",
        tool_name="get_entry",
        input_schema={"type": "object", "properties": {"entry_id": {"type": "string"}}},
        description="Return one ledger entry by id.",
        annotations={"readOnlyHint": True},
        title="Get ledger entry",
    )
    base.update(overrides)
    return McpToolDef(**base)


def _row(**tool_def_overrides) -> RegisteredTool:
    return RegisteredTool(
        tool_def=_tool_def(**tool_def_overrides),
        def_hash="b" * 64,
        status=RegistryStatus.ACTIVE,
        admitted_by="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker-session",
        admitted_at="2026-07-25T00:00:00+00:00",
    )


class TestStoredBytesBasis:
    def test_golden_row_hmac_pin(self) -> None:
        """The write-path HMAC over the canonical payload, pinned byte-exact."""
        assert compute_row_hmac(_row(), HMAC_KEY) == GOLDEN_ROW_HMAC

    def test_write_path_hmacs_the_exact_stored_string(self) -> None:
        """compute_row_hmac == HMAC(canonical_row_payload) — one serialization,
        stored AND hashed; no second basis exists."""
        row = _row()
        assert compute_row_hmac(row, HMAC_KEY) == _hmac_payload(
            canonical_row_payload(row), HMAC_KEY
        )

    def test_verification_is_bytes_verbatim_not_reserialization(self) -> None:
        """A stored data string in a NON-canonical serialization (different key
        order/whitespace) still verifies when its rowHash covers those exact
        bytes — proving the read path never re-serializes the parsed model to
        re-derive the basis. This is the property that makes the basis immune
        to schema evolution (#246)."""
        row = _row()
        # Same JSON content, deliberately not the canonical form.
        noncanonical = json.dumps(
            json.loads(canonical_row_payload(row)), sort_keys=False, indent=2
        )
        assert noncanonical != canonical_row_payload(row)
        store = MemoryToolRegistry(hmac_key=HMAC_KEY)
        store._rows[("ledger", "get_entry")] = {
            "data": noncanonical,
            "rowHash": _hmac_payload(noncanonical, HMAC_KEY),
        }
        result = store.get_tool("ledger", "get_entry")
        assert not result.quarantined
        assert result.tool is not None and result.tool.tool_def.title == "Get ledger entry"

    def test_pre_246_flat_item_reads_quarantined_never_raises(self) -> None:
        """A pre-#246 item (flat payload with the in-payload hash slot, rowHash
        computed under the retired value basis) fails the stored-bytes HMAC and
        is served QUARANTINED with tool=None — never parsed, never a crash.
        The sanctioned recovery is the re-vet migration, not a compat parse."""
        legacy_payload = json.dumps(
            {
                "server_id": "ledger",
                "tool_name": "get_entry",
                "input_schema": {"type": "object"},
                "description": "Return one ledger entry by id.",
                "def_hash": "a" * 64,
                "status": "active",
                "admitted_by": "arn:aws:sts::111111111111:assumed-role/CheckerRole/s",
                "admitted_at": "2026-07-19T13:28:45+00:00",
                "hash": "0" * 64,  # the retired in-payload slot
            },
            sort_keys=True,
        )
        store = MemoryToolRegistry(hmac_key=HMAC_KEY)
        store._rows[("ledger", "get_entry")] = {
            "data": legacy_payload,
            "rowHash": "0" * 64,  # the old value-basis HMAC, wrong under #246
        }
        result = store.get_tool("ledger", "get_entry")
        assert result.quarantined
        assert result.tool is None
        assert result.raw_data == legacy_payload


class TestDetectionIsNotWeakened:
    """The stored-bytes move must not buy evolution-immunity with leniency."""

    def _admitted_store(self, **tool_def_overrides) -> MemoryToolRegistry:
        store = MemoryToolRegistry(hmac_key=HMAC_KEY)
        store.admit_tool(_row(**tool_def_overrides), expected=ToolReadResult(tool=None))
        return store

    def test_tampering_the_stored_data_string_quarantines(self) -> None:
        store = self._admitted_store()
        item = store._rows[("ledger", "get_entry")]
        item["data"] = item["data"].replace('"readOnlyHint": true', '"readOnlyHint": false')
        assert store.get_tool("ledger", "get_entry").quarantined

    def test_tampering_the_item_level_rowhash_quarantines(self) -> None:
        store = self._admitted_store()
        store._rows[("ledger", "get_entry")]["rowHash"] = "0" * 64
        result = store.get_tool("ledger", "get_entry")
        assert result.quarantined and result.tool is None

    def test_missing_rowhash_attribute_quarantines(self) -> None:
        """An item that cannot be verified must not activate anything."""
        store = self._admitted_store()
        del store._rows[("ledger", "get_entry")]["rowHash"]
        result = store.get_tool("ledger", "get_entry")
        assert result.quarantined and result.tool is None

    def test_null_inside_the_schema_interior_is_payload_not_absence(self) -> None:
        """A null inside input_schema's dict interior is bytes under the HMAC;
        changing it must break — carried from the M22 suite, trivially held by
        the stored-bytes basis."""
        schema = {"type": "object", "properties": {"q": {"type": "string", "default": None}}}
        store = self._admitted_store(input_schema=schema)
        item = store._rows[("ledger", "get_entry")]
        item["data"] = item["data"].replace('"default": null', '"default": "changed"')
        assert store.get_tool("ledger", "get_entry").quarantined
