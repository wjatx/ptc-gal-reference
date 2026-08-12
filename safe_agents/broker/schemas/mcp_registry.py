"""MCP tool-registry schemas — the two-key admission of a discovered MCP tool (#174).

An MCP server's tool set is discovered at runtime, so its definitions are NOT
image-baked and cannot be trusted on sight (a compromised or swapped server can
rename a tool, widen its input schema, or rewrite its description — all injection
surface). Admission is therefore TWO-KEY:

  1. The image-baked `AgentManifest` pre-declares the `(server_id, tool_name)`
     namespace and each tool's ToolOp classification (`McpServerDecl` here,
     `AgentManifest.mcp_servers`). Nothing outside the image can widen this set.
  2. A later signed registry store row (`RegisteredTool`) ACTIVATES a declared
     tool only when its discovery-time definition hash matches — so a drifted
     definition (any advertised field changed) fails admission.

This module owns the manifest-side declarations, the discovery-time definition
object, the drift-detection hash AND its companion delta summarizer, and the
store-row model. It does NOT admit, sign, render, or resolve anything — those
seams live outside the schema layer.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


# ---------------------------------------------------------------------------
# Manifest-side declarations — the image-baked namespace (key #1)
# ---------------------------------------------------------------------------


class McpToolDecl(BaseModel):
    """A manifest-side declaration of ONE MCP tool the agent may see.

    `structured_output` is the trust knob: only a tool whose response the server
    returns as structured data (not free text) may be named in
    `Envelope.trusted_read_sources`. A free-text tool is injection surface, so
    trusting its output is refused at manifest load — see
    `AgentManifest`'s structured-only validator.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    structured_output: bool = False


class McpRespawnPolicy(BaseModel):
    """Respawn-after-death policy for a spawned MCP server — data, never code.

    MCP-HOST.md M19: whether a dead child comes back is an *availability* choice
    (polarity-dependent, the liveness genre), so the base ships only the
    mechanism and the block is opt-in on the image-baked `McpServerDecl`; absent
    block = no respawn, byte-for-byte the pre-knob behavior. Bounds are tight by
    design: the whole respawn burst must resolve inside the connector's liveness
    backstop, so a wedged recovery still fails loudly instead of hanging the
    Doer. Attempts are consumed per death; an exhausted policy degrades to the
    OFF behavior (typed failure, no retry storm).
    """

    model_config = ConfigDict(extra="forbid")

    max_attempts: int
    backoff_seconds: float = 0.0

    @field_validator("max_attempts")
    @classmethod
    def _attempts_bounded(cls, value: int) -> int:
        if not 1 <= value <= 3:
            raise ValueError(
                "respawn max_attempts must be between 1 and 3 — the burst must "
                "fit inside the connector's call-liveness backstop"
            )
        return value

    @field_validator("backoff_seconds")
    @classmethod
    def _backoff_bounded(cls, value: float) -> float:
        if not 0.0 <= value <= 10.0:
            raise ValueError(
                "respawn backoff_seconds must be between 0 and 10 — the burst "
                "must fit inside the connector's call-liveness backstop"
            )
        return value

    @model_validator(mode="after")
    def _burst_fits_backstop(self) -> "McpRespawnPolicy":
        # 20s leaves spawn-time headroom under the connector's 30s backstop; a
        # policy that could sleep past it would surface as the bare TimeoutError
        # M17 exists to eliminate.
        if self.max_attempts * self.backoff_seconds > 20.0:
            raise ValueError(
                "respawn policy too slow: max_attempts * backoff_seconds must "
                "not exceed 20 seconds (the burst must resolve inside the "
                "connector's call-liveness backstop)"
            )
        return self


class McpServerDecl(BaseModel):
    """A manifest-side declaration of ONE MCP server and its tool namespace.

    Keyed by `server_id` in `AgentManifest.mcp_servers`. Duplicate `tool_name`s
    are rejected — a server declaring one tool twice is ambiguous (which
    `structured_output` wins?), so fail at load.

    A declaration MAY additionally carry stdio spawn config (`command`, `args`,
    `env`, `cwd`) — the #221 native-construction block. With `command` set, the
    broker's `build_runtime` composes the MCP connector itself (child process,
    host factory, admitted-tool registry) with no `connector_providers` class in
    between. The block names code to run, so it sits in the SAME power class as
    `connector_providers` on the injection-power lattice
    (docs/config-provenance.md): honored ONLY from the image-baked manifest —
    structurally guaranteed, because the envelope store loads an `Envelope`,
    which has no `mcp_servers` field. `env` is the STATIC half of the child
    environment (e.g. `ALPACA_PAPER_TRADE: "true"`); credential material never
    appears here — it is resolved at spawn time via `connector_auth.env_map`
    and the two halves may not overlap (enforced at manifest load).

    A declaration MAY instead carry a remote `url` with `transport=
    "streamable-http"` (MCP-HOST.md M21, #221 Phase 4) — a server the broker
    connects to over HTTP rather than spawns. The URL names where calls (and,
    later, credentials) go, so it sits in the SAME image-baked-only power class
    as `command`, for the same structural reason: the store-loaded `Envelope`
    has no `mcp_servers` field, so nothing store-loaded can point a tool call
    at an attacker-chosen endpoint. `command` and `url` are mutually exclusive
    — a decl is exactly one of stdio or streamable-http, never both. `respawn`
    applies to a remote decl too, governing reconnect bursts after a dropped
    HTTP session (same M19 ships-OFF semantics as the stdio case).

    Without `command` or `url` the declaration is a pure namespace declaration
    (key #1 of two-key admission) and construction is the consumer's concern —
    byte-for-byte the pre-#221 shape.
    """

    model_config = ConfigDict(extra="forbid")

    tools: list[McpToolDecl] = []

    # -- transport + construction config (#221) — image-baked-only power class
    transport: Literal["stdio", "streamable-http"] = "stdio"

    # -- stdio spawn config --
    command: Optional[str] = None
    args: list[str] = []
    env: dict[str, str] = {}
    cwd: Optional[str] = None

    # -- streamable-http remote config (#221 Phase 4, MCP-HOST.md M21) --
    url: Optional[str] = None

    # Respawn-after-death policy (#221 Phase 3, MCP-HOST.md M19). Optional and
    # OFF by default; same image-baked-only power class as the spawn/remote
    # config it governs (the envelope store cannot set or loosen it —
    # `Envelope` has no `mcp_servers` field). Legal with `command` OR `url`.
    respawn: Optional[McpRespawnPolicy] = None

    @field_validator("tools")
    @classmethod
    def _tool_names_are_unique(cls, value: list[McpToolDecl]) -> list[McpToolDecl]:
        seen: set[str] = set()
        for decl in value:
            if decl.tool_name in seen:
                raise ValueError(
                    f"mcp server declares tool {decl.tool_name!r} more than once; each "
                    "tool_name must be declared exactly once"
                )
            seen.add(decl.tool_name)
        return value

    @field_validator("command")
    @classmethod
    def _command_is_non_empty(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not value.strip():
            raise ValueError(
                "mcp server 'command' must be a non-empty program name; omit the "
                "field entirely for a namespace-only declaration"
            )
        return value

    @field_validator("url")
    @classmethod
    def _url_is_well_formed(cls, value: Optional[str]) -> Optional[str]:
        """`url`, when set, must be a well-formed http(s) endpoint.

        MCP-HOST.md M21: plain `http` is refused except to a loopback host —
        the literal hostname `localhost`, or a hostname that parses as an IP
        literal whose `ipaddress.is_loopback` is true (127.0.0.0/8, ::1). This
        is deliberately an IP-literal test, not a string-prefix test: a DNS
        NAME is untrustworthy input regardless of what it starts with —
        `127.0.0.1.evil.com` and `127.evil.com` are valid public DNS names
        that resolve wherever their owner points them, not loopback. Any
        non-loopback plain-http endpoint is refused: cleartext transport for
        a tool-call surface that will later carry credentials.
        """
        if value is None:
            return value
        if not value.strip():
            raise ValueError(
                "mcp server 'url' must be a non-empty endpoint; omit the field "
                "entirely for a stdio or namespace-only declaration"
            )
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(
                f"mcp server 'url' {value!r} must be a well-formed http(s) URL "
                "with a hostname"
            )
        if parsed.scheme == "http":
            hostname = parsed.hostname.lower()
            if hostname == "localhost":
                is_loopback = True
            else:
                try:
                    is_loopback = ipaddress.ip_address(hostname).is_loopback
                except ValueError:
                    is_loopback = False  # not an IP literal — a DNS name is never loopback
            if not is_loopback:
                raise ValueError(
                    f"mcp server 'url' {value!r} uses plain http to a "
                    "non-loopback host; this is a cleartext transport for a "
                    "tool-call surface that will later carry credentials — use "
                    "https, or http only to localhost or a loopback IP "
                    "literal (127.0.0.0/8, ::1)"
                )
        return value

    @model_validator(mode="after")
    def _transport_requires_matching_config(self) -> "McpServerDecl":
        """`command` and `url` are mutually exclusive; transport must match.

        `transport="streamable-http"` requires `url` and forbids `command`;
        `transport="stdio"` forbids `url` (a stdio decl may still be
        namespace-only, with neither `command` nor `url` set — the pre-#221
        shape, unchanged).
        """
        if self.command is not None and self.url is not None:
            raise ValueError(
                "mcp server declares both 'command' and 'url'; a declaration "
                "must be exactly one of stdio ('command') or streamable-http "
                "('url'), never both"
            )
        if self.transport == "streamable-http":
            if self.url is None:
                raise ValueError(
                    "mcp server transport is 'streamable-http' but no 'url' is "
                    "set; a remote server must declare its endpoint"
                )
            if self.command is not None:
                raise ValueError(
                    "mcp server transport is 'streamable-http' but 'command' "
                    "is set; a remote server is not spawned, so 'command' is "
                    "a stdio-only field"
                )
        if self.transport == "stdio" and self.url is not None:
            raise ValueError(
                "mcp server transport is 'stdio' but 'url' is set; a spawned "
                "server has no remote endpoint — use "
                "transport='streamable-http' for a remote server"
            )
        return self

    @model_validator(mode="after")
    def _spawn_accessories_require_command(self) -> "McpServerDecl":
        """`args`/`env`/`cwd` are stdio-only spawn accessories — refuse without `command`.

        These fields configure a spawned child process, so they are refused
        whenever `command` is None — including on a streamable-http
        declaration, where a remote server carries stdio spawn accessories it
        can never use. A namespace-only declaration carrying them is dead
        config at best and a masked typo at worst (an operator who set `env`
        but forgot `command` would silently get no child process). Fail at
        load, not at wire.

        `respawn` is legal with `command` OR `url` (it governs reconnect
        bursts for a spawned or remote server alike) but still refused on a
        namespace-only declaration with neither.
        """
        if self.command is None and (self.args or self.env or self.cwd is not None):
            raise ValueError(
                "mcp server declares stdio spawn accessories (args/env/cwd) "
                "without 'command'; these only apply to a spawned stdio "
                "server — name 'command' to spawn one, or drop the "
                "accessories (namespace-only or streamable-http declaration)"
            )
        if self.command is None and self.url is None and self.respawn is not None:
            raise ValueError(
                "mcp server declares 'respawn' without 'command' or 'url'; "
                "respawn governs reconnect bursts for a spawned or remote "
                "server and requires one of the two (namespace-only "
                "declaration)"
            )
        return self


# ---------------------------------------------------------------------------
# Discovery-time definition + the drift-detection hash (key #2)
# ---------------------------------------------------------------------------


class McpToolDef(BaseModel):
    """The discovery-time definition object for ONE MCP tool.

    Materialized from a live MCP `tools/list` response. Its `def_hash`
    (`compute_tool_def_hash`) is what a signed store row commits to; a match
    against a re-derived hash at admission is what ACTIVATES the pre-declared
    tool (two-key admission, #174).
    """

    model_config = ConfigDict(extra="forbid")

    server_id: str
    tool_name: str
    input_schema: dict
    description: str

    # Advertised metadata (#221 field-carry; SIGNED since #223 — every
    # advertised field rides `compute_tool_def_hash`). Each defaults to `None`,
    # NEVER to an empty container: `None` honestly means "the server didn't
    # advertise this." A `None` field contributes nothing to the signed set
    # (see `compute_tool_def_hash`), so absent->present IS drift while a field
    # no server has started advertising yet moves nothing.
    title: Optional[str] = None
    output_schema: Optional[dict] = None
    icons: Optional[list] = None
    annotations: Optional[dict] = None
    meta: Optional[dict] = None
    execution: Optional[dict] = None


def compute_tool_def_hash(tool_def: McpToolDef) -> str:
    """Hex sha256 over the canonical JSON of the tool's SIGNED SET.

    The signed set is EVERY ADVERTISED FIELD of the definition (#223): the four
    always-present core fields `(server_id, tool_name, input_schema,
    description)` plus each metadata field the server actually advertised
    (`title`/`output_schema`/`icons`/`annotations`/`meta`/`execution`). A
    `None` field is EXCLUDED from the canonical payload rather than serialized
    as null — deliberately, for two properties:

    - **A definition advertising no metadata hashes byte-identically to the
      pre-#223 four-field basis.** The far-jump falls only where new signed
      material actually exists; a row whose live server advertises nothing new
      is not forced through an empty-delta re-vet (a drift with nothing to
      show teaches operators to dismiss the alarm that matters).
    - **Future additive `McpToolDef` growth is not a far-jump.** The MCP spec
      is still adding tool fields; a nulls-in basis would move EVERY hash each
      time the model learns a new optional field. Excluding `None` means a new
      field moves nothing until a server advertises it — and a field
      appearing, changing, or vanishing IS drift.

    No integrity is lost in the collapse: the model cannot distinguish an
    absent field from an advertised-as-null one (`None` means "not
    advertised"), so neither can the hash. `description` is included
    DELIBERATELY — it is model-facing injection surface (a swapped server can
    rewrite it to steer the agent), so a description change must break the
    hash and fail admission just as a schema change does; since #223 the same
    holds for a flipped annotation hint or a rewritten output schema.

    Canonicalization matches `safe_agents/channels/signing.py`: `json.dumps`
    with `sort_keys=True, separators=(",", ":"), ensure_ascii=True`, so key
    order (including within `input_schema`) never changes the hash while any
    value change does. This is THE drift-detection primitive.
    """
    signed_set = {
        name: value
        for name, value in tool_def.model_dump(mode="json").items()
        if value is not None
    }
    canonical = json.dumps(
        signed_set, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The hash's companion — WHAT moved, not merely THAT something did
# ---------------------------------------------------------------------------


@dataclass
class SchemaDelta:
    """A machine-computed summary of a top-level `input_schema` change.

    Scoped to the top-level `properties`/`required` shape of a JSON Schema
    object — the shape every MCP tool's `input_schema` actually takes. A
    nested property's own sub-schema is compared only by its own `type`
    (`retyped_fields`); a deeper structural change inside an unchanged-typed
    property is not itself broken out here (out of scope for a summary whose
    job is legibility, not a full JSON-diff).

    This lives beside `compute_tool_def_hash` deliberately: the two are halves
    of ONE drift primitive. The hash answers *that* a definition moved and is
    what a signed row commits to; this answers *what* moved and is what a human
    re-vetting the drift actually reads. Homing them apart is how a codebase
    ends up with two subtly different notions of "changed" — and it is why this
    is a pure function over schema dicts with no store, no rendering, and no
    I/O, exactly like the hash it accompanies. `broker/mcp/render.py` formats
    it; a consumer-side wrapper renders it under its own TL11 discipline. Both
    consume; neither redefines.
    """

    added_fields: list[str] = field(default_factory=list)
    removed_fields: list[str] = field(default_factory=list)
    retyped_fields: list[tuple[str, str, str]] = field(default_factory=list)
    newly_required: list[str] = field(default_factory=list)
    no_longer_required: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (
            self.added_fields
            or self.removed_fields
            or self.retyped_fields
            or self.newly_required
            or self.no_longer_required
        )


def _field_type(subschema: object) -> str:
    if isinstance(subschema, dict) and "type" in subschema:
        return str(subschema["type"])
    return "<untyped>"


def diff_input_schema(old: dict, new: dict) -> SchemaDelta:
    """Field-added/removed/retyped/required deltas between two `input_schema` dicts."""
    old_props = old.get("properties") or {}
    new_props = new.get("properties") or {}
    old_required = set(old.get("required") or [])
    new_required = set(new.get("required") or [])

    added = sorted(set(new_props) - set(old_props))
    removed = sorted(set(old_props) - set(new_props))
    retyped: list[tuple[str, str, str]] = []
    for name in sorted(set(old_props) & set(new_props)):
        old_type = _field_type(old_props[name])
        new_type = _field_type(new_props[name])
        if old_type != new_type:
            retyped.append((name, old_type, new_type))

    return SchemaDelta(
        added_fields=added,
        removed_fields=removed,
        retyped_fields=retyped,
        newly_required=sorted(new_required - old_required),
        no_longer_required=sorted(old_required - new_required),
    )


# ---------------------------------------------------------------------------
# Store row — the ACTIVATION record (key #2, persisted)
# ---------------------------------------------------------------------------


class RegistryStatus(str, Enum):
    """The closed status catalog for a registry store row.

    `ACTIVE` — the tool is admitted and callable; the ONLY status the admission
    ceremony ever writes. `QUARANTINED` is a reserved DEFENSIVE READ arm with no
    production writer today: drift quarantine is COMPUTED at discovery time (a
    later definition whose hash differs from the admitted one is treated as
    quarantined by the reader), never PERSISTED — the stored row stays ACTIVE and
    the mismatch is derived on each read, mirroring the grant-HMAC
    loud-quarantine posture (sa#124). The arm is retained both so a reader can
    represent that computed state and for a future explicit quarantine ceremony
    (a sanctioned writer that parks a row without deleting it). It is NOT removed:
    a store that round-trips only ACTIVE must still validate the full closed
    catalog, and the read side already branches on it.
    """

    ACTIVE = "active"
    QUARANTINED = "quarantined"


class RegisteredTool(BaseModel):
    """A registry store row activating one declared MCP tool (#174; #246 re-shape A).

    The row NESTS the ratified definition as `tool_def` — the exact `McpToolDef`
    the ceremony admitted — instead of mirroring its fields flat. "The row pins
    what was ratified" is thereby structural: there is no per-field mirror to
    drift out of sync when `McpToolDef` grows (the #223 field-carry bug class
    dies here). Alongside it ride the `def_hash` the admission committed to,
    the closed `status`, and the admitting identity/time.

    The row carries NO integrity slot: the store-integrity HMAC lives at ITEM
    level only (`rowHash` beside the stored `data` bytes), and its basis is the
    stored bytes themselves (`registry.canonical_row_payload`) — never a
    re-serialization of this model, so additive schema growth can never make an
    intact old row read as tampered (#246: integrity indicts tampering, never
    evolution).

    A pre-#246 flat row does NOT parse under this model (its definition fields
    sit at top level, not under `tool_def`). That is deliberate: the migration
    is the dev-floor re-vet (5 rows, per #246) — the ceremony re-mints the rows
    it disturbs rather than this model carrying a dual-shape compat parse.

    `admitted_at` is an ISO-8601 string (tz-aware UTC), matching the string
    timestamp convention of the grant ledger — the row stores a timestamp, it
    never mints one, so no wall-clock read enters the schema layer.
    """

    model_config = ConfigDict(extra="forbid")

    tool_def: McpToolDef  # pins-what-was-ratified, structurally
    def_hash: str
    status: RegistryStatus
    admitted_by: str  # credential ARN of the admitting identity
    admitted_at: str  # ISO-8601, tz-aware UTC

    @property
    def server_id(self) -> str:
        return self.tool_def.server_id

    @property
    def tool_name(self) -> str:
        return self.tool_def.tool_name


# ---------------------------------------------------------------------------
# Snapshot artifact — a captured live tool set, pre-admission (#221 Phase 5)
# ---------------------------------------------------------------------------


class McpSnapshotEntry(BaseModel):
    """One captured tool: its full discovery-time definition plus the
    pre-computed drift-detection hash over its signed set.

    `def_hash` is carried alongside `tool_def` rather than recomputed by every
    consumer so `show`/`diff` (#221 items 3/4) never need to re-derive it (and
    a tampered snapshot file re-hashes to a different value than the one on
    disk, which is exactly the drift `diff` will report).
    """

    model_config = ConfigDict(extra="forbid")

    tool_def: McpToolDef
    def_hash: str


class McpServerSnapshot(BaseModel):
    """A captured artifact of ONE MCP server's full live advertised tool set.

    Produced by `python -m safe_agents.broker.mcp.commands snapshot` — pure
    discovery, no registry read or write. This is the typed input `show`/
    `diff` (#221 item 3) and `admit-propose --from-snapshot` (item 4) consume,
    and is also the mechanical core of the #231 vendor intake probe: capture
    once, inspect/diff/propose off the same file rather than re-querying a
    live (and possibly since-changed) server.

    `entries` is sorted by `tool_name` at construction so two snapshots of an
    unchanged server serialize byte-for-byte identical JSON (a stable diff
    surface) — `_sorted_entries` normalizes regardless of discovery order.

    `captured_at` is tz-aware ISO-8601 (matching `RegisteredTool.admitted_at`'s
    convention); `source` names the transport target (a stdio command line or
    a streamable-http URL) for a human reading the file — NEVER a credential.
    """

    model_config = ConfigDict(extra="forbid")

    server_id: str
    transport: Literal["stdio", "streamable-http"]
    source: str
    captured_at: str  # ISO-8601, tz-aware UTC
    entries: list[McpSnapshotEntry]

    @field_validator("entries")
    @classmethod
    def _sorted_entries(cls, value: list[McpSnapshotEntry]) -> list[McpSnapshotEntry]:
        return sorted(value, key=lambda entry: entry.tool_def.tool_name)
