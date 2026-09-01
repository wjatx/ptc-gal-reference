# alpaca_paper_drill — the #221 Phase-1/2 drill consumer

The first run of the broker's **native MCP construction + spawn-time env-auth**
against a REAL third-party server: Alpaca's official `alpaca-mcp-server`
(pinned `==2.1.1`), paper keys only — first entirely on a laptop (Phase 1,
2026-07-18), then through a DEPLOYED broker task on the `development` floor
(Phase 2, 2026-07-19: `Containerfile.broker` here is that consumer image —
uvx-in-image with a pre-warmed pinned cache).

This is **drill scope**, not production adoption. Production adoption of an
Alpaca MCP surface is a consumer agent's later decision, in its own repo, behind
its own GAL evidence climb (in-loop first). What this drill proves is the
*platform mechanism* at real-world scale: a 69-tool third-party discovery
payload, a 3-tool declared ceiling, credentials the agent never sees.

## The shape

- **`manifest.yaml`** — the whole consumer. `mcp_servers.alpaca` declares the
  pinned spawn (`uvx alpaca-mcp-server==2.1.1`), pins `ALPACA_PAPER_TRADE=true`
  in the static env (manifest-declared, never left to the secret or the server
  default), and declares a READ-ONLY three-tool ceiling: `get_account_info`,
  `get_clock`, `get_stock_latest_quote`. `connector_auth.alpaca.env_map`
  renames the stored leaf's `ALPACA_KEY`/`ALPACA_SECRET` fields to the
  `ALPACA_API_KEY`/`ALPACA_SECRET_KEY` vars the server expects at child spawn —
  mapping as data (CONNECTOR-AUTH.md C9), no consumer code. There is no
  provider class and no server code here: the server is the vendor's, the
  wiring is `build_runtime`'s.
- **`safe_agents/broker/tests/test_example_alpaca_drill_manifest.py`** (CI,
  SDK-free) — the honest-manifest proof,
  including the **epic ceiling as a machine check**: no order / close / cancel /
  mutate-shaped tool name may ever enter this drill's declarations, every
  declared tool and grant is a `get_*` read, and env_map can never shadow the
  paper-trade pin (disjointness refuses at load).
- **`safe_agents/broker/tests/test_alpaca_drill_live.py`** (opt-in, live) — the
  end-to-end laptop proof (lives with the broker tests: a live proof reaches
  into broker internals, and `examples/` is guarded consumer-clean).

## The proof (first run 2026-07-18, all green)

```
set -a && source ~/.secrets/alpaca.txt && set +a && \
  python -m pytest safe_agents/broker/tests/test_alpaca_drill_live.py -q -s
```

1. **Discovery**: the pinned server advertised **69 tools** (v2.1.1;
   market-data, trading, watchlists, options, locates…). `place_stock_order`
   confirmed advertised — so its refusal below is a refusal, not absence.
2. **Local ceremony**: exactly the 3 declared tools admitted — real
   `DynamoToolRegistry` conditional writes + HMAC rows on a moto table.
3. **Native path**: `build_runtime(manifest)` composed the connector from the
   spawn block; the child env = paper pin + env_map-renamed keys, resolved
   broker-side at spawn (values never in output).
4. **Reads flow**: `get_clock` and `get_stock_latest_quote(SPY)` returned live
   structured paper-market data through the full PEP path.
5. **The order tool refused UNLISTED, twice over**: at the PEP (no grant, no
   ToolOp → `deny`) and at the MCP gate (`ToolNotCallableError` — advertised
   but unadmitted). Refused coordinate: `alpaca.place_stock_order`.
6. **M5 at volume**: the **66** UNLISTED findings surfaced as ERROR logs
   exactly ONCE at refresh — repeat calls added zero. The loud-surfacing
   design holds at real-payload scale (it was previously proven at 1–2).

## Watch out for

- **The pin is load-bearing.** A version bump changes tool descriptions →
  admitted tools drift-quarantine at connect. That is the design working; plan
  the re-vet ceremony into any upgrade.
- **Toolset filtering exists server-side** (`ALPACA_TOOLSETS`, v2): a Phase-2
  floor image can additionally shrink the advertised set (e.g.
  `account,stock-data`) — missileer-style absence UNDER the broker's admission
  ceiling. Deliberately not used here: the local proof wants the full flood
  and an advertised order tool to refuse.
- **Paper keys only** — everywhere in this epic until Phase 4's GAL-gated
  posture. The floor leaf (`<prefix>/connectors/alpaca-mcp-paper`, a flat JSON
  string map `{"ALPACA_KEY": …, "ALPACA_SECRET": …}`) was provisioned on the
  development floor in the Phase-2 drill and stays provisioned.

## Relationships

- `broker/MCP-HOST.md` — two-key admission + native construction (M14–M16).
- `broker/CONNECTOR-AUTH.md` — spawn-time credential delivery (C9).
- `examples/restricted_mcp_server/` — the missileer archetype (a server we
  control, dangerous op absent); this drill is its complement (a server we
  don't control, dangerous ops undeclared).
