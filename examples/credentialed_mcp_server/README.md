# credentialed_mcp_server — a toy that genuinely requires a credential

A two-tool MCP server that **refuses to start** without `LEDGER_API_KEY` in its
environment, and reports a **fingerprint** of the key it started with.

It exists because every other toy server in this repo ignores its environment,
which made a whole class of claim unprovable:

- **#253 (credential relocation).** A credential moved out of a harness config
  into the product wrapper's store is only *relocated* if it still arrives. Against a server
  that ignores its environment, a wrap that delivered nothing would pass every
  assertion — the manifest would carry an `env_map`, the harness config would be
  clean, and the server would work exactly as well as if the mechanism were a
  no-op.
- **#298 (carried configuration).** The same hole one hop earlier:
  `McpServerDecl.env` was proven to the manifest and never to the child.

Two design points worth keeping if this is extended:

**It fails at startup, not at first call.** That is what a real credentialed
server does, and it is why an undelivered credential surfaces during the
wrapper's *snapshot* step — before review, before admission. Exiting non-zero with
a legible message is also what lets the wrapper render a useful diagnostic instead of
the MCP SDK's contentless `unhandled errors in a TaskGroup (1 sub-exception)`.

**It reports a fingerprint, never the key.** A truncated SHA-256 proves the child
received the *exact* value the operator relocated, which is the property under
test; echoing the credential itself would prove the same thing and be a bad
example in a repository whose subject is credential handling.

The variable is named `LEDGER_API_KEY` rather than something innocuous on
purpose in one direction and not the other: the wrapper's classification prompt must
never be passable by a `*_KEY`/`*_TOKEN` name heuristic — that is precisely the
shortcut the wrapper's config-value classifier refuses to take, because it fails in
the one direction that must never fail.

```
LEDGER_API_KEY=sk-example python -m examples.credentialed_mcp_server.server
```

Used by the wrapper's end-to-end wrap test. Related:
`examples/restricted_mcp_server/` (the missileer archetype, no credentials).
