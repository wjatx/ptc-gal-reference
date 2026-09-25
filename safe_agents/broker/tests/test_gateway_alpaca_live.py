"""Opt-in LIVE proof: the broker's MCP gateway in front of a REAL vendor server (#283).

`test_gateway_stdio.py` proves the mouth's wiring in process, against a hand-written
manifest and an in-memory sink. This is the other side of both: a **spawned**
`python -m safe_agents.broker.gateway`, driven by a real `ClientSession` over real
stdio, serving tools admitted by the **real two-key ceremony** into a **durable**
store, writing a **hash-chained file** tape — with `alpaca-mcp-server` running as
the gateway's own MCP child and live paper-account data coming back through it.

Alpaca rather than a toy [ruling: maintainer, 2026-07-26]: a toy exercises the paths the
in-process suite already covers, so it would confirm rather than find. A real vendor
crosses what a toy cannot fake — a 69-tool discovery payload, a pinned third-party
package, and credentials the agent never sees.

## Why this runs on sqlite

The gateway is a SEPARATE PROCESS, so the admitted rows and grants it serves must
outlive the test's own interpreter. moto cannot cross that line (it patches botocore
in-process), which leaves the product-wrapper Phase-1 local floor: `BROKER_STORE=sqlite`, the
solo-identity ceremony, and a local issuer key. So this drill also happens to be the
first time the gateway, the local trust substrate and a real vendor server are all
in the same run — with **no AWS credentials anywhere**.

Every #205 refusal is therefore in force (sqlite is a durable arm): the manifest, the
HMAC key, the store path and real secrets are all NAMED here, and `BROKER_GRANT_LOAD`
must be `read` because F5 refuses seed-at-boot on sqlite. Grants come from the
ceremony, exactly as they would on a floor.

## The two refusal classes, and what this drill changed

`alpaca.place_stock_order` is refused because it is absent from `tool_ops` entirely
— the missileer posture keeps a dangerous op out of the manifest rather than denying
it. When this drill first ran, that refusal wrote **no audit record at all**, while
the in-process proof's refusal (of a tool `embedded_agent` CLASSIFIES without
granting) was recorded. Two correct refusals, one word for both in the #283 DoD, and
the safer posture was the one that left no trace.

That was #281, and it is now fixed (MCP-HOST.md **M26**): the refusal below is on the
tape as `deny`/`denied`. The assertion is kept pointed at the coordinate rather than
at a count, so it keeps meaning the same thing as the chain grows.

Gated on paper keys (source ``~/.secrets/alpaca.txt``); needs network + uvx + the
``mcp`` extra. Run:

    set -a && source ~/.secrets/alpaca.txt && set +a && \
      python -m pytest safe_agents/broker/tests/test_gateway_alpaca_live.py -q -s
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytest.importorskip("mcp", reason="the gateway drill drives a real MCP client")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from safe_agents.broker.audit._chain import verify_chain  # noqa: E402
from safe_agents.broker.schemas import AuditRecord  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]
_MANIFEST = _REPO / "examples" / "alpaca_paper_drill" / "manifest.yaml"

#: The manifest's read-only ceiling, as WIRE names (`tool__op`, GATEWAY.md G7).
_EXPECTED_WIRE_NAMES = [
    "alpaca__get_account_info",
    "alpaca__get_clock",
    "alpaca__get_stock_latest_quote",
]
_DECLARED = ("get_account_info", "get_clock", "get_stock_latest_quote")
_REFUSED_TOOL = "alpaca__place_stock_order"

#: A real vendor spawn (uvx resolve + import + an HTTP round trip to Alpaca) is
#: slow enough that the SDK's default request timeout is the wrong bar here.
_CALL_TIMEOUT = datetime.timedelta(seconds=180)

requires_paper_keys = pytest.mark.skipif(
    not (os.environ.get("ALPACA_KEY") and os.environ.get("ALPACA_SECRET")),
    reason="opt-in live proof: source ~/.secrets/alpaca.txt for ALPACA_KEY/ALPACA_SECRET",
)


def _provision(tmp_path: Path) -> dict[str, str]:
    """Write this drill's local floor and return the base environment.

    One 0600 secrets blob, one 0600 issuer signing key, one sqlite database, one
    audit file — the product-wrapper Phase-1 shape, provisioned inline rather than through
    `example-wrapper init` because this drill is proving the BASE's mouth, not the wrapper.
    """
    secrets_file = tmp_path / "broker-secrets.json"
    secrets_file.write_text(
        json.dumps(
            {
                # The sa#164 leaf convention: the leaf VALUE is a flat JSON string
                # map, renamed to the server's variables by the manifest's env_map.
                # Values flow shell env -> file -> broker and are never printed.
                "alpaca-mcp-paper": json.dumps(
                    {
                        "ALPACA_KEY": os.environ["ALPACA_KEY"],
                        "ALPACA_SECRET": os.environ["ALPACA_SECRET"],
                    }
                )
            }
        ), encoding="utf-8"
    )
    secrets_file.chmod(0o600)

    issuer_key = tmp_path / "issuer.pem"
    issuer_key.write_text(
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode(), encoding="utf-8"
    )
    issuer_key.chmod(0o600)

    environment = dict(os.environ)
    # A stale AWS-arm signing source would collide with the file arm, and the base
    # refuses when both are set — correctly, since silently picking one attributes
    # records to a key the operator did not mean.
    for stale in ("ISSUER_SIGNING_KEY_SECRET_ARN", "BROKER_AUDIT_BUCKET",
                  "BROKER_ENVELOPE_LOAD", "BROKER_LOCAL_IDENTITY"):
        environment.pop(stale, None)
    environment.update(
        {
            "BROKER_STORE": "sqlite",
            "BROKER_SQLITE_PATH": str(tmp_path / "broker.db"),
            "BROKER_HMAC_KEY": "gateway-alpaca-drill-hmac",
            "BROKER_MANIFEST": str(_MANIFEST),
            "BROKER_SECRETS": "file",
            "BROKER_SECRETS_FILE": str(secrets_file),
            "ISSUER_SIGNING_KEY_FILE": str(issuer_key),
            "ISSUER_SIGNING_KEY_ID": "gateway-drill-issuer-1",
            "ISSUER_SIGNING_ZONE": "local",
        }
    )
    return environment


def _run(module: str, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    """One ceremony/operator invocation, as a subprocess.

    A subprocess and not an import: `BROKER_LOCAL_IDENTITY` selects the ceremony
    half, and maker != checker is re-derived per invocation. Two roles in one
    interpreter would be one process flipping a variable — which is what the local
    arm's `attestation` marker exists to say out loud, not something to hide behind.
    """
    return subprocess.run(  # noqa: S603 — fixed argv, no shell
        [sys.executable, "-m", module, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _admit(env: dict[str, str], snapshot: Path, tool_name: str) -> None:
    """propose (maker) then ratify (checker) for ONE tool, from the snapshot."""
    propose = _run(
        "safe_agents.broker.mcp.commands",
        [
            "admit-propose",
            "--server-id", "alpaca",
            "--tool-name", tool_name,
            "--from-snapshot", str(snapshot),
            "--ttl-hours", "1",
        ],
        env | {"BROKER_LOCAL_IDENTITY": "maker"},
    )
    assert propose.returncode == 0, f"admit-propose {tool_name}: {propose.stdout}{propose.stderr}"

    proposal_id = ""
    for line in propose.stdout.splitlines():
        if "proposal_id=" in line:
            proposal_id = line.split("proposal_id=", 1)[1].split()[0].strip()
    assert proposal_id, f"admit-propose printed no proposal_id: {propose.stdout}"

    ratify = _run(
        "safe_agents.broker.mcp.commands",
        [
            "admit-ratify",
            "--server-id", "alpaca",
            "--tool-name", tool_name,
            "--proposal-id", proposal_id,
        ],
        env | {"BROKER_LOCAL_IDENTITY": "checker"},
    )
    assert ratify.returncode == 0, f"admit-ratify {tool_name}: {ratify.stdout}{ratify.stderr}"


def _drive_gateway(env: dict[str, str]) -> dict:
    """Spawn the gateway and drive it with a real MCP client over real stdio."""

    async def _session() -> dict:
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "safe_agents.broker.gateway"], env=env
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, read_timeout_seconds=_CALL_TIMEOUT
            ) as client:
                await client.initialize()
                listed = await client.list_tools()
                clock = await client.call_tool("alpaca__get_clock", {})
                order = await client.call_tool(
                    _REFUSED_TOOL, {"symbol": "SPY", "side": "buy", "quantity": 1}
                )
                return {
                    "names": sorted(tool.name for tool in listed.tools),
                    "descriptions": {t.name: t.description for t in listed.tools},
                    "clock": clock,
                    "order": order,
                }

    return asyncio.run(_session())


def _read_chain(path: Path) -> list[AuditRecord]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [AuditRecord.model_validate_json(line) for line in lines]


@requires_paper_keys
def test_gateway_serves_ceremony_admitted_alpaca_tools_over_stdio(tmp_path, capsys) -> None:
    env = _provision(tmp_path)
    audit_path = tmp_path / "audit.jsonl"

    # --- 1. Snapshot the live vendor surface (PRE-admission, no rows yet) ------
    snapshot_path = tmp_path / "alpaca-snapshot.json"
    snap = _run(
        "safe_agents.broker.mcp.commands",
        ["snapshot", "--manifest", str(_MANIFEST), "--server-id", "alpaca",
         "--out", str(snapshot_path)],
        env,
    )
    assert snap.returncode == 0, f"snapshot: {snap.stdout}{snap.stderr}"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    advertised = {entry["tool_def"]["tool_name"] for entry in snapshot["entries"]}
    assert len(advertised) >= 60, f"expected the full advertised set, saw {len(advertised)}"
    # The refusal below is only meaningful because the vendor DOES offer this tool.
    assert "place_stock_order" in advertised

    # --- 2. The real two-key ceremony, per coordinate -------------------------
    for tool_name in _DECLARED:
        _admit(env, snapshot_path, tool_name)

    # --- 3. Grants, from the ceremony (F5 forbids seed-at-boot on sqlite) -----
    seed = _run(
        "safe_agents.broker.grants.commands", ["seed"],
        env | {"BROKER_LOCAL_IDENTITY": "maker"},
    )
    assert seed.returncode == 0, f"grants seed: {seed.stdout}{seed.stderr}"

    # --- 4. Drive the SPAWNED gateway with a real MCP client ------------------
    gateway_env = env | {
        "BROKER_GRANT_LOAD": "read",  # serve what the ceremony wrote; absent => denied
        "BROKER_AUDIT_PATH": str(audit_path),
    }
    observed = _drive_gateway(gateway_env)

    # tools/list is exactly the ceiling — the granted set, in wire form.
    assert observed["names"] == _EXPECTED_WIRE_NAMES
    assert _REFUSED_TOOL not in observed["names"]
    # G5: the description is the broker's own classification, never the vendor's.
    assert observed["descriptions"]["alpaca__get_clock"].startswith(
        "alpaca.get_clock — brokered read, external"
    )

    # A read executed against live paper data, through the gateway's own MCP child.
    clock = observed["clock"]
    assert clock.isError is False, clock
    assert "is_open" in clock.content[0].text

    # The order tool is refused over the wire (G4: a refusal is an error).
    order = observed["order"]
    assert order.isError is True, order
    assert "no manifest entry for alpaca.place_stock_order" in order.content[0].text

    # --- 5. The tape: it verifies, and it does NOT contain the refusal --------
    records = _read_chain(audit_path)
    verify_chain(records)  # the load-bearing assertion

    decisions = [(r.tool, r.op, r.decision, r.outcome) for r in records]
    assert ("alpaca", "get_clock", "allow", "executed") in decisions
    # #281 (M26): the unclassified coordinate's refusal IS on the tape now. This
    # assertion was the exact inverse when the drill first ran, which is how the
    # gap was found — see the module docstring.
    assert ("alpaca", "place_stock_order", "deny", "denied") in decisions

    with capsys.disabled():
        print(
            f"\nGATEWAY DRILL DATUM: advertised={len(advertised)} tools; "
            f"admitted={list(_DECLARED)}; served={observed['names']}; "
            f"live_read=alpaca.get_clock (allow/executed); "
            f"refused={_REFUSED_TOOL} (isError, recorded deny/denied — #281 M26); "
            f"chain={len(records)} records, verify_chain OK"
        )
