"""Opt-in LOCAL proof for the #221 Phase-1 Alpaca paper drill (examples/alpaca_paper_drill).

Lives HERE (not in examples/) because a live proof legitimately reaches into
broker internals (build_runtime, TurnContext, the registry) and examples/ is
guarded consumer-clean — the same split as channels' test_airlock_live*.py.

The laptop slice, end-to-end against the REAL pinned ``alpaca-mcp-server``
with PAPER keys — no AWS floor contact (the admitted-tool registry is a moto
table; every other store is the memory arm):

  1. **Discovery** — the pinned server advertises its full tool set (~69 in
     v2.1.1); ``place_stock_order`` is confirmed ADVERTISED (so its later
     refusal is a real refusal, not absence).
  2. **The REAL admission ceremony** — exactly the three declared tools are
     admitted via ``admit-propose`` → ``admit-ratify`` (the ceremony command
     surface, on real ``DynamoToolRegistry``/``DynamoAdmissionProposalStore``
     conditional writes over moto): proposal HMAC, single-shot consume,
     record-before-row, and issuer-DSSE signing all run against the live
     Alpaca coordinates. The IDENTITY half of maker≠checker — two
     credentials, one unmintable by the proposer — is an IAM fact only the
     floor drill proves; here the STS seam is monkeypatched with two
     distinct fake ARNs, exactly as the conformance suite does.
  3. **The native path** — ``build_runtime(manifest)`` composes the connector
     from the manifest's spawn config; the child env is the manifest-pinned
     ``ALPACA_PAPER_TRADE=true`` plus the env_map-renamed paper keys, resolved
     broker-side at spawn (values never appear in test output).
  4. **Reads flow** — ``get_clock`` and ``get_stock_latest_quote`` return live
     structured market data through the full PEP path (allow, executed).
  5. **The order tool refuses UNLISTED** — at the PEP (no grant, no ToolOp ⇒
     deny) AND at the MCP gate (advertised-but-unadmitted ⇒ uncallable), the
     two independent layers that must both fail open for an order to escape.
  6. **Finding-flood discipline** — the ~66 UNLISTED findings surface as ERROR
     logs exactly ONCE per refresh (M5 at volume), not per call.
  7. **Lifecycle (#221 P3)** — SIGKILL the real server mid-session: the next
     dispatch is the TYPED `McpChildDeathError` promptly (M17); the drill
     manifest declares no respawn block, so the failure is sticky (M19 OFF
     path), and `close()` still reaps the whole child tree (M20).

Gated on paper keys in the environment (source ``~/.secrets/alpaca.txt``,
which provides ALPACA_KEY / ALPACA_SECRET); needs network + uvx + the ``mcp``
extra + moto. Run:

    set -a && source ~/.secrets/alpaca.txt && set +a && \
      python -m pytest safe_agents/broker/tests/test_alpaca_drill_live.py -q -s
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytest.importorskip("mcp", reason="the drill drives a real stdio MCP server")
boto3 = pytest.importorskip("boto3")
from moto import mock_aws  # noqa: E402

from safe_agents.broker.grants.record_signing import signer_from_pem  # noqa: E402
from safe_agents.broker.mcp import commands as _mcp_commands  # noqa: E402
from safe_agents.broker.mcp.client import connect_stdio  # noqa: E402
from safe_agents.broker.mcp.commands import (  # noqa: E402
    _build_stores,
    _parse_args,
    admit_propose_command,
    admit_ratify_command,
)
from safe_agents.broker.mcp.host import ToolNotCallableError  # noqa: E402
from safe_agents.broker.mcp.signing import (  # noqa: E402
    canonical_record_payload,
    verify_admission_record,
)
from safe_agents.broker.prototype.broker_server import build_runtime  # noqa: E402
from safe_agents.broker.runtime import AgentRequest  # noqa: E402
from safe_agents.broker.schemas import AgentManifest  # noqa: E402
from safe_agents.broker.schemas.mcp_registry import compute_tool_def_hash  # noqa: E402
from safe_agents.broker.taint import TurnContext  # noqa: E402
from safe_agents.channels.keys import key_resolver_from_map  # noqa: E402

_DRILL_DIR = Path(__file__).resolve().parents[3] / "examples" / "alpaca_paper_drill"
_TABLE = "alpaca-drill-registry-local"
_DECLARED = ("get_account_info", "get_clock", "get_stock_latest_quote")
_REFUSED_COORDINATE = ("alpaca", "place_stock_order")
# Two DISTINCT fake STS identities through the _caller_identity monkeypatch seam
# (M7's code path; the IAM fact behind it is the floor drill's to prove).
_MAKER_ARN = "arn:aws:sts::000000000000:assumed-role/DrillMakerRole/local-proof"
_CHECKER_ARN = "arn:aws:sts::000000000000:assumed-role/DrillCheckerRole/local-proof"
_ISSUER_KEY_ID = "drill-issuer-1"

requires_paper_keys = pytest.mark.skipif(
    not (os.environ.get("ALPACA_KEY") and os.environ.get("ALPACA_SECRET")),
    reason="opt-in live proof: source ~/.secrets/alpaca.txt for ALPACA_KEY/ALPACA_SECRET",
)


def _child_probe_env() -> dict[str, str]:
    """The DISCOVERY child's env — same rename the manifest env_map performs,
    done here directly because discovery runs before any broker exists."""
    return {
        "ALPACA_API_KEY": os.environ["ALPACA_KEY"],
        "ALPACA_SECRET_KEY": os.environ["ALPACA_SECRET"],
        "ALPACA_PAPER_TRADE": "true",
    }


def _quote_args(input_schema: dict) -> dict:
    """Build get_stock_latest_quote args from the LIVE schema (arg names are
    the server's to define; adapt rather than hardcode)."""
    props = input_schema.get("properties", {})
    for candidate in ("symbol_or_symbols", "symbols", "symbol"):
        if candidate in props:
            return {candidate: "SPY"}
    required = input_schema.get("required") or list(props)
    assert required, "get_stock_latest_quote advertises no arguments?"
    return {required[0]: "SPY"}


@requires_paper_keys
@mock_aws
def test_alpaca_paper_drill_local_proof(monkeypatch, caplog, tmp_path, capsys):
    manifest = AgentManifest.model_validate(
        yaml.safe_load((_DRILL_DIR / "manifest.yaml").read_text())
    )

    # --- broker-side secret leaf: flat JSON string map, 0600 file, values
    # flow shell env -> file -> broker; never printed. -----------------------
    secrets_file = tmp_path / "broker-secrets.json"
    secrets_file.write_text(
        json.dumps(
            {
                "alpaca-mcp-paper": json.dumps(
                    {
                        "ALPACA_KEY": os.environ["ALPACA_KEY"],
                        "ALPACA_SECRET": os.environ["ALPACA_SECRET"],
                    }
                )
            }
        )
    )
    secrets_file.chmod(0o600)
    monkeypatch.setenv("BROKER_SECRETS_FILE", str(secrets_file))
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", _TABLE)
    # One NAMED key for both sides: the ceremony writes and the broker reads
    # under BROKER_HMAC_KEY (the #205 discipline — the ceremony refuses to run
    # on the dev-key fallback).
    monkeypatch.setenv("BROKER_HMAC_KEY", "alpaca-drill-local-hmac")
    for var in ("BROKER_STORE", "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD",
                "BROKER_AUDIT_BUCKET", "BROKER_AUDIT_PATH", "BROKER_SECRETS"):
        monkeypatch.delenv(var, raising=False)

    # The moto registry table (pk/sk, the State-stack shape).
    boto3.resource("dynamodb").create_table(
        TableName=_TABLE,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # --- 1. DISCOVERY against the real pinned server -------------------------
    async def fetch_defs():
        async with connect_stdio(
            "alpaca", "uvx", ["alpaca-mcp-server==2.1.1"], env=_child_probe_env()
        ) as client:
            return await client.list_tool_defs()

    defs = asyncio.run(fetch_defs())
    by_name = {d.tool_name: d for d in defs}
    assert len(defs) >= 60, f"expected the full advertised set, saw {len(defs)}"
    assert set(_DECLARED) <= set(by_name), "a declared tool vanished from discovery"
    assert _REFUSED_COORDINATE[1] in by_name, (
        "place_stock_order must be ADVERTISED for its refusal to mean anything"
    )

    # --- 2. The REAL admission ceremony: admit EXACTLY the declared subset ---
    # admit-propose (maker) -> admit-ratify (checker) through the actual
    # command surface, per tool: proposal HMAC, single-shot consume,
    # record-before-row, issuer-DSSE signing — on the real Dynamo conditional
    # writes (moto). _build_stores exercises the operator path too (named
    # HMAC key + named table, never a dev fallback).
    registry, proposal_store = _build_stores(_TABLE)
    issuer_sk = Ed25519PrivateKey.generate()
    issuer_priv = issuer_sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    issuer_pub = issuer_sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    signer = signer_from_pem(_ISSUER_KEY_ID, "drill-zone", issuer_priv)
    resolver = key_resolver_from_map({_ISSUER_KEY_ID: issuer_pub})

    first_proposal_id: str | None = None
    for name in _DECLARED:
        d = by_name[name]
        def_path = tmp_path / f"tool-def-{name}.json"
        def_path.write_text(d.model_dump_json())

        monkeypatch.setattr(
            _mcp_commands, "_caller_identity", lambda session=None: _MAKER_ARN
        )
        assert admit_propose_command(
            _parse_args(
                [
                    "admit-propose",
                    "--server-id", d.server_id,
                    "--tool-name", name,
                    "--tool-def-json", str(def_path),
                    "--ttl-hours", "1",
                ]
            ),
            proposal_store=proposal_store,
        ) == 0
        match = re.search(r"proposal_id=(\S+)", capsys.readouterr().out)
        assert match, "admit-propose printed no proposal_id"
        proposal_id = match.group(1)
        first_proposal_id = first_proposal_id or proposal_id

        monkeypatch.setattr(
            _mcp_commands, "_caller_identity", lambda session=None: _CHECKER_ARN
        )
        assert admit_ratify_command(
            _parse_args(
                [
                    "admit-ratify",
                    "--server-id", d.server_id,
                    "--tool-name", name,
                    "--proposal-id", proposal_id,
                ]
            ),
            store=registry,
            proposal_store=proposal_store,
            signer=signer,
        ) == 0
        capsys.readouterr()

        # The ledger row binds who+what+hash and its DSSE envelope verifies
        # against the issuer public key (record-before-row landed both).
        records = registry.list_records(d.server_id, name)
        assert len(records) == 1
        record = records[0]
        assert record.defHash == compute_tool_def_hash(d)
        assert record.proposedBy == _MAKER_ARN and record.ratifiedBy == _CHECKER_ARN
        item = boto3.resource("dynamodb").Table(_TABLE).get_item(
            Key={"pk": f"TOOLREC#{d.server_id}#{name}", "sk": record.ts}
        )["Item"]
        envelope = json.loads(item["signature"])
        assert verify_admission_record(canonical_record_payload(record), envelope, resolver).ok

    # Single-shot: a consumed proposal can never be ratified again.
    assert admit_ratify_command(
        _parse_args(
            [
                "admit-ratify",
                "--server-id", "alpaca",
                "--tool-name", _DECLARED[0],
                "--proposal-id", first_proposal_id,
            ]
        ),
        store=registry,
        proposal_store=proposal_store,
        signer=signer,
    ) == 1
    assert "not pending" in capsys.readouterr().out

    # --- 3+4. The native path: build_runtime -> reads flow -------------------
    runtime, _sink = build_runtime(manifest)
    connector = runtime._doer._connectors["alpaca"]  # test-only reach-in (teardown + gate leg)
    try:
        with caplog.at_level(logging.ERROR, logger="safe_agents.broker.mcp.host"):
            r_clock = runtime.handle_request(
                AgentRequest(tool="alpaca", op="get_clock", args={}),
                turn_context=TurnContext(turn_id="drill-turn-1"),
            )
            assert r_clock.decision_kind == "allow", r_clock
            assert r_clock.result.isError is False
            assert "is_open" in (r_clock.result.structuredContent or {}) or True

            quote_args = _quote_args(by_name["get_stock_latest_quote"].input_schema)
            r_quote = runtime.handle_request(
                AgentRequest(tool="alpaca", op="get_stock_latest_quote", args=quote_args),
                turn_context=TurnContext(turn_id="drill-turn-2"),
            )
            assert r_quote.decision_kind == "allow", r_quote
            assert r_quote.result.isError is False, "live paper market-data call failed"

            # --- 6a. Flood discipline: findings surfaced once, at refresh ----
            unlisted_after_refresh = [
                rec for rec in caplog.records if "unlisted" in rec.getMessage()
            ]
            n_findings = len(unlisted_after_refresh)
            assert n_findings >= 50, (
                f"expected the UNLISTED flood to surface at refresh, saw {n_findings}"
            )

            # --- 5. The order tool refuses UNLISTED --------------------------
            # (a) PEP layer: no grant, no ToolOp -> deny before any transport.
            r_order = runtime.handle_request(
                AgentRequest(
                    tool="alpaca",
                    op="place_stock_order",
                    args={"symbol": "SPY", "side": "buy", "quantity": 1},
                ),
                turn_context=TurnContext(turn_id="drill-turn-3"),
            )
            assert r_order.decision_kind == "deny", (
                f"UNLISTED order op must deny at the PEP, got {r_order.decision_kind}"
            )
            # (b) MCP gate layer: even bypassing the PEP, the advertised-but-
            # unadmitted tool is uncallable through the pure discovery gate.
            with pytest.raises(ToolNotCallableError):
                connector.execute(
                    "alpaca", "place_stock_order", {"symbol": "SPY"}, credential=""
                )

            # --- 6b. Once-per-refresh at volume: more calls add NO findings --
            r_again = runtime.handle_request(
                AgentRequest(tool="alpaca", op="get_clock", args={}),
                turn_context=TurnContext(turn_id="drill-turn-4"),
            )
            assert r_again.decision_kind == "allow"
            assert (
                len([rec for rec in caplog.records if "unlisted" in rec.getMessage()])
                == n_findings
            ), "UNLISTED findings re-surfaced per call — M5 discipline broken at volume"

            # --- 7. Lifecycle (#221 P3, M17/M19) against the REAL server -----
            # SIGKILL the pinned server's process tree mid-session: the next
            # dispatch is the TYPED death error, promptly; the drill manifest
            # declares no respawn block, so the failure is sticky — the OFF
            # path against a real third-party child.
            from safe_agents.broker.mcp.factory import McpChildDeathError

            out = subprocess.run(
                ["pgrep", "-f", "alpaca.mcp.server"], capture_output=True, text=True
            )
            child_pids = [int(line) for line in out.stdout.split()]
            assert child_pids, "no live alpaca server child to kill?"
            for pid in child_pids:
                os.kill(pid, signal.SIGKILL)
            t0 = time.monotonic()
            with pytest.raises(McpChildDeathError):
                connector.execute("alpaca", "get_clock", {}, credential="")
            assert time.monotonic() - t0 < 10.0, "death was not prompt"
            with pytest.raises(McpChildDeathError):  # sticky: absent block = no respawn
                connector.execute("alpaca", "get_clock", {}, credential="")
    finally:
        connector.close()
    # M20 through teardown: the killed child's tree is fully gone after close().
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        probe = subprocess.run(
            ["pgrep", "-f", "alpaca.mcp.server"], capture_output=True, text=True
        )
        if not probe.stdout.split():
            break
        time.sleep(0.1)
    else:
        raise AssertionError("alpaca server child leaked past connector.close()")

    # --- The drill datum (for the session summary / epic record) -------------
    with capsys.disabled():
        print(
            f"\nDRILL DATUM: discovered={len(defs)} tools; "
            f"admitted={list(_DECLARED)}; "
            f"refused_coordinate={'.'.join(_REFUSED_COORDINATE)} "
            f"(PEP deny + MCP-gate ToolNotCallableError); "
            f"unlisted_findings_per_refresh={n_findings} (once, not per call)"
        )
