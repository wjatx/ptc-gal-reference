"""An honest MCP registry store, and the ways to damage it out of band.

Shared by the audit's rule tests and its command tests. The store is written by
the admit ceremony itself (``admit_propose_command`` then
``admit_ratify_command``) against a temporary sqlite file, with nothing
hand-built. ``Tamper`` then edits that file with raw sqlite, the way someone
with write access to it would, and each named edit below is one such change.
"""

from __future__ import annotations

import base64
import datetime
import json
import sqlite3
from dataclasses import dataclass

from safe_agents.broker.grants.record_signing import signer_from_pem
from safe_agents.broker.mcp.commands import (
    _parse_args,
    admit_propose_command,
    admit_ratify_command,
)
from safe_agents.broker.mcp.proposals import KIND_ADMISSION, KIND_REVET, _hmac_payload
from safe_agents.broker.mcp.signing import (
    McpAdmissionRecord,
    _build_admission_statement,
    sign_admission_record,
)
from safe_agents.broker.mcp.sqlite_stores import (
    SqliteAdmissionProposalStore,
    SqliteToolRegistry,
)
from safe_agents.broker.schemas.mcp_registry import McpToolDef
from safe_agents.broker.tests.test_mcp_registry_store import (
    CHECKER_ARN,
    MAKER_ARN,
    SERVER_ID,
    _keypair,
    set_caller,
)
from safe_agents.channels.keys import key_resolver_from_map
from safe_agents.channels.signing import DSSE_PAYLOAD_TYPE, pae

HMAC_KEY = b"audit-test-hmac-key"
ISSUER_KEY_ID = "issuer:A"
ZONE = "zone-a"
NOW = datetime.datetime(2026, 7, 17, 12, 0, tzinfo=datetime.timezone.utc)

# Two tools. QUOTE is admitted and then re-vetted, so its row has a two-record
# history; HISTORY is admitted once.
QUOTE, HISTORY = "quote", "history"
ROW_SK = "ROW"


def row_pk(tool: str) -> str:
    return f"TOOLDEF#{SERVER_ID}#{tool}"


def record_pk(tool: str) -> str:
    return f"TOOLREC#{SERVER_ID}#{tool}"


def proposal_pk(tool: str) -> str:
    return f"TOOLPROP#{SERVER_ID}#{tool}"


# ---------------------------------------------------------------------------
# The honest store: the real ceremony against a temporary sqlite file
# ---------------------------------------------------------------------------


@dataclass
class Issuer:
    key_id: str
    signer: object
    public_pem: str

    @property
    def resolver(self):
        return key_resolver_from_map({self.key_id: self.public_pem})


def make_issuer(key_id: str = ISSUER_KEY_ID) -> Issuer:
    private_pem, public_pem = _keypair()
    return Issuer(key_id, signer_from_pem(key_id, ZONE, private_pem), public_pem)


def admit(db_path, monkeypatch, tmp_path, signer, tool, *, description, kind, minute) -> None:
    """One full propose→ratify ceremony for ``tool``, through the command functions."""
    registry = SqliteToolRegistry(HMAC_KEY, db_path)
    proposals = SqliteAdmissionProposalStore(HMAC_KEY, db_path)
    now = NOW + datetime.timedelta(minutes=minute)
    tool_def = McpToolDef(
        server_id=SERVER_ID,
        tool_name=tool,
        input_schema={"type": "object", "properties": {"symbol": {"type": "string"}}},
        description=description,
    )
    def_path = tmp_path / f"{tool}-{minute}.json"
    def_path.write_text(tool_def.model_dump_json(), encoding="utf-8")
    coordinate = ["--server-id", SERVER_ID, "--tool-name", tool]
    try:
        set_caller(monkeypatch, MAKER_ARN)
        propose = _parse_args(
            ["admit-propose", *coordinate, "--tool-def-json", str(def_path),
             "--kind", kind, "--ttl-hours", "1"]
        )
        assert admit_propose_command(propose, store=registry, proposal_store=proposals, now=now) == 0
        ((proposal, _status),) = proposals.list_pending(SERVER_ID, tool)

        set_caller(monkeypatch, CHECKER_ARN)
        ratify = _parse_args(
            ["admit-ratify", *coordinate, "--proposal-id", proposal.proposal_id, "--zone", ZONE]
        )
        assert admit_ratify_command(
            ratify, store=registry, proposal_store=proposals, signer=signer, now=now
        ) == 0
    finally:
        registry.close()
        proposals.close()


def build_honest_store(db_path, monkeypatch, tmp_path, signer) -> None:
    """2 rows, 3 admission records, 3 consumed proposals: all ceremony-written."""
    admit(db_path, monkeypatch, tmp_path, signer, QUOTE,
          description="return a quote", kind=KIND_ADMISSION, minute=0)
    admit(db_path, monkeypatch, tmp_path, signer, HISTORY,
          description="return price history", kind=KIND_ADMISSION, minute=1)
    admit(db_path, monkeypatch, tmp_path, signer, QUOTE,
          description="return a delayed quote", kind=KIND_REVET, minute=2)


# ---------------------------------------------------------------------------
# Out-of-band edits: raw sqlite, as someone with write access to the file would
# ---------------------------------------------------------------------------


class Tamper:
    """Edit the store file directly, bypassing every store class."""

    def __init__(self, db_path, issuer: Issuer) -> None:
        self.db_path = db_path
        self.issuer = issuer

    def _run(self, sql: str, params: tuple = ()) -> list:
        conn = sqlite3.connect(str(self.db_path))
        try:
            with conn:
                return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def sks(self, pk: str) -> list[str]:
        return [sk for (sk,) in self._run("SELECT sk FROM items WHERE pk = ? ORDER BY sk", (pk,))]

    def only_sk(self, pk: str) -> str:
        (sk,) = self.sks(pk)
        return sk

    def get(self, pk: str, sk: str) -> dict:
        ((item,),) = self._run("SELECT item FROM items WHERE pk = ? AND sk = ?", (pk, sk))
        return json.loads(item)

    def put(self, pk: str, sk: str, attrs: dict) -> None:
        self._run(
            "INSERT OR REPLACE INTO items (pk, sk, item) VALUES (?, ?, ?)",
            (pk, sk, json.dumps(attrs)),
        )

    def delete(self, pk: str, sk: str | None = None) -> None:
        if sk is None:
            self._run("DELETE FROM items WHERE pk = ?", (pk,))
        else:
            self._run("DELETE FROM items WHERE pk = ? AND sk = ?", (pk, sk))

    def edit(self, pk: str, sk: str, **changes) -> None:
        """Set attributes; a value of None removes the attribute."""
        attrs = self.get(pk, sk)
        for name, value in changes.items():
            if value is None:
                attrs.pop(name, None)
            else:
                attrs[name] = value
        self.put(pk, sk, attrs)

    def edit_data(self, pk: str, sk: str, **fields) -> dict:
        """Change fields INSIDE the stored ``data`` JSON, keeping it parseable."""
        attrs = self.get(pk, sk)
        data = json.loads(attrs["data"]) | fields
        attrs["data"] = json.dumps(data, sort_keys=True, separators=(",", ":"))
        self.put(pk, sk, attrs)
        return attrs

    def edit_envelope(self, pk: str, sk: str, mutate) -> None:
        attrs = self.get(pk, sk)
        envelope = json.loads(attrs["signature"])
        mutate(envelope)
        self.edit(pk, sk, signature=json.dumps(envelope))


def _resign(tamper: Tamper, signer, tool: str = HISTORY) -> None:
    sk = tamper.only_sk(record_pk(tool))
    record = McpAdmissionRecord.model_validate_json(tamper.get(record_pk(tool), sk)["data"])
    tamper.edit(record_pk(tool), sk, signature=json.dumps(sign_admission_record(record, signer)))


def signature_bytes_altered(t: Tamper) -> None:
    def flip(envelope: dict) -> None:
        envelope["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()

    t.edit_envelope(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), flip)


def stored_record_bytes_altered(t: Tamper) -> None:
    """Still a well-formed record at the same key: only the ratifier changed."""
    t.edit_data(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)),
                ratifiedBy="arn:aws:sts::999999999999:assumed-role/Evil/e")


def stored_record_bytes_reformatted(t: Tamper) -> None:
    """The same record, re-serialized with whitespace. It parses to an equal
    model, so only a check over the STORED bytes can tell it was rewritten."""
    sk = t.only_sk(record_pk(HISTORY))
    data = t.get(record_pk(HISTORY), sk)["data"]
    t.edit(record_pk(HISTORY), sk, data=json.dumps(json.loads(data), indent=1))


def record_signature_removed(t: Tamper) -> None:
    t.edit(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), signature=None)


def record_signed_by_an_unknown_key(t: Tamper) -> None:
    _resign(t, make_issuer("evaluator:B").signer)


def record_signed_by_another_key_under_the_issuer_key_id(t: Tamper) -> None:
    _resign(t, make_issuer(ISSUER_KEY_ID).signer)


def second_signature_does_not_verify(t: Tamper) -> None:
    """The seed checked only ``signatures[0]``; every signature present must verify."""
    def add(envelope: dict) -> None:
        envelope["signatures"].append(
            {"keyid": ISSUER_KEY_ID, "sig": base64.b64encode(b"\x01" * 64).decode()}
        )

    t.edit_envelope(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), add)


def envelope_payload_type_changed(t: Tamper) -> None:
    def retype(envelope: dict) -> None:
        envelope["payloadType"] = "application/json"

    t.edit_envelope(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), retype)


def envelope_is_not_json(t: Tamper) -> None:
    t.edit(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), signature="{not json")


def signed_index_disagrees_with_the_record(t: Tamper) -> None:
    """The issuer key signs a statement whose subject digest is the stored
    record's and whose in-the-clear index names a different ratifier."""
    sk = t.only_sk(record_pk(HISTORY))
    record = McpAdmissionRecord.model_validate_json(t.get(record_pk(HISTORY), sk)["data"])
    signer = t.issuer.signer
    statement = json.loads(
        _build_admission_statement(record, key_id=signer.key_id, zone=signer.zone)
    )
    statement["predicate"]["record"]["ratifiedBy"] = "arn:aws:sts::999999999999:role/Evil"
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": signer.key_id,
                "sig": base64.b64encode(signer.sign_pae(pae(DSSE_PAYLOAD_TYPE, payload))).decode(),
            }
        ],
    }
    t.edit(record_pk(HISTORY), sk, signature=json.dumps(envelope))


def record_copied_in_place_of_another_tools(t: Tamper) -> None:
    """HISTORY's own ledger is replaced by QUOTE's newest, validly signed record."""
    quote_sk = t.sks(record_pk(QUOTE))[-1]
    t.delete(record_pk(HISTORY))
    t.put(record_pk(HISTORY), quote_sk, t.get(record_pk(QUOTE), quote_sk))


def record_copied_beside_another_tools(t: Tamper) -> None:
    """A later-dated foreign record sits beside HISTORY's own. It must not
    become the 'newest record' that row is judged against."""
    quote_sk = t.sks(record_pk(QUOTE))[-1]
    t.put(record_pk(HISTORY), quote_sk, t.get(record_pk(QUOTE), quote_sk))


def record_moved_to_another_sort_key(t: Tamper) -> None:
    sk = t.only_sk(record_pk(HISTORY))
    attrs = t.get(record_pk(HISTORY), sk)
    t.delete(record_pk(HISTORY), sk)
    t.put(record_pk(HISTORY), "2030-01-01T00:00:00+00:00", attrs)


def row_copied_under_another_tools_key(t: Tamper) -> None:
    """The row HMAC is over ``data`` alone, so the copy's HMAC still verifies."""
    t.put(row_pk(HISTORY), ROW_SK, t.get(row_pk(QUOTE), ROW_SK))


def row_hmac_replaced(t: Tamper) -> None:
    t.edit(row_pk(HISTORY), ROW_SK, rowHash="0" * 64)


def row_hmac_removed(t: Tamper) -> None:
    t.edit(row_pk(HISTORY), ROW_SK, rowHash=None)


def row_bytes_altered(t: Tamper) -> None:
    t.edit_data(row_pk(HISTORY), ROW_SK, admitted_by="arn:aws:sts::999999999999:role/Evil")


def row_rewritten_with_the_hmac_key(t: Tamper) -> None:
    """A holder of the HMAC key points the row at a hash no record ratified."""
    attrs = t.edit_data(row_pk(HISTORY), ROW_SK, def_hash="b" * 64)
    t.edit(row_pk(HISTORY), ROW_SK, rowHash=_hmac_payload(attrs["data"], HMAC_KEY))


def newest_record_erased(t: Tamper) -> None:
    """QUOTE's re-vet record is deleted; the row still carries the re-vetted hash."""
    t.delete(record_pk(QUOTE), t.sks(record_pk(QUOTE))[-1])


def all_records_erased(t: Tamper) -> None:
    t.delete(record_pk(HISTORY))


def row_erased(t: Tamper) -> None:
    t.delete(row_pk(HISTORY), ROW_SK)


def row_bytes_unparseable(t: Tamper) -> None:
    t.edit(row_pk(HISTORY), ROW_SK, data="{not json")


def row_fails_the_schema(t: Tamper) -> None:
    t.edit(row_pk(HISTORY), ROW_SK, data=json.dumps({"def_hash": "a" * 64}))


def record_bytes_unparseable(t: Tamper) -> None:
    t.edit(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), data="{not json")


def record_has_no_stored_bytes(t: Tamper) -> None:
    t.edit(record_pk(HISTORY), t.only_sk(record_pk(HISTORY)), data=None)


def proposal_bytes_unparseable(t: Tamper) -> None:
    t.edit(proposal_pk(HISTORY), t.only_sk(proposal_pk(HISTORY)), data="{not json")


def proposal_bytes_altered(t: Tamper) -> None:
    t.edit_data(proposal_pk(HISTORY), t.only_sk(proposal_pk(HISTORY)), def_hash="c" * 64)


def proposal_status_hand_edited(t: Tamper) -> None:
    t.edit(proposal_pk(HISTORY), t.only_sk(proposal_pk(HISTORY)), status="approved")


def proposal_status_not_a_string(t: Tamper) -> None:
    t.edit(proposal_pk(HISTORY), t.only_sk(proposal_pk(HISTORY)), status=["ratified"])


def proposal_moved_to_another_tools_key(t: Tamper) -> None:
    sk = t.only_sk(proposal_pk(HISTORY))
    attrs = t.get(proposal_pk(HISTORY), sk)
    t.delete(proposal_pk(HISTORY), sk)
    t.put(proposal_pk("other"), sk, attrs)
