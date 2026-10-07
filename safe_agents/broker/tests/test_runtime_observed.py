"""`BrokerRuntime.record_observed_event`: a harness's own tool call, observed — SDK-free.

The seam the tool-event mouth enters the runtime through (`broker/GATEWAY.md` G21
on). It records a call the broker never decided, and lets a reported read taint
the broker-held session turn. These tests build the runtime the gateway builds,
from a manifest, through `build_runtime`, so the trust map under test is the base
one (`internal:` trusted, everything else not) and the write that escalates is
decided by the real PDP.

The manifest's write is an external, reversible `crm.post`, granted on-loop and
executed by an offline connector, so on an untainted turn it is ALLOWED. That is
what makes "the report escalates the next write" a comparison and not a constant.
"""

from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path
from typing import Any

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.audit import hash_args, verify_chain
from safe_agents.broker.runtime import AgentRequest
from safe_agents.broker.runtime.observed import (
    TAINTING_CLASSES,
    Locality,
    ToolClass,
    digest_subject,
    validate_observed_event,
)
from safe_agents.broker.runtime.pep import OBSERVED_TOOL
from safe_agents.broker.schemas import compute_envelope_hash

_BROKER_ENV = (
    "BROKER_STORE", "BROKER_MANIFEST", "BROKER_SECRETS", "BROKER_SECRETS_DIR",
    "BROKER_SECRETS_FILE", "BROKER_AUDIT_PATH", "BROKER_AUDIT_BUCKET",
    "BROKER_ENVELOPE_LOAD", "BROKER_GRANT_LOAD", "BROKER_SQLITE_PATH",
)

SUBJECT = digest_subject("/home/someone/.ssh/config")
RESULT = digest_subject("the bytes the read returned")
WRITE = AgentRequest(tool="crm", op="post", args={"note": "hello"})


class OfflinePostConnector:
    """An external write that reaches nothing: the allow path, offline.

    Named by the test manifest's `connector_providers`, so the gateway subprocess
    tests (`test_gateway_events_e2e.py`) execute it too. `crm` is a name the
    memory arm's fake secrets provider already carries.
    """

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        return {"posted": True}


def write_manifest(path: Path, *, trusted: tuple[str, ...] = ()) -> Path:
    """A manifest granting one external write, `crm.post`, on an offline connector."""
    trusted_block = ""
    if trusted:
        trusted_block = "  trusted_read_sources:\n" + "".join(f"    - {s}\n" for s in trusted)
    path.write_text(
        textwrap.dedent(
            """\
            principal:
              agentId: observed-test
              skill: research
              user: local-developer
              tier: C
            grant_classes:
              - crm.post
            connectors:
              - crm
            connector_providers:
              crm: "safe_agents.broker.tests.test_runtime_observed:OfflinePostConnector"
            tool_ops:
              - {tool: crm, op: post, effect: write, external: true, reversible: true}
            envelope:
              polarity: abstain
              caps:
                actions_per_run: 25
              allowlists:
                tools:
                  - crm.post
              high_stakes: false
            """
        )
        + trusted_block,
        encoding="utf-8",
    )
    return path


def _report(**overrides: Any) -> dict[str, Any]:
    report = {
        "mouth": "tool-event",
        "harness": "example-harness",
        "tool_class": "file-read",
        "locality": "outside",
        "subject_digest": SUBJECT,
        "result_digest": RESULT,
    }
    report.update(overrides)
    return report


@pytest.fixture
def built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """(runtime, sink, manifest) from the test manifest; `trusted` via indirect param."""
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    made: list = []

    def build(*, trusted: tuple[str, ...] = ()):
        manifest = load_agent_manifest(write_manifest(tmp_path / f"m{len(made)}.yaml", trusted=trusted))
        runtime, sink = build_runtime(manifest)
        made.append(runtime)
        return runtime, sink, manifest

    try:
        yield build
    finally:
        for runtime in made:
            runtime.close()


class TestTheVocabulary:
    """`observed.py`: the closed sets are exactly what the contract names."""

    def test_the_tool_classes_and_localities_are_closed_sets(self) -> None:
        assert [c.value for c in ToolClass] == [
            "file-read", "file-write", "file-edit", "shell", "web-fetch", "web-search", "other",
        ]
        assert [loc.value for loc in Locality] == ["project", "home", "outside", "remote", "unknown"]
        assert {c.value for c in TAINTING_CLASSES} == {"file-read", "web-fetch", "web-search"}

    def test_the_source_id_is_built_from_codes_alone(self) -> None:
        event = validate_observed_event(**_report(harness="h_1", tool_class="web-fetch", locality="remote"))
        assert event.source_id == "harness:h_1/web-fetch/remote"

    def test_a_subject_digest_is_sha256_over_utf8(self) -> None:
        assert digest_subject("/tmp/é") == "sha256:" + hashlib.sha256("/tmp/é".encode()).hexdigest()


#: Every malformed field the runtime must refuse, whatever the mouth checked.
MALFORMED = [
    pytest.param({"mouth": ""}, id="no mouth"),
    pytest.param({"mouth": "Tool-Event"}, id="uppercase mouth"),
    pytest.param({"mouth": "tool event"}, id="space in mouth"),
    pytest.param({"harness": "Example Harness"}, id="a display name as the harness"),
    pytest.param({"harness": "x" * 41}, id="overlong harness"),
    pytest.param({"harness": "h\nseq=1"}, id="newline in harness"),
    pytest.param({"harness": None}, id="no harness"),
    pytest.param({"harness": 7}, id="number as harness"),
    pytest.param({"tool_class": "read"}, id="unknown tool class"),
    pytest.param({"tool_class": "FILE-READ"}, id="uppercase tool class"),
    pytest.param({"tool_class": None}, id="no tool class"),
    pytest.param({"tool_class": ["file-read"]}, id="list as tool class"),
    pytest.param({"locality": "anywhere"}, id="unknown locality"),
    pytest.param({"locality": ""}, id="empty locality"),
    pytest.param({"subject_digest": "/home/someone/.ssh/config"}, id="a raw path as the subject"),
    pytest.param({"subject_digest": "https://example.com/x"}, id="a raw URL as the subject"),
    pytest.param({"subject_digest": SUBJECT.upper().replace("SHA256", "sha256")}, id="uppercase hex"),
    pytest.param({"subject_digest": SUBJECT[:-1]}, id="short hex"),
    pytest.param({"subject_digest": SUBJECT + "0"}, id="long hex"),
    pytest.param({"subject_digest": SUBJECT + "\n"}, id="trailing newline"),
    pytest.param({"subject_digest": "sha1:" + "0" * 40}, id="another algorithm"),
    pytest.param({"subject_digest": None}, id="no subject"),
    pytest.param({"result_digest": ""}, id="empty result digest"),
    pytest.param({"result_digest": "the file's contents"}, id="content as the result"),
]


class TestTheRecordingSeam:
    @pytest.mark.parametrize("bad", MALFORMED)
    def test_a_malformed_report_is_refused_with_no_record_and_no_taint(self, built, bad) -> None:
        """Every field is re-checked in the runtime. A refusal writes nothing and
        ingests nothing, so a malformed report cannot taint or reach the tape."""
        runtime, sink, _ = built()
        with pytest.raises(ValueError):
            runtime.record_observed_event(**_report(**bad))
        assert sink.records() == []
        assert runtime.session_turn().tainted is False

    def test_a_read_from_outside_taints_the_turn_and_the_next_external_write_escalates(self, built) -> None:
        """The decisive comparison: the same write, allowed before the report and
        held after it, with nothing else changed."""
        runtime, sink, _ = built()
        before = runtime.handle_request(WRITE)
        assert before.decision_kind == "allow"

        source = runtime.record_observed_event(**_report())

        assert source == "harness:example-harness/file-read/outside"
        turn = runtime.session_turn()
        assert turn.tainted is True
        assert turn.to_taint().sources == [source]
        after = runtime.handle_request(WRITE)
        assert after.decision_kind == "require_approval"
        held = sink.records()[-1]
        assert (held.outcome, held.reason) == ("held", "tainted external write")
        assert [r.outcome for r in sink.records()] == ["executed", "observed", "held"]

    @pytest.mark.parametrize("tool_class", sorted(c.value for c in TAINTING_CLASSES))
    def test_every_tainting_class_taints(self, built, tool_class) -> None:
        runtime, _, _ = built()
        assert runtime.record_observed_event(**_report(tool_class=tool_class)) is not None
        assert runtime.session_turn().tainted is True
        assert runtime.handle_request(WRITE).decision_kind == "require_approval"

    @pytest.mark.parametrize(
        "tool_class", sorted(c.value for c in ToolClass if c not in TAINTING_CLASSES)
    )
    def test_a_class_that_brings_nothing_in_records_and_does_not_taint(self, built, tool_class) -> None:
        runtime, sink, _ = built()
        assert runtime.record_observed_event(**_report(tool_class=tool_class)) is None
        assert [r.op for r in sink.records()] == [tool_class]
        assert runtime.session_turn().tainted is False
        assert runtime.handle_request(WRITE).decision_kind == "allow"

    def test_a_source_the_consumer_trusts_records_and_does_not_taint(self, built) -> None:
        """`trusted_read_sources` is the only way a harness class is trusted. The
        report is still on the tape; only the ingest is skipped."""
        trusted = "harness:example-harness/file-read/project"
        runtime, sink, _ = built(trusted=(trusted,))
        assert runtime.record_observed_event(**_report(locality="project")) is None
        assert [r.outcome for r in sink.records()] == ["observed"]
        assert runtime.session_turn().tainted is False
        assert runtime.handle_request(WRITE).decision_kind == "allow"
        # Trust names one class at one locality; the same class from outside still taints.
        assert runtime.record_observed_event(**_report(locality="outside")) is not None
        assert runtime.handle_request(WRITE).decision_kind == "require_approval"

    def test_the_record_has_one_fixed_shape_under_the_runtimes_own_principal(self, built) -> None:
        runtime, sink, manifest = built()
        runtime.record_observed_event(**_report())
        (record,) = sink.records()
        assert (record.tool, record.op) == (OBSERVED_TOOL, "file-read")
        assert (record.decision, record.outcome) == ("abstain", "observed")
        assert record.reason == (
            "observed, not decided: example-harness file-read (outside) reported by mouth tool-event"
        )
        assert record.principal == manifest.principal
        assert record.envelopeHash == compute_envelope_hash(manifest.envelope)
        assert record.resultDigest == RESULT
        assert (record.approvedBy, record.intentId, record.storedCallDigest, record.error) == (
            None, None, None, None,
        )
        verify_chain(sink.records())

    def test_a_reader_holding_the_path_recomputes_the_args_digest(self, built) -> None:
        """What GATEWAY.md promises a reader: from the path and the codes the
        reason names, the record's argsDigest is reproducible, and no other path
        reproduces it."""
        runtime, sink, _ = built()
        runtime.record_observed_event(**_report(result_digest=None))
        (record,) = sink.records()
        assert record.resultDigest is None

        def digest_for(path: str) -> str:
            return hash_args({"harness": "example-harness", "locality": "outside",
                              "subject": digest_subject(path)})

        assert record.argsDigest == digest_for("/home/someone/.ssh/config")
        assert record.argsDigest != digest_for("/home/someone/.ssh/config2")

    def test_taint_lands_even_when_the_record_cannot_be_written(self, built, monkeypatch) -> None:
        """Ingest before emit: every write order fails toward less authority. A
        sink that raises leaves the turn tainted, never the turn clean."""
        runtime, sink, _ = built()

        def broken(_record) -> None:
            raise OSError("the tape is unwritable")

        monkeypatch.setattr(sink, "append", broken)
        with pytest.raises(OSError):
            runtime.record_observed_event(**_report())
        assert runtime.session_turn().tainted is True
        monkeypatch.undo()
        assert runtime.handle_request(WRITE).decision_kind == "require_approval"

    def test_it_never_rolls_the_turn(self, built, monkeypatch) -> None:
        """It can only add taint: `new_turn` is never called and the turn id holds."""
        runtime, _, _ = built()
        turn_id = runtime.session_turn().turn_id
        rolled: list[None] = []
        monkeypatch.setattr(runtime, "new_turn", lambda: rolled.append(None))
        for tool_class in ToolClass:
            runtime.record_observed_event(**_report(tool_class=tool_class.value))
        assert rolled == []
        assert runtime.session_turn().turn_id == turn_id

    def test_every_member_of_both_vocabularies_is_recordable(self, built) -> None:
        runtime, sink, _ = built()
        for tool_class in ToolClass:
            for locality in Locality:
                runtime.record_observed_event(
                    **_report(tool_class=tool_class.value, locality=locality.value)
                )
        assert len(sink.records()) == len(ToolClass) * len(Locality)
        verify_chain(sink.records())
