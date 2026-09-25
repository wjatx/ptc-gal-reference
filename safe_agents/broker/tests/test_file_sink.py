"""Crash-tolerance and thread-safety tests for FileAuditSink (sa#102).

Covers the two hardening fixes for the local-file audit sink:
  1. Torn write on crash — a partial, unterminated final JSON line must not block
     restart: resuming() trims it and records() skips it, both with a warning; but a
     malformed line that IS newline-terminated (real mid-file corruption) still raises.
  2. Thread-safety — under ThreadingHTTPServer two concurrent emit() calls must not read
     the same seq. Concurrent appends must produce a valid, gap-free chain.

All tests are pure stdlib + tmp files; no AWS.
"""

from __future__ import annotations

import threading

import pytest

from safe_agents.broker.audit import FileAuditSink, GENESIS_PREV_HASH, emit, verify_chain
from safe_agents.broker.schemas.common import Principal

PRINCIPAL = Principal(agentId="agent-file", skill="email", user="alice", tier="B")

BASE_EMIT = dict(
    principal=PRINCIPAL,
    tool="email",
    op="send",
    args={"to": "bob@example.com"},
    envelope_hash="sha256:envelope",
    decision="allow",
    outcome="executed",
)


def _emit_n(sink: FileAuditSink, n: int) -> None:
    for _ in range(n):
        emit(sink, **BASE_EMIT)


# ---------------------------------------------------------------------------
# 1. Torn trailing line tolerated
# ---------------------------------------------------------------------------


def test_resuming_tolerates_and_trims_torn_trailing_line(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    sink = FileAuditSink(path)
    _emit_n(sink, 3)  # three complete records, each newline-terminated

    # Simulate a crash mid-append: append a partial, UNTERMINATED line (no newline).
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"seq": 3, "ts": "2026-06-30T00:00:00+00:00", "principal": {"agen')

    # resuming() must not raise; it trims the torn tail and resumes the chain at seq=3.
    resumed = FileAuditSink.resuming(path)
    assert resumed.next_seq == 3
    assert resumed.last_hash != GENESIS_PREV_HASH

    # The torn bytes were physically trimmed, so the next append lands on a clean line
    # and the chain stays valid on the very next resume — no poison line left behind.
    emit(resumed, **BASE_EMIT)
    records = FileAuditSink.resuming(path).records()
    assert len(records) == 4
    assert [r.seq for r in records] == [0, 1, 2, 3]
    verify_chain(records)


def test_records_skips_torn_trailing_line_without_mutating_file(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    sink = FileAuditSink(path)
    _emit_n(sink, 2)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"seq": 2, "ts": "part')  # torn, unterminated

    # records() on a sink pointed at the file skips the torn tail (read-only, no trim).
    reader = FileAuditSink(path, initial_seq=2)
    recs = reader.records()
    assert len(recs) == 2
    verify_chain(recs)
    # File was NOT mutated by records() — the torn bytes are still present on disk.
    with open(path, encoding="utf-8") as handle:
        assert '{"seq": 2, "ts": "part' in handle.read()


def test_middle_corruption_still_raises(tmp_path):
    """A malformed, newline-TERMINATED line (real corruption, not a torn write) raises."""
    path = str(tmp_path / "audit.jsonl")
    sink = FileAuditSink(path)
    _emit_n(sink, 3)
    # Inject a garbage COMPLETE line (terminated) in the middle, followed by more content.
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()
    lines.insert(1, "this-is-not-json\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)

    with pytest.raises(ValueError):
        FileAuditSink.resuming(path)
    with pytest.raises(ValueError):
        FileAuditSink(path).records()


def test_empty_and_missing_file_start_fresh(tmp_path):
    missing = str(tmp_path / "nope.jsonl")
    fresh = FileAuditSink.resuming(missing)
    assert fresh.next_seq == 0
    assert fresh.last_hash == GENESIS_PREV_HASH

    empty = str(tmp_path / "empty.jsonl")
    open(empty, "w", encoding="utf-8").close()
    fresh2 = FileAuditSink.resuming(empty)
    assert fresh2.next_seq == 0


# ---------------------------------------------------------------------------
# 2. Thread-safety — concurrent appends produce a valid, gap-free chain
# ---------------------------------------------------------------------------


def test_concurrent_appends_produce_valid_chain(tmp_path):
    path = str(tmp_path / "concurrent.jsonl")
    sink = FileAuditSink(path)

    threads_count = 16
    per_thread = 20
    barrier = threading.Barrier(threads_count)
    errors: list[Exception] = []

    def worker() -> None:
        barrier.wait()  # maximize contention: all threads hit emit() together
        try:
            for _ in range(per_thread):
                emit(sink, **BASE_EMIT)
        except Exception as exc:  # noqa: BLE001 — recorded and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"emit() raised under concurrency: {errors!r}"

    records = FileAuditSink.resuming(path).records()
    total = threads_count * per_thread
    assert len(records) == total, "every concurrent append must be on the tape"
    # Seq is contiguous 0..total-1 with no gaps or collisions, and the chain verifies.
    assert [r.seq for r in records] == list(range(total))
    verify_chain(records)


def test_concurrent_appends_in_memory_chain_valid():
    """Same guarantee for InMemorySink (used by unit tests + the memory arm)."""
    from safe_agents.broker.audit import InMemorySink

    sink = InMemorySink()
    threads_count = 12
    per_thread = 25
    barrier = threading.Barrier(threads_count)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            emit(sink, **BASE_EMIT)

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = sink.records()
    total = threads_count * per_thread
    assert [r.seq for r in records] == list(range(total))
    verify_chain(records)


# ---------------------------------------------------------------------------
# 3. Multi-process safety (#301) — the gateway and a release CLI share one tape
# ---------------------------------------------------------------------------
#
# Threads are not the hard case here. On the local floor the writers are separate
# PROCESSES — `example-wrapper gateway` serving the wrapped agent, and `example-wrapper approve` releasing
# a held intent — and a threading.Lock does not span them. Before the fix each
# process kept its own cached seq/last_hash, so the second writer produced a
# duplicate seq and a wrong prevHash with NO error raised; the corruption only
# surfaced later, as verify_chain() reporting a gap. An honest release was
# indistinguishable from tampering.
#
# These tests drive real interpreters, because an in-process fake would pass on
# the threading lock alone and prove nothing about the flock.

_WRITER_SRC = """
import sys
from safe_agents.broker.audit import FileAuditSink, emit
from safe_agents.broker.schemas.common import Principal

path, count = sys.argv[1], int(sys.argv[2])
sink = FileAuditSink.resuming(path)
principal = Principal(agentId="agent-file", skill="email", user="alice", tier="B")
for _ in range(count):
    emit(
        sink,
        principal=principal,
        tool="email",
        op="send",
        args={"to": "bob@example.com"},
        envelope_hash="sha256:envelope",
        decision="allow",
        outcome="executed",
    )
"""


def _spawn_writers(path: str, *, processes: int, per_process: int) -> None:
    """Run N interpreters appending to one tape at once; assert all succeeded."""
    import subprocess
    import sys

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WRITER_SRC, path, str(per_process)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(processes)
    ]
    for proc in procs:
        _out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, f"writer failed: {err.decode()}"


def test_concurrent_processes_produce_valid_chain(tmp_path):
    """Separate processes appending to one tape leave a gap-free, verifiable chain."""
    path = str(tmp_path / "multiproc.jsonl")
    processes, per_process = 4, 15
    _spawn_writers(path, processes=processes, per_process=per_process)

    records = FileAuditSink(path).records()
    total = processes * per_process
    assert [r.seq for r in records] == list(range(total)), (
        "seqs must be dense and unique across processes — a duplicate here is the "
        "pre-#301 bug, where each process trusted its own cached counter"
    )
    verify_chain(records)


def test_second_process_release_does_not_break_a_live_sink(tmp_path):
    """The exact #301 shape: a live gateway sink, a release from another process.

    The gateway holds its sink open across the release (it is a long-lived stdio
    server), so its cached counters go stale. Its next append must still land on
    the real tail rather than colliding with the record the other process wrote.
    """
    path = str(tmp_path / "release.jsonl")

    gateway = FileAuditSink.resuming(path)  # long-lived; stays open throughout
    _emit_n(gateway, 2)
    assert gateway.next_seq == 2

    _spawn_writers(path, processes=1, per_process=1)  # `example-wrapper approve` releases

    _emit_n(gateway, 1)  # gateway serves one more call on stale counters

    records = FileAuditSink(path).records()
    assert [r.seq for r in records] == [0, 1, 2, 3]
    verify_chain(records)
