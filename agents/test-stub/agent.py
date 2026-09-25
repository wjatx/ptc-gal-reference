#!/usr/bin/env python3
"""
Test-stub agent — the reference do-nothing agent.

Satisfies runner-contract elements 2, 3, 4, 5 from the Python side.
run.sh covers elements 1, 6, 7 at the shell level.

A real agent replaces `preflight()` with a calendar/queue check and `run()`
with its actual pipeline; everything else (record schema, local-file fallback,
DynamoDB guard) is substrate and stays identical.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

RUN_RECORD_FILENAME = "run_record.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _logical_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def write_run_record(
    status: str,
    summary: str,
    artifact_refs: list | None = None,
    action_dispositions: list | None = None,
) -> None:
    """
    Element 5: write a structured run record.

    Always writes a local file first. The DynamoDB write is an adapter concern
    — optional, guarded by SA_DYNAMO_TABLE; the job never fails because the
    remote store is unreachable.
    """
    record = {
        "status": status,
        "job": "test-stub",
        "logical_date": _logical_date(),
        "run_id": f"test-stub-{_logical_date()}",
        "arm": os.environ.get("SA_ARM", "local"),
        "started_at": _utc_now(),
        "ended_at": _utc_now(),
        "summary": summary,
        "artifact_refs": artifact_refs or [],
        "policy_version": "v0",
        "action_dispositions": action_dispositions or [],
    }

    # Local file — always written (the pull-checkable fallback)
    record_dir = Path(os.environ.get("SA_RUN_RECORD_DIR", "."))
    (record_dir / RUN_RECORD_FILENAME).write_text(json.dumps(record, indent=2), encoding="utf-8")

    # DynamoDB — optional; silently degrade if unavailable or unconfigured
    table_name = os.environ.get("SA_DYNAMO_TABLE")
    if table_name:
        _try_write_dynamo(record, table_name)


def _try_write_dynamo(record: dict, table_name: str) -> None:
    """
    Best-effort DynamoDB write. Failures are swallowed; the local file is
    the authoritative fallback ("a job never fails because the run-record
    store is unreachable" — RUNNER-CONTRACT.md element 5).
    """
    try:
        import boto3  # type: ignore[import-untyped]
        table = boto3.resource("dynamodb").Table(table_name)
        table.put_item(Item={
            "PK": f"JOB#{record['job']}",
            "SK": f"RUN#{record['logical_date']}",
            **record,
        })
    except Exception:
        pass


def preflight() -> int:
    """
    Element 3: cheap pre-flight gate — decide early whether there is work.

    The do-nothing stub always reports nothing-to-do. A real agent checks its
    calendar, queue depth, or schedule here before spending the LLM pass.
    """
    write_run_record(
        status="nothing-to-do",
        summary="Pre-flight: test-stub has no real work to do",
    )
    return 0


def run() -> int:
    """Main execution — do nothing, record a successful run."""
    write_run_record(
        status="ran",
        summary="Test-stub ran successfully (reference do-nothing agent)",
        artifact_refs=[],
        action_dispositions=[
            # Even an all-blocked agent records its dispositions per element 5.
            {"action_class": "example", "decision": "blocked", "ref": None},
        ],
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Test-stub agent (do-nothing reference)")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run the pre-flight gate only (element 3)",
    )
    args = parser.parse_args()

    if args.preflight:
        sys.exit(preflight())
    sys.exit(run())


if __name__ == "__main__":
    main()
