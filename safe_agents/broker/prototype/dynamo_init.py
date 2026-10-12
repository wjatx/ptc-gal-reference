"""dynamo_init.py — create the broker's single table in DynamoDB Local (local/Mac arm).

Idempotent. boto3 reads the endpoint from AWS_ENDPOINT_URL_DYNAMODB (set to the dynamodb-local
container) + dummy creds. One pk/sk table holds every broker item — the single-table design:
COUNTER# / IDEM# / LEDGER# (enforcement) and INTENT# (approval) coexist by key prefix.
"""
from __future__ import annotations

import os
import time

from safe_agents.broker.approval.store import (
    PENDING_EXPIRY_ATTR,
    PENDING_INDEX_NAME,
    PENDING_PRINCIPAL_ATTR,
)


_PENDING_INDEX_ATTRS = [
    {"AttributeName": PENDING_PRINCIPAL_ATTR, "AttributeType": "S"},
    {"AttributeName": PENDING_EXPIRY_ATTR, "AttributeType": "N"},
]
_PENDING_INDEX = {
    "IndexName": PENDING_INDEX_NAME,
    "KeySchema": [
        {"AttributeName": PENDING_PRINCIPAL_ATTR, "KeyType": "HASH"},
        {"AttributeName": PENDING_EXPIRY_ATTR, "KeyType": "RANGE"},
    ],
    "Projection": {"ProjectionType": "KEYS_ONLY"},
}


def _ensure_pending_index(ddb, table: str) -> int:
    """Add the expiry sweep's index to a table created before it existed (#163).

    Without it the broker's sweep Query fails, which it logs and survives, and no
    expiry is recorded until a late approve or reject finds one.
    """
    described = ddb.describe_table(TableName=table)["Table"]
    names = {i["IndexName"] for i in described.get("GlobalSecondaryIndexes", [])}
    if PENDING_INDEX_NAME in names:
        return 0
    ddb.update_table(
        TableName=table,
        AttributeDefinitions=_PENDING_INDEX_ATTRS,
        GlobalSecondaryIndexUpdates=[{"Create": _PENDING_INDEX}],
    )
    print(f"[dynamo-init] added index {PENDING_INDEX_NAME!r} to {table!r}", flush=True)
    return 0


def main() -> int:
    import boto3  # noqa: PLC0415

    table = os.environ.get("BROKER_TABLE", "safe-agents-broker-local")
    ddb = boto3.client("dynamodb")  # endpoint + region + creds from the environment

    # Wait for DynamoDB Local to accept connections.
    for _ in range(60):
        try:
            existing = ddb.list_tables().get("TableNames", [])
            break
        except Exception:  # noqa: BLE001 — connection not up yet
            time.sleep(1)
    else:
        print("[dynamo-init] DynamoDB Local never came up", flush=True)
        return 1

    if table in existing:
        print(f"[dynamo-init] table {table!r} already exists", flush=True)
        return _ensure_pending_index(ddb, table)

    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            *_PENDING_INDEX_ATTRS,
        ],
        # The expiry sweep's sparse index (#163), as infra/lib/state-stack.ts declares it.
        GlobalSecondaryIndexes=[_PENDING_INDEX],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=table)
    # TTL for intent auto-expiry (best-effort; DynamoDB Local honors the attribute lazily).
    try:
        ddb.update_time_to_live(
            TableName=table,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )
    except Exception:  # noqa: BLE001 — TTL is optional locally
        pass
    print(
        f"[dynamo-init] created table {table!r} (pk/sk, PAY_PER_REQUEST, TTL=ttl, "
        f"index {PENDING_INDEX_NAME})",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
