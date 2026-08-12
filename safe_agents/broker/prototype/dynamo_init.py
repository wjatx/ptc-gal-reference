"""dynamo_init.py — create the broker's single table in DynamoDB Local (local/Mac arm, sa#98).

Idempotent. boto3 reads the endpoint from AWS_ENDPOINT_URL_DYNAMODB (set to the dynamodb-local
container) + dummy creds. One pk/sk table holds every broker item — the single-table design:
COUNTER# / IDEM# / LEDGER# (enforcement) and INTENT# (approval) coexist by key prefix.
"""
from __future__ import annotations

import os
import time


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
        return 0

    ddb.create_table(
        TableName=table,
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
    ddb.get_waiter("table_exists").wait(TableName=table)
    # TTL for intent auto-expiry (best-effort; DynamoDB Local honors the attribute lazily).
    try:
        ddb.update_time_to_live(
            TableName=table,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )
    except Exception:  # noqa: BLE001 — TTL is optional locally
        pass
    print(f"[dynamo-init] created table {table!r} (pk/sk, PAY_PER_REQUEST, TTL=ttl)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
