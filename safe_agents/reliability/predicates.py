"""
predicates — boolean check helpers for use with assert_artifact.

All functions return bool and are designed to be passed directly to
assert_artifact as the predicate argument. Agent-agnostic — no domain-
specific thresholds or trading logic.

AWS predicates (s3_object_exists, dynamodb_item_exists) accept an optional
client= keyword so tests can inject mock clients without network access.

Usage:
    assert_artifact(file_exists("/var/audit/run.log"), "audit log written")
    assert_artifact(
        s3_object_exists("audit-bucket", "2024-01-01.jsonl"),
        "S3 audit object present",
    )
"""

from pathlib import Path
from typing import Any, Dict


def file_exists(path: str | Path, *, min_bytes: int = 0) -> bool:
    """True if path is a regular file and is at least min_bytes in size.

    min_bytes=0 (default) checks only that the file exists.
    """
    p = Path(path)
    if not p.is_file():
        return False
    if min_bytes > 0:
        return p.stat().st_size >= min_bytes
    return True


def s3_object_exists(bucket: str, key: str, *, client: Any = None) -> bool:
    """True if the S3 object (bucket, key) exists.

    Returns False for 404 / NoSuchKey. Re-raises all other errors so the
    caller sees network or auth failures rather than a silent False.

    Pass a boto3 S3 client via client= to avoid network access in tests.
    """
    try:
        if client is None:
            import boto3  # noqa: PLC0415
            client = boto3.client("s3")
        client.head_object(Bucket=bucket, Key=key)
        return True
    except Exception as exc:
        if hasattr(exc, "response"):
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchKey"):
                return False
        raise


def dynamodb_item_exists(
    table_name: str,
    key: Dict[str, Any],
    *,
    client: Any = None,
) -> bool:
    """True if the DynamoDB item identified by key exists in table_name.

    key is the full DynamoDB-typed primary key dict, e.g.:
        {"pk": {"S": "audit#001"}, "sk": {"S": "2024-01-01"}}

    Pass a boto3 DynamoDB client via client= to avoid network access in tests.
    """
    if client is None:
        import boto3  # noqa: PLC0415
        client = boto3.client("dynamodb")
    resp = client.get_item(TableName=table_name, Key=key)
    return "Item" in resp


def policy_matches(policy_doc: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    """True if every key-value pair in expected appears in policy_doc.

    Performs a recursive subset check: policy_doc must contain at least the
    fields and values in expected. Extra keys in policy_doc are ignored.

    For complex policy assertions that can't be expressed as a subset match,
    pass a custom lambda to assert_artifact directly.
    """
    def _subset(doc: Any, exp: Any) -> bool:
        if isinstance(exp, dict) and isinstance(doc, dict):
            return all(k in doc and _subset(doc[k], v) for k, v in exp.items())
        return doc == exp

    return _subset(policy_doc, expected)
