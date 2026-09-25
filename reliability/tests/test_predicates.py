"""Tests for reliability.predicates — file_exists, policy_matches, and
the AWS-backed predicates via mock clients."""

from unittest.mock import MagicMock

import pytest

from reliability.predicates import (
    dynamodb_item_exists,
    file_exists,
    policy_matches,
    s3_object_exists,
)


# ------------------------------------------------------------------
# file_exists
# ------------------------------------------------------------------

def test_file_exists_true(tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("some data", encoding="utf-8")
    assert file_exists(f) is True


def test_file_exists_false_missing(tmp_path):
    assert file_exists(tmp_path / "absent.log") is False


def test_file_exists_false_is_directory(tmp_path):
    # tmp_path itself is a directory, not a file
    assert file_exists(tmp_path) is False


def test_file_exists_accepts_str_path(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("x", encoding="utf-8")
    assert file_exists(str(f)) is True


FILE_SIZE_CASES = [
    # (content_bytes, min_bytes, expected)
    (b"x" * 100, 50,  True),
    (b"x" * 10,  50,  False),
    (b"x" * 50,  50,  True),   # exactly at boundary → pass
    (b"",         0,   True),   # empty file, no min_bytes constraint
]


@pytest.mark.parametrize("content, min_bytes, expected", FILE_SIZE_CASES)
def test_file_exists_min_bytes(tmp_path, content, min_bytes, expected):
    f = tmp_path / "sized.log"
    f.write_bytes(content)
    assert file_exists(f, min_bytes=min_bytes) is expected


# ------------------------------------------------------------------
# policy_matches
# ------------------------------------------------------------------

POLICY_CASES = [
    # (policy_doc,                           expected,               should_match)
    ({"Effect": "Allow", "Action": "s3:*"}, {"Effect": "Allow"},    True),
    ({"Effect": "Allow", "Action": "s3:*"}, {"Effect": "Deny"},     False),
    ({"Version": "2012-10-17", "Stmt": []}, {"Version": "2012-10-17"}, True),
    ({},                                    {"Effect": "Allow"},    False),
    ({"nested": {"a": 1, "b": 2}},          {"nested": {"a": 1}},   True),
    ({"nested": {"a": 1}},                  {"nested": {"a": 2}},   False),
    # exact match on full doc
    ({"a": 1},                              {"a": 1},               True),
    # extra keys in policy_doc are allowed
    ({"a": 1, "b": 2},                      {"a": 1},               True),
]


@pytest.mark.parametrize("policy_doc, expected, should_match", POLICY_CASES)
def test_policy_matches(policy_doc, expected, should_match):
    assert policy_matches(policy_doc, expected) is should_match


# ------------------------------------------------------------------
# s3_object_exists — mock client, no network
# ------------------------------------------------------------------

def test_s3_object_exists_true():
    client = MagicMock()
    client.head_object.return_value = {"ContentLength": 42}
    assert s3_object_exists("audit-bucket", "audit/2024.jsonl", client=client) is True
    client.head_object.assert_called_once_with(Bucket="audit-bucket", Key="audit/2024.jsonl")


def _s3_not_found(code: str) -> Exception:
    exc = Exception(f"S3 error {code}")
    exc.response = {"Error": {"Code": code, "Message": "not found"}}
    return exc


@pytest.mark.parametrize("error_code", ["404", "NoSuchKey"])
def test_s3_object_exists_false_on_not_found(error_code):
    client = MagicMock()
    client.head_object.side_effect = _s3_not_found(error_code)
    assert s3_object_exists("audit-bucket", "missing.jsonl", client=client) is False


def test_s3_object_exists_reraises_other_errors():
    client = MagicMock()
    # No .response attribute → treated as non-404, must re-raise
    client.head_object.side_effect = Exception("Connection timeout")
    with pytest.raises(Exception, match="Connection timeout"):
        s3_object_exists("audit-bucket", "key", client=client)


# ------------------------------------------------------------------
# dynamodb_item_exists — mock client, no network
# ------------------------------------------------------------------

def test_dynamodb_item_exists_true():
    client = MagicMock()
    client.get_item.return_value = {
        "Item": {"pk": {"S": "audit#001"}, "sk": {"S": "2024-01-01"}}
    }
    key = {"pk": {"S": "audit#001"}, "sk": {"S": "2024-01-01"}}
    assert dynamodb_item_exists("AuditTable", key, client=client) is True
    client.get_item.assert_called_once_with(TableName="AuditTable", Key=key)


def test_dynamodb_item_exists_false():
    client = MagicMock()
    client.get_item.return_value = {}  # no "Item" key → item not found
    key = {"pk": {"S": "audit#999"}}
    assert dynamodb_item_exists("AuditTable", key, client=client) is False
