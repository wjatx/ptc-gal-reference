"""marshal.py — JSON-native conversion for values crossing a serialization seam.

A dependency-free leaf ON PURPOSE. The one function here is needed by both
``enforcement.engine`` (the audit/idempotency record) and the runtime's HTTP
boundary, and those two packages already depend on each other — homing it in
either one closes a circular import. It has no intra-package imports and must
keep none.
"""

from __future__ import annotations


def marshal_connector_result(result):
    """Marshal a connector result into JSON-native types. Pure; SDK-free.

    A connector may return a TYPED result — the MCP connector's
    ``CallToolResult`` is the first — and EVERY seam that serializes one needs
    the same conversion. #221's floor drill found the HTTP ``/call`` boundary
    missing it; the #247 local drill then found ``enforce()``'s idempotency
    ``result_json`` missing it too, UPSTREAM of that boundary, so any
    in-process caller (a local gateway, not an HTTP client) crashed on a
    successful call *after* the connector had already executed — the worst
    place to discover it.

    Two findings for one omission is the "a seam is proven per transport"
    lesson charging interest, so the marshal is homed ONCE here rather than at
    whichever boundary notices next.

    Duck-types pydantic's ``model_dump`` so the base never imports an SDK;
    plain JSON types pass through unchanged.
    """
    dump = getattr(result, "model_dump", None)
    return dump(mode="json") if callable(dump) else result
