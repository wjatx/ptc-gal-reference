"""Local-Mac prototype of the broker server (sa#98 design direction).

NOT production. A dependency-light, stdlib-only HTTP wrapper around the broker
runtime library so the agent<->broker tool-call round-trip can be run and felt
locally — to settle the protocol, request/response marshaling, and PIP shape
before porting to the separate-broker-box AWS deploy. See README.md.
"""
