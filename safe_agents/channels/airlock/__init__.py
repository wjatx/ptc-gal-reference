"""channels.airlock — the AWS Lambda binding of the reference airlock dispatcher.

Reference-tier per docs/contract-vs-reference.md: `handler.handler` binds the
transport-free `channels.dispatch.dispatch` to API Gateway / DynamoDB / S3 / SQS
seams and adds no policy of its own. See channels/ADAPTERS.md §"Reference
bindings".

Deliberately a thin namespace: the entrypoint is the dotted path
`safe_agents.channels.airlock.handler.handler` (the image CMD), so this package
does NOT re-export the `handler` function — that would shadow the `handler`
submodule name and confuse tooling that imports the module by path.
"""
