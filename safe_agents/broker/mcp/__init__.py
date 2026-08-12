"""Reference MCP host: two-key discovery gate + thin SDK client (#174).

The admitted-tool registry store + admission ceremony (this package's `registry`,
`proposals`, `signing`, and `commands` modules) are the reference binding
MCP-HOST.md defers to; the discovery gate and thin MCP client land alongside them.
"""

from safe_agents.broker.mcp.client import (
    McpClient,
    connect_stdio,
    connect_streamable_http,
)
from safe_agents.broker.mcp.factory import (
    McpChildDeathError,
    SupervisedMcpHost,
    SupervisedStdioHost,
    SupervisedStreamableHttpHost,
    stdio_host_factory,
    streamable_http_host_factory,
)
from safe_agents.broker.mcp.discovery import (
    DiscoveryFinding,
    DiscoveryResult,
    RegistryRead,
    ToolState,
    ToolVerdict,
    evaluate_discovery,
)
from safe_agents.broker.mcp.host import McpHost, ToolNotCallableError
from safe_agents.broker.mcp.proposals import (
    CEREMONY_KINDS,
    KIND_ADMISSION,
    KIND_REVET,
    AdmissionProposalStore,
    DynamoAdmissionProposalStore,
    McpAdmissionProposal,
    MemoryAdmissionProposalStore,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    ProposalIntegrityError,
    compute_proposal_hmac,
)
from safe_agents.broker.mcp.registry import (
    DynamoToolRegistry,
    MemoryToolRegistry,
    QuarantinedToolRowError,
    RecordAlreadyExistsError,
    ToolReadResult,
    ToolRegistryStore,
    canonical_row_payload,
    compute_row_hmac,
)
from safe_agents.broker.mcp.sqlite_stores import (
    SqliteAdmissionProposalStore,
    SqliteToolRegistry,
)
from safe_agents.broker.mcp.signing import (
    ADMISSION_PREDICATE_TYPE,
    AdmissionVerifyResult,
    McpAdmissionRecord,
    canonical_record_payload,
    sign_admission_record,
    verify_admission_record,
)

__all__ = [
    "ADMISSION_PREDICATE_TYPE",
    "CEREMONY_KINDS",
    "KIND_ADMISSION",
    "KIND_REVET",
    "AdmissionProposalStore",
    "AdmissionVerifyResult",
    "DiscoveryFinding",
    "DiscoveryResult",
    "DynamoAdmissionProposalStore",
    "DynamoToolRegistry",
    "McpClient",
    "McpHost",
    "McpAdmissionProposal",
    "McpChildDeathError",
    "McpAdmissionRecord",
    "MemoryAdmissionProposalStore",
    "MemoryToolRegistry",
    "ProposalAlreadyExistsError",
    "ProposalConsumedError",
    "ProposalIntegrityError",
    "QuarantinedToolRowError",
    "RecordAlreadyExistsError",
    "RegistryRead",
    "SqliteAdmissionProposalStore",
    "SqliteToolRegistry",
    "SupervisedMcpHost",
    "SupervisedStdioHost",
    "SupervisedStreamableHttpHost",
    "ToolNotCallableError",
    "ToolReadResult",
    "ToolRegistryStore",
    "ToolState",
    "ToolVerdict",
    "compute_proposal_hmac",
    "canonical_row_payload",
    "compute_row_hmac",
    "connect_stdio",
    "connect_streamable_http",
    "evaluate_discovery",
    "sign_admission_record",
    "stdio_host_factory",
    "streamable_http_host_factory",
    "canonical_record_payload",
    "verify_admission_record",
]
