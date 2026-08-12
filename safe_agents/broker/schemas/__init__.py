"""broker.schemas — the seven base schemas as validated Pydantic v2 models.

All seven types are exported from this package. Import them directly:

    from safe_agents.broker.schemas import Grant, BrokeredCall, Decision, Intent, AuditRecord, Budgets, PromotionRecord

See broker/SCHEMAS.md for the authoritative field-by-field contract.
"""

from .audit_record import AuditRecord
from .brokered_call import BrokeredCall, Session, Taint, ToolOp
from .budgets import Budgets, CapacityBudget, ErrorBudget
from .capability_iam import CapabilityIam
from .connector_auth import AuthStrategy, ConnectorAuth, HeaderSource
from .common import AutonomyLevel, DemotionTrigger, Principal
from .decision import Abstain, Allow, Deny, Decision, RenderedIntent, RequireApproval, Transform
from .envelope import Confidence, Envelope, compute_envelope_hash
from .evidence import (
    BlastClass,
    ConfidenceArtifact,
    ConfidenceEvidence,
    ConfidenceMethod,
    ConformalEvidence,
    CorroborationRecord,
    DemotionSignal,
    EnsembleEvidence,
    SelfConsistencyEvidence,
    derive_blast_class,
    effective_blast_class,
    error_budget_draw,
    meets_bar,
)
from .grant import Grant
from .intent import Intent
from .manifest import AgentManifest
from .mcp_registry import (
    McpRespawnPolicy,
    McpServerDecl,
    McpServerSnapshot,
    McpSnapshotEntry,
    McpToolDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    SchemaDelta,
    compute_tool_def_hash,
    diff_input_schema,
)
from .promotion_record import PromotionRecord

__all__ = [
    # schemas
    "Grant",
    "BrokeredCall",
    "Decision",
    "Intent",
    "AuditRecord",
    "Budgets",
    "PromotionRecord",
    # envelope artifact (sa#135) — pipeline-validated; broker consumption is sa#122
    "Envelope",
    "compute_envelope_hash",
    # evidence contract (#184) — constructed confidence, blast derivation, demotion
    "Confidence",
    "ConfidenceArtifact",
    "ConfidenceEvidence",
    "ConfidenceMethod",
    "SelfConsistencyEvidence",
    "EnsembleEvidence",
    "ConformalEvidence",
    "BlastClass",
    "derive_blast_class",
    "effective_blast_class",
    "meets_bar",
    "error_budget_draw",
    "DemotionSignal",
    "CorroborationRecord",
    # broker-facing typed manifest (broker-debaking P1, sa#113) — envelope + broker blocks
    "AgentManifest",
    # decision variants
    "Allow",
    "Deny",
    "Transform",
    "RequireApproval",
    "Abstain",
    "RenderedIntent",
    # sub-types
    "ToolOp",
    "Taint",
    "Session",
    # connector auth-strategy config (#173) — how the broker resolves a credential
    "AuthStrategy",
    "ConnectorAuth",
    "HeaderSource",
    # per-capability IAM scoping (#175) — the deploy-consumed minimal IAM per capability
    "CapabilityIam",
    # MCP tool-registry schemas (#174) — two-key admission of a discovered MCP tool
    "McpRespawnPolicy",
    "McpServerDecl",
    "McpServerSnapshot",
    "McpSnapshotEntry",
    "McpToolDecl",
    "McpToolDef",
    "RegisteredTool",
    "RegistryStatus",
    "SchemaDelta",
    "compute_tool_def_hash",
    "diff_input_schema",
    "Principal",
    "AutonomyLevel",
    "DemotionTrigger",
    "ErrorBudget",
    "CapacityBudget",
]
