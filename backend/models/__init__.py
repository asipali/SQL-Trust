"""
SQL-TRUST Data Models Package
Includes Module 1 (Backup Manager), Module 2 (Security Monitoring Engine),
Module 3 (Database Forensics Engine), and Module 4 (Cyber Recovery & State Reconstruction) models.
"""
from backend.models.auth import User
from backend.models.backup import (
    Base,
    ProtectedDatabase,
    BackupRecord,
    BackupManifest,
    BackupOperationLog
)
from backend.models.security import (
    SecuritySource,
    SecurityEvent,
    DetectionRule,
    SecurityAlert,
    AlertStatusHistory,
    CollectorCheckpoint,
    EvidenceArchive,
    MonitoringHealth,
    alert_event_associations
)
from backend.models.forensics import (
    ForensicBaseline,
    ForensicBaselineItem,
    ForensicInvestigation,
    ForensicFinding,
    ForensicCorrelation,
    ForensicEvidenceArchive
)
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryAssessment,
    RecoveryAssessmentEvidence,
    RecoveryEligibility,
    RecoveryRecommendation,
    RecoveryAssessmentHistory
)
from backend.models.restore import (
    RecoveryJob,
    RecoveryJobHistory,
    BackupStagingRecord,
    RecoverySandbox,
    RecoveryValidation
)
from backend.models.investigation import (
    InvestigationCase,
    CaseStatusHistory,
    CaseNote,
    CaseAuditLog,
    CaseEvidenceLink,
    CaseContainmentAction,
    CaseMitreTechnique,
    InvestigationWorkflowTemplate,
    InvestigationWorkflow,
    InvestigationWorkflowHistory,
    InvestigationTask,
    InvestigationTaskDependency,
    InvestigationEscalation,
    IncidentResponsePlan,
    ResponsePlanAction,
    ResponsePlanRevision,
    AnalystCollaborationComment
)

__all__ = [
    "User",
    "Base",
    "ProtectedDatabase",
    "BackupRecord",
    "BackupManifest",
    "BackupOperationLog",
    "SecuritySource",
    "SecurityEvent",
    "DetectionRule",
    "SecurityAlert",
    "AlertStatusHistory",
    "CollectorCheckpoint",
    "EvidenceArchive",
    "MonitoringHealth",
    "alert_event_associations",
    "ForensicBaseline",
    "ForensicBaselineItem",
    "ForensicInvestigation",
    "ForensicFinding",
    "ForensicCorrelation",
    "ForensicEvidenceArchive",
    "RecoveryPoint",
    "RecoveryChain",
    "RecoveryChainSegment",
    "RecoveryAssessment",
    "RecoveryAssessmentEvidence",
    "RecoveryEligibility",
    "RecoveryRecommendation",
    "RecoveryAssessmentHistory",
    "RecoveryJob",
    "RecoveryJobHistory",
    "BackupStagingRecord",
    "RecoverySandbox",
    "RecoveryValidation",
    "InvestigationCase",
    "CaseStatusHistory",
    "CaseNote",
    "CaseAuditLog",
    "CaseEvidenceLink",
    "CaseContainmentAction",
    "CaseMitreTechnique",
    "InvestigationWorkflowTemplate",
    "InvestigationWorkflow",
    "InvestigationWorkflowHistory",
    "InvestigationTask",
    "InvestigationTaskDependency",
    "InvestigationEscalation",
    "IncidentResponsePlan",
    "ResponsePlanAction",
    "ResponsePlanRevision",
    "AnalystCollaborationComment"
]
