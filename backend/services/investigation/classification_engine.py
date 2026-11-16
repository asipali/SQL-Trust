"""
SQL-TRUST Incident Classification & MITRE ATT&CK Mapping Engine
Module 6: Cyber Investigation & Incident Response Orchestration
Maps observed indicators and rules to MITRE ATT&CK for Enterprise techniques,
and computes an explainable multi-factor severity score (0.0 to 100.0) and priority (P1 to P4).
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.models.investigation import InvestigationCase, CaseEvidenceLink, CaseMitreTechnique
from backend.models.security import SecurityAlert, DetectionRule
from backend.models.forensics import ForensicFinding
from backend.models.recovery import RecoveryPoint, RecoveryAssessment
from backend.models.restore import RecoveryJob, RecoveryValidation
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]


class ClassificationEngine:
    """Classifies investigation cases, maps MITRE ATT&CK taxonomy, and computes severity scores."""

    # MITRE ATT&CK for Enterprise Knowledge Base for Microsoft SQL Server
    MITRE_CATALOG: Dict[str, Dict[str, str]] = {
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Initial Access",
            "description": "Adversaries may obtain and abuse credentials of existing accounts such as SA or application logins."
        },
        "T1505.001": {
            "name": "Server Software Component: SQL Stored Procedures",
            "tactic": "Persistence",
            "description": "Adversaries may create or modify stored procedures or triggers to maintain persistent access."
        },
        "T1565.001": {
            "name": "Data Manipulation: Stored Data Manipulation",
            "tactic": "Impact",
            "description": "Adversaries may alter or encrypt database records, modifying critical tables or injecting unauthorized updates."
        },
        "T1485": {
            "name": "Data Destruction",
            "tactic": "Impact",
            "description": "Adversaries may drop entire databases, truncate tables, or shrink and corrupt physical database files."
        },
        "T1059.006": {
            "name": "Command and Scripting Interpreter: Python / xp_cmdshell",
            "tactic": "Execution",
            "description": "Adversaries may execute operating system commands or Python scripts through SQL Server extended procedures."
        },
        "T1068": {
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may exploit misconfigurations or add accounts to sysadmin and serveradmin fixed server roles."
        },
        "T1562.001": {
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "description": "Adversaries may alter or disable SQL Server Audit, Extended Events, or tampering-detection traces."
        },
        "T1046": {
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may probe database instances, endpoints, and linked servers across the internal network."
        },
        "T1005": {
            "name": "Data from Local System",
            "tactic": "Collection",
            "description": "Adversaries may query sensitive business data or extract database dumps via BCP."
        }
    }

    # Rule-to-MITRE mapping
    RULE_TECHNIQUE_MAP: Dict[str, List[Tuple[str, float]]] = {
        "RULE_001_FAILED_LOGINS": [("T1078", 0.90), ("T1046", 0.70)],
        "RULE_002_NEW_PRIVILEGED_LOGIN": [("T1078", 0.95), ("T1068", 0.85)],
        "RULE_003_SYSADMIN_CHANGE": [("T1068", 1.0), ("T1078", 0.90)],
        "RULE_004_DATABASE_ROLE_ESCALATION": [("T1068", 0.90)],
        "RULE_005_PERMISSION_CHANGE": [("T1068", 0.85)],
        "RULE_006_PRINCIPAL_DELETION": [("T1078", 0.80), ("T1562.001", 0.75)],
        "RULE_007_SCHEMA_MUTATION": [("T1485", 0.95), ("T1505.001", 0.90)],
        "RULE_008_AUDIT_TAMPERING": [("T1562.001", 1.0)],
        "RULE_009_XE_INTERRUPTION": [("T1562.001", 1.0)],
        "RULE_010_COLLECTION_GAP": [("T1562.001", 0.85)],
        # Short aliases
        "RULE-001": [("T1078", 0.90)],
        "RULE-002": [("T1078", 0.95), ("T1068", 0.85)],
        "RULE-003": [("T1068", 1.0), ("T1078", 0.90)],
        "RULE-004": [("T1068", 0.90)],
        "RULE-005": [("T1068", 0.85)],
        "RULE-006": [("T1078", 0.80)],
        "RULE-007": [("T1485", 0.95), ("T1505.001", 0.90)],
        "RULE-008": [("T1562.001", 1.0)],
        "RULE-009": [("T1562.001", 1.0)],
        "RULE-010": [("T1562.001", 0.85)],
    }

    RULE_CATEGORY_MAP: Dict[str, str] = {
        "RULE_001_FAILED_LOGINS": "CREDENTIAL_ABUSE",
        "RULE_002_NEW_PRIVILEGED_LOGIN": "PRIVILEGE_ESCALATION",
        "RULE_003_SYSADMIN_CHANGE": "PRIVILEGE_ESCALATION",
        "RULE_004_DATABASE_ROLE_ESCALATION": "PRIVILEGE_ESCALATION",
        "RULE_005_PERMISSION_CHANGE": "PRIVILEGE_ESCALATION",
        "RULE_006_PRINCIPAL_DELETION": "DEFENSE_EVASION",
        "RULE_007_SCHEMA_MUTATION": "DATA_DESTRUCTION",
        "RULE_008_AUDIT_TAMPERING": "DEFENSE_EVASION",
        "RULE_009_XE_INTERRUPTION": "DEFENSE_EVASION",
        "RULE_010_COLLECTION_GAP": "DEFENSE_EVASION",
        # Short aliases
        "RULE-001": "CREDENTIAL_ABUSE",
        "RULE-002": "PRIVILEGE_ESCALATION",
        "RULE-003": "PRIVILEGE_ESCALATION",
        "RULE-004": "PRIVILEGE_ESCALATION",
        "RULE-005": "PRIVILEGE_ESCALATION",
        "RULE-006": "DEFENSE_EVASION",
        "RULE-007": "DATA_DESTRUCTION",
        "RULE-008": "DEFENSE_EVASION",
        "RULE-009": "DEFENSE_EVASION",
        "RULE-010": "DEFENSE_EVASION",
    }

    @classmethod
    def calculate_severity_score(
        cls,
        max_rule_severity: str = "MEDIUM",
        affected_objects_count: int = 1,
        principal_name: Optional[str] = None,
        impact_type: str = "MODIFICATION"
    ) -> Tuple[float, str, str]:
        """
        Calculates explainable multi-factor severity score (0.0 - 100.0).
        Formula: (0.30 * Rule) + (0.25 * BlastRadius) + (0.25 * Principal) + (0.20 * Impact)
        Returns (score, priority, blast_summary).
        """
        # 1. Rule Severity Weight (30%)
        rule_weights = {
            "CRITICAL": 100.0,
            "HIGH": 75.0,
            "MEDIUM": 50.0,
            "LOW": 25.0
        }
        rule_score = rule_weights.get(max_rule_severity.upper(), 50.0)

        # 2. Blast Radius Score (25%)
        if affected_objects_count >= 5:
            blast_score = 100.0
            blast_summary = f"Critical multi-object impact: {affected_objects_count} affected objects/tables."
        elif affected_objects_count >= 2:
            blast_score = 75.0
            blast_summary = f"Moderate blast radius: {affected_objects_count} objects modified."
        elif affected_objects_count == 1:
            blast_score = 40.0
            blast_summary = "Localized impact: single target object."
        else:
            blast_score = 20.0
            blast_summary = "Configuration or non-data telemetry."

        # 3. Principal Privilege Tier (25%)
        p_lower = (principal_name or "").lower()
        if any(term in p_lower for term in ("sa", "sysadmin", "serveradmin", "admin")):
            principal_score = 100.0
        elif any(term in p_lower for term in ("db_owner", "securityadmin")):
            principal_score = 75.0
        elif any(term in p_lower for term in ("writer", "ddladmin", "app_")):
            principal_score = 50.0
        elif not principal_name and impact_type in ("DESTRUCTION", "RANSOMWARE"):
            principal_score = 80.0
        else:
            principal_score = 25.0

        # 4. Data Impact Tier (20%)
        impact_weights = {
            "DESTRUCTION": 100.0,    # DROP, TRUNCATE
            "RANSOMWARE": 100.0,
            "PRIVILEGE": 90.0,       # sysadmin grant
            "MODIFICATION": 70.0,    # mass UPDATE / DELETE
            "EXFILTRATION": 60.0,    # BCP export
            "EVASION": 50.0,         # disable audit
            "RECONNAISSANCE": 30.0   # port scan, probe
        }
        impact_score = impact_weights.get(impact_type.upper(), 50.0)

        total_score = round(
            (0.30 * rule_score) +
            (0.25 * blast_score) +
            (0.25 * principal_score) +
            (0.20 * impact_score),
            1
        )

        # Priority derivation
        if total_score >= 80.0:
            priority = "P1_CRITICAL"
        elif total_score >= 60.0:
            priority = "P2_HIGH"
        elif total_score >= 40.0:
            priority = "P3_MEDIUM"
        else:
            priority = "P4_LOW"

        return total_score, priority, blast_summary

    @classmethod
    def classify_case(
        cls,
        db: Session,
        case_id: str,
        actor: str = "system",
        client_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Inspects all linked evidence for a case, extracts TTPs, maps MITRE ATT&CK techniques,
        recalculates multi-factor severity score, and updates case metadata.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        # Gather linked evidence
        evidence_links = db.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()

        max_severity = "LOW"
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        suspect_principals = set()
        affected_objects = set()
        detected_categories = set()
        techniques_to_map: Dict[str, Tuple[str, str, float, str]] = {}

        for link in evidence_links:
            # 1. Module 2 Security Alerts
            if link.source_module == "MODULE_2_SECURITY" and link.source_entity == "security_alerts":
                alert = db.query(SecurityAlert).filter(SecurityAlert.id == link.source_id).first()
                if alert:
                    if severity_rank.get(alert.severity, 0) > severity_rank.get(max_severity, 0):
                        max_severity = alert.severity

                    if alert.principal_name:
                        suspect_principals.add(alert.principal_name)
                    if alert.target_object:
                        affected_objects.add(alert.target_object)

                    rule = db.query(DetectionRule).filter(DetectionRule.id == alert.rule_id).first()
                    rule_code = rule.rule_id if rule and hasattr(rule, "rule_id") else (rule.rule_code if rule and hasattr(rule, "rule_code") else "RULE-001")
                    
                    # Normalize RULE_001 -> RULE-001
                    normalized_code = rule_code.replace("_", "-")[:8].upper()

                    if normalized_code in cls.RULE_CATEGORY_MAP:
                        detected_categories.add(cls.RULE_CATEGORY_MAP[normalized_code])

                    # Map techniques for this rule
                    mapped = cls.RULE_TECHNIQUE_MAP.get(normalized_code) or cls.RULE_TECHNIQUE_MAP.get(rule_code, [])
                    for tech_id, conf in mapped:
                        if tech_id in cls.MITRE_CATALOG:
                            info = cls.MITRE_CATALOG[tech_id]
                            techniques_to_map[tech_id] = (info["name"], info["tactic"], conf, normalized_code)

            # 2. Module 3 Forensic Findings
            elif link.source_module == "MODULE_3_FORENSICS" and link.source_entity == "forensic_findings":
                finding = db.query(ForensicFinding).filter(ForensicFinding.id == link.source_id).first()
                if finding:
                    if severity_rank.get(finding.severity, 0) > severity_rank.get(max_severity, 0):
                        max_severity = finding.severity

                    if finding.entity_name:
                        affected_objects.add(finding.entity_name)

                    f_cat = (finding.category or "").upper()
                    f_type = (finding.finding_type or "").upper()

                    if f_cat == "SCHEMA" or any(x in f_type for x in ("OBJECT", "SCHEMA", "MUTATION")):
                        detected_categories.add("SCHEMA_TAMPERING")
                        info = cls.MITRE_CATALOG["T1505.001"]
                        techniques_to_map["T1505.001"] = (info["name"], info["tactic"], 0.90, "FORENSIC_DRIFT")
                    elif f_cat in ("PRINCIPAL", "ROLE_MEMBERSHIP", "PERMISSION") or any(x in f_type for x in ("USER", "ROLE", "PRIVILEGE", "PERMISSION")):
                        detected_categories.add("PRIVILEGE_ESCALATION")
                        info = cls.MITRE_CATALOG["T1068"]
                        techniques_to_map["T1068"] = (info["name"], info["tactic"], 0.95, "FORENSIC_DRIFT")
                    elif f_cat == "CONFIGURATION" or "CONFIG" in f_type:
                        detected_categories.add("DEFENSE_EVASION")
                        info = cls.MITRE_CATALOG["T1562.001"]
                        techniques_to_map["T1562.001"] = (info["name"], info["tactic"], 0.90, "FORENSIC_DRIFT")

            # 3. Module 4 Recovery Risks
            elif link.source_module == "MODULE_4_RECOVERY" and link.source_entity == "recovery_points":
                point = db.query(RecoveryPoint).filter(RecoveryPoint.id == link.source_id).first()
                if point:
                    if point.database_name:
                        affected_objects.add(point.database_name)
                    assessment = db.query(RecoveryAssessment).filter(RecoveryAssessment.recovery_point_id == point.id).first()
                    is_critical = False
                    if assessment:
                        if assessment.trust_classification in ("LOW_CONFIDENCE", "COMPROMISED") or (assessment.trust_score is not None and assessment.trust_score < 40.0):
                            is_critical = True

                    if is_critical:
                        if severity_rank.get("CRITICAL", 0) > severity_rank.get(max_severity, 0):
                            max_severity = "CRITICAL"
                        detected_categories.add("RANSOMWARE")
                        info = cls.MITRE_CATALOG["T1485"]
                        techniques_to_map["T1485"] = (info["name"], info["tactic"], 0.95, "RECOVERY_RISK")
                        info2 = cls.MITRE_CATALOG["T1565.001"]
                        techniques_to_map["T1565.001"] = (info2["name"], info2["tactic"], 0.90, "RECOVERY_RISK")
                    else:
                        if severity_rank.get("HIGH", 0) > severity_rank.get(max_severity, 0):
                            max_severity = "HIGH"
                        detected_categories.add("SUSPICIOUS_ACTIVITY")

            # 4. Module 5 Restore Validation Failures
            elif link.source_module == "MODULE_5_RESTORE" and link.source_entity == "recovery_jobs":
                job = db.query(RecoveryJob).filter(RecoveryJob.id == link.source_id).first()
                if job:
                    if job.target_database_name:
                        affected_objects.add(job.target_database_name)
                    validation = db.query(RecoveryValidation).filter(RecoveryValidation.job_id == job.id).first()
                    is_failed = False
                    if validation:
                        if validation.overall_assessment == "FAILED" or validation.dbcc_status in ("FAILED", "CORRUPTED"):
                            is_failed = True
                    elif job.status in ("FAILED", "TERMINATED"):
                        is_failed = True

                    if is_failed:
                        if severity_rank.get("CRITICAL", 0) > severity_rank.get(max_severity, 0):
                            max_severity = "CRITICAL"
                        detected_categories.add("DATA_DESTRUCTION")
                        info = cls.MITRE_CATALOG["T1485"]
                        techniques_to_map["T1485"] = (info["name"], info["tactic"], 0.95, "VALIDATION_FAILURE")
                    else:
                        if severity_rank.get("HIGH", 0) > severity_rank.get(max_severity, 0):
                            max_severity = "HIGH"
                        detected_categories.add("SUSPICIOUS_ACTIVITY")

        # Determine primary incident category
        primary_category = "SUSPICIOUS_ACTIVITY"
        priority_category_order = [
            "RANSOMWARE", "DATA_DESTRUCTION", "PRIVILEGE_ESCALATION",
            "COMMAND_EXECUTION", "DEFENSE_EVASION", "SCHEMA_TAMPERING", "DATA_EXFILTRATION"
        ]
        for cat in priority_category_order:
            if cat in detected_categories:
                primary_category = cat
                break

        # Impact type estimation
        if primary_category in ("RANSOMWARE", "DATA_DESTRUCTION"):
            impact_type = "DESTRUCTION"
        elif primary_category == "PRIVILEGE_ESCALATION":
            impact_type = "PRIVILEGE"
        elif primary_category == "DEFENSE_EVASION":
            impact_type = "EVASION"
        elif primary_category == "SCHEMA_TAMPERING":
            impact_type = "MODIFICATION"
        else:
            impact_type = "MODIFICATION"

        # Calculate multi-factor score
        obj_count = max(len(affected_objects), 1 if evidence_links else 0)
        principal = next(iter(suspect_principals), None)
        score, priority, blast_summary = cls.calculate_severity_score(
            max_rule_severity=max_severity,
            affected_objects_count=obj_count,
            principal_name=principal,
            impact_type=impact_type
        )

        # Update case attributes
        case.severity_score = score
        case.priority = priority
        case.incident_category = primary_category
        case.blast_radius_summary = blast_summary
        case.updated_at = datetime.now(timezone.utc)

        # Sync CaseMitreTechnique records
        existing_mapped = {
            mt.technique_id: mt for mt in
            db.query(CaseMitreTechnique).filter(CaseMitreTechnique.case_id == case.id).all()
        }

        for tech_id, (name, tactic, conf, src) in techniques_to_map.items():
            if tech_id not in existing_mapped:
                mt = CaseMitreTechnique(
                    case_id=case.id,
                    technique_id=tech_id,
                    technique_name=name,
                    tactic=tactic,
                    detection_source=src,
                    confidence=conf,
                    mapped_at=datetime.now(timezone.utc)
                )
                db.add(mt)

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="CLASSIFIED",
            actor=actor,
            client_ip=client_ip,
            details=f"Case classified as {priority} (Score {score}) in category {primary_category}. {len(techniques_to_map)} MITRE TTPs mapped."
        )

        db.commit()
        db.refresh(case)

        return {
            "case_id": case.id,
            "severity_score": case.severity_score,
            "priority": case.priority,
            "incident_category": case.incident_category,
            "blast_radius_summary": case.blast_radius_summary,
            "mitre_techniques": case.mitre_techniques
        }
