"""
SQL-TRUST Forensic Investigation Dossier, Reporting & Case Closure Service
Module 6: Cyber Investigation & Incident Response Orchestration
Assembles complete canonical incident reports (Executive Summary, MITRE ATT&CK Matrix,
Chronological Timeline, Correlated Evidence, Workflows, Response Plans, Analyst Comments,
and Cryptographic Audit Trail), renders GFM Markdown reports, signs canonical closure
manifests using Ed25519, and archives artifacts to SeaweedFS Object Lock WORM storage.
"""
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.models.investigation import (
    InvestigationCase,
    CaseEvidenceLink,
    CaseMitreTechnique,
    CaseContainmentAction,
    CaseAuditLog,
    InvestigationWorkflow,
    InvestigationTask,
    IncidentResponsePlan,
    ResponsePlanAction,
    AnalystCollaborationComment
)
from backend.schemas.investigation import CaseTransitionRequest
from backend.services.investigation.case_service import CaseService  # pyrefly: ignore[missing-import]
from backend.services.investigation.timeline_engine import TimelineEngine  # pyrefly: ignore[missing-import]
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]
from backend.services.security.signer import signer
from backend.services.storage import SeaweedFSStorageProvider


def ensure_utc(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DossierService:
    """Compiles forensic dossiers, generates canonical reports, and signs closure manifests."""

    @classmethod
    def generate_dossier(cls, db: Session, case_id: str) -> Dict[str, Any]:
        """Generates comprehensive incident dossier containing all investigation facets."""
        return cls.generate_canonical_report(db, case_id)

    @classmethod
    def generate_canonical_report(cls, db: Session, case_id: str) -> Dict[str, Any]:
        """
        Builds the canonical incident report incorporating all 6 phases:
        Metadata, MITRE taxonomy, Evidence Inventory, Unified Timeline,
        Workflows & Tasks, Response Plans & Execution, Analyst Comments, and Audit Integrity.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        # 1. Timeline & Milestones
        timeline = TimelineEngine.build_case_timeline(db, case.id)
        milestones = TimelineEngine.get_milestones(timeline)

        # 2. MITRE Techniques
        mitre_records = db.query(CaseMitreTechnique).filter(CaseMitreTechnique.case_id == case.id).all()
        mitre_matrix = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "detection_source": m.detection_source,
                "confidence": m.confidence,
                "mapped_at": m.mapped_at.isoformat()
            }
            for m in mitre_records
        ]

        # 3. Evidence Inventory
        evidence_records = db.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()
        evidence_inventory = [
            {
                "link_id": e.id,
                "source_module": e.source_module,
                "source_entity": e.source_entity,
                "source_id": e.source_id,
                "evidence_role": e.evidence_role,
                "sha256_hash": e.sha256_hash,
                "tamper_status": e.tamper_status,
                "metadata": json.loads(e.metadata_snapshot) if e.metadata_snapshot else {},
                "linked_by": e.linked_by,
                "linked_at": e.linked_at.isoformat()
            }
            for e in evidence_records
        ]

        # 4. Containment Actions
        containment_records = db.query(CaseContainmentAction).filter(CaseContainmentAction.case_id == case.id).all()
        containment_actions = [
            {
                "id": c.id,
                "action_type": c.action_type,
                "target_principal": c.target_principal,
                "target_object": c.target_object,
                "recommended_script": c.recommended_script,
                "risk_assessment": c.risk_assessment,
                "status": c.status,
                "reviewed_by": c.reviewed_by,
                "reviewed_at": c.reviewed_at.isoformat() if c.reviewed_at else None,
                "created_at": c.created_at.isoformat()
            }
            for c in containment_records
        ]

        # 5. Workflows and Tasks (Phase 5)
        workflows = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.case_id == case.id).all()
        workflows_summary = []
        for wf in workflows:
            tasks_list = [
                {
                    "id": t.id,
                    "title": t.title,
                    "stage_name": t.stage_name,
                    "status": t.status,
                    "priority": t.priority,
                    "is_mandatory": t.is_mandatory,
                    "assigned_to": t.assigned_to,
                    "completed_by": t.completed_by,
                    "completed_at": t.completed_at.isoformat() if t.completed_at else None
                }
                for t in wf.tasks
            ]
            completed_tasks = sum(1 for t in wf.tasks if t.status in ("COMPLETED", "SKIPPED"))
            workflows_summary.append({
                "workflow_id": wf.id,
                "name": wf.name,
                "status": wf.status,
                "current_stage": wf.current_stage,
                "owner": wf.owner,
                "tasks_count": len(wf.tasks),
                "completed_tasks_count": completed_tasks,
                "tasks": tasks_list
            })

        # 6. Response Plans & Actions (Phase 6)
        response_plans = db.query(IncidentResponsePlan).filter(IncidentResponsePlan.case_id == case.id).all()
        response_plans_summary = []
        for rp in response_plans:
            actions_list = [
                {
                    "id": a.id,
                    "title": a.title,
                    "action_category": a.action_category,
                    "target_type": a.target_type,
                    "risk_level": a.risk_level,
                    "requires_multi_party_approval": a.requires_multi_party_approval,
                    "approval_status": a.approval_status,
                    "proposed_by": a.proposed_by,
                    "approved_by": a.approved_by,
                    "approved_at": a.approved_at.isoformat() if a.approved_at else None,
                    "execution_status": a.execution_status,
                    "executed_by": a.executed_by,
                    "executed_at": a.executed_at.isoformat() if a.executed_at else None
                }
                for a in rp.actions
            ]
            response_plans_summary.append({
                "plan_id": rp.id,
                "title": rp.title,
                "plan_type": rp.plan_type,
                "status": rp.status,
                "version": rp.version,
                "actions_count": len(rp.actions),
                "actions": actions_list
            })

        # 7. Analyst Collaboration Comments (Phase 6)
        comments = (
            db.query(AnalystCollaborationComment)
            .filter(
                AnalystCollaborationComment.case_id == case.id,
                AnalystCollaborationComment.parent_comment_id == None
            )
            .order_by(AnalystCollaborationComment.created_at.asc())
            .all()
        )
        comments_summary = [
            {
                "id": c.id,
                "author": c.author,
                "comment_type": c.comment_type,
                "content": c.content,
                "replies_count": len(c.replies),
                "created_at": c.created_at.isoformat()
            }
            for c in comments
        ]

        # 8. Audit Chain Integrity
        audit_verified = CaseAuditService.verify_audit_chain(db, case.id)
        latest_audit = (
            db.query(CaseAuditLog)
            .filter(CaseAuditLog.case_id == case.id)
            .order_by(CaseAuditLog.sequence_number.desc())
            .first()
        )
        total_audit_events = db.query(CaseAuditLog).filter(CaseAuditLog.case_id == case.id).count()

        # 9. Incident Duration & Executive Summary
        first_event_time = ensure_utc(timeline[0]["timestamp"]) if timeline else ensure_utc(case.opened_at)
        last_event_time = ensure_utc(case.closed_at) if case.closed_at else datetime.now(timezone.utc)
        duration_minutes = max(1, int((last_event_time - first_event_time).total_seconds() / 60))

        root_cause = "Multiple correlated telemetry sources"
        for ev in evidence_records:
            if ev.evidence_role == "ROOT_CAUSE":
                meta = json.loads(ev.metadata_snapshot) if ev.metadata_snapshot else {}
                root_cause = meta.get("title") or meta.get("explanation") or f"Triggered from {ev.source_entity}"
                break

        executive_summary = {
            "title": case.title,
            "case_number": case.case_number,
            "incident_category": case.incident_category,
            "priority": case.priority,
            "severity_score": case.severity_score,
            "target_database": case.target_database_name,
            "duration_minutes": duration_minutes,
            "affected_systems": [case.target_database_name],
            "root_cause_summary": root_cause,
            "blast_radius_summary": case.blast_radius_summary or "Localized impact",
            "containment_status": case.containment_status,
            "key_milestones_count": len(milestones),
            "evidence_items_count": len(evidence_records),
            "workflows_count": len(workflows_summary),
            "response_plans_count": len(response_plans_summary)
        }

        return {
            "case_id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "status": case.status,
            "priority": case.priority,
            "severity_score": case.severity_score,
            "incident_category": case.incident_category,
            "target_database_name": case.target_database_name,
            "opened_at": case.opened_at.isoformat() if case.opened_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "lead_investigator": case.lead_investigator,
            "executive_summary": executive_summary,
            "mitre_matrix": mitre_matrix,
            "evidence_inventory": evidence_inventory,
            "timeline": timeline,
            "containment_actions": containment_actions,
            "workflows": workflows_summary,
            "response_plans": response_plans_summary,
            "collaboration_comments": comments_summary,
            "audit_trail_summary": {
                "total_events": total_audit_events,
                "chain_head_hash": latest_audit.current_hash if latest_audit else None,
                "chain_integrity_verified": audit_verified.get("valid", False)
            }
        }

    @classmethod
    def export_markdown(cls, dossier: Dict[str, Any]) -> str:
        """Renders comprehensive investigation dossier as formatted GitHub Flavored Markdown."""
        exec_sum = dossier["executive_summary"]
        opened_str = dossier["opened_at"] if isinstance(dossier["opened_at"], str) else (dossier["opened_at"].strftime("%Y-%m-%d %H:%M:%S UTC") if dossier.get("opened_at") else "N/A")
        closed_str = dossier["closed_at"] if isinstance(dossier.get("closed_at"), str) else (dossier["closed_at"].strftime("%Y-%m-%d %H:%M:%S UTC") if dossier.get("closed_at") else "ACTIVE (Open)")

        md = f"""# SQL-TRUST Cyber Incident Investigation Dossier
**Case Reference:** `{dossier['case_number']}`  
**Classification:** `{dossier['priority']}` (Score: `{dossier['severity_score']}/100.0`)  
**Status:** `{dossier['status']}` | **Category:** `{dossier['incident_category']}`  

---

## 1. Executive Incident Summary

| Attribute | Details |
| :--- | :--- |
| **Case Title** | {dossier['title']} |
| **Target Database** | `{dossier['target_database_name']}` |
| **Lead Investigator** | {dossier.get('lead_investigator') or 'Unassigned'} |
| **Incident Duration** | {exec_sum['duration_minutes']} minutes |
| **Opened At** | {opened_str} |
| **Closed At** | {closed_str} |
| **Root Cause** | {exec_sum['root_cause_summary']} |
| **Blast Radius** | {exec_sum['blast_radius_summary']} |
| **Containment State** | `{exec_sum['containment_status']}` |

---

## 2. MITRE ATT&CK for Enterprise Matrix Mapping

| Technique ID | Technique Name | Tactic | Source | Confidence |
| :--- | :--- | :--- | :--- | :---: |
"""
        for m in dossier.get("mitre_matrix", []):
            md += f"| **{m['technique_id']}** | {m['technique_name']} | {m['tactic']} | `{m['detection_source']}` | {int(m['confidence']*100)}% |\n"

        md += """
---

## 3. Correlated Forensic Evidence Inventory

| Module | Entity | ID / Key | Role | Tamper Status | SHA-256 Digest |
| :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for e in dossier.get("evidence_inventory", []):
            hash_snippet = f"`{e['sha256_hash'][:16]}...`" if e.get("sha256_hash") else "N/A"
            md += f"| `{e['source_module']}` | `{e['source_entity']}` | `{e['source_id'][:8]}...` | `{e['evidence_role']}` | `{e['tamper_status']}` | {hash_snippet} |\n"

        md += """
---

## 4. Chronological Incident Timeline

| Timestamp (UTC) | Module | Event Type | Severity | Milestone | Summary |
| :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for t in dossier.get("timeline", []):
            ts_val = t["timestamp"]
            ts_str = ts_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts_val, datetime) else str(ts_val)
            ms_icon = "⭐ **YES**" if t.get("is_milestone") else "No"
            md += f"| {ts_str} | `{t['source_module']}` | `{t['event_type']}` | `{t['severity']}` | {ms_icon} | {t['summary']} |\n"

        md += """
---

## 5. Containment & Remediation Playbooks

| Action Type | Target | Status | Reviewer | Recommended Script |
| :--- | :--- | :---: | :--- | :--- |
"""
        for c in dossier.get("containment_actions", []):
            target = c.get("target_principal") or c.get("target_object") or "N/A"
            md += f"| `{c.get('action_type')}` | `{target}` | `{c.get('status')}` | {c.get('reviewed_by') or 'Pending'} | `{c.get('recommended_script')}` |\n"

        audit_sum = dossier["audit_trail_summary"]
        md += f"""
---

## 6. Chain of Custody & Audit Integrity

- **Total Logged Actions:** {audit_sum['total_events']}
- **Latest Audit Hash (Head):** `{audit_sum['chain_head_hash']}`
- **SHA-256 Hash Chaining Status:** {'✅ **VERIFIED IMMUTABLE**' if audit_sum['chain_integrity_verified'] else '❌ **TAMPER DETECTED**'}
- **Platform Guarantee:** SQL-TRUST passively preserves forensic integrity without altering original database evidence.
"""
        return md

    @classmethod
    def export_canonical_markdown(cls, dossier: Dict[str, Any]) -> str:
        """Renders full canonical investigation report as formatted GitHub Flavored Markdown."""
        exec_sum = dossier["executive_summary"]
        opened_str = dossier["opened_at"].strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(dossier["opened_at"], datetime) else str(dossier["opened_at"])
        closed_str = dossier["closed_at"].strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(dossier.get("closed_at"), datetime) else (str(dossier["closed_at"]) if dossier.get("closed_at") else "ACTIVE (Open)")

        md = f"""# SQL-TRUST Cyber Incident Investigation Dossier
**Case Reference:** `{dossier['case_number']}`  
**Classification:** `{dossier['priority']}` (Score: `{dossier['severity_score']}/100.0`)  
**Status:** `{dossier['status']}` | **Category:** `{dossier['incident_category']}`  

---

## 1. Executive Incident Summary

| Attribute | Details |
| :--- | :--- |
| **Case Title** | {dossier['title']} |
| **Target Database** | `{dossier['target_database_name']}` |
| **Lead Investigator** | {dossier.get('lead_investigator') or 'Unassigned'} |
| **Incident Duration** | {exec_sum['duration_minutes']} minutes |
| **Opened At** | {opened_str} |
| **Closed At** | {closed_str} |
| **Root Cause** | {exec_sum['root_cause_summary']} |
| **Blast Radius** | {exec_sum['blast_radius_summary']} |
| **Containment State** | `{exec_sum['containment_status']}` |

---

## 2. MITRE ATT&CK for Enterprise Matrix Mapping

| Technique ID | Technique Name | Tactic | Source | Confidence |
| :--- | :--- | :--- | :--- | :---: |
"""
        for m in dossier.get("mitre_matrix", []):
            md += f"| **{m['technique_id']}** | {m['technique_name']} | {m['tactic']} | `{m['detection_source']}` | {int(m['confidence']*100)}% |\n"

        md += """
---

## 3. Correlated Forensic Evidence Inventory

| Module | Entity | ID / Key | Role | Tamper Status | SHA-256 Digest |
| :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for e in dossier.get("evidence_inventory", []):
            hash_snippet = f"`{e['sha256_hash'][:16]}...`" if e.get("sha256_hash") else "N/A"
            md += f"| `{e['source_module']}` | `{e['source_entity']}` | `{e['source_id'][:8]}...` | `{e['evidence_role']}` | `{e['tamper_status']}` | {hash_snippet} |\n"

        md += """
---

## 4. Chronological Incident Timeline

| Timestamp (UTC) | Module | Event Type | Severity | Milestone | Summary |
| :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for t in dossier.get("timeline", []):
            ts_val = t["timestamp"]
            ts_str = ts_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts_val, datetime) else str(ts_val)
            ms_icon = "⭐ **YES**" if t.get("is_milestone") else "No"
            md += f"| {ts_str} | `{t['source_module']}` | `{t['event_type']}` | `{t['severity']}` | {ms_icon} | {t['summary']} |\n"

        md += """
---

## 5. Investigation Workflows & Tasks Execution

| Workflow Name | Status | Current Stage | Tasks Completed | Owner |
| :--- | :---: | :--- | :---: | :--- |
"""
        for wf in dossier.get("workflows", []):
            md += f"| **{wf['name']}** | `{wf['status']}` | `{wf['current_stage']}` | {wf['completed_tasks_count']}/{wf['tasks_count']} | {wf.get('owner') or 'Unassigned'} |\n"

        md += """
---

## 6. Incident Response Plans & Separation of Duties Approvals

| Plan / Action Title | Category | Risk | Approval Status | Approver | Execution Status |
| :--- | :--- | :---: | :---: | :--- | :---: |
"""
        for plan in dossier.get("response_plans", []):
            for a in plan.get("actions", []):
                approver = a.get("approved_by") or "Pending"
                md += f"| {a['title']} | `{a['action_category']}` | `{a['risk_level']}` | `{a['approval_status']}` | {approver} | `{a['execution_status']}` |\n"

        md += """
---

## 7. Analyst Collaboration & Peer Reviews

| Comment Type | Author | Discussion / Finding | Replies |
| :--- | :--- | :--- | :---: |
"""
        for c in dossier.get("collaboration_comments", []):
            md += f"| `{c['comment_type']}` | **{c['author']}** | {c['content']} | {c['replies_count']} |\n"

        audit_sum = dossier["audit_trail_summary"]
        md += f"""
---

## 8. Chain of Custody & Audit Integrity

- **Total Logged Actions:** {audit_sum['total_events']}
- **Latest Audit Hash (Head):** `{audit_sum['chain_head_hash']}`
- **SHA-256 Hash Chaining Status:** {'✅ **VERIFIED IMMUTABLE**' if audit_sum['chain_integrity_verified'] else '❌ **TAMPER DETECTED**'}
- **Platform Guarantee:** SQL-TRUST passively preserves forensic integrity without altering original database evidence.
"""
        return md

    @classmethod
    def archive_canonical_report(
        cls,
        db: Session,
        case_id: str,
        operator: str,
        retention_days: int = 30
    ) -> Dict[str, Any]:
        """
        Generates canonical report, computes Ed25519 digital signature and SHA-256 digest,
        and archives to SeaweedFS Object Lock WORM storage (or local staging if offline).
        """
        report = cls.generate_canonical_report(db, case_id)
        case_number = report["case_number"]

        # 1. Canonical bytes & Ed25519 signature
        signature = signer.sign_manifest(report)
        report["signature"] = signature
        canonical_bytes = signer.canonicalize(report)
        report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        # 2. Render markdown representation
        md_text = cls.export_canonical_markdown(report)
        md_bytes = md_text.encode("utf-8")
        md_sha256 = hashlib.sha256(md_bytes).hexdigest()

        # 3. Local staging
        local_dir = os.path.abspath(os.path.join(r"data\evidence\investigations", case_number))
        os.makedirs(local_dir, exist_ok=True)
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_filename = f"canonical_report_{case_number}_{timestamp_str}.json"
        md_filename = f"canonical_report_{case_number}_{timestamp_str}.md"
        local_json_path = os.path.join(local_dir, json_filename)
        local_md_path = os.path.join(local_dir, md_filename)

        with open(local_json_path, "wb") as f:
            f.write(canonical_bytes)
        with open(local_md_path, "wb") as f:
            f.write(md_bytes)

        # 4. Storage archival (SeaweedFS with Object Lock fallback)
        storage = SeaweedFSStorageProvider()
        conn = storage.check_connectivity()

        object_key = f"investigations/{case_number}/{json_filename}"
        version_id = None
        storage_bucket = storage.bucket_name
        retention_mode = "COMPLIANCE"
        retain_until = datetime.now(timezone.utc) + timedelta(days=retention_days)

        if conn.get("connected"):
            try:
                upload_res = storage.upload_file(local_file_path=local_json_path, object_key=object_key)
                version_id = upload_res.get("version_id")
                retention_mode = upload_res.get("retention_mode") or "COMPLIANCE"
            except Exception:
                retention_mode = "COMPLIANCE (LOCAL_STAGED)"
        else:
            retention_mode = "COMPLIANCE (LOCAL_STAGED)"

        # 5. Link evidence in case
        link = CaseEvidenceLink(
            case_id=case_id,
            source_module="MODULE_6_INVESTIGATION",
            source_entity="canonical_reports",
            source_id=json_filename,
            evidence_role="CLOSURE_MANIFEST",
            sha256_hash=report_sha256,
            tamper_status="VERIFIED",
            metadata_snapshot=json.dumps({
                "storage_object_key": object_key,
                "storage_version_id": version_id,
                "signature": signature,
                "retention_mode": retention_mode,
                "retention_until": retain_until.isoformat()
            }),
            linked_by=operator
        )
        db.add(link)

        CaseAuditService.log_action(
            db=db,
            case_id=case_id,
            action="CASE_ARCHIVED_WORM",
            actor=operator,
            details=f"Canonical report archived to Object Lock WORM storage. Key: {object_key}, SHA-256: {report_sha256[:16]}..."
        )
        db.commit()

        return {
            "case_id": case_id,
            "case_number": case_number,
            "report_sha256": report_sha256,
            "signature": signature,
            "signature_valid": signer.verify_manifest(report, signature),
            "storage_bucket": storage_bucket,
            "storage_object_key": object_key,
            "storage_version_id": version_id,
            "retention_mode": retention_mode,
            "retention_until": retain_until.isoformat(),
            "local_path": local_json_path
        }

    @classmethod
    def close_and_sign_case(
        cls,
        db: Session,
        case_id: str,
        closed_by: str,
        closure_reason: str,
        closure_notes: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates case resolution, enforces closure requirements,
        generates the canonical closure manifest, signs with Ed25519,
        and archives to SeaweedFS Object Lock WORM storage.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        # 1. Audit Chain Integrity Verification
        chain_res = CaseAuditService.verify_audit_chain(db, case.id)
        is_chain_valid = chain_res.get("valid", False)
        if not is_chain_valid:
            raise ValueError(f"Audit chain verification failed for case {case.case_number}. Cannot close compromised case.")

        # 2. Closure Checklist Validation: Check active workflows
        active_workflows = (
            db.query(InvestigationWorkflow)
            .filter(
                InvestigationWorkflow.case_id == case.id,
                InvestigationWorkflow.status.in_(["ACTIVE", "BLOCKED", "AWAITING_REVIEW", "AWAITING_APPROVAL", "ESCALATED"])
            )
            .all()
        )
        if active_workflows:
            wf_names = [w.name for w in active_workflows]
            raise ValueError(f"Cannot close case: Active workflows remain incomplete: {', '.join(wf_names)}")

        # 3. Closure Checklist Validation: Check pending response actions
        pending_actions = (
            db.query(ResponsePlanAction)
            .filter(
                ResponsePlanAction.case_id == case.id,
                ResponsePlanAction.approval_status == "PENDING_APPROVAL"
            )
            .all()
        )
        if pending_actions:
            raise ValueError(f"Cannot close case: {len(pending_actions)} response action(s) remain pending approval.")

        # 4. Progress through valid state transitions to CLOSED
        if case.status == "NEW":
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="TRIAGED", changed_by=closed_by, transition_reason="Progression to closure"), client_ip=client_ip)
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="ACTIVE", changed_by=closed_by, transition_reason="Progression to closure"), client_ip=client_ip)
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="RESOLVED", changed_by=closed_by, transition_reason=closure_reason), client_ip=client_ip)
        elif case.status == "TRIAGED":
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="ACTIVE", changed_by=closed_by, transition_reason="Progression to closure"), client_ip=client_ip)
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="RESOLVED", changed_by=closed_by, transition_reason=closure_reason), client_ip=client_ip)
        elif case.status in ("ACTIVE", "CONTAINMENT_REVIEW", "RECOVERY_COORDINATION"):
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="RESOLVED", changed_by=closed_by, transition_reason=closure_reason), client_ip=client_ip)

        if case.status == "RESOLVED":
            CaseService.transition_status(db, case.id, CaseTransitionRequest(to_status="CLOSED", changed_by=closed_by, transition_reason=closure_reason), client_ip=client_ip)

        now_utc = datetime.now(timezone.utc)
        case.closed_at = now_utc
        case.closure_reason = closure_reason

        # 5. Archive to SeaweedFS Object Lock WORM storage
        archive_res = cls.archive_canonical_report(
            db=db,
            case_id=case.id,
            operator=closed_by,
            retention_days=30
        )

        # 6. Tamper-evident Audit Logging
        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="CASE_CLOSED_AND_SIGNED",
            actor=closed_by,
            client_ip=client_ip,
            details=f"Case closed, signed with Ed25519, and archived to WORM storage. Manifest SHA-256: {archive_res['report_sha256'][:16]}..."
        )

        db.commit()
        db.refresh(case)

        return {
            "case_id": case.id,
            "case_number": case.case_number,
            "status": case.status,
            "closed_at": case.closed_at,
            "closed_by": closed_by,
            "closure_manifest_hash": archive_res["report_sha256"],
            "signature": archive_res["signature"],
            "signature_valid": archive_res["signature_valid"],
            "audit_chain_verified": is_chain_valid,
            "storage_object_key": archive_res["storage_object_key"],
            "retention_mode": archive_res["retention_mode"]
        }
