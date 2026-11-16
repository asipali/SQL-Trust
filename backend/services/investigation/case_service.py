"""
SQL-TRUST Case Management Service
Module 6: Cyber Investigation & Incident Response Orchestration
Manages the end-to-end lifecycle, finite state machine transitions,
evidence linkages, analyst notes, containment tracking, and concurrency controls
for forensic investigation cases.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.models.investigation import (
    InvestigationCase,
    CaseStatusHistory,
    CaseNote,
    CaseEvidenceLink,
    CaseContainmentAction,
    generate_case_reference
)
from backend.models.backup import ProtectedDatabase
from backend.schemas.investigation import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseTransitionRequest,
    CaseNoteCreateRequest,
    CaseEvidenceLinkCreateRequest,
    CaseContainmentActionCreateRequest,
    CaseContainmentActionUpdateRequest
)
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]


class CaseService:
    """Service governing investigation cases, state machine transitions, and cross-module linkages."""

    VALID_TRANSITIONS: Dict[str, set] = {
        "NEW": {"TRIAGED", "CANCELLED"},
        "TRIAGED": {"ACTIVE", "CANCELLED"},
        "ACTIVE": {"CONTAINMENT_REVIEW", "RECOVERY_COORDINATION", "RESOLVED", "CANCELLED"},
        "CONTAINMENT_REVIEW": {"ACTIVE", "RECOVERY_COORDINATION", "RESOLVED", "CANCELLED"},
        "RECOVERY_COORDINATION": {"RESOLVED", "ACTIVE", "CANCELLED"},
        "RESOLVED": {"CLOSED", "ACTIVE"},
        "CLOSED": set(),       # Terminal state
        "CANCELLED": set()     # Terminal state
    }

    VALID_PRIORITIES = {"P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"}

    @classmethod
    def create_case(
        cls,
        db: Session,
        req: CaseCreateRequest,
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Creates a new investigation case. Enforces idempotency if key provided.
        Initializes status to NEW and records initial audit log and status history.
        """
        # Idempotency check
        if req.idempotency_key:
            existing = (
                db.query(InvestigationCase)
                .filter(InvestigationCase.idempotency_key == req.idempotency_key)
                .first()
            )
            if existing:
                return existing

        # Validate priority if specified
        priority = req.priority or "P3_MEDIUM"
        if priority not in cls.VALID_PRIORITIES:
            priority = "P3_MEDIUM"

        # Validate or resolve target database id
        target_db_id = req.target_database_id
        if not target_db_id and req.target_database_name:
            db_record = (
                db.query(ProtectedDatabase)
                .filter(ProtectedDatabase.database_name == req.target_database_name)
                .first()
            )
            if db_record:
                target_db_id = db_record.id

        # Generate collision-free case number conforming to INV-YYYYMMDD-XXXX
        cand_number = generate_case_reference()
        for _ in range(50):
            if not db.query(InvestigationCase).filter(InvestigationCase.case_number == cand_number).first():
                break
            cand_number = generate_case_reference()

        case = InvestigationCase(
            case_number=cand_number,
            title=req.title,
            description=req.description,
            target_database_id=target_db_id,
            target_database_name=req.target_database_name,
            priority=priority,
            status="NEW",
            incident_category=req.incident_category or "SUSPICIOUS_ACTIVITY",
            lead_investigator=req.lead_investigator,
            assigned_team=req.assigned_team,
            created_by=req.created_by,
            idempotency_key=req.idempotency_key,
            severity_score=0.0,
            containment_status="NONE",
            version=1,
            opened_at=datetime.now(timezone.utc)
        )

        db.add(case)
        db.flush()

        # Record initial status history
        status_history = CaseStatusHistory(
            case_id=case.id,
            from_status="NONE",
            to_status="NEW",
            changed_by=req.created_by,
            transition_reason="Initial case creation and intake",
            transitioned_at=case.opened_at
        )
        db.add(status_history)

        # Record audit log
        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="CASE_CREATED",
            actor=req.created_by,
            client_ip=client_ip,
            details=f"Case {case.case_number} created with priority {case.priority} for database {case.target_database_name}"
        )

        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def get_case(cls, db: Session, case_identifier: str) -> Optional[InvestigationCase]:
        """Looks up a case by UUID or human-readable case_number."""
        return (
            db.query(InvestigationCase)
            .filter(
                or_(
                    InvestigationCase.id == case_identifier,
                    InvestigationCase.case_number == case_identifier
                )
            )
            .first()
        )

    @classmethod
    def list_cases(
        cls,
        db: Session,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        database_name: Optional[str] = None,
        assigned_to: Optional[str] = None,
        category: Optional[str] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Tuple[List[InvestigationCase], int]:
        """Lists cases matching filter criteria with pagination."""
        query = db.query(InvestigationCase)

        if status:
            query = query.filter(InvestigationCase.status == status)
        if priority:
            query = query.filter(InvestigationCase.priority == priority)
        if database_name:
            query = query.filter(InvestigationCase.target_database_name == database_name)
        if assigned_to:
            query = query.filter(InvestigationCase.lead_investigator == assigned_to)
        if category:
            query = query.filter(InvestigationCase.incident_category == category)

        total = query.count()
        offset = max(0, (page - 1) * page_size)
        items = query.order_by(desc(InvestigationCase.created_at)).offset(offset).limit(page_size).all()
        return items, total

    @classmethod
    def update_case(
        cls,
        db: Session,
        case_id: str,
        req: CaseUpdateRequest,
        actor: str,
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Updates editable case attributes with optimistic concurrency validation.
        """
        case = cls.get_case(db, case_id)
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        if case.status == "CLOSED":
            raise ValueError("Cannot modify a CLOSED investigation case. Closed cases are immutable.")

        # Optimistic concurrency check
        if req.expected_version is not None and req.expected_version != case.version:
            raise ValueError(
                f"Concurrency conflict: Case version {case.version} does not match expected {req.expected_version}"
            )

        changes = []
        if req.title is not None and req.title != case.title:
            changes.append(f"title: '{case.title}' -> '{req.title}'")
            case.title = req.title

        if req.description is not None:
            case.description = req.description

        if req.priority is not None and req.priority != case.priority:
            if req.priority in cls.VALID_PRIORITIES:
                changes.append(f"priority: '{case.priority}' -> '{req.priority}'")
                case.priority = req.priority

        if req.incident_category is not None and req.incident_category != case.incident_category:
            changes.append(f"category: '{case.incident_category}' -> '{req.incident_category}'")
            case.incident_category = req.incident_category

        if req.lead_investigator is not None and req.lead_investigator != case.lead_investigator:
            changes.append(f"lead_investigator: '{case.lead_investigator}' -> '{req.lead_investigator}'")
            case.lead_investigator = req.lead_investigator

        if req.assigned_team is not None and req.assigned_team != case.assigned_team:
            changes.append(f"assigned_team: '{case.assigned_team}' -> '{req.assigned_team}'")
            case.assigned_team = req.assigned_team

        if req.blast_radius_summary is not None:
            case.blast_radius_summary = req.blast_radius_summary

        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        if changes:
            CaseAuditService.log_action(
                db=db,
                case_id=case.id,
                action="CASE_UPDATED",
                actor=actor,
                client_ip=client_ip,
                details="; ".join(changes)
            )

        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def transition_status(
        cls,
        db: Session,
        case_id: str,
        req: CaseTransitionRequest,
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Transitions case status through the investigation finite state machine.
        Validates transition legality, updates status, and appends audit log.
        """
        case = cls.get_case(db, case_id)
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        current_status = case.status
        target_status = req.to_status.upper()

        if current_status == "CLOSED":
            raise ValueError("Cannot transition a CLOSED case. Closed cases are immutable forensic artifacts.")

        allowed = cls.VALID_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise ValueError(
                f"Illegal state transition from '{current_status}' to '{target_status}'. "
                f"Permitted next states: {sorted(list(allowed))}"
            )

        # Optimistic concurrency check
        if req.expected_version is not None and req.expected_version != case.version:
            raise ValueError(
                f"Concurrency conflict: Case version {case.version} does not match expected {req.expected_version}"
            )

        now = datetime.now(timezone.utc)
        case.status = target_status
        case.version += 1
        case.updated_at = now

        if target_status in ("CLOSED", "CANCELLED"):
            case.closed_at = now
            case.closure_reason = req.transition_reason or f"Marked {target_status}"

        # Record status history
        history = CaseStatusHistory(
            case_id=case.id,
            from_status=current_status,
            to_status=target_status,
            changed_by=req.changed_by,
            transition_reason=req.transition_reason,
            transitioned_at=now
        )
        db.add(history)

        # Record audit log
        action_name = "CASE_CLOSED" if target_status == "CLOSED" else "STATUS_TRANSITIONED"
        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action=action_name,
            actor=req.changed_by,
            client_ip=client_ip,
            details=f"Status changed from {current_status} to {target_status}. Reason: {req.transition_reason or 'None'}"
        )

        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def add_note(
        cls,
        db: Session,
        case_id: str,
        req: CaseNoteCreateRequest,
        client_ip: Optional[str] = None
    ) -> CaseNote:
        """Adds an analyst observation, hypothesis, or update to the case."""
        case = cls.get_case(db, case_id)
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        if case.status == "CLOSED":
            raise ValueError("Cannot add notes to a CLOSED case.")

        note = CaseNote(
            case_id=case.id,
            author=req.author,
            note_type=req.note_type or "ANALYST_NOTE",
            content=req.content,
            is_pinned=req.is_pinned or False,
            created_at=datetime.now(timezone.utc)
        )
        db.add(note)
        db.flush()

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="NOTE_ADDED",
            actor=req.author,
            client_ip=client_ip,
            details=f"Added {note.note_type} (length {len(note.content)} chars)"
        )

        db.commit()
        db.refresh(note)
        return note

    @classmethod
    def link_evidence(
        cls,
        db: Session,
        case_id: str,
        req: CaseEvidenceLinkCreateRequest,
        client_ip: Optional[str] = None
    ) -> CaseEvidenceLink:
        """
        Attaches a cross-module evidence record reference to the case.
        """
        case = cls.get_case(db, case_id)
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        if case.status == "CLOSED":
            raise ValueError("Cannot attach evidence to a CLOSED case.")

        # Check if already linked
        existing_link = (
            db.query(CaseEvidenceLink)
            .filter(
                CaseEvidenceLink.case_id == case.id,
                CaseEvidenceLink.source_module == req.source_module,
                CaseEvidenceLink.source_id == req.source_id
            )
            .first()
        )
        if existing_link:
            return existing_link

        link = CaseEvidenceLink(
            case_id=case.id,
            source_module=req.source_module,
            source_entity=req.source_entity,
            source_id=req.source_id,
            evidence_role=req.evidence_role or "CORROBORATING",
            sha256_hash=req.sha256_hash,
            tamper_status=req.tamper_status or "VERIFIED",
            metadata_snapshot=req.metadata_snapshot,
            linked_by=req.linked_by,
            linked_at=datetime.now(timezone.utc)
        )
        db.add(link)
        db.flush()

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="EVIDENCE_LINKED",
            actor=req.linked_by,
            client_ip=client_ip,
            details=f"Linked {req.source_module}::{req.source_entity}:{req.source_id} as {link.evidence_role}"
        )

        db.commit()
        db.refresh(link)
        return link

    @classmethod
    def add_containment_action(
        cls,
        db: Session,
        case_id: str,
        req: CaseContainmentActionCreateRequest,
        actor: str,
        client_ip: Optional[str] = None
    ) -> CaseContainmentAction:
        """
        Records a recommended non-automated containment action for human review.
        """
        case = cls.get_case(db, case_id)
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        if case.status == "CLOSED":
            raise ValueError("Cannot recommend containment on a CLOSED case.")

        action = CaseContainmentAction(
            case_id=case.id,
            action_type=req.action_type,
            target_principal=req.target_principal,
            target_object=req.target_object,
            recommended_script=req.recommended_script,
            risk_assessment=req.risk_assessment,
            status="PENDING",
            created_at=datetime.now(timezone.utc)
        )
        db.add(action)

        if case.containment_status == "NONE":
            case.containment_status = "RECOMMENDED"

        db.flush()

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="CONTAINMENT_RECOMMENDED",
            actor=actor,
            client_ip=client_ip,
            details=f"Recommended {action.action_type} for review: target {action.target_principal or action.target_object}"
        )

        db.commit()
        db.refresh(action)
        return action

    @classmethod
    def update_containment_action(
        cls,
        db: Session,
        action_id: str,
        req: CaseContainmentActionUpdateRequest,
        client_ip: Optional[str] = None
    ) -> CaseContainmentAction:
        """
        Reviews a containment recommendation (APPROVED, REJECTED, EXECUTED_MANUALLY).
        Never executes scripts automatically.
        """
        action = db.query(CaseContainmentAction).filter(CaseContainmentAction.id == action_id).first()
        if not action:
            raise ValueError(f"Containment action '{action_id}' not found")

        case = db.query(InvestigationCase).filter(InvestigationCase.id == action.case_id).first()
        if case and case.status == "CLOSED":
            raise ValueError("Cannot modify containment actions on a CLOSED case.")

        now = datetime.now(timezone.utc)
        action.status = req.status.upper()
        action.reviewed_by = req.reviewed_by
        action.reviewed_at = now
        action.review_comment = req.review_comment

        if case:
            if action.status == "APPROVED":
                case.containment_status = "CONTAINED"
            elif action.status == "REJECTED":
                case.containment_status = "WAIVED"

        CaseAuditService.log_action(
            db=db,
            case_id=action.case_id,
            action="CONTAINMENT_REVIEWED",
            actor=req.reviewed_by,
            client_ip=client_ip,
            details=f"Containment action {action.action_type} status updated to {action.status}"
        )

        db.commit()
        db.refresh(action)
        return action
