"""
SQL-TRUST REST API Endpoints
Module 4: Cyber Recovery & State Reconstruction
Exposes recovery point discovery, backup chain analysis, cyber trust assessments,
technical eligibility evaluations, ranked recommendations, and WORM evidence verification.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db, test_sql_connection
from backend.services.storage import SeaweedFSStorageProvider
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryAssessment,
    RecoveryAssessmentEvidence,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.schemas.recovery import (
    RecoveryPointResponse,
    RecoveryChainResponse,
    ChainAnalyzeRequest,
    RecoveryAssessmentCreateRequest,
    RecoveryAssessmentEvidenceResponse,
    RecoveryAssessmentResponse,
    RecoveryEligibilityResponse,
    RecoveryRecommendationResponse,
    RecoveryHealthResponse
)
from backend.schemas.forensics import EvidenceVerificationResponse
from backend.services.recovery.discovery import RecoveryPointDiscoveryService
from backend.services.recovery.chain_analyzer import BackupChainAnalyzer
from backend.services.recovery.trust_engine import RecoveryTrustEngine
from backend.services.recovery.eligibility_engine import RecoveryEligibilityEngine
from backend.services.recovery.recommendation_engine import RecoveryRecommendationEngine
from backend.services.recovery.evidence_service import RecoveryEvidenceService

router = APIRouter(prefix="/recovery", tags=["Cyber Recovery & State Reconstruction"])


@router.get("/points", response_model=List[RecoveryPointResponse])
def list_recovery_points(
    database_name: Optional[str] = Query(None, description="Filter by database name"),
    discover: bool = Query(True, description="Whether to discover new backup records automatically"),
    db: Session = Depends(get_db)
):
    """Lists all discovered recovery points, optionally triggering discovery from new backups."""
    if discover:
        discovery_svc = RecoveryPointDiscoveryService(db)
        discovery_svc.discover_recovery_points(database_name=database_name)

    query = db.query(RecoveryPoint)
    if database_name:
        query = query.filter(RecoveryPoint.database_name == database_name)
    return query.order_by(RecoveryPoint.recovery_point_time.desc()).all()


@router.get("/points/{point_id}", response_model=RecoveryPointResponse)
def get_recovery_point(point_id: str, db: Session = Depends(get_db)):
    """Retrieves a single recovery point by ID."""
    point = db.query(RecoveryPoint).filter(RecoveryPoint.id == point_id).first()
    if not point:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recovery point '{point_id}' not found.")
    return point


@router.post("/chains/analyze", response_model=RecoveryChainResponse)
def analyze_backup_chain(
    payload: ChainAnalyzeRequest,
    db: Session = Depends(get_db)
):
    """Analyzes and validates the backup chain required to reach a target recovery point."""
    analyzer = BackupChainAnalyzer(db)
    try:
        chain = analyzer.analyze_chain_for_target(payload.target_recovery_point_id)
        return chain
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Chain analysis failed: {str(e)}")


@router.get("/chains", response_model=List[RecoveryChainResponse])
def list_recovery_chains(
    database_name: Optional[str] = Query(None, description="Filter by database name"),
    db: Session = Depends(get_db)
):
    """Lists all evaluated recovery chains."""
    query = db.query(RecoveryChain)
    if database_name:
        query = query.filter(RecoveryChain.database_name == database_name)
    return query.order_by(RecoveryChain.created_at.desc()).all()


@router.get("/chains/{chain_id}", response_model=RecoveryChainResponse)
def get_recovery_chain(chain_id: str, db: Session = Depends(get_db)):
    """Retrieves a specific recovery chain with its ordered segments."""
    chain = db.query(RecoveryChain).filter(RecoveryChain.id == chain_id).first()
    if not chain:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recovery chain '{chain_id}' not found.")
    return chain


@router.post("/assessments", response_model=RecoveryAssessmentResponse)
def create_recovery_assessment(
    payload: RecoveryAssessmentCreateRequest,
    db: Session = Depends(get_db)
):
    """Executes a cyber trust assessment and eligibility evaluation for a recovery point."""
    trust_engine = RecoveryTrustEngine(db)
    eligibility_engine = RecoveryEligibilityEngine(db)
    recommendation_engine = RecoveryRecommendationEngine(db)
    evidence_svc = RecoveryEvidenceService(db)

    try:
        # 1. Trust Assessment
        assessment = trust_engine.assess_recovery_point(
            recovery_point_id=payload.recovery_point_id,
            chain_id=payload.chain_id,
            assessment_name=payload.assessment_name
        )

        # 2. Eligibility Evaluation
        eligibility_engine.evaluate_eligibility(
            recovery_point_id=payload.recovery_point_id,
            chain_id=payload.chain_id
        )

        # 3. Generate Ranked Recommendations for the database
        rp = assessment.recovery_point
        recommendation_engine.generate_recommendations(database_id=rp.database_id)

        # 4. Optional WORM Archive
        if payload.archive_to_worm:
            evidence_svc.archive_assessment_report(assessment)

        return assessment
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Assessment failed: {str(e)}")


@router.get("/assessments", response_model=List[RecoveryAssessmentResponse])
def list_recovery_assessments(db: Session = Depends(get_db)):
    """Lists all cyber recovery trust assessments."""
    return db.query(RecoveryAssessment).order_by(RecoveryAssessment.assessed_at.desc()).all()


@router.get("/assessments/{assessment_id}", response_model=RecoveryAssessmentResponse)
def get_recovery_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieves a specific recovery assessment by ID."""
    assessment = db.query(RecoveryAssessment).filter(RecoveryAssessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Assessment '{assessment_id}' not found.")
    return assessment


@router.get("/assessments/{assessment_id}/evidence", response_model=List[RecoveryAssessmentEvidenceResponse])
def get_assessment_evidence(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieves discrete evidence records associated with an assessment."""
    assessment = db.query(RecoveryAssessment).filter(RecoveryAssessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Assessment '{assessment_id}' not found.")
    return assessment.evidence_items


@router.get("/assessments/{assessment_id}/recommendations", response_model=List[RecoveryRecommendationResponse])
def get_assessment_recommendations(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieves candidate recovery recommendations for the database linked to this assessment."""
    assessment = db.query(RecoveryAssessment).filter(RecoveryAssessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Assessment '{assessment_id}' not found.")
    
    db_id = assessment.recovery_point.database_id
    recs = db.query(RecoveryRecommendation).filter(
        RecoveryRecommendation.database_id == db_id
    ).order_by(RecoveryRecommendation.rank_order.asc()).all()
    return recs


@router.get("/evidence/{assessment_id}/verify", response_model=EvidenceVerificationResponse)
def verify_assessment_evidence(assessment_id: str, db: Session = Depends(get_db)):
    """Cryptographically verifies a signed recovery assessment stored in SeaweedFS Object Lock."""
    evidence_svc = RecoveryEvidenceService(db)
    res = evidence_svc.verify_assessment_archive(assessment_id)
    if not res.get("valid") and res.get("error"):
        if "not found" in res.get("error", "").lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=res["error"])
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res["error"])
    return {
        "valid": res.get("valid", False),
        "archive_id": assessment_id,
        "evidence_type": "RECOVERY_ASSESSMENT",
        "sha256_match": res.get("sha256_match"),
        "signature_valid": res.get("signature_valid"),
        "worm_mode": res.get("worm_mode"),
        "retention_until": res.get("retention_until"),
        "version_id": res.get("version_id"),
        "storage_object_key": res.get("storage_object_key"),
        "error": res.get("error")
    }


@router.get("/recommendations", response_model=List[RecoveryRecommendationResponse])
def list_recommendations(
    database_name: Optional[str] = Query(None, description="Filter by database name"),
    db: Session = Depends(get_db)
):
    """Lists all candidate recovery recommendations ordered by rank."""
    query = db.query(RecoveryRecommendation)
    if database_name:
        query = query.join(RecoveryPoint, RecoveryRecommendation.recovery_point_id == RecoveryPoint.id).filter(
            RecoveryPoint.database_name == database_name
        )
    return query.order_by(RecoveryRecommendation.rank_order.asc()).all()


@router.get("/eligibility", response_model=List[RecoveryEligibilityResponse])
def list_eligibility(db: Session = Depends(get_db)):
    """Lists all technical eligibility evaluation records."""
    return db.query(RecoveryEligibility).order_by(RecoveryEligibility.evaluated_at.desc()).all()


@router.get("/health", response_model=RecoveryHealthResponse)
def get_recovery_subsystem_health(db: Session = Depends(get_db)):
    """Returns the operational status of the cyber recovery subsystem."""
    sql_status = test_sql_connection()
    storage = SeaweedFSStorageProvider()
    storage_status = storage.check_connectivity()

    total_pts = db.query(RecoveryPoint).count()
    total_valid_chains = db.query(RecoveryChain).filter(RecoveryChain.is_valid == True).count()
    total_asms = db.query(RecoveryAssessment).count()

    overall_status = "HEALTHY" if (sql_status.get("success") and storage_status.get("connected")) else "DEGRADED"

    return {
        "status": overall_status,
        "database_connected": bool(sql_status.get("success")),
        "storage_connected": bool(storage_status.get("connected")),
        "storage_bucket": storage.bucket_name,
        "worm_compliance_active": True,
        "total_recovery_points": total_pts,
        "total_valid_chains": total_valid_chains,
        "total_assessments": total_asms
    }
