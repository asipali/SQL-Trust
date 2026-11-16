"""
SQL-TRUST Recovery Trust Assessment Engine
Module 4: Cyber Recovery & State Reconstruction
Evaluates evidence completeness, threat proximity, privilege drift, and monitoring gaps
to compute explainable cyber recovery trust classifications and scores.
"""
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryAssessment,
    RecoveryAssessmentEvidence,
    RecoveryAssessmentHistory
)
from backend.services.recovery.correlator import RecoveryCorrelator


class RecoveryTrustEngine:
    """
    Computes explainable cyber recovery confidence classifications.
    Never generates artificial scores when telemetry is insufficient.
    """

    MODEL_VERSION = "1.0.0"

    def __init__(self, db: Session):
        self.db = db
        self.correlator = RecoveryCorrelator(db)

    def assess_recovery_point(
        self,
        recovery_point_id: str,
        chain_id: Optional[str] = None,
        assessment_name: Optional[str] = None
    ) -> RecoveryAssessment:
        """
        Executes a rigorous cyber trust assessment for a candidate recovery point.
        """
        rp = self.db.query(RecoveryPoint).filter(RecoveryPoint.id == recovery_point_id).first()
        if not rp:
            raise ValueError(f"Recovery point '{recovery_point_id}' not found.")

        # Resolve or verify chain
        chain = None
        if chain_id:
            chain = self.db.query(RecoveryChain).filter(RecoveryChain.id == chain_id).first()
        if not chain:
            chain = self.db.query(RecoveryChain).filter(
                RecoveryChain.target_recovery_point_id == rp.id
            ).first()

        # 1. Correlate multi-source evidence
        evidence_pkg = self.correlator.correlate_evidence_for_point(rp)
        positive_items = evidence_pkg["positive_indicators"]
        negative_items = evidence_pkg["negative_indicators"]
        missing_telemetry = evidence_pkg["missing_telemetry"]
        uncertainty_factors = evidence_pkg["uncertainty_factors"]
        all_evidence = evidence_pkg["evidence_records"]

        # 2. Epistemological Guardrail: Check evidence sufficiency
        # Severe collection gaps or corrupted data preclude honest numeric scoring
        critical_gaps = [m for m in missing_telemetry if "telemetry blindness" in m.get("description", "").lower()]
        has_sufficient_evidence = (len(critical_gaps) == 0)

        # 3. Compute score and classification
        trust_classification = "UNASSESSED"
        trust_score: Optional[float] = None
        rationale_lines = []

        if not has_sufficient_evidence:
            trust_classification = "UNASSESSED"
            trust_score = None
            rationale_lines.append(
                "UNASSESSED: Critical monitoring telemetry gaps detected around the recovery window. "
                "Absence of telemetry cannot be treated as evidence of safety. Score suppressed."
            )
        else:
            # Starting baseline score
            score = 70.0  # Base neutral confidence

            # Positive factor bonuses
            for p in positive_items:
                score += p.get("weight_applied", 0.0)

            # Negative threat penalties
            for n in negative_items:
                score += n.get("weight_applied", 0.0)  # weights are already negative

            # Uncertainty penalties
            for u in uncertainty_factors:
                score += u.get("weight_applied", 0.0)

            # Chain technical integrity penalty if chain failed
            if chain and not chain.is_valid:
                score -= 30.0

            # Clamp between 0.0 and 100.0
            trust_score = max(0.0, min(100.0, round(score, 1)))

            # Evaluate critical blockers for classification
            has_critical_threat = any(n.get("weight_applied", 0) <= -40.0 for n in negative_items)
            has_integrity_failure = (rp.integrity_status == "FAILED")

            if has_critical_threat or has_integrity_failure or trust_score < 60.0:
                trust_classification = "LOW_CONFIDENCE"
                rationale_lines.append(
                    f"LOW CONFIDENCE (Score: {trust_score}/100): Confirmed intrusion indicators or integrity failures "
                    f"detected prior to this recovery point ({len(negative_items)} negative factors)."
                )
            elif trust_score >= 85.0 and len(negative_items) == 0 and len(uncertainty_factors) <= 1:
                trust_classification = "HIGH_CONFIDENCE"
                rationale_lines.append(
                    f"HIGH CONFIDENCE (Score: {trust_score}/100): Strong positive verification, zero threat indicators "
                    f"preceding recovery point, and confirmed clean state ({len(positive_items)} positive factors)."
                )
            else:
                trust_classification = "MEDIUM_CONFIDENCE"
                rationale_lines.append(
                    f"MEDIUM CONFIDENCE (Score: {trust_score}/100): Validated recovery candidate with residual uncertainties "
                    f"or minor anomalies ({len(uncertainty_factors)} uncertainty factors)."
                )

        name = assessment_name or f"Assessment_{rp.database_name}_{rp.recovery_point_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        assessment = RecoveryAssessment(
            recovery_point_id=rp.id,
            chain_id=chain.id if chain else None,
            assessment_name=name,
            model_version=self.MODEL_VERSION,
            trust_classification=trust_classification,
            trust_score=trust_score,
            has_sufficient_evidence=has_sufficient_evidence,
            confidence_rationale=" ".join(rationale_lines),
            positive_indicators_json=json.dumps(positive_items, default=str),
            negative_indicators_json=json.dumps(negative_items, default=str),
            missing_telemetry_json=json.dumps(missing_telemetry, default=str),
            uncertainty_factors_json=json.dumps(uncertainty_factors, default=str)
        )
        self.db.add(assessment)
        self.db.flush()

        # Record discrete evidence links
        for ev_item in all_evidence:
            ev_rec = RecoveryAssessmentEvidence(
                assessment_id=assessment.id,
                evidence_source=ev_item["evidence_source"],
                source_record_id=str(ev_item["source_record_id"]),
                relationship_type=ev_item["relationship_type"],
                time_delta_seconds=ev_item["time_delta_seconds"],
                impact_direction=ev_item["impact_direction"],
                weight_applied=ev_item["weight_applied"],
                description=ev_item["description"],
                metadata_json=json.dumps(ev_item.get("metadata", {}), default=str)
            )
            self.db.add(ev_rec)

        # Audit history entry
        hist = RecoveryAssessmentHistory(
            assessment_id=assessment.id,
            event_type="CREATED",
            actor="SYSTEM",
            notes=f"Initial assessment completed with classification: {trust_classification}",
            new_state_json=json.dumps({
                "classification": trust_classification,
                "score": trust_score,
                "model_version": self.MODEL_VERSION
            })
        )
        self.db.add(hist)
        self.db.commit()
        self.db.refresh(assessment)
        return assessment
