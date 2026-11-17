"""
SQL-TRUST Ranked Recovery Recommendation Engine
Module 4: Cyber Recovery & State Reconstruction
Generates ranked candidate recovery points with explainable tradeoffs and next-step actions.
Balances cyber trust confidence, technical eligibility, and minimal data loss.
"""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.models.recovery import (
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)


class RecoveryRecommendationEngine:
    """
    Ranks candidate recovery points by evaluating the tradeoff between forensic confidence,
    transaction data loss, and technical restore readiness.
    """

    def __init__(self, db: Session):
        self.db = db

    def generate_recommendations(self, database_id: str) -> List[RecoveryRecommendation]:
        """
        Ranks all assessed and evaluated recovery points for a protected database.
        """
        # Delete prior recommendations for this database to avoid stale ranks
        self.db.query(RecoveryRecommendation).filter(
            RecoveryRecommendation.database_id == database_id
        ).delete()
        self.db.commit()

        # Fetch recovery points with their latest assessment and eligibility
        points = self.db.query(RecoveryPoint).filter(
            RecoveryPoint.database_id == database_id
        ).order_by(RecoveryPoint.recovery_point_time.asc()).all()

        if not points:
            return []

        candidates: List[Dict[str, Any]] = []

        min_time = min(p.recovery_point_time for p in points)
        max_time = max(p.recovery_point_time for p in points)
        time_span = (max_time - min_time).total_seconds() or 1.0

        for pt in points:
            assessment = self.db.query(RecoveryAssessment).filter(
                RecoveryAssessment.recovery_point_id == pt.id
            ).order_by(RecoveryAssessment.assessed_at.desc()).first()

            eligibility = self.db.query(RecoveryEligibility).filter(
                RecoveryEligibility.recovery_point_id == pt.id
            ).first()

            if not assessment or not eligibility:
                continue

            # Freshness score (0.0 to 100.0) based on timestamp proximity to newest
            freshness_score = round(((pt.recovery_point_time - min_time).total_seconds() / time_span) * 100.0, 1)

            # Trust score (strictly 0.0 if UNASSESSED or missing)
            if assessment.trust_classification == "UNASSESSED" or assessment.trust_score is None:
                t_score = 0.0
            else:
                t_score = assessment.trust_score

            # Composite ranking score: 65% Confidence, 35% Freshness
            rank_score = (t_score * 0.65) + (freshness_score * 0.35)

            # Technical Ineligibility Penalty (Ensure ineligible points cannot outrank eligible ones)
            if not eligibility.is_eligible:
                rank_score -= 100.0

            # Threat Confidence Penalties: Freshness must NEVER compensate for compromised state
            if assessment.trust_classification == "LOW_CONFIDENCE":
                rank_score -= 60.0
            elif assessment.trust_classification == "UNASSESSED":
                rank_score -= 50.0

            candidates.append({
                "point": pt,
                "assessment": assessment,
                "eligibility": eligibility,
                "trust_score": t_score,
                "freshness_score": freshness_score,
                "rank_score": rank_score
            })

        # Sort: 1) Eligible before Ineligible; 2) Non-LOW_CONFIDENCE before LOW_CONFIDENCE; 3) Rank score descending
        candidates.sort(
            key=lambda x: (
                1 if x["eligibility"].is_eligible else 0,
                1 if x["assessment"].trust_classification not in ("LOW_CONFIDENCE", "UNASSESSED") else 0,
                x["rank_score"]
            ),
            reverse=True
        )

        # Clear existing recommendations for this database to avoid duplicate ranks
        self.db.query(RecoveryRecommendation).filter(
            RecoveryRecommendation.database_id == database_id
        ).delete()

        recommendations: List[RecoveryRecommendation] = []

        for idx, cand in enumerate(candidates, start=1):
            pt = cand["point"]
            asm = cand["assessment"]
            elg = cand["eligibility"]

            # Explainable rationale and tradeoffs
            rationale_parts = []
            tradeoff_parts = []
            next_step = ""

            if idx == 1:
                if elg.is_eligible and asm.trust_classification in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"):
                    rationale_parts.append(f"Rank #1 (Optimal Candidate): Highest balanced composite score ({cand['rank_score']:.1f}).")
                else:
                    rationale_parts.append(f"Rank #1 (RESTORE BLOCKED): No clean eligible candidate available. Composite score {cand['rank_score']:.1f}.")
            else:
                rationale_parts.append(f"Rank #{idx}: Composite score {cand['rank_score']:.1f}.")

            if elg.is_eligible and asm.trust_classification == "HIGH_CONFIDENCE":
                rationale_parts.append("Technically eligible with verified clean forensic baseline.")
                tradeoff_parts.append("Provides highest security confidence with minimal compromise risk.")
                next_step = "Direct production restore prohibited. Restore into isolated SQLTrust_Lab sandbox first to verify database consistency and validate integrity before authorized recovery."
            elif elg.is_eligible and asm.trust_classification == "MEDIUM_CONFIDENCE":
                rationale_parts.append("Technically eligible but exhibits minor security anomalies.")
                tradeoff_parts.append(f"Offers fresher data ({cand['freshness_score']}% freshness) but requires thorough audit of intervening sessions.")
                next_step = "Direct production restore prohibited. Restore into isolated SQLTrust_Lab sandbox and execute full Module 3 baseline comparison against pre-incident baseline."
            elif not elg.is_eligible:
                rationale_parts.append(f"RESTORE BLOCKED: Ineligible due to {elg.eligibility_status}.")
                tradeoff_parts.append("Cannot be restored directly; backup chain, file integrity, or verification is broken.")
                next_step = f"Direct production restore prohibited. Restore blocked due to technical ineligibility. Investigate blocking reasons: {elg.blocking_reasons_json}."
            else:
                rationale_parts.append(f"Classified as {asm.trust_classification}.")
                tradeoff_parts.append("High intrusion risk; restoring this candidate likely restores attacker persistence.")
                next_step = "Direct production restore prohibited. Candidate is untrusted or compromised. Retain for forensic inspection in an isolated forensic sandbox only."

            rec = RecoveryRecommendation(
                database_id=database_id,
                recovery_point_id=pt.id,
                assessment_id=asm.id,
                eligibility_id=elg.id,
                rank_order=idx,
                trust_classification=asm.trust_classification,
                eligibility_status=elg.eligibility_status,
                ranking_score=round(max(0.0, min(100.0, cand["rank_score"])), 2),
                rank_rationale=" ".join(rationale_parts),
                tradeoff_analysis=" ".join(tradeoff_parts),
                recommended_next_step=next_step
            )
            self.db.add(rec)
            recommendations.append(rec)

        self.db.commit()
        return recommendations
