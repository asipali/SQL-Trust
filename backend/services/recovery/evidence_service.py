"""
SQL-TRUST Recovery Evidence Management & WORM Service
Module 4: Cyber Recovery & State Reconstruction
Serializes, signs (Ed25519), and archives recovery assessments to SeaweedFS Object Lock WORM storage.
Provides independent cryptographic tamper verification and retention compliance auditing.
"""
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.services.storage import SeaweedFSStorageProvider
from backend.services.security.signer import signer
from backend.models.recovery import (
    RecoveryAssessment,
    RecoveryAssessmentHistory
)


def compute_sha256(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()


class RecoveryEvidenceService:
    """
    Manages cryptographic signing and immutable SeaweedFS WORM storage for cyber recovery assessments.
    """

    def __init__(self, db: Session):
        self.db = db
        self.storage = SeaweedFSStorageProvider()

    def archive_assessment_report(self, assessment: RecoveryAssessment) -> Dict[str, Any]:
        """
        Exports complete recovery assessment to signed canonical JSON in SeaweedFS Object Lock WORM storage.
        """
        rp = assessment.recovery_point
        chain = assessment.chain

        report_data = {
            "assessment_id": assessment.id,
            "assessment_name": assessment.assessment_name,
            "model_version": assessment.model_version,
            "database_name": rp.database_name,
            "server_name": rp.server_name,
            "recovery_point_id": rp.id,
            "recovery_point_time": rp.recovery_point_time.isoformat(),
            "recovery_point_type": rp.recovery_point_type,
            "first_lsn": rp.first_lsn,
            "last_lsn": rp.last_lsn,
            "checkpoint_lsn": rp.checkpoint_lsn,
            "trust_classification": assessment.trust_classification,
            "trust_score": assessment.trust_score,
            "has_sufficient_evidence": assessment.has_sufficient_evidence,
            "confidence_rationale": assessment.confidence_rationale,
            "positive_indicators": json.loads(assessment.positive_indicators_json or "[]"),
            "negative_indicators": json.loads(assessment.negative_indicators_json or "[]"),
            "missing_telemetry": json.loads(assessment.missing_telemetry_json or "[]"),
            "uncertainty_factors": json.loads(assessment.uncertainty_factors_json or "[]"),
            "chain_validation_status": chain.validation_status if chain else "NO_CHAIN",
            "chain_segment_count": chain.segment_count if chain else 0,
            "assessed_at": assessment.assessed_at.isoformat()
        }

        # 1. Sign canonical JSON with Ed25519
        signature = signer.sign_manifest(report_data)
        report_data["signature"] = signature

        canonical_bytes = json.dumps(report_data, sort_keys=True, indent=2).encode("utf-8")
        payload_sha256 = compute_sha256(canonical_bytes)

        # 2. Stage file locally
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        clean_db = rp.database_name.replace("\\", "_")
        local_filename = f"recovery_assessment_{clean_db}_{timestamp_str}.json"
        local_dir = os.path.abspath(r"data\evidence\recovery_assessments")
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, local_filename)

        with open(local_path, "wb") as f:
            f.write(canonical_bytes)

        # 3. Upload to SeaweedFS Object Lock WORM storage
        object_key = f"recovery-evidence/{rp.server_name.replace('\\', '_')}/{clean_db}/{local_filename}"
        upload_res = self.storage.upload_file(
            local_file_path=local_path,
            object_key=object_key
        )

        version_id = upload_res.get("version_id")

        # 4. Update assessment record
        assessment.manifest_sha256 = payload_sha256
        assessment.signature = signature
        assessment.storage_object_key = object_key
        assessment.storage_version_id = version_id

        # 5. History entry
        hist = RecoveryAssessmentHistory(
            assessment_id=assessment.id,
            event_type="ARCHIVED",
            actor="SYSTEM",
            notes=f"Cryptographically signed and archived to SeaweedFS WORM storage: {object_key}",
            new_state_json=json.dumps({
                "storage_object_key": object_key,
                "version_id": version_id,
                "sha256": payload_sha256
            })
        )
        self.db.add(hist)
        self.db.commit()

        return {
            "valid": True,
            "assessment_id": assessment.id,
            "storage_object_key": object_key,
            "storage_version_id": version_id,
            "manifest_sha256": payload_sha256,
            "signature": signature,
            "retention_mode": upload_res.get("retention_mode", "COMPLIANCE")
        }

    def verify_assessment_archive(self, assessment_id: str) -> Dict[str, Any]:
        """
        Retrieves the signed recovery assessment from SeaweedFS S3,
        verifies SHA-256 hash integrity, validates the Ed25519 signature,
        and audits WORM compliance retention metadata.
        """
        asm = self.db.query(RecoveryAssessment).filter(RecoveryAssessment.id == assessment_id).first()
        if not asm:
            return {"valid": False, "error": f"Recovery assessment '{assessment_id}' not found."}

        if not asm.storage_object_key:
            return {"valid": False, "error": "Assessment has not been archived to storage."}

        s3 = self.storage.s3_client
        try:
            get_kwargs = {"Bucket": self.storage.bucket_name, "Key": asm.storage_object_key}
            if asm.storage_version_id:
                get_kwargs["VersionId"] = asm.storage_version_id

            obj = s3.get_object(**get_kwargs)
            body_bytes = obj["Body"].read()

            # 1. SHA-256 check
            calc_sha256 = compute_sha256(body_bytes)
            sha_matches = (calc_sha256 == asm.manifest_sha256)

            # 2. Ed25519 Signature check
            manifest_json = json.loads(body_bytes.decode("utf-8"))
            s3_sig = manifest_json.get("signature")
            db_sig = asm.signature

            sig_in_sync = bool(db_sig and s3_sig and db_sig == s3_sig)
            sig_valid = bool(sig_in_sync and signer.verify_manifest(manifest_json, db_sig))

            # 3. Object Lock retention check
            ret_kwargs = {"Bucket": self.storage.bucket_name, "Key": asm.storage_object_key}
            if asm.storage_version_id:
                ret_kwargs["VersionId"] = asm.storage_version_id

            ret_info = s3.get_object_retention(**ret_kwargs)
            retention = ret_info.get("Retention", {})
            mode = retention.get("Mode")
            retain_until = retention.get("RetainUntilDate")

            now_utc = datetime.now(timezone.utc)
            is_retained = False
            if retain_until:
                if retain_until.tzinfo is None:
                    retain_until_aware = retain_until.replace(tzinfo=timezone.utc)
                else:
                    retain_until_aware = retain_until
                is_retained = bool(retain_until_aware > now_utc)

            worm_compliant = bool(mode == "COMPLIANCE" and is_retained)
            is_valid_overall = bool(sha_matches and sig_valid and worm_compliant)

            return {
                "valid": is_valid_overall,
                "assessment_id": asm.id,
                "sha256_match": sha_matches,
                "signature_valid": sig_valid,
                "signature_in_sync": sig_in_sync,
                "worm_compliant": worm_compliant,
                "worm_mode": mode,
                "retention_until": retain_until.isoformat() if retain_until else None,
                "version_id": asm.storage_version_id,
                "storage_object_key": asm.storage_object_key
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "assessment_id": asm.id
            }
