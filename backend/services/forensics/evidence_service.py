"""
SQL-TRUST Forensic Evidence Service
Module 3: Database Forensics Engine
Packages, signs, and uploads forensic investigation reports and baseline dumps
to SeaweedFS Object Lock WORM storage with 30-day compliance retention.
Verifies Ed25519 digital signatures and SHA-256 payload integrity.
"""
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.services.storage import SeaweedFSStorageProvider
from backend.services.security.signer import signer
from backend.models.forensics import (
    ForensicInvestigation,
    ForensicBaseline,
    ForensicEvidenceArchive
)


def compute_sha256(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()


class ForensicEvidenceService:
    """
    Manages cryptographic preservation of forensic artifacts in immutable WORM storage.
    """

    def __init__(self, db: Session):
        self.db = db
        self.storage = SeaweedFSStorageProvider()

    def archive_baseline(self, baseline: ForensicBaseline) -> ForensicEvidenceArchive:
        """
        Exports full baseline snapshot to signed JSON and archives to SeaweedFS Object Lock storage.
        """
        items = baseline.items
        items_payload = [
            {
                "item_type": it.item_type,
                "schema_name": it.schema_name,
                "item_name": it.item_name,
                "definition_hash": it.definition_hash,
                "raw_definition": it.raw_definition,
                "properties": json.loads(it.properties_json) if it.properties_json else {},
                "is_encrypted": it.is_encrypted
            }
            for it in items
        ]

        manifest_data = {
            "baseline_id": baseline.id,
            "baseline_name": baseline.baseline_name,
            "database_name": baseline.database_name,
            "server_name": baseline.server_name,
            "captured_at": baseline.captured_at.isoformat(),
            "total_objects": baseline.total_objects,
            "total_principals": baseline.total_principals,
            "total_permissions": baseline.total_permissions,
            "sha256_manifest": baseline.sha256_manifest,
            "items": items_payload
        }

        # Deterministic canonical JSON and Ed25519 signature
        signature = signer.sign_manifest(manifest_data)
        manifest_data["signature"] = signature
        canonical_bytes = json.dumps(manifest_data, sort_keys=True, indent=2).encode("utf-8")
        payload_sha256 = compute_sha256(canonical_bytes)

        # Stage file locally
        timestamp_str = baseline.captured_at.strftime("%Y%m%d_%H%M%S")
        clean_db = baseline.database_name.replace("\\", "_")
        local_filename = f"baseline_{clean_db}_{timestamp_str}.json"
        local_dir = os.path.abspath(r"data\evidence\baselines")
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, local_filename)

        with open(local_path, "wb") as f:
            f.write(canonical_bytes)

        # Upload to SeaweedFS WORM storage
        object_key = f"forensics-evidence/{baseline.server_name.replace('\\', '_')}/{clean_db}/baselines/{local_filename}"
        upload_res = self.storage.upload_file(
            local_file_path=local_path,
            object_key=object_key
        )

        version_id = upload_res.get("version_id")
        retention_until = datetime.now(timezone.utc) + timedelta(days=30)

        # Record in forensic_evidence_archives
        archive = ForensicEvidenceArchive(
            baseline_id=baseline.id,
            evidence_type="BASELINE_DUMP",
            storage_bucket=self.storage.bucket_name,
            storage_object_key=object_key,
            storage_version_id=version_id,
            sha256=payload_sha256,
            file_size_bytes=len(canonical_bytes),
            signature=signature,
            retention_mode="COMPLIANCE",
            retention_until=retention_until,
            verification_status="VERIFIED"
        )
        self.db.add(archive)

        # Update baseline metadata
        baseline.storage_object_key = object_key
        baseline.storage_version_id = version_id
        baseline.signature = signature
        self.db.commit()
        self.db.refresh(archive)

        return archive

    def archive_investigation_report(self, investigation: ForensicInvestigation) -> ForensicEvidenceArchive:
        """
        Exports complete investigation findings and timeline to signed JSON manifest in SeaweedFS Object Lock.
        """
        findings = investigation.findings
        findings_payload = [
            {
                "id": f.id,
                "category": f.category,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "entity_name": f.entity_name,
                "schema_name": f.schema_name,
                "before_state": json.loads(f.before_state_json) if f.before_state_json else None,
                "after_state": json.loads(f.after_state_json) if f.after_state_json else None,
                "explanation": f.explanation,
                "confidence_score": f.confidence_score
            }
            for f in findings
        ]

        report_data = {
            "investigation_id": investigation.id,
            "investigation_name": investigation.investigation_name,
            "server_name": investigation.server_name,
            "database_name": investigation.database_name,
            "ref_baseline_id": investigation.ref_baseline_id,
            "target_baseline_id": investigation.target_baseline_id,
            "started_at": investigation.started_at.isoformat(),
            "completed_at": investigation.completed_at.isoformat() if investigation.completed_at else None,
            "findings_count": investigation.findings_count,
            "critical_count": investigation.critical_findings_count,
            "high_count": investigation.high_findings_count,
            "summary_notes": investigation.summary_notes,
            "findings": findings_payload
        }

        # Sign with Ed25519
        signature = signer.sign_manifest(report_data)
        report_data["signature"] = signature
        canonical_bytes = json.dumps(report_data, sort_keys=True, indent=2).encode("utf-8")
        payload_sha256 = compute_sha256(canonical_bytes)

        # Stage file
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        clean_db = investigation.database_name.replace("\\", "_")
        local_filename = f"investigation_{clean_db}_{timestamp_str}.json"
        local_dir = os.path.abspath(r"data\evidence\investigations")
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, local_filename)

        with open(local_path, "wb") as f:
            f.write(canonical_bytes)

        object_key = f"forensics-evidence/{investigation.server_name.replace('\\', '_')}/{clean_db}/investigations/{local_filename}"
        upload_res = self.storage.upload_file(
            local_file_path=local_path,
            object_key=object_key
        )

        version_id = upload_res.get("version_id")
        retention_until = datetime.now(timezone.utc) + timedelta(days=30)

        archive = ForensicEvidenceArchive(
            investigation_id=investigation.id,
            evidence_type="INVESTIGATION_REPORT",
            storage_bucket=self.storage.bucket_name,
            storage_object_key=object_key,
            storage_version_id=version_id,
            sha256=payload_sha256,
            file_size_bytes=len(canonical_bytes),
            signature=signature,
            retention_mode="COMPLIANCE",
            retention_until=retention_until,
            verification_status="VERIFIED"
        )
        self.db.add(archive)

        investigation.storage_object_key = object_key
        investigation.storage_version_id = version_id
        investigation.manifest_sha256 = payload_sha256
        investigation.signature = signature
        self.db.commit()
        self.db.refresh(archive)

        return archive

    def verify_evidence_archive(self, archive_id: str) -> Dict[str, Any]:
        """
        Retrieves evidence object from SeaweedFS, verifies SHA-256 integrity,
        validates Ed25519 digital signature, and checks WORM retention status.
        """
        arc = self.db.query(ForensicEvidenceArchive).filter(ForensicEvidenceArchive.id == archive_id).first()
        if not arc:
            return {"valid": False, "error": "Evidence archive record not found."}

        s3 = self.storage.s3_client
        try:
            obj = s3.get_object(Bucket=arc.storage_bucket, Key=arc.storage_object_key)
            body_bytes = obj["Body"].read()

            # 1. SHA-256 check
            calc_sha256 = compute_sha256(body_bytes)
            sha_matches = (calc_sha256 == arc.sha256)

            # 2. Ed25519 Signature check
            manifest_json = json.loads(body_bytes.decode("utf-8"))
            s3_sig = manifest_json.get("signature")
            db_sig = arc.signature
            sig_in_sync = (db_sig == s3_sig) if (db_sig and s3_sig) else True
            sig_to_verify = db_sig or s3_sig
            sig_valid = bool(sig_in_sync and signer.verify_manifest(manifest_json, sig_to_verify))

            # 3. Object Lock retention check
            ret_info = s3.get_object_retention(Bucket=arc.storage_bucket, Key=arc.storage_object_key)
            retention = ret_info.get("Retention", {})
            mode = retention.get("Mode")
            retain_until = retention.get("RetainUntilDate")

            return {
                "valid": bool(sha_matches and sig_valid),
                "archive_id": arc.id,
                "evidence_type": arc.evidence_type,
                "sha256_match": sha_matches,
                "signature_valid": sig_valid,
                "worm_mode": mode,
                "retention_until": retain_until.isoformat() if retain_until else None,
                "version_id": arc.storage_version_id,
                "storage_object_key": arc.storage_object_key
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "archive_id": arc.id
            }
