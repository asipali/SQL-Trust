"""
SQL-TRUST Backup Chain Analyzer Service
Module 4: Cyber Recovery & State Reconstruction
Validates backup chain relationships, LSN continuity, differential base matching,
recovery fork consistency, and identifies missing log segments or broken chains.
"""
import json
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from backend.models.backup import ProtectedDatabase
from backend.models.recovery import RecoveryPoint, RecoveryChain, RecoveryChainSegment


def compare_lsn(lsn1: Optional[str], lsn2: Optional[str]) -> int:
    """
    Compares two SQL Server LSN strings numerically.
    LSNs are typically formatted as integers or colon-separated hex/decimal.
    Returns:
      -1 if lsn1 < lsn2
       0 if lsn1 == lsn2
       1 if lsn1 > lsn2
    """
    if not lsn1 or not lsn2:
        return 0
    try:
        # If both are clean integer strings
        n1 = int(lsn1.replace(":", ""))
        n2 = int(lsn2.replace(":", ""))
        if n1 < n2:
            return -1
        elif n1 > n2:
            return 1
        return 0
    except ValueError:
        # Fallback string comparison
        if lsn1 < lsn2:
            return -1
        elif lsn1 > lsn2:
            return 1
        return 0


class BackupChainAnalyzer:
    """
    Constructs and validates the technical feasibility of restoring a sequence of backups.
    """

    def __init__(self, db: Session):
        self.db = db

    def analyze_chain_for_target(self, target_point_id: str) -> RecoveryChain:
        """
        Analyzes and validates the complete backup chain required to reach the target recovery point.
        """
        target_point = self.db.query(RecoveryPoint).filter(RecoveryPoint.id == target_point_id).first()
        if not target_point:
            raise ValueError(f"Recovery point '{target_point_id}' not found.")

        db_id = target_point.database_id
        target_time = target_point.recovery_point_time

        # 1. Locate the most recent FULL backup prior to or matching target point
        full_point = self.db.query(RecoveryPoint).filter(
            RecoveryPoint.database_id == db_id,
            RecoveryPoint.recovery_point_type == "FULL",
            RecoveryPoint.recovery_point_time <= target_time
        ).order_by(RecoveryPoint.recovery_point_time.desc()).first()

        if not full_point:
            return self._record_broken_chain(
                target_point=target_point,
                status="BROKEN_CHAIN",
                details="No preceding Full backup exists for this database. Recovery is impossible."
            )

        # 2. Check if target point IS the full backup
        if target_point.id == full_point.id:
            return self._build_full_only_chain(full_point)

        # 3. Locate best intervening Differential backup (if applicable)
        diff_point = None
        if target_point.recovery_point_type == "DIFFERENTIAL":
            diff_point = target_point
        else:
            # For LOG recovery points, find if there is an intervening differential backup
            diff_point = self.db.query(RecoveryPoint).filter(
                RecoveryPoint.database_id == db_id,
                RecoveryPoint.recovery_point_type == "DIFFERENTIAL",
                RecoveryPoint.recovery_point_time > full_point.recovery_point_time,
                RecoveryPoint.recovery_point_time <= target_time
            ).order_by(RecoveryPoint.recovery_point_time.desc()).first()

        # Validate Differential Base relationship if a diff backup exists
        diff_valid = True
        fork_error = None
        if diff_point:
            # Check differential base LSN
            if diff_point.database_backup_lsn and full_point.checkpoint_lsn:
                if compare_lsn(diff_point.database_backup_lsn, full_point.checkpoint_lsn) != 0:
                    diff_valid = False
                    fork_error = f"Differential backup {diff_point.id} base LSN ({diff_point.database_backup_lsn}) does not match Full backup checkpoint LSN ({full_point.checkpoint_lsn})."
            # Check recovery fork GUID consistency
            if diff_point.recovery_fork_guid and full_point.recovery_fork_guid:
                if diff_point.recovery_fork_guid != full_point.recovery_fork_guid:
                    diff_valid = False
                    fork_error = f"Recovery fork divergence: Differential fork GUID ({diff_point.recovery_fork_guid}) differs from base Full fork GUID ({full_point.recovery_fork_guid})."

        if diff_point and not diff_valid:
            return self._record_broken_chain(
                target_point=target_point,
                status="FORK_MISMATCH",
                details=fork_error or f"Differential backup {diff_point.id} base LSN ({diff_point.database_backup_lsn}) does not match Full backup checkpoint LSN ({full_point.checkpoint_lsn}).",
                base_full=full_point,
                diff_point=diff_point
            )

        if target_point.recovery_point_type == "DIFFERENTIAL":
            return self._build_diff_chain(full_point, diff_point)

        # 4. Target is a LOG backup - validate log continuity
        base_point = diff_point if diff_point else full_point
        log_points = self.db.query(RecoveryPoint).filter(
            RecoveryPoint.database_id == db_id,
            RecoveryPoint.recovery_point_type == "LOG",
            RecoveryPoint.recovery_point_time > base_point.recovery_point_time,
            RecoveryPoint.recovery_point_time <= target_time
        ).order_by(RecoveryPoint.recovery_point_time.asc()).all()

        return self._build_log_chain(
            target_point=target_point,
            full_point=full_point,
            diff_point=diff_point,
            log_points=log_points
        )

    def _build_full_only_chain(self, full_point: RecoveryPoint) -> RecoveryChain:
        """Constructs a chain consisting solely of a FULL backup."""
        is_valid = (full_point.integrity_status == "VERIFIED")
        status = "VALID" if is_valid else "INTEGRITY_FAILED"
        details = (
            "Single full backup baseline validated based on catalog LSN metadata. "
            "Catalog metadata alone cannot guarantee physical restore integrity; offline sandbox restore validation in SQLTrust_Lab is required."
            if is_valid else "Full backup failed integrity verification."
        )

        chain = self._get_or_create_chain(
            target_point=full_point,
            base_full_point=full_point,
            diff_point=None,
            is_complete=True,
            is_valid=is_valid,
            status=status,
            details=details,
            first_lsn=full_point.first_lsn,
            last_lsn=full_point.last_lsn,
            segment_count=1
        )
        # Clear old segments and add full segment
        self.db.query(RecoveryChainSegment).filter(RecoveryChainSegment.chain_id == chain.id).delete()
        seg = RecoveryChainSegment(
            chain_id=chain.id,
            recovery_point_id=full_point.id,
            sequence_order=1,
            segment_type="FULL",
            first_lsn=full_point.first_lsn,
            last_lsn=full_point.last_lsn,
            checkpoint_lsn=full_point.checkpoint_lsn,
            is_continuous=True
        )
        self.db.add(seg)
        self.db.commit()
        return chain

    def _build_diff_chain(self, full_point: RecoveryPoint, diff_point: RecoveryPoint) -> RecoveryChain:
        """Constructs a chain of FULL + DIFFERENTIAL."""
        all_verified = (full_point.integrity_status == "VERIFIED" and diff_point.integrity_status == "VERIFIED")
        status = "VALID" if all_verified else "INTEGRITY_FAILED"
        details = (
            "Full and Differential backup chain validated based on catalog LSN metadata. "
            "Catalog metadata alone cannot guarantee physical restore integrity; offline sandbox restore validation in SQLTrust_Lab is required."
            if all_verified else "One or more backup segments failed integrity verification."
        )

        chain = self._get_or_create_chain(
            target_point=diff_point,
            base_full_point=full_point,
            diff_point=diff_point,
            is_complete=True,
            is_valid=all_verified,
            status=status,
            details=details,
            first_lsn=full_point.first_lsn,
            last_lsn=diff_point.last_lsn,
            segment_count=2
        )
        self.db.query(RecoveryChainSegment).filter(RecoveryChainSegment.chain_id == chain.id).delete()
        seg1 = RecoveryChainSegment(
            chain_id=chain.id,
            recovery_point_id=full_point.id,
            sequence_order=1,
            segment_type="FULL",
            first_lsn=full_point.first_lsn,
            last_lsn=full_point.last_lsn,
            checkpoint_lsn=full_point.checkpoint_lsn,
            is_continuous=True
        )
        seg2 = RecoveryChainSegment(
            chain_id=chain.id,
            recovery_point_id=diff_point.id,
            sequence_order=2,
            segment_type="DIFFERENTIAL",
            first_lsn=diff_point.first_lsn,
            last_lsn=diff_point.last_lsn,
            checkpoint_lsn=diff_point.checkpoint_lsn,
            is_continuous=True
        )
        self.db.add_all([seg1, seg2])
        self.db.commit()
        return chain

    def _build_log_chain(
        self,
        target_point: RecoveryPoint,
        full_point: RecoveryPoint,
        diff_point: Optional[RecoveryPoint],
        log_points: List[RecoveryPoint]
    ) -> RecoveryChain:
        """Constructs and validates a multi-segment Full (+ Diff) + Logs chain."""
        segments: List[Tuple[int, RecoveryPoint, bool, Optional[str]]] = []
        seq = 1
        segments.append((seq, full_point, True, None))
        seq += 1

        if diff_point:
            segments.append((seq, diff_point, True, None))
            seq += 1

        is_continuous = True
        gap_reason = None
        broken_segment_id = None
        prev_point = diff_point if diff_point else full_point

        # Validate LSN sequence across log backups
        for log_p in log_points:
            seg_continuous = True
            gap_lsn = None

            # Check Recovery Fork GUID consistency
            if full_point.recovery_fork_guid and log_p.recovery_fork_guid:
                if full_point.recovery_fork_guid != log_p.recovery_fork_guid:
                    seg_continuous = False
                    gap_lsn = f"Recovery fork divergence detected: Base Fork {full_point.recovery_fork_guid} != Log Fork {log_p.recovery_fork_guid}"

            # First log backup must span or touch base checkpoint/last_lsn
            if prev_point.id in (full_point.id, getattr(diff_point, "id", None)):
                # If first log starts strictly after base last_lsn, we have a gap
                if prev_point.last_lsn and log_p.first_lsn:
                    if compare_lsn(log_p.first_lsn, prev_point.last_lsn) > 0:
                        seg_continuous = False
                        gap_lsn = f"Gap between base LastLSN {prev_point.last_lsn} and Log FirstLSN {log_p.first_lsn}"
            else:
                # Consecutive log backups: log[i].first_lsn must be <= log[i-1].last_lsn
                if prev_point.last_lsn and log_p.first_lsn:
                    if compare_lsn(log_p.first_lsn, prev_point.last_lsn) > 0:
                        seg_continuous = False
                        gap_lsn = f"Gap between Log #{seq-1} LastLSN {prev_point.last_lsn} and Log #{seq} FirstLSN {log_p.first_lsn}"

            if not seg_continuous:
                is_continuous = False
                gap_reason = gap_lsn
                broken_segment_id = log_p.id

            segments.append((seq, log_p, seg_continuous, gap_lsn))
            prev_point = log_p
            seq += 1

        # Check integrity of all segments
        all_verified = all(p.integrity_status == "VERIFIED" for _, p, _, _ in segments)
        last_seg_is_target = (segments[-1][1].id == target_point.id)

        if not last_seg_is_target:
            status = "MISSING_LOGS"
            details = "Chain does not reach target recovery point; log segments are missing."
            is_valid = False
            is_complete = False
        elif not is_continuous:
            status = "BROKEN_CHAIN"
            details = f"Transaction-log LSN continuity broken: {gap_reason}"
            is_valid = False
            is_complete = False
        elif not all_verified:
            status = "INTEGRITY_FAILED"
            details = "One or more backup segments in the chain failed integrity verification."
            is_valid = False
            is_complete = True
        else:
            status = "VALID"
            details = (
                f"Complete unbroken backup chain validated across {len(segments)} segments based on catalog LSN metadata. "
                "Catalog metadata alone cannot guarantee physical restore integrity; offline sandbox restore validation in SQLTrust_Lab is required."
            )
            is_valid = True
            is_complete = True

        chain = self._get_or_create_chain(
            target_point=target_point,
            base_full_point=full_point,
            diff_point=diff_point,
            is_complete=is_complete,
            is_valid=is_valid,
            status=status,
            details=details,
            first_lsn=full_point.first_lsn,
            last_lsn=target_point.last_lsn,
            segment_count=len(segments)
        )

        self.db.query(RecoveryChainSegment).filter(RecoveryChainSegment.chain_id == chain.id).delete()
        for s_order, p_record, s_cont, s_gap in segments:
            seg = RecoveryChainSegment(
                chain_id=chain.id,
                recovery_point_id=p_record.id,
                sequence_order=s_order,
                segment_type=p_record.recovery_point_type,
                first_lsn=p_record.first_lsn,
                last_lsn=p_record.last_lsn,
                checkpoint_lsn=p_record.checkpoint_lsn,
                is_continuous=s_cont,
                continuity_gap_lsn=s_gap
            )
            self.db.add(seg)
        self.db.commit()
        return chain

    def _record_broken_chain(
        self,
        target_point: RecoveryPoint,
        status: str,
        details: str,
        base_full: Optional[RecoveryPoint] = None,
        diff_point: Optional[RecoveryPoint] = None
    ) -> RecoveryChain:
        """Persists a broken/invalid chain state for investigative clarity."""
        chain = self._get_or_create_chain(
            target_point=target_point,
            base_full_point=base_full or target_point,
            diff_point=diff_point,
            is_complete=False,
            is_valid=False,
            status=status,
            details=details,
            first_lsn=target_point.first_lsn,
            last_lsn=target_point.last_lsn,
            segment_count=1
        )
        self.db.commit()
        return chain

    def _get_or_create_chain(
        self,
        target_point: RecoveryPoint,
        base_full_point: RecoveryPoint,
        diff_point: Optional[RecoveryPoint],
        is_complete: bool,
        is_valid: bool,
        status: str,
        details: str,
        first_lsn: Optional[str],
        last_lsn: Optional[str],
        segment_count: int
    ) -> RecoveryChain:
        chain = self.db.query(RecoveryChain).filter(
            RecoveryChain.target_recovery_point_id == target_point.id
        ).first()

        name = f"Chain_{target_point.database_name}_{target_point.recovery_point_type}_{target_point.recovery_point_time.strftime('%Y%m%d_%H%M%S')}"

        if not chain:
            chain = RecoveryChain(
                database_id=target_point.database_id,
                server_name=target_point.server_name,
                database_name=target_point.database_name,
                chain_name=name,
                target_recovery_point_id=target_point.id,
                base_full_point_id=base_full_point.id,
                differential_point_id=diff_point.id if diff_point else None,
                is_complete=is_complete,
                is_valid=is_valid,
                validation_status=status,
                validation_details=details,
                first_lsn=first_lsn,
                last_lsn=last_lsn,
                segment_count=segment_count
            )
            self.db.add(chain)
        else:
            chain.base_full_point_id = base_full_point.id
            chain.differential_point_id = diff_point.id if diff_point else None
            chain.is_complete = is_complete
            chain.is_valid = is_valid
            chain.validation_status = status
            chain.validation_details = details
            chain.first_lsn = first_lsn
            chain.last_lsn = last_lsn
            chain.segment_count = segment_count

        self.db.flush()
        return chain
