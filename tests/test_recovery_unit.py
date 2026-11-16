"""
Unit tests for SQL-TRUST Module 4: Cyber Recovery & State Reconstruction.
Tests LSN parsing, backup chain continuity logic, trust scoring rubric,
epistemological telemetry guardrails, and technical eligibility evaluations.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from backend.services.recovery.chain_analyzer import BackupChainAnalyzer, compare_lsn
from backend.services.recovery.trust_engine import RecoveryTrustEngine
from backend.services.recovery.eligibility_engine import RecoveryEligibilityEngine
from backend.services.recovery.recommendation_engine import RecoveryRecommendationEngine
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryAssessment,
    RecoveryEligibility
)


# =====================================================================
# 1. LSN Comparison Unit Tests
# =====================================================================

def test_compare_lsn_numeric():
    assert compare_lsn("1000", "2000") < 0
    assert compare_lsn("2000", "1000") > 0
    assert compare_lsn("1500", "1500") == 0


def test_compare_lsn_colon_formatted():
    lsn1 = "00000025:00000198:0001"
    lsn2 = "00000025:00000198:0002"
    lsn3 = "00000026:00000010:0001"

    assert compare_lsn(lsn1, lsn2) < 0
    assert compare_lsn(lsn2, lsn1) > 0
    assert compare_lsn(lsn2, lsn3) < 0
    assert compare_lsn(lsn1, lsn1) == 0


def test_compare_lsn_none_and_empty():
    assert compare_lsn(None, "100") == 0
    assert compare_lsn("100", None) == 0
    assert compare_lsn(None, None) == 0
    assert compare_lsn("", "100") == 0


# =====================================================================
# 2. Backup Chain Continuity Unit Tests
# =====================================================================

def test_chain_analyzer_full_and_log_continuity():
    mock_db = MagicMock()
    analyzer = BackupChainAnalyzer(mock_db)

    full_rp = RecoveryPoint(
        id="rp-full-1",
        database_id="db-1",
        recovery_point_type="FULL",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=3),
        first_lsn="100",
        last_lsn="200",
        checkpoint_lsn="150",
        database_backup_lsn="0",
        integrity_status="VERIFIED"
    )

    log1_rp = RecoveryPoint(
        id="rp-log-1",
        database_id="db-1",
        recovery_point_type="LOG",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=2),
        first_lsn="150",
        last_lsn="300",
        checkpoint_lsn="250",
        database_backup_lsn="150",
        integrity_status="VERIFIED"
    )

    log2_rp = RecoveryPoint(
        id="rp-log-2",
        database_id="db-1",
        recovery_point_type="LOG",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=1),
        first_lsn="300",
        last_lsn="450",
        checkpoint_lsn="400",
        database_backup_lsn="150",
        integrity_status="VERIFIED"
    )

    analyzer._get_or_create_chain = MagicMock(return_value=RecoveryChain(
        id="chain-test",
        is_complete=True,
        is_valid=True,
        validation_status="VALID",
        segment_count=3
    ))

    chain = analyzer._build_log_chain(
        target_point=log2_rp,
        full_point=full_rp,
        diff_point=None,
        log_points=[log1_rp, log2_rp]
    )
    assert chain.is_complete is True
    assert chain.is_valid is True
    assert chain.validation_status == "VALID"


def test_chain_analyzer_broken_log_gap():
    mock_db = MagicMock()
    analyzer = BackupChainAnalyzer(mock_db)

    full_rp = RecoveryPoint(
        id="rp-full-1",
        database_id="db-1",
        recovery_point_type="FULL",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=3),
        first_lsn="100",
        last_lsn="200",
        checkpoint_lsn="150",
        database_backup_lsn="0",
        integrity_status="VERIFIED"
    )

    log1_rp = RecoveryPoint(
        id="rp-log-1",
        database_id="db-1",
        recovery_point_type="LOG",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=2),
        first_lsn="150",
        last_lsn="250",
        checkpoint_lsn="200",
        integrity_status="VERIFIED"
    )

    log2_rp = RecoveryPoint(
        id="rp-log-2",
        database_id="db-1",
        recovery_point_type="LOG",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=1),
        first_lsn="300",  # GAP: 250 -> 300
        last_lsn="400",
        checkpoint_lsn="350",
        integrity_status="VERIFIED"
    )

    analyzer._get_or_create_chain = MagicMock(return_value=RecoveryChain(
        id="chain-broken",
        is_complete=False,
        is_valid=False,
        validation_status="BROKEN_CHAIN"
    ))

    chain = analyzer._build_log_chain(
        target_point=log2_rp,
        full_point=full_rp,
        diff_point=None,
        log_points=[log1_rp, log2_rp]
    )
    assert chain.is_valid is False
    assert "BROKEN" in chain.validation_status or "GAP" in chain.validation_status


# =====================================================================
# 3. Trust Engine & Epistemological Guardrails Unit Tests
# =====================================================================

def test_trust_engine_clean_window_high_confidence():
    mock_db = MagicMock()
    trust_engine = RecoveryTrustEngine(mock_db)

    rp = RecoveryPoint(
        id="rp-clean",
        database_id="db-1",
        database_name="SQLTrust_Lab",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=2),
        recovery_point_type="FULL",
        integrity_status="VERIFIED",
        sha256="hash-clean"
    )

    def mock_query(model):
        m = MagicMock()
        if model == RecoveryPoint:
            m.filter.return_value.first.return_value = rp
        else:
            m.filter.return_value.first.return_value = None
        return m

    mock_db.query.side_effect = mock_query

    trust_engine.correlator.correlate_evidence_for_point = MagicMock(return_value={
        "positive_indicators": [{"weight_applied": 25.0, "description": "Clean baseline"}],
        "negative_indicators": [],
        "missing_telemetry": [],
        "uncertainty_factors": [],
        "evidence_records": []
    })

    assessment = trust_engine.assess_recovery_point("rp-clean")

    assert assessment.trust_score is not None
    assert assessment.trust_score >= 70.0
    assert assessment.trust_classification in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE")


def test_trust_engine_epistemological_gap_suppression():
    """Verify that when telemetry gaps exist, numeric score is suppressed and UNASSESSED is returned."""
    mock_db = MagicMock()
    trust_engine = RecoveryTrustEngine(mock_db)

    rp = RecoveryPoint(
        id="rp-with-gap",
        database_id="db-1",
        database_name="SQLTrust_Lab",
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=1),
        recovery_point_type="FULL",
        integrity_status="VERIFIED"
    )

    def mock_query(model):
        m = MagicMock()
        if model == RecoveryPoint:
            m.filter.return_value.first.return_value = rp
        else:
            m.filter.return_value.first.return_value = None
        return m

    mock_db.query.side_effect = mock_query

    trust_engine.correlator.correlate_evidence_for_point = MagicMock(return_value={
        "positive_indicators": [],
        "negative_indicators": [],
        "missing_telemetry": [{"source": "COLLECTION_GAP", "description": "Extended Events dropped telemetry blindness"}],
        "uncertainty_factors": [{"source": "COLLECTION_GAP"}],
        "evidence_records": []
    })

    assessment = trust_engine.assess_recovery_point("rp-with-gap")

    assert assessment.trust_score is None, "Numeric score must be suppressed when evidence gaps exist"
    assert assessment.trust_classification == "UNASSESSED", "Trust classification must be UNASSESSED under unobservable conditions"


def test_trust_engine_malicious_ddl_penalty():
    mock_db = MagicMock()
    trust_engine = RecoveryTrustEngine(mock_db)

    rp = RecoveryPoint(
        id="rp-post-incident",
        database_id="db-1",
        database_name="SQLTrust_Lab",
        recovery_point_time=datetime.now(timezone.utc),
        recovery_point_type="FULL",
        integrity_status="VERIFIED"
    )

    def mock_query(model):
        m = MagicMock()
        if model == RecoveryPoint:
            m.filter.return_value.first.return_value = rp
        else:
            m.filter.return_value.first.return_value = None
        return m

    mock_db.query.side_effect = mock_query

    trust_engine.correlator.correlate_evidence_for_point = MagicMock(return_value={
        "positive_indicators": [],
        "negative_indicators": [
            {"weight_applied": -40.0, "description": "Privilege escalation detected"},
            {"weight_applied": -30.0, "description": "Unauthorized DDL mutation"}
        ],
        "missing_telemetry": [],
        "uncertainty_factors": [],
        "evidence_records": []
    })

    assessment = trust_engine.assess_recovery_point("rp-post-incident")

    assert assessment.trust_score is not None
    assert assessment.trust_score < 60.0, "Score must reflect significant penalty from security alerts"
    assert assessment.trust_classification == "LOW_CONFIDENCE"


# =====================================================================
# 4. Eligibility Engine Unit Tests
# =====================================================================

def test_eligibility_engine_valid_evaluation():
    mock_db = MagicMock()
    elig_engine = RecoveryEligibilityEngine(mock_db)

    rp = RecoveryPoint(
        id="rp-1",
        database_id="db-1",
        database_name="SQLTrust_Lab",
        recovery_point_type="FULL",
        integrity_status="VERIFIED",
        storage_object_key="backups/full.bak"
    )
    chain = RecoveryChain(
        id="ch-1",
        is_complete=True,
        is_valid=True,
        validation_status="VALID"
    )

    def mock_query(model):
        m = MagicMock()
        if model == RecoveryPoint:
            m.filter.return_value.first.return_value = rp
        else:
            m.filter.return_value.first.return_value = None
        return m

    mock_db.query.side_effect = mock_query
    elig_engine.chain_analyzer.analyze_chain_for_target = MagicMock(return_value=chain)

    elig = elig_engine.evaluate_eligibility("rp-1")

    assert elig.is_eligible is True
    assert elig.eligibility_status == "ELIGIBLE"
    assert elig.requires_offline_sandbox is True
    assert elig.chain_usable is True


def test_eligibility_engine_invalid_broken_chain():
    mock_db = MagicMock()
    elig_engine = RecoveryEligibilityEngine(mock_db)

    rp = RecoveryPoint(
        id="rp-broken",
        database_id="db-1",
        database_name="SQLTrust_Lab",
        recovery_point_type="FULL",
        integrity_status="VERIFIED",
        storage_object_key="backups/broken.bak"
    )
    chain = RecoveryChain(
        id="ch-broken",
        is_complete=False,
        is_valid=False,
        validation_status="BROKEN_CHAIN",
        validation_details="Missing LSN sequence between 200 and 300"
    )

    def mock_query(model):
        m = MagicMock()
        if model == RecoveryPoint:
            m.filter.return_value.first.return_value = rp
        else:
            m.filter.return_value.first.return_value = None
        return m

    mock_db.query.side_effect = mock_query
    elig_engine.chain_analyzer.analyze_chain_for_target = MagicMock(return_value=chain)

    elig = elig_engine.evaluate_eligibility("rp-broken")

    assert elig.is_eligible is False
    assert elig.eligibility_status in ("INELIGIBLE", "BLOCKED")
    assert elig.chain_usable is False
