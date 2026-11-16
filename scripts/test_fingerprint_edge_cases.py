"""
SQL-TRUST Module 2 Hardening Review: Event Fingerprinting & SHA-256 Determinism Audit
====================================================================================
Tests:
1. Cryptographic determinism across repeated executions.
2. Collision resistance against single-character/single-field variations.
3. Cross-file rollover distinction.
4. Sequence number differentiation for identical queries in the same batch.
5. Invariance across timezone representations (UTC vs local conversion).
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone, timedelta
from backend.services.security.normalizer import compute_event_fingerprint


def test_fingerprint_determinism():
    print("\n--- [FINGERPRINT TEST 1] Determinism ---")
    ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    fp1 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="SQLTrust_Audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="admin",
        session_id=52,
        statement="SELECT 1",
        source_event_id="SQLTrust_Audit_01.sqlaudit:1024:1"
    )
    fp2 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="SQLTrust_Audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="admin",
        session_id=52,
        statement="SELECT 1",
        source_event_id="SQLTrust_Audit_01.sqlaudit:1024:1"
    )
    assert fp1 == fp2, "Fingerprint is not deterministic!"
    print(f"  fp1: {fp1}")
    print(f"  fp2: {fp2}")
    print("  ✓ Determinism verified: Repeated calculation yields exact identical SHA-256 hash.")


def test_fingerprint_collision_resistance():
    print("\n--- [FINGERPRINT TEST 2] Collision Resistance & Sensitivity ---")
    ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    base_params = {
        "server_name": "localhost\\SQLEXPRESS",
        "event_source": "SQL_AUDIT",
        "source_file": "SQLTrust_Audit_01.sqlaudit",
        "event_timestamp": ts,
        "action": "LGFL",
        "principal_name": "admin",
        "session_id": 52,
        "statement": "SELECT 1",
        "source_event_id": "SQLTrust_Audit_01.sqlaudit:1024:1"
    }
    base_fp = compute_event_fingerprint(**base_params)

    # Perturbations
    variations = [
        ("server_name", "localhost\\SQLEXPRESS_2"),
        ("event_source", "EXTENDED_EVENTS"),
        ("source_file", "SQLTrust_Audit_02.sqlaudit"),
        ("event_timestamp", ts + timedelta(milliseconds=1)),
        ("action", "LGSU"),
        ("principal_name", "admin2"),
        ("session_id", 53),
        ("statement", "SELECT 2"),
        ("source_event_id", "SQLTrust_Audit_01.sqlaudit:1024:2")
    ]

    for field, new_val in variations:
        perturbed = dict(base_params)
        perturbed[field] = new_val
        new_fp = compute_event_fingerprint(**perturbed)
        assert new_fp != base_fp, f"Collision detected when modifying field '{field}'!"
        print(f"  Delta '{field}' -> new fingerprint {new_fp[:16]}... (distinct from base {base_fp[:16]}...)")
    print("  ✓ Collision resistance verified: Every field perturbation yields a distinct hash.")


def test_timezone_invariance():
    print("\n--- [FINGERPRINT TEST 3] Timezone Invariance ---")
    ts_utc = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    ts_offset = ts_utc.astimezone(timezone(timedelta(hours=5, minutes=30)))  # IST (+05:30)

    fp_utc = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="SQLTrust_Audit_01.sqlaudit",
        event_timestamp=ts_utc,
        action="LGFL",
        principal_name="admin",
        session_id=52,
        statement="SELECT 1",
        source_event_id="SQLTrust_Audit_01.sqlaudit:1024:1"
    )
    fp_offset = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="SQLTrust_Audit_01.sqlaudit",
        event_timestamp=ts_offset,
        action="LGFL",
        principal_name="admin",
        session_id=52,
        statement="SELECT 1",
        source_event_id="SQLTrust_Audit_01.sqlaudit:1024:1"
    )
    assert fp_utc == fp_offset, f"Fingerprints differ across timezones! UTC={fp_utc}, Offset={fp_offset}"
    print(f"  UTC fingerprint:    {fp_utc}")
    print(f"  +05:30 fingerprint: {fp_offset}")
    print("  ✓ Timezone invariance verified: normalized to ISO-8601 UTC before hashing.")


def main():
    print("=" * 80)
    print("SQL-TRUST MODULE 2: EVENT FINGERPRINTING & SHA-256 AUDIT")
    print("=" * 80)
    test_fingerprint_determinism()
    test_fingerprint_collision_resistance()
    test_timezone_invariance()
    print("\n" + "=" * 80)
    print("ALL FINGERPRINT AUDIT TESTS PASSED.")
    print("=" * 80)


if __name__ == "__main__":
    main()
