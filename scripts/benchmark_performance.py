"""
SQL-TRUST Module 2 Hardening Review: Performance & Operational Benchmark
========================================================================
Measures:
1. Ingestion throughput and processing latency per batch.
2. Rule engine evaluation latency.
3. Database size and average event footprint.
4. FastAPI endpoint latencies (Alerts, Events, Health, Rules).
5. SQL Server telemetry resource footprint.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import uuid
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.models.security import SecuritySource, SecurityEvent, SecurityAlert
from backend.services.security.audit_collector import AuditCollector
from backend.services.security.rule_engine import RuleEngine
from backend.services.security.normalizer import compute_event_fingerprint


def benchmark_ingestion_throughput(db: Session, source: SecuritySource):
    print("\n--- [BENCHMARK 1] Ingestion & Normalization Throughput ---")
    batch_size = 100
    events_data = []
    now = datetime.now(timezone.utc)
    
    for i in range(batch_size):
        seq = f"bench_{uuid.uuid4().hex[:8]}"
        fp = compute_event_fingerprint(
            server_name="localhost\\SQLEXPRESS",
            event_source="SQL_AUDIT",
            source_file="bench.sqlaudit",
            event_timestamp=now,
            action="LGFL",
            principal_name="bench_user",
            session_id=100 + i,
            statement=f"SELECT {i}",
            source_event_id=f"bench.sqlaudit:{i}:{seq}"
        )
        ev = SecurityEvent(
            source_id=source.id,
            event_source="SQL_AUDIT",
            source_file="bench.sqlaudit",
            source_event_id=f"bench.sqlaudit:{i}:{seq}",
            event_fingerprint=fp,
            event_timestamp=now,
            collection_timestamp=now,
            server_name="localhost\\SQLEXPRESS",
            database_name="SQLTrust_Lab",
            principal_name="bench_user",
            session_id=100 + i,
            client_ip="127.0.0.1",
            client_app="BenchmarkSuite",
            event_type="LOGIN_FAILED",
            action="LGFL",
            success=False,
            severity="MEDIUM",
            raw_payload=f"SELECT {i}",
            integrity_status="VERIFIED"
        )
        events_data.append(ev)

    start_t = time.perf_counter()
    db.add_all(events_data)
    db.commit()
    insert_duration = time.perf_counter() - start_t
    throughput = batch_size / insert_duration
    print(f"  Ingested {batch_size} events in {insert_duration * 1000:.2f} ms")
    print(f"  Database Ingestion Throughput: {throughput:.2f} events/sec ({insert_duration * 1000 / batch_size:.2f} ms/event)")

    # Rule evaluation benchmark
    rule_engine = RuleEngine(db)
    start_rule = time.perf_counter()
    alerts = rule_engine.evaluate_events(events_data, source.id)
    rule_duration = time.perf_counter() - start_rule
    print(f"  Evaluated {batch_size} events across 10 rules in {rule_duration * 1000:.2f} ms ({batch_size / rule_duration:.2f} events/sec)")
    print(f"  Alerts generated/updated: {len(alerts)}")

    return {"throughput_events_per_sec": throughput, "rule_eval_duration_ms": rule_duration * 1000}


def benchmark_database_footprint(db: Session):
    print("\n--- [BENCHMARK 2] Control Database Storage Footprint ---")
    event_count = db.query(SecurityEvent).count()
    alert_count = db.query(SecurityAlert).count()
    
    # Query table size in SQL Server
    size_query = text("""
        SELECT 
            t.NAME AS table_name,
            p.rows AS row_counts,
            (SUM(a.total_pages) * 8) AS total_space_kb,
            (SUM(a.used_pages) * 8) AS used_space_kb
        FROM sys.tables t
        INNER JOIN sys.indexes i ON t.OBJECT_ID = i.object_id
        INNER JOIN sys.partitions p ON i.object_id = p.OBJECT_ID AND i.index_id = p.index_id
        INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
        WHERE t.NAME IN ('security_events', 'security_alerts', 'alert_event_associations', 'evidence_archives')
        GROUP BY t.Name, p.Rows;
    """)
    rows = db.execute(size_query).mappings().all()
    total_kb = 0
    for r in rows:
        print(f"  Table: {r['table_name']:<25} | Rows: {r['row_counts']:<6} | Used: {r['used_space_kb']:<6} KB | Total: {r['total_space_kb']:<6} KB")
        total_kb += r['total_space_kb']
    
    print(f"  Total Security Telemetry Footprint: {total_kb} KB ({total_kb / 1024:.2f} MB)")
    if event_count > 0:
        print(f"  Average Footprint per Event (incl. indexes): {total_kb * 1024 / event_count:.2f} bytes")


def benchmark_api_endpoints():
    print("\n--- [BENCHMARK 3] FastAPI Endpoint Response Latencies ---")
    client = TestClient(app)
    endpoints = [
        ("GET /api/v1/security/health", "/api/v1/security/health"),
        ("GET /api/v1/security/rules", "/api/v1/security/rules"),
        ("GET /api/v1/security/sources", "/api/v1/security/sources"),
        ("GET /api/v1/security/alerts", "/api/v1/security/alerts?limit=50"),
        ("GET /api/v1/security/events", "/api/v1/security/events?limit=50"),
    ]

    for label, ep in endpoints:
        latencies = []
        # Warmup
        client.get(ep)
        # 5 measured requests
        for _ in range(5):
            t0 = time.perf_counter()
            resp = client.get(ep)
            dt = (time.perf_counter() - t0) * 1000
            assert resp.status_code == 200, f"Endpoint {ep} returned {resp.status_code}"
            latencies.append(dt)
        avg_lat = sum(latencies) / len(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        print(f"  {label:<35} -> Avg: {avg_lat:6.2f} ms | Min: {min_lat:6.2f} ms | Max: {max_lat:6.2f} ms")


def main():
    print("=" * 80)
    print("SQL-TRUST MODULE 2: PERFORMANCE & OPERATIONAL BENCHMARK")
    print("=" * 80)
    db = SessionLocal()
    try:
        source = db.query(SecuritySource).first()
        benchmark_ingestion_throughput(db, source)
        benchmark_database_footprint(db)
        benchmark_api_endpoints()
        print("\n" + "=" * 80)
        print("PERFORMANCE BENCHMARK COMPLETE.")
        print("=" * 80)
    finally:
        db.close()


if __name__ == "__main__":
    main()
