"""
Unit tests for SQL-TRUST Module 3: Database Forensics Engine.
Validates deterministic hashing, column-level delta diffing, role escalation detection,
and configuration drift parsing.
"""
import json
import pytest
from backend.services.forensics.baseline_collector import compute_sha256
from backend.services.forensics.schema_engine import SchemaForensicsEngine
from backend.services.forensics.principal_analyzer import PrincipalAnalyzer
from backend.services.forensics.config_analyzer import ConfigurationAnalyzer
from backend.models.forensics import ForensicBaselineItem


def make_mock_item(item_type: str, item_name: str, schema_name: str = "dbo", def_hash: str = "abc123hash", properties: dict = None, is_encrypted: bool = False) -> ForensicBaselineItem:
    props_str = json.dumps(properties or {})
    return ForensicBaselineItem(
        id="item-test-uuid",
        baseline_id="baseline-test-uuid",
        item_type=item_type,
        schema_name=schema_name,
        item_name=item_name,
        sql_object_id=1001,
        definition_hash=def_hash,
        raw_definition=None,
        properties_json=props_str,
        is_encrypted=is_encrypted
    )


def test_compute_sha256_deterministic():
    h1 = compute_sha256("CREATE TABLE Test (id INT);")
    h2 = compute_sha256("CREATE TABLE Test (id INT);")
    assert h1 == h2
    assert len(h1) == 64


def test_schema_diff_created_dropped_modified():
    # Ref baseline: has TableA and TableB
    ref_items = [
        make_mock_item("TABLE", "TableA", properties={"columns": [{"column_name": "id", "type_name": "int", "max_length": 4, "is_nullable": False}]}),
        make_mock_item("TABLE", "TableB", properties={"columns": [{"column_name": "val", "type_name": "varchar", "max_length": 50, "is_nullable": True}]}),
    ]

    # Target baseline: TableA modified (new column), TableB dropped, TableC created
    target_items = [
        make_mock_item("TABLE", "TableA", def_hash="diff_hash", properties={"columns": [
            {"column_name": "id", "type_name": "int", "max_length": 4, "is_nullable": False},
            {"column_name": "created_at", "type_name": "datetime", "max_length": 8, "is_nullable": True}
        ]}),
        make_mock_item("TABLE", "TableC", def_hash="tablec_hash", properties={"columns": [{"column_name": "id", "type_name": "int"}]}),
    ]

    findings = SchemaForensicsEngine.compare_schema_items(ref_items, target_items)
    assert len(findings) == 3

    finding_types = {f["finding_type"] for f in findings}
    assert "OBJECT_CREATED" in finding_types
    assert "OBJECT_DROPPED" in finding_types
    assert "OBJECT_MODIFIED" in finding_types

    mod_finding = next(f for f in findings if f["finding_type"] == "OBJECT_MODIFIED")
    assert "created_at" in mod_finding["explanation"]


def test_unobservable_encrypted_object_flagged():
    ref_items = [
        make_mock_item("PROCEDURE", "usp_Secret", def_hash="secret_hash", is_encrypted=False)
    ]
    target_items = [
        make_mock_item("PROCEDURE", "usp_Secret", def_hash="ENCRYPTED_UNOBSERVABLE", is_encrypted=True)
    ]
    findings = SchemaForensicsEngine.compare_schema_items(ref_items, target_items)
    enc_finding = next((f for f in findings if f["finding_type"] == "UNOBSERVABLE_ENCRYPTED"), None)
    assert enc_finding is not None
    assert enc_finding["confidence_score"] == 0.5


def test_principal_role_escalation_detection():
    ref_items = [
        make_mock_item("ROLE_MEMBER", "db_datareader::app_reader", properties={"role_name": "db_datareader", "member_name": "app_reader"})
    ]
    target_items = [
        make_mock_item("ROLE_MEMBER", "db_datareader::app_reader", properties={"role_name": "db_datareader", "member_name": "app_reader"}),
        make_mock_item("ROLE_MEMBER", "db_owner::rogue_user", properties={"role_name": "db_owner", "member_name": "rogue_user"})
    ]
    findings = PrincipalAnalyzer.compare_principals(ref_items, target_items)
    escalations = [f for f in findings if f["finding_type"] == "ROLE_ESCALATION"]
    assert len(escalations) == 1
    assert escalations[0]["severity"] == "CRITICAL"
    assert "db_owner" in escalations[0]["explanation"]


def test_configuration_drift_detection():
    ref_items = [
        make_mock_item("DATABASE_OPTION", "DATABASE_CONFIGURATION", properties={
            "page_verify_option_desc": "CHECKSUM",
            "is_trustworthy_on": False,
            "is_auto_close_on": False
        })
    ]
    target_items = [
        make_mock_item("DATABASE_OPTION", "DATABASE_CONFIGURATION", properties={
            "page_verify_option_desc": "NONE",
            "is_trustworthy_on": True,
            "is_auto_close_on": True
        })
    ]
    findings = ConfigurationAnalyzer.compare_configurations(ref_items, target_items)
    assert len(findings) == 3

    severities = {f["entity_name"]: f["severity"] for f in findings}
    assert severities["OPTION::PAGE_VERIFY_OPTION_DESC"] == "CRITICAL"
    assert severities["OPTION::IS_TRUSTWORTHY_ON"] == "CRITICAL"
    assert severities["OPTION::IS_AUTO_CLOSE_ON"] == "HIGH"
