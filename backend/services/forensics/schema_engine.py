"""
SQL-TRUST Schema Forensics Engine
Module 3: Database Forensics Engine
Performs granular, deterministic schema comparisons between database baselines.
Identifies created, dropped, and mutated tables, columns, views, procedures, functions, and triggers.
Preserves before-and-after metadata representations and flags unobservable encrypted objects.
"""
import json
from typing import Dict, Any, List, Optional
from backend.models.forensics import ForensicBaselineItem


class SchemaForensicsEngine:
    """
    Compares baseline items across schema object categories.
    """

    SCHEMA_TYPES = {"TABLE", "VIEW", "PROCEDURE", "FUNCTION", "TRIGGER"}

    @classmethod
    def compare_schema_items(
        cls,
        ref_items: List[ForensicBaselineItem],
        target_items: List[ForensicBaselineItem]
    ) -> List[Dict[str, Any]]:
        """
        Compares schema objects between reference baseline and target baseline.
        Returns a list of finding dictionaries ready to be recorded as ForensicFindings.
        """
        # Index items by (item_type, schema_name, item_name)
        ref_map: Dict[tuple, ForensicBaselineItem] = {
            (it.item_type, (it.schema_name or "").lower(), it.item_name.lower()): it
            for it in ref_items if it.item_type in cls.SCHEMA_TYPES
        }
        target_map: Dict[tuple, ForensicBaselineItem] = {
            (it.item_type, (it.schema_name or "").lower(), it.item_name.lower()): it
            for it in target_items if it.item_type in cls.SCHEMA_TYPES
        }

        findings: List[Dict[str, Any]] = []

        all_keys = set(ref_map.keys()).union(set(target_map.keys()))

        for key in sorted(all_keys):
            item_type, schema_lower, name_lower = key
            ref_it = ref_map.get(key)
            tgt_it = target_map.get(key)

            # 1. Newly created object
            if ref_it is None and tgt_it is not None:
                severity = "HIGH" if item_type in ("TRIGGER", "PROCEDURE") else "MEDIUM"
                findings.append({
                    "category": "SCHEMA",
                    "finding_type": "OBJECT_CREATED",
                    "severity": severity,
                    "entity_name": tgt_it.item_name,
                    "schema_name": tgt_it.schema_name,
                    "before_state_json": None,
                    "after_state_json": json.dumps({
                        "item_type": tgt_it.item_type,
                        "definition_hash": tgt_it.definition_hash,
                        "raw_definition": tgt_it.raw_definition,
                        "properties": json.loads(tgt_it.properties_json)
                    }),
                    "explanation": f"Newly created {item_type.lower()} '{tgt_it.schema_name or 'dbo'}.{tgt_it.item_name}' detected. Did not exist in reference baseline.",
                    "confidence_score": 1.0
                })
                if tgt_it.is_encrypted:
                    findings.append({
                        "category": "SCHEMA",
                        "finding_type": "UNOBSERVABLE_ENCRYPTED",
                        "severity": "HIGH",
                        "entity_name": tgt_it.item_name,
                        "schema_name": tgt_it.schema_name,
                        "before_state_json": None,
                        "after_state_json": tgt_it.properties_json,
                        "explanation": f"Newly created object '{tgt_it.item_name}' is encrypted WITH ENCRYPTION; code definition is unobservable via catalog inspection.",
                        "confidence_score": 0.5
                    })
                continue

            # 2. Dropped object
            if ref_it is not None and tgt_it is None:
                findings.append({
                    "category": "SCHEMA",
                    "finding_type": "OBJECT_DROPPED",
                    "severity": "HIGH",
                    "entity_name": ref_it.item_name,
                    "schema_name": ref_it.schema_name,
                    "before_state_json": json.dumps({
                        "item_type": ref_it.item_type,
                        "definition_hash": ref_it.definition_hash,
                        "raw_definition": ref_it.raw_definition,
                        "properties": json.loads(ref_it.properties_json)
                    }),
                    "after_state_json": None,
                    "explanation": f"Destructive deletion detected: {item_type.lower()} '{ref_it.schema_name or 'dbo'}.{ref_it.item_name}' was dropped from database schema.",
                    "confidence_score": 1.0
                })
                continue

            # 3. Object present in both - check for definition/structural mutation
            if ref_it is not None and tgt_it is not None:
                # Check for encryption change / unobservable definition
                if tgt_it.is_encrypted:
                    findings.append({
                        "category": "SCHEMA",
                        "finding_type": "UNOBSERVABLE_ENCRYPTED",
                        "severity": "HIGH",
                        "entity_name": tgt_it.item_name,
                        "schema_name": tgt_it.schema_name,
                        "before_state_json": ref_it.properties_json,
                        "after_state_json": tgt_it.properties_json,
                        "explanation": f"Object '{tgt_it.item_name}' is encrypted WITH ENCRYPTION; code definition is unobservable via catalog inspection.",
                        "confidence_score": 0.5
                    })

                if ref_it.definition_hash != tgt_it.definition_hash:
                    explanation_lines = [f"Schema modification detected for {item_type.lower()} '{tgt_it.schema_name or 'dbo'}.{tgt_it.item_name}'."]
                    
                    # Detailed column-level diff for tables
                    if item_type == "TABLE":
                        ref_props = json.loads(ref_it.properties_json)
                        tgt_props = json.loads(tgt_it.properties_json)
                        col_diffs = cls._diff_table_columns(ref_props.get("columns", []), tgt_props.get("columns", []))
                        if col_diffs:
                            explanation_lines.extend(col_diffs)

                    findings.append({
                        "category": "SCHEMA",
                        "finding_type": "OBJECT_MODIFIED",
                        "severity": "HIGH",
                        "entity_name": tgt_it.item_name,
                        "schema_name": tgt_it.schema_name,
                        "before_state_json": json.dumps({
                            "definition_hash": ref_it.definition_hash,
                            "raw_definition": ref_it.raw_definition,
                            "properties": json.loads(ref_it.properties_json)
                        }),
                        "after_state_json": json.dumps({
                            "definition_hash": tgt_it.definition_hash,
                            "raw_definition": tgt_it.raw_definition,
                            "properties": json.loads(tgt_it.properties_json)
                        }),
                        "explanation": " ".join(explanation_lines),
                        "confidence_score": 0.95
                    })

        return findings

    @classmethod
    def _diff_table_columns(cls, ref_cols: List[Dict[str, Any]], tgt_cols: List[Dict[str, Any]]) -> List[str]:
        ref_by_name = {c["column_name"].lower(): c for c in ref_cols}
        tgt_by_name = {c["column_name"].lower(): c for c in tgt_cols}
        diffs = []

        # Added columns
        for cname, c in tgt_by_name.items():
            if cname not in ref_by_name:
                diffs.append(f"Column '{c['column_name']}' ({c['type_name']}) was added.")

        # Dropped columns
        for cname, c in ref_by_name.items():
            if cname not in tgt_by_name:
                diffs.append(f"Column '{c['column_name']}' was removed.")

        # Modified columns
        for cname, rc in ref_by_name.items():
            if cname in tgt_by_name:
                tc = tgt_by_name[cname]
                if rc["type_name"] != tc["type_name"] or rc["max_length"] != tc["max_length"]:
                    diffs.append(f"Column '{rc['column_name']}' type altered from {rc['type_name']}({rc['max_length']}) to {tc['type_name']}({tc['max_length']}).")
                if rc["is_nullable"] != tc["is_nullable"]:
                    diffs.append(f"Column '{rc['column_name']}' nullability changed to {'NULL' if tc['is_nullable'] else 'NOT NULL'}.")

        return diffs
