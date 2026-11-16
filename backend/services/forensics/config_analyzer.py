"""
SQL-TRUST Configuration Drift Analyzer
Module 3: Database Forensics Engine
Detects tampering and drift in critical database options that impact integrity,
data recovery chains, and instance-level security posture.
"""
import json
from typing import Dict, Any, List
from backend.models.forensics import ForensicBaselineItem


class ConfigurationAnalyzer:
    """
    Compares database-level configuration options between baselines.
    """

    CRITICAL_OPTIONS = {
        "is_trustworthy_on": ("TRUSTWORTHY option altered. Setting TRUSTWORTHY=ON enables database code to escalate privileges to sysadmin.", "CRITICAL"),
        "page_verify_option_desc": ("PAGE_VERIFY option altered. Modifying CHECKSUM weakens silent disk corruption detection.", "CRITICAL"),
        "recovery_model_desc": ("Database RECOVERY_MODEL altered. Switching models disrupts log backup chains and cyber recovery capability.", "HIGH"),
        "is_auto_close_on": ("AUTO_CLOSE toggled. Enabling AUTO_CLOSE clears cache and can facilitate timeline tampering.", "HIGH"),
        "is_auto_shrink_on": ("AUTO_SHRINK toggled. Enabling AUTO_SHRINK introduces severe index fragmentation and file allocation volatility.", "MEDIUM"),
        "is_read_only": ("Database READ_ONLY state altered.", "HIGH"),
        "is_encrypted": ("Transparent Data Encryption (TDE) status modified.", "HIGH"),
    }

    @classmethod
    def compare_configurations(
        cls,
        ref_items: List[ForensicBaselineItem],
        target_items: List[ForensicBaselineItem]
    ) -> List[Dict[str, Any]]:
        findings = []

        ref_opt = next((it for it in ref_items if it.item_type == "DATABASE_OPTION"), None)
        tgt_opt = next((it for it in target_items if it.item_type == "DATABASE_OPTION"), None)

        if not ref_opt or not tgt_opt:
            return findings

        ref_props = json.loads(ref_opt.properties_json)
        tgt_props = json.loads(tgt_opt.properties_json)

        for opt_key, (exp_template, default_sev) in cls.CRITICAL_OPTIONS.items():
            ref_val = ref_props.get(opt_key)
            tgt_val = tgt_props.get(opt_key)

            if ref_val != tgt_val:
                findings.append({
                    "category": "CONFIGURATION",
                    "finding_type": "CONFIG_DRIFT",
                    "severity": default_sev,
                    "entity_name": f"OPTION::{opt_key.upper()}",
                    "schema_name": None,
                    "before_state_json": json.dumps({opt_key: ref_val}),
                    "after_state_json": json.dumps({opt_key: tgt_val}),
                    "explanation": f"{exp_template} (Baseline value: '{ref_val}', Current value: '{tgt_val}').",
                    "confidence_score": 1.0
                })

        return findings
