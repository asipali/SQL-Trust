"""
SQL-TRUST Security Principal & Privilege Analyzer
Module 3: Database Forensics Engine
Analyzes identity drift and privilege mutations across database users, role memberships,
and granular database permissions.
"""
import json
from typing import Dict, Any, List
from backend.models.forensics import ForensicBaselineItem


class PrincipalAnalyzer:
    """
    Compares security principals, role memberships, and permissions between baselines.
    """

    HIGH_PRIV_ROLES = {"db_owner", "db_securityadmin", "db_accessadmin"}
    SENSITIVE_PERMISSIONS = {"CONTROL", "ALTER", "TAKE OWNERSHIP", "IMPERSONATE", "ALTER ANY SCHEMA"}

    @classmethod
    def compare_principals(
        cls,
        ref_items: List[ForensicBaselineItem],
        target_items: List[ForensicBaselineItem]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        findings.extend(cls._compare_users(ref_items, target_items))
        findings.extend(cls._compare_roles(ref_items, target_items))
        findings.extend(cls._compare_permissions(ref_items, target_items))

        return findings

    @classmethod
    def _compare_users(cls, ref_items: List[ForensicBaselineItem], target_items: List[ForensicBaselineItem]) -> List[Dict[str, Any]]:
        findings = []
        ref_users = {it.item_name.lower(): it for it in ref_items if it.item_type == "USER"}
        tgt_users = {it.item_name.lower(): it for it in target_items if it.item_type == "USER"}

        all_usernames = set(ref_users.keys()).union(set(tgt_users.keys()))

        for uname in sorted(all_usernames):
            ru = ref_users.get(uname)
            tu = tgt_users.get(uname)

            if ru is None and tu is not None:
                findings.append({
                    "category": "PRINCIPAL",
                    "finding_type": "USER_ADDED",
                    "severity": "HIGH",
                    "entity_name": tu.item_name,
                    "schema_name": None,
                    "before_state_json": None,
                    "after_state_json": tu.properties_json,
                    "explanation": f"New database principal '{tu.item_name}' was created. Requires authorization review.",
                    "confidence_score": 1.0
                })
            elif ru is not None and tu is None:
                findings.append({
                    "category": "PRINCIPAL",
                    "finding_type": "USER_REMOVED",
                    "severity": "MEDIUM",
                    "entity_name": ru.item_name,
                    "schema_name": None,
                    "before_state_json": ru.properties_json,
                    "after_state_json": None,
                    "explanation": f"Database principal '{ru.item_name}' was dropped from database catalog.",
                    "confidence_score": 1.0
                })

        return findings

    @classmethod
    def _compare_roles(cls, ref_items: List[ForensicBaselineItem], target_items: List[ForensicBaselineItem]) -> List[Dict[str, Any]]:
        findings = []
        ref_roles = {it.item_name.lower(): it for it in ref_items if it.item_type == "ROLE_MEMBER"}
        tgt_roles = {it.item_name.lower(): it for it in target_items if it.item_type == "ROLE_MEMBER"}

        all_pairs = set(ref_roles.keys()).union(set(tgt_roles.keys()))

        for pair in sorted(all_pairs):
            rr = ref_roles.get(pair)
            tr = tgt_roles.get(pair)

            if rr is None and tr is not None:
                props = json.loads(tr.properties_json)
                role_name = props.get("role_name", "")
                member_name = props.get("member_name", "")
                severity = "CRITICAL" if role_name.lower() in cls.HIGH_PRIV_ROLES else "HIGH"

                findings.append({
                    "category": "ROLE_MEMBERSHIP",
                    "finding_type": "ROLE_ESCALATION",
                    "severity": severity,
                    "entity_name": f"{role_name} -> {member_name}",
                    "schema_name": None,
                    "before_state_json": None,
                    "after_state_json": tr.properties_json,
                    "explanation": f"Privilege escalation: User '{member_name}' added to high-privilege role '{role_name}'.",
                    "confidence_score": 1.0
                })
            elif rr is not None and tr is None:
                props = json.loads(rr.properties_json)
                role_name = props.get("role_name", "")
                member_name = props.get("member_name", "")

                findings.append({
                    "category": "ROLE_MEMBERSHIP",
                    "finding_type": "ROLE_REVOKED",
                    "severity": "LOW",
                    "entity_name": f"{role_name} -> {member_name}",
                    "schema_name": None,
                    "before_state_json": rr.properties_json,
                    "after_state_json": None,
                    "explanation": f"Role membership removed: User '{member_name}' removed from role '{role_name}'.",
                    "confidence_score": 1.0
                })

        return findings

    @classmethod
    def _compare_permissions(cls, ref_items: List[ForensicBaselineItem], target_items: List[ForensicBaselineItem]) -> List[Dict[str, Any]]:
        findings = []
        ref_perms = {it.item_name.lower(): it for it in ref_items if it.item_type == "PERMISSION"}
        tgt_perms = {it.item_name.lower(): it for it in target_items if it.item_type == "PERMISSION"}

        all_perms = set(ref_perms.keys()).union(set(tgt_perms.keys()))

        for pkey in sorted(all_perms):
            rp = ref_perms.get(pkey)
            tp = tgt_perms.get(pkey)

            if rp is None and tp is not None:
                props = json.loads(tp.properties_json)
                perm_name = props.get("permission_name", "")
                state_desc = props.get("state_desc", "")
                grantee = props.get("grantee_name", "")
                obj_name = props.get("object_name") or "DATABASE"

                is_sensitive = perm_name.upper() in cls.SENSITIVE_PERMISSIONS
                severity = "CRITICAL" if (is_sensitive and state_desc == "GRANT") else ("HIGH" if is_sensitive else "MEDIUM")

                findings.append({
                    "category": "PERMISSION",
                    "finding_type": "PERMISSION_GRANTED",
                    "severity": severity,
                    "entity_name": f"{state_desc} {perm_name} ON {obj_name} TO {grantee}",
                    "schema_name": props.get("object_schema"),
                    "before_state_json": None,
                    "after_state_json": tp.properties_json,
                    "explanation": f"Explicit permission {state_desc} {perm_name} on {obj_name} awarded to '{grantee}'.",
                    "confidence_score": 0.95
                })
            elif rp is not None and tp is None:
                props = json.loads(rp.properties_json)
                findings.append({
                    "category": "PERMISSION",
                    "finding_type": "PERMISSION_REVOKED",
                    "severity": "LOW",
                    "entity_name": rp.item_name,
                    "schema_name": props.get("object_schema"),
                    "before_state_json": rp.properties_json,
                    "after_state_json": None,
                    "explanation": f"Permission grant removed: {rp.item_name}.",
                    "confidence_score": 0.95
                })

        return findings
