"""MITRE ATT&CK mapping - **Part 3 (ARDE)**.

Pure *metadata*: maps rule ids and API families to ATT&CK technique ids.
Detection logic never imports this module - the detector must work correctly
with an empty or outdated mapping, and mapping updates must not require code
changes to the detection path. ``finding.finalize_finding`` attaches mappings
at assembly time; absence of a mapping simply yields an empty list.
"""

from __future__ import annotations

from typing import Optional

#: Cloud-relevant techniques referenced by the current rule catalogue.
ATTACK_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion, Initial Access, Persistence, Privilege Escalation",
    },
    "T1078.004 sub": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
    },
    "T1098.001": {
        "name": "Account Manipulation: Additional Cloud Credentials",
        "tactic": "Persistence",
    },
    "T1098.003": {
        "name": "Account Manipulation: Additional Cloud Roles",
        "tactic": "Persistence",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Defense Evasion, Privilege Escalation",
    },
    "T1550.001": {
        "name": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Defense Evasion",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic": "Discovery",
    },
    "T1069.003": {
        "name": "Permission Groups Discovery: Cloud Groups",
        "tactic": "Discovery",
    },
    "T1552.005": {
        "name": "Unsecured Credentials: Cloud Instance Metadata API",
        "tactic": "Credential Access",
    },
    "T1562.008": {
        "name": "Impair Defenses: Disable Cloud Logs",
        "tactic": "Defense Evasion",
    },
}

#: rule_id -> technique ids. Kept in one table so updates are auditable.
RULE_ATTACK_MAPPING: dict[str, tuple[str, ...]] = {
    "R001": ("T1078.004",),            # new country: valid cloud account abuse
    "R002": ("T1078.004",),
    "R003": ("T1078.004",),
    "R004": ("T1078.004",),
    "R005": ("T1078.004",),
    "R006": ("T1078.004 sub",),
    "R007": ("T1078.004",),
    "R008": ("T1078.004",),
    "R009": ("T1078.004",),
    "R010": ("T1098", "T1098.003", "T1134"),
    "R011": ("T1098.003", "T1134"),
    "R012": ("T1098.001",),            # access-key activity
    "R013": ("T1078.004",),            # MFA anomaly
    "R014": ("T1078.004",),
}

#: API family -> technique ids (used when no rule fired).
FAMILY_ATTACK_MAPPING: dict[str, tuple[str, ...]] = {
    "IAM_PRIVILEGE_MUTATION": ("T1098", "T1098.003"),
    "CREDENTIAL_MANAGEMENT": ("T1098.001",),
    "CLOUDTRAIL_TAMPER": ("T1562.008",),
    "GUARDDUTY_TAMPER": ("T1562.008",),
    "CONFIG_TAMPER": ("T1562.008",),
    "S3_DATA_READ": ("T1530",),
    "STS_SESSION": ("T1550.001",),
}


def map_signals_to_attack(
    signal_rule_ids: list[str],
    api_family: Optional[str] = None,
) -> list[dict[str, str]]:
    """Map fired rule ids (and optionally the API family) to ATT&CK entries.

    Returns a list of ``{"technique_id", "name", "tactic", "source"}`` dicts,
    deduplicated by technique id. Empty input yields an empty list - the
    detector works fine without any mapping.
    """
    techniques: dict[str, dict[str, str]] = {}
    for rule_id in signal_rule_ids:
        for technique_id in RULE_ATTACK_MAPPING.get(rule_id, ()):
            meta = ATTACK_TECHNIQUES.get(technique_id)
            if meta:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "name": meta["name"],
                    "tactic": meta["tactic"],
                    "source": f"rule:{rule_id}",
                }
    if not techniques and api_family:
        # Fall back to family-level mapping when no rule fired.
        for technique_id in FAMILY_ATTACK_MAPPING.get(api_family, ()):
            meta = ATTACK_TECHNIQUES.get(technique_id)
            if meta:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "name": meta["name"],
                    "tactic": meta["tactic"],
                    "source": f"family:{api_family}",
                }
    return list(techniques.values())


__all__ = ["ATTACK_TECHNIQUES", "FAMILY_ATTACK_MAPPING", "RULE_ATTACK_MAPPING", "map_signals_to_attack"]
