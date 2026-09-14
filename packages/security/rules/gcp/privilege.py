from typing import Dict, Any, List

def detect_privilege_escalation(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Intelligence: Detects known privilege escalation paths in GCP IAM.
    For example, a user who can assume a highly privileged Service Account,
    or a user with self-modifying IAM permissions.
    
    WHY IT EXISTS:
    GCP IAM allows granular permission delegation, but certain combinations 
    create dangerous pathways. If a user can manage service accounts or 
    update IAM policies, they might be able to elevate their own privileges 
    without triggering basic alarms. This rule identifies structural weaknesses 
    in IAM bindings.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    An attacker who compromises an identity with these permissions can escalate 
    to organization admin or project owner. This allows them to bypass other 
    security controls, create backdoors, access restricted data, and persist 
    in the environment undetected.
    """
    findings = []
    
    if asset.get("type") != "IAM_POLICY":
        return findings
        
    bindings = asset.get("configuration", {}).get("bindings", [])
    
    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])
        
        # Detect ability to assume highly privileged roles (e.g. Service Account Token Creator)
        # coupled with Owner/Editor access on the target.
        if "roles/iam.serviceAccountTokenCreator" in role or "roles/iam.serviceAccountUser" in role:
            # We flag this as a critical escalation path
            findings.append({
                "rule_id": "gcp-iam-privilege-escalation",
                "title": "Service Account Privilege Escalation Path",
                "severity": "CRITICAL",
                "category": "ESCALATION_PATH",
                "evidence": {
                    "what": f"Identities can impersonate service accounts via {role}",
                    "where": f"IAM Policy on {asset.get('name', 'Unknown')}",
                    "when": "Current",
                    "why": "Allows identity to escalate privileges to whatever the target service account holds.",
                    "source": "GCP IAM Policy Binding"
                }
            })
            
        # Detect self-modification
        if "roles/resourcemanager.projectIamAdmin" in role or "roles/iam.securityAdmin" in role:
            findings.append({
                "rule_id": "gcp-iam-self-modification",
                "title": "Self-Modifying IAM Permissions",
                "severity": "CRITICAL",
                "category": "ESCALATION_PATH",
                "evidence": {
                    "what": f"Identities hold IAM administration roles ({role})",
                    "where": f"IAM Policy on {asset.get('name', 'Unknown')}",
                    "when": "Current",
                    "why": "Allows identity to grant itself Owner privileges.",
                    "source": "GCP IAM Policy Binding"
                }
            })

    return findings
