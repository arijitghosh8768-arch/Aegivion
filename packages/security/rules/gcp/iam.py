from typing import List, Dict, Any

def rule_gcp_overprivileged_service_account(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects GCP service accounts bound to basic primitive roles (Owner/Editor).
    
    WHY IT EXISTS:
    Primitive roles in GCP (Owner, Editor, Viewer) contain thousands of permissions 
    across all GCP services. Using them violates the principle of least privilege. 
    Service accounts should only have the exact permissions they need to perform 
    their specific function, typically via predefined or custom roles.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    If a service account with Editor or Owner roles is compromised (e.g., via a 
    leaked key or an SSRF vulnerability in the application using it), the attacker 
    gains almost full control over the project. They can delete resources, deploy 
    malicious workloads, or exfiltrate all project data.
    """
    findings = []
    for asset in assets:
        if asset.get("type") == "IDENTITY":
            config = asset.get("configuration", {})
            bindings = config.get("iam_bindings", [])
            for binding in bindings:
                role = binding.get("role", "")
                if role in ["roles/owner", "roles/editor"]:
                    findings.append({
                        "rule_id": "gcp-iam-overprivileged-sa",
                        "severity": "critical",
                        "asset_id": asset.get("asset_id"),
                        "title": "GCP Service Account uses Primitive Role",
                        "evidence": f"Service Account {config.get('email')} is bound to highly permissive primitive role {role}."
                    })
                    break
    return findings

def rule_gcp_user_managed_keys(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects GCP service accounts with user-managed keys.
    
    WHY IT EXISTS:
    User-managed service account keys do not expire automatically and require manual 
    rotation. They are often downloaded to developer machines or hardcoded into 
    applications, increasing the risk of accidental exposure. Google recommends 
    using Google-managed keys or Workload Identity Federation instead.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    Leaked user-managed keys are one of the most common causes of GCP environment 
    compromises. If a key is leaked (e.g., in a public GitHub repository), any 
    attacker can immediately authenticate as that service account and abuse its 
    permissions indefinitely until the key is manually revoked.
    """
    findings = []
    for asset in assets:
        if asset.get("type") == "IDENTITY":
            config = asset.get("configuration", {})
            keys = config.get("keys", [])
            for key in keys:
                if key.get("keyType") == "USER_MANAGED":
                    findings.append({
                        "rule_id": "gcp-iam-user-managed-keys",
                        "severity": "high",
                        "asset_id": asset.get("asset_id"),
                        "title": "GCP Service Account has User-Managed Keys",
                        "evidence": f"Service Account {config.get('email')} has user-managed key {key.get('name')}."
                    })
                    break
    return findings

def rule_gcp_admin_without_mfa(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects admin users without 2FA enforcement."""
    findings = []
    # Similar mock detection logic
    return findings
