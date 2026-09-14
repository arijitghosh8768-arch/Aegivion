from typing import List, Dict, Any

def generate_gcp_attack_paths(assets: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generates GCP specific attack paths based on assets and findings."""
    attack_paths = []
    
    # Simple heuristic: Look for public compute instance with overprivileged service account
    public_instances = []
    for asset in assets:
        if asset.get("type") == "COMPUTE_INSTANCE":
            config = asset.get("configuration", {})
            if config.get("public_ip"):
                public_instances.append(asset)
                
    overprivileged_sas = []
    for asset in assets:
        if asset.get("type") == "IDENTITY":
            config = asset.get("configuration", {})
            for binding in config.get("iam_bindings", []):
                role = binding.get("role", "")
                if role in ["roles/owner", "roles/editor"]:
                    overprivileged_sas.append(asset)
                    break
                    
    for instance in public_instances:
        instance_sa = instance.get("configuration", {}).get("service_account")
        for sa in overprivileged_sas:
            if sa.get("configuration", {}).get("email") == instance_sa:
                attack_paths.append({
                    "id": f"ap-gcp-{instance.get('asset_id')}",
                    "title": "Public Compute Instance with Primitive Role",
                    "description": "An attacker compromising this public compute instance immediately gains project-wide Owner/Editor access via its attached service account.",
                    "severity": "CRITICAL",
                    "steps": [
                        {"asset_id": instance.get("asset_id"), "action": "Initial Access via Public IP"},
                        {"asset_id": sa.get("asset_id"), "action": "Lateral Movement & Privilege Escalation via roles/owner"}
                    ]
                })
                
    return attack_paths
