from typing import List, Dict, Any

def get_playbooks() -> List[Dict[str, Any]]:
    """Returns the static playbook mapping."""
    return [
        {
            "id": "pb-aws-001",
            "name": "Remediate Public SSH",
            "trigger_rule_id": "aws-net-ssh-exposed",
            "action_type": "restrict_security_group_rule",
        },
        {
            "id": "pb-aws-002",
            "name": "Block Public S3 Access",
            "trigger_rule_id": "aws-s3-public",
            "action_type": "block_s3_public_access",
        },
        {
            "id": "pb-gcp-001",
            "name": "Disable User-Managed Service Account Key",
            "trigger_rule_id": "gcp-iam-user-managed-keys",
            "action_type": "disable_gcp_service_account_key",
        },
        {
            "id": "pb-gcp-002",
            "name": "Remove Public IP from Compute Engine",
            "trigger_rule_id": "gcp-public-compute-exposure",
            "action_type": "remove_gcp_public_ip",
        }
    ]

def propose_actions(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generates proposed response actions based on playbooks."""
    playbooks = get_playbooks()
    proposed = []
    
    for finding in findings:
        for pb in playbooks:
            if finding.get("rule_id") == pb["trigger_rule_id"]:
                proposed.append({
                    "action_id": f"act-{finding.get('id', 'temp')}",
                    "finding_id": finding.get("id"),
                    "playbook_id": pb["id"],
                    "action_type": pb["action_type"],
                    "status": "PROPOSED",
                    "asset_id": finding.get("asset_id")
                })
                break
                
    return proposed
