from typing import Dict, List, Any

def map_gcp_findings_to_framework(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Maps GCP findings to the CIS GCP Foundation Benchmark framework.
    """
    # Mapping of our internal rule IDs to CIS GCP controls
    # 1.4: Ensure that Service Account has no administrative privileges (or User Managed keys)
    # 6.1.3: Ensure that Cloud SQL database instances do not have public IPs (similarly for Compute)
    mapping = {
        "gcp-iam-user-managed-keys": {
            "framework": "CIS GCP Benchmark v2.0.0",
            "control": "1.4",
            "title": "Ensure that Service Account has no administrative privileges"
        },
        "gcp-public-compute-exposure": {
            "framework": "CIS GCP Benchmark v2.0.0",
            "control": "4.9",
            "title": "Ensure that Compute instances do not have public IP addresses"
        }
    }
    
    compliance_report = {
        "framework": "CIS GCP Benchmark v2.0.0",
        "passed_controls": 0,
        "failed_controls": 0,
        "violations": []
    }
    
    failed_controls_set = set()
    
    for finding in findings:
        rule_id = finding.get("rule_id")
        if rule_id in mapping:
            control_info = mapping[rule_id]
            failed_controls_set.add(control_info["control"])
            compliance_report["violations"].append({
                "finding_id": finding.get("id"),
                "control": control_info["control"],
                "control_title": control_info["title"],
                "asset": finding.get("asset_id")
            })
            
    compliance_report["failed_controls"] = len(failed_controls_set)
    # Assume there are 50 controls in CIS GCP for a mock score
    compliance_report["passed_controls"] = 50 - len(failed_controls_set)
    
    return compliance_report
