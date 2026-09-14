import uuid
from typing import Dict, Any, List

def scan_gcp_compute(instance_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Scans a GCP Compute Instance configuration for security misconfigurations.
    """
    findings = []
    
    # Example check: instance has a public IP
    has_public_ip = instance_config.get("public_ip") is not None
    
    if has_public_ip:
        finding = {
            "finding_id": str(uuid.uuid4()),
            "title": "GCP Compute Instance Public Exposure",
            "severity": "Medium",
            "resource_id": instance_config.get("asset_id", "unknown"),
            "resource_type": "gcp_compute_instance",
            "cloud_provider": "GCP",
            "description": f"The Compute instance '{instance_config.get('name')}' has a public IP address assigned.",
            "remediation": "Remove the public IP from the instance unless it is acting as a public-facing load balancer or bastion host."
        }
        findings.append(finding)
        
    return findings

def scan_gcp_firewall(firewall_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Scans a GCP Firewall configuration for overly permissive rules.
    """
    findings = []
    
    # Check for 0.0.0.0/0 on port 22
    is_ssh_exposed = False
    source_ranges = firewall_config.get("sourceRanges", [])
    
    if "0.0.0.0/0" in source_ranges:
        for rule in firewall_config.get("allowed", []):
            if rule.get("IPProtocol") == "tcp" and "22" in rule.get("ports", []):
                is_ssh_exposed = True
                break
                
    if is_ssh_exposed:
        finding = {
            "finding_id": str(uuid.uuid4()),
            "title": "GCP Firewall SSH Publicly Accessible",
            "severity": "Critical",
            "resource_id": firewall_config.get("asset_id", "unknown"),
            "resource_type": "gcp_firewall",
            "cloud_provider": "GCP",
            "description": f"The Firewall rule '{firewall_config.get('name')}' allows SSH access from the entire internet (0.0.0.0/0).",
            "remediation": "Restrict SSH access to known IP ranges or use Identity-Aware Proxy (IAP) instead."
        }
        findings.append(finding)

    return findings
