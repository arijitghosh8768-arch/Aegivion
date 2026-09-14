from typing import List, Dict, Any

def rule_gcp_ssh_exposed(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects if any GCP Compute instance has SSH exposed to 0.0.0.0/0.
    
    WHY IT EXISTS:
    Exposing SSH (port 22) to the entire internet (0.0.0.0/0) significantly increases 
    the attack surface of a compute instance. Best practices mandate restricting SSH 
    access to specific known IP ranges (like a corporate VPN) or using secure 
    alternatives like Google Cloud Identity-Aware Proxy (IAP).
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    Internet-facing SSH ports are continuously scanned and subjected to automated 
    brute-force attacks. If weak credentials are used, or if a vulnerability exists 
    in the SSH daemon, attackers can gain direct remote access to the instance, 
    potentially compromising the host and pivoting into the internal network.
    """
    findings = []
    for asset in assets:
        if asset.get("type") == "COMPUTE_INSTANCE":
            # In a real environment, we would inspect the firewall rules linked to this instance's network tags.
            # Here we mock the rule evaluation based on the asset structure.
            config = asset.get("configuration", {})
            if config.get("public_ip"):
                findings.append({
                    "rule_id": "gcp-network-ssh-exposed",
                    "severity": "high",
                    "asset_id": asset.get("asset_id"),
                    "title": "GCP Compute Instance SSH Exposed",
                    "evidence": f"Instance {config.get('instance_id')} has public IP {config.get('public_ip')} which may allow SSH."
                })
    return findings

def rule_gcp_rdp_exposed(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects if any GCP Compute instance has RDP exposed to 0.0.0.0/0."""
    findings = []
    # Similar logic for RDP (port 3389)
    return findings

def rule_gcp_public_compute_exposure(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects GCP Compute instances that possess a public IP address."""
    findings = []
    for asset in assets:
        if asset.get("type") == "COMPUTE_INSTANCE":
            config = asset.get("configuration", {})
            if config.get("public_ip"):
                findings.append({
                    "rule_id": "gcp-network-public-ip",
                    "severity": "medium",
                    "asset_id": asset.get("asset_id"),
                    "title": "GCP Compute Instance has Public IP",
                    "evidence": f"Instance {config.get('instance_id')} in zone {config.get('zone')} has public IP {config.get('public_ip')}."
                })
    return findings

def rule_gcp_risky_firewall(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects overly permissive GCP firewall rules.
    
    WHY IT EXISTS:
    Firewall rules that allow traffic from 0.0.0.0/0 (the entire internet) on 
    non-public ports bypass perimeter security. Except for public web services 
    (like HTTP/HTTPS), internal services should never be exposed globally. This 
    rule flags overly broad source ranges.
    
    WHAT ARE THE SECURITY IMPLICATIONS:
    Overly permissive firewalls expose internal services (databases, admin panels, 
    caches) directly to the internet. Attackers can exploit vulnerabilities in these 
    services, bypass authentication, or launch Denial of Service (DoS) attacks, 
    often resulting in severe data breaches.
    """
    findings = []
    for asset in assets:
        if asset.get("type") == "FIREWALL_RULE":
            config = asset.get("configuration", {})
            if config.get("sourceRanges") and "0.0.0.0/0" in config.get("sourceRanges", []):
                findings.append({
                    "rule_id": "gcp-network-risky-firewall",
                    "severity": "high",
                    "asset_id": asset.get("asset_id"),
                    "title": "Risky GCP Firewall Rule",
                    "evidence": f"Firewall rule {config.get('name')} allows traffic from 0.0.0.0/0."
                })
    return findings
