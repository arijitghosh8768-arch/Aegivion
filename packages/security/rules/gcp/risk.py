from typing import List, Dict, Any

def calculate_gcp_risk_score(assets: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates a multi-factor risk score specifically tailored for GCP resources."""
    
    # Base risk starts at 0
    total_risk = 0
    critical_factors = []
    
    # Analyze assets
    for asset in assets:
        if asset.get("type") == "COMPUTE_INSTANCE":
            config = asset.get("configuration", {})
            # If public IP is present, bump risk
            if config.get("public_ip"):
                total_risk += 15
                critical_factors.append("Public IP on Compute Instance")
                
        if asset.get("type") == "IDENTITY":
            config = asset.get("configuration", {})
            for binding in config.get("iam_bindings", []):
                role = binding.get("role", "")
                if role in ["roles/owner", "roles/editor"]:
                    total_risk += 30
                    critical_factors.append("Primitive Role assignment detected")
                    
    # Analyze findings
    for finding in findings:
        severity = finding.get("severity", "").lower()
        if severity == "critical":
            total_risk += 40
        elif severity == "high":
            total_risk += 20
        elif severity == "medium":
            total_risk += 10
            
    # Cap total risk at 100
    normalized_risk = min(100, total_risk)
    
    return {
        "score": normalized_risk,
        "level": "Critical" if normalized_risk >= 75 else "High" if normalized_risk >= 50 else "Medium" if normalized_risk >= 25 else "Low",
        "factors": list(set(critical_factors))
    }

def analyze_gcp_risk(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for asset in assets:
        if asset.get("type") == "COMPUTE_INSTANCE" and asset.get("configuration", {}).get("public_ip"):
            findings.append({
                "rule_id": "gcp-public-compute-exposure",
                "evidence": {
                    "what": "Compute instance has a public IP",
                    "where": f"Asset {asset.get('asset_id')}",
                    "when": "now",
                    "why": "Public IP exposes instance to internet",
                    "source": "gcp-config"
                }
            })
    return findings
