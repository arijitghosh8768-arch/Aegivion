import json
from typing import Dict, Any, List

def verify_asset_schema(asset: Dict[str, Any]) -> bool:
    """Verifies that an asset adheres to the unified schema."""
    required_keys = {"asset_id", "name", "type", "provider", "configuration"}
    if not required_keys.issubset(asset.keys()):
        print(f"ERROR: Missing keys in asset {asset.get('asset_id')}. Found: {list(asset.keys())}")
        return False
        
    if asset["provider"] not in ["aws", "azure", "gcp"]:
        print(f"ERROR: Invalid provider '{asset['provider']}' in asset {asset.get('asset_id')}")
        return False
        
    return True

def run_verification():
    mock_assets = [
        # AWS Asset
        {
            "asset_id": "i-0abcd1234efgh5678",
            "name": "prod-web-server",
            "type": "COMPUTE_INSTANCE",
            "provider": "aws",
            "configuration": {"public_ip": "1.2.3.4"}
        },
        # Azure Asset
        {
            "asset_id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "COMPUTE_INSTANCE",
            "provider": "azure",
            "configuration": {"public_ip": "5.6.7.8"}
        },
        # GCP Asset
        {
            "asset_id": "projects/my-project/zones/us-central1-a/instances/instance-1",
            "name": "instance-1",
            "type": "COMPUTE_INSTANCE",
            "provider": "gcp",
            "configuration": {"public_ip": "9.10.11.12"}
        }
    ]
    
    print(f"Verifying {len(mock_assets)} multi-cloud assets...")
    
    all_passed = True
    for asset in mock_assets:
        if not verify_asset_schema(asset):
            all_passed = False
            
    if all_passed:
        print("SUCCESS: All assets from AWS, Azure, and GCP perfectly match the unified taxonomy schema.")
    else:
        print("FAILURE: Schema violations detected.")

if __name__ == "__main__":
    run_verification()
