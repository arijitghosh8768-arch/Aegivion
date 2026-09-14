import json
from typing import Dict, List, Any
from app.cloud.base import CloudProvider
import google.auth
from google.oauth2 import service_account

class GCPProvider(CloudProvider):
    def __init__(self, credentials_json: str = None, project_id: str = None):
        self.credentials_json = credentials_json
        self.project_id = project_id
        self.credentials = None

    def validate_connection(self) -> bool:
        """Validates connection by loading the service account JSON and fetching the project ID"""
        try:
            if not self.credentials_json:
                return False
                
            info = json.loads(self.credentials_json)
            self.credentials = service_account.Credentials.from_service_account_info(info)
            if not self.project_id:
                self.project_id = info.get("project_id")
            return True
        except Exception:
            return False

    def collect_assets(self) -> List[Dict[str, Any]]:
        """Collects assets (skeleton / returns normalized formats)"""
        # For Day 50, return normalized mock assets or empty list if no connection.
        if not self.validate_connection():
            # Return fallback mock GCP assets for testing pipeline
            return [
                {
                    "asset_id": "gcp-mock-compute-001",
                    "provider": "gcp",
                    "type": "compute_instance",
                    "region": "asia-south1-a",
                    "name": "web-server-prod",
                    "configuration": {
                        "machine_type": "e2-medium",
                        "status": "RUNNING",
                        "public_ip": "34.100.12.34",
                        "private_ip": "10.128.0.2"
                    },
                    "relationships": []
                },
                {
                    "asset_id": "gcp-mock-firewall-001",
                    "provider": "gcp",
                    "type": "firewall",
                    "region": "global",
                    "name": "allow-ssh",
                    "configuration": {
                        "allowed": [
                            {
                                "IPProtocol": "tcp",
                                "ports": ["22"]
                            }
                        ],
                        "sourceRanges": ["0.0.0.0/0"]
                    },
                    "relationships": []
                }
            ]
        
        # Real collection logic using google-api-python-client will be integrated in subsequent days
        return []

    def get_account_info(self) -> Dict[str, Any]:
        """Retrieves generic account information from the provider"""
        try:
            if not self.validate_connection():
                return {
                    "account_id": "unknown-mock",
                    "account_name": "Mock GCP Project",
                    "default_region": "global"
                }
            return {
                "account_id": self.project_id,
                "account_name": f"GCP Project {self.project_id}",
                "default_region": "global" # GCP computes are zonal/regional, project is global
            }
        except Exception:
            return {
                "account_id": "unknown-mock",
                "account_name": "Mock GCP Project (Failed Conn)",
                "default_region": "global"
            }
