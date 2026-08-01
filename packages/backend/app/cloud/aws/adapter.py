from typing import Dict, List, Any
from app.cloud.base import CloudProvider
from app.cloud.aws.client import get_aws_session

class AWSProvider(CloudProvider):
    def __init__(self, access_key: str = None, secret_key: str = None, default_region: str = "ap-south-1"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.default_region = default_region
        self.session = None

    def validate_connection(self) -> bool:
        """Validates connection by querying STS identity"""
        try:
            self.session = get_aws_session(self.access_key, self.secret_key, self.default_region)
            if not self.session:
                return False
            sts = self.session.client("sts")
            sts.get_caller_identity()
            return True
        except Exception:
            return False

    def collect_assets(self) -> List[Dict[str, Any]]:
        """Collects assets (skeleton / returns normalized formats)"""
        # For Day 8, we return normalized mock assets or empty list if no connection.
        # But we'll provide standard mock data conforming to the contract when session is active or for fallback testing.
        if not self.validate_connection():
            # Return fallback mock AWS assets for Day 8 testing pipeline
            return [
                {
                    "asset_id": "i-mock-ec2-001",
                    "provider": "aws",
                    "type": "ec2",
                    "region": self.default_region,
                    "name": "web-server-prod",
                    "configuration": {
                        "instance_type": "t3.medium",
                        "state": "running",
                        "public_ip": "54.210.12.34"
                    },
                    "relationships": []
                },
                {
                    "asset_id": "sg-mock-sg-001",
                    "provider": "aws",
                    "type": "security_group",
                    "region": self.default_region,
                    "name": "public-ssh-sg",
                    "configuration": {
                        "ingress": [
                            {
                                "protocol": "tcp",
                                "from_port": 22,
                                "to_port": 22,
                                "cidr": "0.0.0.0/0"
                            }
                        ]
                    },
                    "relationships": []
                }
            ]
        
        # Real collection will be integrated on Day 9. Let's return empty / skeleton for now.
        return []

    def get_account_info(self) -> Dict[str, Any]:
        """Retrieves caller identity account information"""
        try:
            self.session = get_aws_session(self.access_key, self.secret_key, self.default_region)
            if not self.session:
                return {
                    "account_id": "unknown-mock",
                    "account_name": "Mock AWS Account",
                    "default_region": self.default_region
                }
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "account_id": identity.get("Account"),
                "account_name": f"AWS Account {identity.get('Account')}",
                "default_region": self.default_region
            }
        except Exception:
            return {
                "account_id": "unknown-mock",
                "account_name": "Mock AWS Account (Failed Conn)",
                "default_region": self.default_region
            }
        
# For future provider implementations:
# class AzureProvider(CloudProvider): ...
# class GCPProvider(CloudProvider): ...
