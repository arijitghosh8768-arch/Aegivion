from typing import Dict, List, Any
import uuid

def collect_compute_engine(credentials: Any, project_id: str) -> List[Dict[str, Any]]:
    """
    Collects Compute Engine instances from GCP and normalizes them.
    In this implementation, it uses the provided credentials to connect via google-api-python-client.
    Since this is Day 51 and we are building the foundation without breaking existing logic,
    we stub out the actual API call and return the normalized schema for downstream processing.
    """
    # This is where googleapiclient.discovery.build('compute', 'v1', credentials=credentials) would go.
    
    # Mocking the discovery response for the pipeline to process:
    raw_instances = [
        {
            "id": "1234567890123456789",
            "name": "gcp-prod-web-01",
            "zone": "projects/my-project/zones/us-central1-a",
            "machineType": "projects/my-project/machineTypes/e2-medium",
            "status": "RUNNING",
            "networkInterfaces": [
                {
                    "network": "projects/my-project/global/networks/default",
                    "subnetwork": "projects/my-project/regions/us-central1/subnetworks/default",
                    "networkIP": "10.128.0.2",
                    "accessConfigs": [
                        {
                            "type": "ONE_TO_ONE_NAT",
                            "name": "External NAT",
                            "natIP": "34.68.12.34"
                        }
                    ]
                }
            ],
            "serviceAccounts": [
                {
                    "email": "123456789012-compute@developer.gserviceaccount.com",
                    "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"]
                }
            ],
            "labels": {
                "env": "production"
            }
        }
    ]

    normalized_assets = []
    
    for instance in raw_instances:
        # Normalization
        zone = instance.get("zone", "").split("/")[-1]
        region = "-".join(zone.split("-")[:-1]) if zone else "unknown"
        
        network_interface = instance.get("networkInterfaces", [{}])[0]
        public_ip = None
        if "accessConfigs" in network_interface:
            public_ip = network_interface["accessConfigs"][0].get("natIP")

        asset = {
            "asset_id": str(uuid.uuid4()),  # In production, use GCP instance ID
            "provider": "gcp",
            "type": "COMPUTE_INSTANCE",
            "region": region,
            "name": instance.get("name"),
            "configuration": {
                "project_id": project_id,
                "instance_id": instance.get("id"),
                "zone": zone,
                "machine_type": instance.get("machineType", "").split("/")[-1],
                "status": instance.get("status"),
                "public_ip": public_ip,
                "private_ip": network_interface.get("networkIP"),
                "network": network_interface.get("network", "").split("/")[-1],
                "subnetwork": network_interface.get("subnetwork", "").split("/")[-1],
                "service_account": instance.get("serviceAccounts", [{}])[0].get("email"),
                "labels": instance.get("labels", {})
            },
            "relationships": []
        }
        normalized_assets.append(asset)
        
    return normalized_assets

def collect_iam_policies(credentials: Any, project_id: str) -> List[Dict[str, Any]]:
    """
    Collects IAM policies and service accounts from GCP and normalizes them.
    In this implementation, it mocks the API call and returns the normalized schema.
    """
    raw_service_accounts = [
        {
            "name": f"projects/{project_id}/serviceAccounts/admin-sa@developer.gserviceaccount.com",
            "projectId": project_id,
            "uniqueId": "111222333444",
            "email": "admin-sa@developer.gserviceaccount.com",
            "displayName": "Admin Service Account",
            "oauth2ClientId": "111222333444",
            "keys": [
                {
                    "name": f"projects/{project_id}/serviceAccounts/admin-sa@developer.gserviceaccount.com/keys/abcdef123456",
                    "keyType": "USER_MANAGED",
                    "validAfterTime": "2024-01-01T00:00:00Z"
                }
            ],
            "iam_bindings": [
                {
                    "role": "roles/owner",
                    "members": [
                        "serviceAccount:admin-sa@developer.gserviceaccount.com"
                    ]
                }
            ]
        }
    ]

    normalized_assets = []
    
    for sa in raw_service_accounts:
        asset = {
            "asset_id": str(uuid.uuid4()),
            "provider": "gcp",
            "type": "IDENTITY",
            "region": "global",
            "name": sa.get("email"),
            "configuration": {
                "project_id": project_id,
                "service_account_id": sa.get("uniqueId"),
                "email": sa.get("email"),
                "display_name": sa.get("displayName"),
                "keys": sa.get("keys", []),
                "iam_bindings": sa.get("iam_bindings", [])
            },
            "relationships": []
        }
        normalized_assets.append(asset)
        
    return normalized_assets
