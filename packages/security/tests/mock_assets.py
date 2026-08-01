MOCK_EC2_ASSET = {
  "asset_id": "asset-ec2-001",
  "provider": "aws",
  "type": "ec2",
  "region": "ap-south-1",
  "name": "production-web-server",
  "configuration": {
    "instance_id": "i-0abcdef1234567890",
    "state": "running",
    "public_ip": "54.210.12.34",
    "private_ip": "10.0.1.4",
    "instance_type": "t3.medium",
    "has_public_ip": True
  },
  "relationships": []
}

MOCK_S3_ASSET = {
  "asset_id": "asset-s3-001",
  "provider": "aws",
  "type": "s3_bucket",
  "region": "ap-south-1",
  "name": "aegivion-customer-data-bucket",
  "configuration": {
    "bucket_name": "aegivion-customer-data-bucket",
    "arn": "arn:aws:s3:::aegivion-customer-data-bucket",
    "is_public": True,
    "encryption_enabled": False,
    "versioning_enabled": False
  },
  "relationships": []
}

MOCK_IAM_ASSET = {
  "asset_id": "asset-iam-001",
  "provider": "aws",
  "type": "iam_user",
  "region": "global",
  "name": "breakglass-admin-user",
  "configuration": {
    "username": "breakglass-admin",
    "arn": "arn:aws:iam::123456789012:user/breakglass-admin",
    "mfa_enabled": False,
    "is_admin": True,
    "access_keys_age_days": 185
  },
  "relationships": []
}

MOCK_SECURITY_GROUP_ASSET = {
  "asset_id": "asset-sg-001",
  "provider": "aws",
  "type": "security_group",
  "region": "ap-south-1",
  "name": "test-public-ssh",
  "configuration": {
    "ingress": [{
      "protocol": "tcp",
      "from_port": 22,
      "to_port": 22,
      "cidr": "0.0.0.0/0"
    }]
  },
  "relationships": []
}

ALL_MOCK_ASSETS = [
    MOCK_EC2_ASSET,
    MOCK_S3_ASSET,
    MOCK_IAM_ASSET,
    MOCK_SECURITY_GROUP_ASSET
]
