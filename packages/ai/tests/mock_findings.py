# Day 8 - 5 to 10 Mock Findings for prompt and pipeline testing

MOCK_FINDINGS = [
    {
        "finding_id": "F-001",
        "asset_id": "asset-sg-001",
        "rule_id": "AWS-SG-001",
        "title": "SSH exposed to internet",
        "severity": "critical",
        "risk_score": 92,
        "evidence": {
            "port": 22,
            "protocol": "tcp",
            "cidr": "0.0.0.0/0"
        },
        "mitre": "T1021 - Remote Services"
    },
    {
        "finding_id": "F-002",
        "asset_id": "asset-s3-001",
        "rule_id": "AWS-S3-001",
        "title": "S3 Bucket allows public read access",
        "severity": "high",
        "risk_score": 85,
        "evidence": {
            "bucket_acl": "public-read",
            "block_public_acls": False,
            "block_public_policy": False
        },
        "mitre": "T1530 - Data from Cloud Shared Storage"
    },
    {
        "finding_id": "F-003",
        "asset_id": "asset-iam-001",
        "rule_id": "AWS-IAM-001",
        "title": "Admin user without Multi-Factor Authentication",
        "severity": "high",
        "risk_score": 88,
        "evidence": {
            "username": "breakglass-admin",
            "mfa_enabled": False,
            "is_admin": True
        },
        "mitre": "T1586 - Compromise Accounts"
    },
    {
        "finding_id": "F-004",
        "asset_id": "asset-iam-001",
        "rule_id": "AWS-IAM-002",
        "title": "IAM Access Key older than 180 days",
        "severity": "medium",
        "risk_score": 60,
        "evidence": {
            "access_key_age_days": 185,
            "max_allowed_age_days": 90
        },
        "mitre": "T1078 - Valid Accounts"
    },
    {
        "finding_id": "F-005",
        "asset_id": "asset-s3-001",
        "rule_id": "AWS-S3-002",
        "title": "S3 Bucket Server-Side Encryption disabled",
        "severity": "medium",
        "risk_score": 50,
        "evidence": {
            "encryption_enabled": False,
            "encryption_algorithm": None
        }
    },
    {
        "finding_id": "F-006",
        "asset_id": "asset-ec2-001",
        "rule_id": "AWS-EC2-001",
        "title": "EC2 instance lacks IMDSv2 requirement",
        "severity": "low",
        "risk_score": 35,
        "evidence": {
            "http_tokens": "optional",
            "http_endpoint": "enabled"
        },
        "mitre": "T1552 - Unsecured Credentials"
    }
]
