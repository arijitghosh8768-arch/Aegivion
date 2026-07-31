import uuid

def scan_s3_bucket(bucket_config: dict) -> list:
    """
    Scans a mock AWS S3 bucket configuration to check if public access is allowed.
    Returns a list of findings matching the findings schema if public access is enabled.
    """
    findings = []
    
    # Check for public read access or missing public access block
    is_public = bucket_config.get("acl") == "public-read" or bucket_config.get("public_access_block", {}).get("block_public_acls") is False
    
    if is_public:
        finding = {
            "finding_id": str(uuid.uuid4()),
            "title": "S3 Bucket Public Access Enabled",
            "severity": "High",
            "resource_id": bucket_config.get("arn", "unknown"),
            "resource_type": "aws_s3_bucket",
            "cloud_provider": "AWS",
            "description": f"The S3 bucket '{bucket_config.get('name')}' is configured to allow public access. Anyone on the internet can read or write to it.",
            "remediation": "Enable 'Block all public access' settings in S3 console or Terraform configuration."
        }
        findings.append(finding)
        
    return findings
