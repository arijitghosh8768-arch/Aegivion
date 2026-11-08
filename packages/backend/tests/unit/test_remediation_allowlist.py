import pytest
from app.services.remediation_allowlist import RemediationAllowlistService

def test_allowed_s3_public_access_block_passes():
    """Verify standard valid S3 block public access passes validation."""
    params = {
        "bucket_name": "prod-customer-documents",
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
    validated = RemediationAllowlistService.validate_action(
        "ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        params
    )
    assert validated["bucket_name"] == "prod-customer-documents"
    assert validated["BlockPublicAcls"] is True
    assert validated["BlockPublicPolicy"] is True

def test_allowed_security_group_ingress_revocation_passes():
    """Verify valid unrestricted SSH ingress revocation passes validation."""
    params = {
        "group_id": "sg-0123456789abcdef0",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_ip": "0.0.0.0/0"
    }
    validated = RemediationAllowlistService.validate_action(
        "REVOKE_SECURITY_GROUP_INGRESS",
        params
    )
    assert validated["group_id"] == "sg-0123456789abcdef0"
    assert validated["from_port"] == 22
    assert validated["to_port"] == 22
    assert validated["cidr_ip"] == "0.0.0.0/0"

def test_forbidden_destructive_actions_blocked():
    """Verify destructive actions are strictly blocked by allowlist."""
    forbidden_actions = [
        "DeleteS3Bucket",
        "TerminateInstance",
        "DeleteSecurityGroup",
        "DROP_DATABASE",
        "PURGE_QUEUE"
    ]
    for action in forbidden_actions:
        with pytest.raises(ValueError) as excinfo:
            RemediationAllowlistService.validate_action(action, {})
        assert "Action not allowed" in str(excinfo.value)
        assert "strictly prohibited" in str(excinfo.value) or "not in the approved remediation allowlist" in str(excinfo.value)

def test_s3_block_public_access_rejects_false_flags():
    """Safety check: Setting any S3 protection flag to False must be rejected."""
    bad_params = {
        "bucket_name": "prod-customer-documents",
        "BlockPublicAcls": False,  # Dangerous! Must be blocked
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
    with pytest.raises(ValueError) as excinfo:
        RemediationAllowlistService.validate_action("ENABLE_S3_PUBLIC_ACCESS_BLOCK", bad_params)
    assert "BlockPublicAcls" in str(excinfo.value)
    assert "must be explicitly True" in str(excinfo.value)

def test_security_group_revocation_rejects_non_unrestricted_cidr():
    """Safety check: Automated ingress revocation must only target 0.0.0.0/0 or ::/0."""
    bad_cidr_params = {
        "group_id": "sg-0123456789abcdef0",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_ip": "10.0.1.50/32"  # Internal specific IP - should not be automated by this rule
    }
    with pytest.raises(ValueError) as excinfo:
        RemediationAllowlistService.validate_action("REVOKE_SECURITY_GROUP_INGRESS", bad_cidr_params)
    assert "unrestricted internet CIDRs" in str(excinfo.value)

def test_security_group_revocation_rejects_invalid_port_range():
    """Safety check: to_port cannot be less than from_port."""
    bad_port_params = {
        "group_id": "sg-0123456789abcdef0",
        "protocol": "tcp",
        "from_port": 8080,
        "to_port": 80,  # Invalid range
        "cidr_ip": "0.0.0.0/0"
    }
    with pytest.raises(ValueError) as excinfo:
        RemediationAllowlistService.validate_action("REVOKE_SECURITY_GROUP_INGRESS", bad_port_params)
    assert "cannot be less than from_port" in str(excinfo.value)

def test_invalid_security_group_id_format_blocked():
    """Safety check: group_id must adhere to AWS sg-xxxxxxxx regex."""
    bad_sg_params = {
        "group_id": "malicious-sg-id; rm -rf /",
        "protocol": "tcp",
        "from_port": 443,
        "to_port": 443,
        "cidr_ip": "0.0.0.0/0"
    }
    with pytest.raises(ValueError) as excinfo:
        RemediationAllowlistService.validate_action("REVOKE_SECURITY_GROUP_INGRESS", bad_sg_params)
    assert "Invalid AWS Security Group ID format" in str(excinfo.value)

