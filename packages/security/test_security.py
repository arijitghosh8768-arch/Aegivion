from rules.s3_public_access import scan_s3_bucket

def test_scan_s3_bucket_public():
    public_bucket = {
        "name": "public-test",
        "arn": "arn:aws:s3:::public-test",
        "acl": "public-read"
    }
    findings = scan_s3_bucket(public_bucket)
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["resource_type"] == "aws_s3_bucket"
    assert findings[0]["cloud_provider"] == "AWS"

def test_scan_s3_bucket_private():
    private_bucket = {
        "name": "private-test",
        "arn": "arn:aws:s3:::private-test",
        "acl": "private",
        "public_access_block": {
            "block_public_acls": True
        }
    }
    findings = scan_s3_bucket(private_bucket)
    assert len(findings) == 0
