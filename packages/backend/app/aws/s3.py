import boto3
from botocore.exceptions import ClientError

def discover_s3_buckets(session=None) -> list:
    if session is None:
        # Mock mode
        return [
            {
                "bucket_name": "aegivion-secure-logs",
                "arn": "arn:aws:s3:::aegivion-secure-logs",
                "is_public": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "region": "ap-south-1"
            },
            {
                "bucket_name": "aegivion-public-assets",
                "arn": "arn:aws:s3:::aegivion-public-assets",
                "is_public": True,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "region": "ap-south-1"
            }
        ]
    
    s3_client = session.client("s3")
    discovered = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            arn = f"arn:aws:s3:::{name}"
            region = "ap-south-1"
            try:
                loc = s3_client.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
                if region == "EU":
                    region = "eu-west-1"
            except ClientError:
                pass
            
            is_public = False
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                if not config.get("BlockPublicAcls", True) or not config.get("IgnorePublicAcls", True) or not config.get("BlockPublicPolicy", True) or not config.get("RestrictPublicBuckets", True):
                    is_public = True
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlock":
                    is_public = True
            
            if not is_public:
                try:
                    acl = s3_client.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                        ]:
                            is_public = True
                            break
                except ClientError:
                    pass
            
            encryption_enabled = False
            try:
                s3_client.get_bucket_encryption(Bucket=name)
                encryption_enabled = True
            except ClientError:
                pass
                
            versioning_enabled = False
            try:
                ver = s3_client.get_bucket_versioning(Bucket=name)
                if ver.get("Status") == "Enabled":
                    versioning_enabled = True
            except ClientError:
                pass
                
            discovered.append({
                "bucket_name": name,
                "arn": arn,
                "is_public": is_public,
                "encryption_enabled": encryption_enabled,
                "versioning_enabled": versioning_enabled,
                "region": region
            })
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
    return discovered
