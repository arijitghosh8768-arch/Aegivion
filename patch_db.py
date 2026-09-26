
import re

with open("packages/backend/app/database/__init__.py", "r", encoding="utf-8") as f:
    text = f.read()

def clean(match):
    return """    mapping = {
        "user": "users",
        "role": "roles",
        "organization": "organizations",
        "organizationmember": "organization_members",
        "authsession": "sessions",
        "cloudaccount": "cloud_accounts",
        "cloudaccountv2": "cloud_accounts_v2",
        "cloudasset": "cloud_assets",
        "securitygroupasset": "security_groups",
        "iamuserasset": "iam_users",
        "s3bucketasset": "s3_buckets",
        "ec2instanceasset": "ec2_instances",
        "scanjob": "scan_jobs",
        "relationship": "asset_relationships",
        "assetrelationship": "asset_relationships",
        "finding": "findings",
        "vulnerability": "vulnerabilities"
    }"""

text = re.sub(r"    mapping = \{.*?\}", clean, text, flags=re.DOTALL)

with open("packages/backend/app/database/__init__.py", "w", encoding="utf-8") as f:
    f.write(text)

