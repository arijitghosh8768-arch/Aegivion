
import sys

new_mapping = """SUPABASE_MAPPING = {
    "CloudAsset": "cloud_assets",
    "Finding": "findings",
    "Incident": "incidents",
    "CloudAccount": "cloud_accounts",
    "CloudAccountV2": "cloud_accounts_v2",
    "SecurityGroupAsset": "security_groups",
    "IAMUserAsset": "iam_users",
    "S3BucketAsset": "s3_buckets",
    "EC2InstanceAsset": "ec2_instances",
    "ScanJob": "scan_jobs",
    "Relationship": "asset_relationships",
    "AssetRelationship": "asset_relationships",
    "Vulnerability": "vulnerabilities",
    "Runbook": "runbooks",
    "AgentHeartbeat": "agentheartbeats",
    "ResponseExecution": "responseexecutions",
    "PendingApproval": "pendingapprovals",
    "SyncQuality": "syncqualitys",
    "EvaluationResult": "evaluationresults"
}"""

with open("packages/backend/app/database/__init__.py", "r") as f:
    content = f.read()

content = content.replace("supabase_mapping = {\"CloudAsset\": \"cloud_assets\", \"Finding\": \"findings\", \"Incident\": \"incidents\", \"CloudAccount\": \"cloud_accounts\"}", "supabase_mapping = SUPABASE_MAPPING")
content = content.replace("db_name = \"aegivion\"\n", "db_name = \"aegivion\"\n\n" + new_mapping + "\n")

with open("packages/backend/app/database/__init__.py", "w") as f:
    f.write(content)

print("Mapping updated!")

