import boto3

def discover_rds_instances(session=None) -> list:
    if session is None:
        return [
            {
                "db_instance_identifier": "aegivion-prod-db",
                "arn": "arn:aws:rds:ap-south-1:123456789012:db:aegivion-prod-db",
                "engine": "postgres",
                "publicly_accessible": True,
                "storage_encrypted": False,
                "region": "ap-south-1"
            },
            {
                "db_instance_identifier": "aegivion-backup-db",
                "arn": "arn:aws:rds:ap-south-1:123456789012:db:aegivion-backup-db",
                "engine": "postgres",
                "publicly_accessible": False,
                "storage_encrypted": True,
                "region": "ap-south-1"
            }
        ]

    rds = session.client("rds")
    discovered = []
    try:
        response = rds.describe_db_instances()
        for db in response.get("DBInstances", []):
            discovered.append({
                "db_instance_identifier": db["DBInstanceIdentifier"],
                "arn": db["DBInstanceArn"],
                "engine": db["Engine"],
                "publicly_accessible": db["PubliclyAccessible"],
                "storage_encrypted": db["StorageEncrypted"],
                "region": session.region_name
            })
    except Exception as e:
        print(f"Error listing RDS instances: {e}")
    return discovered
