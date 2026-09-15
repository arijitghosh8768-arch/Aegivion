import boto3

def discover_rds_instances(session=None) -> list:
    if session is None:
        return []
