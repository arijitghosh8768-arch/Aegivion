import boto3

def discover_security_groups(session=None) -> list:
    if session is None:
        return []
