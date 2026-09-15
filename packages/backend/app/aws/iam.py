import boto3
from datetime import datetime, timezone

def discover_iam_users(session=None) -> list:
    if session is None:
        return []
