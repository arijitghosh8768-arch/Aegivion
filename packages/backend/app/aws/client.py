import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def get_aws_session(aws_access_key_id: str = None, aws_secret_access_key: str = None, aws_region: str = None):
    """
    Creates and returns a boto3 Session.
    If no credentials are provided, attempts to load them from environment variables.
    """
    access_key = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
    region = aws_region or os.getenv("AWS_REGION", "ap-south-1")

    if not access_key or not secret_key:
        return None

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        # Test connection using sts
        sts = session.client("sts")
        sts.get_caller_identity()
        return session
    except Exception as e:
        print(f"Failed to create AWS session: {e}")
        return None
