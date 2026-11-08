import os
import logging
from typing import Optional
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Standard adaptive retry configuration for resilient AWS API communication
AWS_CLIENT_CONFIG = Config(
    retries={
        "max_attempts": 5,
        "mode": "adaptive"
    },
    connect_timeout=10,
    read_timeout=30
)

def get_aws_session(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_region: Optional[str] = None,
    role_arn: Optional[str] = None,
    external_id: Optional[str] = None,
    session_name: str = "AegivionCloudSession",
    region_name: Optional[str] = None,
    **kwargs
) -> Optional[boto3.Session]:
    """
    Creates and returns a boto3 Session configured with adaptive backoff retries.
    Supports direct AWS credentials and cross-account IAM Role assumption (STS AssumeRole).
    """
    access_key = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
    region = region_name or aws_region or os.getenv("AWS_REGION", "ap-south-1")

    # 1. Base Session (using explicit keys or default credentials chain)
    try:
        if access_key and secret_key:
            base_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
        else:
            base_session = boto3.Session(region_name=region)
    except Exception as e:
        logger.error(f"Failed to initialize base AWS session: {e}")
        return None

    # 2. Cross-Account Assume Role Flow (if role_arn is provided)
    if role_arn:
        try:
            sts_client = base_session.client("sts", config=AWS_CLIENT_CONFIG)
            assume_params = {
                "RoleArn": role_arn,
                "RoleSessionName": session_name
            }
            if external_id:
                assume_params["ExternalId"] = external_id

            logger.info(f"Assuming cross-account IAM role: {role_arn}")
            response = sts_client.assume_role(**assume_params)
            creds = response["Credentials"]

            assumed_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )

            # Validate assumed caller identity
            assumed_sts = assumed_session.client("sts", config=AWS_CLIENT_CONFIG)
            assumed_sts.get_caller_identity()
            return assumed_session
        except Exception as e:
            logger.error(f"Failed to assume role {role_arn}: {e}")
            return None

    # 3. Direct Credential Flow (validate caller identity)
    if not access_key or not secret_key:
        try:
            # Fallback to local profile or instance role
            sts = base_session.client("sts", config=AWS_CLIENT_CONFIG)
            sts.get_caller_identity()
            return base_session
        except Exception:
            return None

    try:
        sts = base_session.client("sts", config=AWS_CLIENT_CONFIG)
        sts.get_caller_identity()
        return base_session
    except Exception as e:
        logger.error(f"Failed to validate AWS session credentials: {e}")
        return None
