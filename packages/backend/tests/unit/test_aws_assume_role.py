from unittest.mock import MagicMock, patch
import pytest
import boto3
from app.cloud.aws.client import get_aws_session as get_cloud_aws_session
from app.aws.client import get_aws_session as get_base_aws_session

def test_assume_role_success():
    """Verify that when role_arn and external_id are provided, STS assume_role is invoked and temporary credentials session is returned"""
    fake_credentials = {
        "AccessKeyId": "ASIA_MOCK_ACCESS_KEY",
        "SecretAccessKey": "MOCK_SECRET_KEY",
        "SessionToken": "MOCK_SESSION_TOKEN"
    }

    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = {
        "Credentials": fake_credentials
    }
    mock_sts_client.get_caller_identity.return_value = {
        "Account": "999888777666",
        "Arn": "arn:aws:sts::999888777666:assumed-role/AegivionRole/AegivionCloudSession"
    }

    mock_base_session = MagicMock()
    mock_base_session.client.return_value = mock_sts_client

    with patch("boto3.Session") as mock_session_class:
        # First call is base_session, second call is assumed_session
        mock_session_class.side_effect = [mock_base_session, mock_base_session]

        session = get_cloud_aws_session(
            role_arn="arn:aws:iam::999888777666:role/AegivionSecurityRole",
            external_id="ext-unique-12345",
            session_name="TestAssumedSession"
        )

        assert session is not None
        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::999888777666:role/AegivionSecurityRole",
            RoleSessionName="TestAssumedSession",
            ExternalId="ext-unique-12345"
        )

def test_direct_credentials_fallback():
    """Verify that direct credentials path still works when role_arn is omitted"""
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.return_value = {"Account": "111222333444"}

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts_client

    with patch("boto3.Session", return_value=mock_session) as mock_session_class:
        session = get_base_aws_session(
            aws_access_key_id="AKIA_DIRECT_TEST",
            aws_secret_access_key="SECRET_DIRECT_TEST",
            aws_region="eu-west-1"
        )

        assert session is not None
        mock_session_class.assert_called_with(
            aws_access_key_id="AKIA_DIRECT_TEST",
            aws_secret_access_key="SECRET_DIRECT_TEST",
            region_name="eu-west-1"
        )
        mock_sts_client.get_caller_identity.assert_called_once()

