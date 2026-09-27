import pytest
from datetime import datetime
from security.engine.normalizers.aws import AWSNormalizer
from security.engine.normalizers.azure import AzureNormalizer
from security.engine.normalizers.gcp import GCPNormalizer
from app.models.security_event import SecurityEventCategory
from app.repositories.security_event_repository import SecurityEventRepository
from unittest.mock import MagicMock

def test_aws_normalization():
    raw = {
        "eventID": "aws-123",
        "eventName": "GetObject",
        "eventTime": "2026-09-28T00:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:role/user"},
        "resources": [{"ARN": "arn:aws:s3:::bucket/data"}]
    }
    context = {"organization_id": "org-1", "account_id": "acc-1"}
    event = AWSNormalizer.normalize(raw, context)
    assert event.event_type == SecurityEventCategory.OBJECT_READ
    assert event.action == "GetObject"
    assert event.actor["native_id"] == "arn:aws:iam::123:role/user"
    assert event.native_event_id == "aws-123"
    assert event.organization_id == "org-1"

def test_cross_cloud_consistency():
    aws_raw = {"eventName": "GetObject"}
    azure_raw = {"operationName": "Microsoft.Storage/blobs/read"}
    gcp_raw = {"methodName": "storage.objects.get"}
    context = {"organization_id": "org-1"}
    
    aws_evt = AWSNormalizer.normalize(aws_raw, context)
    azure_evt = AzureNormalizer.normalize(azure_raw, context)
    gcp_evt = GCPNormalizer.normalize(gcp_raw, context)
    
    assert aws_evt.event_type == SecurityEventCategory.OBJECT_READ
    assert azure_evt.event_type == SecurityEventCategory.OBJECT_READ
    assert gcp_evt.event_type == SecurityEventCategory.OBJECT_READ

def test_deduplication_and_persistence():
    mock_db = MagicMock()
    mock_table = MagicMock()
    mock_db.table.return_value = mock_table
    
    repo = SecurityEventRepository(mock_db)
    aws_raw = {"eventID": "unique-aws-123", "eventName": "AssumeRole"}
    ctx = {"organization_id": "org-tenant"}
    event = AWSNormalizer.normalize(aws_raw, ctx)
    
    # mock duplicate check
    mock_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []
    
    is_dup = repo.check_duplicate(event.organization_id, event.event_fingerprint)
    assert not is_dup
    
    repo.create(event)
    mock_table.insert.assert_called_once()
    
    # second time it should return duplicate
    mock_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = [event.dict()]
    is_dup2 = repo.check_duplicate(event.organization_id, event.event_fingerprint)
    assert is_dup2

def test_tenant_isolation_validation():
    # If a raw event comes with its own org_id, it is ignored
    aws_raw = {"eventName": "ConsoleLogin", "organization_id": "HACKER_ORG"}
    ctx = {"organization_id": "TRUSTED_ORG"}
    event = AWSNormalizer.normalize(aws_raw, ctx)
    assert event.organization_id == "TRUSTED_ORG"
