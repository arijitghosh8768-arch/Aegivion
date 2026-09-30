import pytest
from app.services.security_event_ingestion_service import SecurityEventIngestionService
from unittest.mock import AsyncMock, MagicMock

@pytest.mark.asyncio
async def test_aws_real_event_ingestion_idempotency():
    mock_db_client = MagicMock()
    mock_db_session = MagicMock()
    
    # Mock supabase table structure
    mock_table = MagicMock()
    mock_db_client.table.return_value = mock_table
    
    # Simulate DB empty initially for duplicate check
    mock_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []
    
    service = SecurityEventIngestionService(mock_db_client, mock_db_session)
    
    raw_cloudtrail_event = {
        "eventID": "aws-live-123",
        "eventName": "ConsoleLogin",
        "eventTime": "2026-09-28T00:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
        "sourceIPAddress": "192.168.1.1"
    }
    
    trusted_context = {
        "organization_id": "ORG-VALID",
        "account_id": "ACC-VALID",
        "provider": "aws"
    }
    
    # First ingestion (should store and trigger twin update)
    result = await service.ingest(raw_cloudtrail_event, trusted_context)
    assert result["status"] == "stored"
    assert result["organization_id"] == "ORG-VALID"
    mock_table.insert.assert_called_once()
    
    # Simulate DB having the record now
    mock_table.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = [{"event_id": result["event_id"]}]
    
    # Second ingestion (should deduplicate and skip DB / Twin update)
    result2 = await service.ingest(raw_cloudtrail_event, trusted_context)
    assert result2["status"] == "duplicate"
    # insert should still only have been called once
    mock_table.insert.assert_called_once()

@pytest.mark.asyncio
async def test_tenant_isolation_enforcement():
    mock_db_client = MagicMock()
    mock_db_session = MagicMock()
    service = SecurityEventIngestionService(mock_db_client, mock_db_session)
    
    # Attempt to ingest without trusted organization context
    bad_context = {"provider": "aws"}
    result = await service.ingest({"eventName": "AssumeRole"}, bad_context)
    
    assert result["status"] == "rejected"
    assert "Missing trusted organization context" in result["reason"]
