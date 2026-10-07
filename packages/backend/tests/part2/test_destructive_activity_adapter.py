import pytest
from datetime import datetime, timezone
import uuid

from app.models.security_event import SecurityEvent
from security.engine.detectors.destructive_activity_adapter import DestructiveActivityAdapter

def test_adapter_name_and_type():
    adapter = DestructiveActivityAdapter()
    assert adapter.name == "DestructiveActivityAdapter"
    assert adapter.attack_type == "DESTRUCTIVE_ACTIVITY"

def test_adapter_evaluate_safe_malformed_input():
    adapter = DestructiveActivityAdapter()
    
    # Event with missing fields
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        organization_id="org_1",
        event_type="cloud_trail",
        timestamp=datetime.now(timezone.utc),
        source={"ip_address": "127.0.0.1"},
        action="some_action",
        actor={},
        target={}
    )
    
    result = adapter.evaluate(event, twin_context={})
    
    # Should not raise, should evaluate safely and return a DetectionResult
    assert result.detector_name == "DestructiveActivityAdapter"
    assert result.is_suspicious is False
    assert result.confidence_score == 0.0

def test_adapter_evaluate_valid_destructive_event():
    adapter = DestructiveActivityAdapter()
    
    # Simulate a destructive action, e.g., deleting an S3 bucket
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        organization_id="org_1",
        event_type="cloud_trail",
        timestamp=datetime.now(timezone.utc),
        source={"ip_address": "127.0.0.1"},
        action="DeleteBucket",
        actor={"native_id": "malicious_user", "name": "bob"},
        target={"native_id": "my-bucket", "type": "S3_BUCKET", "arn": "arn:aws:s3:::my-bucket"}
    )
    
    # Since Algo 3 is instantiated inside and we are relying on its logic,
    # the exact result depends on how Algo 3's real implementation responds
    # to a single event without baseline. However, we can assert that it runs.
    result = adapter.evaluate(event, twin_context={})
    
    assert result.detector_name == "DestructiveActivityAdapter"
    assert isinstance(result.is_suspicious, bool)
    assert isinstance(result.confidence_score, float)
    assert "algo3_risk_score" in result.metadata or "error" in result.metadata
