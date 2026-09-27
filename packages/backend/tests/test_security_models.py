import pytest
from datetime import datetime
from app.models.security_event import SecurityEvent, SecurityEventCategory
from app.models.cloud import CloudIdentity

def test_cloud_identity_creation():
    identity = CloudIdentity(
        identity_id="id-123",
        organization_id="org-1",
        account_id="aws-1",
        native_id="arn:aws:iam::123:role/test",
        identity_type="AWS IAM Role",
        name="TestRole"
    )
    assert identity.identity_id == "id-123"
    assert identity.native_id == "arn:aws:iam::123:role/test"

def test_security_event_deduplication():
    # Events with same native_id should have same fingerprint
    ts = datetime.utcnow()
    event1 = SecurityEvent(
        provider="aws",
        account_id="acc-1",
        native_event_id="evt-native-123",
        timestamp=ts,
        event_type=SecurityEventCategory.LOGIN
    )
    
    event2 = SecurityEvent(
        provider="aws",
        account_id="acc-1",
        native_event_id="evt-native-123",
        timestamp=ts,
        event_type=SecurityEventCategory.LOGIN
    )
    
    assert event1.event_fingerprint == event2.event_fingerprint
    
    # Event without native ID should use deterministic fields
    event3 = SecurityEvent(
        provider="aws",
        account_id="acc-1",
        timestamp=ts,
        event_type=SecurityEventCategory.OBJECT_READ,
        actor={"identity_id": "id-123"},
        action="GetObject"
    )
    
    event4 = SecurityEvent(
        provider="aws",
        account_id="acc-1",
        timestamp=ts,
        event_type=SecurityEventCategory.OBJECT_READ,
        actor={"identity_id": "id-123"},
        action="GetObject"
    )
    
    assert event3.event_fingerprint == event4.event_fingerprint
    assert event1.event_fingerprint != event3.event_fingerprint
