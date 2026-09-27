import pytest
from datetime import datetime
from app.models.security_event import SecurityEvent, SecurityEventCategory
from security.engine.detectors.data_exfiltration import DataExfiltrationDetector

def test_normal_single_object_read():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-1",
        action="GetObject",
        event_type=SecurityEventCategory.OBJECT_READ,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket/file.txt"},
        event_fingerprint="fp-1"
    )
    context = {}
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.1
    assert len(result.evidence) == 0

def test_high_volume_data_access():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-2",
        action="GetObject",
        event_type=SecurityEventCategory.OBJECT_READ,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket/file.txt"},
        metadata={"bytes_transferred": 5000000},
        event_fingerprint="fp-2"
    )
    context = {"actor_baseline_volume": 10000}
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert result.confidence_score == 0.5 # 0.1 (read) + 0.4 (volume)
    assert len(result.evidence) == 1

def test_sensitive_resource_access_with_history():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-3",
        action="GetObject",
        event_type=SecurityEventCategory.OBJECT_READ,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "db-prod-1"},
        event_fingerprint="fp-3"
    )
    context = {
        "sensitive_assets": ["db-prod-1"],
        "actor_historical_targets": ["db-dev-1"]
    }
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert round(result.confidence_score, 1) == 0.6 # 0.1 + 0.3 + 0.2
    assert len(result.evidence) == 2
    
def test_missing_size_information():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-4",
        action="GetObject",
        event_type=SecurityEventCategory.OBJECT_READ,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "db-prod-1"},
        event_fingerprint="fp-4"
    )
    context = {"actor_baseline_volume": 10000}
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.1

def test_external_destination_transfer():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-5",
        action="DataTransfer",
        event_type=SecurityEventCategory.DATA_EXPORT,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "db-prod-1", "destination_ip": "8.8.8.8"},
        event_fingerprint="fp-5"
    )
    context = {"network_zones": {"8.8.8.8": "external"}}
    result = detector.evaluate(event, context)
    assert not result.is_suspicious # Only 0.4 score from external transfer since not read
    assert result.confidence_score == 0.4
    assert len(result.evidence) == 1

def test_tenant_isolation():
    detector = DataExfiltrationDetector()
    event = SecurityEvent(
        event_id="evt-6",
        action="GetObject",
        event_type=SecurityEventCategory.OBJECT_READ,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "db-prod-1"},
        event_fingerprint="fp-6"
    )
    # The context explicitly doesn't contain the sensitivity flag, even if another tenant might
    context = {"sensitive_assets": []}
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.1
