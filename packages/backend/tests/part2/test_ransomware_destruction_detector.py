import pytest
from datetime import datetime
from app.models.security_event import SecurityEvent, SecurityEventCategory
from security.engine.detectors.ransomware_destruction import RansomwareDestructionDetector

def test_normal_single_object_deletion():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-1",
        action="DeleteObject",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket/file.txt"},
        event_fingerprint="fp-1"
    )
    context = {"actor_historical_targets": ["bucket/file.txt"]}
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.05
    assert len(result.evidence) == 0

def test_mass_deletion():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-2",
        action="DeleteObjects",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket"},
        metadata={"objects_deleted": 100},
        event_fingerprint="fp-2"
    )
    context = {"actor_baseline_deletions": 5, "actor_historical_targets": ["bucket"]}
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert round(result.confidence_score, 2) == 0.50 # 0.05 + 0.45
    assert len(result.evidence) == 1

def test_backup_snapshot_deletion():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-3",
        action="DeleteSnapshot",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "snap-123"},
        event_fingerprint="fp-3"
    )
    context = {"actor_historical_targets": ["snap-123"]}
    result = detector.evaluate(event, context)
    assert result.is_suspicious # Score is 0.50 (0.05 + 0.45)
    assert round(result.confidence_score, 2) == 0.50 
    assert len(result.evidence) == 1

def test_backup_deletion_with_unhistorical_target():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-3b",
        action="DeleteSnapshot",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "snap-123"},
        event_fingerprint="fp-3b"
    )
    context = {"actor_historical_targets": ["other-resource"]}
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert round(result.confidence_score, 2) == 0.70 # 0.05 + 0.45 + 0.20

def test_encryption_related_modification():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-4",
        action="PutBucketEncryption",
        event_type=SecurityEventCategory.RESOURCE_MODIFIED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket"},
        metadata={"objects_modified": 50},
        event_fingerprint="fp-4"
    )
    context = {"actor_baseline_modifications": 2, "actor_historical_targets": ["other-bucket"]}
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    # mass modify (0.25) + encryption (0.25) + historical deviation (0.20)
    assert result.confidence_score == 0.70
    assert len(result.evidence) == 3

def test_missing_baseline_graceful_degradation():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-5",
        action="DeleteObject",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket/file.txt"},
        event_fingerprint="fp-5"
    )
    context = {} # Missing context
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.05

def test_tenant_isolation():
    detector = RansomwareDestructionDetector()
    event = SecurityEvent(
        event_id="evt-6",
        action="DeleteObjects",
        event_type=SecurityEventCategory.RESOURCE_DELETED,
        provider="aws",
        actor={"native_id": "user1"},
        target={"native_id": "bucket"},
        metadata={"objects_deleted": 100},
        event_fingerprint="fp-6"
    )
    # Different tenant has massive baseline, meaning THIS deletion isn't suspicious to them, 
    # but we supply low baseline to simulate our tenant context.
    context = {"actor_baseline_deletions": 5, "actor_historical_targets": ["bucket"]}
    result = detector.evaluate(event, context)
    assert result.is_suspicious
