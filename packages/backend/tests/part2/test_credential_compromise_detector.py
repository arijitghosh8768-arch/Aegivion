import pytest
from datetime import datetime
from app.models.security_event import SecurityEvent, SecurityEventCategory
from security.engine.detectors.credential_compromise import CredentialCompromiseDetector

def test_normal_authentication():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-1",
        action="ConsoleLogin",
        event_type=SecurityEventCategory.LOGIN,
        provider="aws",
        source={"ip_address": "192.168.1.1"},
        actor={"native_id": "user1"},
        event_fingerprint="fp-1"
    )
    context = {"known_ips": ["192.168.1.1"], "recent_failed_logins": 0}
    
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.confidence_score == 0.0

def test_new_source_ip_suspicious():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-2",
        action="ConsoleLogin",
        event_type=SecurityEventCategory.LOGIN,
        provider="aws",
        source={"ip_address": "10.0.0.1"},
        actor={"native_id": "user1"},
        event_fingerprint="fp-2"
    )
    context = {"known_ips": ["192.168.1.1"], "recent_failed_logins": 0}
    
    result = detector.evaluate(event, context)
    assert not result.is_suspicious # Only 0.3, threshold is 0.5
    assert result.confidence_score == 0.3
    assert len(result.evidence) == 1
    assert "Unseen source IP" in result.evidence[0].description

def test_failed_then_successful():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-3",
        action="ConsoleLogin",
        event_type=SecurityEventCategory.LOGIN,
        provider="aws",
        source={"ip_address": "10.0.0.1"},
        actor={"native_id": "user1"},
        event_fingerprint="fp-3"
    )
    context = {"known_ips": ["192.168.1.1"], "recent_failed_logins": 5}
    
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert result.confidence_score == 0.8  # 0.3 (IP) + 0.5 (Failed logins)
    assert len(result.evidence) == 2

def test_privilege_modification():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-4",
        action="PutRolePolicy",
        event_type=SecurityEventCategory.PERMISSION_CHANGED,
        provider="aws",
        source={"ip_address": "10.0.0.1"},
        actor={"native_id": "user1"},
        event_fingerprint="fp-4"
    )
    context = {"known_ips": ["192.168.1.1"], "recent_failed_logins": 0}
    
    result = detector.evaluate(event, context)
    assert result.is_suspicious
    assert result.confidence_score == 0.7 # 0.3 (IP) + 0.4 (Privilege)
    
def test_missing_fields():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-5",
        action="ConsoleLogin",
        event_type=SecurityEventCategory.LOGIN,
        provider="aws",
        event_fingerprint="fp-5"
    ) # Missing IP, Actor, Target
    context = {}
    
    result = detector.evaluate(event, context)
    assert not result.is_suspicious
    assert result.actor_id is None

def test_tenant_isolation_indirect():
    detector = CredentialCompromiseDetector()
    event = SecurityEvent(
        event_id="evt-6",
        action="ConsoleLogin",
        event_type=SecurityEventCategory.LOGIN,
        provider="aws",
        source={"ip_address": "192.168.1.1"},
        actor={"native_id": "user1"},
        event_fingerprint="fp-6"
    )
    # Correctly scoped context
    context = {"known_ips": ["192.168.1.1"], "recent_failed_logins": 0}
    result = detector.evaluate(event, context)
    assert result.confidence_score == 0.0
