from typing import Dict, Any, List
from datetime import datetime
import uuid

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent, SecurityEventCategory

class CredentialCompromiseDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "CredentialCompromiseDetector"
        
    @property
    def attack_type(self) -> str:
        return "CREDENTIAL_COMPROMISE"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Evaluates a single SecurityEvent for credential compromise signals.
        Relies heavily on historic behavioral context provided by twin_context.
        """
        evidence = []
        score = 0.0
        
        action = (event.action or "").lower()
        event_type = event.event_type or ""
        source_ip = event.source.get("ip_address") if event.source else None
        
        known_ips = twin_context.get("known_ips", [])
        failed_logins = twin_context.get("recent_failed_logins", 0)
        
        # 1. Source Anomaly
        if source_ip and known_ips and source_ip not in known_ips:
            score += 0.3
            evidence.append(DetectionEvidence(
                event_id=event.event_id,
                description=f"Unseen source IP observed: {source_ip}",
                severity="MEDIUM",
                timestamp=event.timestamp or datetime.utcnow()
            ))

        # 2. Auth Anomaly
        if "login" in action or "signin" in action or "authenticate" in action or event_type in [SecurityEventCategory.LOGIN, SecurityEventCategory.LOGIN_FAILURE]:
            if event_type == SecurityEventCategory.LOGIN_FAILURE:
                # Raw failure is tracked but not immediately suspicious
                pass
            elif event_type == SecurityEventCategory.LOGIN and failed_logins >= 3:
                score += 0.5
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Successful login after {failed_logins} failed attempts",
                    severity="HIGH",
                    timestamp=event.timestamp or datetime.utcnow()
                ))
        
        # 3. Privilege Anomaly
        if event.provider and ("iam" in event.provider.lower() or "role" in action or "policy" in action):
            if event_type in [SecurityEventCategory.RESOURCE_MODIFIED, SecurityEventCategory.PERMISSION_CHANGED]:
                score += 0.4
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Suspicious privilege modification: {event.action}",
                    severity="MEDIUM",
                    timestamp=event.timestamp or datetime.utcnow()
                ))

        # Cap deterministic score at 1.0
        final_score = min(score, 1.0)
        is_suspicious = final_score >= 0.5
        
        actor_id = event.actor.get("native_id") if event.actor else None
        target_id = event.target.get("native_id") if event.target else None
        
        return DetectionResult(
            detector_name=self.name,
            attack_type=self.attack_type,
            is_suspicious=is_suspicious,
            confidence_score=final_score,
            actor_id=actor_id,
            affected_resources=[target_id] if target_id else [],
            evidence=evidence,
            metadata={
                "detector_version": "1.0",
                "triggered_signals": len(evidence),
                "observed_event_ids": [event.event_id],
                "provider": event.provider
            }
        )
