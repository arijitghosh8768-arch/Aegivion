from typing import Dict, Any, List
from datetime import datetime
import uuid

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent, SecurityEventCategory

class DataExfiltrationDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "DataExfiltrationDetector"
        
    @property
    def attack_type(self) -> str:
        return "DATA_EXFILTRATION"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Evaluates a single SecurityEvent for data exfiltration signals.
        """
        evidence = []
        score = 0.0
        
        action = (event.action or "").lower()
        event_type = event.event_type or ""
        
        metadata = event.metadata or {}
        volume = metadata.get("bytes_transferred", 0)
        
        known_sensitive_assets = twin_context.get("sensitive_assets", [])
        actor_baseline_volume = twin_context.get("actor_baseline_volume", 0)
        actor_historical_targets = twin_context.get("actor_historical_targets", [])
        
        target_id = event.target.get("native_id") if event.target else None
        
        # 1. Abnormal Object/Data Read
        is_read_event = event_type in [SecurityEventCategory.OBJECT_READ, SecurityEventCategory.DATABASE_READ] or "getobject" in action or "download" in action
        
        if is_read_event:
            score += 0.1 # Base score for any data read (very low, below threshold)
            
            # 2. Data Access Volume
            if volume > 0 and volume > (actor_baseline_volume * 10) and actor_baseline_volume > 0:
                score += 0.4
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Unusually large data volume accessed: {volume} bytes",
                    severity="HIGH",
                    timestamp=event.timestamp or datetime.utcnow()
                ))
                
            # 3. Resource Sensitivity
            if target_id and target_id in known_sensitive_assets:
                score += 0.3
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Sensitive resource accessed: {target_id}",
                    severity="MEDIUM",
                    timestamp=event.timestamp or datetime.utcnow()
                ))
                
            # 5. Behavioral Anomaly
            if target_id and target_id not in actor_historical_targets and len(actor_historical_targets) > 0:
                score += 0.2
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Identity rarely accesses this resource: {target_id}",
                    severity="MEDIUM",
                    timestamp=event.timestamp or datetime.utcnow()
                ))

        # 4. Destination / Data Movement
        destination = event.target.get("destination_ip") if event.target else None
        if destination and twin_context.get("network_zones", {}).get(destination) == "external":
            score += 0.4
            evidence.append(DetectionEvidence(
                event_id=event.event_id,
                description=f"Data transfer to external destination: {destination}",
                severity="HIGH",
                timestamp=event.timestamp or datetime.utcnow()
            ))

        final_score = min(score, 1.0)
        is_suspicious = final_score >= 0.5
        
        actor_id = event.actor.get("native_id") if event.actor else None
        
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
