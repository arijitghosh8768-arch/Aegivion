from typing import Dict, Any, List
import uuid
import logging
from datetime import datetime, timezone

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent

from algo.detection.cloud_destruction.detector import DestructionDetector as Algo3Detector
from algo.detection.cloud_destruction.schemas import (
    ResourceActivityEvent, 
    CloudProvider, 
    ActorType,
    map_resource_type,
    ActionCategory
)

logger = logging.getLogger(__name__)

class DestructiveActivityAdapter(BaseDetector):
    def __init__(self):
        # Initialize Algo 3 detector
        self.algo3 = Algo3Detector()

    @property
    def name(self) -> str:
        return "DestructiveActivityAdapter"

    @property
    def attack_type(self) -> str:
        return "DESTRUCTIVE_ACTIVITY"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Adapts a single SecurityEvent into Algorithm #3's pipeline.
        """
        actor_id = event.actor.get("native_id", "unknown_user") if getattr(event, "actor", None) else "unknown_user"
        
        target = getattr(event, "target", {})
        if target is None:
            target = {}
            
        resource_id = target.get("native_id", "unknown_resource")
        resource_arn = target.get("arn")
        resource_type = target.get("type")
        
        # Determine canonical resource type using Algo #3's helper
        canonical_resource_type = map_resource_type(resource_arn or resource_type or resource_id)

        source_ip_val = None
        if getattr(event, "source", None):
            source_ip_val = event.source.get("ip_address")
            if source_ip_val:
                import ipaddress
                try:
                    ipaddress.ip_address(source_ip_val)
                except ValueError:
                    source_ip_val = None

        provider_str = getattr(event, "provider", None) or "aws"
        try:
            provider = CloudProvider(provider_str.lower())
        except ValueError:
            provider = CloudProvider.UNKNOWN
            
        action = getattr(event, "action", "unknown")
        if not action:
            action = "unknown"

        try:
            # Build ResourceActivityEvent from SecurityEvent
            algo3_event = ResourceActivityEvent(
                event_id=str(getattr(event, "event_id", uuid.uuid4())),
                timestamp=getattr(event, "timestamp", datetime.now(timezone.utc)),
                provider=provider,
                account_id=str(getattr(event, "account_id", "")) if getattr(event, "account_id", None) else None,
                actor_id=actor_id,
                actor_type=ActorType.UNKNOWN,
                resource_id=resource_id,
                resource_arn=resource_arn,
                resource_type=canonical_resource_type,
                action="unknown", # let the raw action map happen or just keep unknown as canonical
                raw_action=action,
                source_ip=source_ip_val
            )
            
            # Map canonical action if possible
            for cat in ActionCategory:
                if cat.value.lower() in action.lower():
                    algo3_event.action = cat.value
                    break
            
            # evaluate
            outcome = self.algo3.detect([algo3_event])
            
            evidence = []
            is_suspicious = False
            confidence_score = 0.0
            metadata = {
                "events_processed": len(outcome.sessions),
                "findings_count": len(outcome.findings)
            }
            
            # Check findings
            if outcome.findings:
                finding = outcome.findings[0] # taking the first finding
                is_suspicious = finding.risk_score >= 0.35
                confidence_score = finding.confidence_score
                
                # Check explainability if present
                if outcome.explanations:
                    exp = outcome.explanations[0]
                    for comp in exp.components:
                        evidence.append(DetectionEvidence(
                            event_id=str(event.event_id),
                            description=comp.message,
                            severity=finding.severity.value,
                            timestamp=event.timestamp or datetime.now(timezone.utc)
                        ))
                
                if not evidence:
                    evidence.append(DetectionEvidence(
                        event_id=str(event.event_id),
                        description=f"Destructive activity detected with risk {finding.risk_score:.2f}",
                        severity=finding.severity.value,
                        timestamp=event.timestamp or datetime.now(timezone.utc)
                    ))
                    
                metadata["algo3_risk_score"] = finding.risk_score
                metadata["algo3_severity"] = finding.severity.value

            return DetectionResult(
                detector_name=self.name,
                attack_type=self.attack_type,
                is_suspicious=is_suspicious,
                confidence_score=confidence_score,
                actor_id=actor_id,
                affected_resources=[resource_id] if resource_id != "unknown_resource" else [],
                evidence=evidence,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Algo3 Adapter evaluation failed: {e}")
            # Fail safely
            return DetectionResult(
                detector_name=self.name,
                attack_type=self.attack_type,
                is_suspicious=False,
                confidence_score=0.0,
                actor_id=actor_id,
                affected_resources=[],
                evidence=[DetectionEvidence(
                    event_id=str(getattr(event, "event_id", "")),
                    description=f"Internal adapter error: {str(e)}",
                    severity="LOW",
                    timestamp=getattr(event, "timestamp", datetime.now(timezone.utc))
                )],
                metadata={"error": str(e)}
            )
