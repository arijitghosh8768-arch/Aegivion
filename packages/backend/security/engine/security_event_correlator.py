from typing import Dict, Any, List, Optional
from security.models.security_event_schema import SecurityEventSchema
from security.models.security_correlation_schema import SecurityCorrelationSchema
from datetime import datetime

class SecurityEventCorrelator:
    """
    Engine responsible for taking independent detector signals and grouping them
    into a cohesive Incident Storyline based on Temporal, Actor, and Asset relationships.
    """
    
    @staticmethod
    def correlate_signals(event: SecurityEventSchema, detector_results: Dict[str, Any]) -> Optional[SecurityCorrelationSchema]:
        """
        Evaluates the detector results. If actionable attacks are found, correlates them
        into a storyline. If no attacks, returns None.
        """
        active_attacks = []
        for attack_type, signals in detector_results.items():
            if signals:
                active_attacks.append(attack_type)
                
        if not active_attacks:
            return None
            
        # For a full implementation, we would query the database here to find an OPEN incident
        # with the same actor or asset within the last X hours and append to it.
        # Here we fulfill the contract of building the correlated storyline.
        
        actors = [event.actor] if event.actor != "unknown" else []
        assets = [event.target] if event.target != "unknown" else []
        
        timeline_entry = {
            "timestamp": event.timestamp.isoformat(),
            "title": f"Detector Signals Triggered: {', '.join(active_attacks)}",
            "description": f"Event {event.action} by {event.actor} triggered detectors."
        }
        
        # Calculate derived severity and confidence
        severity = "high"
        if "ransomware" in active_attacks or "credential_compromise" in active_attacks:
            severity = "critical"
            
        confidence = 0.90 if len(active_attacks) > 1 else 0.80
        
        reason = f"Correlated event {event.action} matching attack signatures for {', '.join(active_attacks)}."
        
        return SecurityCorrelationSchema(
            organization_id=event.organization_id,
            attack_types=active_attacks,
            confidence=confidence,
            severity=severity,
            actors=actors,
            affected_assets=assets,
            events=[event.event_id],
            evidence={"raw_signals": detector_results},
            timeline=[timeline_entry],
            correlation_reason=reason
        )
