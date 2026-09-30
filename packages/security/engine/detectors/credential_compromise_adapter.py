from typing import Dict, Any, List
import uuid
from datetime import datetime, timezone

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent

from algo.detection.credential_compromise.detector import CredentialCompromiseDetector as Algo1Detector, DetectionMode
from algo.detection.credential_compromise.config import DetectorConfig
from algo.detection.credential_compromise.schemas import IdentityActivityEvent, CloudProvider, PrincipalType, IdentityKind, BaselineCategory, EventCategory, AccessType
from algo.detection.credential_compromise.profile import initial_profile

class CredentialCompromiseAdapter(BaseDetector):
    def __init__(self):
        # Initialize Algo 1 detector
        self.algo1 = Algo1Detector()

    @property
    def name(self) -> str:
        return "CredentialCompromiseAdapter"

    @property
    def attack_type(self) -> str:
        return "CREDENTIAL_COMPROMISE"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Adapts a single SecurityEvent into Algorithm #1's pipeline.
        """
        raw_dict = event.dict()
        
        # Build IdentityActivityEvent from SecurityEvent
        actor_id = event.actor.get("native_id", "unknown_user") if event.actor else "unknown_user"
        
        source_ip_val = event.source.get("ip_address") if event.source else None
        if source_ip_val:
            import ipaddress
            try:
                ipaddress.ip_address(source_ip_val)
            except ValueError:
                source_ip_val = None

        identity_event = IdentityActivityEvent(
            event_id=str(event.event_id or uuid.uuid4()),
            timestamp=event.timestamp or datetime.now(timezone.utc),
            provider=CloudProvider.AWS,
            account_id=str(event.account_id) if event.account_id else None,
            principal_id=actor_id,
            principal_name=event.actor.get("name") if event.actor else None,
            principal_type=PrincipalType.IAM_USER, # Best effort mapping
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
            identity_key=f"aws:iam:{event.account_id or 'unknown'}:user/{actor_id}",
            event_source=event.provider or "unknown.amazonaws.com",
            event_name=event.action or "UnknownAction",
            service_name=(event.provider or "unknown").split(".")[0],
            source_ip=source_ip_val,
        )

        # Build dummy profile from twin context or cold start
        # In Aegivion, twin_context holds baseline information, but for Algo1 we need an IdentityProfile
        # We will let Algo 1 run cold start for now since this is a thin adapter
        
        algo1_result = self.algo1.detect(identity_event, mode=DetectionMode.REAL_TIME)
        
        evidence = []
        if algo1_result.is_finding and algo1_result.finding:
            finding = algo1_result.finding
            for sig in finding.get("signals", []):
                evidence.append(DetectionEvidence(
                    event_id=str(event.event_id),
                    description=sig.get("description", str(sig)),
                    severity=algo1_result.severity.value,
                    timestamp=event.timestamp or datetime.now(timezone.utc)
                ))
            if not evidence:
                evidence.append(DetectionEvidence(
                    event_id=str(event.event_id),
                    description=finding.get("summary", "Anomalous behavior detected"),
                    severity=algo1_result.severity.value,
                    timestamp=event.timestamp or datetime.now(timezone.utc)
                ))

        return DetectionResult(
            detector_name=self.name,
            attack_type=self.attack_type,
            is_suspicious=algo1_result.is_finding,
            confidence_score=algo1_result.confidence,
            actor_id=actor_id,
            affected_resources=[],
            evidence=evidence,
            metadata={
                "algo1_risk_score": algo1_result.risk,
                "algo1_severity": algo1_result.severity.value,
                "algo1_anomaly_score": algo1_result.anomaly_score
            }
        )
