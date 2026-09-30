from typing import Dict, Any, List
import uuid

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent

from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.schemas import Provider, FindingSeverity
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.intelligence.profiler import BehavioralProfiler

class DataExfiltrationAdapter(BaseDetector):
    def __init__(self):
        # We initialize the Algo 2 pipeline
        # Profiler is required to extract behavioral features for scoring.
        # We use in-memory / stateless configurations for the adapter since Aegivion's engine manages state
        self.profiler = BehavioralProfiler()
        self.algo2 = DataExfiltrationDetector(
            config=DetectorConfig(),
            profiler=self.profiler
        )
        # Variant B uses rules and baseline fusion, no fitted IsolationForest required
        self.scoring_stack = ScoringStack(variant="B")

    @property
    def name(self) -> str:
        return "DataExfiltrationAdapter"

    @property
    def attack_type(self) -> str:
        return "DATA_EXFILTRATION"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Adapts a single SecurityEvent into Algorithm #2's pipeline and maps the result.
        """
        # Convert SecurityEvent to generic dict for Algo2
        raw_dict = event.dict()
        generic_record = {
            "event_id": str(event.event_id or uuid.uuid4()),
            "provider": Provider.GENERIC.value,
            "account_id": str(event.account_id) if event.account_id else None,
            "timestamp": raw_dict.get("timestamp"),
            "event_time_epoch_ms": event.timestamp.timestamp() * 1000 if hasattr(event.timestamp, "timestamp") else None,
            "actor_id": event.actor.get("native_id") if event.actor else None,
            "resource_id": event.target.get("native_id") if event.target else None,
            "bytes_accessed": event.metadata.get("bytes_transferred") if event.metadata else None,
            "source_ip": event.source.get("ip_address") if event.source else None,
            "destination_ip": event.target.get("destination_ip") if event.target else None,
            "data_action": event.action,
        }

        # 1. Process event through Algo 2 Pipeline
        algo2_result = self.algo2.process_events(
            cloudtrail_records=[generic_record],
            provider=Provider.GENERIC
        )

        if not algo2_result.sessions:
            # If Algo 2 couldn't build a session, no risk detected
            return DetectionResult(
                detector_name=self.name,
                attack_type=self.attack_type,
                is_suspicious=False,
                confidence_score=0.0,
                actor_id=event.actor.get("native_id") if event.actor else None,
                affected_resources=[],
                evidence=[],
                metadata={"algo2_status": "no_session"}
            )

        # 2. Score session using Algo 2 ScoringStack
        scored_findings = self.algo2.score_sessions(algo2_result, self.scoring_stack)
        
        if not scored_findings:
            return DetectionResult(
                detector_name=self.name,
                attack_type=self.attack_type,
                is_suspicious=False,
                confidence_score=0.0,
                actor_id=event.actor.get("native_id") if event.actor else None,
                affected_resources=[],
                evidence=[],
                metadata={"algo2_status": "no_scored_findings"}
            )

        scored = scored_findings[0]
        
        # 3. Map Algo 2 result to Aegivion DetectionResult
        risk_score = scored.risk_score or 0.0
        confidence = scored.confidence or 0.0
        is_suspicious = risk_score >= 0.5
        
        # Build evidence list
        evidence = []
        # Add discoveries
        for f in algo2_result.findings:
            evidence.append(DetectionEvidence(
                event_id=str(event.event_id),
                description=f.description,
                severity=f.severity.value.upper() if f.severity else "LOW",
                timestamp=event.timestamp
            ))
            
        # 4. Handle Insufficient Evidence
        # If Algo2 states confidence is low due to no history, relay that
        if scored.metadata and scored.metadata.get("confidence_state") == "insufficient_data":
            # Just passing this in metadata so Aegivion's brain can decide
            pass

        return DetectionResult(
            detector_name=self.name,
            attack_type=self.attack_type,
            is_suspicious=is_suspicious,
            confidence_score=confidence,
            actor_id=scored.actor_id,
            affected_resources=[scored.resource_id] if scored.resource_id else [],
            evidence=evidence,
            metadata={
                "algo2_risk_score": risk_score,
                "algo2_severity": scored.severity.value if scored.severity else None,
                "algo2_model": scored.model,
                "algo2_arde": scored.arde
            }
        )
