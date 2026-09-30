from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from enum import Enum
import json
from app.models.security_event import SecurityEventCategory

class TemporalProgressionState(str, Enum):
    NO_SEQUENCE = "NO_SEQUENCE"
    RELATED_EVENTS = "RELATED_EVENTS"
    PARTIAL_PROGRESSION = "PARTIAL_PROGRESSION"
    STRONG_PROGRESSION = "STRONG_PROGRESSION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class TemporalEvidence(BaseModel):
    factor: str
    event_ids: List[str]
    description: Optional[str] = None
    classification: str  # "OBSERVED", "INFERRED", "UNKNOWN"

class TemporalProgressionResult(BaseModel):
    progression_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    actor_id: Optional[str]
    ordered_events: List[str]
    window_minutes: int
    progression_score: float
    state: TemporalProgressionState
    evidence: List[TemporalEvidence]
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    algorithm_version: str = "1.0"


class TemporalAttackProgressionEngine:
    """
    Evaluates chronological sequences of security events to identify
    potential attack progressions. Does NOT execute detection algorithms,
    but groups and evaluates sequential events.
    """
    
    # Default time window in minutes
    DEFAULT_WINDOW_MINUTES = 60
    
    def evaluate(self, 
                 organization_id: str, 
                 events: List[Dict[str, Any]], 
                 actor_id: Optional[str] = None,
                 window_minutes: int = DEFAULT_WINDOW_MINUTES) -> TemporalProgressionResult:
        
        if not events:
            return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.NO_SEQUENCE)
            
        # 1. Tenant Isolation check
        for e in events:
            if e.get("organization_id") and e.get("organization_id") != organization_id:
                raise ValueError(f"Cross-tenant event detected. Expected {organization_id}, found {e.get('organization_id')}")
                
        # 2. Filter duplicate events by event_fingerprint if available, or event_id
        unique_events = []
        seen_fingerprints = set()
        for e in events:
            fp = e.get("event_fingerprint") or e.get("event_id")
            if fp and fp in seen_fingerprints:
                continue
            if fp:
                seen_fingerprints.add(fp)
            unique_events.append(e)
            
        if len(unique_events) < 2:
            return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.NO_SEQUENCE)
            
        # 3. Parse and sort timestamps
        parsed_events = []
        for e in unique_events:
            ts_val = e.get("timestamp")
            if not ts_val:
                # If any timestamp is completely missing, we have UNKNOWN ordering capability
                return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.INSUFFICIENT_EVIDENCE)
                
            try:
                if isinstance(ts_val, datetime):
                    dt = ts_val
                elif isinstance(ts_val, str):
                    # handle naive or aware ISO format
                    dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                else:
                    return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.INSUFFICIENT_EVIDENCE)
            except ValueError:
                return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.INSUFFICIENT_EVIDENCE)
                
            parsed_events.append({"event": e, "dt": dt})
            
        parsed_events.sort(key=lambda x: x["dt"])
        
        # 4. Check time window
        first_dt = parsed_events[0]["dt"]
        last_dt = parsed_events[-1]["dt"]
        diff_minutes = (last_dt - first_dt).total_seconds() / 60.0
        
        if diff_minutes > window_minutes:
            # The events fall outside the progression window
            return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.NO_SEQUENCE)
            
        # Now we evaluate factors
        score = 0.0
        evidence = []
        event_ids = [pe["event"].get("event_id", "unknown") for pe in parsed_events]
        
        # Factor A: Temporal Order (Implied since we got here and diff < window)
        score += 0.2
        evidence.append(TemporalEvidence(
            factor="TEMPORAL_ORDER",
            event_ids=event_ids,
            description=f"Events occurred sequentially within a {diff_minutes:.1f} minute window",
            classification="INFERRED"
        ))
        
        # Factor B: Actor Continuity
        actors = set()
        for pe in parsed_events:
            a = pe["event"].get("actor", {})
            if isinstance(a, dict):
                act_id = a.get("id") or a.get("identity_id") or "UNKNOWN_ACTOR"
                actors.add(act_id)
            elif isinstance(a, str):
                actors.add(a)
                
        if len(actors) == 1 and "UNKNOWN_ACTOR" not in actors:
            score += 0.3
            evidence.append(TemporalEvidence(
                factor="ACTOR_CONTINUITY",
                event_ids=event_ids,
                description="All events share the same actor identity",
                classification="OBSERVED"
            ))
        elif len(actors) > 1:
            # Different actors without relationship = no progression by default
            return self._build_empty_result(organization_id, actor_id, window_minutes, TemporalProgressionState.RELATED_EVENTS)
            
        # Factor C: Resource Continuity
        targets = set()
        for pe in parsed_events:
            t = pe["event"].get("target", {})
            if isinstance(t, dict):
                tgt_id = t.get("id") or t.get("resource_id") or "UNKNOWN_TARGET"
                targets.add(tgt_id)
            elif isinstance(t, str):
                targets.add(t)
                
        if len(targets) == 1 and "UNKNOWN_TARGET" not in targets:
            score += 0.2
            evidence.append(TemporalEvidence(
                factor="RESOURCE_CONTINUITY",
                event_ids=event_ids,
                description="Events target the exact same resource",
                classification="OBSERVED"
            ))
            
        # Factor D: Event Compatibility (Progression Patterns)
        categories = [pe["event"].get("event_type", "UNKNOWN") for pe in parsed_events]
        pattern_detected = self._evaluate_patterns(categories)
        if pattern_detected:
            score += 0.3
            evidence.append(TemporalEvidence(
                factor="EVENT_COMPATIBILITY",
                event_ids=event_ids,
                description=f"Events match known progression pattern: {pattern_detected}",
                classification="INFERRED"
            ))
            
        # Final classification
        score = min(1.0, max(0.0, score))
        
        if score >= 0.75:
            state = TemporalProgressionState.STRONG_PROGRESSION
        elif score >= 0.45:
            state = TemporalProgressionState.PARTIAL_PROGRESSION
        else:
            state = TemporalProgressionState.RELATED_EVENTS
            
        return TemporalProgressionResult(
            organization_id=organization_id,
            actor_id=actor_id,
            ordered_events=event_ids,
            window_minutes=window_minutes,
            progression_score=round(score, 2),
            state=state,
            evidence=evidence
        )
        
    def _evaluate_patterns(self, categories: List[str]) -> Optional[str]:
        # Simple finite state sequences based on SecurityEventCategory
        seq = " -> ".join(categories)
        
        if "LOGIN" in seq and "PERMISSION_CHANGED" in seq and ("READ" in seq or "ACCESS" in seq):
            return "CREDENTIAL_TO_PRIVILEGE_TO_ACCESS"
            
        if "LOGIN" in seq and "OBJECT_READ" in seq and "DATA_EXPORT" in seq:
            return "CREDENTIAL_TO_EXFILTRATION"
            
        if "RESOURCE_MODIFIED" in seq and "DELETED" in seq:
            return "MODIFICATION_TO_DESTRUCTION"
            
        if "MASS_DELETE" in seq or "BACKUP_DELETED" in seq or "SNAPSHOT_DELETED" in seq:
            if seq.count("DELETE") > 1:
                return "DESTRUCTION_AND_RECOVERY_SABOTAGE"
                
        return None

    def _build_empty_result(self, org_id: str, actor_id: Optional[str], window: int, state: TemporalProgressionState) -> TemporalProgressionResult:
        return TemporalProgressionResult(
            organization_id=org_id,
            actor_id=actor_id,
            ordered_events=[],
            window_minutes=window,
            progression_score=0.0,
            state=state,
            evidence=[]
        )
