from typing import Dict, Any, List
from datetime import datetime

from security.engine.detectors.base import BaseDetector, DetectionResult, DetectionEvidence
from app.models.security_event import SecurityEvent, SecurityEventCategory

class RansomwareDestructionDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "RansomwareDestructionDetector"
        
    @property
    def attack_type(self) -> str:
        return "RANSOMWARE_DESTRUCTION"

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        evidence = []
        score = 0.0
        
        action = (event.action or "").lower()
        event_type = event.event_type or ""
        metadata = event.metadata or {}
        
        target_id = event.target.get("native_id") if event.target else None
        
        # Determine context constraints
        baseline_deletions = twin_context.get("actor_baseline_deletions", 0)
        baseline_modifications = twin_context.get("actor_baseline_modifications", 0)
        
        objects_deleted = metadata.get("objects_deleted", 1) if "delete" in action else 0
        objects_modified = metadata.get("objects_modified", 1) if "modi" in action or "update" in action or "put" in action else 0

        # 1 & 4: Deletion & Backup/Snapshot Destruction
        is_delete_event = event_type == SecurityEventCategory.RESOURCE_DELETED or "delete" in action or "remove" in action
        
        is_backup_destruction = any(kw in action for kw in ["snapshot", "backup", "recovery", "version"]) and is_delete_event
        
        if is_delete_event:
            score += 0.05
            
            if objects_deleted > 10 and objects_deleted > (baseline_deletions * 5):
                score += 0.45
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Abnormal mass deletion observed: {objects_deleted} objects deleted",
                    severity="HIGH",
                    timestamp=event.timestamp or datetime.utcnow()
                ))
            elif objects_deleted > 1:
                score += 0.25
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Repeated destructive activity: {objects_deleted} objects deleted",
                    severity="MEDIUM",
                    timestamp=event.timestamp or datetime.utcnow()
                ))

        if is_backup_destruction:
            score += 0.45
            evidence.append(DetectionEvidence(
                event_id=event.event_id,
                description=f"Backup/Snapshot destruction activity: {action} on {target_id}",
                severity="CRITICAL",
                timestamp=event.timestamp or datetime.utcnow()
            ))

        # 2: Mass Modification
        is_modify_event = event_type == SecurityEventCategory.RESOURCE_MODIFIED or "modi" in action or "put" in action or "update" in action
        if is_modify_event and objects_modified > 10 and objects_modified > (baseline_modifications * 5):
            score += 0.25
            evidence.append(DetectionEvidence(
                event_id=event.event_id,
                description=f"Abnormal mass modification observed: {objects_modified} objects modified",
                severity="HIGH",
                timestamp=event.timestamp or datetime.utcnow()
            ))

        # 3: Encryption-like Activity
        is_encryption_activity = "encrypt" in action or "kms" in action
        if is_encryption_activity and (is_modify_event or "config" in action):
            score += 0.25
            evidence.append(DetectionEvidence(
                event_id=event.event_id,
                description=f"Encryption-related configuration or modification: {action}",
                severity="MEDIUM",
                timestamp=event.timestamp or datetime.utcnow()
            ))

        # 6: Strong Historical Deviation
        if (is_delete_event or is_modify_event) and target_id and target_id not in twin_context.get("actor_historical_targets", []):
            if len(twin_context.get("actor_historical_targets", [])) > 0:
                score += 0.20
                evidence.append(DetectionEvidence(
                    event_id=event.event_id,
                    description=f"Strong historical deviation: Actor modifying/deleting unhistorical target {target_id}",
                    severity="MEDIUM",
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
