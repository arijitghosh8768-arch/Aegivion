from typing import Dict, Any, List
from security.models.security_event_schema import SecurityEventSchema
from security.engine.attack_algorithms import (
    detect_credential_compromise,
    detect_data_exfiltration,
    detect_ransomware
)

class SecurityEventDetectorAdapter:
    """
    Adapter that converts canonical SecurityEventSchema instances 
    into the format expected by the existing attack algorithms, 
    and invokes the independent detectors.
    """
    
    @staticmethod
    def run_detectors(event: SecurityEventSchema, twin_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Passes a single event through the three existing detectors.
        In the future, this may pull historical events to satisfy stateful algorithms.
        """
        # Convert canonical event to the legacy/expected format of the detectors
        legacy_event = SecurityEventDetectorAdapter._to_legacy_format(event)
        
        # The existing algorithms expect a List of events and a List of assets.
        # For now, we pass the single event.
        events_list = [legacy_event]
        
        # We can pass an empty list of assets or use the twin context if available
        assets_list = []
        if twin_context and "target_context" in twin_context and twin_context["target_context"]:
            # Convert context to expected asset dict structure if needed
            assets_list.append(twin_context["target_context"])

        # 1. Credential Compromise
        cred_results = detect_credential_compromise(events_list)
        
        # 2. Data Exfiltration
        exfil_results = detect_data_exfiltration(events_list, assets_list)
        
        # 3. Ransomware
        ransomware_results = detect_ransomware(events_list, assets_list)
        
        return {
            "credential_compromise": cred_results,
            "data_exfiltration": exfil_results,
            "ransomware": ransomware_results
        }
        
    @staticmethod
    def _to_legacy_format(event: SecurityEventSchema) -> Dict[str, Any]:
        """Maps canonical schema back to the raw/legacy dict expected by algorithms."""
        return {
            "event_id": event.event_id,
            "event_type": event.action,      # Some algorithms check event_type
            "event_name": event.action,      # Others check event_name
            "status": "Success" if event.status.lower() == "success" else "Failure",
            "event_time": event.timestamp.isoformat() + "Z",
            "user_identity": {
                "arn": event.actor
            },
            "request_parameters": event.metadata.get("requestParameters", {}) if event.metadata else {}
        }
