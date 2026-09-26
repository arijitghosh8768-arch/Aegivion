from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.database import get_db
from app.database.supabase_client import supabase
from app.repositories.security_event_repository import SecurityEventRepository
from security.engine.security_event_normalizer import SecurityEventNormalizer
from security.engine.security_event_deduplicator import SecurityEventDeduplicator
from security.engine.security_digital_twin import SecurityDigitalTwin
from security.engine.security_event_detector_adapter import SecurityEventDetectorAdapter
from security.engine.security_event_correlator import SecurityEventCorrelator

router = APIRouter()

@router.get("")
def list_events(
    current_user: Dict[str, Any] = Depends(get_current_user), 
    limit: int = 50,
    db: Session = Depends(get_db)
):
    user_org_id = get_current_organization(current_user, db)

    try:
        event_repo = SecurityEventRepository(supabase)
        events = event_repo.get_recent_by_organization(user_org_id, limit)
        return {"events": events}
    except Exception as e:
        return {"events": [], "error": str(e)}

@router.post("")
def ingest_event(
    event_data: dict, 
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_org_id = get_current_organization(current_user, db)
    
    try:
        # 1. Normalize and Validate (Pydantic validates inherently)
        provider = event_data.get("provider", "aws").lower()
        canonical_event = SecurityEventNormalizer.normalize(provider, event_data, user_org_id)
        
        # 2. Deduplicate
        dedup = SecurityEventDeduplicator(supabase)
        if dedup.is_duplicate(canonical_event):
            return {"status": "ignored", "reason": "duplicate"}
            
        # 3. Persist Canonical Event (preserving original table compatibility)
        insert_data = canonical_event.dict()
        insert_data['timestamp'] = canonical_event.timestamp.isoformat()
        
        res = supabase.table("security_events").insert(insert_data).execute()
        
        # 4. Security Digital Twin Update
        twin = SecurityDigitalTwin(db, user_org_id)
        impact = twin.evaluate_event_impact(canonical_event)
        
        # 5. Detector Adapter
        detector_results = SecurityEventDetectorAdapter.run_detectors(canonical_event, impact)
        
        # 6. Correlation Engine
        storyline = SecurityEventCorrelator.correlate_signals(canonical_event, detector_results)
        
        # We stop here before Attack Activation Score
        return {
            "status": "accepted", 
            "event_id": canonical_event.event_id, 
            "impact": impact,
            "detectors": detector_results,
            "storyline": storyline.dict() if storyline else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
