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
async def ingest_event(
    event_data: dict, 
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_org_id = get_current_organization(current_user, db)
    
    try:
        from app.services.security_event_ingestion_service import SecurityEventIngestionService
        from security.engine.agent_controller import AegivionAgentController
        
        # Instantiate controller 
        agent_controller = AegivionAgentController(organization_id=user_org_id)
        # Note: in a real environment this controller might be a singleton or retrieved from app state.
        
        service = SecurityEventIngestionService(
            db_client=supabase, 
            db_session=db, 
            agent_controller=agent_controller
        )
        
        context = {
            "organization_id": user_org_id,
            "provider": event_data.get("provider", "aws")
        }
        
        result = await service.ingest(event_data, context)
        
        if result["status"] == "failed":
            raise HTTPException(status_code=400, detail=result.get("reason"))
            
        return result
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
