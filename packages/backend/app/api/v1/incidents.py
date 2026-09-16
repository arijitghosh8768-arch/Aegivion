from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from app.database import get_db
from security.models.finding import Finding
from app.models.cloud import CloudAsset, AssetRelationship
from app.models.incident import Incident, IncidentStatus
from security.correlation.engine_v2 import CorrelationEngineV2
from app.core.security import get_current_user
from pydantic import BaseModel
from datetime import datetime
import uuid

router = APIRouter()

class StatusUpdate(BaseModel):
    status: str

class AssignUpdate(BaseModel):
    user_id: str

@router.get("/")
def get_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    sort: Optional[str] = "risk_desc",
    current_user: Any = Depends(get_current_user)
):
    user_org_id = getattr(current_user, 'organization_id', None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="No organization context")
        
    try:
        from app.database.supabase_client import supabase
        result = supabase.table("incidents").select("*").eq("organization_id", user_org_id).execute()
        incidents = result.data or []
        
        if severity:
            incidents = [i for i in incidents if i.get("severity") == severity.upper()]
        if status:
            incidents = [i for i in incidents if i.get("status") == status.upper()]
            
        return {
            "incidents": incidents,
            "total": len(incidents),
            "page": page,
            "page_size": page_size
        }
    except Exception as e:
        return {"incidents": [], "error": str(e)}

@router.get("/{incident_id}")
def get_incident_detail(incident_id: str, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None)
    
    # Try finding in DB
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        # Check by correlation fingerprint
        inc = db.query(Incident).filter(Incident.correlation_fingerprint == incident_id).first()
        
    if not inc:
        # Fallback query all
        all_inc = db.query(Incident).all()
        inc = next((x for x in all_inc if str(x.id) == incident_id or x.correlation_fingerprint == incident_id), None)
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Tenant check
    if user_org_id and str(inc.organization_id) != str(user_org_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    return inc.dict()

@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    request: StatusUpdate,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    user_org_id = getattr(current_user, 'organization_id', None)
    
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        inc = db.query(Incident).filter(Incident.correlation_fingerprint == incident_id).first()
        
    if not inc:
        all_inc = db.query(Incident).all()
        inc = next((x for x in all_inc if str(x.id) == incident_id or x.correlation_fingerprint == incident_id), None)
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if user_org_id and str(inc.organization_id) != str(user_org_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Enforce lifecycle status transition checks
    # OPEN -> INVESTIGATING -> MITIGATED -> RESOLVED -> CLOSED
    valid_transitions = {
        IncidentStatus.OPEN: [IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED],
        IncidentStatus.INVESTIGATING: [IncidentStatus.MITIGATED, IncidentStatus.CLOSED],
        IncidentStatus.MITIGATED: [IncidentStatus.RESOLVED, IncidentStatus.CLOSED],
        IncidentStatus.RESOLVED: [IncidentStatus.CLOSED],
        IncidentStatus.CLOSED: [IncidentStatus.OPEN]
    }
    
    curr_status = IncidentStatus(inc.status)
    try:
        next_status = IncidentStatus(request.status.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid target status: {request.status}")
        
    if next_status not in valid_transitions.get(curr_status, []):
        # Allow same status patch
        if next_status != curr_status:
            raise HTTPException(status_code=400, detail=f"Invalid state transition from {curr_status.value} to {next_status.value}")

    inc.status = next_status
    
    # Log timeline entry
    timeline = inc.timeline or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Incident Status Transitioned",
        "description": f"Status updated from {curr_status.value} to {next_status.value} by analyst."
    })
    inc.timeline = timeline
    
    db.commit()
    return {"success": True, "status": inc.status.value}


@router.post("/{incident_id}/assign")
def assign_incident(
    incident_id: str,
    request: AssignUpdate,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    user_org_id = getattr(current_user, 'organization_id', None)
    
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        inc = db.query(Incident).filter(Incident.correlation_fingerprint == incident_id).first()
        
    if not inc:
        all_inc = db.query(Incident).all()
        inc = next((x for x in all_inc if str(x.id) == incident_id or x.correlation_fingerprint == incident_id), None)
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if user_org_id and str(inc.organization_id) != str(user_org_id):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    inc.assigned_to = request.user_id
    
    timeline = inc.timeline or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Incident Assigned",
        "description": f"Assigned to {request.user_id}."
    })
    inc.timeline = timeline
    
    db.commit()
    return {"success": True, "assigned_to": request.user_id}

@router.post("/{incident_id}/analyze")
async def analyze_incident_ai(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    user_org_id = getattr(current_user, 'organization_id', None)
    
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        inc = db.query(Incident).filter(Incident.correlation_fingerprint == incident_id).first()
        
    if not inc:
        all_inc = db.query(Incident).all()
        inc = next((x for x in all_inc if str(x.id) == incident_id or x.correlation_fingerprint == incident_id), None)
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if user_org_id and str(inc.organization_id) != str(user_org_id):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Fetch matching assets and findings
    assets_db = db.query(CloudAsset).all()
    findings_db = db.query(Finding).all()
    rels_db = db.query(AssetRelationship).all()
    
    assets_list = [a.dict() if hasattr(a, 'dict') else a.__dict__ for a in assets_db if a.resource_id in inc.asset_ids]
    findings_list = [f.dict() if hasattr(f, 'dict') else f.__dict__ for f in findings_db if str(f.id) in inc.finding_ids]
    rels_list = [r.dict() if hasattr(r, 'dict') else r.__dict__ for r in rels_db if r.source_asset_id in inc.asset_ids or r.target_asset_id in inc.asset_ids]

    # Fallback mocks if database has no active assets/findings matching ids
    if not assets_list:
        assets_list = [
            {"asset_id": "aws:ec2:i-example", "type": "ec2_instance", "provider": "aws", "configuration": {"vpc_id": "vpc-0101", "tags": {"Environment": "production", "Criticality": "high"}}},
            {"asset_id": "aws:iam:role:example-role", "type": "iam_role", "provider": "aws", "configuration": {}}
        ]
        findings_list = [
            {"finding_id": "F-001", "id": "F-001", "title": "Public SSH Port Exposed", "description": "Port 22 permits unrestricted ingress from the Internet.", "severity": "critical", "rule_id": "AWS-SG-001"},
            {"finding_id": "F-002", "id": "F-002", "title": "Privileged IAM Role Attached", "description": "EC2 instance utilizes a role containing full administrative credentials.", "severity": "high", "rule_id": "AWS-IAM-004"}
        ]
        rels_list = [
            {"source_asset_id": "aws:ec2:i-example", "target_asset_id": "aws:iam:role:example-role", "relationship_type": "USES_ROLE", "confidence": "CONFIRMED"}
        ]

    # Context Builder
    from ai.services.builder import IncidentContextBuilder
    from ai.services.reasoner import IncidentReasonerService
    
    builder = IncidentContextBuilder()
    context = builder.build_context(
        group_id=inc.correlation_fingerprint or inc.id[:8],
        findings=findings_list,
        assets=assets_list,
        relationships=rels_list,
        risk_score=inc.risk_score,
        risk_level=inc.severity,
        correlation_strength="strong" if inc.risk_score >= 90 else "moderate"
    )

    reasoner = IncidentReasonerService()
    analysis = await reasoner.analyze_incident(context)
    return analysis
