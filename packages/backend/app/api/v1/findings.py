from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from security.models.finding import Finding
from app.models.cloud import CloudAsset
from app.services.scanner import run_cloud_scan
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid

# Import security engines
from security.engine.mitre import MitreService
from security.engine.risk_engine_v2 import RiskEngineV2
from app.cloud.aws.context.asset_context import AssetContextBuilder

router = APIRouter()

class StatusUpdate(BaseModel):
    status: str

class AssignUpdate(BaseModel):
    user_id: str

class NoteCreate(BaseModel):
    content: str

@router.get("/")
def get_all_findings(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    result = []
    
    mitre_service = MitreService()
    
    for f in findings:
        f_dict = f.dict() if hasattr(f, 'dict') else f.__dict__
        mappings = mitre_service.get_mappings_for_finding(f_dict)
        
        result.append({
            "finding_id": str(f.id),
            "id": str(f.id),
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value.capitalize() if hasattr(f.severity, 'value') else str(f.severity).capitalize(),
            "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "cloud_provider": f.cloud_provider,
            "resource_name": getattr(f, 'resource_name', ''),
            "assigned_to": getattr(f, 'assigned_to', None),
            "notes": getattr(f, 'notes', []),
            "timeline": getattr(f, 'timeline', []),
            "mitre_mappings": [m.to_dict() for m in mappings],
            "evidence": f.evidence or {},
            "remediation": f.remediation_steps[0] if f.remediation_steps and isinstance(f.remediation_steps, list) else "Apply correct security control configurations."
        })
    return {"findings": result}

@router.get("/{finding_id}")
def get_finding_detail(finding_id: str, db: Session = Depends(get_db)):
    # Find in DB
    uuid_id = None
    try:
        uuid_id = uuid.UUID(finding_id)
    except Exception:
        pass
        
    f = None
    if uuid_id:
        f = db.query(Finding).filter(Finding.id == uuid_id).first()
    else:
        # Fallback to string id filter
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        
    if not f:
        # Fallback to finding list search
        all_f = db.query(Finding).all()
        f = next((x for x in all_f if str(x.id) == finding_id), None)

    if not f:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    f_dict = f.dict() if hasattr(f, 'dict') else f.__dict__
    
    # Calculate Risk Score
    risk_engine = RiskEngineV2()
    context_builder = AssetContextBuilder()
    
    asset = db.query(CloudAsset).filter(CloudAsset.resource_id == f.resource_id).first()
    ctx_dict = {}
    if asset:
        ctx = context_builder.build_context({
            "asset_id": asset.resource_id,
            "type": asset.type,
            "configuration": asset.metadata_json or {},
            "metadata": {"collection_status": "complete"}
        }, [])
        ctx_dict = ctx.to_dict()
    else:
        # fallback context
        ctx_dict = {
            "exposure": {"level": "private", "evidence": []},
            "criticality": {"level": "normal"},
            "privilege": {"level": "unknown"},
            "collection_status": "complete"
        }
        
    risk_score_obj = risk_engine.calculate_risk(f_dict, ctx_dict, [])
    
    # MITRE Mappings
    mitre_service = MitreService()
    mappings = mitre_service.get_mappings_for_finding(f_dict)

    return {
        "finding_id": str(f.id),
        "id": str(f.id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value.capitalize() if hasattr(f.severity, 'value') else str(f.severity).capitalize(),
        "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "cloud_provider": f.cloud_provider,
        "resource_name": getattr(f, 'resource_name', ''),
        "assigned_to": getattr(f, 'assigned_to', None),
        "notes": getattr(f, 'notes', []),
        "timeline": getattr(f, 'timeline', []),
        "risk_score": risk_score_obj.score,
        "risk_details": risk_score_obj.to_dict(),
        "mitre_mappings": [m.to_dict() for m in mappings],
        "evidence": f.evidence or {},
        "remediation": f.remediation_steps[0] if f.remediation_steps and isinstance(f.remediation_steps, list) else "Apply correct security control configurations."
    }

@router.patch("/{finding_id}/status")
def update_finding_status(finding_id: str, request: StatusUpdate, db: Session = Depends(get_db)):
    uuid_id = None
    try:
        uuid_id = uuid.UUID(finding_id)
    except Exception:
        pass
        
    f = None
    if uuid_id:
        f = db.query(Finding).filter(Finding.id == uuid_id).first()
    else:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        
    if not f:
        all_f = db.query(Finding).all()
        f = next((x for x in all_f if str(x.id) == finding_id), None)
        
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    old_status = f.status.value if hasattr(f.status, 'value') else str(f.status)
    f.status = request.status
    
    # Add timeline entry
    timeline = getattr(f, 'timeline', []) or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Status Updated",
        "description": f"Status changed from {old_status} to {request.status} by analyst."
    })
    f.timeline = timeline
    
    db.commit()
    return {"success": True, "status": request.status}

@router.patch("/{finding_id}/assign")
def assign_finding(finding_id: str, request: AssignUpdate, db: Session = Depends(get_db)):
    uuid_id = None
    try:
        uuid_id = uuid.UUID(finding_id)
    except Exception:
        pass
        
    f = None
    if uuid_id:
        f = db.query(Finding).filter(Finding.id == uuid_id).first()
    else:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        
    if not f:
        all_f = db.query(Finding).all()
        f = next((x for x in all_f if str(x.id) == finding_id), None)
        
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    f.assigned_to = request.user_id
    
    # Add timeline entry
    timeline = getattr(f, 'timeline', []) or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Assigned User",
        "description": f"Assigned to {request.user_id}."
    })
    f.timeline = timeline
    
    db.commit()
    return {"success": True, "assigned_to": request.user_id}

@router.post("/{finding_id}/notes")
def add_finding_note(finding_id: str, request: NoteCreate, db: Session = Depends(get_db)):
    uuid_id = None
    try:
        uuid_id = uuid.UUID(finding_id)
    except Exception:
        pass
        
    f = None
    if uuid_id:
        f = db.query(Finding).filter(Finding.id == uuid_id).first()
    else:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        
    if not f:
        all_f = db.query(Finding).all()
        f = next((x for x in all_f if str(x.id) == finding_id), None)
        
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    notes = getattr(f, 'notes', []) or []
    notes.append({
        "id": str(uuid.uuid4()),
        "author": "Analyst",
        "content": request.content,
        "created_at": datetime.utcnow().isoformat()
    })
    f.notes = notes
    
    # Add timeline entry
    timeline = getattr(f, 'timeline', []) or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Note Added",
        "description": "Analyst added a security note."
    })
    f.timeline = timeline
    
    db.commit()
    return {"success": True, "notes": notes}

@router.get("/assets")
def get_all_assets(db: Session = Depends(get_db)):
    assets = db.query(CloudAsset).all()
    result = []
    for asset in assets:
        result.append({
            "id": str(asset.id),
            "resource_id": asset.resource_id,
            "name": asset.name,
            "type": asset.type,
            "region": asset.region,
            "provider": asset.provider.value if hasattr(asset.provider, 'value') else str(asset.provider)
        })
    return {"assets": result}

@router.post("/scan")
def trigger_cloud_scan(db: Session = Depends(get_db)):
    try:
        scan_res = run_cloud_scan(db)
        return {"success": True, "data": scan_res}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Cloud scan execution failed: {str(e)}")
