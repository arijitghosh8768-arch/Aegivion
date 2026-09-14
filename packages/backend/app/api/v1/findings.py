from fastapi import APIRouter, Depends, HTTPException, Request
from app.api.deps import require_permission, log_audit_action
from app.core.security import get_current_user

from sqlalchemy.orm import Session
from app.database import get_db
from security.models.finding import Finding
from app.models.cloud import CloudAsset
from app.models.organization import Organization
from app.services.scanner import run_cloud_scan
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid

# Import security engines
from security.engine.mitre import MitreService
from security.engine.risk_engine_v2 import RiskEngineV2
from app.cloud.aws.context.asset_context import AssetContextBuilder
from app.core.rate_limit import limiter

router = APIRouter()

class StatusUpdate(BaseModel):
    status: str

class AssignUpdate(BaseModel):
    user_id: str

class ExceptionCreate(BaseModel):
    reason: str

class NoteCreate(BaseModel):
    content: str

@router.get("/")
def get_all_findings(db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    findings = db.query(Finding).all()
    user_org_id = getattr(current_user, "organization_id", None) if isinstance(current_user, dict) else current_user.get("organization_id", None) if current_user else None
    
    if user_org_id:
        findings = [f for f in findings if str(getattr(f, 'organization_id', '')) == str(user_org_id)]

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
def get_finding_detail(finding_id: str, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):

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

    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")


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
    
    # M2 Day 33 Advanced Contextual Recalculation math:
    # Base Severity + Criticality + Exposure + Privilege + Sensitivity + Compliance + Recent Change
    base_severity = 45
    if str(f.severity).lower() == 'critical': base_severity = 80
    elif str(f.severity).lower() == 'high': base_severity = 65
    elif str(f.severity).lower() == 'low': base_severity = 25
    
    criticality_mod = 0
    if asset:
        criticality_level = getattr(asset, "business_criticality", "UNKNOWN").upper()
        if criticality_level == "CRITICAL": criticality_mod = 15
        elif criticality_level == "HIGH": criticality_mod = 10
        elif criticality_level == "MEDIUM": criticality_mod = 5
        
    exposure_mod = 10 if getattr(asset, "environment", "DEVELOPMENT").upper() == "PRODUCTION" else 0
    sensitivity_mod = 10 if getattr(asset, "data_sensitivity", "UNKNOWN").upper() == "SENSITIVE" else 0
    privilege_mod = 10
    attack_path_mod = 8
    compliance_mod = 5
    recent_change_mod = 5
    
    raw_total = base_severity + criticality_mod + exposure_mod + sensitivity_mod + privilege_mod + attack_path_mod + compliance_mod + recent_change_mod
    final_score = min(100, raw_total)
    
    priority = "P3"
    if final_score >= 90: priority = "P1"
    elif final_score >= 75: priority = "P2"
    elif final_score >= 50: priority = "P3"
    else: priority = "P4"

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
        "risk_score": final_score,
        "priority": priority,
        "risk_details": {
            "score": final_score,
            "priority": priority,
            "factors": {
                "base_severity": base_severity,
                "asset_criticality": criticality_mod,
                "internet_exposure": exposure_mod,
                "privilege": privilege_mod,
                "attack_path": attack_path_mod,
                "data_sensitivity": sensitivity_mod,
                "compliance": compliance_mod,
                "recent_change": recent_change_mod
            }
        },
        "mitre_mappings": [m.to_dict() for m in mappings],
        "evidence": f.evidence or {},
        "remediation": f.remediation_steps[0] if f.remediation_steps and isinstance(f.remediation_steps, list) else "Apply correct security control configurations."
    }

@router.patch("/{finding_id}/status")
@require_permission("manage_findings")
def update_finding_status(finding_id: str, request: StatusUpdate, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):

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

    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")

    log_audit_action("add_note", "finding", finding_id, str(current_user.get("id", "system")), str(user_org_id), {})


    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")

    log_audit_action("assign_finding", "finding", finding_id, str(current_user.get("id", "system")), str(user_org_id), {"assigned_to": request.user_id})

        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")

    log_audit_action("update_status", "finding", finding_id, str(current_user.get("id", "system")), str(user_org_id), {"status": request.status})

        
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

@router.post("/{finding_id}/assign")
def assign_finding(finding_id: str, request: AssignUpdate, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
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
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        
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
@require_permission("manage_findings")
def add_finding_note(finding_id: str, request: NoteCreate, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):

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
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        
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


@router.post("/{finding_id}/exceptions")
def create_finding_exception(finding_id: str, request: ExceptionCreate, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    import uuid
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
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        
    org = db.query(Organization).first()
    require_approval = False
    if org and hasattr(org, 'security_policy') and org.security_policy:
        require_approval = org.security_policy.get("require_exception_approval", False)
        
    status = "pending_approval" if require_approval else "suppressed"
    f.status = status
    
    ext_id = str(uuid.uuid4())
    timeline = getattr(f, 'timeline', []) or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Exception Requested",
        "description": f"Exception requested for reason: {request.reason}. Status set to {status}.",
        "exception_id": ext_id
    })
    f.timeline = timeline
    
    db.commit()
    return {"success": True, "status": status, "exception_id": ext_id}

@router.post("/{finding_id}/exceptions/{ext_id}/approve")
def approve_finding_exception(finding_id: str, ext_id: str, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    import uuid
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
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        
    if getattr(f, 'status', '') != "pending_approval":
        raise HTTPException(status_code=400, detail="Finding is not pending approval")
        
    f.status = "suppressed"
    timeline = getattr(f, 'timeline', []) or []
    timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "title": "Exception Approved",
        "description": f"Exception {ext_id} approved. Status set to suppressed."
    })
    f.timeline = timeline
    
    db.commit()
    return {"success": True, "status": "suppressed"}

@router.get("/assets")
def get_all_assets(db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    
    assets_query = db.query(CloudAsset)
    if user_org_id:
        assets_query = assets_query.filter(CloudAsset.organization_id == user_org_id)
        
    assets = assets_query.all()
    result = []
    for asset in assets:
        result.append({
            "id": str(asset.id),
            "resource_id": asset.resource_id,
            "name": asset.name,
            "type": asset.type,
            "region": asset.region,
            "provider": asset.provider.value if hasattr(asset.provider, 'value') else str(asset.provider),
            "environment": getattr(asset, "environment", "DEVELOPMENT"),
            "owner": getattr(asset, "owner", "UNKNOWN"),
            "department": getattr(asset, "department", "UNKNOWN"),
            "application": getattr(asset, "application", "UNKNOWN"),
            "data_sensitivity": getattr(asset, "data_sensitivity", "UNKNOWN"),
            "business_criticality": getattr(asset, "business_criticality", "UNKNOWN")
        })
    return {"assets": result}

@router.get("/assets/{asset_id}/context")
def get_asset_context(asset_id: str, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve full asset context and business criticality values (M1 context API)"""
    asset = db.query(CloudAsset).filter(CloudAsset.resource_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(asset, 'organization_id', '')) != str(user_org_id) and getattr(asset, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this asset")
        
    return {
        "asset_id": asset.resource_id,
        "environment": getattr(asset, "environment", "DEVELOPMENT"),
        "owner": getattr(asset, "owner", "UNKNOWN"),
        "department": getattr(asset, "department", "UNKNOWN"),
        "application": getattr(asset, "application", "UNKNOWN"),
        "data_sensitivity": getattr(asset, "data_sensitivity", "UNKNOWN"),
        "business_criticality": getattr(asset, "business_criticality", "UNKNOWN")
    }

@router.patch("/assets/{asset_id}/context")
def update_asset_context(
    asset_id: str,
    environment: Optional[str] = None,
    owner: Optional[str] = None,
    department: Optional[str] = None,
    application: Optional[str] = None,
    data_sensitivity: Optional[str] = None,
    business_criticality: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Audit-trail authorization log updating target asset context (M1 Context update)"""
    asset = db.query(CloudAsset).filter(CloudAsset.resource_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(asset, 'organization_id', '')) != str(user_org_id) and getattr(asset, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this asset")
        
    if environment: asset.environment = environment
    if owner: asset.owner = owner
    if department: asset.department = department
    if application: asset.application = application
    if data_sensitivity: asset.data_sensitivity = data_sensitivity
    if business_criticality: asset.business_criticality = business_criticality
    
    db.commit()
    return {"success": True}

@router.get("/{finding_id}/history")
def get_finding_history_occurrences(finding_id: str, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve occurrence deduplication tracking updates and lifecycle timelines (M2/M4 timelines)"""
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
        raise HTTPException(status_code=404, detail="Finding not found")
        
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(f, 'organization_id', '')) != str(user_org_id) and getattr(f, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        
    # Generate structural timeline history based on first/last seen occurrences
    events = [
        {"event": "FIRST_SEEN", "timestamp": getattr(f, "first_seen", datetime.utcnow()).isoformat() if isinstance(getattr(f, "first_seen", datetime.utcnow()), datetime) else str(getattr(f, "first_seen", datetime.utcnow())), "description": "Finding first registered in infrastructure."},
        {"event": "OBSERVED", "timestamp": getattr(f, "last_seen", datetime.utcnow()).isoformat() if isinstance(getattr(f, "last_seen", datetime.utcnow()), datetime) else str(getattr(f, "last_seen", datetime.utcnow())), "description": f"Finding re-observed. Occurrence count: {getattr(f, 'occurrence_count', 1)}"}
    ]
    
    if getattr(f, "status") == "resolved":
        events.append({"event": "RESOLVED", "timestamp": getattr(f, "resolved_at", datetime.utcnow()).isoformat(), "description": "Resolved by security patch."})
    elif getattr(f, "reopened_at", None):
        events.append({"event": "REOPENED", "timestamp": getattr(f, "reopened_at").isoformat(), "description": "Finding re-exposed."})
        
    return {
        "finding_id": str(f.id),
        "fingerprint": getattr(f, "fingerprint", f"{f.rule_id}:{f.resource_id}"),
        "occurrence_count": getattr(f, "occurrence_count", 1),
        "first_seen": getattr(f, "first_seen", datetime.utcnow()).isoformat() if isinstance(getattr(f, "first_seen", datetime.utcnow()), datetime) else str(getattr(f, "first_seen", datetime.utcnow())),
        "last_seen": getattr(f, "last_seen", datetime.utcnow()).isoformat() if isinstance(getattr(f, "last_seen", datetime.utcnow()), datetime) else str(getattr(f, "last_seen", datetime.utcnow())),
        "events": events
    }

import structlog
from app.core.metrics import scans_total

logger = structlog.get_logger(__name__)

@router.post("/scan")
@require_permission("manage_findings")
@limiter.limit("2/minute")
def trigger_cloud_scan(request: Request, db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    log_audit_action("trigger_scan", "cloud", "all", str(current_user.get("id", "system")), str(user_org_id), {})
    
    scans_total.inc()
    logger.info("cloud_scan_triggered", user_id=str(current_user.get("id", "system")), org_id=str(user_org_id))

    try:
        scan_res = run_cloud_scan(db)
        logger.info("cloud_scan_successful", scan_res=scan_res)
        return {"success": True, "data": scan_res}
    except Exception as e:
        logger.error("cloud_scan_failed", error=str(e), exc_info=True)
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Cloud scan execution failed: {str(e)}")

