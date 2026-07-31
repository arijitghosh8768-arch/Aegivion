from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from security.models.finding import Finding
from app.models.cloud import CloudAsset
from app.services.scanner import run_cloud_scan

router = APIRouter()

@router.get("/")
def get_all_findings(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    result = []
    for f in findings:
        result.append({
            "finding_id": str(f.id),
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value.capitalize() if hasattr(f.severity, 'value') else str(f.severity).capitalize(),
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "cloud_provider": f.cloud_provider,
            "remediation": f.remediation_steps[0] if f.remediation_steps else "Apply correct security control configurations."
        })
    return {"findings": result}

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
