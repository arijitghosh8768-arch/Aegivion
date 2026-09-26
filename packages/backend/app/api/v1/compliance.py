from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.repositories import ComplianceRepository
from app.models.compliance import ComplianceControlResult, ComplianceStatus
from security.models.finding import Finding
from app.models.cloud import CloudAsset, AssetRelationship
from datetime import datetime
import uuid

router = APIRouter()

@router.get("/summary")
def get_compliance_summary(
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Retrieve framework summaries, pass rate, and coverage metrics"""
    user_org_id = get_current_organization(current_user, db)
    
    # 1. Fetch compliance results from database
    compliance_repo = ComplianceRepository(db)
    results = compliance_repo.get_by_organization(user_org_id)

    # Calculate metrics
    total = len(results)
    passed = len([r for r in results if r.status == ComplianceStatus.PASS])
    failed = len([r for r in results if r.status == ComplianceStatus.FAIL])
    not_assessed = len([r for r in results if r.status == ComplianceStatus.NOT_ASSESSED])
    not_applicable = len([r for r in results if r.status == ComplianceStatus.NOT_APPLICABLE])
    
    assessed = total - not_assessed - not_applicable
    pass_rate = int((passed / assessed) * 100) if assessed > 0 else 0
    coverage = int((assessed / total) * 100) if total > 0 else 0
    
    return {
        "frameworks": [
            {
                "title": "CIS AWS Benchmark v3",
                "passed": passed,
                "failed": failed,
                "not_assessed": not_assessed,
                "not_applicable": not_applicable,
                "percent": pass_rate,
                "coverage": coverage,
                "total_controls": total,
                "items": [
                    {
                        "control_code": r.control_code,
                        "title": r.title,
                        "description": getattr(r, 'description', None),
                        "category": r.category,
                        "status": r.status.value if hasattr(r.status, 'value') else str(r.status)
                    }
                    for r in results
                ]
            }
        ],
        "overall": {
            "pass_rate": pass_rate,
            "coverage": coverage,
            "passed": passed,
            "failed": failed,
            "not_assessed": not_assessed,
            "not_applicable": not_applicable,
            "total_controls": total
        }
    }

@router.get("/controls/{control_code}")
def get_control_detail(
    control_code: str,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Retrieve detailed compliance control status and evidence references"""
    user_org_id = get_current_organization(current_user, db)
    
    # Try fetching control summary first to ensure mock initialization
    get_compliance_summary(db, current_user)
    
    compliance_repo = ComplianceRepository(db)
    control = compliance_repo.get_by_control_code(user_org_id, control_code)
    
    if not control:
        raise HTTPException(status_code=404, detail="Compliance control not found")
        
    return control.dict()

@router.post("/controls/{control_code}/explain")
async def explain_compliance_control(
    control_code: str,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Generate grounded AI explanation of the compliance status and limitation context"""
    user_org_id = get_current_organization(current_user, db)
    
    compliance_repo = ComplianceRepository(db)
    control = compliance_repo.get_by_control_code(user_org_id, control_code)
    
    if not control:
        raise HTTPException(status_code=404, detail="Compliance control not found")

    from ai.services.compliance_reasoner import ComplianceReasonerService
    reasoner = ComplianceReasonerService()
    explanation = await reasoner.explain_control(control.dict())
    return explanation
