from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from app.database import get_db
from app.core.security import get_current_user
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
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    # 1. Fetch compliance results from database
    results = db.query(ComplianceControlResult).filter(ComplianceControlResult.organization_id == user_org_id).all()
    
    # If database is empty, generate standard mock compliance entries for CIS AWS Benchmark v3
    if not results:
        # Check active findings in DB to make the assessment dynamic
        findings = db.query(Finding).all()
        if user_org_id:
            findings = [f for f in findings if str(getattr(f, 'organization_id', '')) == str(user_org_id)]
            
        has_public_ssh = any("ssh" in f.title.lower() or "22" in f.description.lower() for f in findings)
        has_public_s3 = any("s3" in f.title.lower() or "public" in f.description.lower() for f in findings)
        
        mfa_status = ComplianceStatus.FAIL
        ssh_status = ComplianceStatus.FAIL if has_public_ssh else ComplianceStatus.PASS
        s3_status = ComplianceStatus.FAIL if has_public_s3 else ComplianceStatus.PASS
        logging_status = ComplianceStatus.NOT_ASSESSED
        
        mock_results = [
            ComplianceControlResult(
                organization_id=user_org_id,
                control_code="1.12",
                title="MFA protection for IAM administrative users",
                category="Identity & Access",
                severity="critical",
                status=mfa_status,
                affected_resources=["aws:iam:user:security-admin-01"],
                evidence_refs=["EV-001"],
                finding_refs=["F-00102"] if mfa_status == ComplianceStatus.FAIL else []
            ),
            ComplianceControlResult(
                organization_id=user_org_id,
                control_code="4.1",
                title="No 0.0.0.0/0 ingress on port 22 (SSH)",
                category="Network Security",
                severity="high",
                status=ssh_status,
                affected_resources=["aws:ec2:i-example"] if ssh_status == ComplianceStatus.FAIL else [],
                evidence_refs=["EV-002"],
                finding_refs=["F-001"] if ssh_status == ComplianceStatus.FAIL else []
            ),
            ComplianceControlResult(
                organization_id=user_org_id,
                control_code="2.1.5",
                title="Ensure S3 Buckets have Block Public Access enabled",
                category="Storage Security",
                severity="critical",
                status=s3_status,
                affected_resources=["s3:public-production-data"] if s3_status == ComplianceStatus.FAIL else [],
                evidence_refs=["EV-003"],
                finding_refs=["F-00103"] if s3_status == ComplianceStatus.FAIL else []
            ),
            ComplianceControlResult(
                organization_id=user_org_id,
                control_code="3.1",
                title="Ensure multi-region CloudTrail logging is enabled",
                category="Logging & Monitoring",
                severity="medium",
                status=logging_status,
                affected_resources=[],
                evidence_refs=["EV-004"],
                finding_refs=[]
            )
        ]
        
        for mr in mock_results:
            db.add(mr)
        db.commit()
        results = db.query(ComplianceControlResult).filter(ComplianceControlResult.organization_id == user_org_id).all()

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
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    # Try fetching control summary first to ensure mock initialization
    get_compliance_summary(db, current_user)
    
    control = db.query(ComplianceControlResult).filter(
        ComplianceControlResult.control_code == control_code,
        ComplianceControlResult.organization_id == user_org_id
    ).first()
    
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
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    control = db.query(ComplianceControlResult).filter(
        ComplianceControlResult.control_code == control_code,
        ComplianceControlResult.organization_id == user_org_id
    ).first()
    
    if not control:
        raise HTTPException(status_code=404, detail="Compliance control not found")

    from ai.services.compliance_reasoner import ComplianceReasonerService
    reasoner = ComplianceReasonerService()
    explanation = await reasoner.explain_control(control.dict())
    return explanation
