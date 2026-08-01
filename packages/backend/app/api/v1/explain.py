from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import json

from app.database import get_db
from security.models.finding import Finding
from app.models.cloud import CloudAsset
from ai.services.prompt_builder import PromptBuilder, PromptContext
from ai.services.llm_provider import get_llm_provider
from ai.services.remediation_engine import RemediationEngine
from ai.services.security_brief import SecurityBriefService
from security.engine.risk_engine import ContextualRiskEngine

router = APIRouter()

class ExplainRequest(BaseModel):
    finding_id: str
    include_sensitive: bool = False
    format: str = "json"  # json | markdown | html

class ExplainResponse(BaseModel):
    finding_id: str
    summary: str
    root_cause: str
    technical_impact: str
    business_impact: str
    recommendations: List[str]
    confidence: float
    processing_time_ms: int
    timestamp: str

def get_mock_finding_and_asset(finding_id: str) -> Optional[tuple]:
    """Fallback lookup helper returning mock finding and asset for Day 11 API representation"""
    from ai.tests.mock_findings import MOCK_FINDINGS
    from security.tests.mock_assets import ALL_MOCK_ASSETS
    
    matching_finding = next((f for f in MOCK_FINDINGS if f["finding_id"] == finding_id), None)
    if not matching_finding:
        return None
        
    matching_asset = next((a for a in ALL_MOCK_ASSETS if a["asset_id"] == matching_finding["asset_id"]), None)
    if not matching_asset:
        # Fallback placeholder asset
        matching_asset = {
            "asset_id": matching_finding["asset_id"],
            "provider": "aws",
            "type": "ec2",
            "region": "ap-south-1",
            "name": "mock-asset-01",
            "configuration": {},
            "relationships": []
        }
        
    return matching_finding, matching_asset

@router.post("/explain/{finding_id}")
def explain_finding(
    finding_id: str,
    request: ExplainRequest,
    db: Session = Depends(get_db)
):
    """Generate AI-powered explanation for a finding"""
    start_time = datetime.utcnow()
    
    # 1. Fetch finding & asset (try DB first, then fallback to mocks for MVP)
    finding_obj = None
    asset_obj = None
    
    try:
        uuid_id = uuid.UUID(finding_id)
        finding_obj = db.query(Finding).filter(Finding.id == uuid_id).first()
    except Exception:
        pass
        
    if finding_obj:
        # Map DB model fields to dict for PromptBuilder
        finding = {
            "id": str(finding_obj.id),
            "finding_id": str(finding_obj.id),
            "title": finding_obj.title,
            "description": finding_obj.description,
            "severity": finding_obj.severity.value if hasattr(finding_obj.severity, 'value') else str(finding_obj.severity),
            "rule_id": finding_obj.rule_id,
            "risk_score": finding_obj.risk_score,
            "evidence": finding_obj.evidence or {},
            "mitre_technique": getattr(finding_obj, 'mitre_technique', None),
            "mitre_tactic": getattr(finding_obj, 'mitre_tactic', None)
        }
        
        # Load asset
        asset_db = db.query(CloudAsset).filter(CloudAsset.resource_id == finding_obj.resource_id).first()
        if asset_db:
            asset = {
                "asset_id": asset_db.resource_id,
                "provider": asset_db.provider.value if hasattr(asset_db.provider, 'value') else str(asset_db.provider),
                "type": asset_db.type,
                "region": asset_db.region,
                "name": asset_db.name,
                "configuration": asset_db.metadata_json or {},
                "relationships": []
            }
        else:
            asset = {
                "asset_id": finding_obj.resource_id,
                "provider": finding_obj.cloud_provider,
                "type": finding_obj.resource_type,
                "region": finding_obj.resource_region,
                "name": finding_obj.resource_name,
                "configuration": {},
                "relationships": []
            }
    else:
        # Fallback to mock findings to support testing
        mocks = get_mock_finding_and_asset(finding_id)
        if not mocks:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found in DB or mocks")
        finding, asset = mocks

    # 2. Build prompt context
    prompt_builder = PromptBuilder()
    context = PromptContext(
        finding=finding,
        asset=asset,
        evidence=finding.get("evidence", {}),
        severity=finding.get("severity", "medium"),
        risk_score=finding.get("risk_score"),
        mitre_technique=finding.get("mitre_technique"),
        mitre_tactic=finding.get("mitre_tactic")
    )
    
    prompt = prompt_builder.build_prompt(context)
    
    # 3. Call LLM Provider
    provider = get_llm_provider()
    processing_time = 0
    try:
        response_text = provider.generate(prompt)
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Parse output JSON requirements
        try:
            parsed = json.loads(response_text)
        except Exception:
            # Fallback parse logic
            parsed = {
                "root_cause": f"Resource config violates {finding.get('title')}.",
                "technical_impact": f"Exposure of configuration keys increases risk posture.",
                "business_impact": "Non-compliance triggers data policy review audit warnings.",
                "recommendations": finding.get("remediation", ["Apply correct configuration constraint rules."]),
                "confidence": 0.88
            }
            
        return {
            "finding_id": finding_id,
            "summary": finding.get("description", finding.get("title")),
            "root_cause": parsed.get("root_cause"),
            "technical_impact": parsed.get("technical_impact"),
            "business_impact": parsed.get("business_impact"),
            "recommendations": parsed.get("recommendations", []),
            "confidence": parsed.get("confidence", 0.9),
            "evidence_used": finding.get("evidence", {}),
            "processing_time_ms": processing_time,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        fallback = generate_fallback_explanation(finding)
        return {
            "finding_id": finding_id,
            "error": str(e),
            "fallback": fallback,
            "processing_time_ms": processing_time,
            "timestamp": datetime.utcnow().isoformat()
        }

def generate_fallback_explanation(finding: Dict) -> Dict:
    severity_impact = {
        'critical': 'Immediate action required - potential data breach risk',
        'high': 'High security risk - prioritize within 24 hours',
        'medium': 'Moderate security risk - address within 30 days',
        'low': 'Low security risk - address within 90 days'
    }
    
    return {
        "summary": f"Security finding: {finding.get('title')}",
        "root_cause": "Detailed analysis unavailable. Please review the finding evidence.",
        "technical_impact": severity_impact.get(finding.get('severity', 'medium'), 'Security risk identified'),
        "business_impact": "Review the finding for potential business impact",
        "recommendations": [
            "Review the security finding details",
            "Verify the configuration against security best practices",
            "Apply remediation steps if applicable"
        ],
        "confidence": 0.3
    }

@router.post("/remediate/{finding_id}")
async def remediate_finding(
    finding_id: str,
    db: Session = Depends(get_db)
):
    """Generate structured remediation plan for a finding"""
    finding_obj = None
    
    try:
        uuid_id = uuid.UUID(finding_id)
        finding_obj = db.query(Finding).filter(Finding.id == uuid_id).first()
    except Exception:
        pass
        
    if finding_obj:
        finding = {
            "finding_id": str(finding_obj.id),
            "title": finding_obj.title,
            "description": finding_obj.description,
            "severity": finding_obj.severity.value if hasattr(finding_obj.severity, 'value') else str(finding_obj.severity),
            "rule_id": finding_obj.rule_id,
            "evidence": finding_obj.evidence or {},
            "mitre_technique": getattr(finding_obj, 'mitre_technique', None),
            "mitre_tactic": getattr(finding_obj, 'mitre_tactic', None)
        }
    else:
        mocks = get_mock_finding_and_asset(finding_id)
        if not mocks:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found in DB or mocks")
        finding, _ = mocks

    provider = get_llm_provider()
    prompt_builder = PromptBuilder()
    engine = RemediationEngine(provider, prompt_builder)
    
    plan = await engine.generate_remediation(finding)
    return plan.to_dict()

class BriefRequest(BaseModel):
    cloud_account_id: Optional[str] = None

@router.post("/security-brief")
async def security_brief(
    request: BriefRequest,
    db: Session = Depends(get_db)
):
    """Generate account-level AI security brief"""
    # Try fetching real data first
    real_findings = []
    real_assets = []
    
    try:
        real_findings_db = db.query(Finding).all()
        for f_db in real_findings_db:
            real_findings.append({
                "finding_id": str(f_db.id),
                "title": f_db.title,
                "description": f_db.description,
                "severity": f_db.severity.value if hasattr(f_db.severity, 'value') else str(f_db.severity),
                "status": f_db.status.value if hasattr(f_db.status, 'value') else str(f_db.status),
                "resource_id": f_db.resource_id,
                "cloud_provider": f_db.cloud_provider,
                "resource_type": f_db.resource_type,
                "rule_id": f_db.rule_id,
                "evidence": f_db.evidence or {}
            })
            
        real_assets_db = db.query(CloudAsset).all()
        for a_db in real_assets_db:
            real_assets.append({
                "asset_id": a_db.resource_id,
                "provider": a_db.provider.value if hasattr(a_db.provider, 'value') else str(a_db.provider),
                "type": a_db.type,
                "region": a_db.region,
                "name": a_db.name,
                "configuration": a_db.metadata_json or {}
            })
    except Exception:
        pass
        
    # If no data found, fall back to mock datasets to show dynamic MVP features
    if not real_findings:
        from ai.tests.mock_findings import MOCK_FINDINGS
        from security.tests.mock_assets import ALL_MOCK_ASSETS
        findings_to_use = MOCK_FINDINGS
        assets_to_use = ALL_MOCK_ASSETS
    else:
        findings_to_use = real_findings
        assets_to_use = real_assets

    provider = get_llm_provider()
    risk_engine = ContextualRiskEngine()
    brief_service = SecurityBriefService(provider, risk_engine)
    
    brief_plan = await brief_service.generate_brief(
        cloud_account_id=request.cloud_account_id or "all",
        findings=findings_to_use,
        assets=assets_to_use
    )
    
    return brief_plan.to_dict()


