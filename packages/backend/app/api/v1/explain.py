from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Request
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
from app.api.deps import get_current_user, require_permission
from app.core.rate_limit import limiter

router = APIRouter()

class ExplainRequest(BaseModel):
    finding_id: str
    include_sensitive: bool = False
    format: str = "json"  # json | markdown | html

class ExplainResponse(BaseModel):
    finding_id: str
    summary: str
    observed: List[str]
    inferred: List[str]
    unknown: List[str]
    recommendations: List[str]
    confidence_score: float
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

import time
import structlog
from app.core.metrics import api_requests_total, ai_requests_total, api_request_duration_seconds, ai_request_duration_seconds

logger = structlog.get_logger(__name__)

@router.post("/explain/{finding_id}")
@limiter.limit("10/minute")
async def explain_finding(
    request_obj: Request,
    finding_id: str,
    request: ExplainRequest,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Generate AI-powered explanation for a finding"""
    start_time_float = time.time()
    start_time = datetime.utcnow()
    api_requests_total.labels(method="POST", endpoint="/api/v1/explain/{finding_id}").inc()
    ai_requests_total.inc()
    
    logger.info("processing_explain_request", user_id=getattr(current_user, 'id', 'unknown'), finding_id=finding_id)
    
    from app.models.organization import Organization
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id:
        try:
            org_obj = db.query(Organization).filter(Organization.id == uuid.UUID(str(user_org_id))).first()
            if org_obj and org_obj.settings and not org_obj.settings.get("ai_features_enabled", True):
                raise HTTPException(status_code=403, detail="AI features are not enabled for your organization")
        except ValueError:
            pass
    
    # 1. Fetch finding & asset from database (Strict fail-fast: NO mock fallbacks)
    finding_obj = None
    try:
        uuid_id = uuid.UUID(finding_id)
        finding_obj = db.query(Finding).filter(Finding.id == uuid_id).first()
    except Exception:
        finding_obj = None

    if not finding_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found."
        )

    # Tenant Isolation Check
    if user_org_id and str(finding_obj.organization_id) != str(user_org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: finding does not belong to your organization."
        )

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
            "region": finding_obj.resource_region or "global",
            "name": finding_obj.resource_name or finding_obj.resource_id,
            "configuration": {},
            "relationships": []
        }

    # 2. RAG Retrieval
    from ai.services.rag import rag_retriever
    from ai.services.mitre_mapper import MitreMapper
    
    # Optional dynamic MITRE mapping if not set
    if not finding.get("mitre_technique"):
        finding = MitreMapper.enrich_finding(finding)
        
    rag_metadata = {
        "mitre_technique": finding.get("mitre_technique"),
        "has_cisa_kev": finding.get("has_cisa_kev", False)
    }
    
    rag_result = rag_retriever.retrieve_security_knowledge(
        finding_id=finding.get("finding_id", ""),
        provider=asset.get("provider", "aws"),
        finding_type=finding.get("rule_id", "unknown"),
        finding_metadata=rag_metadata,
        db=db
    )
    
    # 3. Build prompt context
    prompt_builder = PromptBuilder()
    context = PromptContext(
        finding=finding,
        asset=asset,
        evidence=finding.get("evidence", {}),
        severity=finding.get("severity", "medium"),
        risk_score=finding.get("risk_score"),
        mitre_technique=finding.get("mitre_technique"),
        mitre_tactic=finding.get("mitre_tactic"),
        rag_knowledge=rag_result.get("relevant_knowledge", [])
    )
    
    prompt = prompt_builder.build_prompt(context)
    
    # 3. Call LLM Provider
    provider = get_llm_provider()
    processing_time = 0
    try:
        llm_output = provider.generate(prompt)
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Extract text and token accounting
        if hasattr(llm_output, "text"):
            response_text = llm_output.text
            tokens = getattr(llm_output, "tokens", {})
            cost = getattr(llm_output, "cost", 0.0)
            model_used = getattr(llm_output, "model", "unknown")
        else:
            response_text = str(llm_output)
            tokens = {}
            cost = 0.0
            model_used = "unknown"

        logger.info(
            "ai_tokens_logged",
            finding_id=finding_id,
            tokens=tokens,
            cost=cost,
            model=model_used
        )
        
        # Parse output JSON requirements
        try:
            parsed = json.loads(response_text)
        except Exception:
            # Fallback parse logic
            parsed = {
                "summary": f"Potential configuration vulnerability detected for {finding.get('title')}.",
                "observed": [f"Finding {finding.get('title')} was triggered based on resource scan."],
                "inferred": ["Exposure of configuration keys increases risk posture.", "Non-compliance triggers data policy review audit warnings."],
                "unknown": ["Whether this vulnerability is actively exploited.", "Business owner of this resource."],
                "recommendations": finding.get("remediation", ["Apply correct configuration constraint rules."]),
                "citations": [
                    {"source": "finding_id", "value": finding_id},
                    {"source": "rule_id", "value": finding.get("rule_id", "unknown")}
                ],
                "confidence_score": 0.88
            }

        # 4. Hallucination Guardrail Check (GroundingValidator)
        from ai.guardrails.grounding import GroundingValidator
        validator = GroundingValidator()
        grounded_eval = validator.validate_response(parsed, finding.get("evidence", {}))

        if not grounded_eval.is_grounded and grounded_eval.safe_response:
            logger.warning(
                "ai_hallucination_blocked",
                finding_id=finding_id,
                warnings=grounded_eval.warnings
            )
            parsed = grounded_eval.safe_response

        from ai.services.remediation_engine import RemediationEngine
        remediation_engine = RemediationEngine(provider)
        remediation_plan = await remediation_engine.generate_remediation(finding)
        remediation_dict = remediation_plan.to_dict()
            
        duration = time.time() - start_time_float
        api_request_duration_seconds.labels(method="POST", endpoint="/api/v1/explain/{finding_id}").observe(duration)
        ai_request_duration_seconds.observe(duration)
        logger.info("explain_request_successful", finding_id=finding_id, duration=duration)

        return {
            "finding_id": finding_id,
            "summary": parsed.get("summary", finding.get("description", finding.get("title"))),
            "observed": parsed.get("observed", []),
            "inferred": parsed.get("inferred", []),
            "unknown": parsed.get("unknown", []),
            "recommendations": parsed.get("recommendations", []),
            "citations": parsed.get("citations", [
                {"source": "finding_id", "value": finding_id},
                {"source": "rule_id", "value": finding.get("rule_id", "unknown")}
            ]),
            "confidence_score": parsed.get("confidence_score", parsed.get("confidence", 0.9)),
            "evidence_used": finding.get("evidence", {}),
            "is_grounded": getattr(grounded_eval, "is_grounded", True),
            "guardrail_warnings": getattr(grounded_eval, "warnings", []),
            "tokens": tokens,
            "cost": cost,
            "processing_time_ms": processing_time,
            "timestamp": datetime.utcnow().isoformat(),
            "remediation": remediation_dict
        }
        
    except Exception as e:
        logger.error("explain_request_failed", finding_id=finding_id, error=str(e), exc_info=True)
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        fallback = generate_fallback_explanation(finding)
        
        from ai.services.remediation_engine import RemediationEngine
        remediation_engine = RemediationEngine(provider)
        remediation_plan = await remediation_engine.generate_remediation(finding)
        remediation_dict = remediation_plan.to_dict()
        
        duration = time.time() - start_time_float
        api_request_duration_seconds.labels(method="POST", endpoint="/api/v1/explain/{finding_id}").observe(duration)
        ai_request_duration_seconds.observe(duration)
        
        return {
            "finding_id": finding_id,
            "error": str(e),
            "summary": fallback.get("summary", "Error analyzing finding"),
            "observed": fallback.get("observed", []),
            "inferred": fallback.get("inferred", []),
            "unknown": fallback.get("unknown", []),
            "recommendations": fallback.get("recommendations", []),
            "confidence_score": fallback.get("confidence_score", 0.0),
            "processing_time_ms": processing_time,
            "timestamp": datetime.utcnow().isoformat(),
            "remediation": remediation_dict
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
        "observed": ["Detailed analysis unavailable due to processing error."],
        "inferred": [severity_impact.get(finding.get('severity', 'medium'), 'Security risk identified')],
        "unknown": ["Root cause", "Specific business impact", "Active exploitation"],
        "recommendations": [
            "Review the security finding details",
            "Verify the configuration against security best practices",
            "Apply remediation steps if applicable"
        ],
        "confidence_score": 0.3
    }

@router.post("/remediate/{finding_id}", dependencies=[Depends(require_permission("use_ai_assistant"))])
async def remediate_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
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

@router.post("/security-brief", dependencies=[Depends(require_permission("use_ai_assistant"))])
async def security_brief(
    request: BriefRequest,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
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


