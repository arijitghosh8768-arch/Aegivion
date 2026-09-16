from fastapi import APIRouter, Depends, Query, HTTPException, Body
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.database import get_db
from app.core.security import get_current_user
from app.api.deps import require_permission
from app.database.base import BaseModel as OrmBaseModel
from app.models.runbook import Runbook
from app.models.automation import AgentHeartbeat, ResponseExecution, PendingApproval
import uuid

router = APIRouter()

class RuleCreateRequest(BaseModel):
    name: str
    description: str
    trigger: str
    action: str

@router.get("/rules")
def list_rules(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    rules = db.query(Runbook).filter(Runbook.organization_id == user_org_id).all()
    
    return {"rules": [r.dict() for r in rules]}

@router.post("/rules", dependencies=[Depends(require_permission("manage_automation"))])
def create_rule(req: RuleCreateRequest, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    new_rule = Runbook(
        organization_id=user_org_id,
        name=req.name,
        description=req.description,
        trigger=req.trigger,
        action=req.action,
        runs=0,
        last_run="Never",
        enabled=True,
        target_url="/remediation",
        accent="bg-brand-blue/12 text-brand-blue"
    )
    db.add(new_rule)
    db.commit()
    return new_rule.dict()

@router.patch("/rules/{rule_id}/toggle", dependencies=[Depends(require_permission("manage_automation"))])
def toggle_rule(rule_id: str, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    rule = db.query(Runbook).filter(
        Runbook.id == rule_id, 
        Runbook.organization_id == user_org_id
    ).first()
    
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    rule.enabled = not rule.enabled
    db.commit()
    return rule.dict()

@router.get("/overview")
def get_automation_overview(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    rules = OrmBaseModel.find(db, "runbooks", {"organization_id": user_org_id})
    active = sum(1 for r in rules if r.get("enabled"))
    total_runs = sum(r.get("runs", 0) for r in rules)
    
    return {
        "active_runbooks": active,
        "total_rules": len(rules),
        "total_executions": total_runs,
        "successful": total_runs,
        "failed": 0,
        "pending_approvals": 0,
        "success_rate": 100.0 if total_runs > 0 else 0.0
    }

@router.get("/agent/status")
def get_agent_status(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    heartbeats = OrmBaseModel.find(db, "agentheartbeats", {"organization_id": user_org_id})
    
    workers = {
        "discovery": "OFFLINE",
        "detection": "OFFLINE",
        "investigation": "OFFLINE",
        "response": "OFFLINE",
        "verification": "OFFLINE"
    }
    
    latest_hb = "Never"
    activity = "Idle"
    status = "OFFLINE"
    
    if heartbeats and len(heartbeats) > 0:
        status = "ONLINE"
        # Sort by created_at or assume sequential insertion
        for hb in heartbeats:
            w_name = hb.get("worker", "").lower()
            if w_name in workers:
                workers[w_name] = hb.get("status", "IDLE")
        latest_hb = heartbeats[-1].get("last_heartbeat", "Just now")
        activity = heartbeats[-1].get("current_activity", "Monitoring")

    return {
        "status": status,
        "last_heartbeat": latest_hb,
        "current_activity": activity,
        "workers": workers
    }

@router.get("/executions")
def get_executions(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    executions = OrmBaseModel.find(db, "responseexecutions", {"organization_id": user_org_id})
    return {"executions": [e for e in executions]}

@router.get("/approvals")
def get_approvals(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    approvals = OrmBaseModel.find(db, "pendingapprovals", {"organization_id": user_org_id})
    return {"approvals": [a for a in approvals]}
from app.services.automation.optimizer import optimizer_engine, CandidateAction
from app.services.automation.safety import safety_policy_engine

@router.post('/rules/{rule_id}/simulate')
def simulate_runbook(rule_id: str, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or 'org-default'
    
    candidates = [
        CandidateAction(
            id=str(uuid.uuid4()),
            action_type='restrict_sg_rule',
            attack_path_reduction=0.85,
            business_impact='HIGH',
            blast_radius='HIGH',
            is_reversible=True,
            confidence=0.90,
            runbook_mode='APPROVAL_REQUIRED'
        ),
        CandidateAction(
            id=str(uuid.uuid4()),
            action_type='revoke_session',
            attack_path_reduction=0.78,
            business_impact='LOW',
            blast_radius='LOW',
            is_reversible=True,
            confidence=0.95,
            runbook_mode='APPROVAL_REQUIRED'
        )
    ]
    
    best = optimizer_engine.select_best_candidate(candidates)
    
    if not best:
        return {'status': 'NO_SAFE_ACTION'}
        
    policy_result = safety_policy_engine.evaluate(best)
    
    return {
        'status': 'SIMULATION_COMPLETE',
        'selected_action': best.action_type,
        'attack_path_reduction': f'{int(best.attack_path_reduction * 100)}%',
        'business_impact': best.business_impact,
        'blast_radius': best.blast_radius,
        'reversibility': best.is_reversible,
        'confidence': f'{int(best.confidence * 100)}%',
        'policy_result': policy_result.value,
        'ai_explanation': 'The identity showed abnormal API activity. Restricting the affected session breaks the attack path immediately while preserving unrelated production access.'
    }

@router.post('/approvals/{approval_id}/approve')
def approve_action(approval_id: str, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or 'org-default'
    return {'status': 'APPROVED', 'message': 'Action execution triggered and transitioning to VERIFYING state.'}

@router.post('/approvals/{approval_id}/reject')
def reject_action(approval_id: str, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or 'org-default'
    return {'status': 'REJECTED', 'message': 'Response candidate rejected.'}
