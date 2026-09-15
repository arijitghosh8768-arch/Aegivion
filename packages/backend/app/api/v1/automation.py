from fastapi import APIRouter, Depends, Query, HTTPException, Body
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.database import get_db
from app.core.security import get_current_user
from app.api.deps import require_permission
from app.database.base import BaseModel as OrmBaseModel
import uuid

router = APIRouter()

class AutomationRule(OrmBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.name = kwargs.get("name", "New Runbook")
        self.description = kwargs.get("description", "")
        self.trigger = kwargs.get("trigger", "Manual")
        self.action = kwargs.get("action", "Alert")
        self.runs = kwargs.get("runs", 0)
        self.last_run = kwargs.get("last_run", "Never")
        self.enabled = kwargs.get("enabled", True)
        self.target_url = kwargs.get("target_url", "/remediation")
        self.accent = kwargs.get("accent", "bg-brand-blue/12 text-brand-blue")

    def dict(self):
        d = super().dict()
        d.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "name": self.name,
            "desc": self.description,
            "trigger": self.trigger,
            "action": self.action,
            "runs": self.runs,
            "lastRun": self.last_run,
            "enabled": self.enabled,
            "target": self.target_url,
            "accent": self.accent
        })
        return d

class RuleCreateRequest(BaseModel):
    name: str
    description: str
    trigger: str
    action: str

@router.get("/rules")
def list_rules(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    rules = db.query(AutomationRule).filter(AutomationRule.organization_id == user_org_id).all()
    
    # Return empty list if no rules exist yet
    return {"rules": [r.dict() for r in rules]}

@router.post("/rules", dependencies=[Depends(require_permission("manage_automation"))])
def create_rule(req: RuleCreateRequest, db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    new_rule = AutomationRule(
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
    
    rule = db.query(AutomationRule).filter(
        AutomationRule.id == rule_id, 
        AutomationRule.organization_id == user_org_id
    ).first()
    
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    rule.enabled = not rule.enabled
    db.commit()
    return rule.dict()
