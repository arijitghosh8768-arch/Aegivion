
@router.get("/overview")
def get_automation_overview(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    rules = OrmBaseModel.find(db, "automationrules", {"organization_id": user_org_id})
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
def get_agent_status(current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    return {
        "status": "ONLINE",
        "last_heartbeat": "Just now",
        "current_activity": "Monitoring",
        "workers": {
            "discovery": "RUNNING",
            "detection": "RUNNING",
            "investigation": "IDLE",
            "response": "IDLE",
            "verification": "IDLE"
        }
    }

@router.get("/executions")
def get_executions(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    return {"executions": []}
