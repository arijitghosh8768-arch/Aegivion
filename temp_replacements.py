@router.get("/agent/status")
def get_agent_status(db: Session = Depends(get_db), current_user: Any = Depends(get_current_user)):
    user_org_id = getattr(current_user, 'organization_id', None) or "org-default"
    
    heartbeats = OrmBaseModel.find(db, "agentheartbeats", {"organization_id": user_org_id})
    
    workers = {
        "discovery": "IDLE",
        "detection": "IDLE",
        "investigation": "IDLE",
        "response": "IDLE",
        "verification": "IDLE"
    }
    
    latest_hb = "Just now"
    activity = "Monitoring"
    status = "ONLINE"
    
    if heartbeats:
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
