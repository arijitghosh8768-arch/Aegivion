
with open("packages/backend/app/api/v1/admin.py", "a") as f:
    f.write("""

@router.delete("/orgs/{org_id}")
def delete_org(org_id: str, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid org ID format")
    
    org = db.query(OrgSettings).filter(OrgSettings.id == oid).first()
    if not org:
        org = db.query(OrgSettings).filter(OrgSettings.organization_id == oid).first()
        
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    db.delete(org)
    db.commit()
    return {"success": True, "message": "Organization deleted"}

@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
        
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.email == "superadmin@aegivion.com":
        raise HTTPException(status_code=400, detail="Cannot delete superadmin")
        
    db.delete(user)
    db.commit()
    return {"success": True, "message": "User deleted"}
""")

