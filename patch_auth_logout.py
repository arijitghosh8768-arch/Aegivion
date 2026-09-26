import re

with open('packages/backend/app/api/v1/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

logout_logic = '''
@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"success": True}
        
    token = auth_header.split(" ")[1]
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    from app.models.auth_session import AuthSession
    session_record = db.query(AuthSession).filter(AuthSession.session_token_hash == token_hash).first()
    
    if session_record:
        session_record.revoked_at = datetime.datetime.utcnow()
        db.add(session_record)
        db.commit()
        
    return {"success": True, "message": "Logged out successfully"}
'''

content = content + logout_logic

with open('packages/backend/app/api/v1/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Logout patched successfully!")
