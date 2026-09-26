import re

with open('packages/backend/app/api/v1/admin.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('from app.models.org_settings import OrgSettings',
'''from app.models.org_settings import OrgSettings
from app.models.organization_member import OrganizationMember, OrgRole''')

create_logic = '''
    new_user = User(
        email=req.email,
        first_name="Org",
        last_name="Admin",
        password_hash=hashed_pw,
        status=UserStatus.ACTIVE,
        email_verified=True,
        role_id=admin_role.id,
        is_platform_admin=False
    )
    db.add(new_user)
    
    new_member = OrganizationMember(
        user_id=new_user.id,
        organization_id=uuid.UUID(req.org_id),
        role=OrgRole.ORG_ADMIN
    )
    db.add(new_member)
    
    db.commit()
'''

content = re.sub(r'new_user = User\(.*?db\.add\(new_user\)\s+db\.commit\(\)', create_logic, content, flags=re.DOTALL)

list_logic = '''@router.get('/users')
def list_org_admins(db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    users = {str(u.id): u for u in db.query(User).all()}
    orgs = {str(o.organization_id or o.id): o.branding.get('company_name', 'Unknown') for o in db.query(OrgSettings).all()}
    members = db.query(OrganizationMember).all()
    
    data = []
    
    for m in members:
        u = users.get(str(m.user_id))
        if u and u.email != 'superadmin@aegivion.com':
            org_name = orgs.get(str(m.organization_id), 'Unassigned')
            data.append({
                'id': str(u.id),
                'email': u.email,
                'org_name': org_name,
                'role': m.role,
                'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
            })
            
    legacy_user_ids = {str(m.user_id) for m in members}
    for uid, u in users.items():
        if uid not in legacy_user_ids and u.email != 'superadmin@aegivion.com' and getattr(u, 'organization_id', None):
            org_name = orgs.get(str(u.organization_id), 'Unassigned')
            data.append({
                'id': str(u.id),
                'email': u.email,
                'org_name': org_name,
                'role': 'ORG_ADMIN',
                'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
            })
            
    return {'success': True, 'data': data}'''

content = re.sub(r"@router\.get\('/users'\).*?return \{'success': True, 'data': data\}", list_logic, content, flags=re.DOTALL)

with open('packages/backend/app/api/v1/admin.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Admin patched successfully!')
