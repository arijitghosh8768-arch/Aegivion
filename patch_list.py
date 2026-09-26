import re

with open('packages/backend/app/api/v1/admin.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_list = '''@router.get('/users')
def list_org_admins(db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    users = {str(u.id): u for u in db.query(User).all()}
    orgs = {str(o.organization_id or o.id): o.branding.get('company_name', 'Unknown') for o in db.query(OrgSettings).all()}
    members = db.query(OrganizationMember).all()
    roles = {str(r.id): r for r in db.query(Role).all()}
    
    data = []
    
    for m in members:
        u = users.get(str(m.user_id))
        if u and u.email != 'superadmin@aegivion.com':
            role_str = str(m.role).upper()
            if 'ADMIN' in role_str or role_str == 'ORG_ADMIN':
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
            # Check legacy role_id
            is_admin = False
            r_id = str(u.role_id)
            if r_id.upper() in ['ADMIN', 'ORG_ADMIN']:
                is_admin = True
            else:
                role_obj = roles.get(r_id)
                if role_obj and 'admin' in role_obj.name.lower():
                    is_admin = True
                    
            if is_admin:
                org_name = orgs.get(str(u.organization_id), 'Unassigned')
                data.append({
                    'id': str(u.id),
                    'email': u.email,
                    'org_name': org_name,
                    'role': 'ORG_ADMIN',
                    'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
                })
            
    return {'success': True, 'data': data}'''

content = re.sub(r"@router\.get\('/users'\).*?return \{'success': True, 'data': data\}", new_list, content, flags=re.DOTALL)

with open('packages/backend/app/api/v1/admin.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Admin list patched successfully!")
