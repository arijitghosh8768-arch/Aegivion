import re

with open('packages/backend/app/api/v1/admin.py', 'r', encoding='utf-8') as f:
    text = f.read()

new_logic = '''    for m in members:
        u = users.get(str(m.user_id))
        if u and u.email != 'superadmin@aegivion.com':
            # ONLY return users who are actually Org Admins in this panel
            role_str = str(m.role).upper()
            if 'ADMIN' in role_str or role_str == 'ORG_ADMIN':
                org_name = orgs.get(str(m.organization_id), 'Unassigned')
                data.append({
                    'id': str(u.id),
                    'email': u.email,
                    'org_name': org_name,
                    'role': m.role,
                    'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
                })'''

text = re.sub(r"    for m in members:.*?\}\)", new_logic, text, flags=re.DOTALL)

with open('packages/backend/app/api/v1/admin.py', 'w', encoding='utf-8') as f:
    f.write(text)
