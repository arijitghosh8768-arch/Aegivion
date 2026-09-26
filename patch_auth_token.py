import re

with open('packages/backend/app/api/v1/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix SecurityService token generation
new_token_logic = '''
    security_service = SecurityService()
    token = security_service.create_access_token(
        user_id=user_id,
        role=role_name,
        org_id=org_id
    )
'''

content = re.sub(
    r"token = SecurityService\.create_access_token\(\s*subject=user_id,\s*role=role_name,\s*org_id=org_id\s*\)",
    new_token_logic.strip(),
    content
)

with open('packages/backend/app/api/v1/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Auth token logic patched successfully!")
