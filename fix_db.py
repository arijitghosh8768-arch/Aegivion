with open('packages/backend/app/database/__init__.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if line.strip().startswith('"organization"'):
        new_lines.append('        "organization": "organizations",\n')
    elif line.strip().startswith('"organizationmember"'):
        new_lines.append('        "organizationmember": "organization_members",\n')
    elif line.strip().startswith('"authsession"'):
        new_lines.append('        "authsession": "sessions",\n')
    else:
        new_lines.append(line)

with open('packages/backend/app/database/__init__.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("DB file fixed!")
