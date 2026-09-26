import re

with open('packages/frontend/app/(auth)/login/page.tsx', 'r', encoding='utf-8') as f:
    content = f.read()

# Instead of matching the exact message, just replace the timeout block
content = re.sub(
    r"setTimeout\(\(\) => \{\s*router\.push\(data\.user\.role === \"superadmin\" \|\| data\.user\.role === \"Super Admin\" \? \"/admin\" : \"/\"\);\s*\}, 1000\);",
    "router.push(data.user.role === 'superadmin' || data.user.role === 'Super Admin' ? '/admin' : '/');",
    content
)

with open('packages/frontend/app/(auth)/login/page.tsx', 'w', encoding='utf-8') as f:
    f.write(content)

print("Login delay patched successfully!")
