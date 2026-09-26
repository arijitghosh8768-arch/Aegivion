import re

with open('packages/backend/app/api/v1/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Make sure we import datetime module and timedelta at the top
content = re.sub(r'from datetime import datetime', 'import datetime', content)

# Remove local import datetime
content = re.sub(r'\s+import datetime', '', content)

with open('packages/backend/app/api/v1/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Auth datetime patched successfully!")
