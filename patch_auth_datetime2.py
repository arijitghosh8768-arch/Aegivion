import re

with open('packages/backend/app/api/v1/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add import datetime at the top safely
content = "import datetime\n" + content

with open('packages/backend/app/api/v1/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Auth datetime re-patched successfully!")
