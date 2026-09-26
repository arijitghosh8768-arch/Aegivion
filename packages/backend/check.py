import sys, os
sys.path.insert(0, os.path.abspath('.'))
from app.database import get_db
from app.models.user import User
from app.models.role import Role

db = next(get_db())
users = db.query(User).all()
roles = {str(r.id): r.name for r in db.query(Role).all()}
for u in users:
    if 'arijit' in u.email:
        role_name = roles.get(str(u.role_id), 'unknown')
        print(f'{u.email}: role_id={u.role_id} -> {role_name}')
