
import bcrypt
from app.database import db

password = 'SuperSecret123!'
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

res = db['users'].update_one({'email': 'superadmin@aegivion.com'}, {'$set': {'password_hash': hashed}})
print('Modified superadmin password:', res.modified_count)

res = db['users'].update_one({'email': 'admin@aegivion.com'}, {'$set': {'password_hash': hashed}})
print('Modified admin password:', res.modified_count)

