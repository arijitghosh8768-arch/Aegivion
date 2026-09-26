
from pymongo import MongoClient
from passlib.context import CryptContext
import uuid
import datetime

client = MongoClient("mongodb+srv://arijitghosh8768_db_user:***REMOVED***@cluster0.vym1z8g.mongodb.net/")
db = client["aegivion"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed_pw = pwd_context.hash("SuperSecret123!")

admin_role = db["roles"].find_one({"name": "superadmin"})
if not admin_role:
    role_id = str(uuid.uuid4())
    db["roles"].insert_one({
        "id": role_id,
        "name": "superadmin",
        "description": "System Administrator",
        "created_at": datetime.datetime.utcnow().isoformat(),
        "updated_at": datetime.datetime.utcnow().isoformat()
    })
else:
    role_id = admin_role["id"]

user = db["users"].find_one({"email": "superadmin@aegivion.com"})
if not user:
    db["users"].insert_one({
        "id": str(uuid.uuid4()),
        "email": "superadmin@aegivion.com",
        "first_name": "Super",
        "last_name": "Admin",
        "password_hash": hashed_pw,
        "status": "ACTIVE",
        "email_verified": True,
        "role_id": role_id,
        "is_platform_admin": True,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "updated_at": datetime.datetime.utcnow().isoformat()
    })
    print("Superadmin created in Atlas!")
else:
    db["users"].update_one({"email": "superadmin@aegivion.com"}, {"$set": {"password_hash": hashed_pw}})
    print("Superadmin password updated in Atlas!")

