import os
from pymongo import MongoClient
from passlib.context import CryptContext
import uuid
import datetime

mongo_uri = os.environ.get("MONGODB_URI")
if not mongo_uri:
    raise ValueError("MONGODB_URI environment variable must be set")
client = MongoClient(mongo_uri)
db = client["aegivion"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

admin_pass = os.environ.get("DEFAULT_ADMIN_PASSWORD")
if not admin_pass:
    raise ValueError("DEFAULT_ADMIN_PASSWORD environment variable must be set")
hashed_pw = pwd_context.hash(admin_pass)

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

